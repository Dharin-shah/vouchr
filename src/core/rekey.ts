import type { Db } from './db';
import { encrypt, toBuffer, toKeyring, tryDecryptDirect, type MasterKeys } from './crypto';

/**
 * Re-encryption pass for master-key rotation on the DIRECT (non-KMS) path (#115): walk every
 * encrypted column, decrypt each blob with whichever configured key authenticates, and rewrite it
 * under the ring's PRIMARY key. Envelope (KMS) rows are skipped — their rotation happens in the
 * KMS, not in the rows. Driven by `vouchr rekey [--dry-run]`.
 *
 * Interrupt-safe by construction: each row is one small autocommit UPDATE, so a crash mid-run
 * leaves a mixed but fully-readable table (old rows still decrypt via the ring) and a re-run
 * converges. Idempotent: blobs already under the primary are skipped. Concurrency-safe: every
 * UPDATE is guarded on the ciphertext bytes it read, so a token refreshed mid-run is left alone
 * (counted, converged by a re-run) instead of being clobbered with a re-encryption of stale bytes.
 *
 * SEC-1: this module never logs, throws, or reports plaintext or key material — the report is
 * counts plus charset-validated key ids only.
 */

/** Every encrypted column in the schema (grep `encrypt(`/`seal(` call sites: vault.ts writes the
 *  connection token columns; installationStore.ts writes both installation columns. The consent
 *  PKCE verifier is NOT encrypted — it is a short-lived random secret, hashed for the challenge). */
const TARGETS = [
  { table: 'connection', cols: ['access_token_enc', 'refresh_token_enc'] },
  { table: 'installation', cols: ['bot_token', 'data'] },
] as const;

export interface RekeyReport {
  /** Encrypted (non-null) blobs examined. */
  scanned: number;
  /** Blobs rewritten under the primary key (with `dryRun`: the count that WOULD be). */
  reencrypted: number;
  /** Blobs already under the primary key/scheme — skipped (idempotence). */
  alreadyPrimary: number;
  /** Scheme-0x01 blobs no direct key decrypts: KMS envelope rows, skipped (rotate in the KMS). */
  envelope: number;
  /** Blobs no configured key decrypts (includes unknown key ids) — the store needs the missing key. */
  unreadable: number;
  /** Guarded writes that lost to a concurrent writer (e.g. a token refresh); a re-run converges. */
  skippedConcurrent: number;
  /** Distinct key ids named by blobs but absent from the ring (charset-validated, safe to print). */
  unknownKeyIds: string[];
  /** Decrypted-blob counts by source, e.g. "scheme0 (id-less key)" / "scheme2 (key 'k2019')". */
  bySource: Record<string, number>;
}

export interface RekeyOptions {
  /** Classify and count only; write nothing. */
  dryRun?: boolean;
  /** Rows fetched per batch (writes stay row-at-a-time regardless). */
  batchSize?: number;
  /** Called after each batch with rows processed so far in `table`. Counts only — never content. */
  onProgress?: (table: string, done: number, total: number) => void;
}

const sourceLabel = (scheme: 0 | 2, keyId: string | null): string =>
  scheme === 0 ? (keyId === null ? 'scheme0 (id-less key)' : `scheme0 (key '${keyId}')`) : `scheme2 (key '${keyId}')`;

export async function rekey(db: Db, keys: MasterKeys, opts: RekeyOptions = {}): Promise<RekeyReport> {
  const ring = toKeyring(keys);
  const batchSize = opts.batchSize ?? 500;
  const report: RekeyReport = {
    scanned: 0, reencrypted: 0, alreadyPrimary: 0, envelope: 0, unreadable: 0,
    skippedConcurrent: 0, unknownKeyIds: [], bySource: {},
  };
  const unknownIds = new Set<string>();

  for (const { table, cols } of TARGETS) {
    const total = ((await db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table}`))?.n ?? 0) as number;
    let done = 0;
    let lastId = ''; // TEXT primary keys ('' sorts before every real id in both engines)
    for (;;) {
      const rows = await db.all<any>(
        `SELECT id, ${cols.join(', ')} FROM ${table} WHERE id > ? ORDER BY id LIMIT ?`,
        [lastId, batchSize],
      );
      if (!rows.length) break;
      for (const row of rows) {
        lastId = row.id;
        // Collect this row's stale columns, then rewrite them in ONE guarded UPDATE.
        const updates: { col: string; oldBuf: Buffer; newBuf: Buffer }[] = [];
        for (const col of cols) {
          if (row[col] == null) continue; // reference rows / absent bot tokens hold no ciphertext
          const oldBuf = toBuffer(row[col]);
          report.scanned++;
          const r = tryDecryptDirect(oldBuf, ring);
          if (!r.ok) {
            if (r.reason === 'maybe-envelope') report.envelope++;
            else {
              report.unreadable++;
              if (r.reason === 'unknown-key-id') unknownIds.add(r.keyId);
            }
            continue;
          }
          report.bySource[sourceLabel(r.scheme, r.keyId)] = (report.bySource[sourceLabel(r.scheme, r.keyId)] ?? 0) + 1;
          const isPrimary = ring.primary.id === null
            ? r.scheme === 0 && r.keyId === null
            : r.scheme === 2 && r.keyId === ring.primary.id;
          if (isPrimary) report.alreadyPrimary++;
          else updates.push({ col, oldBuf, newBuf: encrypt(r.plaintext, ring) });
        }
        if (!updates.length) continue;
        if (opts.dryRun) {
          report.reencrypted += updates.length;
          continue;
        }
        // Optimistic guard: only write if every column still holds the exact bytes we decrypted.
        const { changes } = await db.run(
          `UPDATE ${table} SET ${updates.map((u) => `${u.col}=?`).join(', ')}
           WHERE id = ? AND ${updates.map((u) => `${u.col}=?`).join(' AND ')}`,
          [...updates.map((u) => u.newBuf), row.id, ...updates.map((u) => u.oldBuf)],
        );
        if (changes === 1) report.reencrypted += updates.length;
        else report.skippedConcurrent += updates.length;
      }
      done += rows.length;
      opts.onProgress?.(table, done, total);
      if (rows.length < batchSize) break;
    }
  }
  report.unknownKeyIds = [...unknownIds].sort();
  return report;
}
