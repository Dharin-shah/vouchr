#!/usr/bin/env node
/**
 * vouchr: operator CLI for self-hosted deployments.
 *
 * Connects to the SAME credential store the app uses (PostgreSQL via
 * VOUCHR_DATABASE_URL or --db) through `openDb`. The read commands
 * (inventory/channels/doctor/health) are metadata-only and NEVER decrypt or print
 * token/secret material. Two commands mutate: `revoke` DELETES rows and may
 * best-effort decrypt an access token to hand to the upstream revoke — never to
 * stdout; `rekey` re-encrypts ciphertext columns under the primary master key and
 * prints counts only. `secret_ref` (an external manager ARN/pointer, non-secret by
 * design) is the only ref any command surfaces.
 *
 * Run: `node --import tsx bin/vouchr.ts <cmd>` (or `npm run cli -- <cmd>`).
 */
import { openDb, migrate, type Db } from '../src/core/db';
import { loadKeyring, type Keyring } from '../src/core/crypto';
import { rekey } from '../src/core/rekey';
import { isPostgresUrl } from '../src/core/options';
import { github, google, gitlab, notion, ProviderRegistry, type Provider } from '../src/core/providers';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import { selectRevocations, revokeConnection, countPendingForProvider, purgePendingForProvider, type RevokeFilter } from '../src/core/offboard';
import { loadProviders } from './providerConfig';

type Flags = { values: Record<string, string>; positional: string[] };

/** Tiny flag parser: `--key value` / `--key=value` → values; everything else positional. */
function parseFlags(argv: string[]): Flags {
  const values: Record<string, string> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) { values[a.slice(2, eq)] = a.slice(eq + 1); continue; }
      // Boolean flag: a `--flag` with no value (end of argv or another `--flag` next) must not swallow
      // the following flag as its value. Ids never start with `--`, so this is unambiguous.
      const next = argv[i + 1];
      values[a.slice(2)] = next === undefined || next.startsWith('--') ? '' : argv[++i];
    } else positional.push(a);
  }
  return { values, positional };
}

const ts = (ms: number | null | undefined): string =>
  ms == null ? '-' : new Date(ms).toISOString();

/** Compact left-aligned table. */
function printTable(headers: string[], rows: string[][]): void {
  if (!rows.length) {
    console.log('(none)');
    return;
  }
  const widths = headers.map((h, c) => Math.max(h.length, ...rows.map((r) => (r[c] ?? '').length)));
  const fmt = (cells: string[]) => cells.map((v, c) => (v ?? '').padEnd(widths[c])).join('  ').trimEnd();
  console.log(fmt(headers));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const r of rows) console.log(fmt(r));
}

/** Mirror openDb's backend resolution so `doctor` can report it without opening twice. */
function describeBackend(dbUrl?: string): string {
  const url = dbUrl ?? process.env.VOUCHR_DATABASE_URL; // no generic DATABASE_URL fallback (#204)
  return isPostgresUrl(url) ? 'PostgreSQL' : 'PostgreSQL (not configured — set VOUCHR_DATABASE_URL)';
}

async function cmdInventory(db: Db, f: Flags): Promise<void> {
  const where: string[] = [];
  const params: any[] = [];
  if (f.values.team) { where.push('team_id=?'); params.push(f.values.team); }
  if (f.values.provider) { where.push('provider=?'); params.push(f.values.provider); }
  // Metadata columns only. Token ciphertext columns are never selected.
  const rows = await db.all<any>(
    `SELECT team_id, owner_kind, owner_id, provider, source, secret_ref, created_at, last_used_at, expires_at
     FROM connection ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
     ORDER BY team_id, provider, owner_kind, owner_id`,
    params,
  );
  printTable(
    ['team', 'owner_kind', 'owner_id', 'provider', 'source', 'secret_ref', 'created_at', 'last_used_at', 'expires_at'],
    rows.map((r) => [
      r.team_id, r.owner_kind, r.owner_id, r.provider, r.source,
      r.secret_ref ?? '-', ts(r.created_at), ts(r.last_used_at), ts(r.expires_at),
    ]),
  );
}

async function cmdChannels(db: Db, f: Flags): Promise<void> {
  // FULL OUTER JOIN: a channel may have a config row, a tool row, or both.
  const where = f.values.team ? 'WHERE COALESCE(c.team_id, t.team_id)=?' : '';
  const params = f.values.team ? [f.values.team] : [];
  const rows = await db.all<any>(
    `SELECT COALESCE(c.team_id, t.team_id)   AS team_id,
            COALESCE(c.channel, t.channel)   AS channel,
            COALESCE(c.provider, t.provider) AS provider,
            c.mode    AS mode,
            t.enabled AS enabled
     FROM channel_config c
     FULL OUTER JOIN channel_tool t
       ON c.team_id=t.team_id AND c.channel=t.channel AND c.provider=t.provider
     ${where}
     ORDER BY team_id, channel, provider`,
    params,
  );
  printTable(
    ['team', 'channel', 'provider', 'mode', 'enabled'],
    rows.map((r) => [
      r.team_id, r.channel, r.provider,
      r.mode ?? '-',
      r.enabled == null ? '-' : r.enabled ? 'yes' : 'no',
    ]),
  );
}

/**
 * Break-glass bulk revocation: kill every stored credential for a provider (optionally narrowed to a
 * team/user/channel) during incident response. Dry-run is the DEFAULT — it prints a no-secret table
 * and mutates nothing; `--yes` is required to actually revoke. Refuses to run without `--provider`.
 *
 * Local deletion is the security-meaningful action and MUST be guaranteed: the provider registry and
 * master key (needed only for the best-effort UPSTREAM revoke + token decrypt) are loaded defensively,
 * so a malformed provider config or an unavailable master key disables upstream revoke but never blocks
 * the local kill. It never PRINTS a secret; the only decryption is the just-read access token handed to
 * the upstream revoke, never to stdout. Pending consent + thread grants for the scope are cleared too.
 */
async function cmdRevoke(db: Db, f: Flags): Promise<number> {
  // A scoping flag written with NO value (e.g. the typo `--team --yes`, where `--yes` is consumed as a
  // boolean and `--team` is left empty) must NOT silently widen the blast radius to every team. Refuse
  // any scope flag that is PRESENT but empty rather than treating it as "unset".
  for (const k of ['provider', 'team', 'user', 'channel'] as const) {
    if (k in f.values && !f.values[k]) {
      console.error(`revoke: --${k} was given with no value; refusing to run with an ambiguous scope`);
      return 2;
    }
  }
  const provider = f.values.provider;
  if (!provider) {
    console.error('revoke: --provider <id> is required (refusing to revoke across every provider)');
    return 2;
  }
  const filter: RevokeFilter = { provider, teamId: f.values.team, userId: f.values.user, channel: f.values.channel };
  const rows = await selectRevocations(db, filter);

  // Dry-run unless --yes (and an explicit --dry-run forces it even alongside --yes). Print + exit.
  const dryRun = 'dry-run' in f.values || !('yes' in f.values);
  const scope = [`provider=${provider}`, f.values.team && `team=${f.values.team}`, f.values.user && `user=${f.values.user}`, f.values.channel && `channel=${f.values.channel}`].filter(Boolean).join(' ');
  console.log(`${dryRun ? 'DRY-RUN' : 'REVOKE'} ${scope}: ${rows.length} connection(s)`);
  printTable(
    ['team', 'owner_kind', 'owner', 'external_account', 'created_at'],
    rows.map((r) => [r.teamId, r.ownerKind, r.ownerId, r.externalAccount ?? '-', ts(r.createdAt)]),
  );
  if (dryRun) {
    const pending = await countPendingForProvider(db, filter);
    if (pending.consents || pending.grants) {
      console.log(`Would also clear ${pending.consents} pending consent + ${pending.grants} session grant(s).`);
    }
    if (rows.length || pending.consents || pending.grants) console.log('\nNo changes made. Re-run with --yes to revoke.');
    return 0;
  }

  // Load the registry + master key BEST-EFFORT: break-glass must not die before the local delete just
  // because provider config is malformed or the key is missing. A failure only disables upstream revoke
  // (and token decrypt); the local delete below needs neither the key nor the registry.
  let registry: ProviderRegistry | undefined;
  try {
    registry = new ProviderRegistry(loadProviders(process.env));
  } catch (e: any) {
    console.error(`revoke: provider config unavailable (${e?.message ?? e}); upstream revoke disabled — local deletion will proceed`);
  }
  let key: Buffer | Keyring;
  try {
    key = loadKeyring(); // full ring, so post-rotation rows (keyed scheme) still decrypt for upstream revoke
  } catch (e: any) {
    console.error(`revoke: master key unavailable (${e?.message ?? e}); token decrypt + upstream revoke disabled — local deletion will proceed`);
    key = Buffer.alloc(32); // never used to decrypt successfully; vault.delete needs no key
  }
  const vault = new Vault(db, key);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);

  let localFailures = 0;
  let upstreamAttempted = 0;
  let upstreamFailures = 0;
  let upstreamSkipped = 0;
  for (const row of rows) {
    // revokeConnection is best-effort internally, but keep a backstop so an unexpected throw on one row
    // never strands the rest of a break-glass sweep.
    try {
      const r = await revokeConnection(vault, audit, consent, sessions, registry, row, provider);
      if (!r.removed) localFailures++;
      if (r.upstreamAttempted) { upstreamAttempted++; if (!r.upstreamOk) upstreamFailures++; }
      else upstreamSkipped++;
    } catch (e: any) {
      localFailures++;
      console.error(`revoke: ${row.ownerKind}:${row.ownerId} failed (${e?.message ?? e})`);
    }
  }
  // Clear pending consent + thread grants for the SCOPE regardless of whether any connection matched —
  // an in-flight "Connect" or a lingering grant with no live connection would otherwise resurrect access.
  const purged = await purgePendingForProvider(db, filter);
  const revoked = rows.length - localFailures;
  console.log(`\nRevoked ${revoked}/${rows.length} locally.`);
  // Report upstream honestly: attempted vs skipped (no revoke endpoint / no decryptable token) are NOT
  // the same as success. A skip is not a failure, but it is not a revoke either.
  console.log(`Upstream revoke: ${upstreamAttempted} attempted (${upstreamFailures} failed), ${upstreamSkipped} skipped (no revoke endpoint or no decryptable token).`);
  console.log(`Cleared ${purged.consents} pending consent + ${purged.grants} session grant(s).`);
  // Non-zero only when a LOCAL deletion failed (access still present); upstream failures don't fail.
  return localFailures ? 1 : 0;
}

/**
 * Master-key rotation (#115): re-encrypt every stored ciphertext under the PRIMARY key (the first
 * `VOUCHR_MASTER_KEYS` entry). All logic lives in core (`src/core/rekey.ts`); this prints counts
 * only — never key material, plaintext, or ciphertext (SEC-1). `--dry-run` classifies and counts
 * per key-id/scheme without writing, which is also the runbook's "zero old-key rows" check.
 */
async function cmdRekey(db: Db, f: Flags): Promise<number> {
  let ring: Keyring;
  try {
    ring = loadKeyring();
  } catch (e: any) {
    console.error(`rekey: ${e?.message ?? e}`);
    return 2;
  }
  const dryRun = 'dry-run' in f.values;
  const primary = ring.primary.id === null ? 'id-less VOUCHR_MASTER_KEY' : `key '${ring.primary.id}'`;
  console.log(`${dryRun ? 'REKEY DRY-RUN' : 'REKEY'}: re-encrypt under ${primary} (${ring.legacy.length} key(s) configured)`);
  const r = await rekey(db, ring, {
    dryRun,
    onProgress: (table, done, total) => console.log(`  ${table}: ${done}/${total} row(s)`),
  });
  console.log('');
  printTable(
    ['decrypt source', 'blobs'],
    Object.entries(r.bySource).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, String(v)]),
  );
  console.log(`\nalready under primary: ${r.alreadyPrimary}`);
  console.log(`${dryRun ? 'would re-encrypt' : 're-encrypted'}: ${r.reencrypted}`);
  console.log(`envelope (KMS-managed, skipped): ${r.envelope}`);
  if (r.skippedConcurrent) console.log(`skipped (written concurrently; re-run to converge): ${r.skippedConcurrent}`);
  console.log(`unreadable under configured keys: ${r.unreadable}`);
  if (dryRun) console.log('\nNo changes made. Re-run without --dry-run to re-encrypt.');
  if (r.unreadable) {
    const ids = r.unknownKeyIds.length ? ` Missing key id(s): ${r.unknownKeyIds.map((i) => `'${i}'`).join(', ')}.` : '';
    console.error(`\nrekey: ${r.unreadable} blob(s) decrypt under NO configured key.${ids} Add the missing key(s) to VOUCHR_MASTER_KEYS and re-run.`);
    return 1;
  }
  return 0;
}

async function cmdDoctor(f: Flags): Promise<number> {
  let failed = false;
  const pass = (label: string, msg = '') => console.log(`PASS ${label}${msg ? ': ' + msg : ''}`);
  const fail = (label: string, msg = '') => { failed = true; console.log(`FAIL ${label}${msg ? ': ' + msg : ''}`); };

  // 1. Master key(s): load via loadKeyring, never print key material itself.
  try {
    const ring = loadKeyring();
    // Single id-less key → today's exact output (UX-2); a keyring reports count + primary id.
    if (ring.primary.id === null && ring.legacy.length === 1) pass('master key', '32 bytes');
    else pass('master key', `${ring.legacy.length} keys; new writes under '${ring.primary.id}'`);
  } catch (e: any) {
    fail('master key', e?.message ?? 'invalid');
  }

  // 2. Backend in use (informational).
  console.log(`INFO backend: ${describeBackend(f.values.db)}`);

  // 3. DB reachable + counts.
  let db: Db | undefined;
  try {
    db = await openDb({ databaseUrl: f.values.db });
    await db.get('SELECT 1 AS x');
    pass('db reachable');
    const conns = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM connection');
    const consents = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM consent_request');
    console.log(`INFO connections: ${conns?.n ?? 0}`);
    console.log(`INFO consent_requests: ${consents?.n ?? 0}`);
  } catch (e: any) {
    fail('db reachable', e?.message ?? 'open failed');
  } finally {
    await db?.close();
  }

  return failed ? 1 : 0;
}

/** Best-effort: any HTTP response (even 4xx/5xx) means the host is reachable. */
async function reachable(host: string, timeoutMs = 5000): Promise<boolean> {
  try {
    await fetch(`https://${host}/`, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    return true;
  } catch {
    return false;
  }
}

// Built-in providers. Dummy creds satisfy defineProvider's clientId/clientSecret check;
// health only reads authorizeUrl/tokenUrl hosts and never sends credentials.
const BUILTINS: Record<string, () => Provider> = {
  github: () => github({ clientId: 'x', clientSecret: 'x' }),
  google: () => google({ clientId: 'x', clientSecret: 'x' }),
  gitlab: () => gitlab({ clientId: 'x', clientSecret: 'x' }),
  notion: () => notion({ clientId: 'x', clientSecret: 'x' }),
};

async function cmdHealth(f: Flags): Promise<void> {
  // Each target → a label and the set of hosts to probe.
  const targets: { label: string; hosts: string[] }[] = [];
  const names = f.positional.length ? f.positional : Object.keys(BUILTINS);
  for (const name of names) {
    if (BUILTINS[name]) {
      const p = BUILTINS[name]();
      const hosts = [...new Set([new URL(p.authorizeUrl).host, new URL(p.tokenUrl).host])];
      targets.push({ label: name, hosts });
    } else {
      // Treat an unrecognised arg as a bare hostname to probe directly.
      targets.push({ label: name, hosts: [name] });
    }
  }
  const rows: string[][] = [];
  for (const t of targets) {
    for (const host of t.hosts) {
      const ok = await reachable(host);
      rows.push([t.label, host, ok ? 'reachable' : 'unreachable']);
    }
  }
  printTable(['target', 'host', 'status'], rows);
}

function usage(): void {
  console.log(`vouchr: operator CLI (reads are metadata-only; only \`revoke\` and \`rekey\` mutate)

Usage: vouchr <command> [options]

Commands:
  migrate     Create/upgrade the PostgreSQL schema to this build's version. Run
              ONCE per deploy/upgrade with a role that can create tables; the
              runtime then connects with a DML-only role. Idempotent and safe to
              run concurrently. Prefer VOUCHR_DATABASE_URL over --db (keeps the
              credential URL out of shell history / process args).
  inventory   List stored connections (metadata only; never tokens).
                --team <id>      filter by team
                --provider <id>  filter by provider
  channels    List per-channel config: team, channel, provider, mode, enabled.
                --team <id>      filter by team
  revoke      Break-glass bulk revocation for an incident (delete locally, then
              best-effort upstream revoke; audited, no secrets printed).
                --provider <id>  REQUIRED (refuses to run without it)
                --team <id>      narrow to one team
                --user <id>      narrow to one user's own credentials
                --channel <id>   narrow to one channel's shared credentials
                --yes            actually revoke (default is a dry-run)
                exits non-zero if any LOCAL deletion failed
  doctor      Diagnostics (PASS/FAIL): master key(s), DB reachability, row counts.
                exits non-zero if any check fails
  rekey       Re-encrypt every stored ciphertext under the PRIMARY master key
              (the first VOUCHR_MASTER_KEYS entry). Old rows are decrypted with
              whichever configured key matches; envelope (KMS) rows are skipped.
              Idempotent and safe to interrupt/re-run; prints counts, never secrets.
                --dry-run        classify + count per key id/scheme; write nothing
                exits non-zero if any blob decrypts under NO configured key
  health [provider|host ...]
              Reachability of provider authorize/token hosts (no credentials sent).
              Defaults to built-ins: ${Object.keys(BUILTINS).join(', ')}.
  help        This message.

Store selection (shared with the app):
  --db <url>             PostgreSQL connection string (overrides VOUCHR_DATABASE_URL)
  VOUCHR_DATABASE_URL    PostgreSQL connection string (required; no embedded mode)
  VOUCHR_MASTER_KEY      base64 32-byte key (validated by doctor; loaded by revoke
                         for best-effort upstream token revocation, and by rekey)
  VOUCHR_MASTER_KEYS     comma-separated id:base64key entries; FIRST is the primary
                         (encrypts new writes), the rest decrypt-only (rotation)`);
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  const f = parseFlags(rest);

  switch (cmd) {
    case 'migrate': {
      // The ONLY command that creates/alters tables. Run it once per deploy/upgrade with a
      // schema-owner role; the runtime then connects with a DML-only role. Idempotent and safe to
      // run concurrently (advisory-locked). Prefer VOUCHR_DATABASE_URL over --db so a credential URL
      // stays out of shell history / process args.
      const { version } = await migrate({ databaseUrl: f.values.db });
      console.log(`OK schema migrated to version ${version}`);
      return 0;
    }
    case 'inventory':
    case 'channels': {
      const db = await openDb({ databaseUrl: f.values.db });
      try {
        if (cmd === 'inventory') await cmdInventory(db, f);
        else await cmdChannels(db, f);
      } finally {
        await db.close();
      }
      return 0;
    }
    case 'revoke': {
      const db = await openDb({ databaseUrl: f.values.db });
      try {
        return await cmdRevoke(db, f);
      } finally {
        await db.close();
      }
    }
    case 'rekey': {
      const db = await openDb({ databaseUrl: f.values.db });
      try {
        return await cmdRekey(db, f);
      } finally {
        await db.close();
      }
    }
    case 'doctor':
      return cmdDoctor(f);
    case 'health':
      await cmdHealth(f);
      return 0;
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      usage();
      return 0;
    default:
      console.error(`Unknown command: ${cmd}\n`);
      usage();
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error(`vouchr: ${e?.message ?? e}`);
    process.exit(1);
  });
