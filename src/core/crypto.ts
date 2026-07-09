import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

const ALGO = 'aes-256-gcm';

/**
 * Master-key id charset (SEC-4): ids are operator-chosen labels that end up inside ciphertext
 * headers, error messages, and `vouchr rekey` output, so they are constrained to a safe set at
 * parse time — an id that fails this is rejected before it is stored or printed anywhere.
 */
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,32}$/;

/**
 * The set of master keys a deployment knows (#115).
 * - `primary` encrypts every NEW write. `id === null` is the id-less `VOUCHR_MASTER_KEY` and
 *   produces today's scheme-0 bytes unchanged; a named id produces keyed (scheme 0x02) bytes.
 * - `byId` is the exact-lookup table for keyed rows: a stored key id routes to precisely one key,
 *   and an unknown id fails closed (never a try-all loop across unrelated keys).
 * - `legacy` is the trial-order candidate list for id-less scheme-0 rows: the id-less key first,
 *   then the listed keys, so "move the old key into VOUCHR_MASTER_KEYS under an id" keeps old
 *   rows readable. Trying is safe: GCM's auth tag makes a wrong key fail loudly, never return
 *   wrong plaintext.
 */
export interface Keyring {
  primary: { id: string | null; key: Buffer };
  byId: ReadonlyMap<string, Buffer>;
  legacy: readonly { id: string | null; key: Buffer }[];
}

/** Every crypto entry point accepts this: a bare Buffer is exactly today's single master key. */
export type MasterKeys = Buffer | Keyring;

/** Normalize the `Buffer | Keyring` union. A bare Buffer = one id-less key (today's behavior). */
export function toKeyring(k: MasterKeys): Keyring {
  if (!Buffer.isBuffer(k)) return k;
  return { primary: { id: null, key: k }, byId: new Map(), legacy: [{ id: null, key: k }] };
}

function decodeKey(b64: string, label: string): Buffer {
  const key = Buffer.from(b64, 'base64');
  if (key.length !== 32) throw new Error(`${label} must decode to exactly 32 bytes`);
  return key;
}

/**
 * Load the full keyring from env (#115). Two variables, both optional but at least one required:
 * - `VOUCHR_MASTER_KEYS` = comma-separated `id:base64key` entries. The FIRST entry encrypts all
 *   new writes; every entry is a decryption candidate. Ids must match `[A-Za-z0-9._-]{1,32}`.
 * - `VOUCHR_MASTER_KEY` = the id-less single key (today's variable). Alone, behavior is
 *   bit-for-bit unchanged; alongside `VOUCHR_MASTER_KEYS` it remains the designated decryption
 *   key for old scheme-0 rows while the listed primary takes over new writes.
 * Malformed entries fail closed with errors that never echo key material (a swapped `key:id`
 * would otherwise leak the key into logs).
 */
export function loadKeyring(env: Record<string, string | undefined> = process.env): Keyring {
  const single = env.VOUCHR_MASTER_KEY;
  const idless = single ? decodeKey(single, 'VOUCHR_MASTER_KEY') : null;

  const listed: { id: string; key: Buffer }[] = [];
  const multi = env.VOUCHR_MASTER_KEYS;
  if (multi && multi.trim()) {
    const entries = multi.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
    for (let i = 0; i < entries.length; i++) {
      const colon = entries[i].indexOf(':');
      // Errors below cite the entry POSITION, never its content: if the operator swapped id and
      // key, the "id" is key material and must not reach stderr/logs (SEC-1).
      if (colon <= 0) {
        throw new Error(`VOUCHR_MASTER_KEYS entry ${i + 1} must be 'id:base64key'`);
      }
      const id = entries[i].slice(0, colon);
      if (!KEY_ID_RE.test(id)) {
        throw new Error(
          `VOUCHR_MASTER_KEYS entry ${i + 1} has an invalid key id (allowed: letters, digits, '.', '_', '-'; 1-32 chars)`,
        );
      }
      if (listed.some((e) => e.id === id)) {
        throw new Error(`VOUCHR_MASTER_KEYS lists key id '${id}' twice`);
      }
      listed.push({ id, key: decodeKey(entries[i].slice(colon + 1), `VOUCHR_MASTER_KEYS entry '${id}'`) });
    }
  }

  if (!idless && !listed.length) {
    throw new Error(
      'VOUCHR_MASTER_KEY (or VOUCHR_MASTER_KEYS) is required (base64-encoded 32 bytes). Generate with: openssl rand -base64 32',
    );
  }
  return {
    primary: listed.length ? { id: listed[0].id, key: listed[0].key } : { id: null, key: idless! },
    byId: new Map(listed.map((e) => [e.id, e.key])),
    legacy: [...(idless ? [{ id: null as string | null, key: idless }] : []), ...listed],
  };
}

/**
 * AES-256-GCM at the storage boundary — the direct (non-KMS) path. Two on-disk layouts:
 * - scheme-0 (id-less key, today's format, NO version byte):  iv(12) | tag(16) | ciphertext
 * - scheme 0x02 (keyed, #115):  0x02 | idLen(1) | keyId | iv(12) | tag(16) | ciphertext
 * A bare Buffer (or a keyring whose primary is id-less) writes scheme-0, so existing deployments
 * stay byte-for-byte unchanged. The optional envelope path (per-secret data key wrapped by a
 * KMS/Vault KEK) lives in seal()/open() with an EnvelopeProvider; these stay the direct path.
 */
export function encrypt(plaintext: string, keys: MasterKeys): Buffer {
  const { primary } = toKeyring(keys);
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, primary.key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  if (primary.id === null) return Buffer.concat([iv, tag, ct]); // legacy direct, unprefixed
  if (!KEY_ID_RE.test(primary.id)) throw new Error('invalid master key id (allowed: [A-Za-z0-9._-]{1,32})');
  const idBytes = Buffer.from(primary.id, 'utf8');
  return Buffer.concat([Buffer.from([SCHEME_KEYED, idBytes.length]), idBytes, iv, tag, ct]);
}

/** Inner GCM decrypt of an unprefixed iv|tag|ct body. */
function decryptBody(body: Buffer, key: Buffer): string {
  const iv = body.subarray(0, 12);
  const tag = body.subarray(12, 28);
  const ct = body.subarray(28);
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** How `vouchr rekey` and decrypt() see a direct-path blob: which scheme/key produced it, or why not. */
export type DirectDecrypt =
  | { ok: true; plaintext: string; scheme: 0 | 2; keyId: string | null }
  | { ok: false; reason: 'unknown-key-id'; keyId: string }
  | { ok: false; reason: 'maybe-envelope' }
  | { ok: false; reason: 'undecryptable' };

/** Trial-decrypt an id-less scheme-0 blob against the legacy candidates, in order. */
function tryLegacy(blob: Buffer, ring: Keyring): { plaintext: string; keyId: string | null } | null {
  for (const cand of ring.legacy) {
    try {
      return { plaintext: decryptBody(blob, cand.key), keyId: cand.id };
    } catch {
      /* wrong candidate: GCM refused; try the next */
    }
  }
  return null;
}

/**
 * Decrypt a direct-path blob and report WHICH scheme + key succeeded (never throws). This is the
 * one place the scheme discrimination lives; decrypt() and `vouchr rekey` are thin layers on it.
 *
 * Routing (fail-closed, mirroring open()'s 0x01 handling so the legacy ambiguity is not widened):
 * - First byte 0x02 → parse as keyed. A stored key id routes to exactly one key; an id missing
 *   from the ring is a hard failure naming the id — NOT a try-all across unrelated keys. Because
 *   a legacy IV also begins with 0x02 once in 256 rows, any keyed-path failure first probes the
 *   scheme-0 candidates; only if no probe authenticates does the keyed failure stand.
 * - Anything else → scheme-0: try the legacy candidates in order. A blob that fails all of them
 *   and begins with 0x01 is (almost certainly) a KMS envelope row → 'maybe-envelope'.
 * Nothing is ever returned unless a GCM decrypt authenticated.
 */
export function tryDecryptDirect(blob: Buffer, keys: MasterKeys): DirectDecrypt {
  const ring = toKeyring(keys);
  if (blob.length > 2 && blob[0] === SCHEME_KEYED) {
    const idLen = blob[1];
    const body = blob.subarray(2 + idLen);
    let keyedFailure: DirectDecrypt | null = null;
    if (idLen >= 1 && idLen <= 32 && body.length >= 28) {
      const keyId = blob.subarray(2, 2 + idLen).toString('utf8');
      if (KEY_ID_RE.test(keyId)) {
        const key = ring.byId.get(keyId);
        if (!key) {
          keyedFailure = { ok: false, reason: 'unknown-key-id', keyId };
        } else {
          try {
            return { ok: true, plaintext: decryptBody(body, key), scheme: 2, keyId };
          } catch {
            keyedFailure = { ok: false, reason: 'undecryptable' }; // known key, GCM refused: tamper/corruption
          }
        }
      }
    }
    // Keyed parse/decrypt failed. Probe the 1-in-256 legacy collision (an IV that begins 0x02)
    // before surfacing the keyed failure; a header that never parsed falls through to legacy too.
    const legacy = tryLegacy(blob, ring);
    if (legacy) return { ok: true, plaintext: legacy.plaintext, scheme: 0, keyId: legacy.keyId };
    return keyedFailure ?? { ok: false, reason: 'undecryptable' };
  }
  const legacy = tryLegacy(blob, ring);
  if (legacy) return { ok: true, plaintext: legacy.plaintext, scheme: 0, keyId: legacy.keyId };
  return blob[0] === SCHEME_ENVELOPE ? { ok: false, reason: 'maybe-envelope' } : { ok: false, reason: 'undecryptable' };
}

export function decrypt(blob: Buffer, keys: MasterKeys): string {
  // Bit-for-bit back-compat: a bare single Buffer takes the raw single-key path, surfacing node's
  // own GCM error exactly as before (unless the blob names a key id, where the routed error is
  // strictly more useful).
  if (Buffer.isBuffer(keys) && blob[0] !== SCHEME_KEYED) return decryptBody(blob, keys);
  const r = tryDecryptDirect(blob, keys);
  if (r.ok) return r.plaintext;
  if (r.reason === 'unknown-key-id') {
    throw new Error(
      `vouchr: ciphertext was encrypted under master key id '${r.keyId}', which is not configured — add it to VOUCHR_MASTER_KEYS to decrypt (or run 'vouchr rekey' before removing keys)`,
    );
  }
  throw new Error('vouchr: ciphertext does not decrypt under any configured master key');
}

/**
 * Operator-supplied KMS/Vault binding for envelope encryption (like the `Resolvers` pattern).
 * `wrapDataKey` encrypts a freshly generated 32-byte data key (DEK) under an external
 * key-encryption key (KEK); `unwrapDataKey` reverses it. Both are async: a real KMS is a network
 * call. Implementations MUST NOT log the DEK or the KEK. Core deliberately ships no AWS SDK
 * dependency; a real AWS KMS impl (GenerateDataKey/Decrypt) is sketched in test/envelope.test.ts.
 */
export interface EnvelopeProvider {
  wrapDataKey(dek: Buffer): Promise<Buffer>;
  unwrapDataKey(wrapped: Buffer): Promise<Buffer>;
}

/** Leading byte of the envelope format. Legacy rows have NO version byte (see open()). */
const SCHEME_ENVELOPE = 0x01;
/** Leading byte of the keyed direct format (#115): 0x02 | idLen(1) | keyId | iv | tag | ct. */
const SCHEME_KEYED = 0x02;

/**
 * Encrypt a secret for storage, async because the envelope path makes a KMS call.
 *
 * With an `envelope` provider: scheme 0x01 envelope encryption. A fresh random DEK encrypts the
 * secret; the DEK is wrapped by the KEK and stored alongside the ciphertext. Layout:
 *   0x01 | dekLen(2, big-endian) | wrappedDek | iv(12) | tag(16) | ciphertext
 * where `iv|tag|ciphertext` is the secret under the DEK (the same inner layout as encrypt()).
 *
 * Without a provider: the direct format under the ring's primary key — scheme-0 when the primary
 * is the id-less master key (a local deploy's bytes stay byte-for-byte identical to today's),
 * scheme 0x02 when `VOUCHR_MASTER_KEYS` names one.
 */
export async function seal(plaintext: string, keys: MasterKeys, envelope?: EnvelopeProvider): Promise<Buffer> {
  if (!envelope) return encrypt(plaintext, keys); // direct path (scheme-0 or keyed per the primary)
  const dek = randomBytes(32);
  try {
    const body = encrypt(plaintext, dek); // iv|tag|ct under the fresh per-secret DEK
    const wrapped = await envelope.wrapDataKey(dek);
    const len = Buffer.alloc(2);
    len.writeUInt16BE(wrapped.length); // wrapped DEKs are small (KMS ~184B); 16 bits is ample
    return Buffer.concat([Buffer.from([SCHEME_ENVELOPE]), len, wrapped, body]);
  } finally {
    dek.fill(0); // scrub the plaintext DEK; the wrapped copy is all that persists
  }
}

/**
 * Decrypt a stored secret, dispatching on format so existing rows keep working.
 *
 * Detection (unambiguous, fail-closed):
 *  - First byte 0x02 → the keyed direct scheme (#115), which routes by the STORED key id whether
 *    or not an envelope provider is configured (a deploy that later enables KMS must keep reading
 *    its keyed rows). tryDecryptDirect() owns that routing, including the 1-in-256 legacy-IV
 *    collision probe.
 *  - No provider → otherwise ALWAYS legacy. A no-provider deploy never wrote envelope rows, so
 *    the bytes are the unprefixed iv|tag|ct format and decrypt under the scheme-0 candidates,
 *    exactly as the current code does. This is what keeps a local deploy reading its own data.
 *  - Provider + first byte != 0x01 → legacy (envelope rows always start 0x01).
 *  - Provider + first byte == 0x01 → the envelope path. On failure, we DON'T blindly return the
 *    legacy decrypt: that masked a transient KMS unwrap outage behind an opaque GCM "bad data"
 *    error. Instead we probe the legacy decrypt only to disambiguate the 1-in-256 case of a legacy
 *    IV that happens to begin with 0x01 (a genuine non-envelope row, relevant when migrating a
 *    local deploy to envelope): if that probe SUCCEEDS the row really was legacy, so return it; if
 *    it FAILS the row was a true envelope row, so re-raise the ENVELOPE error — the clear KMS/tamper
 *    message, never the legacy GCM one. Either way nothing is returned unless a decrypt authenticated.
 */
export async function open(blob: Buffer, keys: MasterKeys, envelope?: EnvelopeProvider, onUnwrap?: () => void): Promise<string> {
  if (!envelope || blob[0] !== SCHEME_ENVELOPE) return decrypt(blob, keys);
  let envErr: unknown;
  try {
    const dekLen = blob.readUInt16BE(1);
    const wrapped = blob.subarray(3, 3 + dekLen);
    const body = blob.subarray(3 + dekLen);
    const dek = await envelope.unwrapDataKey(wrapped);
    onUnwrap?.(); // a real KMS/Vault decrypt happened; count it for observability (never logs the DEK)
    try {
      return decryptBody(body, dek);
    } finally {
      dek.fill(0); // scrub the unwrapped DEK once we're done with it
    }
  } catch (e) {
    envErr = e; // KMS unwrap outage, envelope tamper, OR a legacy 0x01-IV collision — disambiguate below.
  }
  const probe = tryDecryptDirect(blob, keys); // recovers a genuine legacy row whose IV collided with 0x01.
  if (probe.ok) return probe.plaintext;
  throw envErr; // not legacy → this was a real envelope row; surface its clear error, not the GCM one.
}

/** Coerce a DB BYTEA/BLOB value to a Buffer. Postgres returns a Buffer already; SQLite may hand
 *  back other shapes. A no-op guard shared by the Vault and the installation store. */
export function toBuffer(v: unknown): Buffer {
  return Buffer.isBuffer(v) ? v : Buffer.from(v as any);
}

/** PKCE code challenge: base64url(SHA-256(verifier)). */
export function sha256base64url(input: string): string {
  return createHash('sha256').update(input).digest('base64url');
}
