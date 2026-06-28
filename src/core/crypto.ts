import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

const ALGO = 'aes-256-gcm';

/** Load the 32-byte root key from env. Generate one with: openssl rand -base64 32 */
export function loadMasterKey(): Buffer {
  const b64 = process.env.VOUCHR_MASTER_KEY;
  if (!b64) {
    throw new Error(
      'VOUCHR_MASTER_KEY is required (base64-encoded 32 bytes). Generate with: openssl rand -base64 32',
    );
  }
  const key = Buffer.from(b64, 'base64');
  if (key.length !== 32) throw new Error('VOUCHR_MASTER_KEY must decode to exactly 32 bytes');
  return key;
}

/**
 * AES-256-GCM with the master key directly: the unversioned scheme-0 path. Layout:
 * iv(12) | tag(16) | ciphertext. The optional envelope path (per-secret data key wrapped
 * by a KMS/Vault KEK) lives in seal()/open() with an EnvelopeProvider; these stay the direct path.
 */
export function encrypt(plaintext: string, key: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

export function decrypt(blob: Buffer, key: Buffer): string {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/**
 * Operator-supplied KMS/Vault binding for envelope encryption (like the `Resolvers` pattern).
 * `wrapDataKey` encrypts a freshly generated 32-byte data key (DEK) under an external
 * key-encryption key (KEK); `unwrapDataKey` reverses it. Both are async — a real KMS is a network
 * call. Implementations MUST NOT log the DEK or the KEK. Core deliberately ships no AWS SDK
 * dependency; a real AWS KMS impl (GenerateDataKey/Decrypt) is sketched in test/envelope.test.ts.
 */
export interface EnvelopeProvider {
  wrapDataKey(dek: Buffer): Promise<Buffer>;
  unwrapDataKey(wrapped: Buffer): Promise<Buffer>;
}

/** Leading byte of the envelope format. Legacy rows have NO version byte (see open()). */
const SCHEME_ENVELOPE = 0x01;

/**
 * Encrypt a secret for storage, async because the envelope path makes a KMS call.
 *
 * With an `envelope` provider: scheme 0x01 envelope encryption. A fresh random DEK encrypts the
 * secret; the DEK is wrapped by the KEK and stored alongside the ciphertext. Layout:
 *   0x01 | dekLen(2, big-endian) | wrappedDek | iv(12) | tag(16) | ciphertext
 * where `iv|tag|ciphertext` is the secret under the DEK (the same inner layout as encrypt()).
 *
 * Without a provider: the legacy direct format (plain `encrypt`, NO version byte), so a local
 * deploy's bytes stay byte-for-byte identical to today's.
 */
export async function seal(plaintext: string, key: Buffer, envelope?: EnvelopeProvider): Promise<Buffer> {
  if (!envelope) return encrypt(plaintext, key); // legacy direct-to-master, unprefixed
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
 *  - No provider  → ALWAYS legacy. A no-provider deploy never wrote envelope rows, so the bytes
 *    are the unprefixed iv|tag|ct format and decrypt directly under the master key — exactly as
 *    the current code does. This is what keeps a local deploy reading its own existing data.
 *  - Provider + first byte != 0x01 → legacy (envelope rows always start 0x01).
 *  - Provider + first byte == 0x01 → try the envelope path; on ANY failure fall back to legacy.
 *    The fallback covers the 1-in-256 case of a legacy random IV that happens to begin with 0x01
 *    (relevant only when migrating an existing local deploy to envelope). Tampered/corrupt data
 *    still fails closed: the legacy attempt's GCM tag check then throws too.
 */
export async function open(blob: Buffer, key: Buffer, envelope?: EnvelopeProvider): Promise<string> {
  if (!envelope || blob[0] !== SCHEME_ENVELOPE) return decrypt(blob, key);
  try {
    const dekLen = blob.readUInt16BE(1);
    const wrapped = blob.subarray(3, 3 + dekLen);
    const body = blob.subarray(3 + dekLen);
    const dek = await envelope.unwrapDataKey(wrapped);
    try {
      return decrypt(body, dek);
    } finally {
      dek.fill(0); // scrub the unwrapped DEK once we're done with it
    }
  } catch {
    // Not a real envelope row (legacy IV starting 0x01) — or genuinely bad data. Legacy decrypt
    // either recovers it or throws, so corruption/tampering still fails closed.
    return decrypt(blob, key);
  }
}

/** PKCE code challenge: base64url(SHA-256(verifier)). */
export function sha256base64url(input: string): string {
  return createHash('sha256').update(input).digest('base64url');
}
