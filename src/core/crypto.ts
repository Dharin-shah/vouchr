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
 * AES-256-GCM with the master key directly. Layout: iv(12) | tag(16) | ciphertext.
 * M2 upgrades this to envelope encryption (per-connection data key wrapped by a
 * KMS/Vault root key) — the call sites here do not change when it does.
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

/** PKCE code challenge: base64url(SHA-256(verifier)). */
export function sha256base64url(input: string): string {
  return createHash('sha256').update(input).digest('base64url');
}
