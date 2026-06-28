import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { encrypt, open, type EnvelopeProvider } from '../src/core/crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32); // Vouchr master key
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);

/**
 * Mock EnvelopeProvider: the KEK is a local AES-256-GCM key, so wrap = encrypt the DEK under the
 * KEK and unwrap = decrypt it. `unwraps` proves the read path actually calls the provider.
 *
 * A REAL AWS KMS provider (no SDK imported here, core stays dependency-free) looks like:
 *
 *   import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';
 *   const kms = new KMSClient({});
 *   const KEY_ID = process.env.VOUCHR_KMS_KEY_ID!;
 *   const awsEnvelope: EnvelopeProvider = {
 *     // seal() generates its own DEK, so we KMS-Encrypt it to get the wrapped form. (KMS's
 *     // GenerateDataKey, which returns both plaintext + ciphertext DEK in one call, is the
 *     // alternative if you let KMS mint the DEK instead.)
 *     async wrapDataKey(dek) {
 *       const r = await kms.send(new EncryptCommand({ KeyId: KEY_ID, Plaintext: dek }));
 *       return Buffer.from(r.CiphertextBlob!);
 *     },
 *     async unwrapDataKey(wrapped) {
 *       const r = await kms.send(new DecryptCommand({ KeyId: KEY_ID, CiphertextBlob: wrapped }));
 *       return Buffer.from(r.Plaintext!);
 *     },
 *   };
 */
const KEK = randomBytes(32);
let unwraps = 0;
function aesWrap(dek: Buffer): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', KEK, iv);
  const ct = Buffer.concat([c.update(dek), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}
function aesUnwrap(w: Buffer): Buffer {
  const d = createDecipheriv('aes-256-gcm', KEK, w.subarray(0, 12));
  d.setAuthTag(w.subarray(12, 28));
  return Buffer.concat([d.update(w.subarray(28)), d.final()]);
}
const provider: EnvelopeProvider = {
  async wrapDataKey(dek) { return aesWrap(dek); },
  async unwrapDataKey(w) { unwraps++; return aesUnwrap(w); },
};

test('envelope: round-trips through Vault, stores scheme 0x01, invokes unwrap on read', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, {}, provider);
  await vault.upsert(O1, 'github', {
    accessToken: 'tok_env', refreshToken: 'ref_env', scopes: 'repo', expiresAt: null, externalAccount: 'octo',
  });

  const before = unwraps;
  const got = await vault.get(O1, 'github');
  assert.equal(got?.accessToken, 'tok_env');
  assert.equal(got?.refreshToken, 'ref_env');
  assert.ok(unwraps > before, 'provider.unwrapDataKey must be invoked on read');

  // Stored bytes: envelope scheme byte, and never the plaintext.
  const raw = (await db.get('SELECT access_token_enc FROM connection')) as any;
  const buf = Buffer.from(raw.access_token_enc);
  assert.equal(buf[0], 0x01, 'envelope rows begin with the 0x01 scheme byte');
  assert.ok(!buf.toString('utf8').includes('tok_env'), 'ciphertext must not contain the plaintext');
});

test('envelope: local-path rows (no provider) still decrypt under both a local and an envelope vault', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const local = new Vault(db, KEY); // no provider → current behavior
  await local.upsert(O1, 'github', {
    accessToken: 'tok_legacy', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  // The local vault reads its own row (back-compat with today's deploy).
  assert.equal((await local.get(O1, 'github'))?.accessToken, 'tok_legacy');

  // An envelope-enabled vault over the SAME db still reads the legacy row (migration path).
  const env = new Vault(db, KEY, {}, provider);
  assert.equal((await env.get(O1, 'github'))?.accessToken, 'tok_legacy');
});

test('envelope: a legacy blob whose IV starts with 0x01 still decrypts under an envelope vault (fallback)', async () => {
  let blob: Buffer;
  do { blob = encrypt('collision_secret', KEY); } while (blob[0] !== 0x01); // force the 1/256 collision
  assert.equal(await open(blob, KEY, provider), 'collision_secret');
});
