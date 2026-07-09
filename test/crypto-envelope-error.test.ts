import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { encrypt, seal, open, type EnvelopeProvider } from '../src/core/crypto';
import { isPostgresUrl } from '../src/core/options';

const KEY = randomBytes(32); // Vouchr master key
const KEK = randomBytes(32); // envelope KEK (would be a KMS/Vault key in prod)

// A working local-AES envelope provider (same shape as test/envelope.test.ts): wrap = encrypt the
// DEK under the KEK, unwrap = decrypt it. Used to mint a genuine envelope row.
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
const working: EnvelopeProvider = {
  async wrapDataKey(dek) { return aesWrap(dek); },
  async unwrapDataKey(w) { return aesUnwrap(w); },
};

// A provider whose KMS is down: unwrap always throws a distinctive, operator-legible error.
const KMS_DOWN = 'kms unwrapDataKey failed: endpoint unreachable';
const outage: EnvelopeProvider = {
  async wrapDataKey(dek) { return aesWrap(dek); },
  async unwrapDataKey() { throw new Error(KMS_DOWN); },
};

test('legacy (non-envelope) row still decrypts with an envelope provider set', async () => {
  const blob = encrypt('tok_legacy', KEY); // unprefixed iv|tag|ct — a pre-envelope row
  assert.equal(await open(blob, KEY, working), 'tok_legacy');
});

test('envelope row whose provider throws on unwrap propagates the clear error and yields no plaintext', async () => {
  const blob = await seal('super_secret', KEY, working); // genuine 0x01 envelope row
  assert.equal(blob[0], 0x01);

  let leaked: unknown;
  await assert.rejects(
    async () => { leaked = await open(blob, KEY, outage); },
    (err: Error) => {
      // The KMS message must survive, not be masked behind the legacy GCM "bad data" error.
      assert.equal(err.message, KMS_DOWN);
      assert.doesNotMatch(err.message, /auth|gcm|bad decrypt/i);
      return true;
    },
  );
  assert.equal(leaked, undefined, 'no plaintext may be produced on unwrap failure');
});

test('envelope unwrap outage error survives a multi-key keyring (probe must not mask it)', async () => {
  // #115: with several direct keys configured, the legacy disambiguation probe tries each of
  // them — none may authenticate a true envelope row, and the clear KMS error must still win.
  const ring = {
    primary: { id: 'k2025' as string | null, key: randomBytes(32) },
    byId: new Map([['k2025', randomBytes(32)]]),
    legacy: [{ id: null as string | null, key: KEY }, { id: 'k2025' as string | null, key: randomBytes(32) }],
  };
  const blob = await seal('super_secret', KEY, working);
  await assert.rejects(() => open(blob, ring, outage), (err: Error) => {
    assert.equal(err.message, KMS_DOWN);
    return true;
  });
});

test('isPostgresUrl classifies postgres/postgresql vs sqlite/undefined', () => {
  assert.equal(isPostgresUrl('postgres://u:p@h:5432/db'), true);
  assert.equal(isPostgresUrl('postgresql://u:p@h:5432/db'), true);
  assert.equal(isPostgresUrl('sqlite:///vouchr.db'), false);
  assert.equal(isPostgresUrl('vouchr.db'), false);
  assert.equal(isPostgresUrl(undefined), false);
  assert.equal(isPostgresUrl(''), false);
});
