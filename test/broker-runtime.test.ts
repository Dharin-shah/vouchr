import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';
import { DbReplayStore } from '../src/adapters/http/replayStore';
import { kmsEnvelope, type KmsClientLike } from '../src/adapters/kms';

// ── T4: DbReplayStore (cluster-wide single-use jti) ──────────────────────────

test('DbReplayStore: a jti is single-use across two stores sharing the DB (multi-replica)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const a = new DbReplayStore(db); // simulate two broker replicas...
  const b = new DbReplayStore(db); // ...backed by one shared table
  const exp = Date.now() + 60_000;

  assert.equal(await a.use('jti-1', exp), true);   // first use on "pod A" -> fresh
  assert.equal(await b.use('jti-1', exp), false);  // replay on "pod B" -> rejected
  assert.equal(await a.use('jti-1', exp), false);  // and again on A
  assert.equal(await b.use('jti-2', exp), true);   // a distinct jti is independent
});

test('DbReplayStore: concurrent use of the same jti admits exactly one', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const store = new DbReplayStore(db);
  const exp = Date.now() + 60_000;
  const results = await Promise.all(Array.from({ length: 8 }, () => store.use('race', exp)));
  assert.equal(results.filter(Boolean).length, 1, 'exactly one caller may claim a jti');
});

// ── T5: kmsEnvelope (at-rest DEK wrapping, injectable client) ─────────────────

// A fake, reversible KMS client — proves the envelope wiring without any AWS SDK.
function fakeKms(): KmsClientLike {
  return {
    encrypt: async (keyId, plaintext) => Buffer.concat([Buffer.from(`wrap:${keyId}:`), plaintext]),
    decrypt: async (ciphertext) => ciphertext.subarray(ciphertext.indexOf(0x3a, 5) + 1),
  };
}

test('kmsEnvelope: wraps and unwraps a data key', async () => {
  const env = kmsEnvelope('key-1', fakeKms());
  const dek = randomBytes(32);
  const wrapped = await env.wrapDataKey(dek);
  assert.ok(wrapped.toString('utf8').startsWith('wrap:key-1:'));
  assert.deepEqual(await env.unwrapDataKey(wrapped), dek);
});

test('kmsEnvelope: a Vault write round-trips through envelope encryption (scheme 0x01)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, randomBytes(32), {}, kmsEnvelope('key-1', fakeKms()));
  const owner = userOwner({ enterpriseId: null, teamId: 'T', userId: 'U' });
  await vault.upsert(owner, 'confluence', { accessToken: 'sk-secret', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const got = await vault.get(owner, 'confluence');
  assert.equal(got?.accessToken, 'sk-secret'); // encrypted with a KMS-wrapped DEK, decrypted on read
});
