import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintIdentity, verifyIdentity, ReplayGuard, MAX_LIFETIME_MS } from '../src/adapters/http/identity';

const SECRET = 'trust-root';
const who = { teamId: 'T1', userId: 'U1', channel: 'C1' };

test('mintIdentity: produces a token verifyIdentity accepts, preserving the claims', () => {
  const token = mintIdentity({ ...who, threadTs: '123.45' }, SECRET);
  const claims = verifyIdentity(token, SECRET);
  assert.equal(claims.teamId, 'T1');
  assert.equal(claims.userId, 'U1');
  assert.equal(claims.channel, 'C1');
  assert.equal(claims.threadTs, '123.45');
});

test('mintIdentity: each call gets a unique jti (so tokens are not accidental replays)', () => {
  const jtis = new Set(Array.from({ length: 100 }, () => verifyIdentity(mintIdentity(who, SECRET), SECRET).jti));
  assert.equal(jtis.size, 100);
});

test('mintIdentity: exp is clamped to the 5-minute ceiling even if a longer ttl is asked', () => {
  const now = 1_000_000;
  const claims = verifyIdentity(mintIdentity(who, SECRET, 60 * 60_000, now), SECRET, { now });
  assert.equal(claims.exp, now + MAX_LIFETIME_MS); // not now + 1h
});

test('mintIdentity: default ttl is ~60s', () => {
  const now = 1_000_000;
  const claims = verifyIdentity(mintIdentity(who, SECRET, undefined, now), SECRET, { now });
  assert.equal(claims.exp, now + 60_000);
});

test('mintIdentity: a token is single-use against a replay guard', () => {
  const token = mintIdentity(who, SECRET);
  const replay = new ReplayGuard();
  verifyIdentity(token, SECRET, { replay });                    // first use ok
  assert.throws(() => verifyIdentity(token, SECRET, { replay }), /replayed jti/); // second rejected
});
