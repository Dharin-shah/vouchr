import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  signIdentity, mintIdentity, verifyIdentity, ReplayGuard, MAX_LIFETIME_MS,
  loadIdentityConfig, normalizeIdentityConfig, assertStrongIdentitySecret, identityKid, IDENTITY_SKEW_MS,
  type IdentityConfig, type IdentityClaims,
} from '../src/adapters/http/identity';

const SECRET = 'trust-root';
const who = { teamId: 'T1', userId: 'U1', channel: 'C1' };

// ── #212 deployment-bound (IdentityConfig) mode ────────────────────────────────────────────────────
const ACTIVE = 'active-identity-secret-32-bytes-or-more!!';
const PREV = 'previous-identity-secret-32-bytes-or-more!';
const cfg = (over: Partial<IdentityConfig> = {}): IdentityConfig => ({
  issuer: 'vouchr', audience: 'deploy-A', keys: [{ kid: identityKid(ACTIVE), secret: ACTIVE }], ...over,
});

test('#212 config mode: a deployment-bound token round-trips with iss/aud/iat/kid set + verified', () => {
  const now = 1_000_000;
  const claims = verifyIdentity(mintIdentity(who, cfg(), 60_000, now), cfg(), { now });
  assert.equal(claims.iss, 'vouchr');
  assert.equal(claims.aud, 'deploy-A');
  assert.equal(claims.iat, now);
  assert.equal(claims.kid, identityKid(ACTIVE));
});

test('#194 identity minter round-trips the signed enterprise offboard target', () => {
  const now = 1_000_000;
  const claims = verifyIdentity(mintIdentity({
    ...who,
    enterpriseId: 'E1',
    isAdmin: true,
    offboardTargetUserId: 'U_TARGET',
  }, cfg(), 60_000, now), cfg(), { now });
  assert.equal(claims.offboardTargetUserId, 'U_TARGET');
});

test('#212 normalizeIdentityConfig: rejects malformed, ambiguous, weak, and non-canonical config', () => {
  assert.throws(() => normalizeIdentityConfig(null as any), /plain object/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), extra: true } as any), /unknown field/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), skewMs: 0 } as any), /unknown field/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), issuer: '' }), /issuer/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), audience: ' deploy-A' }), /audience/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), audience: 'a'.repeat(257) }), /audience/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), audience: 'REPLACE_ME-vouchr-production' }), /placeholder/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), keys: [] }), /one active key/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), keys: Array(1) } as any), /dense array/);
  const keysWithExtra = [{ kid: identityKid(ACTIVE), secret: ACTIVE }];
  (keysWithExtra as any).extra = true;
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), keys: keysWithExtra }), /dense array/);
  assert.throws(() => normalizeIdentityConfig({
    ...cfg(),
    keys: [
      { kid: identityKid(ACTIVE), secret: ACTIVE },
      { kid: identityKid(PREV), secret: PREV },
      { kid: identityKid(`${PREV}!`), secret: `${PREV}!` },
    ],
  }), /at most one previous/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), keys: [{ kid: identityKid('short'), secret: 'short' }] }), /at least 32/);
  assert.throws(() => normalizeIdentityConfig({ ...cfg(), keys: [{ kid: 'not-canonical', secret: ACTIVE }] }), /canonical fingerprint/);
  assert.throws(() => normalizeIdentityConfig({
    ...cfg(), keys: [{ kid: identityKid(ACTIVE), secret: ACTIVE }, { kid: identityKid(ACTIVE), secret: ACTIVE }],
  }), /must be distinct/);
});

test('#212 normalizeIdentityConfig: returns an immutable defensive snapshot', () => {
  const raw = cfg() as any;
  const normalized = normalizeIdentityConfig(raw);
  raw.audience = 'mutated-deployment';
  raw.keys[0].secret = PREV;

  assert.equal(normalized.audience, 'deploy-A');
  assert.equal(normalized.keys[0].secret, ACTIVE);
  assert.ok(Object.isFrozen(normalized));
  assert.ok(Object.isFrozen(normalized.keys));
  assert.ok(Object.isFrozen(normalized.keys[0]));
  assert.throws(() => { (normalized.keys as any).push({ kid: identityKid(PREV), secret: PREV }); }, TypeError);
  assert.doesNotThrow(() => verifyIdentity(mintIdentity(who, normalized), normalized));
});

test('#212 config mode: a token minted for one deployment is rejected by another (audience binding)', () => {
  const token = mintIdentity(who, cfg({ audience: 'deploy-A' }));
  assert.throws(() => verifyIdentity(token, cfg({ audience: 'deploy-B' })), /wrong audience/);
});

test('#212 config mode: a wrong issuer is rejected', () => {
  const token = mintIdentity(who, cfg({ issuer: 'someone-else' }));
  assert.throws(() => verifyIdentity(token, cfg({ issuer: 'vouchr' })), /wrong issuer/);
});

test('#212 config mode: an unknown kid (rotated-away key) is rejected before signature work', () => {
  // Token signed by a key whose kid is not in the verifier's key set.
  const token = mintIdentity(who, cfg({ keys: [{ kid: identityKid(PREV), secret: PREV }] }));
  assert.throws(() => verifyIdentity(token, cfg()), /unknown kid/); // verifier only knows ACTIVE
});

test('#212 config mode: a future-issued token (beyond skew) is rejected; within skew it passes', () => {
  const now = 1_000_000;
  // iat is stamped at mint time; verify at an EARLIER now to simulate a token from a fast clock.
  const token = mintIdentity(who, cfg(), 60_000, now);
  assert.throws(() => verifyIdentity(token, cfg(), { now: now - IDENTITY_SKEW_MS - 1_000 }), /issued in the future/);
  assert.doesNotThrow(() => verifyIdentity(token, cfg(), { now: now - IDENTITY_SKEW_MS + 1_000 })); // within skew
});

test('#212 config mode: an expired token within skew still passes; past skew is rejected', () => {
  const now = 1_000_000;
  const token = mintIdentity(who, cfg(), 60_000, now);
  const justExpired = now + 60_000 + IDENTITY_SKEW_MS - 1_000; // exp is now+60s; still within skew
  assert.doesNotThrow(() => verifyIdentity(token, cfg(), { now: justExpired }));
  assert.throws(() => verifyIdentity(token, cfg(), { now: now + 60_000 + IDENTITY_SKEW_MS + 1_000 }), /expired/);
});

test('#212 config mode: rolling rotation — a previous-key token verifies during overlap, fails after drop', () => {
  // Minter still signs with PREV (the old active) while the broker has rotated: new active + prev overlap.
  const oldToken = mintIdentity(who, cfg({ keys: [{ kid: identityKid(PREV), secret: PREV }] }));
  const overlap = cfg({ keys: [{ kid: identityKid(ACTIVE), secret: ACTIVE }, { kid: identityKid(PREV), secret: PREV }] });
  assert.doesNotThrow(() => verifyIdentity(oldToken, overlap)); // accepted during the overlap window
  // After the operator drops the previous key, the same token no longer verifies (unknown kid).
  assert.throws(() => verifyIdentity(oldToken, cfg()), /unknown kid/);
});

test('#212 config mode: a jti replay is rejected (single-use) just like legacy mode', () => {
  const token = mintIdentity(who, cfg());
  const replay = new ReplayGuard();
  verifyIdentity(token, cfg(), { replay });
  assert.throws(() => verifyIdentity(token, cfg(), { replay }), /replayed jti/);
});

test('#212 config mode: a jti stays single-use through the whole skew window (no prune-then-replay)', () => {
  // The token is acceptable in [exp, exp+skew) under clock skew, so the replay record must survive that
  // window even though the guard prunes on use(). Without storing the exp+skew horizon, a prune here
  // would evict the jti and the second use would be (wrongly) accepted.
  const now = 1_000_000;
  const token = mintIdentity(who, cfg(), 60_000, now); // exp = now + 60_000
  const replay = new ReplayGuard();
  verifyIdentity(token, cfg(), { replay, now }); // consumed
  const inSkewWindow = now + 60_000 + IDENTITY_SKEW_MS - 1_000; // past exp, still within skew → acceptable
  assert.throws(() => verifyIdentity(token, cfg(), { replay, now: inSkewWindow }), /replayed jti/);
});

test('#212 assertStrongIdentitySecret: rejects short, placeholder, and repeated-pattern material', () => {
  assert.throws(() => assertStrongIdentitySecret('short'), /at least 32 bytes/);
  assert.throws(() => assertStrongIdentitySecret(' '.repeat(32)), /at least 32 bytes/);
  assert.throws(() => assertStrongIdentitySecret('ChangeMe'), /placeholder/);
  assert.throws(() => assertStrongIdentitySecret('abcd'.repeat(8)), /obvious repeated pattern/);
  assert.doesNotThrow(() => assertStrongIdentitySecret(ACTIVE));
});

test('#212 repeated-key rejection never echoes the supplied key', () => {
  const repeated = 'abcd'.repeat(8);
  assert.throws(
    () => normalizeIdentityConfig({ ...cfg(), keys: [{ kid: identityKid(repeated), secret: repeated }] }),
    (error: Error) => error.message.includes('obvious repeated pattern') && !error.message.includes(repeated),
  );
});

test('#212 loadIdentityConfig: builds a config; fails closed on weak secret / missing deployment id / reuse / prev==active', () => {
  const good = loadIdentityConfig({ VOUCHR_IDENTITY_SECRET: ACTIVE, VOUCHR_DEPLOYMENT_ID: 'deploy-A' } as any);
  assert.equal(good.audience, 'deploy-A');
  assert.equal(good.issuer, 'vouchr');
  assert.equal(good.keys[0].kid, identityKid(ACTIVE));
  // previous key adds a second verify candidate
  const rotated = loadIdentityConfig({ VOUCHR_IDENTITY_SECRET: ACTIVE, VOUCHR_IDENTITY_SECRET_PREVIOUS: PREV, VOUCHR_DEPLOYMENT_ID: 'deploy-A' } as any);
  assert.deepEqual(rotated.keys.map((k) => k.kid), [identityKid(ACTIVE), identityKid(PREV)]);
  assert.throws(() => loadIdentityConfig({ VOUCHR_IDENTITY_SECRET: 'short', VOUCHR_DEPLOYMENT_ID: 'd' } as any), /at least 32 bytes/);
  assert.throws(() => loadIdentityConfig({ VOUCHR_IDENTITY_SECRET: ACTIVE } as any), /VOUCHR_DEPLOYMENT_ID/);
  assert.throws(() => loadIdentityConfig({ VOUCHR_IDENTITY_SECRET: ACTIVE, VOUCHR_IDENTITY_SECRET_PREVIOUS: ACTIVE, VOUCHR_DEPLOYMENT_ID: 'd' } as any), /PREVIOUS must differ/);
  assert.throws(() => loadIdentityConfig({ VOUCHR_IDENTITY_SECRET: ACTIVE, VOUCHR_DEPLOYMENT_ID: 'd' } as any, [ACTIVE]), /distinct from the master key/);
});

test('#212 loadIdentityConfig: automatically rejects byte-level reuse across colocated secret purposes', () => {
  const base = { VOUCHR_IDENTITY_SECRET: ACTIVE, VOUCHR_DEPLOYMENT_ID: 'deploy-A' };
  const decodedMaster = Buffer.from(ACTIVE, 'utf8').toString('base64');
  const reusedEnvs = [
    { SLACK_SIGNING_SECRET: ACTIVE },
    { VOUCHR_BROKER_TOKEN: ACTIVE },
    { VOUCHR_PROVIDER_GITHUB_CLIENT_SECRET: ACTIVE },
    { VOUCHR_MASTER_KEY: ACTIVE },
    { VOUCHR_MASTER_KEY: decodedMaster },
    { VOUCHR_MASTER_KEYS: `current:${decodedMaster}` },
  ];
  for (const reused of reusedEnvs) {
    assert.throws(
      () => loadIdentityConfig({ ...base, ...reused } as any),
      (error: Error) => /distinct/.test(error.message) && !error.message.includes(ACTIVE),
    );
  }
  assert.throws(() => loadIdentityConfig(base as any, [Buffer.from(ACTIVE)]), /distinct/);
  assert.throws(
    () => loadIdentityConfig({ ...base, VOUCHR_IDENTITY_SECRET_PREVIOUS: PREV, SLACK_SIGNING_SECRET: PREV } as any),
    /distinct/,
  );
});

test('#212 a rejection error never echoes the assertion or the signing secret', () => {
  const token = mintIdentity(who, cfg({ audience: 'deploy-A' }));
  assert.throws(
    () => verifyIdentity(token, cfg({ audience: 'deploy-B' })),
    (e: Error) => e.message.includes(token) === false && e.message.includes(ACTIVE) === false && /wrong audience/.test(e.message),
  );
});

test('#212 config mode: an empty jti is rejected (not a usable single-use id)', () => {
  // A hand-forged token with an empty jti, signed with the active key, must fail the claims check.
  const bad = signIdentity({ ...who, jti: '', exp: Date.now() + 60_000, iss: 'vouchr', aud: 'deploy-A', iat: Date.now(), kid: identityKid(ACTIVE) }, ACTIVE);
  assert.throws(() => verifyIdentity(bad, cfg()), /incomplete claims/);
});

test('#212 config mode: non-finite time inputs and oversized replay keys fail closed', () => {
  assert.throws(() => mintIdentity(who, cfg(), 60_000, Number.NaN), /finite safe integers/);
  assert.throws(() => verifyIdentity(mintIdentity(who, cfg()), cfg(), { now: Number.NaN }), /verification time/);

  const now = 1_000_000;
  const signed = (over: Record<string, unknown>) => signIdentity({
    ...who,
    jti: 'bounded-jti',
    exp: now + 60_000,
    iss: 'vouchr',
    aud: 'deploy-A',
    iat: now,
    kid: identityKid(ACTIVE),
    ...over,
  } as IdentityClaims, ACTIVE);
  assert.throws(() => verifyIdentity(signed({ iat: Number.MAX_SAFE_INTEGER + 1 }), cfg(), { now }), /invalid iat/);
  assert.throws(() => verifyIdentity(signed({ exp: Number.MAX_SAFE_INTEGER + 1 }), cfg(), { now }), /invalid exp/);
  assert.throws(() => verifyIdentity(signed({ jti: 'x'.repeat(129) }), cfg(), { now }), /invalid jti/);
});

test('mintIdentity: produces a token verifyIdentity accepts, preserving the claims', () => {
  const token = mintIdentity({ ...who, threadTs: '123.45' }, SECRET);
  const claims = verifyIdentity(token, SECRET);
  assert.equal(claims.teamId, 'T1');
  assert.equal(claims.userId, 'U1');
  assert.equal(claims.channel, 'C1');
  assert.equal(claims.threadTs, '123.45');
});

test('#2 channelType is a closed signed fact: supported values round-trip and malformed values fail closed', () => {
  for (const channelType of ['channel', 'group', 'im', 'mpim', 'app_home'] as const) {
    assert.equal(
      verifyIdentity(mintIdentity({ ...who, channelType }, SECRET), SECRET).channelType,
      channelType,
    );
  }

  for (const channelType of ['', 'MPIM', 'unknown', 'mpim\n', 'x'.repeat(300)]) {
    assert.throws(
      () => mintIdentity({ ...who, channelType } as any, SECRET),
      /supported Slack conversation type/,
    );
    const forged = signIdentity({
      ...who,
      channelType,
      exp: Date.now() + 60_000,
      jti: `bad-${channelType.length}`,
    } as any, SECRET);
    assert.throws(() => verifyIdentity(forged, SECRET), /incomplete claims/);
  }
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
