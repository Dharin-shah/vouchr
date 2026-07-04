import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle } from '../src/core/injector';
import { Policy, type PolicyRule } from '../src/core/policy';
import { Consent } from '../src/core/consent';
import { defineProvider, github, google, gitlab, notion, type Provider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

// Property / fuzz tests: generate many randomized + crafted inputs in-process and assert that the
// core invariants hold for all of them. Loops are bounded so the suite stays fast.

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);

// ---- seeded PRNG so a CI failure is reproducible (#127) ----
// Seed from VOUCHR_TEST_SEED (set it to replay a failing run byte-for-byte) or a fresh random seed,
// logged below. Date.now() as the default seed is fine here — this is test code, not a workflow script.
function mulberry32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const SEED = Number(process.env.VOUCHR_TEST_SEED ?? (Date.now() >>> 0)) >>> 0;
// eslint-disable-next-line no-console
console.log(`property-test seed: ${SEED} (replay with VOUCHR_TEST_SEED=${SEED})`);
const rnd = mulberry32(SEED);

// Iteration multiplier: default 1× (per-push latency); the nightly fuzz job sets VOUCHR_TEST_ITERS
// high to explore the deep tail (#127). Applied to every per-property loop count.
const ITERS = Math.max(1, Number(process.env.VOUCHR_TEST_ITERS ?? 1) || 1);
const scale = (n: number) => n * ITERS;

// ---- tiny PRNG helpers (seeded via `rnd` above) ----
const rint = (n: number) => Math.floor(rnd() * n);
const pick = <T>(a: readonly T[]): T => a[rint(a.length)];
const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const B64 = ALNUM + '_-+/=';
const randStr = (len: number, alphabet = ALNUM) =>
  Array.from({ length: len }, () => alphabet[rint(alphabet.length)]).join('');

// =====================================================================================
// 1. Egress matching: a denial NEVER reads the secret (resolver call-counter stays 0).
// =====================================================================================
const EG_HOST = 'api.acme.example';
const egProvider = defineProvider({
  id: 'eg',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: [EG_HOST],
  egressPaths: ['/repos/', '/user'],
  egressMethods: ['GET', 'POST'],
  refresh: 'none',
  pkce: false,
  clientId: 'id',
  clientSecret: 'sec',
});

function pathAllowed(pathname: string, allowed: string): boolean {
  if (allowed === '/') return true;
  if (allowed.endsWith('/')) return pathname.startsWith(allowed);
  return pathname === allowed || pathname.startsWith(`${allowed}/`);
}

// One handle, reused across iterations; the resolver counter is reset per case. A referenced cred
// means the ONLY way to read the secret is the resolver, and count 0 proves the secret was never read.
async function makeEgressHandle(provider: Provider) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  let calls = 0;
  await vault.reference(O1, provider.id, { source: 'ext', secretRef: 'arn:secret' });
  const resolvers = { ext: async () => { calls++; return 'super-secret-token'; } };
  const handle = new ConnectionHandle(provider, O1, ID, vault, new Audit(db), resolvers);
  return { handle, getCalls: () => calls, reset: () => { calls = 0; } };
}

test('property: random non-allowlisted hosts are ALWAYS denied, secret never read', async () => {
  const realFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = (async () => { fetched = true; return new Response('{}', { status: 200 }); }) as any;
  try {
    const { handle, getCalls, reset } = await makeEgressHandle(egProvider);
    const N = scale(300);
    for (let i = 0; i < N; i++) {
      // random hostname, never the allowlisted one
      const host = `${randStr(1 + rint(8), 'abcdefghijklmnopqrstuvwxyz')}.${pick(['example', 'evil', 'test', 'internal'])}`;
      if (host === EG_HOST) continue;
      reset();
      fetched = false;
      await assert.rejects(
        () => handle.fetch(`https://${host}/repos/x`, { method: 'GET' }),
        /Egress blocked/,
        `host ${host} should be denied`,
      );
      assert.equal(getCalls(), 0, `secret read for denied host ${host}`);
      assert.equal(fetched, false, `request went out for denied host ${host}`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('property: allowlisted host + non-https (non-loopback) is ALWAYS denied, secret never read', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    const { handle, getCalls, reset } = await makeEgressHandle(egProvider);
    const N = scale(200);
    for (let i = 0; i < N; i++) {
      const scheme = pick(['http', 'ftp', 'ws', 'gopher']);
      reset();
      await assert.rejects(
        () => handle.fetch(`${scheme}://${EG_HOST}/repos/x`, { method: 'GET' }),
        /Egress blocked/,
        `scheme ${scheme} should be denied`,
      );
      assert.equal(getCalls(), 0, `secret read for non-https scheme ${scheme}`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('property: only matching path+method pass; mismatches denied with secret unread', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    const { handle, getCalls, reset } = await makeEgressHandle(egProvider);
    const paths = ['/repos/x', '/repos/', '/repos', '/user', '/user/abc', '/userish', '/secrets', '/other', '/'];
    const methods = ['GET', 'POST', 'DELETE', 'PUT', 'PATCH', 'get', 'post'];
    const N = scale(400);
    for (let i = 0; i < N; i++) {
      const path = pick(paths);
      const method = pick(methods);
      const m = method.toUpperCase();
      const pathOk = egProvider.egressPaths!.some((p) => pathAllowed(path, p));
      const methodOk = egProvider.egressMethods!.some((mm) => mm.toUpperCase() === m);
      reset();
      if (pathOk && methodOk) {
        const res = await handle.fetch(`https://${EG_HOST}${path}`, { method });
        assert.equal(res.status, 200, `expected pass for ${method} ${path}`);
        assert.equal(getCalls(), 1, `secret should be read once for passing ${method} ${path}`);
      } else {
        await assert.rejects(
          () => handle.fetch(`https://${EG_HOST}${path}`, { method }),
          /Egress blocked/,
          `expected deny for ${method} ${path}`,
        );
        assert.equal(getCalls(), 0, `secret read for denied ${method} ${path}`);
      }
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

// =====================================================================================
// 2. Metadata redaction: credential-shaped values become '[redacted]', benign values pass through.
// =====================================================================================
function secretValue(): string {
  switch (rint(6)) {
    case 0: return `xox${pick(['b', 'p', 'a', 'r', 's'])}-${randStr(20)}`;
    case 1: return `ghp_${randStr(36)}`;
    case 2: return `sk-${randStr(2 + rint(40))}`;
    case 3: return `AKIA${randStr(16)}`;
    case 4: return `Bearer ${randStr(20)}`;
    default: return randStr(40 + rint(40), B64); // generic high-entropy blob (>=40 chars)
  }
}
function benignValue(): string {
  switch (rint(3)) {
    // hostname (contains dots → never matches the high-entropy regex), lowercase → no token prefix
    case 0: return `${randStr(3 + rint(6), 'abcdefghijklmnopqrstuvwxyz')}.${pick(['github.com', 'example.com', 'acme.io'])}`;
    // short channel-style id C + 7 alnum (8 chars, well under 40)
    case 1: return `C${randStr(7)}`;
    // short opaque id, kept < 40 chars
    default: return randStr(1 + rint(30));
  }
}

test('property: token-shaped values are redacted, benign values pass through unchanged', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const audit = new Audit(db);
  // Query by a per-iteration unique provider id. `at` is a ms timestamp and collides in a tight loop,
  // so ORDER BY at would read back the wrong row.
  const readBack = async (provider: string) =>
    JSON.parse((await db.get('SELECT meta FROM audit WHERE provider=?', [provider]) as any).meta);

  const N = scale(250);
  for (let i = 0; i < N; i++) {
    const sec = secretValue();
    const ben = benignValue();
    const smallInt = rint(1000);
    const bool = rnd() < 0.5;
    const provider = `p${i}`;
    await audit.record('config', ID, provider, { sec, ben, n: smallInt, b: bool });
    const m = await readBack(provider);
    assert.equal(m.sec, '[redacted]', `not redacted: ${JSON.stringify(sec)}`);
    assert.equal(m.ben, ben, `benign mangled: ${JSON.stringify(ben)}`);
    assert.equal(m.n, smallInt, 'small int should pass through');
    assert.equal(m.b, bool, 'boolean should pass through');
  }
});

// =====================================================================================
// 3. Policy decisions: check() never throws; fallback / denyChannels / allowChannels invariants.
// =====================================================================================
test('property: policy check() never throws and honors its invariants', async () => {
  const pool = ['C1', 'C2', 'C3', 'C4', 'C5'];
  const subset = () => pool.filter(() => rnd() < 0.4);
  const N = scale(500);
  for (let i = 0; i < N; i++) {
    const defaultDeny = rnd() < 0.5;
    const defaultAllow = rnd() < 0.5;
    const allowChannels = subset();
    const denyChannels = subset();
    const rule: PolicyRule = { defaultAllow, allowChannels, denyChannels };
    const channel = rnd() < 0.8 ? pick(pool) : null;

    const ruled = new Policy({ prov: rule }, { defaultDeny });
    const empty = new Policy({}, { defaultDeny });

    // never throws over any combination
    let decision = false;
    assert.doesNotThrow(() => { decision = ruled.check('prov', channel); });

    // no-rule provider falls back to !defaultDeny
    assert.equal(empty.check('whatever', channel), !defaultDeny, 'no-rule fallback');

    // denyChannels always wins
    if (channel && denyChannels.includes(channel)) {
      assert.equal(decision, false, 'denyChannels must win');
    } else if (defaultAllow) {
      // default-allow → allowed everywhere except denyChannels
      assert.equal(decision, true, 'defaultAllow should allow when not denied');
    } else {
      // default-deny per-rule → allowed only when explicitly in allowChannels
      assert.equal(decision, !!(channel && allowChannels.includes(channel)), 'allowChannels gating');
    }
  }
});

// =====================================================================================
// 4. OAuth state single-use, begin() then consume() once; second/unknown/expired return null.
// =====================================================================================
const STATE_TTL_MS = 10 * 60 * 1000; // mirrors consent.ts (not exported)
const consentProvider = defineProvider({
  id: 'cp',
  authorizeUrl: 'https://idp.example/authorize',
  tokenUrl: 'https://idp.example/token',
  scopesDefault: ['a'],
  egressAllow: ['idp.example'],
  refresh: 'none',
  pkce: true,
  clientId: 'cid',
  clientSecret: 'csec',
});

test('property: consume() is single-use; unknown states return null', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const consent = new Consent(db);
  const N = scale(200);
  for (let i = 0; i < N; i++) {
    const ident: SlackIdentity = { enterpriseId: null, teamId: `T${rint(5)}`, userId: `U${rint(1000)}` };
    const channel = rnd() < 0.5 ? `C${randStr(6)}` : null;
    const { state } = await consent.begin(ident, consentProvider, 'https://app/cb', channel);

    const first = await consent.consume(state);
    assert.ok(first, 'first consume should return the row');
    assert.equal(first!.state, state);
    assert.equal(first!.identity.teamId, ident.teamId);
    assert.equal(first!.identity.userId, ident.userId);
    assert.equal(first!.provider, consentProvider.id);
    assert.equal(first!.channel, channel);

    // single-use: a second consume of the same state returns null
    assert.equal(await consent.consume(state), null, 'second consume must be null');

    // an unknown / never-issued state returns null
    assert.equal(await consent.consume(`never-${randStr(20)}`), null, 'unknown state must be null');
  }
});

test('property: rows older than the TTL are treated as expired (null)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const consent = new Consent(db);
  const N = scale(100);
  for (let i = 0; i < N; i++) {
    const state = `stale-${randStr(24)}`;
    // Insert a row directly with a created_at older than the TTL (can't control the clock otherwise).
    const age = STATE_TTL_MS + 1000 + rint(60_000);
    await db.run(
      `INSERT INTO consent_request (state, enterprise_id, team_id, user_id, provider, channel, pkce_verifier, created_at)
       VALUES (?,?,?,?,?,?,?,?)`,
      [state, null, 'T1', 'U1', 'cp', null, 'verifier', Date.now() - age],
    );
    assert.equal(await consent.consume(state), null, 'expired state must consume to null');
  }
});

// =====================================================================================
// 5. Provider URL building: required params always present; code_challenge iff provider.pkce.
// =====================================================================================
test('property: authorize URL always carries the required params; code_challenge iff pkce', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const consent = new Consent(db);
  const redirectUri = 'https://app.example/oauth/callback';

  const builtins = [github, google, gitlab, notion];
  const N = scale(250);
  for (let i = 0; i < N; i++) {
    let provider: Provider;
    if (rnd() < 0.5) {
      // a built-in with random scopes + injected client creds
      const scopes = Array.from({ length: rint(4) }, () => randStr(4 + rint(6)));
      provider = pick(builtins)({ clientId: `cid-${randStr(6)}`, clientSecret: 'sec', scopes });
    } else {
      // a synthetic provider with random pkce / scopes to cover both branches densely
      provider = defineProvider({
        id: `syn-${randStr(5)}`,
        authorizeUrl: `https://idp${rint(5)}.example/authorize`,
        tokenUrl: 'https://idp.example/token',
        scopesDefault: Array.from({ length: rint(4) }, () => randStr(4 + rint(6))),
        egressAllow: ['idp.example'],
        refresh: 'none',
        pkce: rnd() < 0.5,
        clientId: `cid-${randStr(6)}`,
        clientSecret: 'sec',
      });
    }

    const ident: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: `U${rint(1000)}` };
    const { authorizeUrl, state } = await consent.begin(ident, provider, redirectUri, null);
    const sp = new URL(authorizeUrl).searchParams;

    assert.equal(sp.get('client_id'), provider.clientId, 'client_id');
    assert.equal(sp.get('redirect_uri'), redirectUri, 'redirect_uri');
    assert.equal(sp.get('state'), state, 'state matches returned value');
    assert.equal(sp.get('response_type'), 'code', 'response_type=code');
    assert.equal(sp.has('code_challenge'), provider.pkce, 'code_challenge present iff pkce');
    if (provider.pkce) assert.equal(sp.get('code_challenge_method'), 'S256', 'S256 when pkce');
  }
});
