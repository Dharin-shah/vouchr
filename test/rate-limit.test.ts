import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { Policy } from '../src/core/policy';
import { ConnectionHandle, type VouchrEvent } from '../src/core/injector';
import { MemoryRateLimitStore, RateLimitedError } from '../src/core/rateLimit';
import { defineProvider, ProviderRegistry, type Provider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';
import { createBroker } from '../src/adapters/http/broker';
import { signIdentity, type IdentityClaims } from '../src/adapters/http/identity';
import { ConnectContext, safeUserMessage } from '../src/adapters/bolt';

// Per-(owner, provider) rate limiting at the injection boundary (#114). Time-sensitive cases run on
// node:test mock timers (Date only — real I/O timers keep working), so refill math is exact.

const KEY = randomBytes(32);
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';
const U1: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const U2: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U2' };
const T0 = 1_000_000; // mock-clock epoch; anything > 0 works

function provider(id: string, rateLimit?: Provider['rateLimit']): Provider {
  return defineProvider({
    id,
    authorizeUrl: 'https://acme.example/auth',
    tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'],
    egressAllow: ['api.acme.example'],
    refresh: 'none',
    pkce: false,
    clientId: 'id',
    clientSecret: 'sec',
    rateLimit,
  });
}

/**
 * A handle over a REFERENCED credential plus two independent "was the secret touched?" counters
 * (the property.test.ts technique): `resolves` counts secret resolutions, `vaultGets` counts
 * vault.get calls — a rate-limit deny must leave BOTH untouched.
 */
async function makeHandle(p: Provider, acting: SlackIdentity = U1, store = new MemoryRateLimitStore()) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const owner = userOwner(acting);
  await vault.reference(owner, p.id, { source: 'ext', secretRef: 'arn:secret' });
  let resolves = 0;
  let vaultGets = 0;
  const realGet = vault.get.bind(vault);
  (vault as any).get = (...args: Parameters<Vault['get']>) => {
    vaultGets++;
    return realGet(...args);
  };
  const events: VouchrEvent[] = [];
  const handle = new ConnectionHandle(
    p, owner, acting, vault, new Audit(db),
    { ext: async () => { resolves++; return SECRET_TOKEN; } },
    new Map(), (e) => events.push(e), () => {}, null, null, store,
  );
  return { handle, db, events, getResolves: () => resolves, getVaultGets: () => vaultGets };
}

function stubUpstream() {
  const real = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => { calls++; return new Response('{}', { status: 200 }); }) as any;
  return { getCalls: () => calls, restore: () => { globalThis.fetch = real; } };
}

test('rate limit: N+1th request inside the window is denied BEFORE the vault is read, with event + audit', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: T0 });
  const up = stubUpstream();
  try {
    const p = provider('rl', { perMinute: 60, burst: 3 });
    const { handle, db, events, getResolves, getVaultGets } = await makeHandle(p);

    for (let i = 0; i < 3; i++) {
      const res = await handle.fetch('https://api.acme.example/user');
      assert.equal(res.status, 200);
    }
    assert.equal(getResolves(), 3);
    const getsAfterBurst = getVaultGets();
    const upstreamAfterBurst = up.getCalls();

    // 4th request in the same instant: denied, with the secret and the network untouched.
    const err = await handle
      .fetch('https://api.acme.example/user?hint=topsecretquery')
      .then(() => null, (e: unknown) => e);
    assert.ok(err instanceof RateLimitedError, `expected RateLimitedError, got ${String(err)}`);
    assert.equal(err.provider, 'rl');
    assert.equal(err.perMinute, 60);
    assert.equal(err.retryAfterMs, 1000); // 60/min = 1 token per second; the bucket is exactly empty
    assert.ok(!err.message.includes(SECRET_TOKEN));
    assert.equal(getResolves(), 3, 'secret was resolved for a rate-limited request');
    assert.equal(getVaultGets(), getsAfterBurst, 'vault was read for a rate-limited request');
    assert.equal(up.getCalls(), upstreamAfterBurst, 'a rate-limited request went out');

    // Event: no-secret, provider + hostname only.
    const ev = events.find((e) => e.type === 'rate_limited') as Extract<VouchrEvent, { type: 'rate_limited' }>;
    assert.ok(ev, 'rate_limited event not emitted');
    assert.deepEqual(ev, { type: 'rate_limited', provider: 'rl', host: 'api.acme.example' });
    for (const e of events) assert.ok(!JSON.stringify(e).includes(SECRET_TOKEN));

    // Audit: action rate_limited, attributed to the acting human, meta = hostname + owner kind —
    // never the url/query string, never the secret.
    const row = await db.get(`SELECT team_id, user_id, provider, meta FROM audit WHERE action='rate_limited'`);
    assert.ok(row, 'rate_limited audit row missing');
    assert.equal(row.team_id, 'T1');
    assert.equal(row.user_id, 'U1');
    assert.equal(row.provider, 'rl');
    assert.deepEqual(JSON.parse(row.meta), { host: 'api.acme.example', owner: 'user' });
    assert.ok(!row.meta.includes('topsecretquery'), 'audit meta leaked the query string');
    assert.ok(!row.meta.includes(SECRET_TOKEN));
  } finally {
    up.restore();
  }
});

test('rate limit: the bucket refills over time and retryAfter tracks the exact deficit', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: T0 });
  const up = stubUpstream();
  try {
    const p = provider('rl', { perMinute: 60, burst: 2 });
    const { handle } = await makeHandle(p);
    await handle.fetch('https://api.acme.example/user');
    await handle.fetch('https://api.acme.example/user');
    await assert.rejects(() => handle.fetch('https://api.acme.example/user'), RateLimitedError);

    // One token refills after 1s (60/min): allowed again, then empty again.
    t.mock.timers.tick(1000);
    assert.equal((await handle.fetch('https://api.acme.example/user')).status, 200);

    // 400ms later only 0.4 tokens exist: denied, ~600ms to the next whole token (±1ms float dust).
    t.mock.timers.tick(400);
    const err = await handle.fetch('https://api.acme.example/user').then(() => null, (e: unknown) => e);
    assert.ok(err instanceof RateLimitedError);
    assert.ok(Math.abs(err.retryAfterMs - 600) <= 1, `retryAfterMs ${err.retryAfterMs} != ~600`);

    // Wait exactly what it told us to: the request passes.
    t.mock.timers.tick(err.retryAfterMs);
    assert.equal((await handle.fetch('https://api.acme.example/user')).status, 200);
  } finally {
    up.restore();
  }
});

test('rate limit: buckets are isolated per owner and per provider; user A limited != user B limited', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: T0 });
  const up = stubUpstream();
  try {
    const store = new MemoryRateLimitStore(); // one SHARED store, as in a real deployment
    const p = provider('rl', { perMinute: 60, burst: 1 });
    const a = await makeHandle(p, U1, store);
    const b = await makeHandle(p, U2, store);
    const other = await makeHandle(provider('rl2', { perMinute: 60, burst: 1 }), U1, store);

    assert.equal((await a.handle.fetch('https://api.acme.example/user')).status, 200);
    await assert.rejects(() => a.handle.fetch('https://api.acme.example/user'), RateLimitedError);
    // A's exhaustion affects neither B (other owner) nor A's other provider.
    assert.equal((await b.handle.fetch('https://api.acme.example/user')).status, 200);
    assert.equal((await other.handle.fetch('https://api.acme.example/user')).status, 200);
  } finally {
    up.restore();
  }
});

test('rate limit: a provider without the knob is unlimited (no event, no audit, unchanged behavior)', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: T0 });
  const up = stubUpstream();
  try {
    const { handle, db, events } = await makeHandle(provider('free'));
    for (let i = 0; i < 50; i++) {
      assert.equal((await handle.fetch('https://api.acme.example/user')).status, 200);
    }
    assert.ok(!events.some((e) => e.type === 'rate_limited'));
    assert.equal(await db.get(`SELECT count(*) AS n FROM audit WHERE action='rate_limited'`).then((r: any) => Number(r.n)), 0);
  } finally {
    up.restore();
  }
});

test('rate limit: defineProvider rejects a zero/negative/NaN limit at definition time', () => {
  for (const rateLimit of [{ perMinute: 0 }, { perMinute: -1 }, { perMinute: Number.NaN }, { perMinute: 60, burst: 0 }]) {
    assert.throws(() => provider('bad', rateLimit), /invalid rateLimit/);
  }
});

test('rate limit: idle refilled buckets are pruned on the lazy 60s cadence (memory stays bounded)', (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: T0 });
  const store = new MemoryRateLimitStore();
  const refill = 60 / 60_000;
  for (let i = 0; i < 100; i++) assert.equal(store.take(`k${i}`, 1, refill, 1).ok, true);
  assert.equal((store as any).buckets.size, 100);
  // After every bucket has refilled to capacity AND the prune cadence elapsed, one take sweeps them.
  t.mock.timers.tick(61_000);
  store.take('fresh', 1, refill, 1);
  assert.equal((store as any).buckets.size, 1, 'idle full buckets were not pruned');
});

// ── broker surface: 429 + Retry-After ────────────────────────────────────────

function postJson(port: number, path: string, body: unknown): Promise<{ status: number; json: any; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString('utf8')), headers: res.headers }));
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

test('broker: a rate-limited /v1/fetch returns 429 with a Retry-After header, upstream untouched', async () => {
  // Real clock here (an HTTP round trip needs live timers): perMinute 1 makes the window generous
  // enough that two back-to-back calls can never straddle a refill.
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const limited = provider('acme', { perMinute: 1 }); // burst defaults to perMinute = 1
  await vault.upsert(userOwner(U1), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [limited], vault, audit, db, identitySecret: 'broker-secret' });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  const realFetch = globalThis.fetch;
  let upstream = 0;
  globalThis.fetch = (async () => { upstream++; return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }); }) as any;
  try {
    const call = () => postJson(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() } satisfies IdentityClaims, 'broker-secret'),
      method: 'GET', path: '/user',
    });
    assert.equal((await call()).status, 200);
    assert.equal(upstream, 1);

    const denied = await call();
    assert.equal(denied.status, 429);
    assert.equal(denied.json.error, 'rate limited');
    assert.ok(denied.json.retryAfterMs > 0 && denied.json.retryAfterMs <= 60_000);
    const retryAfter = Number(denied.headers['retry-after']);
    assert.ok(retryAfter >= 1 && retryAfter <= 60, `Retry-After ${denied.headers['retry-after']} not in (0, 60]s`);
    assert.equal(upstream, 1, 'a rate-limited broker request reached the upstream');
    assert.ok(!JSON.stringify(denied.json).includes(SECRET_TOKEN));

    const row = await db.get(`SELECT user_id, provider FROM audit WHERE action='rate_limited'`);
    assert.ok(row, 'broker deny did not write the rate_limited audit row');
    assert.equal(row.user_id, 'U1');
    assert.equal(row.provider, 'acme');
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});

// ── Bolt surface: ephemeral notice ───────────────────────────────────────────

test('bolt: a rate-limited fetch tells the acting user ephemerally and still throws the typed error', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const p = provider('rl', { perMinute: 1 }); // real clock; 1/min cannot refill between two awaits
  await vault.upsert(userOwner(U1), 'rl', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const posted: any[] = [];
  const client = { chat: { postEphemeral: async (a: any) => { posted.push(a); } } } as any;
  const ctx = new ConnectContext({
    identity: U1, channel: 'C1', client, registry: new ProviderRegistry([p]), vault,
    audit: new Audit(db), consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
  });
  const up = stubUpstream();
  try {
    const handle = await ctx.connect('rl');
    assert.equal((await handle.fetch('https://api.acme.example/user')).status, 200);

    const err = await handle.fetch('https://api.acme.example/user').then(() => null, (e: unknown) => e);
    assert.ok(err instanceof RateLimitedError, 'typed error must still reach the caller');
    assert.equal(posted.length, 1, 'no ephemeral notice was posted');
    assert.equal(posted[0].channel, 'C1');
    assert.equal(posted[0].user, 'U1'); // only the acting user sees it
    assert.match(posted[0].text, /^Slow down: rl is limited to 1 requests\/min, try again in \d+s\.$/);
    assert.ok(!posted[0].text.includes(SECRET_TOKEN));
    // And the error's own message is Vouchr-authored + secret-free, so safeUserMessage echoes it.
    assert.equal(safeUserMessage(err), err.message);
  } finally {
    up.restore();
  }
});
