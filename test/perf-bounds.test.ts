import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle } from '../src/core/injector';
import { defineProvider, github } from '../src/core/providers';
import { InflightLimiter, OverloadedError } from '../src/core/inflight';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';
import { createBroker, type BrokerOptions } from '../src/adapters/http/broker';
import { identityConfig, signIdentity, type IdentityClaims } from './support/identity';

// #209 resource bounds at the HTTP boundary: finite upstream deadlines + client-cancel propagation,
// inbound Content-Length/streamed caps, per-process global + per-provider in-flight ceilings (503 +
// Retry-After), a 401 refresh that replays only idempotent methods, and account-probe socket release.

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';
const U1: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(U1);

const acme = defineProvider({
  id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false, clientId: 'id', clientSecret: 'sec',
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}
function token(over: Partial<IdentityClaims> = {}): string {
  return signIdentity(claims(over), SECRET);
}

function post(port: number, path: string, body: unknown): Promise<{ status: number; json: any; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let json: any = null; try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* leave null */ }
          resolve({ status: res.statusCode ?? 0, json, headers: res.headers });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

/** POST with NO Content-Length → Node sends the body chunked (Transfer-Encoding: chunked), so the
 *  broker's streamed byte counter — not the Content-Length fast-reject — is what must cut it. */
function chunkedPost(port: number, path: string, bodyStr: string): Promise<{ status: number }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json' } },
      (res) => { res.resume(); res.on('end', () => resolve({ status: res.statusCode ?? 0 })); },
    );
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

async function listen(server: http.Server): Promise<number> {
  await new Promise<void>((r) => server.listen(0, r));
  return (server.address() as any).port;
}

async function waitFor(pred: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (!pred()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function buildBroker(t: TestContext, over: Partial<BrokerOptions> = {}) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const server = createBroker({ providers: [acme], vault, audit: new Audit(db), db, identitySecret: identityConfig(SECRET), ...over });
  const port = await listen(server);
  t.after(() => server.close());
  return { db, vault, server, port };
}

/** Upstream that BLOCKS the provider fetch until release() — for concurrency tests. Token endpoint
 *  (refresh) returns immediately so it never gates. */
function barrierUpstream() {
  const real = globalThis.fetch;
  let calls = 0;
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  globalThis.fetch = (async (url: any) => {
    if (String(url).includes('/token')) return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    calls++;
    await gate;
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  return { calls: () => calls, release, restore: () => { globalThis.fetch = real; } };
}

/** Upstream whose provider fetch never resolves until its AbortSignal fires, then rejects like undici
 *  does — for deadline + client-disconnect tests. Records how many fetches were aborted. */
function hangingUpstream() {
  const real = globalThis.fetch;
  let calls = 0;
  let aborts = 0;
  globalThis.fetch = ((url: any, init: any) => {
    if (String(url).includes('/token')) return Promise.resolve(new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    calls++;
    return new Promise((_resolve, reject) => {
      const sig: AbortSignal | undefined = init?.signal;
      const onAbort = () => { aborts++; reject(new DOMException('aborted', 'AbortError')); };
      if (sig?.aborted) return onAbort();
      sig?.addEventListener('abort', onAbort, { once: true });
    });
  }) as any;
  return { calls: () => calls, aborts: () => aborts, restore: () => { globalThis.fetch = real; } };
}

const fetchBody = (over: Record<string, unknown> = {}) => ({ handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'GET', path: '/x', ...over });

// ── InflightLimiter (unit) ────────────────────────────────────────────────────

test('InflightLimiter: admits to the ceiling, rejects past it, releases, and double-release is a no-op (#209)', () => {
  const lim = new InflightLimiter(2, 1, 500);
  const g1 = lim.enter();
  lim.enter();
  assert.equal(lim.inFlight(), 2);
  assert.throws(() => lim.enter(), (e) => e instanceof OverloadedError && e.scope === 'global' && e.retryAfterMs === 500);
  g1();
  g1(); // idempotent: a second release must not drop the counter below the live count
  assert.equal(lim.inFlight(), 1);
  lim.enter(); // room freed exactly once
  assert.equal(lim.inFlight(), 2);

  const pA = lim.enterProvider('a');
  assert.throws(() => lim.enterProvider('a'), (e) => e instanceof OverloadedError && e.scope === 'provider');
  const pB = lim.enterProvider('b'); // a different provider has its own budget
  pA();
  pB();
  assert.equal(lim.inFlight(), 2, 'per-provider admission never touches the global counter');
});

// ── inbound body caps ─────────────────────────────────────────────────────────

test('/v1/fetch: an oversize Content-Length is fast-rejected 413 before the body is read (#209)', async (t) => {
  const { port } = await buildBroker(t);
  const r = await post(port, '/v1/fetch', fetchBody({ query: { pad: 'A'.repeat(70_000) } }));
  assert.equal(r.status, 413);
  assert.equal(r.json.error, 'request body too large');
});

test('/v1/fetch: an oversize chunked body (no Content-Length) is cut by the streamed counter 413 (#209)', async (t) => {
  const { port } = await buildBroker(t);
  const big = JSON.stringify(fetchBody({ query: { pad: 'A'.repeat(70_000) } }));
  const r = await chunkedPost(port, '/v1/fetch', big);
  assert.equal(r.status, 413);
});

// ── upstream deadline + client cancellation ───────────────────────────────────

test('/v1/fetch: a hung upstream is cut at fetchDeadlineMs → 504, and the upstream fetch is aborted (#209)', async (t) => {
  const { port } = await buildBroker(t, { fetchDeadlineMs: 150 });
  const up = hangingUpstream();
  try {
    const r = await post(port, '/v1/fetch', fetchBody());
    assert.equal(r.status, 504);
    assert.equal(r.json.error, 'upstream timed out');
    assert.ok(up.aborts() >= 1, 'the deadline must abort the upstream fetch (socket released)');
  } finally {
    up.restore();
  }
});

test('/v1/fetch: a client disconnect aborts the in-flight upstream fetch (#209)', async (t) => {
  const { port } = await buildBroker(t, { fetchDeadlineMs: 30_000 });
  const up = hangingUpstream();
  try {
    const data = Buffer.from(JSON.stringify(fetchBody()));
    const req = http.request({ host: '127.0.0.1', port, path: '/v1/fetch', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } });
    req.on('error', () => { /* the client aborts on purpose */ });
    req.end(data);
    await waitFor(() => up.calls() === 1); // the request reached the (hung) upstream
    req.destroy(); // client drops the connection
    await waitFor(() => up.aborts() >= 1); // res 'close' must propagate to the upstream signal
    assert.ok(up.aborts() >= 1, 'a client disconnect must release the upstream socket');
  } finally {
    up.restore();
  }
});

// ── concurrency ceilings ──────────────────────────────────────────────────────

test('/v1/fetch: the global in-flight ceiling returns 503 + Retry-After (#209)', async (t) => {
  const { port } = await buildBroker(t, { maxInflight: 1 });
  const up = barrierUpstream();
  try {
    const pA = post(port, '/v1/fetch', fetchBody()); // holds the only global slot (blocked upstream)
    await waitFor(() => up.calls() === 1);
    const rB = await post(port, '/v1/fetch', fetchBody());
    assert.equal(rB.status, 503);
    assert.equal(rB.json.error, 'overloaded');
    assert.equal(rB.json.scope, 'global');
    assert.ok(rB.json.retryAfterMs > 0);
    assert.ok(rB.headers['retry-after'], 'a 503 overload carries a Retry-After header');
    up.release();
    assert.equal((await pA).status, 200);
  } finally {
    up.release();
    up.restore();
  }
});

test('/v1/fetch: the per-provider ceiling returns 503 scope=provider while the global budget has room (#209)', async (t) => {
  const { port } = await buildBroker(t, { maxInflight: 10, maxInflightPerProvider: 1 });
  const up = barrierUpstream();
  try {
    const pA = post(port, '/v1/fetch', fetchBody());
    await waitFor(() => up.calls() === 1);
    const rB = await post(port, '/v1/fetch', fetchBody());
    assert.equal(rB.status, 503);
    assert.equal(rB.json.scope, 'provider');
    up.release();
    assert.equal((await pA).status, 200);
  } finally {
    up.release();
    up.restore();
  }
});

test('/v1/fetch: repeated deadline timeouts release the slot — a later request is not starved (#209)', async (t) => {
  const { port } = await buildBroker(t, { maxInflight: 2, maxInflightPerProvider: 2, fetchDeadlineMs: 80 });
  const up = hangingUpstream();
  try {
    // If a global/per-provider slot leaked on timeout, iteration 3+ would 503 instead of 504.
    for (let i = 0; i < 8; i++) {
      const r = await post(port, '/v1/fetch', fetchBody());
      assert.equal(r.status, 504, `iteration ${i} must time out (slot released each time)`);
    }
    // Swap to a working upstream: if any slot had leaked across the 8 timeouts, the ceilings would be
    // exhausted and this would 503. A clean 200 proves every global + per-provider slot was released.
    globalThis.fetch = (async () => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
    const ok = await post(port, '/v1/fetch', fetchBody());
    assert.equal(ok.status, 200);
  } finally {
    up.restore();
  }
});

// ── 401 refresh: idempotent-only replay ───────────────────────────────────────

test('401 refresh-retry replays an idempotent GET but NOT a non-idempotent POST (#209)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const p = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], egressMethods: ['GET', 'POST'], refresh: 'rotating', pkce: true, clientId: 'id', clientSecret: 'sec',
  });
  const real = globalThis.fetch;
  const stub = (staleBearer: string, counter: { n: number }) => (async (url: any, init: any) => {
    if (String(url).includes('/token')) return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    counter.n++;
    const auth = new Headers(init?.headers).get('authorization');
    if (auth === `Bearer ${staleBearer}`) return new Response('nope', { status: 401 });
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    // GET: the 401 refreshes and the request is REPLAYED with the new token → 200, two provider calls.
    await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });
    const getCalls = { n: 0 };
    globalThis.fetch = stub('old', getCalls);
    const getRes = await new ConnectionHandle(p, O1, U1, vault, new Audit(db)).fetch('https://api.acme.example/data', { method: 'GET' });
    assert.equal(getRes.status, 200);
    assert.equal(getCalls.n, 2, 'GET: original 401 + one refreshed replay');

    // POST: the 401 still refreshes (next call is fresh) but the write is NOT replayed → the 401 is
    // returned as-is, exactly ONE provider call (no double side-effect).
    await vault.upsert(O1, 'acme', { accessToken: 'old2', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });
    const postCalls = { n: 0 };
    globalThis.fetch = stub('old2', postCalls);
    const postRes = await new ConnectionHandle(p, O1, U1, vault, new Audit(db)).fetch('https://api.acme.example/data', { method: 'POST', body: '{}' });
    assert.equal(postRes.status, 401, 'a non-idempotent 401 is surfaced, not replayed');
    assert.equal(postCalls.n, 1, 'POST: never replayed');
  } finally {
    globalThis.fetch = real;
  }
});

// ── inbound server timeouts ───────────────────────────────────────────────────

// The slow-loris header/body bounds are Node's to enforce (server.headersTimeout / requestTimeout),
// on its connectionsCheckingInterval — not something to re-verify with a flaky timing test. What #209
// owns is SETTING them from config; assert exactly that. (Oversize bodies are cut synchronously by the
// streamed counter above, independent of these timers.)
test('createBroker: inbound server timeouts are set from the configured values (#209)', async (t) => {
  const { server } = await buildBroker(t, { headersTimeoutMs: 12_000, requestTimeoutMs: 21_000, keepAliveTimeoutMs: 7_000 });
  assert.equal(server.headersTimeout, 12_000);
  assert.equal(server.requestTimeout, 21_000);
  assert.equal(server.keepAliveTimeout, 7_000);
});

// ── account probe socket release ──────────────────────────────────────────────

test('accountProbe: releases the socket on a non-OK response, returns null on timeout, carries a deadline signal (#209)', async () => {
  const probe = github({ clientId: 'x', clientSecret: 'y' }).accountProbe!;
  const real = globalThis.fetch;
  try {
    // (a) non-OK → the unread body is cancelled (undici otherwise pins the socket, #172), result null.
    let cancelled = false;
    let sawSignal = false;
    globalThis.fetch = (async (_u: any, init: any) => {
      sawSignal = init?.signal instanceof AbortSignal;
      const body = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('x')); }, cancel() { cancelled = true; } });
      return new Response(body, { status: 403 });
    }) as any;
    assert.equal(await probe('tok'), null);
    assert.equal(cancelled, true, 'a non-OK probe body must be cancelled');
    assert.equal(sawSignal, true, 'the probe fetch must carry a deadline AbortSignal');

    // (b) a timeout / network throw resolves to null, never throws (a hung probe can't stall connect).
    globalThis.fetch = (async () => { throw new DOMException('timed out', 'TimeoutError'); }) as any;
    assert.equal(await probe('tok'), null);

    // (c) an OK probe returns the display field.
    globalThis.fetch = (async () => new Response(JSON.stringify({ login: 'octocat' }), { status: 200, headers: { 'content-type': 'application/json' } })) as any;
    assert.equal(await probe('tok'), 'octocat');
  } finally {
    globalThis.fetch = real;
  }
});
