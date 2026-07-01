import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Policy } from '../src/core/policy';
import { ChannelTools } from '../src/core/tools';
import { defineProvider, type Provider } from '../src/core/providers';
import { ConnectionHandle, type VouchrEvent } from '../src/core/injector';
import { userOwner } from '../src/core/owner';
import { createBroker, withEgressDefaults } from '../src/adapters/http/broker';
import { signIdentity, verifyIdentity, IdentityError, ReplayGuard, type IdentityClaims } from '../src/adapters/http/identity';

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK'; // the vaulted token that must never escape

const acme = defineProvider({
  id: 'acme',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  refresh: 'none',
  pkce: false,
  clientId: 'id',
  clientSecret: 'sec',
});

// A service-to-service tool the broker must refuse (no human credential to broker).
const svc = defineProvider({
  id: 'svc', identity: 'service', credential: 'key',
  authorizeUrl: 'https://svc.example/auth', tokenUrl: 'https://svc.example/token',
  scopesDefault: ['x'], egressAllow: ['api.svc.example'], refresh: 'none', pkce: false,
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}

async function makeBroker(extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  // Seed U1's acme credential so /v1/fetch has a token to (privately) inject.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: SECRET, ...extra });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  return { server, vault, db, port };
}

/** POST JSON to the broker over a real socket (NOT global fetch, which the upstream mock owns). */
function post(port: number, path: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; json: any; raw: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length, ...headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json: any = null;
          try { json = JSON.parse(raw); } catch { /* leave null */ }
          resolve({ status: res.statusCode ?? 0, json, raw });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

function get(port: number, path: string): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    }).on('error', reject);
  });
}

/** Mock the upstream provider call (global fetch). Returns the requested Response and records what it saw. */
function mockUpstream(response: () => Response) {
  const real = globalThis.fetch;
  const seen: { auth: string | null; method: string }[] = [];
  globalThis.fetch = (async (_url: any, init: any) => {
    seen.push({ auth: new Headers(init?.headers).get('authorization'), method: init?.method ?? 'GET' });
    return response();
  }) as any;
  return { seen, restore: () => { globalThis.fetch = real; } };
}

// ── identity unit tests (no server) ─────────────────────────────────────────

test('identity: round-trips and rejects tampering/expiry/over-long lifetime', () => {
  const c = claims();
  const tok = signIdentity(c, SECRET);
  assert.deepEqual(verifyIdentity(tok, SECRET), c);

  // wrong secret -> bad signature
  assert.throws(() => verifyIdentity(tok, 'other'), IdentityError);
  // flipped last char -> bad signature
  assert.throws(() => verifyIdentity(tok.slice(0, -1) + (tok.endsWith('a') ? 'b' : 'a'), SECRET), IdentityError);
  // expired
  assert.throws(() => verifyIdentity(signIdentity(claims({ exp: Date.now() - 1 }), SECRET), SECRET), /expired/);
  // lifetime > 5min
  assert.throws(() => verifyIdentity(signIdentity(claims({ exp: Date.now() + 10 * 60_000 }), SECRET), SECRET), /5min/);
});

test('identity: jti is single-use within the replay guard', () => {
  const replay = new ReplayGuard();
  const tok = signIdentity(claims(), SECRET);
  assert.ok(verifyIdentity(tok, SECRET, { replay })); // first use ok
  assert.throws(() => verifyIdentity(tok, SECRET, { replay }), /replayed jti/); // second use rejected
});

// ── /v1/fetch ────────────────────────────────────────────────────────────────

test('fetch: token is NEVER present in the response body', async () => {
  const { server, port } = await makeBroker();
  const up = mockUpstream(() => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/data',
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.body, '{"ok":true}');
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`); // token went out on the wire, privately
    assert.ok(!r.raw.includes(SECRET_TOKEN), 'secret must not appear anywhere in the broker response');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: the broker forwards metrics events to onEvent (no longer a black box), no secret', async () => {
  const events: VouchrEvent[] = [];
  const { server, port } = await makeBroker({ onEvent: (e) => events.push(e) });
  const up = mockUpstream(() => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/data',
    });
    assert.equal(r.status, 200);
  } finally {
    up.restore();
    server.close();
  }
  const injected = events.find((e) => e.type === 'injected') as Extract<VouchrEvent, { type: 'injected' }> | undefined;
  assert.ok(injected, 'broker did not forward the injected metric — it is still a black box');
  assert.equal(injected.provider, 'acme');
  assert.equal(injected.status, 200);
  assert.equal(typeof injected.ms, 'number');
  for (const e of events) assert.ok(!JSON.stringify(e).includes(SECRET_TOKEN), 'metric event leaked the token');
});

test('fetch: the broker emits an audit-STREAM event (raw verified actor id) to auditSink, no secret', async () => {
  const events: any[] = [];
  const { server, port } = await makeBroker({ auditSink: (e) => events.push(e) });
  const up = mockUpstream(() => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/data',
    });
    assert.equal(r.status, 200);
  } finally {
    up.restore();
    server.close();
  }
  assert.equal(events.length, 1, 'broker did not emit an audit-stream copy');
  const e = events[0];
  assert.equal(e.action, 'fetch');
  assert.equal(e.provider, 'acme');
  assert.equal(e.teamId, 'T1');
  assert.equal(e.userId, 'U1'); // RAW actor id, from the VERIFIED claims (never the request body)
  assert.equal(e.ownerKind, 'user');
  assert.equal(e.egressHost, 'api.acme.example');
  assert.equal(e.status, 200);
  assert.ok(e.jti, 'jti missing');
  assert.ok(!JSON.stringify(e).includes(SECRET_TOKEN), 'audit-stream event leaked the token');
});

test('fetch: an incoming traceparent is propagated onto the outbound provider fetch', async () => {
  const { server, port } = await makeBroker();
  const real = globalThis.fetch;
  let outbound: Headers | null = null;
  globalThis.fetch = (async (_u: any, init: any) => {
    outbound = new Headers(init?.headers);
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  const TP = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';
  try {
    // with a traceparent header -> forwarded verbatim
    const r = await post(port, '/v1/fetch',
      { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' },
      { traceparent: TP, tracestate: 'vendor=1' });
    assert.equal(r.status, 200);
    assert.equal(outbound!.get('traceparent'), TP);
    assert.equal(outbound!.get('tracestate'), 'vendor=1');

    // no-op when unset -> no trace headers fabricated
    outbound = null;
    const r2 = await post(port, '/v1/fetch',
      { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(r2.status, 200);
    assert.equal(outbound!.get('traceparent'), null);
  } finally {
    globalThis.fetch = real;
    server.close();
  }
});

test('fetch: non-GET/HEAD -> 405 BEFORE the vault/upstream is touched', async () => {
  const { server, port } = await makeBroker();
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'POST', path: '/data',
    });
    assert.equal(r.status, 405);
    assert.equal(up.seen.length, 0, 'upstream (and therefore the vault) was never reached');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: unsigned/expired identity -> 401', async () => {
  const { server, port } = await makeBroker();
  try {
    const bad = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: 'not.a.real.token', method: 'GET', path: '/x' });
    assert.equal(bad.status, 401);
    const expired = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims({ exp: Date.now() - 1 }), SECRET), method: 'GET', path: '/x',
    });
    assert.equal(expired.status, 401);
  } finally {
    server.close();
  }
});

test('fetch: a replayed jti is rejected on the second call', async () => {
  const { server, port } = await makeBroker();
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const token = signIdentity(claims(), SECRET);
    const first = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token, method: 'GET', path: '/x' });
    assert.equal(first.status, 200);
    const replay = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token, method: 'GET', path: '/x' });
    assert.equal(replay.status, 401);
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: a shared replayStore rejects a replay across DIFFERENT broker instances (multi-pod)', async () => {
  // A shared store makes single-use cluster-wide, not per-process (the default in-memory guard would
  // let each instance accept the same jti once). Simulates two pods behind one Redis-backed store.
  const seen = new Map<string, number>();
  const replayStore = { use: (jti: string, exp: number) => (seen.has(jti) ? false : (seen.set(jti, exp), true)) };
  const a = await makeBroker({ replayStore });
  const b = await makeBroker({ replayStore });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const token = signIdentity(claims(), SECRET);
    const first = await post(a.port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token, method: 'GET', path: '/x' });
    assert.equal(first.status, 200);
    const onOther = await post(b.port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token, method: 'GET', path: '/x' });
    assert.equal(onOther.status, 401); // second pod refuses the already-used jti
  } finally {
    up.restore();
    a.server.close();
    b.server.close();
  }
});

test('fetch: a service-to-service provider is refused (403), never brokered', async () => {
  const { server, port } = await makeBroker({ providers: [acme, svc] });
  try {
    const token = signIdentity(claims(), SECRET);
    const r = await post(port, '/v1/fetch', { handle: { provider: 'svc', owner: 'user' }, identityToken: token, method: 'GET', path: '/x' });
    assert.equal(r.status, 403);
    assert.ok(!r.raw.includes(SECRET_TOKEN)); // and no credential material anywhere in the response
  } finally {
    server.close();
  }
});

test('fetch: body-supplied identity is IGNORED; cross-tenant probe gets the attacker their OWN (empty) owner', async () => {
  const { server, port } = await makeBroker();
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    // Attacker is U2 (no credential). They sign their own valid token but stuff U1's id in the body.
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims({ userId: 'U2' }), SECRET),
      method: 'GET', path: '/x',
      // body-level identity that MUST be ignored:
      teamId: 'T1', userId: 'U1', channel: 'C1',
    } as any);
    // U2 has no acme credential, so the broker resolves U2's owner (from the token) and finds nothing.
    assert.equal(r.status, 409, 'resolved the token owner (U2), not the body-supplied U1');
    assert.equal(up.seen.length, 0, 'U1\'s token was never read, so nothing went upstream');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: over-cap response -> 413, never a truncated partial body', async () => {
  const { server, port } = await makeBroker({ maxResponseBytes: 64 });
  const big = JSON.stringify({ blob: 'x'.repeat(500) });
  const up = mockUpstream(() => new Response(big, { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(r.status, 413);
    assert.equal(r.json.body, undefined, 'no partial body is returned on over-cap');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: disallowed content-type is rejected before the body is returned', async () => {
  const { server, port } = await makeBroker();
  const up = mockUpstream(() => new Response('<html>injection</html>', { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } }));
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(r.status, 502);
    assert.ok(!r.raw.includes('injection'), 'disallowed body never relayed');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: content-type allowlist ignores ;charset and is case-insensitive', async () => {
  const { server, port } = await makeBroker();
  const up = mockUpstream(() => new Response('{"ok":1}', { status: 200, headers: { 'content-type': 'APPLICATION/JSON; charset=UTF-8' } }));
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(r.status, 200);
    assert.equal(r.json.body, '{"ok":1}');
  } finally {
    up.restore();
    server.close();
  }
});

// ── /v1/resolve ──────────────────────────────────────────────────────────────

test('resolve: returns existence + consent state, NEVER the secret', async () => {
  const { server, port } = await makeBroker();
  try {
    const connected = await post(port, '/v1/resolve', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(connected.status, 200);
    assert.equal(connected.json.connected, true);
    assert.equal(connected.json.consentState, 'connected');
    assert.ok(!connected.raw.includes(SECRET_TOKEN), 'resolve must not leak the token');

    const other = await post(port, '/v1/resolve', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims({ userId: 'U2' }), SECRET) });
    assert.equal(other.json.connected, false);
    assert.equal(other.json.consentState, 'needs_consent');
  } finally {
    server.close();
  }
});

// ── /healthz ─────────────────────────────────────────────────────────────────

test('healthz: reflects DB reachability + signing key loaded', async () => {
  const { server, db, port } = await makeBroker();
  try {
    const ok = await get(port, '/healthz');
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.json, { ok: true, dbReachable: true, signingKeyLoaded: true });

    await db.close(); // DB now unreachable
    const down = await get(port, '/healthz');
    assert.equal(down.status, 503);
    assert.equal(down.json.dbReachable, false);
  } finally {
    server.close();
  }
});

// ── operator authorization parity with the Bolt path (#21/#22): Policy + ChannelTools ──

/** Build a broker over a fresh in-memory db with U1's acme credential seeded, returning the db so a
 *  test can wire a Policy / ChannelTools backed by the SAME store the broker reads. */
async function makeBrokerOn(build: (db: any, vault: Vault, audit: Audit) => Partial<Parameters<typeof createBroker>[0]>) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: SECRET, ...build(db, vault, audit) });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, db, audit, port: (server.address() as any).port };
}

test('fetch: a Policy that denies the provider in this channel -> 403, credential NEVER injected', async () => {
  // Policy denies acme in C1 (the channel comes from the verified claims, not the body).
  const policy = new Policy({ acme: { defaultAllow: true, denyChannels: ['C1'] } });
  const { server, db, audit, port } = await makeBrokerOn(() => ({ policy }));
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(r.status, 403);
    assert.equal(up.seen.length, 0, 'denied: the vault/token was never read and nothing went upstream');
    const denied = (await db.get(`SELECT count(*) AS n FROM audit WHERE action='denied'`)) as { n: number };
    assert.equal(denied.n, 1, 'the deny was audited (no secret)');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: a ChannelTools allowlist that disables the provider here -> 403, credential NEVER injected', async () => {
  const { server, db, audit, port } = await makeBrokerOn((db) => ({ channelTools: new ChannelTools(db) }));
  // Configure the channel as an allowlist that does NOT include acme -> acme is disabled here.
  await new ChannelTools(db).setEnabled('T1', 'C1', 'other', true);
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(r.status, 403);
    assert.equal(up.seen.length, 0, 'tool-disabled: nothing went upstream');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: a caller-supplied Authorization header is DROPPED; only the broker-injected Bearer reaches upstream', async () => {
  const { server, port } = await makeBroker();
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/x',
      headers: { authorization: 'Bearer attacker-token', Authorization: 'Bearer attacker-token-2' },
    });
    assert.equal(r.status, 200);
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`, 'the attacker Authorization was dropped; the injected Bearer reached upstream');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: brokerToken network gate — wrong/absent token 401, correct token passes', async () => {
  const { server, port } = await makeBroker({ brokerToken: 'perimeter-secret' });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const body = { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' };
    const noTok = await post(port, '/v1/fetch', body);
    assert.equal(noTok.status, 401);
    const wrong = await post(port, '/v1/fetch', body, { authorization: 'Bearer nope' });
    assert.equal(wrong.status, 401);
    const ok = await post(port, '/v1/fetch', body, { authorization: 'Bearer perimeter-secret' });
    assert.equal(ok.status, 200);
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: a malformed host -> clean 400, not a 500', async () => {
  const { server, port } = await makeBroker();
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/x', host: 'api.acme.example:notaport',
    });
    assert.equal(r.status, 400);
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch/resolve: owner:"channel" is rejected (the channel shared-cred path is omitted from this broker)', async () => {
  const { server, port } = await makeBroker();
  try {
    const f = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'channel' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' } as any);
    assert.equal(f.status, 400);
    const rv = await post(port, '/v1/resolve', { handle: { provider: 'acme', owner: 'channel' }, identityToken: signIdentity(claims(), SECRET) } as any);
    assert.equal(rv.status, 400);
  } finally {
    server.close();
  }
});

// ── #25 default-deny at the provider level (injector enforces it; core unchanged) ──

test('egress default-deny: unset egressMethods means GET/HEAD-only under the broker switch', async () => {
  // The broker clones the provider with egressMethods=['GET','HEAD'] when defaultDenyNonGet is on,
  // and the EXISTING injector enforcement (injector.ts) denies POST. Without the switch, POST passes.
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  await vault.upsert(owner, 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

  // The broker switch produces a GET/HEAD-only clone for an unset provider, and leaves it alone off.
  assert.deepEqual(withEgressDefaults(acme, true).egressMethods, ['GET', 'HEAD']);
  assert.equal(withEgressDefaults(acme, false).egressMethods, undefined);
  // An explicit egressMethods is preserved (backward compatible) even with the switch on.
  assert.deepEqual(withEgressDefaults({ ...acme, egressMethods: ['GET', 'POST'] } as Provider, true).egressMethods, ['GET', 'POST']);

  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    // default-deny ON: the clone denies POST via the EXISTING injector enforcement.
    const denied = withEgressDefaults(acme, true);
    await assert.rejects(
      () => new ConnectionHandle(denied, owner, { enterpriseId: null, teamId: 'T1', userId: 'U1' }, vault, audit).fetch('https://api.acme.example/x', { method: 'POST' }),
      /method "POST" is not allowed/,
    );
    // switch OFF (provider unchanged, no egressMethods): POST passes, exactly as today.
    const res = await new ConnectionHandle(acme, owner, { enterpriseId: null, teamId: 'T1', userId: 'U1' }, vault, audit).fetch('https://api.acme.example/x', { method: 'POST' });
    assert.equal(res.status, 200);
  } finally {
    globalThis.fetch = real;
  }
});
