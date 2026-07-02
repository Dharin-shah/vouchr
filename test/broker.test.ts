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
import { userOwner, channelOwner } from '../src/core/owner';
import { ChannelConfig } from '../src/core/channelConfig';
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
  const seen: { auth: string | null; method: string; url: string; contentType: string | null; body: unknown }[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    const headers = new Headers(init?.headers);
    seen.push({
      auth: headers.get('authorization'),
      method: init?.method ?? 'GET',
      url: String(url),
      contentType: headers.get('content-type'),
      body: init?.body,
    });
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

test('fetch: allowWrites + provider egressMethods lets a POST body reach upstream, with audit method', async () => {
  const events: any[] = [];
  const writeAcme = { ...acme, egressMethods: ['GET', 'POST'] } as Provider;
  const { server, db, port } = await makeBroker({ providers: [writeAcme], allowWrites: true, auditSink: (e) => events.push(e) });
  const up = mockUpstream(() => new Response('{"created":true}', { status: 201, headers: { 'content-type': 'application/json' } }));
  try {
    const payload = JSON.stringify({ title: 'from broker' });
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'POST',
      path: '/issues',
      headers: { 'content-type': 'application/json', authorization: 'Bearer attacker-token' },
      body: payload,
    });

    assert.equal(r.status, 200);
    assert.equal(r.json.status, 201);
    assert.equal(r.json.body, '{"created":true}');
    assert.equal(up.seen.length, 1);
    assert.equal(up.seen[0].method, 'POST');
    assert.equal(up.seen[0].body, payload);
    assert.equal(up.seen[0].contentType, 'application/json');
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`, 'caller Authorization was dropped; Vouchr injected the token');

    const row = await db.get(`SELECT meta FROM audit WHERE action='inject' ORDER BY at DESC LIMIT 1`) as any;
    assert.equal(JSON.parse(row.meta).method, 'POST');
    assert.equal(events[0].method, 'POST');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: write no-content responses pass through as empty successful bodies', async () => {
  const writeAcme = { ...acme, egressMethods: ['PUT', 'DELETE', 'PATCH'] } as Provider;
  const { server, port } = await makeBroker({ providers: [writeAcme], allowWrites: true });
  const responses = [
    () => new Response(null, { status: 204 }),
    () => new Response(null, { status: 205 }),
    () => new Response('', { status: 200, headers: { 'content-length': '0' } }),
  ];
  const up = mockUpstream(() => responses.shift()!());
  try {
    const put = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'PUT',
      path: '/issue/1',
      body: '{}',
    });
    assert.equal(put.status, 200);
    assert.equal(put.json.status, 204);
    assert.equal(put.json.body, '');

    const del = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'DELETE',
      path: '/issue/1',
      body: '{}',
    });
    assert.equal(del.status, 200);
    assert.equal(del.json.status, 205);
    assert.equal(del.json.body, '');

    const patch = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'PATCH',
      path: '/issue/1',
      body: '{}',
    });
    assert.equal(patch.status, 200);
    assert.equal(patch.json.status, 200);
    assert.equal(patch.json.body, '');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: allowWrites still requires per-provider egressMethods', async () => {
  const { server, port } = await makeBroker({ allowWrites: true }); // acme has no egressMethods
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'POST',
      path: '/x',
      body: '{}',
    });
    assert.equal(r.status, 403);
    assert.equal(up.seen.length, 0, 'provider without egressMethods stays read-only');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: allowWrites denies methods not listed by the provider', async () => {
  const writeAcme = { ...acme, egressMethods: ['GET', 'POST'] } as Provider;
  const { server, port } = await makeBroker({ providers: [writeAcme], allowWrites: true });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'DELETE',
      path: '/x',
      body: '{}',
    });
    assert.equal(r.status, 403);
    assert.equal(up.seen.length, 0, 'method denial happens before upstream');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: write body over the broker cap is rejected, never truncated or forwarded', async () => {
  const writeAcme = { ...acme, egressMethods: ['POST'] } as Provider;
  const { server, port } = await makeBroker({ providers: [writeAcme], allowWrites: true });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const maxBody = 'x'.repeat(64 * 1024);
    const ok = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'POST',
      path: '/x',
      body: maxBody,
    });
    assert.equal(ok.status, 200);
    assert.equal(up.seen[0].body, maxBody);

    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'POST',
      path: '/x',
      body: 'x'.repeat(64 * 1024 + 1),
    });
    assert.equal(r.status, 413);
    assert.equal(up.seen.length, 1);
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: write requests still enforce host, path, validator, and replay checks', async () => {
  const guarded = {
    ...acme,
    egressMethods: ['POST'],
    egressPaths: ['/allowed'],
    egressValidate: (url: URL) => url.searchParams.get('ok') === '1',
  } as Provider;
  const { server, port } = await makeBroker({ providers: [guarded], allowWrites: true });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const blockedHost = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'POST', host: 'evil.example.com', path: '/allowed', query: { ok: '1' }, body: '{}',
    });
    assert.equal(blockedHost.status, 403);

    const blockedPath = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'POST', path: '/blocked', query: { ok: '1' }, body: '{}',
    });
    assert.equal(blockedPath.status, 403);

    const blockedValidator = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'POST', path: '/allowed', query: { ok: '0' }, body: '{}',
    });
    assert.equal(blockedValidator.status, 403);
    assert.equal(up.seen.length, 0, 'egress denials happen before upstream');

    const token = signIdentity(claims(), SECRET);
    const first = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: token,
      method: 'POST', path: '/allowed', query: { ok: '1' }, body: '{}',
    });
    assert.equal(first.status, 200);
    const replay = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: token,
      method: 'POST', path: '/allowed', query: { ok: '1' }, body: '{}',
    });
    assert.equal(replay.status, 401);
    assert.equal(up.seen.length, 1, 'replay did not reach upstream');
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

test('resolve: a service-to-service provider is refused (403), never reported connected', async () => {
  const { server, port } = await makeBroker({ providers: [acme, svc] });
  try {
    const token = signIdentity(claims(), SECRET);
    const r = await post(port, '/v1/resolve', { handle: { provider: 'svc', owner: 'user' }, identityToken: token });
    assert.equal(r.status, 403); // not {connected|needs_consent}: Vouchr does not broker service tools
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

test('fetch: write requests still honor Policy before injection', async () => {
  const policy = new Policy({ acme: { defaultAllow: true, denyChannels: ['C1'] } });
  const writeAcme = { ...acme, egressMethods: ['POST'] } as Provider;
  const { server, port } = await makeBrokerOn(() => ({ providers: [writeAcme], allowWrites: true, policy }));
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'POST',
      path: '/x',
      body: '{}',
    });
    assert.equal(r.status, 403);
    assert.equal(up.seen.length, 0);
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

test('fetch: write requests still honor ChannelTools before injection', async () => {
  const writeAcme = { ...acme, egressMethods: ['POST'] } as Provider;
  const { server, db, port } = await makeBrokerOn((db) => ({
    providers: [writeAcme],
    allowWrites: true,
    channelTools: new ChannelTools(db),
  }));
  await new ChannelTools(db).setEnabled('T1', 'C1', 'other', true);
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'POST',
      path: '/x',
      body: '{}',
    });
    assert.equal(r.status, 403);
    assert.equal(up.seen.length, 0);
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

test('fetch/resolve: owner:"channel" is rejected by default (no channelConfig; forged body can\'t reach a channel cred)', async () => {
  const { server, port } = await makeBroker();
  try {
    // #51: a forged body owner:'channel' on a PLAIN user token (no signed ownerKind) is refused — the
    // signed claim defaults to 'user' and must match the handle. 403, never a channel-credential read.
    const f = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'channel' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' } as any);
    assert.equal(f.status, 403);
    // /v1/resolve stays user-only in #51: a channel handle is an invalid handle there.
    const rv = await post(port, '/v1/resolve', { handle: { provider: 'acme', owner: 'channel' }, identityToken: signIdentity(claims(), SECRET) } as any);
    assert.equal(rv.status, 400);
  } finally {
    server.close();
  }
});

// ── #51 transport-agnostic channel gate (owner:"channel" via SIGNED claims) ──────

/** A broker with the channel gate ENABLED (channelConfig set), seeded per the requested mode. */
async function makeChannelBroker(mode: 'shared' | 'union' | 'per-user') {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  await channelConfig.setMode('T1', 'C1', 'acme', mode);
  if (mode === 'shared') {
    // The channel owns one credential every member injects.
    await vault.upsert(channelOwner('T1', 'C1'), 'acme', {
      accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  if (mode === 'union') {
    // A connected member (U9) whose OWN credential the caller elects to act as.
    await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U9' }), 'acme', {
      accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: SECRET, channelConfig });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, vault, db, port: (server.address() as any).port };
}

/** Sign a channel-owned identity token (the SIGNED facts a trusted caller supplies). */
function channelToken(over: Partial<IdentityClaims> = {}): string {
  return signIdentity(claims({ ownerKind: 'channel', channelEligible: true, ...over }), SECRET);
}

test('#51 shared: owner:"channel" resolves to the channel credential and injects it', async () => {
  const { server, db, port } = await makeChannelBroker('shared');
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken(), method: 'GET', path: '/x',
    });
    assert.equal(r.status, 200);
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`, 'the channel-owned token was injected');
    // Audited as the acting human (invariant 9); the channel-owned inject promotes the channel column.
    const row = (await db.get(`SELECT user_id, channel FROM audit WHERE action='inject' ORDER BY at DESC LIMIT 1`)) as any;
    assert.equal(row.user_id, 'U1'); // the real acting human, never the channel
    assert.equal(row.channel, 'C1'); // attributed to the channel that owns the credential
  } finally {
    up.restore();
    server.close();
  }
});

test('#51 union: resolves to and audits the SIGNED acting member (never the caller)', async () => {
  const { server, db, port } = await makeChannelBroker('union');
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    // Caller (U1) elects to act as connected member U9; the member is the vault owner AND audited actor.
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken({ actingMemberId: 'U9' }), method: 'GET', path: '/x',
    });
    assert.equal(r.status, 200);
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`);
    const row = (await db.get(`SELECT user_id, channel FROM audit WHERE action='inject' ORDER BY at DESC LIMIT 1`)) as any;
    assert.equal(row.user_id, 'U9');   // audited as U9 (the real member whose cred was used), not caller U1
    assert.equal(row.channel, null);   // union uses U9's OWN (user-owned) cred, so no channel attribution
  } finally {
    up.restore();
    server.close();
  }
});

test('#51 union without a signed actingMemberId -> 400 (no member to act as)', async () => {
  const { server, port } = await makeChannelBroker('union');
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken(), method: 'GET', path: '/x',
    });
    assert.equal(r.status, 400);
  } finally {
    server.close();
  }
});

test('#51 ineligible signed claim -> refused (fail closed, cred never read)', async () => {
  const { server, port } = await makeChannelBroker('shared');
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    // channelEligible:false (the caller computed channelIneligibleReason() != null) -> 403.
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken({ channelEligible: false }), method: 'GET', path: '/x',
    });
    assert.equal(r.status, 403);
    // Also refused when the eligibility claim is simply ABSENT (fail closed).
    const r2 = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' }, identityToken: signIdentity(claims({ ownerKind: 'channel' }), SECRET), method: 'GET', path: '/x',
    });
    assert.equal(r2.status, 403);
    assert.equal(up.seen.length, 0, 'the vault/upstream was never reached');
  } finally {
    up.restore();
    server.close();
  }
});

test('#51 a per-user channel is not reachable via owner:"channel"', async () => {
  const { server, port } = await makeChannelBroker('per-user');
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken(), method: 'GET', path: '/x',
    });
    assert.equal(r.status, 403);
  } finally {
    server.close();
  }
});

test('#51 forged signed ownerKind mismatch: body owner:"user" but claim says "channel" -> refused', async () => {
  const { server, port } = await makeChannelBroker('shared');
  try {
    // The handle must match the SIGNED ownerKind; a user handle with a channel claim is refused.
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: channelToken(), method: 'GET', path: '/x',
    });
    assert.equal(r.status, 403);
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

// ── standalone-broker seams (PR1) ─────────────────────────────────────────────

test('health: GET /health is an alias for /healthz', async () => {
  const { server, port } = await makeBroker();
  try {
    const hz = await get(port, '/healthz');
    const h = await get(port, '/health');
    assert.equal(hz.status, 200);
    assert.equal(h.status, 200);
    assert.equal(h.json.ok, true);
    assert.equal(h.json.dbReachable, true);
    assert.equal(h.json.signingKeyLoaded, true);
  } finally {
    server.close();
  }
});

test('perimeter: a custom authorize hook replaces the brokerToken gate (reject then accept)', async () => {
  const authorize = (req: any) => { if (req.headers['x-svc'] !== 'ok') throw new Error('nope'); };
  const { server, port } = await makeBroker({ authorize });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const denied = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(denied.status, 401);            // hook threw a plain Error -> 401, before identity verify
    assert.equal(up.seen.length, 0);             // never reached upstream
    const ok = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' }, { 'x-svc': 'ok' });
    assert.equal(ok.status, 200);                // hook passed -> normal flow
    assert.equal(up.seen.length, 1);
  } finally {
    up.restore();
    server.close();
  }
});

test('refresh single-flight: concurrent broker requests collapse to ONE /token call (shared inflight map)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const refreshing = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: false, clientId: 'id', clientSecret: 'sec',
  });
  // Expired token so both concurrent requests trigger a refresh; a slow /token keeps both in the
  // refresh window at once, so a per-request inflight map would fire TWO /token calls.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: Date.now() - 1000, externalAccount: null });
  const server = createBroker({ providers: [refreshing], vault, audit, db, identitySecret: SECRET });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  const real = globalThis.fetch;
  let tokenCalls = 0;
  globalThis.fetch = (async (url: any) => {
    if (String(url) === 'https://acme.example/token') {
      tokenCalls++;
      await new Promise((r) => setTimeout(r, 50)); // hold both requests in the refresh window
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const req = () => post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    const [a, b] = await Promise.all([req(), req()]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.equal(tokenCalls, 1, 'shared inflight map must collapse the two concurrent refreshes into one /token call');
  } finally {
    globalThis.fetch = real;
    server.close();
  }
});

// ── #54 lifecycle: disconnect / admin offboard ───────────────────────────────

test('#54 /v1/disconnect removes the acting user\'s connection; resolve then needs_consent', async () => {
  const { server, port, vault } = await makeBroker(); // seeds U1's acme cred
  try {
    const d = await post(port, '/v1/disconnect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(d.status, 200);
    assert.deepEqual(d.json.revoked, ['acme']);
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
    const rv = await post(port, '/v1/resolve', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(rv.json.consentState, 'needs_consent');
  } finally {
    server.close();
  }
});

test('#54 /v1/disconnect acts only on the token identity (a different user is untouched)', async () => {
  const { server, port, vault } = await makeBroker();
  // Seed a second user U2 whose cred must survive U1 disconnecting.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  try {
    await post(port, '/v1/disconnect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims({ userId: 'U1' }), SECRET) });
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
    assert.ok(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme'), 'U2 must be untouched');
  } finally {
    server.close();
  }
});

test('#54 /v1/admin/offboard with a signed isAdmin claim clears the target user', async () => {
  const { server, port, vault } = await makeBroker();
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  try {
    const r = await post(port, '/v1/admin/offboard', { identityToken: signIdentity(claims({ userId: 'ADMIN', isAdmin: true }), SECRET), targetUserId: 'U2' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.revoked, ['acme']);
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme'), null);
  } finally {
    server.close();
  }
});

test('#54 /v1/admin/offboard without the signed isAdmin claim -> 403 (forged body can\'t assert admin)', async () => {
  const { server, port, vault } = await makeBroker();
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  try {
    // A plain user token, plus a forged body isAdmin flag (ignored — authority is the signed claim only).
    const r = await post(port, '/v1/admin/offboard', { identityToken: signIdentity(claims(), SECRET), targetUserId: 'U2', isAdmin: true } as any);
    assert.equal(r.status, 403);
    assert.ok(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme'), 'a refused offboard must not remove anything');
  } finally {
    server.close();
  }
});

test('#54 /v1/admin/offboard requires a targetUserId', async () => {
  const { server, port } = await makeBroker();
  try {
    const r = await post(port, '/v1/admin/offboard', { identityToken: signIdentity(claims({ isAdmin: true }), SECRET) });
    assert.equal(r.status, 400);
  } finally {
    server.close();
  }
});

// ── #52 OAuth connect + callback routes ──────────────────────────────────────

/** A broker with the OAuth connect flow mounted (baseUrl set), starting with NO stored cred. */
async function makeOauthBroker(extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const server = createBroker({
    providers: [acme, svc], vault, audit, db, identitySecret: SECRET,
    baseUrl: 'https://broker.example', callbackPath: '/oauth/callback', ...extra,
  });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, vault, db, port: (server.address() as any).port };
}

/** Raw GET (the callback returns HTML, not JSON). */
function getRaw(port: number, path: string): Promise<{ status: number; raw: string; contentType: string | null }> {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, raw: Buffer.concat(chunks).toString('utf8'), contentType: res.headers['content-type'] ?? null }));
    }).on('error', reject);
  });
}

test('#52 /v1/connect mints an authorizeUrl + single-use state bound to the verified user', async () => {
  const { server, port, db } = await makeOauthBroker();
  try {
    const r = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(r.status, 200);
    assert.match(r.json.authorizeUrl, /^https:\/\/acme\.example\/auth\?/);
    assert.match(r.json.authorizeUrl, /redirect_uri=https%3A%2F%2Fbroker\.example%2Foauth%2Fcallback/);
    assert.ok(r.json.state, 'no state returned');
    // State is persisted bound to the VERIFIED identity (U1), never the body.
    const row = (await db.get(`SELECT user_id, provider FROM consent_request WHERE state=?`, [r.json.state])) as any;
    assert.equal(row.user_id, 'U1');
    assert.equal(row.provider, 'acme');
  } finally {
    server.close();
  }
});

test('#52 /v1/connect refuses a tampered identity token (identity only from the signed token)', async () => {
  const { server, port } = await makeOauthBroker();
  try {
    const r = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: 'not-a-real-token' });
    assert.equal(r.status, 401);
  } finally {
    server.close();
  }
});

test('#52 /v1/connect refuses a service tool (no human credential / OAuth handshake)', async () => {
  const { server, port } = await makeOauthBroker();
  try {
    const r = await post(port, '/v1/connect', { handle: { provider: 'svc' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(r.status, 403);
  } finally {
    server.close();
  }
});

test('#52 /v1/connect is 404 when baseUrl is unset (use-only broker unchanged)', async () => {
  const { server, port } = await makeBroker(); // no baseUrl
  try {
    const r = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(r.status, 404);
  } finally {
    server.close();
  }
});

test('#52 full flow: connect -> callback vaults the token -> /v1/fetch succeeds', async () => {
  const { server, port } = await makeOauthBroker();
  const NEW = 'NEW_ACCESS_TOKEN_from_oauth';
  const real = globalThis.fetch;
  globalThis.fetch = (async (u: any, init: any) => {
    if (String(u).startsWith('https://acme.example/token')) {
      return new Response(JSON.stringify({ access_token: NEW }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    // upstream provider API: echo the injected Authorization so we can assert the new token flows.
    const auth = new Headers(init?.headers).get('authorization');
    return new Response(JSON.stringify({ auth }), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const c = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
    const cb = await getRaw(port, `/oauth/callback?code=abc123&state=${encodeURIComponent(c.json.state)}`);
    assert.equal(cb.status, 200);
    assert.match(cb.contentType ?? '', /text\/html/);
    assert.match(cb.raw, /connected/);
    // The token is now vaulted; a subsequent fetch injects it and resolve reports connected.
    const f = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(f.status, 200);
    assert.equal(JSON.parse(f.json.body).auth, `Bearer ${NEW}`);
    const rv = await post(port, '/v1/resolve', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(rv.json.consentState, 'connected');
  } finally {
    globalThis.fetch = real;
    server.close();
  }
});

test('#52 callback with provider denial (?error) audits consent_denied and stores no token', async () => {
  const events: any[] = [];
  const { server, port, db } = await makeOauthBroker({ auditSink: (e) => events.push(e) });
  try {
    const c = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
    const cb = await getRaw(port, `/oauth/callback?error=access_denied&state=${encodeURIComponent(c.json.state)}`);
    assert.equal(cb.status, 400);
    assert.ok(events.some((e) => e.action === 'consent_denied'), 'consent_denied not emitted on the audit stream');
    const conn = await db.get(`SELECT 1 AS x FROM connection WHERE owner_id='U1' AND provider='acme'`);
    assert.equal(conn, undefined, 'a denied consent must not store a connection');
  } finally {
    server.close();
  }
});

test('#52 callback state is single-use: replaying it fails (no second connection)', async () => {
  const { server, port } = await makeOauthBroker();
  const real = globalThis.fetch;
  globalThis.fetch = (async (u: any) =>
    String(u).startsWith('https://acme.example/token')
      ? new Response(JSON.stringify({ access_token: 'x' }), { status: 200, headers: { 'content-type': 'application/json' } })
      : new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    const c = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
    const first = await getRaw(port, `/oauth/callback?code=abc&state=${encodeURIComponent(c.json.state)}`);
    assert.equal(first.status, 200);
    const replay = await getRaw(port, `/oauth/callback?code=abc&state=${encodeURIComponent(c.json.state)}`);
    assert.equal(replay.status, 400); // state already consumed
  } finally {
    globalThis.fetch = real;
    server.close();
  }
});

// ── #53 admin channel-credential reference (POST /v1/admin/reference) ─────────

async function makeAdminBroker(extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  const server = createBroker({ providers: [acme, svc], vault, audit, db, identitySecret: SECRET, channelConfig, ...extra });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, vault, db, channelConfig, port: (server.address() as any).port };
}

function adminToken(over: Partial<IdentityClaims> = {}): string {
  return signIdentity(claims({ userId: 'ADMIN', isAdmin: true, channelEligible: true, ...over }), SECRET);
}

test('#53 admin reference stores a channel ref, flips to shared; a member fetch resolves it at egress', async () => {
  const resolvers = { 'aws-sm': async (ref: string) => (ref === 'arn:xyz' ? SECRET_TOKEN : 'WRONG') };
  const { server, port, channelConfig } = await makeAdminBroker({ resolvers });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken(), source: 'aws-sm', secretRef: 'arn:xyz',
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), 'shared');
    // A channel member's fetch now injects the JIT-resolved secret (never stored raw).
    const f = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken(), method: 'GET', path: '/x' });
    assert.equal(f.status, 200);
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`);
  } finally {
    up.restore();
    server.close();
  }
});

test('#53 non-admin signed token -> refused (nothing configured)', async () => {
  const { server, port, channelConfig } = await makeAdminBroker();
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: signIdentity(claims({ channelEligible: true }), SECRET), source: 'aws-sm', secretRef: 'arn:xyz',
    });
    assert.equal(r.status, 403);
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), null);
  } finally {
    server.close();
  }
});

test('#53 forged body admin flag (no signed isAdmin claim) -> refused', async () => {
  const { server, port } = await makeAdminBroker();
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: signIdentity(claims({ channelEligible: true }), SECRET),
      source: 'aws-sm', secretRef: 'arn:xyz', isAdmin: true,
    } as any);
    assert.equal(r.status, 403);
  } finally {
    server.close();
  }
});

test('#53 ineligible channel (signed eligibility false) -> refused', async () => {
  const { server, port, channelConfig } = await makeAdminBroker();
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken({ channelEligible: false }), source: 'aws-sm', secretRef: 'arn:xyz',
    });
    assert.equal(r.status, 403);
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), null);
  } finally {
    server.close();
  }
});

test('#53 refused when channel modes are not enabled (no channelConfig)', async () => {
  const { server, port } = await makeBroker(); // no channelConfig
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken(), source: 'aws-sm', secretRef: 'arn:xyz',
    });
    assert.equal(r.status, 403);
  } finally {
    server.close();
  }
});

test('#53 no raw secret is accepted (source + secretRef are required, not a token)', async () => {
  const { server, port } = await makeAdminBroker();
  try {
    const r = await post(port, '/v1/admin/reference', { handle: { provider: 'acme' }, identityToken: adminToken() } as any);
    assert.equal(r.status, 400);
  } finally {
    server.close();
  }
});

test('#53 refuses a channel locked to a user-owned mode (invariant 7)', async () => {
  const { server, port, channelConfig } = await makeAdminBroker();
  await channelConfig.setMode('T1', 'C1', 'acme', 'per-user');
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken(), source: 'aws-sm', secretRef: 'arn:xyz',
    });
    assert.equal(r.status, 409);
  } finally {
    server.close();
  }
});

// ── #55 batch status + tool manifest (POST /v1/status, GET /v1/manifest) ──────

const other = defineProvider({
  id: 'other', authorizeUrl: 'https://other.example/auth', tokenUrl: 'https://other.example/token',
  scopesDefault: ['x'], egressAllow: ['api.other.example'], refresh: 'none', pkce: false, clientId: 'id', clientSecret: 'sec',
});

async function makeMultiBroker(extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  // Only acme is connected for U1; `other` is not; `svc` is a service tool (never brokered).
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [acme, other, svc], vault, audit, db, identitySecret: SECRET, ...extra });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, db, port: (server.address() as any).port };
}

test('#55 /v1/status batches connection state across brokered providers (service omitted)', async () => {
  const { server, port } = await makeMultiBroker();
  try {
    const r = await post(port, '/v1/status', { identityToken: signIdentity(claims(), SECRET) });
    assert.equal(r.status, 200);
    const byId = Object.fromEntries(r.json.providers.map((p: any) => [p.provider, p]));
    assert.deepEqual(byId.acme, { provider: 'acme', connected: true, consentState: 'connected' });
    assert.deepEqual(byId.other, { provider: 'other', connected: false, consentState: 'needs_consent' });
    assert.equal(byId.svc, undefined, 'service tools are not brokered, so they are omitted from status');
    assert.ok(!r.raw.includes(SECRET_TOKEN), 'status must never carry secret material');
  } finally {
    server.close();
  }
});

test('#55 /v1/status rejects a tampered identity token', async () => {
  const { server, port } = await makeMultiBroker();
  try {
    const r = await post(port, '/v1/status', { identityToken: 'nope' });
    assert.equal(r.status, 401);
  } finally {
    server.close();
  }
});

test('#55 /v1/manifest lists providers with their acting_human/service identity', async () => {
  const { server, port } = await makeMultiBroker();
  try {
    const r = await get(port, '/v1/manifest');
    assert.equal(r.status, 200);
    const byId = Object.fromEntries(r.json.providers.map((p: any) => [p.provider, p.identity]));
    assert.equal(byId.acme, 'acting_human');
    assert.equal(byId.other, 'acting_human');
    assert.equal(byId.svc, 'service');
  } finally {
    server.close();
  }
});

test('#55 /v1/manifest sits behind the perimeter gate', async () => {
  const { server, port } = await makeMultiBroker({ brokerToken: 'sekret' });
  try {
    const missing = await get(port, '/v1/manifest'); // no bearer
    assert.equal(missing.status, 401);
  } finally {
    server.close();
  }
});
