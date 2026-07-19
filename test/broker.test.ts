import { test, type TestContext } from 'node:test';
import { openTestDb, testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Policy } from '../src/core/policy';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { defineProvider, type Provider } from '../src/core/providers';
import { ConnectionHandle, type VouchrEvent } from '../src/core/injector';
import { userOwner, channelOwner } from '../src/core/owner';
import { ChannelConfig, writeChannelMode } from '../src/core/channelConfig';
import { MAX_SECRET_REFERENCE_BYTES } from '../src/core/reference';
import { createBroker, withEgressDefaults } from '../src/adapters/http/broker';
import { openDb } from '../src/core/db';
import { Consent } from '../src/core/consent';
import { offboardUser, offboardUserEverywhere } from '../src/core/offboard';
import { ChannelProvisioningRequests } from '../src/core/provisioning';
import { identityKid, normalizeIdentityConfig } from '../src/adapters/http/identity';
import {
  signIdentity,
  mintIdentity,
  verifyIdentity,
  identityConfig,
  IdentityError,
  ReplayGuard,
  IDENTITY_SKEW_MS,
  type IdentityClaims,
} from './support/identity';

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK'; // the vaulted token that must never escape
const AWS_ADMIN_REF = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/channel';
const AWS_USER_REF = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/user';
const VAULT_USER_REF = 'vault://secret/vouchr/user#token';

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

async function makeBroker(t: TestContext, extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  // Seed U1's acme credential so /v1/fetch has a token to (privately) inject.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), ...extra });
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
  const { iss, aud, iat, kid, ...roundTrip } = verifyIdentity(tok, SECRET);
  assert.deepEqual(roundTrip, c);
  assert.ok(iss && aud && iat && kid, 'test broker identity is deployment-bound');

  // wrong secret -> bad signature
  assert.throws(() => verifyIdentity(tok, 'other'), IdentityError);
  // flipped last char -> bad signature
  assert.throws(() => verifyIdentity(tok.slice(0, -1) + (tok.endsWith('a') ? 'b' : 'a'), SECRET), IdentityError);
  // expired
  assert.throws(() => verifyIdentity(signIdentity(claims({ exp: Date.now() - IDENTITY_SKEW_MS - 1 }), SECRET), SECRET), /expired/);
  // lifetime > 5min
  assert.throws(() => verifyIdentity(signIdentity(claims({ exp: Date.now() + 10 * 60_000 }), SECRET), SECRET), /5min/);
});

test('identity: jti is single-use within the replay guard', () => {
  const replay = new ReplayGuard();
  const tok = signIdentity(claims(), SECRET);
  assert.ok(verifyIdentity(tok, SECRET, { replay })); // first use ok
  assert.throws(() => verifyIdentity(tok, SECRET, { replay }), /replayed jti/); // second use rejected
});

test('#212 createBroker rejects a legacy bare identity secret at the production boundary', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  assert.throws(
    () => createBroker({ providers: [acme], vault, audit, db, identitySecret: SECRET as any }),
    /identity config must be a plain object/,
  );
});

test('#212 createBroker rejects identity-key reuse with direct broker/provider secrets', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const identity = identityConfig('purpose-reuse');
  const reused = identity.keys[0].secret;
  const provider = defineProvider({
    id: 'reused',
    authorizeUrl: 'https://reused.example/auth',
    tokenUrl: 'https://reused.example/token',
    scopesDefault: ['x'],
    egressAllow: ['api.reused.example'],
    refresh: 'none',
    pkce: false,
    clientId: 'id',
    clientSecret: reused,
  });

  for (const options of [
    { providers: [acme], brokerToken: reused },
    { providers: [provider] },
  ]) {
    assert.throws(
      () => createBroker({ ...options, vault, audit, db, identitySecret: identity }),
      (error: Error) => /distinct/.test(error.message) && !error.message.includes(reused),
    );
  }

  const masterSecret = 'M7vouchrMasterKey2026abcdef12345';
  const masterIdentity = normalizeIdentityConfig({
    issuer: 'vouchr-test',
    audience: 'test-deployment',
    keys: [{ kid: identityKid(masterSecret), secret: masterSecret }],
  });
  assert.throws(
    () => createBroker({
      providers: [acme], vault: new Vault(db, Buffer.from(masterSecret)), audit, db,
      identitySecret: masterIdentity,
    }),
    (error: Error) => /distinct from the master key/.test(error.message) && !error.message.includes(masterSecret),
  );
});

// ── /v1/fetch ────────────────────────────────────────────────────────────────

test('fetch: token is NEVER present in the response body', async (t) => {
  const { server, port } = await makeBroker(t);
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

test('fetch: the broker forwards metrics events to onEvent (no longer a black box), no secret', async (t) => {
  const events: VouchrEvent[] = [];
  const { server, port } = await makeBroker(t, { onEvent: (e) => events.push(e) });
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

test('fetch: the broker emits an audit-STREAM event (raw verified actor id) to auditSink, no secret', async (t) => {
  const events: any[] = [];
  const { server, port } = await makeBroker(t, { auditSink: (e) => events.push(e) });
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

test('fetch: an incoming traceparent is propagated onto the outbound provider fetch', async (t) => {
  const { server, port } = await makeBroker(t);
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

test('fetch: non-GET/HEAD -> 405 BEFORE the vault/upstream is touched', async (t) => {
  const { server, port } = await makeBroker(t);
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

test('fetch: invalid methods return 400 with no side effects; canonical method reaches upstream', async (t) => {
  const writeAcme = { ...acme, egressMethods: ['GET', 'POST'] } as Provider;
  const { server, vault, db, port } = await makeBroker(t, { providers: [writeAcme], allowWrites: true });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  const realGet = vault.get.bind(vault);
  let credentialReads = 0;
  (vault as any).get = (...args: any[]) => {
    credentialReads += 1;
    return (realGet as any)(...args);
  };
  const request = (method: unknown) => post(port, '/v1/fetch', {
    handle: { provider: 'acme', owner: 'user' },
    identityToken: signIdentity(claims(), SECRET),
    method,
    path: '/data',
  });
  try {
    for (const method of ['', ' ', 'PO ST', 'POST\n', '\tGET', 'GE\u007fT', 'POſT', 'CONNECT', 'TRACE', 'TRACK', null, undefined]) {
      const response = await request(method);
      assert.equal(response.status, 400);
      assert.deepEqual(response.json, { error: 'invalid method' });
    }
    assert.equal(up.seen.length, 0);
    assert.equal(credentialReads, 0);
    assert.equal((await db.all(`SELECT 1 FROM approval_request`)).length, 0);
    assert.equal((await db.all(`SELECT 1 FROM audit`)).length, 0);

    const canonical = await request(' post ');
    assert.equal(canonical.status, 200);
    assert.equal(up.seen[0].method, 'POST', 'the canonical method is the one sent upstream');
    assert.equal(credentialReads, 1);
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: allowWrites + provider egressMethods lets a POST body reach upstream, with audit method', async (t) => {
  const events: any[] = [];
  const writeAcme = { ...acme, egressMethods: ['GET', 'POST'] } as Provider;
  const { server, db, port } = await makeBroker(t, { providers: [writeAcme], allowWrites: true, auditSink: (e) => events.push(e) });
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

test('fetch: write no-content responses pass through as empty successful bodies', async (t) => {
  const writeAcme = { ...acme, egressMethods: ['PUT', 'DELETE', 'PATCH'] } as Provider;
  const { server, port } = await makeBroker(t, { providers: [writeAcme], allowWrites: true });
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

test('fetch: allowWrites still requires per-provider egressMethods', async (t) => {
  const { server, port } = await makeBroker(t, { allowWrites: true }); // acme has no egressMethods
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

test('fetch: allowWrites denies methods not listed by the provider', async (t) => {
  const writeAcme = { ...acme, egressMethods: ['GET', 'POST'] } as Provider;
  const { server, port } = await makeBroker(t, { providers: [writeAcme], allowWrites: true });
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

test('fetch: write body over the broker cap is rejected, never truncated or forwarded', async (t) => {
  const writeAcme = { ...acme, egressMethods: ['POST'] } as Provider;
  const { server, port } = await makeBroker(t, { providers: [writeAcme], allowWrites: true });
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

test('fetch: write requests still enforce host, path, validator, and replay checks', async (t) => {
  const guarded = {
    ...acme,
    egressMethods: ['POST'],
    egressPaths: ['/allowed'],
    egressValidate: (url: URL) => url.searchParams.get('ok') === '1',
  } as Provider;
  const { server, port } = await makeBroker(t, { providers: [guarded], allowWrites: true });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const blockedHost = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'POST', host: 'evil.example.com', path: '/allowed', query: { ok: '1' }, body: '{}',
    });
    assert.equal(blockedHost.status, 403);
    assert.deepEqual(blockedHost.json, {
      error: 'egress blocked', code: 'egress_blocked', retryable: false, recovery: 'fix_configuration',
    });

    const blockedPath = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'POST', path: '/blocked', query: { ok: '1' }, body: '{}',
    });
    assert.equal(blockedPath.status, 403);
    assert.deepEqual(blockedPath.json, blockedHost.json);

    const blockedValidator = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'POST', path: '/allowed', query: { ok: '0' }, body: '{}',
    });
    assert.equal(blockedValidator.status, 403);
    assert.deepEqual(blockedValidator.json, blockedHost.json);
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

test('fetch: unsigned/expired identity -> 401', async (t) => {
  const { server, port } = await makeBroker(t);
  try {
    const bad = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: 'not.a.real.token', method: 'GET', path: '/x' });
    assert.equal(bad.status, 401);
    const expired = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims({ exp: Date.now() - IDENTITY_SKEW_MS - 1 }), SECRET), method: 'GET', path: '/x',
    });
    assert.equal(expired.status, 401);
  } finally {
    server.close();
  }
});

test('fetch: a replayed jti is rejected on the second call', async (t) => {
  const { server, port } = await makeBroker(t);
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

test('#212 PostgreSQL replay protection rejects one jti across broker instances', async (t) => {
  // Two brokers over ONE shared db must make a jti single-use CLUSTER-WIDE.
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const a = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET) });
  const b = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET) });
  await new Promise<void>((r) => a.listen(0, r));
  await new Promise<void>((r) => b.listen(0, r));
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const tok = signIdentity(claims(), SECRET);
    const first = await post((a.address() as any).port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: tok, method: 'GET', path: '/x' });
    assert.equal(first.status, 200);
    const onOther = await post((b.address() as any).port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: tok, method: 'GET', path: '/x' });
    assert.equal(onOther.status, 401); // replay refused cluster-wide, with NO explicit store passed
  } finally {
    up.restore();
    a.close();
    b.close();
    await db.close();
  }
});

test('fetch: a service-to-service provider is refused (403), never brokered', async (t) => {
  const { server, port } = await makeBroker(t, { providers: [acme, svc] });
  try {
    const token = signIdentity(claims(), SECRET);
    const r = await post(port, '/v1/fetch', { handle: { provider: 'svc', owner: 'user' }, identityToken: token, method: 'GET', path: '/x' });
    assert.equal(r.status, 403);
    assert.ok(!r.raw.includes(SECRET_TOKEN)); // and no credential material anywhere in the response
  } finally {
    server.close();
  }
});

test('resolve: a service-to-service provider is refused (403), never reported connected', async (t) => {
  const { server, port } = await makeBroker(t, { providers: [acme, svc] });
  try {
    const token = signIdentity(claims(), SECRET);
    const r = await post(port, '/v1/resolve', { handle: { provider: 'svc', owner: 'user' }, identityToken: token });
    assert.equal(r.status, 403); // not {connected|needs_consent}: Vouchr does not broker service tools
  } finally {
    server.close();
  }
});

test('fetch: body-supplied identity is IGNORED; cross-tenant probe gets the attacker their OWN (empty) owner', async (t) => {
  const { server, port } = await makeBroker(t);
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
    assert.deepEqual(r.json, {
      error: 'not connected', code: 'not_connected', retryable: false, recovery: 'connect',
    });
    assert.equal(up.seen.length, 0, 'U1\'s token was never read, so nothing went upstream');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: over-cap response -> 413, never a truncated partial body', async (t) => {
  const { server, port } = await makeBroker(t, { maxResponseBytes: 64 });
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

test('fetch: disallowed content-type is rejected before the body is returned', async (t) => {
  const { server, port } = await makeBroker(t);
  const up = mockUpstream(() => new Response('<html>injection</html>', { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } }));
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(r.status, 502);
    assert.deepEqual(r.json, {
      error: 'disallowed content-type',
      code: 'response_blocked',
      retryable: false,
      recovery: 'fix_configuration',
    });
    assert.ok(!r.raw.includes('injection'), 'disallowed body never relayed');
  } finally {
    up.restore();
    server.close();
  }
});

test('fetch: content-type allowlist ignores ;charset and is case-insensitive', async (t) => {
  const { server, port } = await makeBroker(t);
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

test('resolve: returns existence + consent state, NEVER the secret', async (t) => {
  const { server, port } = await makeBroker(t);
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

// ── #101 /healthz (liveness) + /readyz (readiness) ────────────────────────────

test('#101 healthz: liveness is a bare 200 {ok:true}, never touches the db', async (t) => {
  const { server, db, port } = await makeBroker(t);
  try {
    const up = await get(port, '/healthz');
    assert.equal(up.status, 200);
    assert.deepEqual(up.json, { ok: true }); // bare status only — no db field, no secrets

    await db.close(); // liveness must stay green even with the db down (that's readiness' job)
    const stillUp = await get(port, '/healthz');
    assert.equal(stillUp.status, 200);
    assert.deepEqual(stillUp.json, { ok: true });
  } finally {
    server.close();
  }
});

test('#101 readyz: 200 with a working db, 503 (bare {ok:false}) when the db is unreachable', async (t) => {
  const { server, db, port } = await makeBroker(t);
  try {
    const ready = await get(port, '/readyz');
    assert.equal(ready.status, 200);
    assert.deepEqual(ready.json, { ok: true });

    await db.close(); // db now unreachable
    const notReady = await get(port, '/readyz');
    assert.equal(notReady.status, 503);
    assert.deepEqual(notReady.json, { ok: false }); // bare status: no error text / connection string
  } finally {
    server.close();
  }
});

test('#212 readyz: 503 when the cluster-wide replay relation is missing', async (t) => {
  const { server, db, port } = await makeBroker(t);
  try {
    assert.equal((await get(port, '/readyz')).status, 200);
    await db.exec('DROP TABLE broker_jti');
    const notReady = await get(port, '/readyz');
    assert.equal(notReady.status, 503);
    assert.deepEqual(notReady.json, { ok: false });
  } finally {
    server.close();
  }
});

test('#212 readyz: 503 when the replay conflict arbiter is missing', async (t) => {
  const { server, db, port } = await makeBroker(t);
  try {
    assert.equal((await get(port, '/readyz')).status, 200);
    await db.exec('ALTER TABLE broker_jti DROP CONSTRAINT broker_jti_pkey');
    const notReady = await get(port, '/readyz');
    assert.equal(notReady.status, 503);
    assert.deepEqual(notReady.json, { ok: false });
  } finally {
    server.close();
  }
});

test('#212 readyz: 503 when the replay expiry column is missing', async (t) => {
  const { server, db, port } = await makeBroker(t);
  try {
    assert.equal((await get(port, '/readyz')).status, 200);
    await db.exec('ALTER TABLE broker_jti DROP COLUMN exp');
    const notReady = await get(port, '/readyz');
    assert.equal(notReady.status, 503);
    assert.deepEqual(notReady.json, { ok: false });
  } finally {
    server.close();
  }
});

test('#212 createBroker rejects the removed custom replayStore at runtime', async (t) => {
  const db = await openTestDb(t);
  assert.throws(
    () => createBroker({
      providers: [acme], vault: new Vault(db, KEY), audit: new Audit(db), db,
      identitySecret: identityConfig(SECRET),
      replayStore: { use: () => true, ready: async () => {} },
    } as any),
    /replayStore is not configurable; PostgreSQL replay protection is required/,
  );
});

test('#101 probes need no auth and leak no secrets even behind a brokerToken gate', async (t) => {
  const { server, port } = await makeBroker(t, { brokerToken: 'perimeter-secret' });
  try {
    const hz = await get(port, '/healthz'); // no Authorization header sent
    const rz = await get(port, '/readyz');
    assert.equal(hz.status, 200);
    assert.equal(rz.status, 200);
    // The bodies are exactly the minimal JSON — no token, config, or error text.
    assert.equal(JSON.stringify(hz.json), '{"ok":true}');
    assert.equal(JSON.stringify(rz.json), '{"ok":true}');
  } finally {
    server.close();
  }
});

// ── operator authorization parity with the Bolt path (#21/#22): Policy + ChannelTools ──

/** Build a broker over a fresh in-memory db with U1's acme credential seeded, returning the db so a
 *  test can wire a Policy / ChannelTools backed by the SAME store the broker reads. */
async function makeBrokerOn(t: TestContext, build: (db: any, vault: Vault, audit: Audit) => Partial<Parameters<typeof createBroker>[0]>) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), ...build(db, vault, audit) });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, db, audit, port: (server.address() as any).port };
}

test('fetch: a Policy that denies the provider in this channel -> 403, credential NEVER injected', async (t) => {
  // Policy denies acme in C1 (the channel comes from the verified claims, not the body).
  const policy = new Policy({ acme: { defaultAllow: true, denyChannels: ['C1'] } });
  const { server, db, port } = await makeBrokerOn(t, () => ({ policy }));
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

test('fetch: write requests still honor Policy before injection', async (t) => {
  const policy = new Policy({ acme: { defaultAllow: true, denyChannels: ['C1'] } });
  const writeAcme = { ...acme, egressMethods: ['POST'] } as Provider;
  const { server, port } = await makeBrokerOn(t, () => ({ providers: [writeAcme], allowWrites: true, policy }));
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

test('fetch: a ChannelTools allowlist that disables the provider here -> 403, credential NEVER injected', async (t) => {
  const { server, db, port } = await makeBrokerOn(t, (db) => ({ channelTools: new ChannelTools(db) }));
  // Configure the channel as an allowlist that does NOT include acme -> acme is disabled here.
  await setChannelToolEnabled(new ChannelTools(db), 'T1', 'C1', 'other', true);
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

test('fetch: write requests still honor ChannelTools before injection', async (t) => {
  const writeAcme = { ...acme, egressMethods: ['POST'] } as Provider;
  const { server, db, port } = await makeBrokerOn(t, (db) => ({
    providers: [writeAcme],
    allowWrites: true,
    channelTools: new ChannelTools(db),
  }));
  await setChannelToolEnabled(new ChannelTools(db), 'T1', 'C1', 'other', true);
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

test('fetch: a caller-supplied Authorization header is DROPPED; only the broker-injected Bearer reaches upstream', async (t) => {
  const { server, port } = await makeBroker(t);
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

test('fetch: brokerToken network gate — wrong/absent token 401, correct token passes', async (t) => {
  const { server, port } = await makeBroker(t, { brokerToken: 'perimeter-secret' });
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

test('fetch: a malformed host -> clean 400, not a 500', async (t) => {
  const { server, port } = await makeBroker(t);
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

test('fetch/resolve: owner:"channel" is rejected by default (no channelConfig; forged body can\'t reach a channel cred)', async (t) => {
  const { server, port } = await makeBroker(t);
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

test('#194 session-mode broker denial has stable request-approval recovery metadata', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  await writeChannelMode(channelConfig, 'T1', 'C1', 'acme', 'session');
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({
    providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), channelConfig,
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims({ threadTs: '1700000000.000001' }), SECRET),
      method: 'GET', path: '/x',
    });
    assert.equal(r.status, 403);
    assert.deepEqual(r.json, {
      error: 'provider requires a thread-scoped session approval',
      code: 'session_approval_required',
      retryable: false,
      recovery: 'request_approval',
    });
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

// ── #51 transport-agnostic channel gate (owner:"channel" via SIGNED claims) ──────

/** A broker with the channel gate ENABLED (channelConfig set), seeded per the requested mode. */
async function makeChannelBroker(t: TestContext, mode: 'shared' | 'per-user', seedShared = true) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  await writeChannelMode(channelConfig, 'T1', 'C1', 'acme', mode);
  if (mode === 'shared' && seedShared) {
    // The channel owns one credential every member injects.
    await vault.upsert(channelOwner('T1', 'C1'), 'acme', {
      accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), channelConfig });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, vault, db, port: (server.address() as any).port };
}

/** Sign a channel-owned identity token (the SIGNED facts a trusted caller supplies). */
function channelToken(over: Partial<IdentityClaims> = {}): string {
  return signIdentity(claims({ ownerKind: 'channel', channelEligible: true, ...over }), SECRET);
}

test('#194 shared owner missing a credential returns configuration recovery, never personal connect', async (t) => {
  const { server, port } = await makeChannelBroker(t, 'shared', false);
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken(), method: 'GET', path: '/x',
    });
    assert.equal(r.status, 409);
    assert.deepEqual(r.json, {
      error: 'not connected', code: 'not_connected', retryable: false, recovery: 'fix_configuration',
    });
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#51 shared: owner:"channel" resolves to the channel credential and injects it', async (t) => {
  const { server, db, port } = await makeChannelBroker(t, 'shared');
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

test('#194 shared use rejects a pre-offboard assertion while preserving the channel credential', async (t) => {
  const { server, vault, db, port } = await makeChannelBroker(t, 'shared');
  const owner = channelOwner('T1', 'C1');
  const sharedId = await vault.liveId(owner, 'acme');
  assert.ok(sharedId);
  const stale = channelToken();
  await new Consent(db).markOffboarded({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  const up = mockUpstream(() => new Response('{}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }));
  try {
    const refused = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' },
      identityToken: stale,
      method: 'GET',
      path: '/x',
    });
    assert.equal(refused.status, 409);
    assert.equal(refused.json.code, 'interaction_state_changed');
    assert.equal(refused.json.retryable, false);
    assert.equal(refused.json.recovery, 'resolve_again');
    assert.equal(up.seen.length, 0);
    assert.equal(
      (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='inject'`))?.n,
      0,
    );
    assert.equal(await vault.liveId(owner, 'acme'), sharedId);

    // The stale path above proves the fence. Pin the marker to a known earlier instant so this fresh
    // assertion is unambiguously post-tombstone under both PostgreSQL and process clocks; a 1ms
    // boundary races the broker's conservative assertion-age calculation under coverage.
    await db.run(
      `UPDATE offboard_tombstone SET created_at=0 WHERE team_id=? AND user_id=?`,
      ['T1', 'U1'],
    );
    const fresh = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' },
      identityToken: channelToken(),
      method: 'GET',
      path: '/x',
    });
    assert.equal(fresh.status, 200, 'a post-tombstone assertion represents a re-onboarded actor');
    assert.equal(up.seen.length, 1);
  } finally {
    up.restore();
    server.close();
  }
});

test('#51 ineligible signed claim -> refused (fail closed, cred never read)', async (t) => {
  const { server, port } = await makeChannelBroker(t, 'shared');
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

test('#51 a per-user channel is not reachable via owner:"channel"', async (t) => {
  const { server, port } = await makeChannelBroker(t, 'per-user');
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken(), method: 'GET', path: '/x',
    });
    assert.equal(r.status, 403);
  } finally {
    server.close();
  }
});

test('#51 forged signed ownerKind mismatch: body owner:"user" but claim says "channel" -> refused', async (t) => {
  const { server, port } = await makeChannelBroker(t, 'shared');
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

test('egress default-deny: unset egressMethods means GET/HEAD-only under the broker switch', async (t) => {
  // The broker clones the provider with egressMethods=['GET','HEAD'] when defaultDenyNonGet is on,
  // and the EXISTING injector enforcement (injector.ts) denies POST. Without the switch, POST passes.
  const db = await openTestDb(t);
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

test('health: GET /health is an alias for the /healthz liveness probe', async (t) => {
  const { server, port } = await makeBroker(t);
  try {
    const hz = await get(port, '/healthz');
    const h = await get(port, '/health');
    assert.equal(hz.status, 200);
    assert.equal(h.status, 200);
    assert.deepEqual(h.json, { ok: true });
  } finally {
    server.close();
  }
});

test('perimeter: a custom authorize hook replaces the brokerToken gate (reject then accept)', async (t) => {
  const authorize = (req: any) => { if (req.headers['x-svc'] !== 'ok') throw new Error('nope'); };
  const { server, port } = await makeBroker(t, { authorize });
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

test('refresh single-flight: concurrent broker requests collapse to ONE /token call (shared inflight map)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const refreshing = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: false, clientId: 'id', clientSecret: 'sec',
  });
  // Expired token so both concurrent requests trigger a refresh; a slow /token keeps both in the
  // refresh window at once, so a per-request inflight map would fire TWO /token calls.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: Date.now() - 1000, externalAccount: null });
  const server = createBroker({ providers: [refreshing], vault, audit, db, identitySecret: identityConfig(SECRET) });
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

test('#54 /v1/disconnect removes the acting user\'s connection; resolve then needs_consent', async (t) => {
  const { server, port, vault } = await makeBroker(t); // seeds U1's acme cred
  try {
    const credentialId = await vault.liveId(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme');
    const d = await post(port, '/v1/disconnect', { handle: { provider: 'acme', credentialId }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(d.status, 200);
    assert.deepEqual(d.json.revoked, ['acme']);
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
    const rv = await post(port, '/v1/resolve', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(rv.json.consentState, 'needs_consent');
  } finally {
    server.close();
  }
});

test('#194 resolve can bind an immediate headless disconnect to one exact credential generation', async (t) => {
  const { server, port, vault } = await makeBroker(t);
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  try {
    const resolvedA = await post(port, '/v1/resolve', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      includeCredentialId: true,
    });
    assert.equal(resolvedA.status, 200);
    assert.equal(resolvedA.json.connected, true);
    assert.equal(typeof resolvedA.json.credentialId, 'string');

    await vault.upsert(owner, 'acme', {
      accessToken: 'GENERATION_B', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
    const generationB = await vault.liveId(owner, 'acme');
    assert.ok(generationB);
    assert.notEqual(generationB, resolvedA.json.credentialId);

    const stale = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme', credentialId: resolvedA.json.credentialId },
      identityToken: signIdentity(claims(), SECRET),
    });
    assert.equal(stale.status, 409);
    assert.equal(stale.json.code, 'interaction_state_changed');
    assert.equal(await vault.liveId(owner, 'acme'), generationB);

    const resolvedB = await post(port, '/v1/resolve', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      includeCredentialId: true,
    });
    assert.equal(resolvedB.json.credentialId, generationB);
    const current = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme', credentialId: resolvedB.json.credentialId },
      identityToken: signIdentity(claims(), SECRET),
    });
    assert.equal(current.status, 200);
    assert.deepEqual(current.json, { ok: true, revoked: ['acme'] });
    assert.equal(await vault.has(owner, 'acme'), false);
  } finally {
    server.close();
  }
});

test('#54 /v1/disconnect acts only on the token identity (a different user is untouched)', async (t) => {
  const { server, port, vault } = await makeBroker(t);
  // Seed a second user U2 whose cred must survive U1 disconnecting.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  try {
    const credentialId = await vault.liveId(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme');
    await post(port, '/v1/disconnect', { handle: { provider: 'acme', credentialId }, identityToken: signIdentity(claims({ userId: 'U1' }), SECRET) });
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
    assert.ok(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme'), 'U2 must be untouched');
  } finally {
    server.close();
  }
});

test('/v1/disconnect reports a referenced revocable credential as only locally removed', async (t) => {
  const provider = defineProvider({
    ...acme,
    revokeUrl: 'https://acme.example/revoke',
  });
  const { server, port, vault, db } = await makeBroker(t, { providers: [provider] });
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  await vault.reference(owner, 'acme', { source: 'external', secretRef: 'TEST_EXTERNAL_REFERENCE' });

  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = (async () => {
    upstreamCalls++;
    return new Response('', { status: 200 });
  }) as any;
  try {
    const credentialId = await vault.liveId(owner, 'acme');
    const r = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme', credentialId }, identityToken: signIdentity(claims(), SECRET),
    });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { ok: false, revoked: ['acme'] });
    assert.equal(upstreamCalls, 0);
    assert.equal(await vault.has(owner, 'acme'), false);
    const row = (await db.get(
      `SELECT meta FROM audit WHERE action='revoke' AND provider='acme'`,
    )) as { meta: string };
    assert.deepEqual(JSON.parse(row.meta), { ok: false, upstream: 'skipped' });
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});

test('/v1/disconnect returns a static 404 for an unregistered, unstored provider and writes no audit', async (t) => {
  const { server, port, db } = await makeBroker(t);
  const untrusted = 'ghp_UNTRUSTED_PROVIDER_MUST_NOT_BE_REFLECTED';
  try {
    const r = await post(port, '/v1/disconnect', {
      handle: { provider: untrusted }, identityToken: signIdentity(claims(), SECRET),
    });
    assert.equal(r.status, 404);
    assert.deepEqual(r.json, { error: 'unknown provider' });
    assert.ok(!r.raw.includes(untrusted));
    assert.equal(((await db.get(`SELECT COUNT(*) AS n FROM audit WHERE action='revoke'`)) as any).n, 0);
  } finally {
    server.close();
  }
});

test('/v1/disconnect removes a stale stored provider and preserves the success wire shape', async (t) => {
  const { server, port, vault, db } = await makeBroker(t);
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  await vault.upsert(owner, 'retired', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  try {
    const credentialId = await vault.liveId(owner, 'retired');
    const r = await post(port, '/v1/disconnect', {
      handle: { provider: 'retired', credentialId }, identityToken: signIdentity(claims(), SECRET),
    });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { ok: false, revoked: ['retired'] });
    assert.equal(await vault.has(owner, 'retired'), false);
    const row = (await db.get(`SELECT meta FROM audit WHERE action='revoke' AND provider='retired'`)) as any;
    assert.deepEqual(JSON.parse(row.meta), { ok: false, upstream: 'skipped' });
  } finally {
    server.close();
  }
});

test('/v1/disconnect reports a committed delete when auditing fails without exposing the error', async (t) => {
  const auditError = 'ghp_AUDIT_FAILURE_MUST_NOT_REACH_HTTP';
  const badAudit = { record: async () => { throw new Error(auditError); } } as unknown as Audit;
  const { server, port, vault } = await makeBroker(t, { audit: badAudit });
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  try {
    const credentialId = await vault.liveId(owner, 'acme');
    const r = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme', credentialId }, identityToken: signIdentity(claims(), SECRET),
    });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { ok: false, revoked: ['acme'] });
    assert.equal(await vault.has(owner, 'acme'), false);
    assert.ok(!r.raw.includes(auditError));
  } finally {
    server.close();
  }
});

test('/v1/disconnect reports an incomplete fence without losing the committed local removal', async (t) => {
  const { server, port, vault, db } = await makeBroker(t);
  const sentinel = 'ghp_HTTP_FENCE_FAILURE_MUST_NOT_ESCAPE';
  await db.exec(`
    CREATE FUNCTION fail_http_provisioning_fence() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION '${sentinel}';
    END;
    $$ LANGUAGE plpgsql;
    CREATE TRIGGER fail_http_provisioning_fence
      BEFORE INSERT OR UPDATE ON provisioning_revocation_tombstone
      FOR EACH ROW EXECUTE FUNCTION fail_http_provisioning_fence();
  `);
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  try {
    const credentialId = await vault.liveId(owner, 'acme');
    const r = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme', credentialId }, identityToken: signIdentity(claims(), SECRET),
    });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { ok: false, revoked: ['acme'] });
    assert.equal(await vault.has(owner, 'acme'), false);
    assert.ok(!r.raw.includes(sentinel));
    const row = await db.get<{ meta: string }>(
      `SELECT meta FROM audit WHERE action='revoke' AND provider='acme'`,
    );
    assert.deepEqual(JSON.parse(row!.meta), { ok: false, upstream: 'skipped' });
    assert.ok(!row!.meta.includes(sentinel));
  } finally {
    server.close();
  }
});

test('#194 a delayed pre-offboard disconnect cannot revoke a fresh post-offboard credential', async (t) => {
  const databaseUrl = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl }),
    openDb({ databaseUrl }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const provider = defineProvider({
    ...acme,
    revokeUrl: 'https://acme.example/revoke',
  });
  const vaultA = new Vault(dbA, KEY);
  const vaultB = new Vault(dbB, KEY);
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  await vaultA.upsert(owner, 'acme', {
    accessToken: 'OLD_TOKEN', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const staleAssertion = signIdentity(claims(), SECRET);
  const server = createBroker({
    providers: [provider], vault: vaultA, audit: new Audit(dbA), db: dbA,
    identitySecret: identityConfig(SECRET),
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;

  await offboardUser(vaultB, new Audit(dbB), new Consent(dbB), {
    enterpriseId: null, teamId: 'T1', userId: 'U1',
  });
  // A legitimate new setup occurs after the tombstones. Keep it a separate credential generation.
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(await vaultB.upsert(owner, 'acme', {
    accessToken: 'FRESH_TOKEN', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  }), true);
  const freshId = await vaultB.liveId(owner, 'acme');
  assert.ok(freshId);
  const auditBefore = (await dbB.get<{ n: number }>(
    `SELECT COUNT(*)::int AS n FROM audit WHERE action='revoke' AND provider='acme'`,
  ))!.n;
  const markerBefore = await dbB.get<{ created_at: number }>(
    `SELECT created_at FROM provisioning_revocation_tombstone
      WHERE provider='acme' AND scope_kind='team-user'`,
  );
  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = (async () => {
    upstreamCalls++;
    return new Response('', { status: 200 });
  }) as any;
  try {
    const response = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme' }, identityToken: staleAssertion,
    });
    assert.equal(response.status, 409);
    assert.deepEqual(response.json, {
      error: 'authorization changed; resolve and retry',
      code: 'interaction_state_changed',
      retryable: false,
      recovery: 'resolve_again',
    });
    assert.equal(await vaultB.liveId(owner, 'acme'), freshId);
    assert.equal((await vaultB.get(owner, 'acme'))?.accessToken, 'FRESH_TOKEN');
    assert.equal(upstreamCalls, 0, 'the stale request must not revoke either token generation');
    assert.equal((await dbB.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM audit WHERE action='revoke' AND provider='acme'`,
    ))!.n, auditBefore);
    assert.deepEqual(
      await dbB.get<{ created_at: number }>(
        `SELECT created_at FROM provisioning_revocation_tombstone
          WHERE provider='acme' AND scope_kind='team-user'`,
      ),
      markerBefore,
      'a stale disconnect must not advance the provisioning revocation fence',
    );
    const replay = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme' }, identityToken: staleAssertion,
    });
    assert.equal(replay.status, 401);
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});

test('#194 a delayed assertion cannot retarget disconnect onto a later reconnect', async (t) => {
  const databaseUrl = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl }),
    openDb({ databaseUrl }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const provider = defineProvider({
    ...acme,
    revokeUrl: 'https://acme.example/revoke',
  });
  const vaultA = new Vault(dbA, KEY);
  const vaultB = new Vault(dbB, KEY);
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  await vaultA.upsert(owner, 'acme', {
    accessToken: 'GENERATION_A', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const staleAssertion = signIdentity(claims(), SECRET);
  await new Promise((resolve) => setTimeout(resolve, 5));
  await vaultB.upsert(owner, 'acme', {
    accessToken: 'GENERATION_B', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const generationB = await vaultB.liveId(owner, 'acme');
  assert.ok(generationB);

  const server = createBroker({
    providers: [provider], vault: vaultA, audit: new Audit(dbA), db: dbA,
    identitySecret: identityConfig(SECRET),
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;
  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = (async () => {
    upstreamCalls++;
    return new Response('', { status: 200 });
  }) as any;
  try {
    const response = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme' }, identityToken: staleAssertion,
    });
    assert.equal(response.status, 409);
    assert.deepEqual(response.json, {
      error: 'connection changed; resolve and retry',
      code: 'interaction_state_changed',
      retryable: false,
      recovery: 'resolve_again',
    });
    assert.equal(await vaultB.liveId(owner, 'acme'), generationB);
    assert.equal((await vaultB.get(owner, 'acme'))?.accessToken, 'GENERATION_B');
    assert.equal(upstreamCalls, 0);
    assert.equal(
      (await dbB.get<{ n: number }>(
        `SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone`,
      ))!.n,
      0,
    );
    assert.equal(
      (await dbB.get<{ n: number }>(
        `SELECT COUNT(*)::int AS n FROM audit WHERE action='revoke'`,
      ))!.n,
      0,
    );
    const replay = await post(port, '/v1/disconnect', {
      handle: { provider: 'acme' }, identityToken: staleAssertion,
    });
    assert.equal(replay.status, 401);
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});

test('#54 /v1/admin/offboard with a signed isAdmin claim clears the target user', async (t) => {
  const { server, port, vault, db } = await makeBroker(t);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const setup = new ChannelProvisioningRequests(db, vault);
  const target = { enterpriseId: null, teamId: 'T1', userId: 'U2' };
  assert.ok(await setup.issue(
    target,
    'C1',
    'acme',
    await vault.userProvisioningIssuedAt(),
  ));
  try {
    const r = await post(port, '/v1/admin/offboard', { identityToken: signIdentity(claims({ userId: 'ADMIN', isAdmin: true }), SECRET), targetUserId: 'U2' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.revoked, ['acme']);
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme'), null);
    assert.equal(
      (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM channel_provisioning_request`))?.n,
      0,
    );
  } finally {
    server.close();
  }
});

test('#194 team admin offboard reports incomplete when upstream revocation fails', async (t) => {
  const revocableAcme = defineProvider({
    ...acme,
    revokeUrl: 'https://acme.example/revoke',
  });
  const { server, port, vault, db } = await makeBroker(t, { providers: [revocableAcme] });
  const target = { enterpriseId: null, teamId: 'T1', userId: 'U2' };
  await vault.upsert(userOwner(target), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = (async () => {
    upstreamCalls++;
    return new Response('refused', { status: 500 });
  }) as any;
  try {
    const response = await post(port, '/v1/admin/offboard', {
      identityToken: signIdentity(claims({ userId: 'ADMIN', isAdmin: true }), SECRET),
      targetUserId: target.userId,
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { ok: false, revoked: ['acme'] });
    assert.equal(await vault.get(userOwner(target), 'acme'), null, 'local deletion still commits');
    assert.equal(upstreamCalls, 1);
    const row = await db.get<{ meta: string }>(
      `SELECT meta FROM audit WHERE action='revoke' AND team_id=? AND user_id=?`,
      [target.teamId, target.userId],
    );
    assert.equal(JSON.parse(row!.meta).ok, false);
    assert.ok(!response.raw.includes(SECRET_TOKEN));
    assert.ok(!row!.meta.includes(SECRET_TOKEN));
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});

test('#194 team admin offboard reports incomplete when its audit row cannot be recorded', async (t) => {
  let auditCalls = 0;
  const failingAudit = {
    record: async () => {
      auditCalls++;
      throw new Error('audit unavailable');
    },
  } as unknown as Audit;
  const { server, port, vault } = await makeBroker(t, { audit: failingAudit });
  const target = { enterpriseId: null, teamId: 'T1', userId: 'U2' };
  await vault.upsert(userOwner(target), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  try {
    const response = await post(port, '/v1/admin/offboard', {
      identityToken: signIdentity(claims({ userId: 'ADMIN', isAdmin: true }), SECRET),
      targetUserId: target.userId,
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { ok: false, revoked: ['acme'] });
    assert.equal(await vault.get(userOwner(target), 'acme'), null, 'local deletion still commits');
    assert.equal(auditCalls, 1);
    assert.ok(!response.raw.includes(SECRET_TOKEN));
  } finally {
    server.close();
  }
});

test('#54 /v1/admin/offboard without the signed isAdmin claim -> 403 (forged body can\'t assert admin)', async (t) => {
  const { server, port, vault } = await makeBroker(t);
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

test('#194 /v1/admin/offboard rejects an assertion issued before the acting admin was offboarded', async (t) => {
  const { server, port, vault, db } = await makeBroker(t);
  const actor = { enterpriseId: null, teamId: 'T1', userId: 'ADMIN' };
  const target = { enterpriseId: null, teamId: 'T1', userId: 'U2' };
  await vault.upsert(userOwner(target), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const stale = signIdentity(claims({ userId: actor.userId, isAdmin: true }), SECRET);
  await new Consent(db).markOffboarded(actor);
  try {
    const response = await post(port, '/v1/admin/offboard', {
      identityToken: stale,
      targetUserId: target.userId,
    });
    assert.equal(response.status, 409);
    assert.equal(response.json.code, 'interaction_state_changed');
    assert.equal(response.json.recovery, 'resolve_again');
    assert.ok(await vault.get(userOwner(target), 'acme'), 'the stale admin cannot remove the target');
    assert.equal(
      (await db.get<{ n: number }>(
        `SELECT COUNT(*)::int AS n FROM offboard_tombstone WHERE team_id=? AND user_id=?`,
        [target.teamId, target.userId],
      ))?.n,
      0,
      'the refused actor writes no target tombstone',
    );
  } finally {
    server.close();
  }
});

test('#54 /v1/admin/offboard requires a targetUserId', async (t) => {
  const { server, port } = await makeBroker(t);
  try {
    const r = await post(port, '/v1/admin/offboard', { identityToken: signIdentity(claims({ isAdmin: true }), SECRET) });
    assert.equal(r.status, 400);
  } finally {
    server.close();
  }
});

test('#194 enterprise offboard binds the target in the signed admin assertion', async (t) => {
  const { server, port, vault, db } = await makeBroker(t);
  const foreign = { enterpriseId: null, teamId: 'T_FOREIGN', userId: 'U_FOREIGN' };
  await vault.upsert(userOwner(foreign), 'acme', {
    accessToken: 'FOREIGN_USER_TOKEN', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  try {
    const forged = await post(port, '/v1/admin/offboard', {
      identityToken: signIdentity(claims({
        userId: 'ADMIN',
        isAdmin: true,
        enterpriseId: 'E1',
        offboardTargetUserId: 'U_E1_MEMBER',
      }), SECRET),
      targetUserId: foreign.userId,
    });
    assert.equal(forged.status, 403);
    assert.deepEqual(forged.json, { error: 'signed offboard target required' });
    assert.ok(await vault.get(userOwner(foreign), 'acme'));
    assert.equal(
      (await db.get<{ n: number }>(
        `SELECT COUNT(*)::int AS n FROM user_offboard_scope_tombstone WHERE user_id=?`,
        [foreign.userId],
      ))?.n,
      0,
      'a body-selected foreign target must not gain even an unscoped tombstone',
    );
  } finally {
    server.close();
  }
});

test('#194 enterprise offboard accepts the exact signed target', async (t) => {
  const { server, port, vault } = await makeBroker(t);
  const target = { enterpriseId: 'E1', teamId: 'T_E1_MEMBER', userId: 'U_E1_MEMBER' };
  await vault.upsert(userOwner(target), 'acme', {
    accessToken: 'E1_USER_TOKEN', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  try {
    const response = await post(port, '/v1/admin/offboard', {
      identityToken: mintIdentity({
        teamId: 'T1',
        userId: 'ADMIN',
        channel: 'C1',
        isAdmin: true,
        enterpriseId: target.enterpriseId,
        offboardTargetUserId: target.userId,
      }, SECRET),
      targetUserId: target.userId,
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { ok: true, revoked: ['acme'] });
    assert.equal(await vault.get(userOwner(target), 'acme'), null);
  } finally {
    server.close();
  }
});

test('#194 enterprise admin offboard includes a team with upstream debt in incompleteTeams', async (t) => {
  const revocableAcme = defineProvider({
    ...acme,
    revokeUrl: 'https://acme.example/revoke',
  });
  const { server, port, vault } = await makeBroker(t, { providers: [revocableAcme] });
  const target = { enterpriseId: 'E1', teamId: 'T_E1_MEMBER', userId: 'U_E1_MEMBER' };
  await vault.upsert(userOwner(target), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('refused', { status: 500 })) as any;
  try {
    const response = await post(port, '/v1/admin/offboard', {
      identityToken: mintIdentity({
        teamId: 'T1',
        userId: 'ADMIN',
        channel: 'C1',
        isAdmin: true,
        enterpriseId: target.enterpriseId,
        offboardTargetUserId: target.userId,
      }, SECRET),
      targetUserId: target.userId,
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { ok: false, revoked: ['acme'], incompleteTeams: 1 });
    assert.equal(await vault.get(userOwner(target), 'acme'), null, 'local deletion still commits');
    assert.ok(!response.raw.includes(SECRET_TOKEN));
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});

// ── #52 OAuth connect + callback routes ──────────────────────────────────────

/** A broker with the OAuth connect flow mounted (baseUrl set), starting with NO stored cred. */
async function makeOauthBroker(t: TestContext, extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const server = createBroker({
    providers: [acme, svc], vault, audit, db, identitySecret: identityConfig(SECRET),
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

test('#52 /v1/connect mints an authorizeUrl + single-use state bound to the verified user', async (t) => {
  const { server, port, db } = await makeOauthBroker(t);
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

test('#52 /v1/connect refuses a tampered identity token (identity only from the signed token)', async (t) => {
  const { server, port } = await makeOauthBroker(t);
  try {
    const r = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: 'not-a-real-token' });
    assert.equal(r.status, 401);
  } finally {
    server.close();
  }
});

test('#52 /v1/connect refuses a service tool (no human credential / OAuth handshake)', async (t) => {
  const { server, port } = await makeOauthBroker(t);
  try {
    const r = await post(port, '/v1/connect', { handle: { provider: 'svc' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(r.status, 403);
  } finally {
    server.close();
  }
});

test('#52 /v1/connect is 404 when baseUrl is unset (use-only broker unchanged)', async (t) => {
  const { server, port } = await makeBroker(t); // no baseUrl
  try {
    const r = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(r.status, 404);
  } finally {
    server.close();
  }
});

test('#52 full flow: connect -> callback vaults the token -> /v1/fetch succeeds', async (t) => {
  const { server, port } = await makeOauthBroker(t);
  const NEW = 'NEW_ACCESS_TOKEN_from_oauth';
  const real = globalThis.fetch;
  let upstreamAuth: string | null = null; // what the provider API received on the wire
  globalThis.fetch = (async (u: any, init: any) => {
    if (String(u).startsWith('https://acme.example/token')) {
      return new Response(JSON.stringify({ access_token: NEW }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    // upstream provider API: capture the injected Authorization so we can assert the new token flows on
    // the wire (the injection proof — the broker relays the body verbatim, no response sanitization).
    const auth = new Headers(init?.headers).get('authorization');
    upstreamAuth = auth;
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const c = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
    const cb = await getRaw(port, `/oauth/callback?code=abc123&state=${encodeURIComponent(c.json.state)}`);
    assert.equal(cb.status, 200);
    assert.match(cb.contentType ?? '', /text\/html/);
    assert.match(cb.raw, /connected/);
    // The supported headless callback surface must ALSO name the bound Slack identity, so a
    // forwarded /v1/connect URL cannot silently bind the completer's account to the initiator.
    assert.match(cb.raw, /U1/); // bound Slack user
    assert.match(cb.raw, /not you/i); // the forwarded-link warning
    // The token is now vaulted; a subsequent fetch injects it and resolve reports connected.
    const f = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(f.status, 200);
    // The new OAuth token was injected — observed on the wire (the upstream received it).
    assert.equal(upstreamAuth, `Bearer ${NEW}`);
    const rv = await post(port, '/v1/resolve', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET) });
    assert.equal(rv.json.consentState, 'connected');
  } finally {
    globalThis.fetch = real;
    server.close();
  }
});

test('#52 callback with provider denial (?error) audits consent_denied and stores no token', async (t) => {
  const events: any[] = [];
  const { server, port, db } = await makeOauthBroker(t, { auditSink: (e) => events.push(e) });
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

test('#52 callback state is single-use: replaying it fails (no second connection)', async (t) => {
  const { server, port } = await makeOauthBroker(t);
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

async function makeAdminBroker(t: TestContext, extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  const server = createBroker({
    providers: [acme, svc], vault, audit, db, identitySecret: identityConfig(SECRET), channelConfig,
    resolvers: { 'aws-sm': async () => SECRET_TOKEN },
    ...extra,
  });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, vault, db, channelConfig, port: (server.address() as any).port };
}

function adminToken(over: Partial<IdentityClaims> = {}): string {
  return signIdentity(claims({ userId: 'ADMIN', isAdmin: true, channelEligible: true, ...over }), SECRET);
}

test('#53 admin reference stores a channel ref, flips to shared; a member fetch resolves it at egress', async (t) => {
  let resolverCalls = 0;
  const resolvers = { 'aws-sm': async (ref: string) => { resolverCalls++; return ref === AWS_ADMIN_REF ? SECRET_TOKEN : 'WRONG'; } };
  const { server, port, channelConfig, vault, db } = await makeAdminBroker(t, { resolvers });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken(), secretRef: AWS_ADMIN_REF, scopes: 'x',
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
    assert.equal(resolverCalls, 0, 'configuration validates resolver presence without reading the secret');
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), 'shared');
    const stored = await vault.get(channelOwner('T1', 'C1'), 'acme');
    assert.equal(stored?.source, 'aws-sm');
    assert.equal(stored?.secretRef, AWS_ADMIN_REF);
    assert.equal(stored?.scopes, 'x');
    assert.equal(stored?.accessToken, null);
    const configAudit = await db.get<any>(`SELECT meta FROM audit WHERE action='config'`);
    assert.deepEqual(JSON.parse(configAudit.meta), {
      owner: 'channel', channel: 'C1', mode: 'shared', kind: 'ref', source: 'aws-sm',
    });
    // A channel member's fetch now injects the JIT-resolved secret (never stored raw).
    const f = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'channel' }, identityToken: channelToken(), method: 'GET', path: '/x' });
    assert.equal(f.status, 200);
    assert.equal(resolverCalls, 1);
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`);
    assert.ok(!r.raw.includes(SECRET_TOKEN) && !f.raw.includes(SECRET_TOKEN));
  } finally {
    up.restore();
    server.close();
  }
});

test('#53 non-admin signed token -> refused (nothing configured)', async (t) => {
  const { server, port, channelConfig } = await makeAdminBroker(t);
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: signIdentity(claims({ channelEligible: true }), SECRET), source: 'aws-sm', secretRef: AWS_ADMIN_REF,
    });
    assert.equal(r.status, 403);
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), null);
  } finally {
    server.close();
  }
});

test('#53 forged body admin flag (no signed isAdmin claim) -> refused', async (t) => {
  const { server, port } = await makeAdminBroker(t);
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: signIdentity(claims({ channelEligible: true }), SECRET),
      source: 'aws-sm', secretRef: AWS_ADMIN_REF, isAdmin: true,
    } as any);
    assert.equal(r.status, 403);
  } finally {
    server.close();
  }
});

test('#53 ineligible channel (signed eligibility false) -> refused', async (t) => {
  const { server, port, channelConfig } = await makeAdminBroker(t);
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken({ channelEligible: false }), source: 'aws-sm', secretRef: AWS_ADMIN_REF,
    });
    assert.equal(r.status, 403);
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), null);
  } finally {
    server.close();
  }
});

test('#53 refused when channel modes are not enabled (no channelConfig)', async (t) => {
  const { server, port } = await makeBroker(t); // no channelConfig
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken(), source: 'aws-sm', secretRef: AWS_ADMIN_REF,
    });
    assert.equal(r.status, 403);
  } finally {
    server.close();
  }
});

test('#53 no raw secret is accepted in place of a supported reference', async (t) => {
  const { server, port } = await makeAdminBroker(t);
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken(), secretRef: SECRET_TOKEN,
    });
    assert.equal(r.status, 400);
    assert.equal(r.json.code, 'invalid_reference');
    assert.ok(!r.raw.includes(SECRET_TOKEN));
  } finally {
    server.close();
  }
});

test('#53 both reference routes reject non-object JSON with a fixed 400 and no state', async (t) => {
  const { server, port, vault, db, channelConfig } = await makeAdminBroker(t);
  try {
    for (const path of ['/v1/admin/reference', '/v1/user/reference']) {
      for (const body of [null, [], 'reference', 53]) {
        const response = await post(port, path, body);
        assert.equal(response.status, 400);
        assert.deepEqual(response.json, { error: 'JSON body must be an object' });
      }
    }
    assert.equal(await vault.get(channelOwner('T1', 'C1'), 'acme'), null);
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), null);
    assert.equal((await db.get<any>('SELECT COUNT(*) n FROM audit')).n, 0);
  } finally {
    server.close();
  }
});

test('#53 admin reference rejects invalid input before connection, mode, or audit state', async (t) => {
  const sentinel = 'sk_live_ADMIN_REFERENCE_SENTINEL';
  const cases: Array<{ body: Record<string, unknown>; code: string; noResolver?: boolean }> = [
    { body: { secretRef: sentinel }, code: 'invalid_reference' },
    { body: { secretRef: `${AWS_ADMIN_REF} ${sentinel}` }, code: 'invalid_reference' },
    { body: { secretRef: 'gcp-sm://projects/../secrets/s/versions/latest' }, code: 'invalid_reference' },
    { body: { secretRef: AWS_ADMIN_REF, source: sentinel }, code: 'source_mismatch' },
    { body: { secretRef: AWS_ADMIN_REF, scopes: sentinel }, code: 'invalid_scopes' },
    { body: { secretRef: AWS_ADMIN_REF, scopes: `${sentinel}\nread` }, code: 'invalid_scopes' },
    { body: { secretRef: AWS_ADMIN_REF + 'x'.repeat(MAX_SECRET_REFERENCE_BYTES) }, code: 'invalid_reference' },
    { body: { secretRef: { sentinel } }, code: 'invalid_reference' },
    { body: { secretRef: AWS_ADMIN_REF }, code: 'resolver_unavailable', noResolver: true },
  ];

  for (const entry of cases) {
    const { server, port, vault, db, channelConfig } = await makeAdminBroker(
      t,
      entry.noResolver ? { resolvers: {} } : {},
    );
    try {
      const r = await post(port, '/v1/admin/reference', {
        handle: { provider: 'acme' }, identityToken: adminToken(), ...entry.body,
      });
      assert.equal(r.status, 400);
      assert.equal(r.json.code, entry.code);
      assert.ok(!r.raw.includes(sentinel), 'fixed validation response must not reflect caller input');
      assert.equal(await vault.get(channelOwner('T1', 'C1'), 'acme'), null);
      assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), null);
      assert.equal((await db.get<any>('SELECT COUNT(*) n FROM audit')).n, 0);
    } finally {
      server.close();
    }
  }
});

test('#53 refuses a channel locked to a user-owned mode (invariant 7)', async (t) => {
  const { server, port, channelConfig } = await makeAdminBroker(t);
  await writeChannelMode(channelConfig, 'T1', 'C1', 'acme', 'per-user');
  try {
    const r = await post(port, '/v1/admin/reference', {
      handle: { provider: 'acme' }, identityToken: adminToken(), source: 'aws-sm', secretRef: AWS_ADMIN_REF,
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

async function makeMultiBroker(t: TestContext, extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  // Only acme is connected for U1; `other` is not; `svc` is a service tool (never brokered).
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [acme, other, svc], vault, audit, db, identitySecret: identityConfig(SECRET), ...extra });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, db, port: (server.address() as any).port };
}

test('#194 stale assertions cannot read resolve, status, or the channel manifest and remain single-use', async (t) => {
  const { server, db, port } = await makeMultiBroker(t);
  const routes = [
    {
      name: 'resolve',
      path: '/v1/resolve',
      body: (identityToken: string) => ({
        handle: { provider: 'acme', owner: 'user' },
        identityToken,
      }),
      assertFresh: (json: any) => assert.deepEqual(json, {
        connected: true,
        consentState: 'connected',
      }),
    },
    {
      name: 'status',
      path: '/v1/status',
      body: (identityToken: string) => ({ identityToken }),
      assertFresh: (json: any) => {
        const byId = Object.fromEntries(json.providers.map((provider: any) => [provider.provider, provider]));
        assert.deepEqual(byId.acme, { provider: 'acme', connected: true, consentState: 'connected' });
        assert.deepEqual(byId.other, { provider: 'other', connected: false, consentState: 'needs_consent' });
        assert.equal(byId.svc, undefined);
      },
    },
    {
      name: 'channel manifest',
      path: '/v1/manifest',
      body: (identityToken: string) => ({ identityToken }),
      assertFresh: (json: any) => {
        const byId = Object.fromEntries(json.tools.map((tool: any) => [tool.provider, tool]));
        assert.deepEqual(byId.acme, { provider: 'acme', mode: null, enabled: true, identity: 'acting_human' });
        assert.equal(byId.svc.identity, 'service');
      },
    },
  ].map((route) => ({ ...route, staleBody: route.body(signIdentity(claims(), SECRET)) }));
  await new Consent(db).markOffboarded({ enterpriseId: null, teamId: 'T1', userId: 'U1' });

  try {
    for (const route of routes) {
      const refused = await post(port, route.path, route.staleBody);
      assert.equal(refused.status, 409, `${route.name} must reject the pre-offboard assertion`);
      assert.deepEqual(refused.json, {
        error: 'authorization changed; resolve and retry',
        code: 'interaction_state_changed',
        retryable: false,
        recovery: 'resolve_again',
      });
      const replay = await post(port, route.path, route.staleBody);
      assert.equal(replay.status, 401, `${route.name} must spend even a refused assertion`);
      assert.deepEqual(replay.json, { error: 'invalid identity token' });
    }

    // Make fresh assertions unambiguously post-tombstone without a wall-clock race. Exact boundary
    // behavior belongs to the core fence tests; these route tests verify every adapter gate.
    await db.run(
      `UPDATE offboard_tombstone SET created_at=0 WHERE team_id=? AND user_id=?`,
      ['T1', 'U1'],
    );
    for (const route of routes) {
      const fresh = await post(port, route.path, route.body(signIdentity(claims(), SECRET)));
      assert.equal(fresh.status, 200, `${route.name} accepts a post-tombstone assertion`);
      route.assertFresh(fresh.json);
    }
  } finally {
    server.close();
  }
});

test('#194 stale assertions reach no mutation-route probe, denial audit, or state', async (t) => {
  const { server, db, port } = await makeBrokerOn(t, (sharedDb) => ({
    providers: [acme, svc],
    baseUrl: 'https://broker.example',
    channelConfig: new ChannelConfig(sharedDb),
    channelTools: new ChannelTools(sharedDb),
    resolvers: { 'aws-sm': async () => SECRET_TOKEN },
  }));
  const staleClaims = { isAdmin: false, channelEligible: false };
  const routes = [
    {
      name: 'disconnect',
      path: '/v1/disconnect',
      body: (identityToken: string) => ({
        handle: { provider: 'not-registered' },
        identityToken,
      }),
    },
    {
      name: 'admin offboard',
      path: '/v1/admin/offboard',
      body: (identityToken: string) => ({ identityToken, targetUserId: 'U2' }),
    },
    {
      name: 'admin reference',
      path: '/v1/admin/reference',
      body: (identityToken: string) => ({
        handle: { provider: 'not-registered' },
        identityToken,
        secretRef: 'not-a-reference',
      }),
    },
    {
      name: 'admin mode',
      path: '/v1/admin/mode',
      body: (identityToken: string) => ({
        provider: 'not-registered', mode: 'shared', identityToken,
      }),
    },
    {
      name: 'admin tools',
      path: '/v1/admin/tools',
      body: (identityToken: string) => ({
        provider: 'not-registered', enabled: false, identityToken,
      }),
    },
    {
      name: 'connect',
      path: '/v1/connect',
      body: (identityToken: string) => ({
        handle: { provider: 'not-registered' }, identityToken,
      }),
    },
    {
      name: 'user reference',
      path: '/v1/user/reference',
      body: (identityToken: string) => ({
        handle: { provider: 'not-registered' },
        identityToken,
        secretRef: 'not-a-reference',
      }),
    },
  ].map((route) => ({
    ...route,
    request: route.body(signIdentity(claims(staleClaims), SECRET)),
  }));
  await new Consent(db).markOffboarded({ enterpriseId: null, teamId: 'T1', userId: 'U1' });

  try {
    for (const route of routes) {
      const refused = await post(port, route.path, route.request);
      assert.equal(refused.status, 409, `${route.name} must reject before route-specific work`);
      assert.deepEqual(refused.json, {
        error: 'authorization changed; resolve and retry',
        code: 'interaction_state_changed',
        retryable: false,
        recovery: 'resolve_again',
      });
      const replay = await post(port, route.path, route.request);
      assert.equal(replay.status, 401, `${route.name} must spend the refused assertion`);
      assert.deepEqual(replay.json, { error: 'invalid identity token' });
    }
    assert.equal((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit`))!.n, 0);
    assert.equal((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM connection`))!.n, 1);
    assert.equal((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM consent_request`))!.n, 0);
    assert.equal((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM channel_config`))!.n, 0);
    assert.equal((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM channel_tool`))!.n, 0);
  } finally {
    server.close();
  }
});

test('#55 /v1/status batches connection state across brokered providers (service omitted)', async (t) => {
  const { server, port } = await makeMultiBroker(t);
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

test('#55 /v1/status rejects a tampered identity token', async (t) => {
  const { server, port } = await makeMultiBroker(t);
  try {
    const r = await post(port, '/v1/status', { identityToken: 'nope' });
    assert.equal(r.status, 401);
  } finally {
    server.close();
  }
});

test('#55 /v1/manifest lists providers with their acting_human/service identity', async (t) => {
  const { server, port } = await makeMultiBroker(t);
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

test('#55 /v1/manifest sits behind the perimeter gate', async (t) => {
  const { server, port } = await makeMultiBroker(t, { brokerToken: 'sekret' });
  try {
    const missing = await get(port, '/v1/manifest'); // no bearer
    assert.equal(missing.status, 401);
  } finally {
    server.close();
  }
});

// ── #58 per-user reference-only config (POST /v1/user/reference) ──────────────

async function makeRefBroker(t: TestContext, extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const server = createBroker({
    providers: [acme, svc], vault, audit, db, identitySecret: identityConfig(SECRET),
    resolvers: { 'aws-sm': async () => SECRET_TOKEN },
    ...extra,
  });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, vault, db, port: (server.address() as any).port };
}

test('#58 user reference stores the acting user\'s ref; their fetch resolves it at egress', async (t) => {
  let resolverCalls = 0;
  const resolvers = { 'aws-sm': async (ref: string) => { resolverCalls++; return ref === AWS_USER_REF ? SECRET_TOKEN : 'WRONG'; } };
  const { server, port, vault, db } = await makeRefBroker(t, { resolvers });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await post(port, '/v1/user/reference', {
      handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET), secretRef: AWS_USER_REF,
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
    assert.equal(resolverCalls, 0, 'saving a reference must not read the external secret');
    // Stored against the acting user (U1) as a validated reference — no raw secret persisted.
    const cred = await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme');
    assert.equal(cred?.source, 'aws-sm');
    assert.equal(cred?.secretRef, AWS_USER_REF);
    assert.equal(cred?.accessToken, null);
    const configAudit = await db.get<any>(`SELECT meta FROM audit WHERE action='config'`);
    assert.deepEqual(JSON.parse(configAudit.meta), { owner: 'user', kind: 'ref', source: 'aws-sm' });
    const f = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET), method: 'GET', path: '/x' });
    assert.equal(f.status, 200);
    assert.equal(resolverCalls, 1);
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`);
    assert.ok(!r.raw.includes(SECRET_TOKEN) && !f.raw.includes(SECRET_TOKEN));
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 a pre-offboard identity token cannot recreate a user reference on another replica', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(() => Promise.all([dbA.close(), dbB.close()]));
  const vaultA = new Vault(dbA, KEY);
  const server = createBroker({
    providers: [acme],
    vault: vaultA,
    audit: new Audit(dbA),
    db: dbA,
    identitySecret: identityConfig(SECRET),
    resolvers: { 'aws-sm': async () => SECRET_TOKEN },
    baseUrl: 'https://broker.example',
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  t.after(() => server.close());
  const port = (server.address() as any).port;
  const oldReferenceToken = signIdentity(claims(), SECRET);
  const oldConnectToken = signIdentity(claims(), SECRET);

  await offboardUser(
    new Vault(dbB, KEY),
    new Audit(dbB),
    new Consent(dbB),
    { enterpriseId: null, teamId: 'T1', userId: 'U1' },
  );
  const response = await post(port, '/v1/user/reference', {
    handle: { provider: 'acme' },
    identityToken: oldReferenceToken,
    secretRef: AWS_USER_REF,
  });

  assert.equal(response.status, 409);
  assert.deepEqual(response.json, {
    error: 'authorization changed; resolve and retry',
    code: 'interaction_state_changed',
    retryable: false,
    recovery: 'resolve_again',
  });
  assert.equal(await vaultA.has(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), false);
  assert.equal((await dbA.get<any>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`)).n, 0);

  const connect = await post(port, '/v1/connect', {
    handle: { provider: 'acme' },
    identityToken: oldConnectToken,
  });
  assert.equal(connect.status, 409);
  assert.deepEqual(connect.json, response.json);
  assert.equal((await dbA.get<any>(`SELECT COUNT(*)::int AS n FROM consent_request`)).n, 0);
});

test('#194 enterprise offboard fences old headless setup on an artifact-free team', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(() => Promise.all([dbA.close(), dbB.close()]));
  const vaultA = new Vault(dbA, KEY);
  const server = createBroker({
    providers: [acme],
    vault: vaultA,
    audit: new Audit(dbA),
    db: dbA,
    identitySecret: identityConfig(SECRET),
    resolvers: { 'aws-sm': async () => SECRET_TOKEN },
    baseUrl: 'https://broker.example',
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  t.after(() => server.close());
  const port = (server.address() as any).port;
  const identity = { enterpriseId: 'E1', teamId: 'T_EMPTY', userId: 'U_EMPTY' };
  const oldReferenceToken = signIdentity(claims(identity), SECRET);
  const oldConnectToken = signIdentity(claims(identity), SECRET);

  const summary = await offboardUserEverywhere(
    dbB,
    new Vault(dbB, KEY),
    new Audit(dbB),
    new Consent(dbB),
    { enterpriseId: identity.enterpriseId, userId: identity.userId },
  );
  assert.deepEqual(summary, [], 'precondition: no team artifact existed for discovery');

  const reference = await post(port, '/v1/user/reference', {
    handle: { provider: 'acme' },
    identityToken: oldReferenceToken,
    secretRef: AWS_USER_REF,
  });
  assert.equal(reference.status, 409);
  assert.deepEqual(reference.json, {
    error: 'authorization changed; resolve and retry',
    code: 'interaction_state_changed',
    retryable: false,
    recovery: 'resolve_again',
  });

  const connect = await post(port, '/v1/connect', {
    handle: { provider: 'acme' },
    identityToken: oldConnectToken,
  });
  assert.equal(connect.status, 409);
  assert.deepEqual(connect.json, reference.json);
  assert.equal(await vaultA.has(userOwner(identity), 'acme'), false);
  assert.equal((await dbA.get<any>(`SELECT COUNT(*)::int AS n FROM consent_request`)).n, 0);
  assert.equal((await dbA.get<any>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`)).n, 0);
});

test('#58 resolver failure returns a stable code without resolver text or the reference', async (t) => {
  const sentinel = 'ghp_RESOLVER_WIRE_SENTINEL';
  const events: VouchrEvent[] = [];
  const { server, port } = await makeRefBroker(t, {
    resolvers: { 'aws-sm': async () => { throw new Error(`${sentinel}:${AWS_USER_REF}`); } },
    onEvent: (event) => events.push(event),
  });
  try {
    const configured = await post(port, '/v1/user/reference', {
      handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET), secretRef: AWS_USER_REF,
    });
    assert.equal(configured.status, 200);
    const response = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'GET',
      path: '/x',
    });
    assert.equal(response.status, 502);
    assert.deepEqual(response.json, {
      error: 'credential resolution failed',
      code: 'resolver_failed',
      retryable: true,
      recovery: 'retry_later',
    });
    assert.ok(!response.raw.includes(sentinel));
    assert.ok(!response.raw.includes(AWS_USER_REF));
    assert.deepEqual(
      events.filter((event) => event.type === 'resolver_failed'),
      [{ type: 'resolver_failed', provider: 'acme', source: 'aws-sm' }],
    );
  } finally {
    server.close();
  }
});

test('#58 malformed stored reference returns resolver_configuration_error before resolver or provider I/O', async (t) => {
  const malformed = 'arn:aws:secretsmanager:malformed-reference-sentinel';
  let resolverCalls = 0;
  const events: VouchrEvent[] = [];
  const { server, port, vault } = await makeRefBroker(t, {
    resolvers: { 'aws-sm': async () => { resolverCalls++; return SECRET_TOKEN; } },
    onEvent: (event) => events.push(event),
  });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    // Simulate a legacy row written before the public reference validator existed.
    await vault.reference(
      userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }),
      'acme',
      { source: 'aws-sm', secretRef: malformed },
    );
    const response = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity(claims(), SECRET),
      method: 'GET',
      path: '/x',
    });
    assert.equal(response.status, 502);
    assert.deepEqual(response.json, {
      error: 'credential resolution failed',
      code: 'resolver_configuration_error',
      retryable: false,
      recovery: 'fix_configuration',
    });
    assert.equal(resolverCalls, 0);
    assert.equal(up.seen.length, 0);
    assert.equal(events.filter((event) => event.type === 'resolver_failed').length, 0);
    assert.ok(!response.raw.includes(malformed));
  } finally {
    up.restore();
    server.close();
  }
});

test('#58 user reference is bound to the token identity (a forged body can\'t reference into another slot)', async (t) => {
  const { server, port, vault } = await makeRefBroker(t);
  try {
    await post(port, '/v1/user/reference', {
      handle: { provider: 'acme' }, identityToken: signIdentity(claims({ userId: 'U1' }), SECRET),
      source: 'aws-sm', secretRef: AWS_USER_REF,
      userId: 'U2', teamId: 'T2', enterpriseId: 'E2',
      identity: { teamId: 'T2', userId: 'U2' },
    } as any);
    assert.ok(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), 'stored for the token user U1');
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme'), null, 'never for another user');
    assert.equal(await vault.get(userOwner({ enterpriseId: 'E2', teamId: 'T2', userId: 'U2' }), 'acme'), null, 'body identity is ignored');
  } finally {
    server.close();
  }
});

test('#53 user reference rejects invalid input before connection or audit state', async (t) => {
  const sentinel = 'sk_live_USER_ROUTE_REFERENCE_SENTINEL';
  const cases: Array<{ body: Record<string, unknown>; noResolver?: boolean }> = [
    { body: { secretRef: sentinel } },
    { body: { secretRef: ` ${AWS_USER_REF}` } },
    { body: { secretRef: 'gcp-sm://projects/../secrets/s/versions/latest' } },
    { body: { secretRef: AWS_USER_REF, source: sentinel } },
    { body: { secretRef: AWS_USER_REF, scopes: sentinel } },
    { body: { secretRef: AWS_USER_REF, scopes: `read  ${sentinel}` } },
    { body: { secretRef: AWS_USER_REF + 'x'.repeat(MAX_SECRET_REFERENCE_BYTES) } },
    { body: { secretRef: null } },
    { body: { secretRef: AWS_USER_REF }, noResolver: true },
  ];

  for (const entry of cases) {
    const { server, port, vault, db } = await makeRefBroker(
      t,
      entry.noResolver ? { resolvers: {} } : {},
    );
    try {
      const r = await post(port, '/v1/user/reference', {
        handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET), ...entry.body,
      });
      assert.equal(r.status, 400);
      assert.ok(!r.raw.includes(sentinel), 'fixed validation response must not reflect caller input');
      assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
      assert.equal((await db.get<any>('SELECT COUNT(*) n FROM audit')).n, 0);
    } finally {
      server.close();
    }
  }
});

test('#53 vault:// reference reaches the configured HashiCorp resolver instead of the local vault path', async (t) => {
  let resolvedWith: string | null = null;
  const { server, port, vault } = await makeRefBroker(t, {
    resolvers: { vault: async (ref: string) => { resolvedWith = ref; return SECRET_TOKEN; } },
  });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const configured = await post(port, '/v1/user/reference', {
      handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET), secretRef: VAULT_USER_REF,
    });
    assert.equal(configured.status, 200);
    const stored = await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme');
    assert.equal(stored?.source, 'vault');
    assert.equal(stored?.secretRef, VAULT_USER_REF);
    assert.equal(stored?.accessToken, null);
    assert.equal(resolvedWith, null);

    const fetched = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/x',
    });
    assert.equal(fetched.status, 200);
    assert.equal(resolvedWith, VAULT_USER_REF);
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`);
    assert.ok(!configured.raw.includes(SECRET_TOKEN) && !fetched.raw.includes(SECRET_TOKEN));
  } finally {
    up.restore();
    server.close();
  }
});

test('#53 malformed legacy vault:// row is quarantined before resolver or provider I/O', async (t) => {
  const sentinel = 'ghp_LEGACY_REFERENCE_SENTINEL';
  const legacyRef = `vault://secret/foo/../../../other/data/target#${sentinel}`;
  let resolverCalls = 0;
  const { server, port, vault } = await makeRefBroker(t, {
    resolvers: { vault: async () => { resolverCalls++; return SECRET_TOKEN; } },
  });
  await vault.reference(
    userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }),
    'acme',
    { source: 'vault', secretRef: legacyRef },
  );
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const fetched = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/x',
    });
    assert.equal(fetched.status, 502);
    assert.equal(resolverCalls, 0);
    assert.equal(up.seen.length, 0);
    assert.ok(!fetched.raw.includes(sentinel));
  } finally {
    up.restore();
    server.close();
  }
});

test('#58 user reference rejects a tampered token, service tools, and a missing secretRef', async (t) => {
  const { server, port } = await makeRefBroker(t);
  try {
    assert.equal((await post(port, '/v1/user/reference', { handle: { provider: 'acme' }, identityToken: 'nope', source: 'aws-sm', secretRef: AWS_USER_REF })).status, 401);
    assert.equal((await post(port, '/v1/user/reference', { handle: { provider: 'svc' }, identityToken: signIdentity(claims(), SECRET), source: 'aws-sm', secretRef: AWS_USER_REF })).status, 403);
    assert.equal((await post(port, '/v1/user/reference', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET), source: 'aws-sm' } as any)).status, 400);
  } finally {
    server.close();
  }
});
