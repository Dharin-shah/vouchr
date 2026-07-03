import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { ConnectionHandle } from '../src/core/injector';
import { createBroker } from '../src/adapters/http/broker';
import { signIdentity, type IdentityClaims } from '../src/adapters/http/identity';

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';

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

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}

async function makeBroker() {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: SECRET });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, db, port: (server.address() as any).port };
}

function post(port: number, path: string, body: unknown): Promise<{ status: number; json: any; raw: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
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

// An echo endpoint reflects the injected Authorization header verbatim in its JSON body. The broker must
// scrub the exact injected secret before relaying, so the caller never sees the bearer.
test('token-reflection: a header-reflecting upstream cannot echo the injected bearer back to the caller', async () => {
  const { server, port } = await makeBroker();
  const real = globalThis.fetch;
  globalThis.fetch = (async (_url: any, init: any) => {
    const auth = new Headers(init?.headers).get('authorization'); // "Bearer <token>"
    return new Response(JSON.stringify({ youSent: auth }), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/echo',
    });
    assert.equal(r.status, 200);
    assert.ok(!r.json.body.includes(SECRET_TOKEN), 'the reflected bearer leaked in the relayed body');
    assert.ok(!r.raw.includes(SECRET_TOKEN), 'the secret must not appear anywhere in the broker response');
    assert.ok(r.json.body.includes('[REDACTED]'), 'the injected secret should be redacted, not merely absent');
  } finally {
    globalThis.fetch = real;
    server.close();
  }
});

// The handle is handed to agent/tool code, which calls handle.fetch(). The injected credential must
// NEVER be readable back off the handle — otherwise the scrubber would have turned the handle into a
// token carrier (a worse leak than the reflection it closes). It's a true #private field: no public
// property, no getter, not enumerable. redactSecret() still scrubs it from a body without exposing it.
test('token-reflection: the injected credential is not readable off the handle after fetch()', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  await vault.upsert(owner, 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(acme, owner, { enterpriseId: null, teamId: 'T1', userId: 'U1' }, vault, new Audit(db));

  const real = globalThis.fetch;
  globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
  try {
    await handle.fetch('https://api.acme.example/x');
  } finally {
    globalThis.fetch = real;
  }

  // No public field (the pre-fix public `injectedSecret` would return the raw token here); a `#private`
  // field is not reachable as a string key either.
  assert.equal((handle as any).injectedSecret, undefined, 'no public injectedSecret field may exist');
  assert.ok(!Object.getOwnPropertyNames(handle).includes('injectedSecret'), 'injectedSecret must not be an own property');
  // The token must not surface through any enumerable own property (functions/#private are omitted by
  // JSON.stringify; this catches any accidental data property carrying the credential).
  assert.ok(!JSON.stringify(handle).includes(SECRET_TOKEN), 'the handle serialized the token');
  for (const name of Object.getOwnPropertyNames(handle)) {
    assert.ok(!String((handle as any)[name] ?? '').includes(SECRET_TOKEN), `property ${name} exposed the token`);
  }
  // But redactSecret still works internally — scrubs the token without ever returning it.
  assert.equal(handle.redactSecret(`{"auth":"Bearer ${SECRET_TOKEN}"}`), '{"auth":"Bearer [REDACTED]"}');
});
