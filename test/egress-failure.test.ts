import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { type VouchrEvent } from '../src/core/injector';
import { createBroker } from '../src/adapters/http/broker';
import { identityConfig, signIdentity, type IdentityClaims } from './support/identity';

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

async function makeBroker(t: TestContext, events: VouchrEvent[]) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), onEvent: (e) => events.push(e) });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, db, port: (server.address() as any).port };
}

function post(port: number, path: string, body: unknown): Promise<{ status: number; raw: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, raw: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

// A network-level throw from the upstream fetch (DNS/connection refused) must (a) map to 502 and (b) fire
// the no-secret egress_error signal with only host + reason — never the token, never the error message.
test('egress-failure: an upstream fetch throw returns 502 and emits egress_error (no secret)', async (t) => {
  const events: VouchrEvent[] = [];
  const { server, port } = await makeBroker(t, events);
  const real = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error(`ECONNREFUSED reaching ${SECRET_TOKEN}`); }) as any; // error carries a secret on purpose
  try {
    const r = await post(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'GET', path: '/data',
    });
    assert.equal(r.status, 502, 'a network throw must map to 502');
    assert.ok(!r.raw.includes(SECRET_TOKEN), 'the secret must not leak into the 502 response');
  } finally {
    globalThis.fetch = real;
    server.close();
  }

  const err = events.find((e) => e.type === 'egress_error') as Extract<VouchrEvent, { type: 'egress_error' }> | undefined;
  assert.ok(err, 'egress_error must fire on an upstream fetch throw (not a silent black box)');
  assert.equal(err.provider, 'acme');
  assert.equal(err.host, 'api.acme.example', 'host is the hostname only');
  assert.equal(err.reason, 'fetch_failed');
  // No token and no error-message content anywhere in any emitted event.
  for (const e of events) {
    const s = JSON.stringify(e);
    assert.ok(!s.includes(SECRET_TOKEN), 'an event leaked the token');
    assert.ok(!s.includes('ECONNREFUSED'), 'an event leaked the raw error message');
  }
});
