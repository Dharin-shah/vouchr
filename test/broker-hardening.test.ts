import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Policy } from '../src/core/policy';
import { ChannelConfig, writeChannelMode } from '../src/core/channelConfig';
import { SessionGrants } from '../src/core/session';
import { defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { VouchrEvent } from '../src/core/injector';
import { createBroker } from '../src/adapters/http/broker';
import { identityConfig, signIdentity, type IdentityClaims } from './support/identity';

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';
const U1 = { enterpriseId: null, teamId: 'T1', userId: 'U1' };

const acme = defineProvider({
  id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false, clientId: 'id', clientSecret: 'sec',
});
const beta = defineProvider({
  id: 'beta', authorizeUrl: 'https://beta.example/auth', tokenUrl: 'https://beta.example/token',
  scopesDefault: ['x'], egressAllow: ['api.beta.example'], refresh: 'none', pkce: false, clientId: 'id', clientSecret: 'sec',
});
const svc = defineProvider({
  id: 'svc', identity: 'service', credential: 'key',
  authorizeUrl: 'https://svc.example/auth', tokenUrl: 'https://svc.example/token',
  scopesDefault: ['x'], egressAllow: ['api.svc.example'], refresh: 'none', pkce: false,
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}
function token(over: Partial<IdentityClaims> = {}): string {
  return signIdentity(claims(over), SECRET);
}

function post(port: number, path: string, body: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json: any = null; try { json = JSON.parse(raw); } catch { /* leave null */ }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

function mockUpstream() {
  const real = globalThis.fetch;
  const seen: string[] = [];
  globalThis.fetch = (async (url: any) => { seen.push(String(url)); return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }); }) as any;
  return { seen, restore: () => { globalThis.fetch = real; } };
}

async function listen(server: http.Server): Promise<number> {
  await new Promise<void>((r) => server.listen(0, r));
  return (server.address() as any).port;
}

// ── (a) SECURITY: session-mode is fail-closed in the headless broker ──────────

test('session-mode: owner:"user" fetch is REFUSED without a live thread grant', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  await writeChannelMode(channelConfig, 'T1', 'C1', 'acme', 'session');
  await vault.upsert(userOwner(U1), 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), channelConfig });
  const port = await listen(server);
  const up = mockUpstream();
  try {
    // A signed user token WITH a thread but no grant → fail closed, no upstream call, token never served.
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token({ threadTs: '111.222' }), method: 'GET', path: '/x' });
    assert.equal(r.status, 403);
    assert.equal(up.seen.length, 0, 'the credential must NOT have been injected');
    // No threadTs at all → cannot scope a session → also fail closed.
    const r2 = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'GET', path: '/x' });
    assert.equal(r2.status, 403);
    const row = (await db.get(`SELECT meta FROM audit WHERE action='denied' AND meta LIKE '%no-thread%' LIMIT 1`)) as any;
    // meta carries the reason; a denied audit row exists for the no-thread case.
    assert.ok(row, 'a denied audit row is written for the no-thread session refusal');
  } finally { up.restore(); server.close(); }
});

test('session-mode: owner:"user" fetch is ALLOWED with a live thread grant', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  const sessions = new SessionGrants(db);
  await writeChannelMode(channelConfig, 'T1', 'C1', 'acme', 'session');
  await vault.upsert(userOwner(U1), 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const credentialId = await vault.liveId(userOwner(U1), 'acme');
  assert.ok(credentialId);
  await sessions.grant(U1, 'C1', '111.222', 'acme', 60_000, credentialId); // approve exactly this thread
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), channelConfig });
  const port = await listen(server);
  const up = mockUpstream();
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token({ threadTs: '111.222' }), method: 'GET', path: '/x' });
    assert.equal(r.status, 200);
    assert.equal(up.seen.length, 1, 'the credential was injected once the grant existed');
    // A different thread has no grant → still refused (grant is thread-scoped, not user-wide).
    const r2 = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token({ threadTs: '999.999' }), method: 'GET', path: '/x' });
    assert.equal(r2.status, 403);
  } finally { up.restore(); server.close(); }
});

test('session-mode is opt-in: with NO channelConfig the user credential serves as before', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner(U1), 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET) }); // no channelConfig
  const port = await listen(server);
  const up = mockUpstream();
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'GET', path: '/x' });
    assert.equal(r.status, 200);
  } finally { up.restore(); server.close(); }
});

// ── (b) /v1/status: single query, no per-provider decrypt ─────────────────────

test('/v1/status: one listForUser call, no per-provider vault.get decrypts', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner(U1), 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  // Spy: prove the status path never falls back to the N-per-provider get() (which would decrypt).
  let getCalls = 0;
  const realGet = vault.get.bind(vault);
  (vault as any).get = (...a: any[]) => { getCalls++; return (realGet as any)(...a); };
  const server = createBroker({ providers: [acme, beta, svc], vault, audit, db, identitySecret: identityConfig(SECRET) });
  const port = await listen(server);
  try {
    const r = await post(port, '/v1/status', { identityToken: token() });
    assert.equal(r.status, 200);
    const byId = Object.fromEntries(r.json.providers.map((p: any) => [p.provider, p]));
    assert.deepEqual(byId.acme, { provider: 'acme', connected: true, consentState: 'connected' });
    assert.deepEqual(byId.beta, { provider: 'beta', connected: false, consentState: 'needs_consent' });
    assert.equal(byId.svc, undefined, 'service tools are not brokered and are omitted');
    assert.equal(getCalls, 0, 'status must not call vault.get per provider (no decrypt storm)');
  } finally { server.close(); }
});

test('/v1/status: a past-idle-TTL connection reports needs_consent, not connected', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY, { idleMs: 1000 }); // idle-expire after 1s
  const audit = new Audit(db);
  await vault.upsert(userOwner(U1), 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  // Age the row past the idle window (mirrors what vault.get would treat as expired → null).
  await db.run(`UPDATE connection SET last_used_at=?, created_at=? WHERE provider='acme'`, [Date.now() - 5000, Date.now() - 5000]);
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET) });
  const port = await listen(server);
  try {
    const r = await post(port, '/v1/status', { identityToken: token() });
    assert.equal(r.status, 200);
    const acmeRow = r.json.providers.find((p: any) => p.provider === 'acme');
    assert.deepEqual(acmeRow, { provider: 'acme', connected: false, consentState: 'needs_consent' }, 'expired connection must read needs_consent');
    // Sanity: vault.get agrees the row is expired (null), so status matches the single-fetch path.
    assert.equal(await vault.get(userOwner(U1), 'acme'), null);
  } finally { server.close(); }
});

// ── (c) policy_denied metric fires on a denied fetch ──────────────────────────

test('policy_denied event fires on a policy-denied fetch (parity with the Bolt path)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner(U1), 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const events: VouchrEvent[] = [];
  const server = createBroker({
    providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET),
    policy: new Policy({}, { defaultDeny: true }), // no rule for acme + defaultDeny → denied
    onEvent: (e) => events.push(e),
  });
  const port = await listen(server);
  const up = mockUpstream();
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'GET', path: '/x' });
    assert.equal(r.status, 403);
    assert.equal(up.seen.length, 0, 'no credential injected on a denied fetch');
    assert.ok(events.some((e) => e.type === 'policy_denied' && e.provider === 'acme'), 'policy_denied metric was emitted');
  } finally { up.restore(); server.close(); }
});

test('a throwing onEvent sink does not turn a denied fetch into a 500 (stays 403)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner(U1), 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const server = createBroker({
    providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET),
    policy: new Policy({}, { defaultDeny: true }), // acme denied → emits policy_denied
    onEvent: () => { throw new Error('sink boom'); }, // a broken sink must never affect the request
  });
  const port = await listen(server);
  const up = mockUpstream();
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'GET', path: '/x' });
    assert.equal(r.status, 403, 'a throwing sink must not escalate the 403 to a 500');
    assert.equal(up.seen.length, 0);
  } finally { up.restore(); server.close(); }
});

// ── (d) removing defaultDenyNonGet did not change write-gating ────────────────

test('write-gating unchanged: non-GET is 405 when allowWrites is unset', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner(U1), 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET) }); // allowWrites unset
  const port = await listen(server);
  try {
    const r = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'POST', path: '/x', body: '{}' });
    assert.equal(r.status, 405);
  } finally { server.close(); }
});
