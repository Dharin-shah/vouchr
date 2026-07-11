import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { defineProvider } from '../src/core/providers';
import { createBroker } from '../src/adapters/http/broker';
import { signIdentity, type IdentityClaims } from '../src/adapters/http/identity';
import type { SlackIdentity } from '../src/core/identity';

// Headless /v1/audit parity (#150). Same invariants as the Slack /vouchr audit (#104): a caller only
// ever reads their OWN rows, `audit channel` is admin-gated on the SIGNED claim, and `meta` is never
// returned. Scoping is enforced in core; these tests drive it through the real HTTP surface.

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';
const uid = (userId: string): SlackIdentity => ({ enterpriseId: null, teamId: 'T1', userId });
const acme = defineProvider({
  id: 'acme', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.x'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}
const userToken = (over: Partial<IdentityClaims> = {}) => signIdentity(claims(over), SECRET);
const adminToken = (over: Partial<IdentityClaims> = {}) => signIdentity(claims({ isAdmin: true, ...over }), SECRET);

async function harness(t: TestContext) {
  const db = await openTestDb(t);
  const audit = new Audit(db);
  const server = createBroker({
    providers: [acme], vault: new Vault(db, KEY), audit, db, identitySecret: SECRET,
    channelConfig: new ChannelConfig(db), channelTools: new ChannelTools(db),
    baseUrl: 'https://broker.example', callbackPath: '/oauth/callback',
  });
  await new Promise<void>((r) => server.listen(0, r));
  return { audit, server, port: (server.address() as any).port };
}

function request(port: number, method: string, urlPath: string, body?: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path: urlPath, method,
        headers: data ? { 'content-type': 'application/json', 'content-length': data.length } : {} },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let json: any = null;
          try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* non-JSON */ }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

test('POST /v1/audit: a caller sees only their own rows, never another user\'s', async (t) => {
  const { audit, server, port } = await harness(t);
  try {
    await audit.record('inject', uid('U1'), 'gh-owned-by-u1', { host: 'api.x' });
    await audit.record('inject', uid('U2'), 'gh-owned-by-u2', { host: 'api.x' });

    const res = await request(port, 'POST', '/v1/audit', { identityToken: userToken({ userId: 'U1' }) });
    assert.equal(res.status, 200);
    const providers = res.json.events.map((e: any) => e.provider);
    assert.ok(providers.includes('gh-owned-by-u1'));
    assert.ok(!providers.includes('gh-owned-by-u2')); // U2's row must never leak to U1
  } finally { server.close(); }
});

test('POST /v1/audit: empty events when the caller has no rows; no meta key anywhere', async (t) => {
  const { audit, server, port } = await harness(t);
  try {
    await audit.record('inject', uid('U1'), 'gh', { host: 'api.x', label: 'TOPSECRETLABEL' });
    const empty = await request(port, 'POST', '/v1/audit', { identityToken: userToken({ userId: 'U_NEW' }) });
    assert.deepEqual(empty.json.events, []);

    const mine = await request(port, 'POST', '/v1/audit', { identityToken: userToken({ userId: 'U1' }) });
    assert.doesNotMatch(JSON.stringify(mine.json), /TOPSECRETLABEL/); // meta contents never serialized
    assert.ok(mine.json.events.every((e: any) => !('meta' in e)));    // and no meta key on the row
  } finally { server.close(); }
});

test('POST /v1/admin/audit: signed admin sees only THIS channel\'s rows', async (t) => {
  const { audit, server, port } = await harness(t);
  try {
    await audit.record('inject', uid('U1'), 'gh-in-c1', { channel: 'C1' });
    await audit.record('inject', uid('U1'), 'gh-in-c2', { channel: 'C2' });

    const res = await request(port, 'POST', '/v1/admin/audit', { identityToken: adminToken({ channel: 'C1' }) });
    assert.equal(res.status, 200);
    const providers = res.json.events.map((e: any) => e.provider);
    assert.ok(providers.includes('gh-in-c1'));
    assert.ok(!providers.includes('gh-in-c2')); // a different channel must not appear
  } finally { server.close(); }
});

test('POST /v1/admin/audit: a non-admin token is refused (authority is the signed claim, not the body)', async (t) => {
  const { server, port } = await harness(t);
  try {
    // A forged body isAdmin must be ignored — only the signed claim counts.
    const res = await request(port, 'POST', '/v1/admin/audit', { identityToken: userToken(), isAdmin: true } as any);
    assert.equal(res.status, 403);
  } finally { server.close(); }
});
