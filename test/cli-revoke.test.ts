import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { selectRevocations, revokeConnection } from '../src/core/offboard';
import { userOwner, channelOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32);

// Google-like: form body `token=<token>`, has a revoke endpoint.
const revocable = defineProvider({
  id: 'revocable',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  refresh: 'rotating',
  pkce: true,
  revokeUrl: 'https://acme.example/revoke',
  clientId: 'id',
  clientSecret: 'sec',
});

const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

/** Seed 3 connections across 2 teams: T1 user U1, T1 channel C1, T2 user U2 — all for `revocable`. */
async function seed() {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable', tok('TOK_U1'));
  await vault.upsert(channelOwner('T1', 'C1'), 'revocable', tok('TOK_C1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T2', userId: 'U2' }), 'revocable', tok('TOK_U2'));
  return { db, vault, audit: new Audit(db), consent: new Consent(db), sessions: new SessionGrants(db), registry: new ProviderRegistry([revocable]) };
}

test('dry-run (selectRevocations) matches without mutating; filters compose', async () => {
  const { db, vault } = await seed();
  assert.equal((await selectRevocations(db, { provider: 'revocable' })).length, 3);
  assert.equal((await selectRevocations(db, { provider: 'revocable', teamId: 'T1' })).length, 2);
  assert.equal((await selectRevocations(db, { provider: 'revocable', userId: 'U1' })).length, 1);
  assert.equal((await selectRevocations(db, { provider: 'revocable', channel: 'C1' })).length, 1);
  assert.equal((await selectRevocations(db, { provider: 'other' })).length, 0);
  // Nothing was deleted by selecting.
  assert.ok(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'));
  assert.equal((await db.get('SELECT COUNT(*) AS n FROM connection') as any).n, 3);
});

test('--team T1 revokes only T1 rows, calls upstream revoke, writes audit; T2 untouched', async () => {
  const { db, vault, audit, consent, sessions, registry } = await seed();
  const realFetch = globalThis.fetch;
  const revokedTokens: string[] = [];
  globalThis.fetch = (async (_url: any, init: any) => {
    revokedTokens.push(new URLSearchParams(init.body).get('token')!);
    return new Response('', { status: 200 });
  }) as any;
  try {
    const rows = await selectRevocations(db, { provider: 'revocable', teamId: 'T1' });
    for (const r of rows) {
      const out = await revokeConnection(vault, audit, consent, sessions, registry, r, 'revocable');
      assert.equal(out.removed, true);
      assert.equal(out.upstreamOk, true);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
  // Only the two T1 rows are gone; the T2 user row survives (filters compose).
  assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'), null);
  assert.equal(await vault.get(channelOwner('T1', 'C1'), 'revocable'), null);
  assert.ok(await vault.get(userOwner({ enterpriseId: null, teamId: 'T2', userId: 'U2' }), 'revocable'));
  // Both live tokens hit the upstream revoke endpoint.
  assert.deepEqual(revokedTokens.sort(), ['TOK_C1', 'TOK_U1']);
  // One audit 'revoke' row per revoked connection, no token material in meta.
  const rows = (await db.all('SELECT meta FROM audit WHERE action=?', ['revoke'])) as any[];
  assert.equal(rows.length, 2);
  for (const r of rows) assert.ok(!r.meta.includes('TOK_'));
});

test('failing upstream revoke still deletes locally and reports upstreamOk=false', async () => {
  const { db, vault, audit, consent, sessions, registry } = await seed();
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('nope', { status: 500 })) as any;
  try {
    const [row] = await selectRevocations(db, { provider: 'revocable', userId: 'U1' });
    const out = await revokeConnection(vault, audit, consent, sessions, registry, row, 'revocable');
    assert.equal(out.removed, true); // local delete is the security-meaningful action
    assert.equal(out.upstreamOk, false); // best-effort revoke failed, but did not fail the delete
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'), null);
  assert.equal(JSON.parse((await db.get('SELECT meta FROM audit WHERE action=?', ['revoke']) as any).meta).ok, false);
});

test('revoking a user connection clears that user+provider session grants and pending consent', async () => {
  const { db, vault, audit, consent, sessions, registry } = await seed();
  const id: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  await sessions.grant(id, 'C9', 'THREAD', 'revocable', 60_000);
  await consent.begin(id, revocable, 'https://broker.example/cb', 'C9');
  assert.equal(await sessions.isGranted(id, 'C9', 'THREAD', 'revocable'), true);
  assert.equal((await db.get('SELECT COUNT(*) AS n FROM consent_request') as any).n, 1);

  const [row] = await selectRevocations(db, { provider: 'revocable', userId: 'U1' });
  await revokeConnection(vault, audit, consent, sessions, registry, row, 'revocable');

  assert.equal(await sessions.isGranted(id, 'C9', 'THREAD', 'revocable'), false); // grant cleared
  assert.equal((await db.get('SELECT COUNT(*) AS n FROM consent_request') as any).n, 0); // consent cleared
});
