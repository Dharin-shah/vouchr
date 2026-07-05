import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { selectRevocations, revokeConnection, countPendingForProvider, purgePendingForProvider } from '../src/core/offboard';
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

// No revoke endpoint (Notion-style): an upstream revoke is a no-op → reported SKIPPED, never success.
const norevoke = defineProvider({
  id: 'norevoke', authorizeUrl: 'https://no.example/a', tokenUrl: 'https://no.example/t',
  scopesDefault: [], egressAllow: ['api.no.example'], refresh: 'none', pkce: false, clientId: 'id', clientSecret: 'sec',
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

test('local delete is guaranteed even with a wrong key and no registry (break-glass invariant)', async () => {
  // P1: if the master key / provider registry are unavailable, the CLI still constructs a Vault with a
  // throwaway key and no registry. revokeConnection must delete locally regardless — the token read
  // fails to decrypt (swallowed) and upstream revoke is skipped, but the credential is gone.
  const { db, audit, consent, sessions } = await seed();
  const wrongKeyVault = new Vault(db, randomBytes(32)); // a DIFFERENT key than the data was sealed with
  const [row] = await selectRevocations(db, { provider: 'revocable', userId: 'U1' });
  const out = await revokeConnection(wrongKeyVault, audit, consent, sessions, undefined, row, 'revocable');
  assert.equal(out.removed, true); // deleted despite being unable to decrypt the token
  assert.equal(out.upstreamOk, true); // no registry → upstream revoke skipped, not failed
  assert.equal(await wrongKeyVault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'), null);
});

test('pending consent + grants with NO connection are counted and purged for the scope', async () => {
  // P2: a pending "Connect" (or lingering thread grant) for the provider but no live connection must
  // still be cleared, or it resurrects access after the break-glass run.
  const { db } = await seed();
  const id: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U_ORPHAN' }; // no connection row
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);
  await consent.begin(id, revocable, 'https://broker.example/cb', 'C9');
  await sessions.grant(id, 'C9', 'THREAD', 'revocable', 60_000);
  // A different provider's pending state must survive the scoped purge.
  await consent.begin(id, { ...revocable, id: 'other' } as any, 'https://broker.example/cb', 'C9');

  assert.deepEqual(await countPendingForProvider(db, { provider: 'revocable' }), { consents: 1, grants: 1 });
  const purged = await purgePendingForProvider(db, { provider: 'revocable' });
  assert.deepEqual(purged, { consents: 1, grants: 1 });
  assert.deepEqual(await countPendingForProvider(db, { provider: 'revocable' }), { consents: 0, grants: 0 });
  assert.deepEqual(await countPendingForProvider(db, { provider: 'other' }), { consents: 1, grants: 0 }); // untouched
});

test('pending purge respects the team/user scope', async () => {
  const { db } = await seed();
  const consent = new Consent(db);
  await consent.begin({ enterpriseId: null, teamId: 'T1', userId: 'U1' }, revocable, 'https://x/cb', null);
  await consent.begin({ enterpriseId: null, teamId: 'T2', userId: 'U2' }, revocable, 'https://x/cb', null);
  const purged = await purgePendingForProvider(db, { provider: 'revocable', teamId: 'T1' });
  assert.equal(purged.consents, 1); // only T1
  assert.deepEqual(await countPendingForProvider(db, { provider: 'revocable', teamId: 'T2' }), { consents: 1, grants: 0 });
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

test('a provider with no revoke endpoint reports upstream SKIPPED, not success', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'norevoke', tok('TOK'));
  const realFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = (async () => { called = true; return new Response('', { status: 200 }); }) as any;
  try {
    const [row] = await selectRevocations(db, { provider: 'norevoke', userId: 'U1' });
    const out = await revokeConnection(vault, new Audit(db), new Consent(db), new SessionGrants(db), new ProviderRegistry([norevoke]), row, 'norevoke');
    assert.equal(out.removed, true);
    assert.equal(out.upstreamAttempted, false); // no revoke endpoint → not attempted
    assert.equal(called, false); // fetch never called
  } finally {
    globalThis.fetch = realFetch;
  }
  // The audit meta records the skip, not ok:true (a skip must not read as a success).
  const meta = JSON.parse((await db.get('SELECT meta FROM audit WHERE action=?', ['revoke']) as any).meta);
  assert.equal(meta.ok, undefined);
  assert.equal(meta.upstream, 'skipped');
});

test('revokeConnection swallows a post-delete audit failure (bulk sweep never strands rows)', async () => {
  const { db, vault, consent, sessions, registry } = await seed();
  const throwingAudit = { record: async () => { throw new Error('db down'); } } as any;
  const [row] = await selectRevocations(db, { provider: 'revocable', userId: 'U1' });
  // Must NOT throw — the local delete already happened and the loop must continue for the other rows.
  const out = await revokeConnection(vault, throwingAudit, consent, sessions, registry, row, 'revocable');
  assert.equal(out.removed, true);
  assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'), null);
});

test('CLI refuses an empty --team scope instead of widening to every team', async () => {
  // The `--team --yes` typo leaves --team empty; the CLI must refuse rather than revoke all teams.
  const dir = mkdtempSync(path.join(os.tmpdir(), 'vouchr-revoke-'));
  const dbPath = path.join(dir, 'v.db');
  const keyB64 = randomBytes(32).toString('base64');
  const db = await openDb({ dbPath });
  const vault = new Vault(db, Buffer.from(keyB64, 'base64'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'gh', tok('X1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T2', userId: 'U2' }), 'gh', tok('X2'));
  await db.close();

  const res = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'revoke', '--provider', 'gh', '--team', '--yes'], {
    env: { ...process.env, VOUCHR_DB: dbPath, VOUCHR_MASTER_KEY: keyB64 }, encoding: 'utf8',
  });
  assert.equal(res.status, 2); // refused with the usage exit code
  assert.match(res.stderr, /ambiguous scope/);
  const db2 = await openDb({ dbPath });
  const n = (await db2.get('SELECT COUNT(*) AS n FROM connection')) as any;
  await db2.close();
  assert.equal(n.n, 2); // BOTH teams' connections survive — nothing was revoked
});
