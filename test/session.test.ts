import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { Policy } from '../src/core/policy';
import { SessionGrants } from '../src/core/session';
import { ChannelConfig } from '../src/core/channelConfig';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { offboardUserEverywhere } from '../src/core/offboard';
import { ConnectContext, SessionApprovalRequiredError } from '../src/adapters/bolt';

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };

const gh = defineProvider({
  id: 'gh', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

// ── Store unit tests ──────────────────────────────────────────────────────────────────────
test('SessionGrants: thread-scoped grant, isolation, expiry, revoke, sweep', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const s = new SessionGrants(db);

  // No grant initially.
  assert.equal(await s.isGranted(ID, 'C1', 'TH_A', 'gh'), false);

  // Grant binds to exactly (team, channel, thread, user, provider).
  await s.grant(ID, 'C1', 'TH_A', 'gh', 60_000);
  assert.equal(await s.isGranted(ID, 'C1', 'TH_A', 'gh'), true);

  // A different thread / channel / provider is NOT covered by that grant.
  assert.equal(await s.isGranted(ID, 'C1', 'TH_B', 'gh'), false); // other thread
  assert.equal(await s.isGranted(ID, 'C2', 'TH_A', 'gh'), false); // other channel
  assert.equal(await s.isGranted(ID, 'C1', 'TH_A', 'other'), false); // other provider
  assert.equal(await s.isGranted({ ...ID, userId: 'U2' }, 'C1', 'TH_A', 'gh'), false); // other user

  // Expired grant (negative ttl => already past) is not granted, and sweep removes it.
  await s.grant(ID, 'C1', 'TH_OLD', 'gh', -1);
  assert.equal(await s.isGranted(ID, 'C1', 'TH_OLD', 'gh'), false);
  const swept = await s.sweepExpired();
  assert.ok(swept >= 1);

  // Revoke clears every grant for the user.
  await s.revokeForUser(ID);
  assert.equal(await s.isGranted(ID, 'C1', 'TH_A', 'gh'), false);
});

// Regression: the Grid/SCIM cross-team sweep must clear session grants too, including a team that
// is discoverable ONLY by a lingering grant (no connection/consent there).
test('offboardUserEverywhere clears session grants across teams', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);

  // T1: only a session grant (no connection/consent), found solely via session_grant discovery.
  await sessions.grant({ ...ID, teamId: 'T1' }, 'C1', 'TH_A', 'gh', 60_000);
  // T2: a grant plus a stored connection.
  await sessions.grant({ ...ID, teamId: 'T2' }, 'C2', 'TH_B', 'gh', 60_000);
  await vault.upsert(userOwner({ ...ID, teamId: 'T2' }), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  await offboardUserEverywhere(db, vault, audit, consent, { userId: ID.userId });

  assert.equal(await sessions.isGranted({ ...ID, teamId: 'T1' }, 'C1', 'TH_A', 'gh'), false);
  assert.equal(await sessions.isGranted({ ...ID, teamId: 'T2' }, 'C2', 'TH_B', 'gh'), false);
  const left = (await db.all('SELECT 1 AS x FROM session_grant WHERE user_id=?', [ID.userId])) as any[];
  assert.equal(left.length, 0);
});

// ── connect() gate (driven by the 'session' channel mode) ───────────────────────────────────
// `ghMode` sets the channel auth mode for 'gh' in channel C1 (default 'session' to exercise the gate).
async function setup(ghMode: 'session' | 'per-user' | 'shared' = 'session') {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const sessions = new SessionGrants(db);
  const channelConfig = new ChannelConfig(db);
  await channelConfig.setMode('T1', 'C1', 'gh', ghMode);
  const posted: any[] = [];
  const client = { chat: { postEphemeral: async (p: any) => { posted.push(p); return {}; } } } as any;
  const make = (thread: string | null, channel: string | null = 'C1') =>
    new ConnectContext(
      ID, channel, client, new ProviderRegistry([gh]), vault, audit,
      new Consent(db), new Policy(), 'http://x', {}, channelConfig, undefined,
      new Map(), () => {}, ['gh'], undefined, false, thread, sessions,
    );
  const auditRows = async () => (await db.all('SELECT action, meta FROM audit')) as any[];
  return { db, vault, sessions, posted, make, auditRows };
}

test('connect(): covered provider with no grant posts an in-thread approval and throws', async () => {
  const { vault, posted, make, auditRows } = await setup();
  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  // In a thread, no grant yet → approval prompt + SessionApprovalRequiredError (even though a cred
  // is stored: "connected once" still needs per-thread approval).
  await assert.rejects(() => make('TH_A').connect('gh'), SessionApprovalRequiredError);
  assert.equal(posted.length, 1);
  assert.equal(posted[0].thread_ts, 'TH_A');
  assert.equal(posted[0].user, 'U1');
  const sessionRows = (await auditRows()).filter((r) => r.action === 'session');
  assert.equal(sessionRows.length, 1);
  assert.match(sessionRows[0].meta, /prompt/);
});

test('connect(): after granting the thread, the same thread proceeds but other threads do not', async () => {
  const { vault, sessions, make } = await setup();
  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  await sessions.grant(ID, 'C1', 'TH_A', 'gh', 60_000);
  assert.ok(await make('TH_A').connect('gh')); // granted thread → real handle

  // A different thread has no grant → still blocked. The grant cannot leak across threads.
  await assert.rejects(() => make('TH_B').connect('gh'), SessionApprovalRequiredError);
});

test('connect(): covered provider off-thread is refused (no thread to scope a session)', async () => {
  const { make, auditRows } = await setup();
  await assert.rejects(() => make(null).connect('gh'), /thread-scoped session/);
  const denied = (await auditRows()).filter((r) => r.action === 'denied');
  assert.equal(denied.length, 1);
  assert.match(denied[0].meta, /no-thread/);
});

test('connect(): a provider in per-user mode is not gated', async () => {
  // Channel mode is 'per-user' for gh → no session needed; with a stored cred connect() returns a handle.
  const { vault, posted, make } = await setup('per-user');
  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  assert.ok(await make('TH_A').connect('gh'));
  assert.equal(posted.length, 0); // no approval prompt
});

test('connect(): shared mode routes to the channel-credential path', async () => {
  // With no shared cred configured, connect() in 'shared' mode surfaces connectChannel's specific
  // error, proving it delegated to the channel path rather than the per-user one.
  const { make } = await setup('shared');
  await assert.rejects(() => make('TH_A').connect('gh'), /No channel credential configured/);
});
