import { test, type TestContext } from 'node:test';
import { openTestDb, testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { ErrorCode as SlackErrorCode } from '@slack/web-api';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import {
  Consent,
  latestUserOffboardTombstone,
  markUserOffboardedEverywhere,
  offboardLockKey,
  withOffboardLock,
} from '../src/core/consent';
import { Policy } from '../src/core/policy';
import { SessionGrants } from '../src/core/session';
import { ChannelConfig, writeChannelMode } from '../src/core/channelConfig';
import { ProviderRegistry, defineProvider, type Provider } from '../src/core/providers';
import { channelOwner, userOwner } from '../src/core/owner';
import { offboardUser, offboardUserEverywhere } from '../src/core/offboard';
import {
  ConnectContext,
  ConsentRequiredError,
  createVouchr,
  SessionApprovalRequiredError,
  UserFacingError,
} from '../src/adapters/bolt';
import { APPROVE_SESSION_ACTION } from '../src/adapters/blocks';
import { openDb, type Db } from '../src/core/db';
import { ChannelTools, configureChannelTools } from '../src/core/tools';
import { setChannelCredentialMode } from '../src/core/channelCredential';
import { Approvals } from '../src/core/approval';
import { InteractionStateChangedError, POSTGRES_NOW_MS_SQL } from '../src/core/interaction';
import { mapSafeError, type VouchrRecovery } from '../src/core/errors';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const GENERATION = '00000000-0000-4000-8000-000000000001';
const FOREIGN_SLACK_ERROR = 'FOREIGN_SLACK_ERROR_MUST_NOT_RENDER';

function slackWebApiError(code: SlackErrorCode): Error {
  const error = new Error(FOREIGN_SLACK_ERROR);
  if (code === SlackErrorCode.PlatformError) {
    return Object.assign(error, { code, data: { ok: false, error: FOREIGN_SLACK_ERROR } });
  }
  if (code === SlackErrorCode.RateLimitedError) return Object.assign(error, { code, retryAfter: 1 });
  if (code === SlackErrorCode.RequestError) return Object.assign(error, { code, original: error });
  return Object.assign(error, { code });
}

async function expectUserRecovery(
  p: Promise<unknown>,
  recovery: VouchrRecovery,
  message: RegExp,
): Promise<UserFacingError> {
  try {
    await p;
  } catch (error) {
    assert.ok(error instanceof UserFacingError);
    assert.match(error.message, message);
    assert.equal(error.recovery, recovery);
    const safe = mapSafeError(error);
    assert.equal(safe.recovery, recovery);
    assert.equal(safe.retryable, false, 'recovery guidance never authorizes blind replay');
    return error;
  }
  throw new Error('expected a user-facing recovery error');
}

async function withClockOffset<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  const real = Date.now;
  const base = real();
  Date.now = () => base + ms;
  try {
    return await fn();
  } finally {
    Date.now = real;
  }
}

const gh = defineProvider({
  id: 'gh', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

const rateGh = defineProvider({
  id: 'gh', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  rateLimit: { perMinute: 1, burst: 1 },
});

// ── Store unit tests ──────────────────────────────────────────────────────────────────────
test('SessionGrants: thread-scoped grant, isolation, expiry, revoke, sweep', async (t) => {
  const db = await openTestDb(t);
  const s = new SessionGrants(db);

  // No grant initially.
  assert.equal(await s.isGranted(ID, 'C1', 'TH_A', 'gh', GENERATION), false);

  // Grant binds to exactly (team, channel, thread, user, provider).
  await s.grant(ID, 'C1', 'TH_A', 'gh', 60_000, GENERATION);
  assert.equal(await s.isGranted(ID, 'C1', 'TH_A', 'gh', GENERATION), true);

  // A different thread / channel / provider is NOT covered by that grant.
  assert.equal(await s.isGranted(ID, 'C1', 'TH_B', 'gh', GENERATION), false); // other thread
  assert.equal(await s.isGranted(ID, 'C2', 'TH_A', 'gh', GENERATION), false); // other channel
  assert.equal(await s.isGranted(ID, 'C1', 'TH_A', 'other', GENERATION), false); // other provider
  assert.equal(await s.isGranted({ ...ID, userId: 'U2' }, 'C1', 'TH_A', 'gh', GENERATION), false); // other user

  // Expired grant (negative ttl => already past) is not granted, and sweep removes it.
  await s.grant(ID, 'C1', 'TH_OLD', 'gh', -1, GENERATION);
  const expiredRequest = await s.request(ID, 'C1', 'TH_REQUEST_OLD', 'gh', GENERATION);
  await db.run(`UPDATE session_grant SET expires_at=0 WHERE thread=?`, ['TH_OLD']);
  await db.run(`UPDATE session_request SET expires_at=0 WHERE id=?`, [expiredRequest.id]);
  assert.equal(await s.isGranted(ID, 'C1', 'TH_OLD', 'gh', GENERATION), false);
  const swept = await s.sweepExpired();
  assert.ok(swept >= 2);
  assert.equal(await db.get(`SELECT 1 AS x FROM session_request WHERE id=?`, [expiredRequest.id]), undefined);

  // Revoke clears every grant for the user.
  await s.revokeForUser(ID);
  assert.equal(await s.isGranted(ID, 'C1', 'TH_A', 'gh', GENERATION), false);
});

test('SessionGrants rejects missing, malformed, and oversized credential generations at runtime', async (t) => {
  const db = await openTestDb(t);
  const sessions = new SessionGrants(db);
  for (const credentialId of [undefined, '', ' ', 'not-a-uuid', 'x'.repeat(10_000)]) {
    await assert.rejects(
      () => sessions.request(ID, 'C1', 'TH1', 'gh', credentialId as any),
      /valid credential generation id/,
    );
    await assert.rejects(
      () => sessions.grant(ID, 'C1', 'TH1', 'gh', 60_000, credentialId as any),
      /valid credential generation id/,
    );
    assert.equal(await sessions.isGranted(ID, 'C1', 'TH1', 'gh', credentialId as any), false);
  }
  assert.equal((await db.all(`SELECT 1 FROM session_request`)).length, 0);
  assert.equal((await db.all(`SELECT 1 FROM session_grant`)).length, 0);
});

test('PostgreSQL clock owns session TTL/lease and expired delivered requests reset', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const a = new SessionGrants(dbA);
  const b = new SessionGrants(dbB);

  const first = await withClockOffset(60 * 60_000, () => a.request(ID, 'C1', 'TH1', 'gh', GENERATION));
  const firstRow = await dbA.get<any>(`SELECT * FROM session_request WHERE id=?`, [first.id]);
  const dbNow = await dbA.get<{ now_ms: number }>(
    `SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint AS now_ms`,
  );
  assert.ok(Math.abs(firstRow.created_at - dbNow!.now_ms) < 5_000);
  const claim = await withClockOffset(60 * 60_000, () => a.claimDelivery(first.id));
  assert.equal(claim.status, 'claimed');
  assert.equal((await withClockOffset(-60 * 60_000, () => b.claimDelivery(first.id))).status, 'in-flight');
  assert.equal(await a.confirmDelivery(first.id, (claim as any).token), true);

  await dbA.run(`UPDATE session_request SET expires_at=0 WHERE id=?`, [first.id]);
  const replacement = await b.request(ID, 'C1', 'TH1', 'gh', GENERATION);
  assert.notEqual(replacement.id, first.id);
  const row = await dbA.get<any>(`SELECT * FROM session_request WHERE id=?`, [replacement.id]);
  assert.equal(row.delivered_at, null);
  assert.equal(row.delivery_token, null);
  assert.equal(row.delivery_lease_expires_at, 0);

  await withClockOffset(60 * 60_000, () => a.grant(ID, 'C1', 'TH2', 'gh', 60_000, GENERATION));
  assert.equal(
    await withClockOffset(-60 * 60_000, () => b.isGranted(ID, 'C1', 'TH2', 'gh', GENERATION)),
    true,
  );
});

// Regression: the Grid/SCIM cross-team sweep must clear session grants too, including a team that
// is discoverable ONLY by a lingering grant (no connection/consent there).
test('offboardUserEverywhere clears session grants across teams', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);

  // T1: only a session grant (no connection/consent), found solely via session_grant discovery.
  await sessions.grant({ ...ID, teamId: 'T1' }, 'C1', 'TH_A', 'gh', 60_000, GENERATION);
  // T2: a grant plus a stored connection.
  await sessions.grant({ ...ID, teamId: 'T2' }, 'C2', 'TH_B', 'gh', 60_000, GENERATION);
  await sessions.request({ ...ID, teamId: 'T2' }, 'C2', 'TH_PENDING', 'gh', GENERATION);
  await vault.upsert(userOwner({ ...ID, teamId: 'T2' }), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  // T3: only an unanswered session request; discovery must include this table too.
  await sessions.request({ ...ID, teamId: 'T3' }, 'C3', 'TH_ONLY_PENDING', 'gh', GENERATION);

  await offboardUserEverywhere(db, vault, audit, consent, { userId: ID.userId });

  assert.equal(await sessions.isGranted({ ...ID, teamId: 'T1' }, 'C1', 'TH_A', 'gh', GENERATION), false);
  assert.equal(await sessions.isGranted({ ...ID, teamId: 'T2' }, 'C2', 'TH_B', 'gh', GENERATION), false);
  assert.equal((await db.all('SELECT 1 AS x FROM session_grant WHERE user_id=?', [ID.userId])).length, 0);
  assert.equal((await db.all('SELECT 1 AS x FROM session_request WHERE user_id=?', [ID.userId])).length, 0);
});

// ── connect() gate (driven by the 'session' channel mode) ───────────────────────────────────
// `ghMode` sets the channel auth mode for 'gh' in channel C1 (default 'session' to exercise the gate).
async function setup(t: TestContext, ghMode: 'session' | 'per-user' | 'shared' = 'session') {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const sessions = new SessionGrants(db);
  const channelConfig = new ChannelConfig(db);
  await writeChannelMode(channelConfig, 'T1', 'C1', 'gh', ghMode);
  const posted: any[] = [];
  const client = { chat: { postEphemeral: async (p: any) => { posted.push(p); return {}; } } } as any;
  const make = (thread: string | null, channel: string | null = 'C1') =>
    new ConnectContext({
      identity: ID, channel, client, registry: new ProviderRegistry([gh]), vault, audit,
      consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
      channelConfig, providerIds: ['gh'], thread, sessions,
    });
  const auditRows = async () => (await db.all('SELECT action, meta FROM audit')) as any[];
  return { db, vault, sessions, posted, make, auditRows };
}

/** Real Bolt middleware + registered action handler with Slack transport faked. */
async function sessionHarness(t: TestContext, o: {
  db?: Db;
  providers?: Provider[];
  credential?: boolean;
  policy?: Policy;
  postEphemeral?: (payload: any) => Promise<unknown>;
} = {}) {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = o.db ?? await openTestDb(t);
  const providers = o.providers ?? [gh];
  const vouchr = await createVouchr({
    providers,
    baseUrl: 'http://127.0.0.1:1',
    db,
    policy: o.policy,
  });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, handler: any) => { actions[id] = handler; },
  });
  const ephemerals: any[] = [];
  const dms: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: {
      info: async ({ channel }: any) => ({ channel: { id: channel, is_channel: true, creator: 'U1' } }),
      members: async () => ({ members: ['U1'] }),
    },
    chat: {
      postEphemeral: async (payload: any) => {
        ephemerals.push(payload);
        return o.postEphemeral ? o.postEphemeral(payload) : {};
      },
      postMessage: async (payload: any) => { dms.push(payload); return {}; },
    },
  } as any;
  if (providers.some((p) => p.id === 'gh')) {
    await writeChannelMode(new ChannelConfig(db), 'T1', 'C1', 'gh', 'session');
    if (o.credential !== false) {
      await vouchr.vault.upsert(userOwner(ID), 'gh', {
        accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
      });
    }
  }
  const middlewareArgs: any = {
    context: {},
    client,
    event: { team: 'T1', user: 'U1', channel: 'C1', thread_ts: 'TH1' },
    next: async () => {},
  };
  await vouchr.middleware(middlewareArgs);
  const freshContext = async (): Promise<ConnectContext> => {
    const args = { ...middlewareArgs, context: {} };
    await vouchr.middleware(args);
    return args.context.vouchr as ConnectContext;
  };
  const click = async (id: string, over: {
    team?: string;
    user?: string;
    channel?: string;
    thread?: string | null;
    ack?: () => Promise<void>;
  } = {}) => {
    const responses: any[] = [];
    const channel = over.channel ?? 'C1';
    const thread = over.thread === undefined ? 'TH1' : over.thread;
    await actions[APPROVE_SESSION_ACTION]({
      ack: over.ack ?? (async () => {}),
      body: {
        team: { id: over.team ?? 'T1' },
        user: { id: over.user ?? 'U1' },
        channel: { id: channel },
        container: { channel_id: channel, ...(thread ? { thread_ts: thread } : {}) },
        actions: [{ value: id }],
      },
      client,
      respond: async (payload: any) => { responses.push(payload); },
    });
    return responses;
  };
  return {
    db,
    vouchr,
    ctx: middlewareArgs.context.vouchr as ConnectContext,
    freshContext,
    actions,
    client,
    ephemerals,
    dms,
    click,
    sessions: new SessionGrants(db),
  };
}

async function assertTombstoneFirstSessionFence(
  t: TestContext,
  identity: SlackIdentity,
  label: string,
  markOffboarded: (db: Db, identity: SlackIdentity) => Promise<void>,
): Promise<void> {
  const url = await testDbUrl(t);
  const actorDb = await openDb({ databaseUrl: url });
  const offboardDb = await openDb({ databaseUrl: url });
  t.after(() => actorDb.close());
  t.after(() => offboardDb.close());
  const vault = new Vault(actorDb, KEY);
  const audit = new Audit(actorDb);
  const sessions = new SessionGrants(actorDb);
  const owner = userOwner(identity);
  await vault.upsert(owner, 'gh', {
    accessToken: `stranded-${label}`, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const credentialId = await vault.liveId(owner, 'gh');
  assert.ok(credentialId);

  // Keep both the credential and one pre-offboard request deliberately stranded. The durable
  // tombstone—not best-effort cleanup—must prevent every subsequent authority mutation and use.
  const pending = await sessions.request(identity, `C_${label}`, `TH_GRANT_${label}`, 'gh', credentialId);
  const actorIssuedAt = await vault.userProvisioningIssuedAt();
  const retained = await new ConnectContext({
    identity,
    channel: null,
    client: {} as any,
    registry: new ProviderRegistry([gh]),
    vault,
    audit,
    consent: new Consent(actorDb),
    policy: new Policy(),
    redirectUri: 'http://x',
    providerIds: ['gh'],
    thread: null,
    sessions,
  }).connect('gh');

  await markOffboarded(offboardDb, identity);
  assert.equal(await vault.liveId(owner, 'gh'), credentialId, 'the regression keeps the credential stranded');

  let requestValidated = false;
  await assert.rejects(
    sessions.requestAudited({
      identity,
      channel: `C_${label}`,
      thread: `TH_REQUEST_${label}`,
      provider: 'gh',
      credentialId,
      actorIssuedAt,
      audit,
      vault,
      validate: async () => {
        requestValidated = true;
        return true;
      },
    }),
    (error: unknown) =>
      error instanceof InteractionStateChangedError &&
      error.interaction === 'session' &&
      error.reason === 'authorization',
  );
  assert.equal(requestValidated, false, 'the offboard fence rejects before mutable authorization work');

  let grantValidated = false;
  assert.deepEqual(await sessions.grantRequested({
    id: pending.id,
    identity,
    channel: `C_${label}`,
    thread: `TH_GRANT_${label}`,
    ttlMs: 60_000,
    actorIssuedAt,
    audit,
    validate: async () => {
      grantValidated = true;
      return true;
    },
  }), { status: 'actor-stale' });
  assert.ok(
    await actorDb.get(`SELECT 1 FROM session_request WHERE id=?`, [pending.id]),
    'a stale actor receipt cannot delete a request that may be newer than it',
  );

  const offboardedAt = await latestUserOffboardTombstone(actorDb, identity);
  assert.ok(offboardedAt != null);
  let freshActorIssuedAt = await vault.userProvisioningIssuedAt();
  while (freshActorIssuedAt <= offboardedAt) {
    await new Promise((resolve) => setTimeout(resolve, 1));
    freshActorIssuedAt = await vault.userProvisioningIssuedAt();
  }
  assert.deepEqual(await sessions.grantRequested({
    id: pending.id,
    identity,
    channel: `C_${label}`,
    thread: `TH_GRANT_${label}`,
    ttlMs: 60_000,
    actorIssuedAt: freshActorIssuedAt,
    audit,
    validate: async () => {
      grantValidated = true;
      return true;
    },
  }), { status: 'invalidated' });
  assert.equal(grantValidated, false, 'a current actor reclaims the pre-offboard request before authorization');

  const realFetch = globalThis.fetch;
  let egressCalls = 0;
  globalThis.fetch = (async () => {
    egressCalls++;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    await assert.rejects(retained.fetch('https://api.test/x'), (error: unknown) =>
      error instanceof InteractionStateChangedError && error.reason === 'authorization');
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(egressCalls, 0, 'a stranded credential is never usable after the tombstone');
  assert.equal((await actorDb.all(`SELECT 1 FROM session_request WHERE user_id=?`, [identity.userId])).length, 0);
  assert.equal((await actorDb.all(`SELECT 1 FROM session_grant WHERE user_id=?`, [identity.userId])).length, 0);
  assert.equal((await actorDb.all(`SELECT 1 FROM audit WHERE action='session' AND user_id=?`, [identity.userId])).length, 0);
}

test('two pools: a team tombstone fences a stranded credential from session request, grant, and use', async (t) => {
  await assertTombstoneFirstSessionFence(
    t,
    { enterpriseId: null, teamId: 'T_TEAM_FENCE', userId: 'U_TEAM_FENCE' },
    'TEAM',
    (db, identity) => new Consent(db).markOffboarded(identity),
  );
});

test('two pools: enterprise and global tombstones fence stranded session authority', async (t) => {
  await assertTombstoneFirstSessionFence(
    t,
    { enterpriseId: 'E_FENCE', teamId: 'T_ENTERPRISE_FENCE', userId: 'U_ENTERPRISE_FENCE' },
    'ENTERPRISE',
    (db, identity) => markUserOffboardedEverywhere(db, {
      enterpriseId: identity.enterpriseId,
      userId: identity.userId,
    }),
  );
  await assertTombstoneFirstSessionFence(
    t,
    { enterpriseId: 'E_OTHER', teamId: 'T_GLOBAL_FENCE', userId: 'U_GLOBAL_FENCE' },
    'GLOBAL',
    (db, identity) => markUserOffboardedEverywhere(db, { userId: identity.userId }),
  );
});

test('connect(): covered provider deduplicates one opaque in-thread request and prompt', async (t) => {
  const { db, vault, posted, make, auditRows } = await setup(t);
  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  // In a thread, no grant yet → approval prompt + SessionApprovalRequiredError (even though a cred
  // is stored: "connected once" still needs per-thread approval).
  await assert.rejects(() => make('TH_A').connect('gh'), SessionApprovalRequiredError);
  assert.equal(posted.length, 1);
  assert.equal(posted[0].thread_ts, 'TH_A');
  assert.equal(posted[0].user, 'U1');
  assert.match(posted[0].text, /only inside this thread/i);
  assert.match(posted[0].text, /session expires/i);
  const button = posted[0].blocks.find((block: any) => block.type === 'actions').elements[0];
  assert.match(button.value, /^[0-9a-f-]{36}$/i);
  assert.ok(!button.value.includes('gh'));
  assert.ok(!button.value.includes('TH_A'));

  // A repeated agent turn converges on the same live row and does not post/audit another prompt.
  await assert.rejects(() => make('TH_A').connect('gh'), SessionApprovalRequiredError);
  assert.equal(posted.length, 1);
  const pending = (await db.all(`SELECT id, provider, thread FROM session_request`)) as any[];
  assert.deepEqual(pending, [{ id: button.value, provider: 'gh', thread: 'TH_A' }]);
  const sessionRows = (await auditRows()).filter((r) => r.action === 'session');
  assert.equal(sessionRows.length, 1);
  assert.deepEqual(JSON.parse(sessionRows[0].meta), { channel: 'C1', thread: 'TH_A', event: 'request' });
  assert.ok(!sessionRows[0].meta.includes(button.value), 'opaque control ids never enter audit metadata');
});

test('connect(): after granting the thread, the same thread proceeds but other threads do not', async (t) => {
  const { vault, sessions, make } = await setup(t);
  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const credentialId = await vault.liveId(userOwner(ID), 'gh');
  assert.ok(credentialId);
  await sessions.grant(ID, 'C1', 'TH_A', 'gh', 60_000, credentialId);
  assert.ok(await make('TH_A').connect('gh')); // granted thread → real handle

  // A different thread has no grant → still blocked. The grant cannot leak across threads.
  await assert.rejects(() => make('TH_B').connect('gh'), SessionApprovalRequiredError);
});

test('connect(): covered provider off-thread is refused (no thread to scope a session)', async (t) => {
  const { vault, make, auditRows } = await setup(t);
  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  await assert.rejects(() => make(null).connect('gh'), /thread-scoped session/);
  const denied = (await auditRows()).filter((r) => r.action === 'denied');
  assert.equal(denied.length, 1);
  assert.match(denied[0].meta, /no-thread/);
});

test('connect(): a provider in per-user mode is not gated', async (t) => {
  // Channel mode is 'per-user' for gh → no session needed; with a stored cred connect() returns a handle.
  const { vault, posted, make } = await setup(t, 'per-user');
  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  assert.ok(await make('TH_A').connect('gh'));
  assert.equal(posted.length, 0); // no approval prompt
});

test('connect(): shared mode routes to the channel-credential path', async (t) => {
  // With no shared cred configured, connect() in 'shared' mode surfaces connectChannel's specific
  // error, proving it delegated to the channel path rather than the per-user one.
  const { make } = await setup(t, 'shared');
  await assert.rejects(() => make('TH_A').connect('gh'), /No channel credential configured/);
});

test('session mode connects first, then requests thread approval after the credential exists', async (t) => {
  const { db, vouchr, ctx, ephemerals } = await sessionHarness(t, { credential: false });
  await assert.rejects(() => ctx.connect('gh'), ConsentRequiredError);
  assert.equal((await db.all(`SELECT 1 AS x FROM session_request`)).length, 0);
  assert.match(JSON.stringify(ephemerals[0]?.blocks), /Connect gh/);

  await vouchr.vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  assert.equal((await db.all(`SELECT 1 AS x FROM session_request`)).length, 1);
  assert.match(JSON.stringify(ephemerals.at(-1)?.blocks), new RegExp(APPROVE_SESSION_ACTION));
});

test('platform-rejected session prompt clears its request so an immediate retry can deliver', async (t) => {
  let reject = true;
  const { db, ctx, ephemerals } = await sessionHarness(t, {
    postEphemeral: async () => {
      if (reject) throw slackWebApiError(SlackErrorCode.PlatformError);
      return {};
    },
  });
  const error = await expectUserRecovery(
    ctx.connect('gh'),
    'fix_configuration',
    /Slack rejected the session prompt before delivery/i,
  );
  assert.ok(!error.message.includes(FOREIGN_SLACK_ERROR));
  assert.equal((await db.all(`SELECT 1 FROM session_request`)).length, 0);

  reject = false;
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  assert.equal(ephemerals.length, 2, 'definite rejection does not park the immediate retry behind a lease');
  const retried = await db.get<any>(`SELECT delivery_token, delivered_at FROM session_request`);
  assert.equal(retried?.delivery_token, null);
  assert.ok(retried?.delivered_at != null);
});

test('rate-limited session prompt clears its request so an immediate retry can deliver', async (t) => {
  let reject = true;
  const { db, ctx, ephemerals } = await sessionHarness(t, {
    postEphemeral: async () => {
      if (reject) throw slackWebApiError(SlackErrorCode.RateLimitedError);
      return {};
    },
  });
  const error = await expectUserRecovery(
    ctx.connect('gh'),
    'retry_later',
    /Slack rate-limited the session prompt before delivery/i,
  );
  assert.ok(!error.message.includes(FOREIGN_SLACK_ERROR));
  assert.equal((await db.all(`SELECT 1 FROM session_request`)).length, 0);

  reject = false;
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  assert.equal(ephemerals.length, 2, 'known rate limiting does not park the immediate retry behind a lease');
  assert.equal((await db.all(`SELECT 1 FROM session_request`)).length, 1);
});

test('request-error session-prompt delivery retains one decidable request and no immediate duplicate', async (t) => {
  const { db, ctx, ephemerals, click } = await sessionHarness(t, {
    postEphemeral: async () => { throw slackWebApiError(SlackErrorCode.RequestError); },
  });
  const error = await expectUserRecovery(
    ctx.connect('gh'),
    'retry_later',
    /could not confirm session-prompt delivery/i,
  );
  assert.ok(!error.message.includes(FOREIGN_SLACK_ERROR));
  const row = await db.get<any>(`SELECT id, delivery_token FROM session_request`);
  assert.ok(row?.delivery_token);
  await expectUserRecovery(ctx.connect('gh'), 'retry_later', /still being delivered/i);
  assert.equal(ephemerals.length, 1, 'live lease prevents an immediate duplicate prompt');
  assert.match((await click(row.id))[0]?.text ?? '', /Approved/);
  const audits = await db.all<any>(`SELECT meta FROM audit WHERE action='session'`);
  assert.equal(audits.filter((r) => JSON.parse(r.meta).event === 'request').length, 1);
  assert.equal(audits.filter((r) => JSON.parse(r.meta).event === 'grant').length, 1);
});

test('definite rejection after an ambiguous session takeover retains the old decidable row', async (t) => {
  let outcome: 'ambiguous' | 'platform' = 'ambiguous';
  const { db, ctx, click } = await sessionHarness(t, {
    postEphemeral: () => Promise.reject(slackWebApiError(
      outcome === 'ambiguous' ? SlackErrorCode.RequestError : SlackErrorCode.PlatformError,
    )),
  });
  await expectUserRecovery(
    ctx.connect('gh'),
    'retry_later',
    /could not confirm session-prompt delivery/i,
  );
  const original = await db.get<any>(`SELECT id, delivery_token FROM session_request`);
  assert.ok(original?.delivery_token);
  await db.run(`UPDATE session_request SET delivery_lease_expires_at=0 WHERE id=?`, [original.id]);

  outcome = 'platform';
  await expectUserRecovery(
    ctx.connect('gh'),
    'fix_configuration',
    /Slack rejected the session prompt before delivery/i,
  );
  const retained = await db.get<any>(`SELECT id, delivery_token FROM session_request`);
  assert.equal(retained?.id, original.id);
  assert.equal(retained?.delivery_token, null, 'a failed takeover releases rather than deletes the old row');
  assert.match((await click(original.id))[0]?.text ?? '', /Approved/);
});

test('session prompt confirmation drift reports resolve-again recovery', async (t) => {
  const { ctx } = await sessionHarness(t);
  (ctx as any).sessions.confirmDelivery = async () => false;
  await expectUserRecovery(
    ctx.connect('gh'),
    'resolve_again',
    /request changed before confirmation/i,
  );
});

test('session prompt-audit failure rolls back before Slack delivery and a later retry can prompt', async (t) => {
  const { db, vouchr, ctx, ephemerals } = await sessionHarness(t);
  const original = vouchr.audit.record.bind(vouchr.audit);
  (vouchr.audit as any).record = async (action: string, identity: any, provider: string, meta: any, ...rest: any[]) => {
    if (action === 'session' && meta?.event === 'request') throw new Error('audit unavailable');
    return (original as any)(action, identity, provider, meta, ...rest);
  };
  await assert.rejects(() => ctx.connect('gh'), /audit unavailable/);
  assert.equal(ephemerals.length, 0, 'no actionable button exists without its audit companion');
  assert.equal((await db.all(`SELECT 1 FROM session_request`)).length, 0);
  assert.equal((await db.all(`SELECT 1 FROM audit WHERE action='session'`)).length, 0);

  (vouchr.audit as any).record = original;
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  assert.equal(ephemerals.length, 1);
  assert.equal((await db.all(`SELECT 1 FROM session_request`)).length, 1);
});

test('session click is bound to exact signed team/user/channel/thread and commits grant+audit once', async (t) => {
  const { db, ctx, click, sessions } = await sessionHarness(t);
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  const pending = await db.get<any>(`SELECT * FROM session_request`);
  assert.ok(pending?.id);

  for (const wrong of [
    { team: 'T_OTHER' },
    { user: 'U_OTHER' },
    { channel: 'C_OTHER' },
    { thread: 'TH_OTHER' },
    { thread: null },
  ]) {
    const response = await click(pending.id, wrong);
    assert.match(response[0]?.text, /expired or was already completed/);
    assert.ok(await db.get(`SELECT 1 AS x FROM session_request WHERE id=?`, [pending.id]));
    assert.equal(await sessions.isGranted(ID, 'C1', 'TH1', 'gh', pending.credential_id), false);
  }

  const response = await click(pending.id);
  assert.match(response[0]?.text, /Approved \*gh\*/);
  assert.equal(await sessions.isGranted(ID, 'C1', 'TH1', 'gh', pending.credential_id), true);
  assert.equal(await db.get(`SELECT 1 AS x FROM session_request WHERE id=?`, [pending.id]), undefined);
  const grants = await db.all<any>(`SELECT meta FROM audit WHERE action='session'`);
  assert.equal(grants.filter((r) => JSON.parse(r.meta).event === 'grant').length, 1);
  assert.deepEqual(
    JSON.parse(grants.find((r) => JSON.parse(r.meta).event === 'grant').meta),
    { channel: 'C1', thread: 'TH1', event: 'grant' },
  );
  assert.ok(!JSON.stringify(grants).includes(pending.id));

  const duplicate = await click(pending.id);
  assert.match(duplicate[0]?.text, /expired or was already completed/);
  assert.equal((await db.all<any>(`SELECT 1 FROM audit WHERE action='session' AND meta LIKE '%"grant"%'`)).length, 1);
});

test('session action handler acknowledges Slack before database work', async (t) => {
  const raw = await openTestDb(t);
  let enforceAck = false;
  let acked = false;
  const wrapped: Db = {
    get: async (sql, params) => {
      if (enforceAck && /session_request/.test(sql)) assert.equal(acked, true, 'ack must precede the first request lookup');
      return raw.get(sql, params);
    },
    all: (sql, params) => raw.all(sql, params),
    run: (sql, params) => raw.run(sql, params),
    exec: (sql) => raw.exec(sql),
    close: async () => {},
    ...(raw.transaction ? { transaction: <T>(fn: (tx: Db) => Promise<T>) => raw.transaction!(fn) } : {}),
    ...(raw.withRefreshLock
      ? { withRefreshLock: <T>(key: string, fn: (tx: Db) => Promise<T>) => raw.withRefreshLock!(key, fn) }
      : {}),
    ...(raw.withRefreshLocks
      ? { withRefreshLocks: <T>(keys: readonly string[], fn: (tx: Db) => Promise<T>) => raw.withRefreshLocks!(keys, fn) }
      : {}),
  };
  const { db, ctx, click } = await sessionHarness(t, { db: wrapped });
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  const pending = await db.get<any>(`SELECT id, credential_id FROM session_request`);
  enforceAck = true;
  await click(pending.id, { ack: async () => { acked = true; } });
  assert.equal(acked, true);
});

test('a Slack session click received before offboarding cannot grant or delete the live request', async (t) => {
  const url = await testDbUrl(t);
  const actorDb = await openDb({ databaseUrl: url });
  const offboardDb = await openDb({ databaseUrl: url });
  t.after(() => actorDb.close());
  t.after(() => offboardDb.close());
  const h = await sessionHarness(t, { db: actorDb });
  await assert.rejects(() => h.ctx.connect('gh'), SessionApprovalRequiredError);
  const pending = await actorDb.get<{ id: string }>(`SELECT id FROM session_request`);
  assert.ok(pending);

  const response = await h.click(pending.id, {
    // The handler captures its trusted monotonic receipt before ack. Commit the tombstone during
    // ack so the later PostgreSQL conversion proves that this click predates offboarding.
    ack: async () => new Consent(offboardDb).markOffboarded(ID),
  });
  assert.match(response[0]?.text ?? '', /authority changed/i);
  assert.ok(
    await actorDb.get(`SELECT 1 FROM session_request WHERE id=?`, [pending.id]),
    'a stale click cannot consume a request that a newer interaction may still decide',
  );
  assert.equal((await actorDb.all(`SELECT 1 FROM session_grant`)).length, 0);
  const audits = await actorDb.all<any>(`SELECT meta FROM audit WHERE action='session'`);
  assert.equal(audits.filter((row) => JSON.parse(row.meta).event === 'request').length, 1);
  assert.equal(audits.filter((row) => JSON.parse(row.meta).event === 'grant').length, 0);
});

test('session audit failure rolls back consume+grant and the same button remains retryable', async (t) => {
  const { db, vouchr, ctx, click, sessions } = await sessionHarness(t);
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  const pending = await db.get<any>(`SELECT id, credential_id FROM session_request`);
  const original = vouchr.audit.record.bind(vouchr.audit);
  (vouchr.audit as any).record = async (action: string, identity: any, provider: string, meta: any, ...rest: any[]) => {
    if (action === 'session' && meta?.event === 'grant') throw new Error('audit unavailable');
    return (original as any)(action, identity, provider, meta, ...rest);
  };
  const failed = await click(pending.id);
  assert.match(failed[0]?.text, /could not confirm the session/i);
  assert.ok(await db.get(`SELECT 1 AS x FROM session_request WHERE id=?`, [pending.id]));
  assert.equal(await sessions.isGranted(ID, 'C1', 'TH1', 'gh', pending.credential_id), false);

  (vouchr.audit as any).record = original;
  const retried = await click(pending.id);
  assert.match(retried[0]?.text, /Approved/);
  assert.equal(await sessions.isGranted(ID, 'C1', 'TH1', 'gh', pending.credential_id), true);
});

test('two replicas clicking one session request yield one grant and one fixed stale receipt', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const a = await sessionHarness(t, { db: dbA });
  const b = await sessionHarness(t, { db: dbB });
  await assert.rejects(() => a.ctx.connect('gh'), SessionApprovalRequiredError);
  const pending = await dbA.get<any>(`SELECT id FROM session_request`);
  const [left, right] = await Promise.all([a.click(pending.id), b.click(pending.id)]);
  const receipts = [left[0]?.text, right[0]?.text].join('\n');
  assert.match(receipts, /Approved/);
  assert.match(receipts, /expired or was already completed/);
  assert.equal((await dbA.all(`SELECT 1 FROM session_grant`)).length, 1);
  assert.equal((await dbA.all<any>(`SELECT 1 FROM audit WHERE action='session' AND meta LIKE '%"grant"%'`)).length, 1);
});

test('cross-pool session decisions linearize with mode and tool writers in both commit orders', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const a = await sessionHarness(t, { db: dbA });
  const b = await sessionHarness(t, { db: dbB });
  const cfgB = new ChannelConfig(dbB);

  // Mode writer commits first: the click observes the purge after acquiring the same channel lock.
  await assert.rejects(() => a.ctx.connect('gh'), SessionApprovalRequiredError);
  const modePending = await dbA.get<any>(`SELECT id FROM session_request`);
  const modeAudit = new Audit(dbB);
  const modeRecord = modeAudit.record.bind(modeAudit);
  let releaseMode!: () => void;
  let modeAtAudit!: () => void;
  const releaseModeP = new Promise<void>((resolve) => { releaseMode = resolve; });
  const modeAtAuditP = new Promise<void>((resolve) => { modeAtAudit = resolve; });
  (modeAudit as any).record = async (...args: any[]) => {
    modeAtAudit();
    await releaseModeP;
    return (modeRecord as any)(...args);
  };
  const modeWriterIssuance = await b.vouchr.vault.userProvisioningIssuedAt();
  const modeWriter = setChannelCredentialMode({
    vault: b.vouchr.vault,
    audit: modeAudit,
    channelConfig: cfgB,
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: 'per-user',
    issuance: modeWriterIssuance,
  });
  await modeAtAuditP;
  let clickSettled = false;
  const waitingClick = a.click(modePending.id).then((r) => { clickSettled = true; return r; });
  let demandSettled = false;
  const staleDemand = a.ctx.connect('gh').finally(() => { demandSettled = true; });
  void staleDemand.catch(() => undefined);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(clickSettled, false, 'click waits for the mode writer lifecycle lock');
  assert.equal(demandSettled, false, 'request creation waits for the mode writer lifecycle lock');
  releaseMode();
  await modeWriter;
  assert.match((await waitingClick)[0]?.text, /expired or was already completed/);
  await assert.rejects(staleDemand, (error) =>
    error instanceof InteractionStateChangedError &&
    error.interaction === 'session' &&
    error.reason === 'authorization');
  assert.equal((await dbA.all(`SELECT 1 FROM session_request`)).length, 0, 'stale demand cannot recreate a purged request');

  // Click commits first: the following mode writer waits, then purges the just-created grant.
  const resetModeIssuance = await b.vouchr.vault.userProvisioningIssuedAt();
  await setChannelCredentialMode({
    vault: b.vouchr.vault,
    audit: new Audit(dbB),
    channelConfig: cfgB,
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: 'session',
    issuance: resetModeIssuance,
  });
  await assert.rejects(() => a.ctx.connect('gh'), SessionApprovalRequiredError);
  const clickPending = await dbA.get<any>(`SELECT id FROM session_request`);
  const originalClickAudit = a.vouchr.audit.record.bind(a.vouchr.audit);
  let releaseClick!: () => void;
  let clickAtAudit!: () => void;
  const releaseClickP = new Promise<void>((resolve) => { releaseClick = resolve; });
  const clickAtAuditP = new Promise<void>((resolve) => { clickAtAudit = resolve; });
  (a.vouchr.audit as any).record = async (action: string, identity: any, provider: string, meta: any, ...rest: any[]) => {
    if (action === 'session' && meta?.event === 'grant') {
      clickAtAudit();
      await releaseClickP;
    }
    return (originalClickAudit as any)(action, identity, provider, meta, ...rest);
  };
  const followingWriterIssuance = await b.vouchr.vault.userProvisioningIssuedAt();
  const firstClick = a.click(clickPending.id);
  await clickAtAuditP;
  let writerSettled = false;
  const followingWriter = setChannelCredentialMode({
    vault: b.vouchr.vault,
    audit: new Audit(dbB),
    channelConfig: cfgB,
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: 'per-user',
    issuance: followingWriterIssuance,
  }).then(() => { writerSettled = true; });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(writerSettled, false, 'mode writer waits for the session decision lock');
  releaseClick();
  assert.match((await firstClick)[0]?.text, /Approved/);
  await followingWriter;
  (a.vouchr.audit as any).record = originalClickAudit;
  assert.equal(await a.sessions.grantedCredentialId(ID, 'C1', 'TH1', 'gh'), null, 'later governance commit purges the grant');

  // Tool writer first uses the same canonical channel/provider lock and invalidates the control.
  const toolResetIssuance = await b.vouchr.vault.userProvisioningIssuedAt();
  await setChannelCredentialMode({
    vault: b.vouchr.vault,
    audit: new Audit(dbB),
    channelConfig: cfgB,
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: 'session',
    issuance: toolResetIssuance,
  });
  await assert.rejects(() => a.ctx.connect('gh'), SessionApprovalRequiredError);
  const toolPending = await dbA.get<any>(`SELECT id FROM session_request`);
  const toolAudit = new Audit(dbB);
  const toolRecord = toolAudit.record.bind(toolAudit);
  let releaseTool!: () => void;
  let toolAtAudit!: () => void;
  const releaseToolP = new Promise<void>((resolve) => { releaseTool = resolve; });
  const toolAtAuditP = new Promise<void>((resolve) => { toolAtAudit = resolve; });
  (toolAudit as any).record = async (...args: any[]) => {
    toolAtAudit();
    await releaseToolP;
    return (toolRecord as any)(...args);
  };
  const toolWriterIssuance = await b.vouchr.vault.userProvisioningIssuedAt();
  const toolWriter = configureChannelTools({
    channelTools: new ChannelTools(dbB),
    vault: b.vouchr.vault,
    audit: toolAudit,
    identity: ID,
    channel: 'C1',
    changes: [['gh', false]],
    allProviders: ['gh'],
    authorize: async () => true,
    assertEligible: async () => {},
    issuance: toolWriterIssuance,
  });
  await toolAtAuditP;
  let toolClickSettled = false;
  const toolClick = a.click(toolPending.id).then((r) => { toolClickSettled = true; return r; });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(toolClickSettled, false, 'click waits for the tool writer lifecycle lock');
  releaseTool();
  await toolWriter;
  assert.match((await toolClick)[0]?.text, /expired or was already completed/);
});

test('a grant click racing connect resumes without a redundant request, prompt, or audit', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const a = await sessionHarness(t, { db: dbA });
  const b = await sessionHarness(t, { db: dbB });

  await assert.rejects(() => a.ctx.connect('gh'), SessionApprovalRequiredError);
  const pending = await dbA.get<any>(`SELECT id FROM session_request`);
  const originalRecord = a.vouchr.audit.record.bind(a.vouchr.audit);
  let atGrant!: () => void;
  let release!: () => void;
  const atGrantP = new Promise<void>((resolve) => { atGrant = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  (a.vouchr.audit as any).record = async (
    action: string,
    identity: any,
    provider: string,
    meta: any,
    ...rest: any[]
  ) => {
    if (action === 'session' && meta?.event === 'grant') {
      atGrant();
      await releaseP;
    }
    return (originalRecord as any)(action, identity, provider, meta, ...rest);
  };

  const clicking = a.click(pending.id);
  await atGrantP;
  let connectSettled = false;
  const connecting = b.ctx.connect('gh').finally(() => { connectSettled = true; });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(connectSettled, false, 'connect waits for the click lifecycle transaction');
  release();
  assert.match((await clicking)[0]?.text, /Approved/);
  assert.ok(await connecting, 'the newly committed exact grant resumes the waiting connect');

  assert.equal((await dbA.all(`SELECT 1 FROM session_request`)).length, 0);
  const audits = await dbA.all<any>(`SELECT meta FROM audit WHERE action='session'`);
  assert.equal(audits.filter((row) => JSON.parse(row.meta).event === 'request').length, 1);
  assert.equal(audits.filter((row) => JSON.parse(row.meta).event === 'grant').length, 1);
  assert.equal(a.ephemerals.length, 1);
  assert.equal(b.ephemerals.length, 0, 'waiting connect does not deliver a phantom second prompt');
});

test('offboard tombstone and session grant linearize across pools; tombstone-first invalidates', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const sessions = new SessionGrants(dbA);
  const pending = await sessions.request(ID, 'C1', 'TH1', 'gh', GENERATION);
  let release!: () => void;
  let started!: () => void;
  const startedP = new Promise<void>((resolve) => { started = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const tombstone = withOffboardLock(dbB, 'T1', 'U1', async (tx) => {
    await tx.run(
      `INSERT INTO offboard_tombstone (team_id,user_id,created_at) VALUES (?,?,${POSTGRES_NOW_MS_SQL})
       ON CONFLICT(team_id,user_id) DO UPDATE SET created_at=excluded.created_at`,
      ['T1', 'U1'],
    );
    started();
    await releaseP;
  });
  await startedP;
  await new Promise((resolve) => setTimeout(resolve, 2));
  const actorIssuedAt = await new Vault(dbA, KEY).userProvisioningIssuedAt();
  let settled = false;
  const grant = sessions.grantRequested({
    id: pending.id,
    identity: ID,
    channel: 'C1',
    thread: 'TH1',
    ttlMs: 60_000,
    actorIssuedAt,
    audit: new Audit(dbA),
    validate: async () => true,
  }).then((result) => { settled = true; return result; });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(settled, false, 'grant waits on the durable offboard fence');
  release();
  await tombstone;
  assert.deepEqual(await grant, { status: 'invalidated' });
  assert.equal((await dbA.all(`SELECT 1 FROM session_grant`)).length, 0);
});

test('gated credential upsert holds the offboard fence through commit and a successful offboard deletes it', async (t) => {
  const url = await testDbUrl(t);
  const writeDb = await openDb({ databaseUrl: url });
  const offboardDb = await openDb({ databaseUrl: url });
  const probeDb = await openDb({ databaseUrl: url });
  t.after(() => writeDb.close());
  t.after(() => offboardDb.close());
  t.after(() => probeDb.close());
  const writeVault = new Vault(writeDb, KEY);
  const offboardVault = new Vault(offboardDb, KEY);
  const owner = userOwner(ID);
  let paused!: () => void;
  let release!: () => void;
  const pausedP = new Promise<void>((resolve) => { paused = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });

  // afterWrite runs after the conditional INSERT but before the lifecycle transaction COMMIT.
  const writing = writeVault.upsert(owner, 'gh', {
    accessToken: 'new', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  }, { mintedAt: 0 }, async () => {
    paused();
    await releaseP;
  });
  await pausedP;

  const probe = await probeDb.transaction!(async (tx) => tx.get<{ got: boolean }>(
    `SELECT pg_try_advisory_xact_lock(hashtext(?)) AS got`,
    [offboardLockKey(ID.teamId, ID.userId)],
  ));
  const offboarding = offboardUser(
    offboardVault,
    new Audit(offboardDb),
    new Consent(offboardDb),
    ID,
  );
  // Dispatch offboarding while the upsert is still paused. The production fence makes it wait;
  // release unconditionally before assertions so a broken implementation cannot hang cleanup.
  await new Promise<void>((resolve) => setImmediate(resolve));
  release();
  const [written, removed] = await Promise.all([writing, offboarding]);

  assert.equal(probe?.got, false, 'the pre-commit upsert owns the canonical offboard fence');
  assert.equal(written, true);
  assert.deepEqual(removed, ['gh']);
  assert.equal(await offboardVault.liveId(owner, 'gh'), null);
});

test('an offboard gate is rejected for a non-user credential owner', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = channelOwner(ID.teamId, 'C1');
  await assert.rejects(
    vault.upsert(owner, 'gh', {
      accessToken: 'shared', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    }, { mintedAt: 0 }),
    /requires a user owner/,
  );
  assert.equal(await vault.liveId(owner, 'gh'), null);
});

test('PostgreSQL clock makes tombstone-first session grants fail closed under ±1h pod skew', async (t) => {
  const url = await testDbUrl(t);
  const requestDb = await openDb({ databaseUrl: url });
  const offboardDb = await openDb({ databaseUrl: url });
  t.after(() => requestDb.close());
  t.after(() => offboardDb.close());

  for (const [index, offset] of [-60 * 60_000, 60 * 60_000].entries()) {
    const identity = { ...ID, userId: `U_SKEW_${index}` };
    const sessions = new SessionGrants(requestDb);
    const pending = await sessions.request(identity, 'C1', `TH_${index}`, 'gh', GENERATION);
    // Simulate failed best-effort request cleanup: the pre-offboard row deliberately remains. The
    // durable tombstone alone must fence it, regardless of the offboarding pod's application clock.
    await withClockOffset(offset, () => new Consent(offboardDb).markOffboarded(identity));
    const offboardedAt = await latestUserOffboardTombstone(requestDb, identity);
    assert.ok(offboardedAt != null);
    const requestVault = new Vault(requestDb, KEY);
    let actorIssuedAt = await requestVault.userProvisioningIssuedAt();
    while (actorIssuedAt <= offboardedAt) {
      await new Promise((resolve) => setTimeout(resolve, 1));
      actorIssuedAt = await requestVault.userProvisioningIssuedAt();
    }
    const result = await sessions.grantRequested({
      id: pending.id,
      identity,
      channel: 'C1',
      thread: `TH_${index}`,
      ttlMs: 60_000,
      actorIssuedAt,
      audit: new Audit(requestDb),
      validate: async () => true,
    });
    assert.deepEqual(result, { status: 'invalidated' });
  }
  assert.equal((await requestDb.all(`SELECT 1 FROM session_grant`)).length, 0);
  assert.equal((await requestDb.all(`SELECT 1 FROM audit WHERE action='session'`)).length, 0);
});

test('vault writes and delete purge pending requests and live grants as credential satellites', async (t) => {
  const { db, vault, sessions } = await setup(t);
  const seed = async (thread: string) => {
    const credentialId = await vault.liveId(userOwner(ID), 'gh');
    assert.ok(credentialId);
    await sessions.request(ID, 'C1', `${thread}-pending`, 'gh', credentialId);
    await sessions.grant(ID, 'C1', `${thread}-grant`, 'gh', 60_000, credentialId);
  };
  const assertPurged = async () => {
    assert.equal((await db.all(`SELECT 1 FROM session_request`)).length, 0);
    assert.equal((await db.all(`SELECT 1 FROM session_grant`)).length, 0);
  };

  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-initial', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  await seed('upsert');
  await vault.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-new', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  await assertPurged();
  await seed('reference');
  await vault.reference(userOwner(ID), 'gh', { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:example' });
  await assertPurged();
  await seed('delete');
  await vault.delete(userOwner(ID), 'gh');
  await assertPurged();
});

test('session click revalidates a live current user credential before granting', async (t) => {
  const { db, ctx, click, sessions } = await sessionHarness(t);
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  const pending = await db.get<any>(`SELECT id FROM session_request`);
  // Preserve the pending row deliberately so this exercises mutation-time credential validation,
  // not the normal Vault satellite purge.
  await db.run(
    `DELETE FROM connection WHERE team_id=? AND owner_kind='user' AND owner_id=? AND provider=?`,
    ['T1', 'U1', 'gh'],
  );
  const response = await click(pending.id);
  assert.match(response[0]?.text, /no longer valid because provider or channel access changed/);
  assert.equal(await sessions.grantedCredentialId(ID, 'C1', 'TH1', 'gh'), null);
  assert.equal((await db.all(`SELECT 1 FROM session_request`)).length, 0);
});

test('cross-pool reconnect commits before an old session click and the old request cannot cross generations', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const a = await sessionHarness(t, { db: dbA });
  const replacement = new Vault(dbB, KEY);
  await assert.rejects(() => a.ctx.connect('gh'), SessionApprovalRequiredError);
  const pending = await dbA.get<any>(`SELECT id FROM session_request`);
  let release!: () => void;
  let afterPurge!: () => void;
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const afterPurgeP = new Promise<void>((resolve) => { afterPurge = resolve; });
  const reconnect = replacement.upsert(userOwner(ID), 'gh', {
    accessToken: 'sk-replacement', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  }, undefined, async () => {
    afterPurge();
    await releaseP;
  });
  await afterPurgeP;
  let settled = false;
  const click = a.click(pending.id).then((r) => { settled = true; return r; });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(settled, false, 'the click waits for the reconnect satellite delete to commit');
  release();
  assert.equal(await reconnect, true);
  assert.match((await click)[0]?.text, /expired or was already completed/);
  assert.equal(await a.sessions.grantedCredentialId(ID, 'C1', 'TH1', 'gh'), null);
});

test('post-purge stale session request insert is fenced by the credential-generation lock', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const vaultA = new Vault(dbA, KEY);
  const vaultB = new Vault(dbB, KEY);
  await vaultA.upsert(userOwner(ID), 'gh', {
    accessToken: 'old', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const oldId = await vaultA.liveId(userOwner(ID), 'gh');
  assert.ok(oldId);
  const actorIssuedAt = await vaultA.userProvisioningIssuedAt();
  let purged!: () => void;
  let release!: () => void;
  const purgedP = new Promise<void>((resolve) => { purged = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const reconnect = vaultB.upsert(userOwner(ID), 'gh', {
    accessToken: 'new', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  }, undefined, async () => {
    purged();
    await releaseP;
  });
  await purgedP;
  const staleInsert = new SessionGrants(dbA).requestAudited({
    identity: ID,
    channel: 'C1',
    thread: 'TH1',
    provider: 'gh',
    credentialId: oldId,
    actorIssuedAt,
    audit: new Audit(dbA),
    vault: vaultA,
    validate: async () => true,
  });
  let settled = false;
  void staleInsert.finally(() => { settled = true; }).catch(() => undefined);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(settled, false, 'stale creator waits for the reconnect transaction');
  release();
  await reconnect;
  await assert.rejects(staleInsert, (error) =>
    error instanceof InteractionStateChangedError &&
    error.interaction === 'session' &&
    error.reason === 'credential');
  assert.equal((await dbA.all(`SELECT 1 FROM session_request`)).length, 0);
});

test('delete-in-progress fences both session and approval request recreation across pools', async (t) => {
  const url = await testDbUrl(t);
  const rawDelete = await openDb({ databaseUrl: url });
  const requestDb = await openDb({ databaseUrl: url });
  t.after(() => rawDelete.close());
  t.after(() => requestDb.close());
  let pauseDelete = false;
  let purged!: () => void;
  let release!: () => void;
  const purgedP = new Promise<void>((resolve) => { purged = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const deleteDb: Db = {
    get: (sql, params) => rawDelete.get(sql, params), all: (sql, params) => rawDelete.all(sql, params),
    run: (sql, params) => rawDelete.run(sql, params), exec: (sql) => rawDelete.exec(sql), close: async () => {},
    transaction: <T>(fn: (tx: Db) => Promise<T>) => rawDelete.transaction!(fn),
    withRefreshLock: <T>(key: string, fn: (tx: Db) => Promise<T>) => rawDelete.withRefreshLock!(key, async (tx) => {
      const wrapped: Db = {
        get: (sql, params) => tx.get(sql, params), all: (sql, params) => tx.all(sql, params),
        run: async (sql, params) => {
          const result = await tx.run(sql, params);
          if (pauseDelete && /DELETE FROM session_grant/.test(sql)) {
            purged();
            await releaseP;
          }
          return result;
        },
        exec: (sql) => tx.exec(sql), close: async () => {},
        transaction: <U>(inner: (db: Db) => Promise<U>) => inner(wrapped),
        withRefreshLock: <U>(_innerKey: string, inner: (db: Db) => Promise<U>) => inner(wrapped),
        withRefreshLocks: <U>(_keys: readonly string[], inner: (db: Db) => Promise<U>) => inner(wrapped),
      };
      return fn(wrapped);
    }),
  };
  const deleteVault = new Vault(deleteDb, KEY);
  const requestVault = new Vault(requestDb, KEY);
  const owner = userOwner(ID);
  await deleteVault.upsert(owner, 'gh', {
    accessToken: 'old', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const credentialId = await deleteVault.liveId(owner, 'gh');
  assert.ok(credentialId);
  const actorIssuedAt = await requestVault.userProvisioningIssuedAt();
  pauseDelete = true;
  const deleting = deleteVault.delete(owner, 'gh');
  await purgedP;
  const sessionRequest = new SessionGrants(requestDb).requestAudited({
    identity: ID, channel: 'C1', thread: 'TH1', provider: 'gh', credentialId,
    actorIssuedAt, audit: new Audit(requestDb), vault: requestVault, validate: async () => true,
  });
  const approvalRequest = new Approvals(requestDb).requestAudited({
    teamId: 'T1', userId: 'U1', ownerKind: 'user', ownerId: 'U1', credentialId,
    provider: 'gh', method: 'POST', origin: 'https://api.test', host: 'api.test', path: '/x', queryHash: '',
    channel: 'C1', thread: 'TH1',
  }, new Audit(requestDb), ID, requestVault, async () => true);
  void sessionRequest.catch(() => undefined);
  void approvalRequest.catch(() => undefined);
  await new Promise((resolve) => setTimeout(resolve, 20));
  release();
  assert.equal(await deleting, true);
  await assert.rejects(sessionRequest, (error) =>
    error instanceof InteractionStateChangedError &&
    error.interaction === 'session' &&
    error.reason === 'credential');
  await assert.rejects(approvalRequest, (error) =>
    error instanceof InteractionStateChangedError &&
    error.interaction === 'approval' &&
    error.reason === 'credential');
  assert.equal((await requestDb.all(`SELECT 1 FROM session_request`)).length, 0);
  assert.equal((await requestDb.all(`SELECT 1 FROM approval_request`)).length, 0);
});

test('deleteExpired shares the credential lock and purges a request that commits first', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const requestVault = new Vault(dbA, KEY);
  const expiryVault = new Vault(dbB, KEY, { maxAgeMs: 1 });
  const owner = userOwner(ID);
  await requestVault.upsert(owner, 'gh', {
    accessToken: 'old', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const credentialId = await requestVault.liveId(owner, 'gh');
  assert.ok(credentialId);
  await dbA.run(`UPDATE connection SET created_at=0 WHERE id=?`, [credentialId]);
  let validating!: () => void;
  let release!: () => void;
  const validatingP = new Promise<void>((resolve) => { validating = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const request = new SessionGrants(dbA).requestAudited({
    identity: ID, channel: 'C1', thread: 'TH1', provider: 'gh', credentialId,
    actorIssuedAt: await requestVault.userProvisioningIssuedAt(),
    audit: new Audit(dbA), vault: requestVault,
    validate: async () => {
      validating();
      await releaseP;
      return true;
    },
  });
  await validatingP;
  let deleteSettled = false;
  const deleting = expiryVault.deleteExpired(owner, 'gh').then((value) => {
    deleteSettled = true;
    return value;
  });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(deleteSettled, false);
  release();
  await request;
  assert.equal(await deleting, true);
  assert.equal((await dbA.all(`SELECT 1 FROM session_request`)).length, 0);
});

test('cross-pool reconnect after session grant check cannot make connect adopt the replacement credential', async (t) => {
  const url = await testDbUrl(t);
  const raw = await openDb({ databaseUrl: url });
  const peer = await openDb({ databaseUrl: url });
  t.after(() => raw.close());
  t.after(() => peer.close());
  let blockExactRead = false;
  let reached!: () => void;
  let release!: () => void;
  const reachedP = new Promise<void>((resolve) => { reached = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const db: Db = {
    get: async (sql, params) => {
      if (blockExactRead && /SELECT \* FROM connection/.test(sql) && /AND id=\?/.test(sql)) {
        reached();
        await releaseP;
      }
      return raw.get(sql, params);
    },
    all: (sql, params) => raw.all(sql, params),
    run: (sql, params) => raw.run(sql, params),
    exec: (sql) => raw.exec(sql),
    close: async () => {},
    transaction: <T>(fn: (tx: Db) => Promise<T>) => raw.transaction!(fn),
    withRefreshLock: <T>(key: string, fn: (tx: Db) => Promise<T>) => raw.withRefreshLock!(key, fn),
    withRefreshLocks: <T>(keys: readonly string[], fn: (tx: Db) => Promise<T>) => raw.withRefreshLocks!(keys, fn),
  };
  const h = await sessionHarness(t, { db });
  const replacement = new Vault(peer, KEY);
  const credentialId = await h.vouchr.vault.liveId(userOwner(ID), 'gh');
  assert.ok(credentialId);
  await h.sessions.grant(ID, 'C1', 'TH1', 'gh', 60_000, credentialId);
  blockExactRead = true;
  const connecting = h.ctx.connect('gh');
  await reachedP;
  await replacement.upsert(userOwner(ID), 'gh', {
    accessToken: 'replacement', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  release();
  await assert.rejects(connecting, ConsentRequiredError);
  blockExactRead = false;
  await assert.rejects(() => h.ctx.connect('gh'), SessionApprovalRequiredError);
});

test('mode session→per-user→session and tool off→on cannot resurrect old session controls or grants', async (t) => {
  const { db, vouchr, ctx, click, sessions } = await sessionHarness(t);
  await assert.rejects(() => ctx.connect('gh'), SessionApprovalRequiredError);
  const old = await db.get<any>(`SELECT id FROM session_request`);
  const cfg = new ChannelConfig(db);
  const issuance = await vouchr.vault.userProvisioningIssuedAt();
  const mode = (value: 'session' | 'per-user') => setChannelCredentialMode({
    vault: vouchr.vault,
    audit: vouchr.audit,
    channelConfig: cfg,
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: value,
    issuance,
  });
  await mode('per-user');
  await mode('session');
  assert.match((await click(old.id))[0]?.text, /expired or was already completed/);

  const credentialId = await vouchr.vault.liveId(userOwner(ID), 'gh');
  assert.ok(credentialId);
  await sessions.grant(ID, 'C1', 'TH1', 'gh', 60_000, credentialId);
  assert.equal(await sessions.isGranted(ID, 'C1', 'TH1', 'gh', credentialId), true);
  await mode('per-user');
  await mode('session');
  assert.equal(await sessions.grantedCredentialId(ID, 'C1', 'TH1', 'gh'), null);

  await sessions.grant(ID, 'C1', 'TH1', 'gh', 60_000, credentialId);
  const tools = (enabled: boolean) => configureChannelTools({
    channelTools: new ChannelTools(db),
    vault: vouchr.vault,
    audit: vouchr.audit,
    identity: ID,
    channel: 'C1',
    changes: [['gh', enabled]],
    allProviders: ['gh'],
    authorize: async () => true,
    assertEligible: async () => {},
    issuance,
  });
  await tools(false);
  await tools(true);
  assert.equal(await sessions.grantedCredentialId(ID, 'C1', 'TH1', 'gh'), null);
});

test('retained per-user handle revalidates before account, decrypt, rate budget, or egress', async (t) => {
  const h = await sessionHarness(t, { providers: [rateGh] });
  const cfg = new ChannelConfig(h.db);
  const issuance = await h.vouchr.vault.userProvisioningIssuedAt();
  const setMode = (mode: 'per-user' | 'session') => setChannelCredentialMode({
    vault: h.vouchr.vault,
    audit: h.vouchr.audit,
    channelConfig: cfg,
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode,
    issuance,
  });
  await setMode('per-user');
  const handle = await h.ctx.connect('gh');
  await setMode('session');

  const originalGet = h.vouchr.vault.get.bind(h.vouchr.vault);
  const originalAccount = h.vouchr.vault.getAccount.bind(h.vouchr.vault);
  let decryptingReads = 0;
  let accountReads = 0;
  (h.vouchr.vault as any).get = (...args: any[]) => {
    decryptingReads++;
    return (originalGet as any)(...args);
  };
  (h.vouchr.vault as any).getAccount = (...args: any[]) => {
    accountReads++;
    return (originalAccount as any)(...args);
  };
  const realFetch = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (url: any) => {
    calls.push(String(url));
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    await assert.rejects(handle.fetch('https://api.test/x'), (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'authorization');
    await assert.rejects(handle.account(), (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'authorization');
    assert.equal(decryptingReads, 0);
    assert.equal(accountReads, 0, 'stale account() never reads even non-secret connection metadata');
    assert.equal(calls.length, 0);

    // The stale attempt did not consume the one-token burst. Once governance permits this exact
    // generation again, the same handle gets its first and only budget token and succeeds.
    await setMode('per-user');
    assert.equal((await handle.fetch('https://api.test/x')).status, 200);
    assert.equal(calls.length, 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('retained shared handle cannot survive a channel mode change', async (t) => {
  const h = await sessionHarness(t);
  const sharedModeIssuance = await h.vouchr.vault.userProvisioningIssuedAt();
  await setChannelCredentialMode({
    vault: h.vouchr.vault,
    audit: h.vouchr.audit,
    channelConfig: new ChannelConfig(h.db),
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: 'shared',
    issuance: sharedModeIssuance,
  });
  const sharedContext = await h.freshContext();
  await sharedContext.setChannelSecret('gh', 'shared-secret');
  const handle = await sharedContext.connect('gh');
  const perUserModeIssuance = await h.vouchr.vault.userProvisioningIssuedAt();
  await setChannelCredentialMode({
    vault: h.vouchr.vault,
    audit: h.vouchr.audit,
    channelConfig: new ChannelConfig(h.db),
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: 'per-user',
    issuance: perUserModeIssuance,
  });
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    await assert.rejects(handle.fetch('https://api.test/x'), (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'authorization');
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('retained shared handle cannot survive actor offboarding, while a fresh actor can reuse the channel credential', async (t) => {
  const h = await sessionHarness(t);
  await setChannelCredentialMode({
    vault: h.vouchr.vault,
    audit: h.vouchr.audit,
    channelConfig: new ChannelConfig(h.db),
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: 'shared',
    issuance: await h.vouchr.vault.userProvisioningIssuedAt(),
  });
  const context = await h.freshContext();
  await context.setChannelSecret('gh', 'shared-secret');
  const handle = await context.connect('gh');
  const owner = channelOwner('T1', 'C1');
  const sharedId = await h.vouchr.vault.liveId(owner, 'gh');
  assert.ok(sharedId);

  await h.vouchr.offboard(ID);
  assert.equal(
    await h.vouchr.vault.liveId(owner, 'gh'),
    sharedId,
    'offboarding preserves the channel-owned credential for other actors',
  );
  const initialInjects = (await h.db.all<any>(`SELECT 1 FROM audit WHERE action='inject'`)).length;
  const originalGet = h.vouchr.vault.get.bind(h.vouchr.vault);
  let credentialReads = 0;
  (h.vouchr.vault as any).get = (...args: any[]) => {
    credentialReads++;
    return (originalGet as any)(...args);
  };
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    await assert.rejects(handle.fetch('https://api.test/x'), (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'authorization');
    assert.equal(credentialReads, 0, 'the stale actor is refused before decrypting the shared row');
    assert.equal(calls, 0);
    assert.equal(
      (await h.db.all<any>(`SELECT 1 FROM audit WHERE action='inject'`)).length,
      initialInjects,
    );

    await new Promise((resolve) => setTimeout(resolve, 2));
    const reonboarded = await h.freshContext();
    const freshHandle = await reonboarded.connect('gh');
    const response = await freshHandle.fetch('https://api.test/x');
    assert.equal(response.status, 200);
    await response.text();
    assert.equal(calls, 1, 'a post-tombstone receipt can use the surviving shared credential');
  } finally {
    h.vouchr.vault.get = originalGet;
    globalThis.fetch = realFetch;
  }
});

test('late shared-handle validation blocks egress when offboarding commits during credential work', async (t) => {
  const h = await sessionHarness(t);
  await setChannelCredentialMode({
    vault: h.vouchr.vault,
    audit: h.vouchr.audit,
    channelConfig: new ChannelConfig(h.db),
    identity: ID,
    channel: 'C1',
    providerId: 'gh',
    mode: 'shared',
    issuance: await h.vouchr.vault.userProvisioningIssuedAt(),
  });
  const context = await h.freshContext();
  await context.setChannelSecret('gh', 'shared-secret');
  const handle = await context.connect('gh');
  const originalGet = h.vouchr.vault.get.bind(h.vouchr.vault);
  let reachedCredentialRead!: () => void;
  let releaseCredentialRead!: () => void;
  const atCredentialRead = new Promise<void>((resolve) => { reachedCredentialRead = resolve; });
  const resumeCredentialRead = new Promise<void>((resolve) => { releaseCredentialRead = resolve; });
  (h.vouchr.vault as any).get = async (...args: any[]) => {
    const value = await (originalGet as any)(...args);
    reachedCredentialRead();
    await resumeCredentialRead;
    return value;
  };
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    const pending = handle.fetch('https://api.test/x');
    await atCredentialRead;
    await h.vouchr.offboard(ID);
    releaseCredentialRead();
    await assert.rejects(pending, (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'authorization');
    assert.equal(calls, 0, 'the second use validator runs immediately before provider send');
    assert.ok(await h.vouchr.vault.liveId(channelOwner('T1', 'C1'), 'gh'));
  } finally {
    h.vouchr.vault.get = originalGet;
    globalThis.fetch = realFetch;
  }
});

test('a DM handle is offboard-fenced even when credential cleanup is delayed', async (t) => {
  const { db, vault, make } = await setup(t, 'per-user');
  const owner = userOwner(ID);
  await vault.upsert(owner, 'gh', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const handle = await make(null, null).connect('gh');
  await new Consent(db).markOffboarded(ID);
  assert.ok(await vault.liveId(owner, 'gh'), 'the test deliberately leaves the local row behind');
  const originalGet = vault.get.bind(vault);
  let reads = 0;
  (vault as any).get = (...args: any[]) => {
    reads++;
    return (originalGet as any)(...args);
  };
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    await assert.rejects(handle.fetch('https://api.test/x'), (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'authorization');
    assert.equal(reads, 0);
    assert.equal(calls, 0);
  } finally {
    vault.get = originalGet;
    globalThis.fetch = realFetch;
  }
});

test('late session revalidation blocks egress when a grant expires during credential work', async (t) => {
  const h = await sessionHarness(t);
  const credentialId = await h.vouchr.vault.liveId(userOwner(ID), 'gh');
  assert.ok(credentialId);
  await h.sessions.grant(ID, 'C1', 'TH1', 'gh', 60_000, credentialId);
  const handle = await h.ctx.connect('gh');

  const originalGet = h.vouchr.vault.get.bind(h.vouchr.vault);
  let credentialRead!: () => void;
  let release!: () => void;
  const credentialReadP = new Promise<void>((resolve) => { credentialRead = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  (h.vouchr.vault as any).get = async (...args: any[]) => {
    const value = await (originalGet as any)(...args);
    credentialRead();
    await releaseP;
    return value;
  };
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    const fetching = handle.fetch('https://api.test/x');
    await credentialReadP;
    await h.db.run(`UPDATE session_grant SET expires_at=0 WHERE credential_id=?`, [credentialId]);
    release();
    await assert.rejects(fetching, (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'authorization');
    assert.equal(calls, 0, 'late gate runs immediately before provider send');
  } finally {
    globalThis.fetch = realFetch;
  }
});
