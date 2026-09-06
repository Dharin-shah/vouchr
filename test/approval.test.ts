import { test, type TestContext } from 'node:test';
import { openTestDb, testDbUrl } from './support/pg';
import { listen } from './support/http';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { ErrorCode as SlackErrorCode } from '@slack/web-api';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent, withUserInteractionFence } from '../src/core/consent';
import {
  Approvals,
  approvalDeliveryAudienceKey,
  approvalOwnerStillCurrent,
  ApprovalPathTooLongError,
  ApprovalRequiredError,
  MAX_APPROVAL_PATH_BYTES,
  queryDigest,
  type ApprovalKey,
} from '../src/core/approval';
import {
  approvalActionKey,
  InteractionStateChangedError,
  POSTGRES_NOW_US_SQL,
  PROMPT_DELIVERY_LEASE_US,
  PROMPT_REDELIVERY_DEBOUNCE_US,
  usFromMs,
} from '../src/core/interaction';
import { approvalNeeded, ConnectionHandle, EgressBlockedError } from '../src/core/injector';
import { defineProvider, github, ProviderRegistry, type Provider } from '../src/core/providers';
import { ChannelConfig, writeChannelMode } from '../src/core/channelConfig';
import { setChannelCredentialMode } from '../src/core/channelCredential';
import { ChannelTools, configureChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { userOwner, channelOwner } from '../src/core/owner';
import { sweepExpired } from '../src/core/sweep';
import {
  APPROVAL_DELIVERY_SAFETY_MARGIN_MS,
  APPROVAL_PROMPT_POST_DEADLINE_MS,
  ConnectContext,
  createVouchr,
  safeUserMessage,
  SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS,
  UserFacingError,
} from '../src/adapters/bolt';
import { APPROVAL_APPROVE_ACTION, APPROVAL_DENY_ACTION, OAUTH_CONNECT_ACTION } from '../src/adapters/blocks';
import { createBroker } from '../src/adapters/http/broker';
import { identityConfig, signIdentity } from './support/identity';
import {
  DB_CONNECTION_TIMEOUT_MS,
  DB_RUNTIME_QUERY_TIMEOUT_MS,
  DB_RUNTIME_STATEMENT_TIMEOUT_MS,
  openDb,
  type Db,
} from '../src/core/db';
import { Policy } from '../src/core/policy';
import { SessionGrants } from '../src/core/session';
import { mapSafeError, type VouchrRecovery } from '../src/core/errors';
import { BROKER_REQUIRED } from './support/slackOidc';

// #113 human-in-the-loop approval for sensitive writes: the full state machine (prompt → approve →
// consume → re-prompt; deny; TTL expiry; the double-consume race), gate ordering (egress beats
// approval), the member/self approver matrices with forged clicks, the broker's 403 shape, the sweep,
// and the no-knob zero-change guarantee. No network: outbound fetch is stubbed (restored in
// finally), Slack is a fake client, and the SQL runs on a throwaway PostgreSQL schema.

const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const BODY_SENTINEL = 'SECRET_BODY_PAYLOAD_never_rendered';
const TOKEN = 'tok_live_secret_value';
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

const approvalProvider = (over: Partial<Provider> = {}): Provider => defineProvider({
  id: 'acme', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.acme.test'], egressMethods: ['GET', 'POST'],
  approval: { approver: 'self' },
  refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  ...over,
});

/** Stub global fetch (TEST-3), recording outbound calls; ALWAYS restored in finally. */
async function withFetch<T>(fn: (calls: { url: string; init?: RequestInit }[]) => Promise<T>): Promise<T> {
  const real = globalThis.fetch;
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = (async (url: any, init?: any) => {
    calls.push({ url: String(url), init });
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = real;
  }
}

/** Fake clock: run `fn` with Date.now() shifted forward by `ms`; ALWAYS restored in finally. */
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

/** Capture the typed rejection from a fetch that must prompt. */
async function expectApprovalRequired(p: Promise<unknown>): Promise<ApprovalRequiredError> {
  try {
    await p;
  } catch (e) {
    assert.ok(e instanceof ApprovalRequiredError, `expected ApprovalRequiredError, got ${(e as Error)?.name}`);
    return e;
  }
  throw new Error('expected the fetch to throw ApprovalRequiredError');
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

/**
 * Integration harness through the PUBLIC API (TEST-2): a real createVouchr, its real middleware
 * building context.vouchr, and the real registered Approve/Deny action handlers — Slack faked.
 */
async function harness(t: TestContext, o: {
  provider?: Provider;
  members?: string[];
  sharedChannel?: boolean;
  channel?: string | null;
  thread?: string | null;
  postEphemeral?: (payload: any) => Promise<unknown>;
  postMessage?: (payload: any) => Promise<unknown>;
  db?: Db;
  onSlackRead?: () => void | Promise<void>;
  masterKey?: Buffer;
  /** Extra conversations.info fields (e.g. `is_ext_shared`); read at call time so a test can flip them. */
  channelInfo?: Record<string, unknown>;
} = {}) {
  process.env.VOUCHR_MASTER_KEY = (o.masterKey ?? randomBytes(32)).toString('base64');
  const provider = o.provider ?? approvalProvider();
  const vouchr = await createVouchr({
    providers: [provider],
    baseUrl: 'http://127.0.0.1:1',
    db: o.db ?? await openTestDb(t),
  });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, h: any) => (actions[id] = h),
  });
  const ephemerals: any[] = [];
  const dms: any[] = [];
  const updates: any[] = [];
  const members = o.members ?? ['U1'];
  const client = {
    conversations: {
      info: async ({ channel }: any) => {
        await o.onSlackRead?.();
        return { channel: { id: channel, is_channel: true, creator: 'U_CREATOR', ...o.channelInfo } };
      },
      members: async () => { await o.onSlackRead?.(); return { members }; },
    },
    chat: {
      postEphemeral: async (p: any) => {
        ephemerals.push(p);
        return o.postEphemeral ? o.postEphemeral(p) : {};
      },
      postMessage: async (p: any) => {
        dms.push(p);
        return o.postMessage ? o.postMessage(p) : {};
      },
      update: async (p: any) => { updates.push(p); return {}; },
    },
  } as any;
  const channel = o.channel === undefined ? 'C1' : o.channel;
  const thread = o.thread === undefined ? 'TH1' : o.thread;
  // The real middleware builds context.vouchr from a fake, already-verified Slack event.
  const args: any = {
    context: {},
    client,
    event: {
      user: 'U1',
      team: 'T1',
      ...(channel ? { channel } : {}),
      ...(thread ? { thread_ts: thread } : {}),
    },
    next: async () => {},
  };
  await vouchr.middleware(args);
  const ctx = args.context.vouchr;
  // Deny-by-default: a channel enables no provider until a member opts it in. Mirror that setup so
  // these tests exercise the approval/egress flow rather than tripping the tool gate first.
  if (channel) await setChannelToolEnabled(new ChannelTools(vouchr.db), 'T1', channel, provider.id, true);
  if (o.sharedChannel) {
    // shared: the CHANNEL owns the credential (owner_kind=channel/owner_id=C1); the caller borrows it.
    await writeChannelMode(new ChannelConfig(vouchr.db), 'T1', 'C1', provider.id, 'shared');
    await vouchr.vault.upsert(channelOwner('T1', 'C1'), provider.id, {
      accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  } else {
    await vouchr.vault.upsert(userOwner(ID), provider.id, {
      accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  const click = (
    actionId: string,
    clicker: string,
    value: string,
    responds: any[] = [],
    ack: () => Promise<void> = async () => {},
    /** The Slack-signed conversation the click arrives from (defaults to the request's). */
    location: { channel: string; thread?: string } = { channel: 'C1', thread: 'TH1' },
  ) =>
    actions[actionId]({
      ack,
      body: {
        team: { id: 'T1' },
        user: { id: clicker },
        channel: { id: location.channel },
        container: { channel_id: location.channel, ...(location.thread ? { thread_ts: location.thread } : {}) },
        actions: [{ value }],
      },
      client,
      respond: async (m: any) => { responds.push(m); },
    });
  const auditRows = async () =>
    (await vouchr.db.all(`SELECT action, user_id, actor, meta FROM audit ORDER BY at`)) as any[];
  const approvalRows = async () =>
    (await vouchr.db.all(`SELECT * FROM approval_request`)) as any[];
  return { vouchr, ctx, ephemerals, dms, updates, click, auditRows, approvalRows, provider, members, client };
}

// The OAuth "Connect" button is a url button, but Slack still delivers a block_actions interaction for
// it — the host MUST register a no-op ack() or the client shows "Operation timed out. Apps need to
// respond within 3 seconds." Prove the registered handler acknowledges the click.
test('the OAuth Connect url-button action is acknowledged (no 3s timeout) (#6/#7)', async (t) => {
  const { click } = await harness(t);
  let acked = false;
  await click(OAUTH_CONNECT_ACTION, 'U1', '', [], async () => { acked = true; });
  assert.equal(acked, true, 'the registered OAUTH_CONNECT_ACTION handler must call ack()');
});

// ── predicate ─────────────────────────────────────────────────────────────────────────────────────

test('approvalNeeded: default is every non-read method; explicit methods/paths narrow it', () => {
  const base = { approver: 'self' as const };
  for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) assert.equal(approvalNeeded(base, m, '/x'), true);
  assert.equal(approvalNeeded(base, 'GET', '/x'), false);
  assert.equal(approvalNeeded(base, 'HEAD', '/x'), false);
  // Explicit methods replace the default (case-insensitive), and GET can be opted IN.
  assert.equal(approvalNeeded({ ...base, methods: ['get'] }, 'GET', '/x'), true);
  assert.equal(approvalNeeded({ ...base, methods: ['DELETE'] }, 'POST', '/x'), false);
  // Paths use the same matcher semantics as egressPaths: exact segment or subpath, '/' = all.
  assert.equal(approvalNeeded({ ...base, paths: ['/repos'] }, 'POST', '/repos/r/issues'), true);
  assert.equal(approvalNeeded({ ...base, paths: ['/repos'] }, 'POST', '/user'), false);
});

test('defineProvider: garbage approval knobs are rejected at definition time (SEC-4)', () => {
  const spec = (approval: any) => () => approvalProvider({ approval });
  assert.throws(spec({ approver: 'anyone' }), /approval\.approver/);
  assert.throws(spec({}), /approval\.approver/);
  assert.throws(spec({ approver: 'self', methods: [] }), /approval\.methods/);
  assert.throws(spec({ approver: 'self', paths: [] }), /approval\.paths/);
  assert.throws(spec({ approver: 'self', ttlMs: 0 }), /approval\.ttlMs/);
  assert.throws(spec({ approver: 'self', ttlMs: Number.NaN }), /approval\.ttlMs/);
});

test('defineProvider: non-canonical approval paths/methods are rejected; methods normalize (P2-D fail-open guard)', () => {
  const spec = (approval: any) => () => approvalProvider({ approval });
  // These are non-empty but never match url.pathname / the upper-cased method, so before this guard
  // they'd DISABLE approval silently. Reject them (fail closed).
  assert.throws(spec({ approver: 'self', paths: ['repos'] }), /approval\.paths/); // no leading slash
  assert.throws(spec({ approver: 'self', paths: [' /repos'] }), /approval\.paths/); // leading space
  assert.throws(spec({ approver: 'self', paths: ['/pay ments'] }), /approval\.paths/); // re-encoded on parse
  assert.throws(spec({ approver: 'self', methods: ['PO ST'] }), /approval\.methods/); // internal space
  assert.throws(spec({ approver: 'self', methods: ['POST\n'] }), /approval\.methods/); // control character
  assert.throws(spec({ approver: 'self', methods: ['POſT'] }), /approval\.methods/); // Unicode lookalike
  for (const method of ['CONNECT', 'TRACE', 'TRACK']) {
    assert.throws(spec({ approver: 'self', methods: [method] }), /approval\.methods/);
  }
  // A trailing-space / lowercase method is CANONICALIZABLE → normalized (trim + upper) so it actually
  // matches, instead of silently disabling approval.
  const p = approvalProvider({ approval: { approver: 'self', methods: ['post ', 'Delete'] } });
  assert.deepEqual(p.approval!.methods, ['POST', 'DELETE']);
  assert.equal(approvalNeeded(p.approval!, 'POST', '/x'), true);
  assert.equal(approvalNeeded(p.approval!, 'DELETE', '/x'), true);
});

test('P2-C: the approval knob threads through built-in provider configs (github) and enforces', async (t) => {
  const gh = github({ clientId: 'c', clientSecret: 's', approval: { approver: 'self' } });
  assert.deepEqual(gh.approval, { approver: 'self' }, 'ProviderConfig → egressOptions → defineProvider');
  const { ctx } = await harness(t, { provider: gh });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('github');
    await handle.fetch('https://api.github.com/user'); // GET: no approval
    assert.equal(calls.length, 1);
    await expectApprovalRequired(handle.fetch('https://api.github.com/user/repos', { method: 'POST' }));
    assert.equal(calls.length, 1, 'the write was gated, not sent');
  });
});

test('Bolt retained-use and approval-request validation preserves injected governance stores', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const audit = new Audit(db);
  const provider = approvalProvider();
  class MutableTools extends ChannelTools {
    enabled = true;
    verdicts: boolean[] = [];
    override async isEnabled(
      _teamId: string,
      _channel: string,
      _provider: string,
      _db?: Db,
    ): Promise<boolean> {
      return this.verdicts.length ? this.verdicts.shift()! : this.enabled;
    }
  }
  class MutableConfig extends ChannelConfig {
    mode: 'shared' | 'per-user' | 'session' | null = null;
    override async getMode(
      _teamId: string,
      _channel: string,
      _provider: string,
      _db?: Db,
    ): Promise<'shared' | 'per-user' | 'session' | null> {
      return this.mode;
    }
  }
  const tools = new MutableTools(db);
  const config = new MutableConfig(db);
  const ephemerals: unknown[] = [];
  const ctx = new ConnectContext({
    identity: ID,
    channel: 'C1',
    client: { chat: { postEphemeral: async (payload: unknown) => { ephemerals.push(payload); return {}; } } } as any,
    registry: new ProviderRegistry([provider]),
    vault,
    audit,
    consent: new Consent(db),
    policy: new Policy(),
    redirectUri: 'http://x',
    channelConfig: config,
    channelTools: tools,
    approvals: new Approvals(db),
    thread: 'TH1',
  });
  await vault.upsert(userOwner(ID), provider.id, {
    accessToken: TOKEN,
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: null,
  });
  const handle = await ctx.connect(provider.id);

  await withFetch(async (calls) => {
    tools.enabled = false;
    await assert.rejects(
      handle.fetch('https://api.acme.test/user'),
      (error: unknown) => error instanceof InteractionStateChangedError && error.reason === 'authorization',
    );

    tools.enabled = true;
    config.mode = 'shared';
    await assert.rejects(
      handle.fetch('https://api.acme.test/user'),
      (error: unknown) => error instanceof InteractionStateChangedError && error.reason === 'authorization',
    );

    // The retained-use check sees allow, then the request validator sees the custom store's
    // post-resolution deny. Falling back to a raw PostgreSQL ChannelTools here would mint a prompt.
    config.mode = null;
    tools.verdicts = [true, false];
    await assert.rejects(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      (error: unknown) => error instanceof InteractionStateChangedError && error.reason === 'authorization',
    );
    assert.equal((await db.all(`SELECT 1 FROM approval_request`)).length, 0);
    assert.equal(ephemerals.length, 0);
    assert.equal(calls.length, 0);
  });
});

test('Bolt omitted governance stores ignore ambient rows in retained and approval validation', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const audit = new Audit(db);
  const provider = approvalProvider();
  await setChannelToolEnabled(new ChannelTools(db), ID.teamId, 'C1', provider.id, false);
  await writeChannelMode(new ChannelConfig(db), ID.teamId, 'C1', provider.id, 'shared');
  await vault.upsert(userOwner(ID), provider.id, {
    accessToken: TOKEN,
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: null,
  });
  const ephemerals: unknown[] = [];
  const ctx = new ConnectContext({
    identity: ID,
    channel: 'C1',
    client: { chat: { postEphemeral: async (payload: unknown) => { ephemerals.push(payload); return {}; } } } as any,
    registry: new ProviderRegistry([provider]),
    vault,
    audit,
    consent: new Consent(db),
    policy: new Policy(),
    redirectUri: 'http://x',
    approvals: new Approvals(db),
    thread: 'TH1',
    // Deliberately omit channelTools/channelConfig: historical Bolt-host semantics stay opted out.
  });
  const handle = await ctx.connect(provider.id);
  await withFetch(async (calls) => {
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0);
  });
  assert.equal((await db.all(`SELECT 1 FROM approval_request`)).length, 1);
  assert.equal(ephemerals.length, 1);
});

// #2: an approval PERSISTS the mutable-governance scope of its channel at request time, so the DECISION
// revalidation (which has no Slack channel_type) classifies a group DM correctly. A personal-conversation
// scope (null) stays valid even with no channel enable; a governed channel with no enable is invalidated.
test('#2: a persisted governance scope drives approval revalidation (group DM stays valid; governed-no-enable invalidated)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const provider = approvalProvider();
  const registry = new ProviderRegistry([provider]);
  const channelTools = new ChannelTools(db); // deny-by-default active
  const channelConfig = new ChannelConfig(db);
  await vault.upsert(userOwner(ID), provider.id, { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const credentialId = (await vault.liveId(userOwner(ID), provider.id))!;
  const approvals = new Approvals(db);
  const key = (channel: string, thread: string, governableChannel: string | null): ApprovalKey => ({
    teamId: ID.teamId, userId: ID.userId, ownerKind: 'user', ownerId: ID.userId, credentialId,
    provider: provider.id, method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test',
    path: '/repos', queryHash: '', channel, thread, governableChannel,
  });
  const revalidate = async (k: ApprovalKey): Promise<boolean> => approvalOwnerStillCurrent({
    row: k, db, registry, policy: new Policy(), vault, actorIssuedAt: await vault.userProvisioningIssuedAt(), channelTools, channelConfig,
  });
  const stored = async (id: string): Promise<string> =>
    (await db.get(`SELECT governable_channel FROM approval_request WHERE id=?`, [id]) as any).governable_channel;

  // A group DM: governance scope persists as the explicit empty-string personal encoding. Even with NO channel enable, the
  // decision revalidation stays valid — deny-by-default never reaches a personal conversation.
  const mpim = key('GROUPDM01', 'TH1', null);
  const mpimId = await approvals.request(mpim);
  assert.equal(await stored(mpimId), '', 'the personal governance scope has a non-ambiguous storage encoding');
  const persistedMpim = await approvals.get(mpimId);
  assert.equal(persistedMpim?.governableChannel, null, 'the public row decodes personal scope to null');
  assert.ok(persistedMpim);
  assert.equal(await revalidate(persistedMpim), true, 'the persisted group-DM approval is not invalidated by deny-by-default');

  // The same action cannot silently reuse a row under a different signed channel classification.
  await assert.rejects(
    approvals.request({ ...mpim, governableChannel: 'GROUPDM01' }),
    /could not be recorded/,
  );
  await assert.rejects(
    approvals.request({ ...mpim, governableChannel: 'C_OTHER' }),
    /invalid governance scope/,
  );
  await db.run(`UPDATE approval_request SET expires_at=0 WHERE id=?`, [mpimId]);
  const reclassifiedId = await approvals.request({ ...mpim, governableChannel: 'GROUPDM01' });
  assert.notEqual(reclassifiedId, mpimId);
  assert.equal(await stored(reclassifiedId), 'GROUPDM01', 'an expired row can be safely replaced under current classification');

  // A governed channel with no enable: scope persisted as the channel → deny-by-default invalidates it.
  const gov = key('C_GOV', 'TH2', 'C_GOV');
  const govId = await approvals.request(gov);
  assert.equal(await stored(govId), 'C_GOV', 'the governed-channel scope round-trips through storage');
  assert.equal(await revalidate(gov), false, 'a governed, un-enabled channel invalidates the approval');
});

// ── the full state machine, through the public Bolt API ──────────────────────────────────────────

test('state machine: prompt → approve → consume exactly once → re-prompt', async (t) => {
  const { ctx, ephemerals, click, auditRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');

    // A read passes with no gate (default predicate = non-GET/HEAD only).
    await handle.fetch('https://api.acme.test/user');
    assert.equal(calls.length, 1);

    // A write with no grant: NOTHING reaches the wire, a prompt is posted, the typed error throws.
    const e = await expectApprovalRequired(
      handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL }),
    );
    assert.equal(calls.length, 1, 'the unapproved write never hit the network');
    assert.equal(e.approver, 'self');
    assert.ok(e.approvalId);
    assert.equal(ephemerals.length, 1);
    assert.equal(ephemerals[0].user, 'U1'); // 'self': the acting user gets the prompt
    assert.equal(ephemerals[0].thread_ts, 'TH1');
    const rendered = JSON.stringify(ephemerals[0].blocks);
    assert.match(rendered, /POST/);
    assert.match(rendered, /api\.acme\.test/);
    assert.match(rendered, /Action fingerprint: hmac-sha256:[0-9a-f]{64}/);
    assert.ok(!rendered.includes('/repos'));
    assert.match(ephemerals[0].text, /POST/);
    assert.match(ephemerals[0].text, /api\.acme\.test/);
    assert.ok(!ephemerals[0].text.includes('/repos'));
    assert.match(ephemerals[0].text, /once/);
    assert.match(
      ephemerals[0].text,
      /raw path and request body are not displayed or inspected/i,
    );
    // SEC-1: prompt shows method + host + salted fingerprint, never raw path/body/token.
    assert.ok(!rendered.includes(BODY_SENTINEL));
    assert.ok(!rendered.includes(TOKEN));
    assert.ok(!ephemerals[0].text.includes(BODY_SENTINEL));
    assert.ok(!ephemerals[0].text.includes(TOKEN));

    // Approve (self = the requester), then the retried fetch consumes the grant and executes.
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 2, 'the approved retry executed exactly once');

    // Single-use: the SAME identical fetch immediately re-prompts (no second free pass).
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL }));
    assert.equal(calls.length, 2);

    // Audit trail: requested → approved → consumed, approver in the actor column (STR-4), and
    // meta carries method+host+salted action fingerprint — never raw path/body/token/query (SEC-1).
    const rows = await auditRows();
    const actions = rows.map((r) => r.action);
    assert.ok(actions.includes('approval_requested'));
    assert.ok(actions.includes('approved'));
    assert.ok(actions.includes('approval_consumed'));
    const approved = rows.find((r) => r.action === 'approved');
    assert.equal(approved.user_id, 'U1'); // the requester owns the row
    assert.equal(approved.actor, 'U1'); // the approver rides the actor column
    const consumed = rows.find((r) => r.action === 'approval_consumed');
    assert.equal(consumed.actor, 'U1');
    const consumedMeta = JSON.parse(consumed.meta);
    assert.equal(consumedMeta.host, 'api.acme.test');
    assert.equal(consumedMeta.method, 'POST');
    assert.equal(consumedMeta.channel, 'C1');
    assert.match(consumedMeta.actionFingerprint, /^hmac-sha256:[0-9a-f]{64}$/);
    assert.equal('path' in consumedMeta, false);
    assert.ok(!JSON.stringify(rows).includes(BODY_SENTINEL), 'no body bytes in audit');
    assert.ok(!JSON.stringify(rows).includes(TOKEN), 'no token in audit');
  });
});

test('an aged durable self-approval DM remains deduplicated', async (t) => {
  const { vouchr, ctx, ephemerals, dms } = await harness(t, {
    channel: null,
    thread: null,
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const first = await expectApprovalRequired(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    );
    assert.equal(ephemerals.length, 0);
    assert.equal(dms.length, 1);

    await vouchr.db.run(
      `UPDATE approval_request SET delivered_at=${POSTGRES_NOW_US_SQL}-? WHERE id=?`,
      [PROMPT_REDELIVERY_DEBOUNCE_US + 1_000, first.approvalId],
    );
    await expectApprovalRequired(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    );
    assert.equal(dms.length, 1, 'a persistent approval DM is not posted again');
    assert.equal(calls.length, 0, 'the unapproved action never reaches the provider');
  });
});

test('exact matching: a grant never covers a different method, path, or query', async (t) => {
  // PUT is egress-allowed here so the mismatch reaches the APPROVAL gate (not the egress one).
  const { ctx, click } = await harness(t, { provider: approvalProvider({ egressMethods: ['GET', 'POST', 'PUT'] }) });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    // Approved POST /repos does NOT authorize POST /repos/evil (exact path, not a prefix)…
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos/evil', { method: 'POST' }));
    // …nor PUT /repos (exact method)…
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'PUT' }));
    // …nor POST /repos?x=1 (GHSA-pg84: added query parameters are a DIFFERENT action).
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos?x=1', { method: 'POST' }));
    assert.equal(calls.length, 0, 'nothing reached the wire');
    // The original approved tuple still works (the grant was not burned by the mismatches).
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    assert.equal(res.status, 200);
  });
});

test('exact matching binds scheme and effective port while audit host stays hostname-only', async (t) => {
  const { ctx, click, auditRows } = await harness(t, {
    provider: approvalProvider({ egressAllow: ['127.0.0.1'] }),
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const first = await expectApprovalRequired(
      handle.fetch('http://127.0.0.1:3001/pay', { method: 'POST' }),
    );
    await click(APPROVAL_APPROVE_ACTION, 'U1', first.approvalId);

    const otherPort = await expectApprovalRequired(
      handle.fetch('http://127.0.0.1:3002/pay', { method: 'POST' }),
    );
    assert.notEqual(otherPort.approvalId, first.approvalId);
    assert.notEqual(otherPort.actionFingerprint, first.actionFingerprint);
    assert.equal(calls.length, 0, 'the different origin cannot consume the port-3001 grant');

    assert.equal(
      (await handle.fetch('http://127.0.0.1:3001/pay', { method: 'POST' })).status,
      200,
    );
    assert.equal(calls.length, 1, 'the byte-identical original origin consumes once');
    for (const row of await auditRows()) {
      const meta = JSON.parse(row.meta);
      if (meta.host) assert.equal(meta.host, '127.0.0.1', 'audit host shape remains hostname-only');
      assert.equal('origin' in meta, false);
    }
  });
});

// ── GHSA-pg84: the grant binds the exact (canonical) query parameters ──────────────────────────────

test('queryDigest: byte-exact — ANY textual change (order, duplicates, encoding) is a different action', () => {
  assert.equal(queryDigest(''), '');
  assert.equal(queryDigest('?'), '');
  assert.equal(queryDigest('?a=1&b=2'), queryDigest('?a=1&b=2')); // identical bytes match
  assert.notEqual(queryDigest('?a=1&b=2'), queryDigest('?b=2&a=1')); // reordering re-prompts (fail closed)
  assert.notEqual(queryDigest('?amount=10&amount=1000000'), queryDigest('?amount=1000000&amount=10')); // duplicate order matters upstream
  assert.notEqual(queryDigest('?a=%31'), queryDigest('?a=1')); // different bytes upstream = different action
  assert.notEqual(queryDigest('?a=1'), queryDigest('?a=2')); // changed value
  assert.notEqual(queryDigest('?a=1'), queryDigest('?b=1')); // changed key
  assert.notEqual(queryDigest('?a=1'), queryDigest('?a=1&a=1')); // repeated param is different
  assert.notEqual(queryDigest('?a=1'), ''); // params never collapse to the no-query value
  assert.notEqual(queryDigest('?a=1'), 'pre-v5'); // and can never equal the migration sentinel
});

test('GHSA-pg84: an approval binds the exact query — tampered, reordered, or duplicate-shuffled retries re-prompt', async (t) => {
  const { ctx, click, ephemerals, approvalRows, auditRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const QUERY_SENTINEL = 'alice-PII-payee'; // a query VALUE that must never leave the process
    const e = await expectApprovalRequired(
      handle.fetch(`https://api.acme.test/transfer?to=${QUERY_SENTINEL}&amount=10`, { method: 'POST' }),
    );
    // The human sees only the parameter COUNT (names are as caller-controlled as values, SEC-1)…
    assert.equal(e.queryParamCount, 2);
    const rendered = JSON.stringify(ephemerals[0].blocks);
    assert.match(rendered, /\(2 parameters\)/);
    // …and neither values nor names reach Slack, the error serialization, the store, or audit.
    assert.ok(!rendered.includes(QUERY_SENTINEL), 'no query value in the prompt');
    assert.ok(!rendered.includes('to='), 'no parameter names in the prompt');
    assert.ok(!JSON.stringify({ ...e }).includes(QUERY_SENTINEL), 'no query data on enumerable error properties');
    assert.ok(!JSON.stringify(await approvalRows()).includes(QUERY_SENTINEL), 'no raw query in the approval row');
    assert.ok(!JSON.stringify(await auditRows()).includes(QUERY_SENTINEL), 'no raw query in audit');

    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    // ANY textual change to the query is a different action: re-prompts, grant intact.
    await expectApprovalRequired(
      handle.fetch('https://api.acme.test/transfer?to=attacker&amount=1000000', { method: 'POST' }),
    );
    await expectApprovalRequired( // reordered params — upstream may parse differently, fail closed
      handle.fetch(`https://api.acme.test/transfer?amount=10&to=${QUERY_SENTINEL}`, { method: 'POST' }),
    );
    assert.equal(calls.length, 0, 'no mismatched retry reached the wire');
    // The byte-identical retry consumes the grant exactly once.
    const res = await handle.fetch(`https://api.acme.test/transfer?to=${QUERY_SENTINEL}&amount=10`, { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1, 'the faithful retry executed exactly once');
    assert.ok(!JSON.stringify(await auditRows()).includes(QUERY_SENTINEL), 'consumption audit carries no raw query');
  });
});

test('GHSA-pg84: a secret in a parameter NAME never reaches the prompt or the error serialization', async (t) => {
  const { ctx, ephemerals } = await harness(t);
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const NAME_SENTINEL = 'ghp_name_sentinel_token'; // a query KEY that must never leave the process
    const e = await expectApprovalRequired(
      handle.fetch(`https://api.acme.test/transfer?${NAME_SENTINEL}=1`, { method: 'POST' }),
    );
    assert.equal(e.queryParamCount, 1);
    assert.ok(!JSON.stringify({ ...e }).includes(NAME_SENTINEL), 'no name on enumerable error properties');
    assert.ok(!e.message.includes(NAME_SENTINEL), 'no name in the error message');
    assert.ok(!JSON.stringify(ephemerals[0].blocks).includes(NAME_SENTINEL), 'no name in the Slack prompt');
  });
});

test('GHSA-pg84: duplicate-key reordering cannot spend a grant (first-wins vs last-wins upstreams)', async (t) => {
  const { ctx, click } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(
      handle.fetch('https://api.acme.test/transfer?amount=10&amount=1000000', { method: 'POST' }),
    );
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    // Same multiset of parameters, different order — a first-wins upstream now reads 1000000.
    await expectApprovalRequired(
      handle.fetch('https://api.acme.test/transfer?amount=1000000&amount=10', { method: 'POST' }),
    );
    assert.equal(calls.length, 0);
    const res = await handle.fetch('https://api.acme.test/transfer?amount=10&amount=1000000', { method: 'POST' });
    assert.equal(res.status, 200); // the exact approved bytes still work
  });
});

test('P1-B: an encoded path separator cannot slip past an approval.paths lock (fail closed)', async (t) => {
  // approval.paths WITHOUT an independent egressPaths: `/payments%2Fsend` does not prefix-match
  // `/payments`, but an upstream that decodes %2F routes it as `/payments/send`. Before the guard it
  // needed NO approval and ran; now it REQUIRES approval. Fail-before (executes, no throw) / pass-after.
  const { ctx, approvalRows } = await harness(t, { provider: approvalProvider({ approval: { approver: 'self', paths: ['/payments'] } }) });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    await expectApprovalRequired(handle.fetch('https://api.acme.test/payments%2Fsend', { method: 'POST' }));
    await expectApprovalRequired(handle.fetch('https://api.acme.test/payments/%252e%252e%252fadmin', { method: 'POST' }));
    assert.equal(calls.length, 0, 'the encoded-separator write never reached the wire unconfirmed');
    assert.equal((await approvalRows()).length, 2, 'direct and nested encodings minted approvals instead of bypassing');
    // A path plainly OUTSIDE the lock still needs no approval (the guard didn't over-fire).
    const res = await handle.fetch('https://api.acme.test/orders', { method: 'POST' });
    assert.equal(res.status, 200);
  });
});

// ── P1-A: grants are bound to the credential OWNER (mode change) and to its lifecycle ──

test('P1-A(a): a grant minted for one credential owner cannot be consumed for another (owner change)', async (t) => {
  // Models a mode/owner change between prompt and retry (e.g. per-user → shared): the grant is keyed
  // to owner A, so a consume that resolves to owner B must MISS (the write would otherwise run against
  // a DIFFERENT credential than was approved). Store-level, deterministic. Fail-before: without the
  // owner clause in consume(), the B-owner consume would wrongly succeed.
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const forOwner = (ownerId: string) => ({
    teamId: 'T1', userId: 'U_CALLER', ownerKind: 'user' as const, ownerId,
    credentialId: GENERATION, provider: 'acme', method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '', channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  });
  const id = await approvals.request(forOwner('U_OWNER_A'));
  assert.ok(await approvals.approve(id, 'U_CALLER', 60_000));
  // Resolution switched to owner B → the grant for A does not match.
  assert.equal(await approvals.consume(forOwner('U_OWNER_B')), null);
  // The grant for the ORIGINAL owner A is still spendable exactly once.
  assert.ok(await approvals.consume(forOwner('U_OWNER_A')));
});

test('approval consumption matches governance scope exactly without burning the grant', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const base = {
    teamId: 'T1', userId: 'U_CALLER', ownerKind: 'user' as const, ownerId: 'U_OWNER',
    credentialId: GENERATION, provider: 'acme', method: 'POST',
    origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '',
    channel: 'GROUPDM01', thread: 'TH1',
  };

  // Exercise both directions. A personal-conversation grant cannot authorize the same Slack
  // action after it is classified as governed, and a governed grant cannot be spent after the
  // classification is changed to personal. The mismatched lookup must not burn the real grant.
  for (const [storedScope, wrongScope] of [
    [null, 'GROUPDM01'],
    ['GROUPDM01', null],
  ] as const) {
    const stored = { ...base, governableChannel: storedScope };
    const id = await approvals.request(stored);
    assert.ok(await approvals.approve(id, 'U_APPROVER', 60_000));

    assert.equal(
      await approvals.consume({ ...base, governableChannel: wrongScope }),
      null,
      'a different governance classification must not consume the grant',
    );
    assert.deepEqual(
      await approvals.consume(stored),
      { approvedBy: 'U_APPROVER' },
      'the exact persisted governance classification remains spendable',
    );
    assert.equal(await approvals.consume(stored), null, 'the exact grant remains single-use');
  }
});

test('P1-A(b): reconnect invalidates the old handle and a new generation needs fresh approval', async (t) => {
  // Mint + approve a grant, then disconnect (vault.delete — the shared disconnect/offboard/revoke/
  // expiry primitive) and reconnect (vault.upsert). The old grant must be gone. Fail-before: without
  // the vault-side purge the grant survives the delete and, since the reconnect restores the SAME
  // owner, the retry would consume it and run the write with NO fresh human approval.
  const { ctx, vouchr, click, approvalRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    assert.equal((await approvalRows()).filter((r) => r.status === 'granted').length, 1, 'grant is live before disconnect');

    // Disconnect (delete) then reconnect (upsert) the SAME owner+provider.
    await vouchr.vault.delete(userOwner(ID), 'acme');
    assert.equal((await approvalRows()).length, 0, 'disconnect purged the grant');
    await vouchr.vault.upsert(userOwner(ID), 'acme', { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

    // The old handle is generation-bound and cannot silently adopt the replacement credential.
    await assert.rejects(handle.fetch('https://api.acme.test/repos', { method: 'POST' }), (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'credential');
    const replacement = await ctx.connect('acme');
    await expectApprovalRequired(replacement.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0);
  });
});

test('post-purge stale approval request insert is fenced by the credential-generation lock', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const vaultKey = randomBytes(32);
  const vaultA = new Vault(dbA, vaultKey);
  const vaultB = new Vault(dbB, vaultKey);
  await vaultA.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const oldId = await vaultA.liveId(userOwner(ID), 'acme');
  assert.ok(oldId);
  const key = {
    teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1', credentialId: oldId,
    provider: 'acme', method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '',
    channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  };
  let purged!: () => void;
  let release!: () => void;
  const purgedP = new Promise<void>((resolve) => { purged = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const reconnect = vaultB.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  }, undefined, async () => {
    purged();
    await releaseP;
  });
  await purgedP;
  const staleInsert = new Approvals(dbA).requestAudited(key, new Audit(dbA), ID, vaultA);
  let settled = false;
  void staleInsert.finally(() => { settled = true; }).catch(() => undefined);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(settled, false);
  release();
  await reconnect;
  await assert.rejects(
    staleInsert,
    (error: unknown) => error instanceof InteractionStateChangedError && error.reason === 'credential',
  );
  assert.equal((await dbA.all(`SELECT 1 FROM approval_request`)).length, 0);
});

test('two replicas: a paused DM approval request cannot cross actor offboarding', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const vaultA = new Vault(dbA, randomBytes(32));
  await vaultA.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const credentialId = await vaultA.liveId(userOwner(ID), 'acme');
  assert.ok(credentialId);
  const actorIssuedAt = (await vaultA.userProvisioningIssuedAt()) - 10_000;
  const key = {
    teamId: ID.teamId, userId: ID.userId, ownerKind: 'user' as const, ownerId: ID.userId,
    credentialId, provider: 'acme', method: 'POST', origin: 'https://api.acme.test',
    host: 'api.acme.test', path: '/repos', queryHash: '', channel: null, thread: null,
    governableChannel: null,
  };
  let reached!: () => void;
  let release!: () => void;
  const reachedP = new Promise<void>((resolve) => { reached = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const staleRequest = new Approvals(dbA).requestAudited(
    key,
    new Audit(dbA),
    ID,
    vaultA,
    async (_approval, tx) => {
      reached();
      await releaseP;
      const fenced = await withUserInteractionFence(tx, ID, actorIssuedAt, async () => true);
      return fenced.status === 'current';
    },
  );

  await reachedP;
  try {
    await new Consent(dbB).markOffboarded(ID);
  } finally {
    release();
  }
  await assert.rejects(
    staleRequest,
    (error: unknown) => error instanceof InteractionStateChangedError && error.reason === 'authorization',
  );
  assert.equal(
    (await dbA.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM approval_request`))?.n,
    0,
  );
  assert.equal(
    (await dbA.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM audit WHERE action='approval_requested'`,
    ))?.n,
    0,
  );
});

test('cross-pool reconnect after approval consume cannot make the old handle read replacement credentials', async (t) => {
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
  const masterKey = randomBytes(32);
  const { ctx, click } = await harness(t, { db, masterKey });
  const replacement = new Vault(peer, masterKey);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const pending = await expectApprovalRequired(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    );
    await click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId);
    blockExactRead = true;
    const retry = handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    await reachedP;
    await replacement.upsert(userOwner(ID), 'acme', {
      accessToken: 'replacement-token', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
    release();
    await assert.rejects(retry, (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'credential');
    assert.equal(calls.length, 0, 'neither generation reached the provider');
    blockExactRead = false;
    const fresh = await ctx.connect('acme');
    await expectApprovalRequired(fresh.fetch('https://api.acme.test/repos', { method: 'POST' }));
  });
});

test('cross-pool reconnect before refresh makes the old generation fail without token or API egress', async (t) => {
  const url = await testDbUrl(t);
  const raw = await openDb({ databaseUrl: url });
  const peer = await openDb({ databaseUrl: url });
  t.after(() => raw.close());
  t.after(() => peer.close());
  let announceLock = false;
  let attempted!: () => void;
  const attemptedP = new Promise<void>((resolve) => { attempted = resolve; });
  const db: Db = {
    get: (sql, params) => raw.get(sql, params), all: (sql, params) => raw.all(sql, params),
    run: (sql, params) => raw.run(sql, params), exec: (sql) => raw.exec(sql), close: async () => {},
    transaction: <T>(fn: (tx: Db) => Promise<T>) => raw.transaction!(fn),
    withRefreshLock: <T>(key: string, fn: (tx: Db) => Promise<T>) => {
      if (announceLock) attempted();
      return raw.withRefreshLock!(key, fn);
    },
    withRefreshLocks: <T>(keys: readonly string[], fn: (tx: Db) => Promise<T>) => {
      if (announceLock && keys.includes('T1:user:U1:acme')) attempted();
      return raw.withRefreshLocks!(keys, fn);
    },
  };
  const vaultKey = randomBytes(32);
  const vault = new Vault(db, vaultKey);
  const replacement = new Vault(peer, vaultKey);
  const owner = userOwner(ID);
  await vault.upsert(owner, 'acme', {
    accessToken: TOKEN, refreshToken: 'refresh-old', scopes: '', expiresAt: Date.now() + 1_000, externalAccount: null,
  });
  const provider = approvalProvider({ approval: undefined, refresh: 'rotating' });
  const handle = new ConnectionHandle(provider, owner, ID, vault, new Audit(db));
  let purged!: () => void;
  let release!: () => void;
  const purgedP = new Promise<void>((resolve) => { purged = resolve; });
  const releaseP = new Promise<void>((resolve) => { release = resolve; });
  const reconnect = replacement.upsert(owner, 'acme', {
    accessToken: 'replacement', refreshToken: 'refresh-new', scopes: '', expiresAt: null, externalAccount: null,
  }, undefined, async () => {
    purged();
    await releaseP;
  });
  await purgedP;
  announceLock = true;
  await withFetch(async (calls) => {
    const fetching = handle.fetch('https://api.acme.test/user');
    await attemptedP;
    release();
    await reconnect;
    await assert.rejects(fetching, (error) =>
      error instanceof InteractionStateChangedError && error.reason === 'credential');
    assert.equal(calls.length, 0);
  });
});

test('deny: audited with the approver as actor, requester notified, no grant minted', async (t) => {
  const { ctx, click, auditRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const responds: any[] = [];
    await click(APPROVAL_DENY_ACTION, 'U1', e.approvalId, responds);
    assert.match(responds[0]?.text ?? '', /Denied/);
    // Denied: the retry re-prompts (a fresh request), never executes.
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0);
    const denied = (await auditRows()).find((r) => r.action === 'denied' && r.meta.includes('approval-denied'));
    assert.ok(denied, 'denied audit row written');
    assert.equal(denied.user_id, 'U1'); // attributed to the requester
    assert.equal(denied.actor, 'U1'); // decided by the approver
    const deniedMeta = JSON.parse(denied.meta);
    assert.equal(deniedMeta.host, 'api.acme.test');
    assert.equal(deniedMeta.method, 'POST');
    assert.equal(deniedMeta.channel, 'C1');
    assert.equal(deniedMeta.reason, 'approval-denied');
    assert.match(deniedMeta.actionFingerprint, /^hmac-sha256:[0-9a-f]{64}$/);
    assert.equal('path' in deniedMeta, false);
  });
});

test('TTL expiry: an unspent grant dies by PostgreSQL time and the next fetch re-prompts', async (t) => {
  const { vouchr, ctx, click } = await harness(t, { provider: approvalProvider({ approval: { approver: 'self', ttlMs: 60_000 } }) });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    // Past the grant TTL the retried fetch finds nothing to consume and prompts again.
    await vouchr.db.run(`UPDATE approval_request SET expires_at=0 WHERE status='granted'`);
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0, 'the expired grant never authorized a call');
  });
});

test('race: two concurrent identical fetches cannot both spend one grant (DELETE…RETURNING)', async (t) => {
  const { ctx, click } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    const results = await Promise.allSettled([
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    ]);
    const ok = results.filter((r) => r.status === 'fulfilled');
    const failed = results.filter((r) => r.status === 'rejected') as PromiseRejectedResult[];
    assert.equal(ok.length, 1, 'exactly one retry consumed the grant');
    assert.equal(failed.length, 1);
    assert.ok(failed[0].reason instanceof ApprovalRequiredError, 'the loser re-prompts, never executes');
    assert.equal(calls.length, 1, 'exactly one call reached the wire');
  });
});

test('race: two concurrent store-level consumes yield exactly one winner (consent-consume pattern)', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const key = { teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1', credentialId: GENERATION, provider: 'acme', method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '', channel: 'C1', thread: null, governableChannel: 'C1' };
  const id = await approvals.request(key);
  assert.ok(await approvals.approve(id, 'U9', 60_000));
  const [a, b] = await Promise.all([approvals.consume(key), approvals.consume(key)]);
  assert.equal([a, b].filter((r) => r !== null).length, 1);
  // The winner carries the approver for audit attribution.
  assert.equal((a ?? b)!.approvedBy, 'U9');
});

test('a pre-offboard shared-credential grant cannot revive after actor re-onboarding', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const audit = new Audit(db);
  const key = {
    teamId: 'T1', userId: 'U1', ownerKind: 'channel' as const, ownerId: 'C1',
    credentialId: GENERATION, provider: 'acme', method: 'POST',
    origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '',
    channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  };
  const id = await approvals.request(key);
  assert.ok(await approvals.approve(id, 'U_ADMIN', 60_000));
  await new Consent(db).markOffboarded(ID);

  assert.equal(
    await approvals.consumeAudited(key, audit, ID),
    null,
    'grant creation predates the durable actor tombstone',
  );
  assert.equal(
    (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM approval_request`))?.n,
    0,
    'the stale grant is reclaimed so a fresh request can proceed',
  );
  assert.equal(
    (await db.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM audit WHERE action='approval_consumed'`,
    ))?.n,
    0,
  );
});

test('two replicas: a stale actor receipt cannot consume a fresh post-offboard grant', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const masterKey = randomBytes(32);
  const vaultA = new Vault(dbA, masterKey);
  const vaultB = new Vault(dbB, masterKey);
  const owner = channelOwner(ID.teamId, 'C1');
  await vaultA.upsert(owner, 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const credentialId = await vaultA.liveId(owner, 'acme');
  assert.ok(credentialId);
  const staleIssuedAt = (await vaultA.userProvisioningIssuedAt()) - 10_000;
  await new Consent(dbB).markOffboarded(ID);
  // Keep the ordering deterministic despite PostgreSQL's millisecond timestamps: this marker still
  // follows the stale receipt, while a newly issued request and grant are observably newer.
  await dbB.run(
    `UPDATE offboard_tombstone SET created_at=created_at-? WHERE team_id=? AND user_id=?`,
    [1_000, ID.teamId, ID.userId],
  );
  const marker = await dbB.get<{ created_at: number }>(
    `SELECT created_at FROM offboard_tombstone WHERE team_id=? AND user_id=?`,
    [ID.teamId, ID.userId],
  );
  assert.ok(marker);
  assert.ok(marker.created_at > staleIssuedAt);
  const freshIssuedAt = await vaultB.userProvisioningIssuedAt();
  assert.ok(freshIssuedAt > marker.created_at);
  const key = {
    teamId: ID.teamId, userId: ID.userId, ownerKind: 'channel' as const, ownerId: 'C1',
    credentialId, provider: 'acme', method: 'POST', origin: 'https://api.acme.test',
    host: 'api.acme.test', path: '/repos', queryHash: '', channel: 'C1', thread: 'TH1',
    governableChannel: 'C1',
  };
  const validateAt = (issuedAt: number) => async (_approval: ApprovalKey, tx: Db) => {
    const fenced = await withUserInteractionFence(tx, ID, issuedAt, async () => true);
    return fenced.status === 'current';
  };
  const approvalsB = new Approvals(dbB);
  const fresh = await approvalsB.requestAudited(
    key,
    new Audit(dbB),
    ID,
    vaultB,
    validateAt(freshIssuedAt),
  );
  assert.ok(await approvalsB.approve(fresh.id, 'U_ADMIN', 60_000));
  const granted = await dbB.get<{ status: string; created_at: number }>(
    `SELECT status, created_at FROM approval_request WHERE id=?`,
    [fresh.id],
  );
  assert.equal(granted?.status, 'granted');
  assert.ok(granted!.created_at > marker.created_at, 'the grant itself is newer than the tombstone');

  await assert.rejects(
    new Approvals(dbA).consumeAudited(
      key,
      new Audit(dbA),
      ID,
      vaultA,
      validateAt(staleIssuedAt),
    ),
    (error: unknown) => error instanceof InteractionStateChangedError && error.reason === 'authorization',
  );
  assert.equal(
    (await dbA.get<{ status: string }>(`SELECT status FROM approval_request WHERE id=?`, [fresh.id]))?.status,
    'granted',
    'the stale caller must not burn the legitimate single-use grant',
  );
  assert.equal(
    (await dbA.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM audit WHERE action='approval_consumed'`,
    ))?.n,
    0,
  );
});

test('Approvals rejects missing, malformed, and oversized credential generations at runtime', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const base = {
    teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1',
    credentialId: GENERATION, provider: 'acme', method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test',
    path: '/repos', queryHash: '', channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  };
  for (const credentialId of [undefined, '', ' ', 'not-a-uuid', 'x'.repeat(10_000)]) {
    const invalid = { ...base, credentialId: credentialId as any };
    await assert.rejects(() => approvals.request(invalid), /valid credential generation id/);
    assert.equal(await approvals.consume(invalid), null);
  }
  assert.equal((await db.all(`SELECT 1 FROM approval_request`)).length, 0);
});

test('concurrent decisions: approve and deny on one pending request — exactly one wins', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const key = { teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1', credentialId: GENERATION, provider: 'acme', method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '', channel: null, thread: null, governableChannel: null };
  const id = await approvals.request(key);
  const [approved, denied] = await Promise.all([approvals.approve(id, 'U9', 60_000), approvals.deny(id)]);
  assert.equal([approved !== false && approved !== null, denied !== null].filter(Boolean).length, 1);
});

test('decideAudited rejects malformed decisions and validator results before row or audit mutation', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const audit = new Audit(db);
  const vault = new Vault(db, randomBytes(32));
  const id = await approvals.request({
    teamId: 'T1', userId: 'U1', ownerKind: 'user', ownerId: 'U1',
    credentialId: GENERATION, provider: 'acme', method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test',
    path: '/repos', queryHash: '', channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  });
  const base = {
    id,
    approvedBy: 'U1',
    actor: ID,
    issuance: await vault.userProvisioningIssuedAt(),
    ttlMs: 60_000,
    audit,
  };

  await assert.rejects(
    approvals.decideAudited({ ...base, decision: 'anything' as any, validate: async () => 'valid' }),
    /decision must be approve or deny/,
  );
  for (const validate of [undefined, async () => undefined, async () => true, async () => 'typo']) {
    await assert.rejects(
      approvals.decideAudited({ ...base, decision: 'approve', validate } as any),
      /validator/,
    );
  }
  assert.ok(await approvals.get(id), 'malformed direct calls leave the pending row unchanged');
  assert.equal((await db.all(`SELECT 1 FROM audit`)).length, 0);
});

test('PostgreSQL clock owns approval TTL/lease and expired delivered pending/granted rows reset', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const a = new Approvals(dbA);
  const b = new Approvals(dbB);
  const key = {
    teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1',
    credentialId: GENERATION, provider: 'acme', method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test',
    path: '/repos', queryHash: '', channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  };

  const first = await withClockOffset(60 * 60_000, () => a.request(key));
  const firstRow = await dbA.get<any>(`SELECT * FROM approval_request WHERE id=?`, [first]);
  const dbNow = await dbA.get<{ now_us: number }>(
    `SELECT ${POSTGRES_NOW_US_SQL} AS now_us`,
  );
  assert.ok(Math.abs(firstRow.created_at - dbNow!.now_us) < 5_000_000, 'pod clock never stamps authority TTL');
  const firstAudience = approvalDeliveryAudienceKey(first, 'self', ['U1']);
  const claim = await withClockOffset(60 * 60_000, () => a.claimDelivery(first, firstAudience));
  assert.equal(claim.status, 'claimed');
  assert.equal(
    (await withClockOffset(-60 * 60_000, () => b.claimDelivery(first, firstAudience))).status,
    'in-flight',
  );
  assert.equal(await a.confirmDelivery(first, (claim as any).token, firstAudience), true);

  await dbA.run(`UPDATE approval_request SET expires_at=0 WHERE id=?`, [first]);
  const second = await withClockOffset(-60 * 60_000, () => b.request(key));
  assert.notEqual(second, first);
  let row = await dbA.get<any>(`SELECT * FROM approval_request WHERE id=?`, [second]);
  assert.equal(row.delivered_at, null);
  assert.equal(row.delivery_token, null);
  assert.equal(row.delivery_lease_expires_at, 0);

  const secondAudience = approvalDeliveryAudienceKey(second, 'self', ['U1']);
  const secondClaim = await b.claimDelivery(second, secondAudience);
  assert.equal(secondClaim.status, 'claimed');
  await b.confirmDelivery(second, (secondClaim as any).token, secondAudience);
  await b.approve(second, 'U1', 60_000);
  await dbA.run(`UPDATE approval_request SET expires_at=0 WHERE id=?`, [second]);
  const third = await a.request(key);
  row = await dbA.get<any>(`SELECT * FROM approval_request WHERE id=?`, [third]);
  assert.notEqual(third, second);
  assert.equal(row.status, 'pending');
  assert.equal(row.delivered_at, null);
  assert.equal(row.delivery_token, null);
});

test('approval delivery is reusable only by the same approver class and recipient set', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const id = await approvals.request({
    teamId: 'T1', userId: 'U1', ownerKind: 'user', ownerId: 'U1',
    credentialId: GENERATION, provider: 'acme', method: 'POST',
    origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '',
    channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  });
  const selfAudience = approvalDeliveryAudienceKey(id, 'self', ['U1']);
  const selfClaim = await approvals.claimDelivery(id, selfAudience);
  assert.equal(selfClaim.status, 'claimed');
  assert.equal(
    await approvals.confirmDelivery(id, (selfClaim as { token: string }).token, selfAudience),
    true,
  );
  assert.deepEqual(await approvals.claimDelivery(id, selfAudience), { status: 'delivered' });

  const memberAudience = approvalDeliveryAudienceKey(id, 'member', ['C1']);
  const memberClaim = await approvals.claimDelivery(id, memberAudience);
  assert.equal(memberClaim.status, 'claimed', 'self delivery cannot suppress the new member surface');
  assert.equal(
    await approvals.confirmDelivery(id, (memberClaim as { token: string }).token, memberAudience),
    true,
  );
  assert.deepEqual(await approvals.claimDelivery(id, memberAudience), { status: 'delivered' });
  // The digest is bound to exactly one surface id: no surface, or more than one, is not an audience.
  assert.throws(() => approvalDeliveryAudienceKey(id, 'member', []), /invalid approval delivery audience/);
  assert.throws(() => approvalDeliveryAudienceKey(id, 'member', ['C1', 'C2']), /invalid approval delivery audience/);
  assert.throws(() => approvalDeliveryAudienceKey(id, 'admin' as any, ['U1']), /invalid approval delivery audience/);
});

// ── gate ordering: approval is an ADDITIONAL gate, never a bypass ─────────────────────────────────

test('two replicas: a changing approval audience cannot replace an active delivery lease', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const firstReplica = new Approvals(dbA);
  const secondReplica = new Approvals(dbB);
  const id = await firstReplica.request({
    teamId: 'T1', userId: 'U1', ownerKind: 'user', ownerId: 'U1',
    credentialId: GENERATION, provider: 'acme', method: 'POST',
    origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '',
    channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  });
  const oldAudience = approvalDeliveryAudienceKey(id, 'self', ['U1']);
  const newAudience = approvalDeliveryAudienceKey(id, 'member', ['C1']);

  const held = await firstReplica.claimDelivery(id, oldAudience);
  assert.equal(held.status, 'claimed');
  assert.deepEqual(
    await secondReplica.claimDelivery(id, newAudience),
    { status: 'in-flight' },
    'a rule change must not invalidate a post already in progress on another replica',
  );
  assert.equal(
    await firstReplica.confirmDelivery(id, (held as { token: string }).token, oldAudience),
    true,
    'the first replica retains authority to confirm its Slack delivery',
  );

  const replacement = await secondReplica.claimDelivery(id, newAudience);
  assert.equal(replacement.status, 'claimed', 'the changed audience can post after the first lease settles');
  assert.equal(
    await secondReplica.confirmDelivery(id, (replacement as { token: string }).token, newAudience),
    true,
  );
});

test('ordering: an egress-denied target throws EgressBlockedError and never mints a prompt', async (t) => {
  const { ctx, vouchr, ephemerals, auditRows, approvalRows } = await harness(t);
  // Count credential reads across the refused requests. The sibling test above pins this for
  // *malformed* methods; a well-formed method the provider simply never declared is the case a
  // model actually produces, and examples/multi-provider-agent leans on it — the model picks the
  // URL and the method, so the gate has to be what stops it, not the tool schema.
  //
  // Note the baseline: connect() itself reads once (existence check), so the property is that a
  // refused request adds NO read — not that no read has ever happened. Asserting 0 total would be
  // asserting something untrue about connect().
  const realGet = vouchr.vault.get.bind(vouchr.vault);
  let credentialReads = 0;
  (vouchr.vault as unknown as { get: unknown }).get = (...args: unknown[]) => {
    credentialReads += 1;
    return (realGet as (...a: unknown[]) => unknown)(...args);
  };
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const afterConnect = credentialReads;
    // Host off the allowlist: egress wins.
    await assert.rejects(() => handle.fetch('https://evil.test/x', { method: 'POST' }), EgressBlockedError);
    // Method off egressMethods (GET/POST): egress wins over the approval predicate too.
    await assert.rejects(() => handle.fetch('https://api.acme.test/x', { method: 'DELETE' }), EgressBlockedError);
    // PATCH: well-formed, plausible, undeclared here — the shape a model emits unprompted.
    await assert.rejects(() => handle.fetch('https://api.acme.test/x', { method: 'PATCH' }), EgressBlockedError);
    assert.equal(calls.length, 0);
    assert.equal(
      credentialReads, afterConnect,
      'an egress-denied request must be refused without reading the credential',
    );
    assert.equal(ephemerals.length, 0, 'no approval prompt for an egress-denied request');
    assert.equal((await approvalRows()).length, 0, 'no pending approval row minted');
    assert.ok(!(await auditRows()).some((r) => r.action === 'approval_requested'));
  });
});

test('ordering: invalid request methods reach no approval, audit, Slack, credential, or provider state', async (t) => {
  const { ctx, vouchr, ephemerals, dms, auditRows, approvalRows } = await harness(t);
  const handle = await ctx.connect('acme');
  const initialAuditCount = (await auditRows()).length;
  const realGet = vouchr.vault.get.bind(vouchr.vault);
  let credentialReads = 0;
  (vouchr.vault as any).get = (...args: any[]) => {
    credentialReads += 1;
    return (realGet as any)(...args);
  };

  await withFetch(async (calls) => {
    for (const method of ['', ' ', 'PO ST', 'POST\n', '\tGET', 'GE\u007fT', 'POſT', 'CONNECT', 'TRACE', 'TRACK']) {
      await assert.rejects(
        handle.fetch('https://api.acme.test/repos', { method }),
        (error: unknown) => error instanceof TypeError && error.message === 'Invalid HTTP method.',
      );
    }
    assert.equal(calls.length, 0, 'invalid methods never reach the provider');
  });

  assert.equal(credentialReads, 0, 'invalid methods never read the credential');
  assert.equal((await approvalRows()).length, 0, 'invalid methods never persist approval state');
  assert.equal((await auditRows()).length, initialAuditCount, 'invalid methods never append audit rows');
  assert.equal(ephemerals.length, 0, 'invalid methods never render an ephemeral prompt');
  assert.equal(dms.length, 0, 'invalid methods never render a DM prompt');
});

// ── approver matrices ─────────────────────────────────────────────────────────────────────────────

test('member approver (#322): one channel message; the requester and a non-member are refused and audited; another member approves and the action runs once with the requester\'s credential', async (t) => {
  const { vouchr, ctx, ephemerals, dms, click, auditRows, approvalRows } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_MEMBER'],
  });
  // The approving colleague has their own credential too: the grant must still spend the REQUESTER's.
  await vouchr.vault.upsert(userOwner({ ...ID, userId: 'U_MEMBER' }), 'acme', {
    accessToken: 'tok_member_never_used', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL }));
    assert.equal(e.approver, 'member');
    // One regular message in the owning channel, in the originating thread — not an ephemeral.
    assert.equal(ephemerals.length, 0);
    assert.equal(dms.length, 1);
    assert.equal(dms[0].channel, 'C1');
    assert.equal(dms[0].thread_ts, 'TH1');
    assert.equal(dms[0].user, undefined);
    const rendered = JSON.stringify(dms[0]);
    assert.match(rendered, /Another member of this channel must approve it/);
    assert.match(rendered, /<@U1>/);
    assert.ok(!rendered.includes(BODY_SENTINEL), 'SEC-1: no body in the channel prompt');
    assert.ok(!rendered.includes(TOKEN), 'SEC-1: no credential in the channel prompt');
    assert.ok(!rendered.includes('/repos'), 'raw path never rendered');

    // SEC-3: the requester's own click, and a click from someone who is not a member, are
    // re-checked server-side, rejected, and audited; the prompt stays pending.
    const own: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId, own);
    assert.match(String(own[0]?.text), /not eligible to decide this approval; another channel member must\./i);
    assert.equal(own[0]?.replace_original, false, 'the channel prompt is left in place for a teammate');
    await click(APPROVAL_APPROVE_ACTION, 'U_OUTSIDER', e.approvalId);
    const rejected = (await auditRows()).filter((r) => r.action === 'denied' && r.meta.includes('not-approver'));
    assert.deepEqual(rejected.map((r) => r.user_id).sort(), ['U1', 'U_OUTSIDER']);
    assert.equal((await approvalRows())[0]?.status, 'pending');
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0, 'no grant existed after the rejected clicks');
    assert.equal(dms.length, 1, 'the durable channel prompt is not re-posted');

    // Another member approves; the retry executes exactly once, with the requester's credential.
    const receipt: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U_MEMBER', e.approvalId, receipt);
    assert.match(String(receipt[0]?.text), /Approved/);
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
    assert.equal(new Headers(calls[0].init?.headers).get('authorization'), `Bearer ${TOKEN}`, 'the requester\'s credential, never the approver\'s');
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 1, 'single-use');
    const consumed = (await auditRows()).find((r) => r.action === 'approval_consumed');
    assert.equal(consumed.actor, 'U_MEMBER');
    assert.equal(consumed.user_id, 'U1');
    // The requester was told their request was approved (ephemeral in the channel).
    assert.ok(ephemerals.some((p) => p.user === 'U1' && /approved/i.test(String(p.text))));
  });
});

test('member approver: no prompt is posted into an externally shared (Slack Connect) channel', async (t) => {
  const { ctx, dms, ephemerals, approvalRows, auditRows } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_EXTERNAL_ORG'],
    channelInfo: { is_ext_shared: true },
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    await assert.rejects(handle.fetch('https://api.acme.test/repos', { method: 'POST' }), /externally shared channels/);
    assert.equal(dms.length, 0, 'a foreign org must never see the prompt');
    assert.equal(ephemerals.length, 0);
    assert.equal((await approvalRows()).length, 0, 'the undeliverable request is removed, not parked behind a lease');
    assert.ok(!(await auditRows()).some((r) => r.action === 'approved' || r.action === 'approval_consumed'));
    assert.equal(calls.length, 0, 'no egress');
  });
});

test('member approver: a Slack Connect conversion after the prompt invalidates it; a foreign-org member cannot approve', async (t) => {
  const channelInfo: Record<string, unknown> = {};
  const { ctx, click, dms, approvalRows, auditRows } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_EXTERNAL_ORG'],
    channelInfo,
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(dms.length, 1, 'the prompt was posted while the channel was internal');
    // The probe: conversations.info now reports Slack Connect and conversations.members lists a user
    // from the other org, who is not the requester. Membership alone must not be enough.
    channelInfo.is_ext_shared = true;
    const responds: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U_EXTERNAL_ORG', e.approvalId, responds);
    assert.match(String(responds[0]?.text), /no longer valid because provider or channel access changed/);
    assert.equal((await approvalRows()).length, 0, 'the pending request is removed under the decision locks');
    const audits = await auditRows();
    assert.ok(!audits.some((r) => r.action === 'approved' || r.action === 'approval_consumed'), 'nothing was granted');
    assert.equal(audits.filter((r) => r.action === 'approval_requested').length, 1, 'the request audit stands as the record');
    // A retry cannot re-post into the now-external channel, and U1's credential never left.
    await assert.rejects(handle.fetch('https://api.acme.test/repos', { method: 'POST' }), /externally shared channels/);
    assert.equal(dms.length, 1, 'no second prompt reaches the shared channel');
    assert.equal(calls.length, 0, 'no egress with the requester\'s credential');
  });
});

test('member approver: a click whose signed channel differs from the request\'s channel decides nothing', async (t) => {
  const { ctx, click, approvalRows, auditRows } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_MEMBER'],
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const responds: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U_MEMBER', e.approvalId, responds, undefined, { channel: 'C_OTHER', thread: 'TH1' });
    assert.match(responds[0]?.text ?? '', /expired or was already decided/);
    assert.equal((await approvalRows())[0]?.status, 'pending', 'the real pending request is untouched');
    assert.ok(!(await auditRows()).some((r) => r.action === 'approved'));
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0);
  });
});

test('member approver: two members clicking at once on two Bolt instances yield exactly one decision', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const provider = approvalProvider({ approval: { approver: 'member' } });
  const { ctx, click, auditRows, approvalRows, client } = await harness(t, {
    db: dbA, provider, members: ['U1', 'U_M1', 'U_M2'],
  });
  // A second replica over the same store, with its own registered Approve/Deny handlers.
  const replica = await createVouchr({ providers: [provider], baseUrl: 'http://127.0.0.1:1', db: dbB });
  const actionsB: Record<string, any> = {};
  replica.registerCommands({ command: () => undefined, view: () => undefined, action: (id: string, h: any) => (actionsB[id] = h) });
  const clickB = (clicker: string, value: string, responds: any[]) => actionsB[APPROVAL_APPROVE_ACTION]({
    ack: async () => {},
    body: { team: { id: 'T1' }, user: { id: clicker }, channel: { id: 'C1' }, container: { channel_id: 'C1', thread_ts: 'TH1' }, actions: [{ value }] },
    client,
    respond: async (m: any) => { responds.push(m); },
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const a: any[] = [];
    const b: any[] = [];
    await Promise.all([click(APPROVAL_APPROVE_ACTION, 'U_M1', e.approvalId, a), clickB('U_M2', e.approvalId, b)]);
    const texts = [a[0]?.text, b[0]?.text].map(String);
    assert.equal(texts.filter((x) => /Approved/.test(x)).length, 1, `exactly one winner: ${texts.join(' | ')}`);
    assert.equal(texts.filter((x) => /expired or was already decided/.test(x)).length, 1, 'the loser sees the fixed stale receipt');
    const [row] = await approvalRows();
    assert.equal(row.status, 'granted');
    assert.ok(['U_M1', 'U_M2'].includes(row.approved_by));
    assert.equal((await auditRows()).filter((r) => r.action === 'approved').length, 1, 'one decision audit row');
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
  });
});

test('member approver in a DM degrades to self: the requester is prompted privately and decides', async (t) => {
  const { ctx, ephemerals, dms, click } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    channel: 'D0PERSONAL',
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(e.approver, 'self', 'no channel governs a DM, so the rule resolves to self');
    assert.equal(dms.length, 0, 'no channel message');
    assert.equal(ephemerals.length, 1);
    assert.equal(ephemerals[0].channel, 'D0PERSONAL');
    assert.equal(ephemerals[0].user, 'U1');
    assert.match(JSON.stringify(ephemerals[0]), /as you on/);
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId, [], undefined, { channel: 'D0PERSONAL', thread: 'TH1' });
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
  });
});

test('the approval prompt post reserves a post, pool wait, query confirmation, and margin inside the lease', () => {
  assert.ok(APPROVAL_PROMPT_POST_DEADLINE_MS > 0, 'the posting window must remain usable');
  assert.ok(
    DB_RUNTIME_STATEMENT_TIMEOUT_MS <= DB_RUNTIME_QUERY_TIMEOUT_MS,
    'PostgreSQL must cancel no later than the client completion bound',
  );
  assert.equal(
    APPROVAL_PROMPT_POST_DEADLINE_MS
      + SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS
      + DB_CONNECTION_TIMEOUT_MS
      + DB_RUNTIME_QUERY_TIMEOUT_MS
      + APPROVAL_DELIVERY_SAFETY_MARGIN_MS,
    PROMPT_DELIVERY_LEASE_US / 1_000,
    'the component bounds and explicit safety margin must exactly consume the lease budget',
  );
});

test('an elapsed start budget sends nothing, releases its lease, and reports known non-delivery', async (t) => {
  const hrtime = process.hrtime as typeof process.hrtime & { bigint: () => bigint };
  const realHrtime = hrtime.bigint;
  let monotonicNow = 0n;
  hrtime.bigint = () => monotonicNow;
  try {
    for (const approver of ['self', 'member'] as const) {
      monotonicNow = 0n;
      const { ctx, approvalRows, ephemerals, dms } = await harness(t, {
        provider: approvalProvider({ approval: { approver } }),
        members: ['U1', 'U_MEMBER'],
      });
      const approvals = (ctx as any).approvals;
      const realClaim = approvals.claimDelivery.bind(approvals);
      approvals.claimDelivery = async (...args: unknown[]) => {
        const claim = await realClaim(...args);
        monotonicNow = BigInt((APPROVAL_PROMPT_POST_DEADLINE_MS + 1) * 1_000_000);
        return claim;
      };
      await withFetch(async () => {
        const handle = await ctx.connect('acme');
        await expectUserRecovery(
          handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
          'retry_later',
          /delivery window elapsed before a prompt could be sent/i,
        );
      });
      assert.equal(ephemerals.length, 0, `${approver}: no Slack request was started`);
      assert.equal(dms.length, 0, `${approver}: no Slack request was started`);
      assert.equal((await approvalRows()).length, 0, `${approver}: the newly minted row was released`);
    }
  } finally {
    hrtime.bigint = realHrtime;
  }
});

test('member approver: deny is retained (#296), notifies the requester ephemerally, and audits the member as actor', async (t) => {
  const { ctx, ephemerals, click, auditRows, approvalRows } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_MEMBER'],
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_DENY_ACTION, 'U_MEMBER', e.approvalId);
    const denied = (await auditRows()).find((r) => r.action === 'denied' && r.meta.includes('approval-denied'));
    assert.equal(denied.user_id, 'U1');
    assert.equal(denied.actor, 'U_MEMBER');
    const note = ephemerals.find((p) => p.user === 'U1' && /denied/i.test(String(p.text)));
    assert.ok(note, 'requester was notified of the denial');
    const [row] = await approvalRows();
    assert.equal(row.status, 'denied', 'the denial is persisted, not deleted');
    assert.equal(calls.length, 0);
    // No auto-retry: the same action re-asks with a NEW request rather than reviving the denied one.
    const again = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.notEqual(again.approvalId, e.approvalId);
    assert.equal(calls.length, 0);
  });
});

test("self approver: another user's click is rejected and audited; nothing is granted", async (t) => {
  const { ctx, click, auditRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U_EVIL', e.approvalId);
    const denied = (await auditRows()).filter((r) => r.action === 'denied' && r.meta.includes('not-approver'));
    assert.equal(denied.length, 1);
    assert.equal(denied[0].user_id, 'U_EVIL');
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0);
  });
});

test('forged approval id / cross-team id decides nothing', async (t) => {
  const { ctx, click, approvalRows } = await harness(t);
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const responds: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', randomUUID(), responds); // unknown id
    assert.match(responds[0]?.text ?? '', /expired or was already decided/);
    const rows = await approvalRows();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, 'pending', 'the real pending request is untouched');
  });
});

// ── zero behavior change without the knob ─────────────────────────────────────────────────────────

test('providers without the approval knob: writes pass untouched, no approval rows anywhere', async (t) => {
  const { ctx, ephemerals, auditRows, approvalRows } = await harness(t, {
    provider: approvalProvider({ approval: undefined }),
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
    assert.equal(ephemerals.length, 0);
    assert.equal((await approvalRows()).length, 0);
    assert.ok(!(await auditRows()).some((r) => String(r.action).startsWith('approval')));
  });
});

// ── shared channel-owned credential: the grant binds to owner_kind=channel ────────────────────────

test('shared mode: a write on a channel-owned credential prompts, binds to the channel owner, and consumes once', async (t) => {
  // connect() in shared mode borrows the CHANNEL's credential (owner_kind=channel/owner_id=C1),
  // audited as the acting human. Closes owner-binding coverage for the channel owner kind (the
  // per-user kind is covered above). Approver 'self' = the caller confirms their own action.
  const { ctx, ephemerals, click, approvalRows, auditRows } = await harness(t, { sharedChannel: true });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme'); // shared mode → connectChannel, channel-owned cred
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(ephemerals[0]?.user, 'U1'); // prompted the acting human

    // The pending grant is bound to the CHANNEL owner, not a user.
    const [pending] = await approvalRows();
    assert.equal(pending.owner_kind, 'channel');
    assert.equal(pending.owner_id, 'C1');
    assert.equal(pending.user_id, 'U1'); // the requester (acting human)

    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
    // Single-use across the channel owner too.
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 1);
    const consumed = (await auditRows()).find((r) => r.action === 'approval_consumed');
    assert.equal(JSON.parse(consumed.meta).channel, 'C1');
  });
});

test('identical pending actions converge on one opaque id, prompt, and requested audit', async (t) => {
  const { ctx, ephemerals, approvalRows, auditRows } = await harness(t);
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const first = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const second = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(second.approvalId, first.approvalId);
    assert.equal(first.newRequest, true);
    assert.equal(second.newRequest, false);
    assert.equal(ephemerals.length, 1);
    assert.equal((await approvalRows()).length, 1);
    assert.equal((await auditRows()).filter((r) => r.action === 'approval_requested').length, 1);
    assert.ok(!JSON.stringify(await auditRows()).includes(first.approvalId));
  });
});

test('member prompt: platform rejection of the channel message is definite and immediately retryable', async (t) => {
  let reject = true;
  const { ctx, approvalRows, dms } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_MEMBER'],
    postMessage: async () => {
      if (reject) throw slackWebApiError(SlackErrorCode.PlatformError);
      return {};
    },
  });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const error = await expectUserRecovery(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      'fix_configuration',
      /Slack rejected the approval prompt before delivery/i,
    );
    assert.ok(!error.message.includes(FOREIGN_SLACK_ERROR));
    assert.equal(dms.length, 1);
    assert.equal((await approvalRows()).length, 0, 'a definitely undelivered new request is removed');

    reject = false;
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(dms.length, 2, 'the cleared delivery state allows an immediate retry');
    const [retried] = await approvalRows();
    assert.equal(retried?.delivery_token, null);
    assert.ok(retried?.delivered_at != null);
  });
});

test('member prompt: rate limiting of the channel message is definite and immediately retryable', async (t) => {
  let reject = true;
  const { ctx, approvalRows, dms } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_MEMBER'],
    postMessage: async () => {
      if (reject) throw slackWebApiError(SlackErrorCode.RateLimitedError);
      return {};
    },
  });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const error = await expectUserRecovery(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      'retry_later',
      /Slack rate-limited the approval prompt before delivery/i,
    );
    assert.ok(!error.message.includes(FOREIGN_SLACK_ERROR));
    assert.equal((await approvalRows()).length, 0, 'a definitely undelivered new request is removed');
    reject = false;
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(dms.length, 2);
    assert.equal((await approvalRows()).length, 1);
  });
});

test('member prompt: an ambiguous channel-message failure retains the lease and stays decidable by a member', async (t) => {
  for (const [name, reason] of [
    ['request error', () => slackWebApiError(SlackErrorCode.RequestError)],
    ['bare rejected value', () => undefined],
  ] as const) {
    await t.test(name, async (st) => {
      const { ctx, approvalRows, dms, click } = await harness(st, {
        provider: approvalProvider({ approval: { approver: 'member' } }),
        members: ['U1', 'U_MEMBER'],
        postMessage: () => Promise.reject(reason()),
      });
      await withFetch(async () => {
        const handle = await ctx.connect('acme');
        const error = await expectUserRecovery(
          handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
          'retry_later',
          /could not confirm approval-prompt delivery/i,
        );
        assert.ok(!error.message.includes(FOREIGN_SLACK_ERROR));
        const [row] = await approvalRows();
        assert.ok(row?.delivery_token, 'unknown outcome retains the live lease and request');
        await expectUserRecovery(
          handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
          'retry_later',
          /still being delivered/i,
        );
        assert.equal(dms.length, 1, 'no second post starts during the live lease');
        // Slack may have accepted before rejecting locally: the visible button remains decidable.
        const receipt: any[] = [];
        await click(APPROVAL_APPROVE_ACTION, 'U_MEMBER', row.id, receipt);
        assert.match(receipt[0]?.text ?? '', /Approved/);
        assert.equal((await approvalRows())[0]?.status, 'granted');
      });
    });
  }
});

test('hostile Slack error proxies stay ambiguous without leaking their contents', async (t) => {
  for (const trap of ['prototype', 'code'] as const) {
    await t.test(trap, async (st) => {
      const sentinel = `${FOREIGN_SLACK_ERROR}_${trap}`;
      const hostile = trap === 'prototype'
        ? new Proxy({}, { getPrototypeOf: () => { throw new Error(sentinel); } })
        : new Proxy({}, {
          getPrototypeOf: () => Object.prototype,
          get: (target, property, receiver) => {
            if (property === 'code') throw new Error(sentinel);
            return Reflect.get(target, property, receiver);
          },
        });
      const { ctx, approvalRows, ephemerals, click } = await harness(st, {
        postEphemeral: () => Promise.reject(hostile),
      });
      await withFetch(async () => {
        const handle = await ctx.connect('acme');
        const error = await expectUserRecovery(
          handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
          'retry_later',
          /could not confirm approval-prompt delivery/i,
        );
        assert.ok(!error.message.includes(sentinel));
        assert.ok(!JSON.stringify(ephemerals).includes(sentinel));
        const [row] = await approvalRows();
        assert.ok(row?.delivery_token, 'hostile values fail safe as possibly delivered');

        const receipt: any[] = [];
        await click(APPROVAL_APPROVE_ACTION, 'U1', row.id, receipt);
        assert.match(receipt[0]?.text ?? '', /Approved/);
      });
    });
  }
});

test('definite rejection after an ambiguous approval takeover retains the old decidable row', async (t) => {
  let outcome: 'ambiguous' | 'platform' = 'ambiguous';
  const { vouchr, ctx, approvalRows, click } = await harness(t, {
    postEphemeral: () => Promise.reject(slackWebApiError(
      outcome === 'ambiguous' ? SlackErrorCode.RequestError : SlackErrorCode.PlatformError,
    )),
  });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    await expectUserRecovery(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      'retry_later',
      /could not confirm approval-prompt delivery/i,
    );
    const [original] = await approvalRows();
    assert.ok(original?.delivery_token);
    await vouchr.db.run(`UPDATE approval_request SET delivery_lease_expires_at=0 WHERE id=?`, [original.id]);

    outcome = 'platform';
    await expectUserRecovery(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      'fix_configuration',
      /Slack rejected the approval prompt before delivery/i,
    );
    const [retained] = await approvalRows();
    assert.equal(retained?.id, original.id);
    assert.equal(retained?.delivery_token, null, 'a failed takeover releases rather than deletes the old row');

    const receipt: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', original.id, receipt);
    assert.match(receipt[0]?.text ?? '', /Approved/);
  });
});

test('approval prompt confirmation drift reports resolve-again recovery', async (t) => {
  const { ctx } = await harness(t);
  (ctx as any).approvals.confirmDelivery = async () => false;
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    await expectUserRecovery(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      'resolve_again',
      /state was already handled or changed before confirmation/i,
    );
  });
});

test('approval prompt confirmation failure reports an unknown outcome without leaking database text', async (t) => {
  const sentinel = 'RAW_DATABASE_CONFIRMATION_ERROR_MUST_NOT_ESCAPE';
  const { ctx, approvalRows, dms } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_MEMBER'],
  });
  (ctx as any).approvals.confirmDelivery = async () => { throw new Error(sentinel); };
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const error = await expectUserRecovery(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      'retry_later',
      /delivered, but Vouchr could not confirm its delivery state/i,
    );
    assert.ok(!error.message.includes(sentinel));
    assert.ok(!JSON.stringify(dms).includes(sentinel));
    assert.deepEqual(dms.map((prompt) => prompt.channel), ['C1']);
    const [row] = await approvalRows();
    assert.ok(row?.delivery_token, 'an unknown confirmation outcome must retain the delivery lease');
  });
});

test('approval surfaces expose only a salted action fingerprint and deduplicate the maximum path', async (t) => {
  const { ctx, approvalRows, ephemerals, auditRows } = await harness(t);
  const sensitivePath = '/hook/ghp_path_sentinel_token';
  const maxPath = `/${'a'.repeat(MAX_APPROVAL_PATH_BYTES - 1)}`;
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const sensitive = await expectApprovalRequired(
      handle.fetch(`https://api.acme.test${sensitivePath}`, { method: 'POST' }),
    );
    const serializedError = JSON.stringify({ ...sensitive });
    const rendered = JSON.stringify(ephemerals[0]);
    const audit = JSON.stringify(await auditRows());
    assert.ok(!serializedError.includes(sensitivePath));
    assert.ok(!rendered.includes(sensitivePath));
    assert.ok(!audit.includes(sensitivePath));
    assert.match(sensitive.actionFingerprint, /^hmac-sha256:[0-9a-f]{64}$/);
    assert.match(rendered, /Action fingerprint/);

    const first = await expectApprovalRequired(
      handle.fetch(`https://api.acme.test${maxPath}`, { method: 'POST' }),
    );
    const second = await expectApprovalRequired(
      handle.fetch(`https://api.acme.test${maxPath}`, { method: 'POST' }),
    );
    assert.equal(second.approvalId, first.approvalId);
    assert.equal(ephemerals.length, 2, 'one sensitive action plus one deduplicated maximum action');
    const rows = await approvalRows();
    assert.equal(rows.length, 2);
    assert.equal(rows.find((row: any) => row.id === first.approvalId)?.path, maxPath);
    assert.equal((await auditRows()).filter((row: any) => row.action === 'approval_requested').length, 2);
    assert.equal(calls.length, 0);
  });
});

test('just-over-limit approval path fails before rate budget, persistence, audit, Slack, or egress', async (t) => {
  const provider = approvalProvider({ rateLimit: { perMinute: 1, burst: 1 } });
  const { ctx, approvalRows, ephemerals, auditRows } = await harness(t, { provider });
  const tooLarge = `/${'z'.repeat(MAX_APPROVAL_PATH_BYTES)}`;
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    await assert.rejects(
      handle.fetch(`https://api.acme.test${tooLarge}`, { method: 'POST' }),
      (error) => {
        assert.ok(error instanceof ApprovalPathTooLongError);
        assert.equal(safeUserMessage(error), 'The approval action path is too large. Narrow the endpoint and retry.');
        assert.ok(!JSON.stringify({ ...error }).includes(tooLarge));
        return true;
      },
    );
    assert.equal((await approvalRows()).length, 0);
    assert.equal((await auditRows()).length, 0);
    assert.equal(ephemerals.length, 0);
    assert.equal(calls.length, 0);

    // If the rejected path had spent the one-token burst, this bounded action would return 429
    // instead of creating its approval request.
    await expectApprovalRequired(handle.fetch('https://api.acme.test/ok', { method: 'POST' }));
    assert.equal((await approvalRows()).length, 1);
  });
});

test('action digest is never authority: selector collisions cannot reuse another exact action', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const base = {
    teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1', provider: 'acme',
    credentialId: GENERATION, method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test', queryHash: '', channel: 'C1', thread: 'TH1', governableChannel: 'C1',
  };
  const first = { ...base, path: '/first' };
  const providerMismatch = { ...first, provider: 'other' };
  const collision = { ...base, path: '/different' };
  const firstId = await approvals.request(first);

  // The globally unique credential generation already binds its provider, so provider is omitted
  // from the bounded selector. It remains an exact SQL authority field: even a deliberately reused
  // generation cannot cross provider names through the selector collision.
  assert.equal(approvalActionKey(providerMismatch), approvalActionKey(first));
  await assert.rejects(() => approvals.request(providerMismatch), /could not be recorded/);
  assert.deepEqual(
    await db.all<any>(`SELECT id, provider, path FROM approval_request`),
    [{ id: firstId, provider: 'acme', path: '/first' }],
    'the provider mismatch leaves the original exact row untouched',
  );

  await db.run(`UPDATE approval_request SET action_key=? WHERE id=?`, [approvalActionKey(collision), firstId]);

  await assert.rejects(() => approvals.request(collision), /could not be recorded/);
  const rows = await db.all<any>(`SELECT id, path FROM approval_request`);
  assert.deepEqual(rows, [{ id: firstId, path: '/first' }], 'full-field mismatch fails closed');
});

test('decision audit failure rolls back the grant; a retry of the same button can succeed', async (t) => {
  const { vouchr, ctx, click, approvalRows, auditRows } = await harness(t);
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const pending = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const original = vouchr.audit.record.bind(vouchr.audit);
    (vouchr.audit as any).record = async (action: string, ...args: any[]) => {
      if (action === 'approved') throw new Error('audit unavailable');
      return (original as any)(action, ...args);
    };
    const failed: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId, failed);
    assert.match(failed[0]?.text, /could not confirm this approval/i);
    assert.equal((await approvalRows())[0]?.status, 'pending');
    assert.equal((await auditRows()).filter((r) => r.action === 'approved').length, 0);

    (vouchr.audit as any).record = original;
    const retried: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId, retried);
    assert.match(retried[0]?.text, /Approved/);
    assert.equal((await approvalRows())[0]?.status, 'granted');
  });
});

test('consume audit failure rolls back the spend and sends nothing upstream', async (t) => {
  const { vouchr, ctx, click, approvalRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const pending = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId);
    const original = vouchr.audit.record.bind(vouchr.audit);
    (vouchr.audit as any).record = async (action: string, ...args: any[]) => {
      if (action === 'approval_consumed') throw new Error('audit unavailable');
      return (original as any)(action, ...args);
    };
    await assert.rejects(handle.fetch('https://api.acme.test/repos', { method: 'POST' }), /audit unavailable/);
    assert.equal(calls.length, 0);
    assert.equal((await approvalRows())[0]?.status, 'granted');

    (vouchr.audit as any).record = original;
    assert.equal((await handle.fetch('https://api.acme.test/repos', { method: 'POST' })).status, 200);
    assert.equal(calls.length, 1);
  });
});

test('duplicate approval clicks get one committed success and one fixed stale receipt', async (t) => {
  const { ctx, click, auditRows } = await harness(t);
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const pending = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const a: any[] = [];
    const b: any[] = [];
    await Promise.all([
      click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId, a),
      click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId, b),
    ]);
    const receipts = [a[0]?.text, b[0]?.text].join('\n');
    assert.match(receipts, /✅ Approved/);
    assert.match(receipts, /expired or was already decided/);
    assert.equal((await auditRows()).filter((r) => r.action === 'approved').length, 1);
  });
});

test('approval action acknowledges Slack before its first database lookup', async (t) => {
  const raw = await openTestDb(t);
  let enforceAck = false;
  let acked = false;
  const wrapped: Db = {
    get: async (sql, params) => {
      if (enforceAck && /approval_request/.test(sql)) assert.equal(acked, true);
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
  const { ctx, click } = await harness(t, { db: wrapped });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const pending = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    enforceAck = true;
    await click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId, [], async () => { acked = true; });
    assert.equal(acked, true);
  });
});

test('member eligibility Slack reads happen before, never inside, the decision transaction', async (t) => {
  const raw = await openTestDb(t);
  let insideTransaction = false;
  const wrapped: Db = {
    get: (sql, params) => raw.get(sql, params),
    all: (sql, params) => raw.all(sql, params),
    run: (sql, params) => raw.run(sql, params),
    exec: (sql) => raw.exec(sql),
    close: async () => {},
    ...(raw.transaction ? {
      transaction: <T>(fn: (tx: Db) => Promise<T>) => raw.transaction!(async (tx) => {
        insideTransaction = true;
        try { return await fn(tx); } finally { insideTransaction = false; }
      }),
    } : {}),
    ...(raw.withRefreshLock ? {
      withRefreshLock: <T>(key: string, fn: (tx: Db) => Promise<T>) => raw.withRefreshLock!(key, async (tx) => {
        insideTransaction = true;
        try { return await fn(tx); } finally { insideTransaction = false; }
      }),
    } : {}),
    ...(raw.withRefreshLocks ? {
      withRefreshLocks: <T>(keys: readonly string[], fn: (tx: Db) => Promise<T>) => raw.withRefreshLocks!(keys, async (tx) => {
        insideTransaction = true;
        try { return await fn(tx); } finally { insideTransaction = false; }
      }),
    } : {}),
  };
  const { ctx, click } = await harness(t, {
    db: wrapped,
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_MEMBER'],
    onSlackRead: () => assert.equal(insideTransaction, false, 'Slack I/O must not pin a DB transaction'),
  });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const pending = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U_MEMBER', pending.approvalId);
  });
});

for (const decision of ['approve', 'deny'] as const) {
  test(`a member offboarded during Slack eligibility checks cannot ${decision} a pending request`, async (t) => {
    let armed = false;
    let reachedSlackRead!: () => void;
    let releaseSlackRead!: () => void;
    const atSlackRead = new Promise<void>((resolve) => { reachedSlackRead = resolve; });
    const resumeSlackRead = new Promise<void>((resolve) => { releaseSlackRead = resolve; });
    const { vouchr, ctx, click, approvalRows, auditRows } = await harness(t, {
      provider: approvalProvider({ approval: { approver: 'member' } }),
      members: ['U1', 'U_MEMBER'],
      onSlackRead: async () => {
        if (!armed) return;
        armed = false;
        reachedSlackRead();
        await resumeSlackRead;
      },
    });

    await withFetch(async () => {
      const handle = await ctx.connect('acme');
      const pending = await expectApprovalRequired(
        handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      );
      const responses: any[] = [];
      armed = true;
      const deciding = click(
        decision === 'approve' ? APPROVAL_APPROVE_ACTION : APPROVAL_DENY_ACTION,
        'U_MEMBER',
        pending.approvalId,
        responses,
      );
      await atSlackRead;
      await new Consent(vouchr.db).markOffboarded({
        enterpriseId: null,
        teamId: 'T1',
        userId: 'U_MEMBER',
      });
      releaseSlackRead();
      await deciding;

      assert.match(String(responses[0]?.text), /authority changed/i);
      const [row] = await approvalRows();
      assert.equal(row.status, 'pending', 'the pre-offboard decision leaves the request pending');
      assert.ok(
        !(await auditRows()).some((audit) =>
          audit.action === 'approved' ||
          (audit.action === 'denied' && audit.meta.includes('approval-denied'))),
        'no decision audit row is written',
      );
    });
  });
}

test('a requester-stale channel approval is removed so re-onboarding can request a fresh decision', async (t) => {
  const { vouchr, ctx, click, approvalRows, auditRows, client } = await harness(t, {
    sharedChannel: true,
    members: ['U1'],
  });

  await withFetch(async () => {
    const originalHandle = await ctx.connect('acme');
    const original = await expectApprovalRequired(
      originalHandle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    );

    // Model a failed/bypassed best-effort approval cleanup: only the durable offboard fence lands.
    // The shared channel credential intentionally survives, as does the pre-offboard pending row.
    await new Consent(vouchr.db).markOffboarded(ID);
    assert.equal((await approvalRows()).length, 1);

    // Re-onboarding is represented by a newly received Slack event after the tombstone. The receipt
    // conversion is deliberately conservative: it backdates the event by one PostgreSQL round trip
    // (fail closed), so the margin here must cover a slow query, not just clock resolution. A 10µs
    // margin flaked in CI (#306 run): the return leg of connect()'s own clock query exceeded it and
    // the fresh event was fenced as pre-offboard (InteractionStateChangedError, not a new prompt).
    const tombstone = await vouchr.db.get<{ created_at: number }>(
      `SELECT created_at FROM offboard_tombstone WHERE team_id=? AND user_id=?`,
      [ID.teamId, ID.userId],
    );
    assert.ok(tombstone);
    while (await vouchr.vault.userProvisioningIssuedAt() <= tombstone.created_at + usFromMs(250)) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    const args: any = {
      context: {},
      client,
      event: { channel: 'C1', user: 'U1', team: 'T1', thread_ts: 'TH1' },
      next: async () => {},
    };
    await vouchr.middleware(args);
    const freshHandle = await args.context.vouchr.connect('acme');

    // The surviving row initially parks exact-action dedupe, so the first fresh request observes the
    // old id. Deciding it must delete that exact stale generation rather than leave it until TTL.
    const reused = await expectApprovalRequired(
      freshHandle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    );
    assert.equal(reused.approvalId, original.approvalId);
    const responses: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', reused.approvalId, responses);
    assert.match(String(responses[0]?.text), /no longer valid/i);
    assert.equal((await approvalRows()).length, 0);
    assert.ok(
      !(await auditRows()).some((row) => row.action === 'approved' || row.action === 'denied'),
      'requester-stale cleanup creates neither an approval nor a denial audit',
    );

    const replacement = await expectApprovalRequired(
      freshHandle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    );
    assert.notEqual(replacement.approvalId, original.approvalId);
    assert.deepEqual((await approvalRows()).map((row) => row.id), [replacement.approvalId]);
  });
});

test('cross-pool approval decision waits for a tool writer and observes its atomic invalidation', async (t) => {
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const key = randomBytes(32);
  const a = await harness(t, { db: dbA, masterKey: key });
  const vaultB = new Vault(dbB, key);

  await withFetch(async () => {
    const handle = await a.ctx.connect('acme');
    const pending = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const writerAudit = new Audit(dbB);
    const original = writerAudit.record.bind(writerAudit);
    let release!: () => void;
    let atAudit!: () => void;
    const releaseP = new Promise<void>((resolve) => { release = resolve; });
    const atAuditP = new Promise<void>((resolve) => { atAudit = resolve; });
    (writerAudit as any).record = async (...args: any[]) => {
      atAudit();
      await releaseP;
      return (original as any)(...args);
    };
    const writerIssuance = await vaultB.userProvisioningIssuedAt();
    const writer = configureChannelTools({
      channelTools: new ChannelTools(dbB),
      vault: vaultB,
      audit: writerAudit,
      identity: ID,
      channel: 'C1',
      changes: [['acme', false]],
      allProviders: ['acme'],
      authorize: async () => true,
      assertEligible: async () => {},
      issuance: writerIssuance,
    });
    await atAuditP;

    const responses: any[] = [];
    let clickSettled = false;
    const click = a.click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId, responses)
      .then(() => { clickSettled = true; });
    let demandSettled = false;
    const staleDemand = handle.fetch('https://api.acme.test/repos', { method: 'POST' })
      .finally(() => { demandSettled = true; });
    void staleDemand.catch(() => undefined);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(clickSettled, false, 'decision waits for the canonical channel/provider lock');
    assert.equal(demandSettled, false, 'request creation waits for the canonical channel/provider lock');
    release();
    await writer;
    await click;
    await assert.rejects(staleDemand, (error: unknown) => {
      assert.ok(error instanceof InteractionStateChangedError);
      assert.equal(error.reason, 'authorization');
      assert.equal(
        safeUserMessage(error),
        'Access changed while Vouchr was handling this request. Resolve current access and retry.',
      );
      return true;
    });
    assert.match(responses[0]?.text, /expired or was already decided/);
    assert.equal((await a.approvalRows()).length, 0);
    assert.equal((await a.auditRows()).filter((r) => r.action === 'approved').length, 0);
  });
});

test('mode owner ABA purges both pending controls and granted approvals', async (t) => {
  const { vouchr, ctx, click, approvalRows } = await harness(t);
  const cfg = new ChannelConfig(vouchr.db);
  const issuance = await vouchr.vault.userProvisioningIssuedAt();
  const mutate = (mode: 'shared' | 'per-user') => setChannelCredentialMode({
    vault: vouchr.vault,
    audit: vouchr.audit,
    channelConfig: cfg,
    identity: ID,
    channel: 'C1',
    providerId: 'acme',
    mode,
    issuance,
  });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const oldControl = await expectApprovalRequired(handle.fetch('https://api.acme.test/pending', { method: 'POST' }));
    await mutate('shared');
    await mutate('per-user');
    const response: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', oldControl.approvalId, response);
    assert.match(response[0]?.text, /expired or was already decided/);

    const granted = await expectApprovalRequired(handle.fetch('https://api.acme.test/granted', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', granted.approvalId);
    assert.equal((await approvalRows())[0]?.status, 'granted');
    await mutate('shared');
    await mutate('per-user');
    const next = await expectApprovalRequired(handle.fetch('https://api.acme.test/granted', { method: 'POST' }));
    assert.notEqual(next.approvalId, granted.approvalId, 'the pre-ABA grant cannot resurrect');
  });
});

test('tool enabled→disabled→enabled ABA purges a granted approval', async (t) => {
  const { vouchr, ctx, click } = await harness(t);
  const issuance = await vouchr.vault.userProvisioningIssuedAt();
  const configure = (enabled: boolean) => configureChannelTools({
    channelTools: new ChannelTools(vouchr.db),
    vault: vouchr.vault,
    audit: vouchr.audit,
    identity: ID,
    channel: 'C1',
    changes: [['acme', enabled]],
    allProviders: ['acme'],
    authorize: async () => true,
    assertEligible: async () => {},
    issuance,
  });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const granted = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', granted.approvalId);
    await configure(false);
    await configure(true);
    const next = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.notEqual(next.approvalId, granted.approvalId);
  });
});

test('same-value tool retries preserve live approval and session grants', async (t) => {
  const { vouchr, ctx, click, approvalRows, auditRows } = await harness(t);
  const sessions = new SessionGrants(vouchr.db);
  const issuance = await vouchr.vault.userProvisioningIssuedAt();
  const configureEnabled = (
    changes: readonly (readonly [string, boolean])[] = [['acme', true]],
  ) => configureChannelTools({
    channelTools: new ChannelTools(vouchr.db),
    vault: vouchr.vault,
    audit: vouchr.audit,
    identity: ID,
    channel: 'C1',
    changes,
    allProviders: ['acme'],
    authorize: async () => true,
    assertEligible: async () => {},
    issuance,
  });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const granted = await expectApprovalRequired(
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    );
    await click(APPROVAL_APPROVE_ACTION, 'U1', granted.approvalId);
    const credentialId = await vouchr.vault.liveId(userOwner(ID), 'acme');
    assert.ok(credentialId);
    await sessions.grant(ID, 'C1', 'TH_KEEP', 'acme', 60_000, credentialId);

    // acme is already enabled (the harness opted it in). Re-asserting the enabled bit — even via
    // conflicting duplicate tuples, then a plain retry — nets to the SAME state, so the no-op filter
    // writes nothing: it must neither revoke the live approval/session grants (no purge) nor fabricate
    // a config audit row.
    await configureEnabled([['acme', false], ['acme', true]]);
    await configureEnabled();

    assert.equal((await approvalRows()).find((row) => row.id === granted.approvalId)?.status, 'granted');
    assert.equal(await sessions.isGranted(ID, 'C1', 'TH_KEEP', 'acme', credentialId), true);
    const configRows = (await auditRows()).filter((row) => row.action === 'config');
    assert.equal(configRows.length, 0, 'same-value retries are no-ops — no config audit, no purge');
  });
});

test('shared→user owner drift and missing live credential invalidate pending approvals without denial audit', async (t) => {
  const { vouchr, ctx, click, auditRows } = await harness(t, { sharedChannel: true });
  const issuance = await vouchr.vault.userProvisioningIssuedAt();
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const pending = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await setChannelCredentialMode({
      vault: vouchr.vault,
      audit: vouchr.audit,
      channelConfig: new ChannelConfig(vouchr.db),
      identity: ID,
      channel: 'C1',
      providerId: 'acme',
      mode: 'per-user',
      issuance,
    });
    const response: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', pending.approvalId, response);
    assert.match(response[0]?.text, /expired or was already decided/);
    assert.equal((await auditRows()).filter((r) => r.action === 'denied' && JSON.parse(r.meta).reason === 'approval-denied').length, 0);
  });
});

// ── headless broker: same core enforcement, structured 403 ────────────────────────────────────────

function post(port: number, path: string, body: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let json: any = null;
          try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* leave null */ }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

test('broker: unapproved write → 403 { error: "approval_required", approvalId }; approved retry executes once', async (t) => {
  const SECRET = 'broker-signing-secret';
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const audit = new Audit(db);
  const provider = approvalProvider();
  await vault.upsert(userOwner(ID), 'acme', { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const server = createBroker({ ...BROKER_REQUIRED, providers: [provider], vault, audit, db, identitySecret: identityConfig(SECRET), allowWrites: true });
  await listen(t, server);
  const port = (server.address() as any).port;
  const tok = () => signIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() }, SECRET);
  const fetchBody = { handle: { provider: 'acme', owner: 'user' }, method: 'POST', path: '/repos', body: '{}' };
  try {
    await withFetch(async (calls) => {
      const oversized = await post(port, '/v1/fetch', {
        ...fetchBody,
        path: `/${'x'.repeat(MAX_APPROVAL_PATH_BYTES)}`,
        identityToken: tok(),
      });
      assert.deepEqual(oversized, {
        status: 413,
        json: {
          error: 'approval action path too large',
          code: 'approval_path_too_large',
          retryable: false,
          recovery: 'fix_configuration',
        },
      });
      assert.equal(calls.length, 0);
      assert.equal((await db.all(`SELECT 1 FROM approval_request`)).length, 0);
      assert.equal((await db.all(`SELECT 1 FROM audit`)).length, 0);

      const first = await post(port, '/v1/fetch', { ...fetchBody, identityToken: tok() });
      assert.equal(first.status, 403);
      assert.equal(first.json.error, 'approval_required');
      assert.equal(first.json.code, 'approval_required');
      assert.equal(first.json.retryable, false);
      assert.equal(first.json.recovery, 'request_approval');
      assert.equal(typeof first.json.approvalId, 'string');
      assert.equal(calls.length, 0, 'nothing reached the wire');

      // The approval SURFACE is the Bolt app / the host: the broker only enforces. Approve the
      // pending id out-of-band (same store, same db) and the retried call passes exactly once.
      assert.ok(await new Approvals(db).approve(first.json.approvalId, 'U_ADM', 60_000));
      const retry = await post(port, '/v1/fetch', { ...fetchBody, identityToken: tok() });
      assert.equal(retry.status, 200);
      assert.equal(retry.json.status, 200);
      assert.equal(calls.length, 1);

      // Single-use across doors too: the same call right after re-prompts with a fresh id.
      const again = await post(port, '/v1/fetch', { ...fetchBody, identityToken: tok() });
      assert.equal(again.status, 403);
      assert.equal(again.json.error, 'approval_required');
      assert.notEqual(again.json.approvalId, first.json.approvalId);

      // Direct createBroker consumers never receive the raw Approvals store. Its safe public
      // lifecycle facade must still reclaim the private row this route created and preserve the
      // canonical system-attributed expiry audit.
      await db.run(`UPDATE approval_request SET expires_at=0 WHERE id=?`, [again.json.approvalId]);
      assert.equal(await server.sweepExpired(), 0, 'the compatible return counts credentials only');
      assert.equal((await db.all(`SELECT 1 FROM approval_request`)).length, 0);
      const expiry = await db.get<any>(
        `SELECT actor, meta FROM audit WHERE action='denied' ORDER BY at DESC LIMIT 1`,
      );
      assert.equal(expiry?.actor, 'system');
      assert.equal(JSON.parse(expiry?.meta ?? '{}').reason, 'approval-expired');
    });
  } finally {
    server.close();
  }
});

test('broker revalidates concurrent governance/reconnect and preserves omitted-store opt-outs', async (t) => {
  const SECRET = 'broker-use-time-secret';
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(() => dbA.close());
  t.after(() => dbB.close());
  const key = randomBytes(32);
  const vaultA = new Vault(dbA, key);
  const vaultB = new Vault(dbB, key);
  const auditA = new Audit(dbA);
  const auditB = new Audit(dbB);
  const provider = approvalProvider({ approval: undefined });
  await vaultA.reference(userOwner(ID), 'acme', { source: 'test', secretRef: 'ref://user/acme' });

  let resolverCalls = 0;
  const brokerOptions = {
    ...BROKER_REQUIRED,
    providers: [provider], vault: vaultA, audit: auditA, db: dbA,
    identitySecret: identityConfig(SECRET),
    resolvers: { test: async () => { resolverCalls++; return TOKEN; } },
  };
  const token = () => signIdentity({
    teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(),
  }, SECRET);
  const body = () => ({
    handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'GET', path: '/repos',
  });

  const originalLocks = dbA.withRefreshLocks!.bind(dbA);
  let onValidatorLock: () => void = () => {};
  (dbA as any).withRefreshLocks = (keys: readonly string[], fn: (tx: Db) => Promise<unknown>) => {
    onValidatorLock();
    return originalLocks(keys, fn);
  };

  const withTools = createBroker({ ...BROKER_REQUIRED, ...brokerOptions, channelTools: new ChannelTools(dbA) });
  await listen(t, withTools);
  const toolsPort = (withTools.address() as any).port;
  try {
    await withFetch(async (calls) => {
      // Deny-by-default: seed an explicit ENABLED row so the fetch clears the tool gate and reaches
      // the governance lock. Without it the rowless channel denies the fetch before onValidatorLock,
      // and the paused disable transaction below never gets its release() — the deadlock that hung CI.
      // The race then flips enabled -> disabled under the paused governance transaction.
      await setChannelToolEnabled(new ChannelTools(dbB), 'T1', 'C1', 'acme', true);
      const originalRecord = auditB.record.bind(auditB);
      let atAudit!: () => void;
      let release!: () => void;
      let entered!: () => void;
      const atAuditP = new Promise<void>((resolve) => { atAudit = resolve; });
      const releaseP = new Promise<void>((resolve) => { release = resolve; });
      const enteredP = new Promise<void>((resolve) => { entered = resolve; });
      (auditB as any).record = async (...args: any[]) => {
        atAudit();
        await releaseP;
        return (originalRecord as any)(...args);
      };
      const disablingIssuance = await vaultB.userProvisioningIssuedAt();
      const disabling = configureChannelTools({
        channelTools: new ChannelTools(dbB),
        vault: vaultB,
        audit: auditB,
        identity: ID,
        channel: 'C1',
        changes: [['acme', false]],
        allProviders: ['acme'],
        authorize: async () => true,
        assertEligible: async () => {},
        issuance: disablingIssuance,
      });
      onValidatorLock = entered;
      let settled = false;
      try {
        await atAuditP;
        const pending = post(toolsPort, '/v1/fetch', body()).then((response) => {
          settled = true;
          return response;
        });
        // Bounded: a fetch that never reaches the lock (a regressed gate) must FAIL here, not hang CI.
        await Promise.race([
          enteredP,
          new Promise<void>((_, reject) => {
            const timer = setTimeout(() => reject(new Error('fetch never reached the governance lock within 5s')), 5000);
            (timer as { unref?: () => void }).unref?.();
          }),
        ]);
        assert.equal(settled, false, 'route waits for the governance lifecycle transaction');
        release();
        await disabling;
        const denied = await pending;
        assert.deepEqual(denied, {
          status: 403,
          json: {
            error: 'authorization changed; resolve and retry',
            code: 'interaction_state_changed',
            retryable: false,
            recovery: 'resolve_again',
          },
        });
        assert.equal(resolverCalls, 0);
        assert.equal(calls.length, 0);
      } finally {
        // Release every barrier unconditionally so a failed assertion or the timeout can never
        // deadlock the paused governance transaction (and the rest of the suite).
        entered();
        release();
        await (disabling as Promise<unknown>).catch(() => {});
      }
    });
  } finally {
    await new Promise<void>((resolve) => withTools.close(() => resolve()));
  }

  // A caller that omits channelTools keeps the documented historical no-tool-gate semantics even
  // though the shared database now contains an explicit disabled row. The conflicting session-mode
  // row likewise stays inert when channelConfig is omitted (historical user-only/no-mode broker).
  await writeChannelMode(new ChannelConfig(dbB), 'T1', 'C1', 'acme', 'session');
  const withoutTools = createBroker(brokerOptions);
  await listen(t, withoutTools);
  const plainPort = (withoutTools.address() as any).port;
  try {
    await withFetch(async (calls) => {
      const allowed = await post(plainPort, '/v1/fetch', body());
      assert.equal(allowed.status, 200);
      assert.equal(resolverCalls, 1);
      assert.equal(calls.length, 1);

      let replaced!: () => void;
      let release!: () => void;
      const replacedP = new Promise<void>((resolve) => { replaced = resolve; });
      const releaseP = new Promise<void>((resolve) => { release = resolve; });
      const reconnect = vaultB.upsert(userOwner(ID), 'acme', {
        accessToken: 'replacement-secret', refreshToken: null, scopes: '',
        expiresAt: null, externalAccount: null,
      }, undefined, async () => {
        replaced();
        await releaseP;
      });
      await replacedP;
      let entered!: () => void;
      const enteredP = new Promise<void>((resolve) => { entered = resolve; });
      onValidatorLock = entered;
      const racing = post(plainPort, '/v1/fetch', body());
      await enteredP;
      release();
      await reconnect;
      const changed = await racing;
      assert.deepEqual(changed, {
        status: 409,
        json: {
          error: 'connection changed; resolve and retry',
          code: 'interaction_state_changed',
          retryable: false,
          recovery: 'resolve_again',
        },
      });
      assert.equal(resolverCalls, 1, 'replacement race never resolves the old reference');
      assert.equal(calls.length, 1, 'replacement race never reaches provider egress');
    });
  } finally {
    await new Promise<void>((resolve) => withoutTools.close(() => resolve()));
  }
});

// ── sweep ─────────────────────────────────────────────────────────────────────────────────────────

// #348: a never-clicked channel prompt must not keep live-looking Approve/Deny buttons after its row
// expires. No column stores the message ts, so the posting process remembers it and the sweep edits
// the message (best-effort) once the database row is gone; a locally decided prompt is left alone.
test('sweep: an expired, unclicked member prompt loses its buttons; a decided one is not overwritten', async (t) => {
  const { vouchr, ctx, dms, updates, click } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'member' } }),
    members: ['U1', 'U_MEMBER'],
    postMessage: async () => ({ ok: true, channel: 'C1', ts: `${1_700_000_000 + dms.length}.000100` }),
  });
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const expired = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL }));
    const decided = await expectApprovalRequired(handle.fetch('https://api.acme.test/other', { method: 'POST', body: BODY_SENTINEL }));
    assert.equal(dms.length, 2, 'one channel message per pending action');
    assert.equal(updates.length, 0);

    // Still pending: the sweep leaves both prompts untouched.
    await vouchr.sweepExpired();
    assert.equal(updates.length, 0, 'a live prompt is never edited');

    await click(APPROVAL_APPROVE_ACTION, 'U_MEMBER', decided.approvalId);
    await vouchr.db.run(`UPDATE approval_request SET expires_at=0 WHERE id=?`, [expired.approvalId]);
    await vouchr.sweepExpired();
    assert.equal(updates.length, 1, 'only the expired prompt is edited; the decided one was replaced by its click');
    assert.deepEqual(updates[0], {
      channel: 'C1',
      ts: '1700000001.000100',
      text: 'This approval expired or was already decided. Ask the agent again.',
      blocks: [],
    });
    // Idempotent: the entry is dropped after one edit.
    await vouchr.sweepExpired();
    assert.equal(updates.length, 1);
  });
});

test('sweep: expired prompts and unspent grants are deleted and audited (actor: system)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const audit = new Audit(db);
  const consent = new Consent(db);
  const approvals = new Approvals(db);
  const key = { teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1', credentialId: GENERATION, provider: 'acme', method: 'POST', origin: 'https://api.acme.test', host: 'api.acme.test', path: '/repos', queryHash: '', channel: 'C1', thread: 'TH1', governableChannel: 'C1' };
  await approvals.request(key); // pending, 10-minute prompt lifetime
  const granted = await approvals.request({ ...key, path: '/other' });
  await approvals.approve(granted, 'U_ADM', 1_000); // grant, 1s TTL
  // A live grant survives the sweep.
  await sweepExpired(vault, audit, consent, undefined, undefined, approvals);
  assert.equal(((await db.all(`SELECT * FROM approval_request`)) as any[]).length, 2);
  // Past both TTLs everything is reclaimed, each expiry audited with the non-human actor.
  await db.run(`UPDATE approval_request SET expires_at=0`);
  await sweepExpired(vault, audit, consent, undefined, undefined, approvals);
  assert.equal(((await db.all(`SELECT * FROM approval_request`)) as any[]).length, 0);
  const rows = (await db.all(`SELECT action, user_id, actor, meta FROM audit WHERE action='denied'`)) as any[];
  assert.equal(rows.length, 2);
  for (const r of rows) {
    assert.equal(r.user_id, 'U1');
    assert.equal(r.actor, 'system');
    assert.match(r.meta, /approval-expired/);
  }
});

// #2/#4: the ENTIRE approval flow in a group DM (MPIM), through the production Bolt adapter — middleware
// (classifies the 'mpim' + 'G…' delivery channel as ungoverned), storage (persists the personal scope),
// and revalidation (the Approve decision + the consume re-check both honor it). With NO channel enable, a
// self-approval in a group DM must prompt → approve → retry → execute, not be invalidated by deny-by-default.
test('#4 MPIM approval flow through Bolt: prompt → approve → retry executes with no channel enable', async (t) => {
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');
  const provider = approvalProvider();
  const vouchr = await createVouchr({ providers: [provider], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t) });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({ command: () => undefined, view: () => undefined, action: (id: string, h: any) => (actions[id] = h) });
  const ephemerals: any[] = [];
  const client = { chat: { postEphemeral: async (p: any) => { ephemerals.push(p); return {}; }, postMessage: async () => ({}) } } as any;
  // A verified group-DM event: id 'G…' + channel_type 'mpim' ⇒ governanceChannelOf returns null (ungoverned).
  const args: any = {
    context: {}, client,
    event: { user: 'U1', team: 'T1', channel: 'GROUPDM01', channel_type: 'mpim', thread_ts: 'TH1' },
    next: async () => {},
  };
  await vouchr.middleware(args);
  const ctx = args.context.vouchr;
  // Deliberately NO setChannelToolEnabled: deny-by-default must not reach the group DM.
  await vouchr.vault.upsert(userOwner(ID), provider.id, { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

  await withFetch(async (calls) => {
    const handle = await ctx.connect(provider.id);
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL }));
    assert.equal(e.approver, 'self');
    assert.equal(calls.length, 0, 'the unapproved write never hit the network');
    assert.equal(ephemerals.length, 1);
    assert.equal(ephemerals[0].channel, 'GROUPDM01', 'the prompt is delivered in the group DM');
    assert.equal(ephemerals[0].user, 'U1');

    // Approve (self = requester), clicking in the SAME group DM. The decision revalidation reads the
    // persisted personal scope, so deny-by-default does NOT invalidate the grant.
    await actions[APPROVAL_APPROVE_ACTION]({
      ack: async () => {},
      body: {
        team: { id: 'T1' }, user: { id: 'U1' }, channel: { id: 'GROUPDM01' },
        container: { channel_id: 'GROUPDM01', thread_ts: 'TH1' }, actions: [{ value: e.approvalId }],
      },
      client, respond: async () => {},
    });

    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL });
    assert.equal(res.status, 200, 'the approved retry executed instead of being invalidated');
    assert.equal(calls.length, 1, 'exactly one upstream call — the approved retry');
  });
});
