// #194 — the trusted broker-to-Slack recovery bridge: ConnectContext.recoverBrokerDenial maps a
// relayed broker denial (untrusted routing guidance) to the correct private Slack recovery action.
// Driven through the PUBLIC API (TEST-2): a real createVouchr, its real middleware, and — for the
// approval outcome — a real in-process createBroker sharing the same PostgreSQL schema, so the
// pending approval row is minted by the actual broker door the hybrid deployment uses.
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { ErrorCode as SlackErrorCode, WebClient } from '@slack/web-api';
import { openTestDb, testDbUrl } from './support/pg';
import { identityConfig, signIdentity } from './support/identity';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig, writeChannelMode } from '../src/core/channelConfig';
import { setChannelCredentialMode } from '../src/core/channelCredential';
import { defineProvider, ProviderRegistry, type Provider } from '../src/core/providers';
import { channelOwner, userOwner } from '../src/core/owner';
import { Policy } from '../src/core/policy';
import { PolicyDeniedError } from '../src/core/authz';
import { SessionGrants } from '../src/core/session';
import { createBroker } from '../src/adapters/http/broker';
import {
  APPROVAL_AUDIENCE_RESOLUTION_DEADLINE_MS,
  ConnectContext,
  createVouchr,
  type BrokerDenialRecovery,
} from '../src/adapters/bolt';
import {
  APPROVAL_APPROVE_ACTION,
  APPROVE_SESSION_ACTION,
  SETUP_KEY_ACTION,
} from '../src/adapters/blocks';
import type { Db } from '../src/core/db';
import { openDb } from '../src/core/db';
import {
  POSTGRES_NOW_MS_SQL,
  PROMPT_REDELIVERY_DEBOUNCE_MS,
} from '../src/core/interaction';

const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const TOKEN = 'sk-secret-token';

function slackWebApiError(code: SlackErrorCode): Error {
  const error = new Error('foreign Slack detail must not escape');
  if (code === SlackErrorCode.PlatformError) {
    return Object.assign(error, { code, data: { ok: false, error: 'invalid_auth' } });
  }
  if (code === SlackErrorCode.RateLimitedError) return Object.assign(error, { code, retryAfter: 1 });
  return Object.assign(error, { code, original: error });
}

const oauthGh = defineProvider({
  id: 'gh', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

const keyProv = defineProvider({
  id: 'vaulted', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false,
});

const approvalProv = (approver: 'self' | 'admin' = 'self'): Provider => defineProvider({
  id: 'acme', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.acme.test'], egressMethods: ['GET', 'POST'],
  approval: { approver },
  refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

/** Real createVouchr + middleware + registered action handlers, Slack transport faked. */
async function harness(t: TestContext, o: {
  providers?: Provider[];
  slackAdmins?: string[];
  members?: string[];
  policy?: Policy;
  channelInfo?: Record<string, unknown>;
  postMessage?: (payload: any, attempt: number) => Promise<unknown>;
  postEphemeral?: (payload: any, attempt: number) => Promise<unknown>;
  memberPage?: (payload: any, attempt: number) => Promise<unknown>;
  userInfo?: (payload: any, attempt: number) => Promise<unknown>;
  clientToken?: string;
  slackClientOptions?: Record<string, unknown>;
} = {}) {
  const key = randomBytes(32);
  process.env.VOUCHR_MASTER_KEY = key.toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: o.providers ?? [oauthGh],
    baseUrl: 'http://127.0.0.1:1',
    db,
    policy: o.policy,
    slackClientOptions: o.slackClientOptions,
  });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, h: any) => { actions[id] = h; },
  });
  const ephemerals: any[] = [];
  const dms: any[] = [];
  const admins = new Set(o.slackAdmins ?? []);
  const members = o.members ?? ['U1'];
  let messageAttempts = 0;
  let ephemeralAttempts = 0;
  let memberAttempts = 0;
  let userInfoAttempts = 0;
  const client = {
    ...(o.clientToken ? { token: o.clientToken } : {}),
    users: { info: async (payload: any) => {
      userInfoAttempts += 1;
      return o.userInfo?.(payload, userInfoAttempts)
        ?? { user: { is_admin: admins.has(payload.user) } };
    } },
    conversations: {
      info: async ({ channel }: any) => ({
        channel: { id: channel, is_channel: true, creator: 'UCREATOR', ...o.channelInfo },
      }),
      members: async (payload: any) => {
        memberAttempts += 1;
        return o.memberPage?.(payload, memberAttempts) ?? { members };
      },
    },
    chat: {
      postEphemeral: async (p: any) => {
        ephemerals.push(p);
        ephemeralAttempts += 1;
        return o.postEphemeral?.(p, ephemeralAttempts) ?? {};
      },
      postMessage: async (p: any) => {
        dms.push(p);
        messageAttempts += 1;
        return o.postMessage?.(p, messageAttempts) ?? {};
      },
    },
  } as any;
  /** A ConnectContext built by the REAL middleware from a verified-event shape. */
  const context = async (over: {
    user?: string; channel?: string | null; thread?: string | null;
  } = {}): Promise<ConnectContext> => {
    const channel = over.channel === null ? undefined : (over.channel ?? 'C1');
    const thread = over.thread === null ? undefined : (over.thread ?? 'TH1');
    const args: any = {
      context: {},
      client,
      event: {
        team: 'T1',
        user: over.user ?? 'U1',
        ...(channel ? { channel } : {}),
        ...(thread ? { thread_ts: thread } : {}),
      },
      next: async () => {},
    };
    await vouchr.middleware(args);
    return args.context.vouchr as ConnectContext;
  };
  const click = async (actionId: string, o2: {
    value: string; user?: string; channel?: string; thread?: string | null;
  }) => {
    const responses: any[] = [];
    const channel = o2.channel ?? 'C1';
    const thread = o2.thread === undefined ? 'TH1' : o2.thread;
    await actions[actionId]({
      ack: async () => {},
      body: {
        team: { id: 'T1' },
        user: { id: o2.user ?? 'U1' },
        channel: { id: channel },
        container: { channel_id: channel, ...(thread ? { thread_ts: thread } : {}) },
        actions: [{ value: o2.value }],
      },
      client,
      respond: async (p: any) => { responses.push(p); },
    });
    return responses;
  };
  return { db, key, vouchr, actions, client, ephemerals, dms, admins, members, context, click };
}

/** Stub global fetch (TEST-3), recording outbound calls; ALWAYS restored in finally. */
async function withFetch<T>(fn: (calls: { url: string }[]) => Promise<T>): Promise<T> {
  const real = globalThis.fetch;
  const calls: { url: string }[] = [];
  globalThis.fetch = (async (url: any) => {
    calls.push({ url: String(url) });
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = real;
  }
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

/** Boot a REAL in-process broker over the harness's schema and collect one approval_required
 * denial for a POST — the exact wire body a hybrid worker would relay to the bridge. */
async function brokerApprovalDenial(
  t: TestContext,
  db: Db,
  key: Buffer,
  provider: Provider,
  options: { owner?: 'user' | 'channel'; channelConfig?: ChannelConfig } = {},
): Promise<{
  denial: any;
  deny: () => Promise<{ status: number; json: any }>;
}> {
  const SECRET = 'bridge-test-secret';
  const owner = options.owner ?? 'user';
  const server = createBroker({
    providers: [provider],
    vault: new Vault(db, key),
    audit: new Audit(db),
    db,
    identitySecret: identityConfig(SECRET),
    allowWrites: true,
    channelConfig: options.channelConfig,
  });
  await new Promise<void>((r) => server.listen(0, r));
  t.after(() => new Promise((r) => server.close(() => r(null))));
  const port = (server.address() as any).port;
  const deny = async () => post(port, '/v1/fetch', {
    handle: { provider: provider.id, owner },
    method: 'POST',
    path: '/repos',
    body: '{}',
    identityToken: signIdentity(
      {
        teamId: 'T1', userId: 'U1', channel: 'C1', threadTs: 'TH1',
        ...(owner === 'channel' ? { ownerKind: 'channel' as const, channelEligible: true } : {}),
        exp: Date.now() + 60_000, jti: randomUUID(),
      },
      SECRET,
    ),
  });
  const first = await deny();
  assert.equal(first.status, 403);
  assert.equal(first.json.code, 'approval_required');
  assert.equal(typeof first.json.approvalId, 'string');
  return { denial: first.json, deny };
}

// ── input validation: untrusted denial bodies fail closed ─────────────────────────────────────────

test('bridge: non-bridgeable and malformed denials change nothing', async (t) => {
  const h = await harness(t);
  const ctx = await h.context();
  for (const denial of [null, undefined, 'not_connected', {}, { code: 'nope' }, { code: 42 }, { code: 'rate_limited' }]) {
    const r = await ctx.recoverBrokerDenial('gh', denial);
    assert.deepEqual(r, { status: 'not_bridgeable' } satisfies BrokerDenialRecovery);
  }
  assert.equal(h.ephemerals.length, 0);
  assert.equal(h.dms.length, 0);
  assert.equal((await h.db.all('SELECT 1 AS x FROM consent_request')).length, 0);
  assert.equal((await h.db.all('SELECT 1 AS x FROM audit')).length, 0);
});

test('bridge: the provider is registry-validated before anything (SEC-4)', async (t) => {
  const h = await harness(t);
  const ctx = await h.context();
  await assert.rejects(ctx.recoverBrokerDenial('unknown', { code: 'not_connected' }));
  assert.equal(h.ephemerals.length, 0);
  assert.equal((await h.db.all('SELECT 1 AS x FROM audit')).length, 0);
});

// ── not_connected, user owner → the existing private connect/key flow ─────────────────────────────

test('bridge: connect prompts deduplicate rapid retries and recover after an ephemeral vanishes', async (t) => {
  const h = await harness(t);
  const ctx = await h.context();
  const first = await ctx.recoverBrokerDenial('gh', { code: 'not_connected', recovery: 'connect' });
  assert.deepEqual(first, { status: 'connect_prompted', provider: 'gh', promptState: 'posted' });
  assert.equal(h.ephemerals.length, 1);
  assert.equal(h.ephemerals[0].channel, 'C1');
  assert.equal(h.ephemerals[0].user, 'U1');
  // A repeated relay of the same denial reuses the live consent generation instead of spamming.
  const again = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(again, { status: 'connect_prompted', provider: 'gh', promptState: 'reused' });
  assert.equal(h.ephemerals.length, 1, 'no duplicate prompt');
  assert.equal((await h.db.all("SELECT 1 AS x FROM consent_request WHERE superseded_at IS NULL")).length, 1);

  await h.db.run(
    `UPDATE consent_request SET delivered_at=${POSTGRES_NOW_MS_SQL}-?
      WHERE superseded_at IS NULL`,
    [PROMPT_REDELIVERY_DEBOUNCE_MS + 1_000],
  );
  const recovered = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(recovered, {
    status: 'connect_prompted', provider: 'gh', promptState: 'posted',
  });
  assert.equal(h.ephemerals.length, 2, 'the vanished ephemeral is re-posted after the debounce');
});

test('bridge: an aged durable connect DM remains deduplicated', async (t) => {
  const h = await harness(t);
  const first = await (await h.context({ channel: null, thread: null }))
    .recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(first, {
    status: 'connect_prompted', provider: 'gh', promptState: 'posted',
  });
  assert.equal(h.ephemerals.length, 0);
  assert.equal(h.dms.length, 1);

  await h.db.run(
    `UPDATE consent_request SET delivered_at=${POSTGRES_NOW_MS_SQL}-?
      WHERE superseded_at IS NULL`,
    [PROMPT_REDELIVERY_DEBOUNCE_MS + 1_000],
  );
  const again = await (await h.context({ channel: null, thread: null }))
    .recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(again, {
    status: 'connect_prompted', provider: 'gh', promptState: 'reused',
  });
  assert.equal(h.dms.length, 1, 'a persistent DM is not posted again after the ephemeral debounce');
});

test('bridge: user not_connected for a key provider posts the key-setup prompt', async (t) => {
  const h = await harness(t, { providers: [keyProv] });
  const ctx = await h.context();
  const r = await ctx.recoverBrokerDenial('vaulted', { code: 'not_connected' });
  assert.deepEqual(r, { status: 'connect_prompted', provider: 'vaulted', promptState: 'posted' });
  assert.equal(h.ephemerals.length, 1);
  const button = JSON.stringify(h.ephemerals[0].blocks);
  assert.ok(button.includes(SETUP_KEY_ACTION), 'key setup button posted');
  assert.equal((await h.db.all('SELECT 1 AS x FROM user_provisioning_request')).length, 1);
  const again = await (await h.context()).recoverBrokerDenial('vaulted', { code: 'not_connected' });
  assert.deepEqual(again, {
    status: 'connect_prompted', provider: 'vaulted', promptState: 'reused',
  });
  assert.equal(h.ephemerals.length, 1, 'the delivered key-setup prompt is not reposted');

  await h.db.run(
    `UPDATE user_provisioning_request SET delivered_at=${POSTGRES_NOW_MS_SQL}-?`,
    [PROMPT_REDELIVERY_DEBOUNCE_MS + 1_000],
  );
  const recovered = await (await h.context()).recoverBrokerDenial('vaulted', {
    code: 'not_connected',
  });
  assert.deepEqual(recovered, {
    status: 'connect_prompted', provider: 'vaulted', promptState: 'posted',
  });
  assert.equal(h.ephemerals.length, 2, 'the vanished key-setup ephemeral is re-posted');
});

test('bridge: an aged durable key-setup DM remains deduplicated', async (t) => {
  const h = await harness(t, { providers: [keyProv] });
  const first = await (await h.context({ channel: null, thread: null }))
    .recoverBrokerDenial('vaulted', { code: 'not_connected' });
  assert.deepEqual(first, {
    status: 'connect_prompted', provider: 'vaulted', promptState: 'posted',
  });
  assert.equal(h.dms.length, 1);

  await h.db.run(
    `UPDATE user_provisioning_request SET delivered_at=${POSTGRES_NOW_MS_SQL}-?`,
    [PROMPT_REDELIVERY_DEBOUNCE_MS + 1_000],
  );
  const again = await (await h.context({ channel: null, thread: null }))
    .recoverBrokerDenial('vaulted', { code: 'not_connected' });
  assert.deepEqual(again, {
    status: 'connect_prompted', provider: 'vaulted', promptState: 'reused',
  });
  assert.equal(h.dms.length, 1, 'a persistent key-setup DM is not posted again');
});

test('bridge: key-setup delivery deduplicates across two PostgreSQL replicas', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const key = randomBytes(32);
  const posts: any[] = [];
  const client = {
    chat: { postEphemeral: async (payload: any) => { posts.push(payload); return {}; } },
  } as any;
  const registry = new ProviderRegistry([keyProv]);
  const context = (db: Db) => new ConnectContext({
    identity: ID,
    channel: 'C1',
    thread: 'TH1',
    client,
    registry,
    vault: new Vault(db, key),
    audit: new Audit(db),
    consent: new Consent(db),
    policy: new Policy(),
    redirectUri: 'http://127.0.0.1/callback',
    channelConfig: new ChannelConfig(db),
  });

  const first = await context(dbA).recoverBrokerDenial('vaulted', { code: 'not_connected' });
  const second = await context(dbB).recoverBrokerDenial('vaulted', { code: 'not_connected' });
  assert.deepEqual(first, { status: 'connect_prompted', provider: 'vaulted', promptState: 'posted' });
  assert.deepEqual(second, { status: 'connect_prompted', provider: 'vaulted', promptState: 'reused' });
  assert.equal(posts.length, 1);
  assert.equal(
    (await dbB.get<{ delivered_at: number | null }>(
      'SELECT delivered_at FROM user_provisioning_request',
    ))?.delivered_at != null,
    true,
  );
});

test('bridge: definite key-prompt rejection releases its lease for a clean retry', async (t) => {
  const h = await harness(t, {
    providers: [keyProv],
    postEphemeral: async (_payload, attempt) => {
      if (attempt === 1) throw slackWebApiError(SlackErrorCode.PlatformError);
      return {};
    },
  });
  await assert.rejects(
    (await h.context()).recoverBrokerDenial('vaulted', { code: 'not_connected' }),
    (error: any) => error?.recovery === 'fix_configuration'
      && !error.message.includes('foreign Slack detail'),
  );
  assert.deepEqual(
    await h.db.get('SELECT delivery_token,delivered_at FROM user_provisioning_request'),
    { delivery_token: null, delivered_at: null },
  );

  const retry = await (await h.context()).recoverBrokerDenial('vaulted', { code: 'not_connected' });
  assert.deepEqual(retry, { status: 'connect_prompted', provider: 'vaulted', promptState: 'posted' });
  assert.equal(h.ephemerals.length, 2, 'one rejected attempt and one successful retry');
});

test('bridge: ambiguous key-prompt delivery retains its lease and cannot duplicate', async (t) => {
  const h = await harness(t, {
    providers: [keyProv],
    postEphemeral: async () => { throw slackWebApiError(SlackErrorCode.RequestError); },
  });
  await assert.rejects(
    (await h.context()).recoverBrokerDenial('vaulted', { code: 'not_connected' }),
    (error: any) => error?.recovery === 'retry_later',
  );
  assert.ok(
    (await h.db.get<{ delivery_token: string | null }>(
      'SELECT delivery_token FROM user_provisioning_request',
    ))?.delivery_token,
  );
  await assert.rejects(
    (await h.context()).recoverBrokerDenial('vaulted', { code: 'not_connected' }),
    (error: any) => error?.recovery === 'retry_later' && /already being delivered/i.test(error.message),
  );
  assert.equal(h.ephemerals.length, 1, 'the retained cross-replica lease suppresses a second post');
});

test('bridge: key-setup posts use the bounded Slack client and operator transport', async (t) => {
  const seen: any[] = [];
  const prototype = WebClient.prototype as any;
  const realApiCall = prototype.apiCall;
  prototype.apiCall = async function (this: any) {
    seen.push({
      retries: this.retryConfig?.retries,
      rejectRateLimited: this.rejectRateLimitedCalls,
      apiUrl: this.slackApiUrl,
    });
    return { ok: true };
  };
  try {
    const h = await harness(t, {
      providers: [keyProv],
      clientToken: 'xoxb-key-setup-test',
      slackClientOptions: { slackApiUrl: 'https://slack-proxy.internal/api/' },
    });
    const result = await (await h.context()).recoverBrokerDenial('vaulted', { code: 'not_connected' });
    assert.deepEqual(result, {
      status: 'connect_prompted', provider: 'vaulted', promptState: 'posted',
    });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].retries, 0);
    assert.equal(seen[0].rejectRateLimited, true);
    assert.equal(seen[0].apiUrl, 'https://slack-proxy.internal/api/');
  } finally {
    prototype.apiCall = realApiCall;
  }
});

test('bridge: a stale not_connected relay resolves when the user is already connected', async (t) => {
  const h = await harness(t);
  await h.vouchr.vault.upsert(userOwner(ID), 'gh', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const r = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(r, { status: 'resolved', provider: 'gh' });
  assert.equal(h.ephemerals.length, 0, 'nothing to prompt');
});

// ── session_approval_required → the thread-scoped session prompt ──────────────────────────────────

test('bridge: session denial posts ONE in-thread prompt; the click grants; a rerun resolves', async (t) => {
  const h = await harness(t);
  await writeChannelMode(new ChannelConfig(h.db), 'T1', 'C1', 'gh', 'session');
  await h.vouchr.vault.upsert(userOwner(ID), 'gh', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const denial = { code: 'session_approval_required', recovery: 'request_approval' };
  const first = await (await h.context()).recoverBrokerDenial('gh', denial);
  assert.deepEqual(first, { status: 'session_prompted', provider: 'gh' });
  assert.equal(h.ephemerals.length, 1);
  assert.equal(h.ephemerals[0].thread_ts, 'TH1', 'prompt is thread-scoped');
  assert.ok(JSON.stringify(h.ephemerals[0].blocks).includes(APPROVE_SESSION_ACTION));
  const rows = await h.db.all<any>('SELECT id FROM session_request', []);
  assert.equal(rows.length, 1);

  // Repeated relays converge on the one live request without re-posting.
  const again = await (await h.context()).recoverBrokerDenial('gh', denial);
  assert.deepEqual(again, { status: 'session_prompted', provider: 'gh' });
  assert.equal(h.ephemerals.length, 1, 'no duplicate prompt');

  // The click re-decides authority at the mutation (existing handler), then the bridge resolves.
  await h.click(APPROVE_SESSION_ACTION, { value: rows[0].id });
  const after = await (await h.context()).recoverBrokerDenial('gh', denial);
  assert.deepEqual(after, { status: 'resolved', provider: 'gh' });
});

test('bridge: session denial without a thread yields the fixed off-thread guidance', async (t) => {
  const h = await harness(t);
  await writeChannelMode(new ChannelConfig(h.db), 'T1', 'C1', 'gh', 'session');
  await h.vouchr.vault.upsert(userOwner(ID), 'gh', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const ctx = await h.context({ thread: null });
  await assert.rejects(
    ctx.recoverBrokerDenial('gh', { code: 'session_approval_required' }),
    /thread-scoped session/,
  );
  assert.equal(h.ephemerals.length, 0);
});

// ── not_connected, shared owner → direct an eligible admin to channel configuration ───────────────

async function sharedModeVia(h: Awaited<ReturnType<typeof harness>>, adminId: string, providerId = 'gh') {
  // The audited admin mutation (writes the 'config' row lastChannelConfigActor reads).
  await setChannelCredentialMode({
    vault: h.vouchr.vault,
    audit: h.vouchr.audit,
    channelConfig: new ChannelConfig(h.db),
    identity: { ...ID, userId: adminId },
    channel: 'C1',
    providerId,
    mode: 'shared',
    issuance: await h.vouchr.vault.userProvisioningIssuedAt(),
  });
}

test('bridge: shared-owner miss directs an admin-eligible actor in place (never a personal prompt)', async (t) => {
  const h = await harness(t, { slackAdmins: ['U1'] });
  await sharedModeVia(h, 'UADM');
  const r = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected', recovery: 'fix_configuration' });
  assert.deepEqual(r, { status: 'configuration_required', provider: 'gh' });
  assert.equal(h.ephemerals.length, 1);
  assert.match(h.ephemerals[0].text, /\/vouchr configure gh/);
  assert.equal(h.dms.length, 0, 'the actor IS the eligible admin — no extra DM');
  assert.equal((await h.db.all('SELECT 1 AS x FROM consent_request')).length, 0, 'no personal connect flow');
});

test('bridge: shared-owner miss DMs the responsible admin once per window for a non-admin actor', async (t) => {
  const h = await harness(t, { slackAdmins: ['UADM'], members: ['U1', 'UADM'] });
  await sharedModeVia(h, 'UADM');
  const denial = { code: 'not_connected', recovery: 'fix_configuration' };
  const r = await (await h.context()).recoverBrokerDenial('gh', denial);
  assert.deepEqual(r, { status: 'configuration_required', provider: 'gh' });
  assert.equal(h.dms.length, 1, 'the last configuring admin is asked');
  assert.equal(h.dms[0].channel, 'UADM');
  assert.match(h.dms[0].text, /\/vouchr configure gh/);
  assert.match(h.ephemerals[0].text, /has been asked/);
  assert.ok(!h.ephemerals[0].text.includes(TOKEN));

  // Repeated relays do not spam: the 24h notification window is already claimed.
  const again = await (await h.context()).recoverBrokerDenial('gh', denial);
  assert.deepEqual(again, { status: 'configuration_required', provider: 'gh' });
  assert.equal(h.dms.length, 1, 'debounced');
  assert.match(
    h.ephemerals[1].text,
    /may already have been notified/,
    'an existing claim never overstates that Slack confirmed delivery',
  );
});

test('bridge: shared-owner miss with no known admin gives the actor the ask-an-admin step', async (t) => {
  const h = await harness(t);
  // Mode written without the audited mutation: no 'config' row → no responsible admin on record.
  await writeChannelMode(new ChannelConfig(h.db), 'T1', 'C1', 'gh', 'shared');
  const r = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(r, { status: 'configuration_required', provider: 'gh' });
  assert.equal(h.dms.length, 0);
  assert.match(h.ephemerals[0].text, /Ask a channel admin to run/);
});

test('bridge: shared-owner miss never DMs a former or removed configuring admin', async (t) => {
  for (const scenario of [
    { name: 'demoted', slackAdmins: [] as string[], members: ['U1', 'UOLD'] },
    { name: 'removed', slackAdmins: ['UOLD'], members: ['U1'] },
  ]) {
    await t.test(scenario.name, async (st) => {
      const h = await harness(st, {
        slackAdmins: scenario.slackAdmins,
        members: scenario.members,
      });
      await sharedModeVia(h, 'UOLD');
      const r = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
      assert.deepEqual(r, { status: 'configuration_required', provider: 'gh' });
      assert.equal(h.dms.length, 0, 'stale audit identity receives no channel disclosure');
      assert.match(h.ephemerals[0].text, /Ask a channel admin to run/);
    });
  }
});

test('bridge: shared-owner miss rechecks channel eligibility before configuration direction', async (t) => {
  const h = await harness(t, {
    slackAdmins: ['U1'],
    channelInfo: { is_ext_shared: true },
  });
  await sharedModeVia(h, 'U1');
  await assert.rejects(
    (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' }),
    /externally shared channels/,
  );
  assert.equal(h.dms.length, 0);
  assert.equal(h.ephemerals.length, 0);
});

test('bridge: ambiguous admin DM retains the debounce claim and cannot duplicate', async (t) => {
  const h = await harness(t, {
    slackAdmins: ['UADM'],
    members: ['U1', 'UADM'],
    postMessage: async () => { throw slackWebApiError(SlackErrorCode.RequestError); },
  });
  await sharedModeVia(h, 'UADM');

  const first = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(first, { status: 'configuration_required', provider: 'gh' });
  assert.equal(h.dms.length, 1, 'one ambiguous send was attempted');
  assert.match(h.ephemerals[0].text, /may already have been notified/);
  assert.equal(
    (await h.db.all("SELECT 1 AS x FROM notification_state WHERE type='not_configured'")).length,
    1,
    'ambiguous acceptance keeps the cross-replica debounce claim',
  );

  const again = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(again, { status: 'configuration_required', provider: 'gh' });
  assert.equal(h.dms.length, 1, 'the retained claim prevents duplicate delivery');
});

test('bridge: definite admin DM rejection releases the debounce claim for retry', async (t) => {
  for (const code of [SlackErrorCode.PlatformError, SlackErrorCode.RateLimitedError]) {
    await t.test(code, async (st) => {
      const h = await harness(st, {
        slackAdmins: ['UADM'],
        members: ['U1', 'UADM'],
        postMessage: async (_payload, attempt) => {
          if (attempt === 1) throw slackWebApiError(code);
          return {};
        },
      });
      await sharedModeVia(h, 'UADM');

      const first = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
      assert.deepEqual(first, { status: 'configuration_required', provider: 'gh' });
      assert.match(h.ephemerals[0].text, /Ask a channel admin to run/);
      assert.equal(
        (await h.db.all("SELECT 1 AS x FROM notification_state WHERE type='not_configured'")).length,
        0,
        'known non-delivery releases the claim',
      );

      const again = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
      assert.deepEqual(again, { status: 'configuration_required', provider: 'gh' });
      assert.equal(h.dms.length, 2, 'the next relay retries the known-undelivered DM');
      assert.match(h.ephemerals[1].text, /has been asked/);
    });
  }
});

test('bridge: shared-owner relay resolves once the channel credential exists', async (t) => {
  const h = await harness(t);
  await sharedModeVia(h, 'UADM');
  await h.vouchr.vault.upsert(channelOwner('T1', 'C1'), 'gh', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const r = await (await h.context()).recoverBrokerDenial('gh', { code: 'not_connected' });
  assert.deepEqual(r, { status: 'resolved', provider: 'gh' });
  assert.equal(h.ephemerals.length, 0);
  assert.equal(h.dms.length, 0);
});

// ── approval_required → the self/admin decision surface, hydrated from the stored row ────────────

test('bridge: broker approval denial delivers ONE self decision surface; approve → single-use grant', async (t) => {
  const provider = approvalProv('self');
  const h = await harness(t, { providers: [provider] });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial, deny } = await brokerApprovalDenial(t, h.db, h.key, provider);

  const first = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(first, { status: 'approval_prompted', provider: 'acme', approver: 'self' });
  assert.equal(h.ephemerals.length, 1);
  assert.equal(h.ephemerals[0].user, 'U1', 'self approval goes to the requester');
  assert.equal(h.ephemerals[0].thread_ts, 'TH1', 'delivered into the thread the action is bound to');
  const rendered = JSON.stringify(h.ephemerals[0].blocks);
  assert.ok(rendered.includes(APPROVAL_APPROVE_ACTION));
  assert.ok(rendered.includes(denial.approvalId), 'button carries only the opaque id');
  assert.ok(!rendered.includes(TOKEN), 'no secret in the prompt (SEC-1)');

  // A repeated relay converges: the delivery lease reports delivered, nothing re-posts.
  const again = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(again, { status: 'approval_prompted', provider: 'acme', approver: 'self' });
  assert.equal(h.ephemerals.length, 1, 'no duplicate prompt');

  await h.db.run(
    `UPDATE approval_request SET delivered_at=${POSTGRES_NOW_MS_SQL}-? WHERE id=?`,
    [PROMPT_REDELIVERY_DEBOUNCE_MS + 1_000, denial.approvalId],
  );
  const recovered = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(recovered, {
    status: 'approval_prompted', provider: 'acme', approver: 'self',
  });
  assert.equal(h.ephemerals.length, 2, 'the vanished approval ephemeral is re-posted');

  // The existing click handler re-decides everything at the mutation; the grant is single-use.
  await h.click(APPROVAL_APPROVE_ACTION, { value: denial.approvalId });
  const granted = await h.db.get<any>("SELECT status FROM approval_request WHERE id=?", [denial.approvalId]);
  assert.equal(granted?.status, 'granted');

  // The decided id no longer names a live pending approval: relaying it again is stale.
  const stale = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(stale, { status: 'stale', provider: 'acme' });

  // And the broker retry mints a FRESH pending id afterward (single-use, no revival).
  await withFetch(async (calls) => {
    const consumed = await deny();
    assert.equal(consumed.status, 200, 'granted action executes once');
    assert.equal(calls.length, 1, 'exactly one call reached the wire');
    const reprompt = await deny();
    assert.equal(reprompt.status, 403);
    assert.notEqual(reprompt.json.approvalId, denial.approvalId);
  });
});

test('bridge: admin approval denial fans out to eligible admins only', async (t) => {
  const provider = approvalProv('admin');
  const h = await harness(t, { providers: [provider], slackAdmins: ['UADM'], members: ['U1', 'U2', 'UADM'] });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider);
  const r = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(r, { status: 'approval_prompted', provider: 'acme', approver: 'admin' });
  assert.equal(h.ephemerals.length, 1, 'one eligible admin, one prompt');
  assert.equal(h.ephemerals[0].user, 'UADM');
});

test('bridge: approval delivery follows the current admin audience, not an old delivered marker', async (t) => {
  const provider = approvalProv('admin');
  const h = await harness(t, {
    providers: [provider],
    slackAdmins: ['UOLD'],
    members: ['U1', 'UOLD'],
  });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider);

  const first = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(first, { status: 'approval_prompted', provider: 'acme', approver: 'admin' });
  assert.deepEqual(h.ephemerals.map((post) => post.user), ['UOLD']);
  const oldAudience = (await h.db.get<{ delivery_audience: string }>(
    'SELECT delivery_audience FROM approval_request WHERE id=?',
    [denial.approvalId],
  ))?.delivery_audience;

  h.admins.delete('UOLD');
  h.admins.add('UNEW');
  h.members.splice(0, h.members.length, 'U1', 'UNEW');
  const next = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(next, { status: 'approval_prompted', provider: 'acme', approver: 'admin' });
  assert.deepEqual(
    h.ephemerals.map((post) => post.user),
    ['UOLD', 'UNEW'],
    'the newly eligible admin receives a usable surface despite the old delivery',
  );
  const newAudience = (await h.db.get<{ delivery_audience: string }>(
    'SELECT delivery_audience FROM approval_request WHERE id=?',
    [denial.approvalId],
  ))?.delivery_audience;
  assert.notEqual(newAudience, oldAudience, 'the persisted delivery is bound to the recipient set');
});

test('bridge: a never-settling member read times out before approval delivery is claimed', async (t) => {
  const provider = approvalProv('admin');
  let nowNs = 0n;
  const h = await harness(t, {
    providers: [provider],
    memberPage: async () => {
      nowNs = BigInt(APPROVAL_AUDIENCE_RESOLUTION_DEADLINE_MS + 1) * 1_000_000n;
      return new Promise(() => {});
    },
  });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider);
  const hrtime = process.hrtime as typeof process.hrtime & { bigint: () => bigint };
  const realHrtime = hrtime.bigint;
  hrtime.bigint = () => nowNs;
  try {
    await assert.rejects(
      (await h.context()).recoverBrokerDenial('acme', denial),
      (error: any) => error?.recovery === 'retry_later'
        && /current approval recipients/i.test(error.message),
    );
  } finally {
    hrtime.bigint = realHrtime;
  }
  assert.equal(h.ephemerals.length, 0);
  assert.deepEqual(
    await h.db.get(
      'SELECT delivery_token,delivery_audience FROM approval_request WHERE id=?',
      [denial.approvalId],
    ),
    { delivery_token: null, delivery_audience: null },
  );
});

test('bridge: multi-page large-channel admin resolution fails closed on its overall deadline', async (t) => {
  const provider = approvalProv('admin');
  let nowNs = 0n;
  let pages = 0;
  let adminReads = 0;
  const h = await harness(t, {
    providers: [provider],
    memberPage: async ({ cursor }) => {
      pages += 1;
      return cursor
        ? { members: Array.from({ length: 1_000 }, (_, i) => `U_B_${i}`) }
        : {
            members: Array.from({ length: 1_000 }, (_, i) => `U_A_${i}`),
            response_metadata: { next_cursor: 'page-2' },
          };
    },
    userInfo: async () => {
      adminReads += 1;
      nowNs = BigInt(APPROVAL_AUDIENCE_RESOLUTION_DEADLINE_MS + 1) * 1_000_000n;
      return new Promise(() => {});
    },
  });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider);
  const hrtime = process.hrtime as typeof process.hrtime & { bigint: () => bigint };
  const realHrtime = hrtime.bigint;
  hrtime.bigint = () => nowNs;
  try {
    await assert.rejects(
      (await h.context()).recoverBrokerDenial('acme', denial),
      (error: any) => error?.recovery === 'retry_later',
    );
  } finally {
    hrtime.bigint = realHrtime;
  }
  assert.equal(pages, 2, 'the complete paginated member set was attempted');
  assert.ok(adminReads > 0 && adminReads <= 16, 'admin work is concurrency-capped');
  assert.equal(h.ephemerals.length, 0);
  assert.deepEqual(
    await h.db.get(
      'SELECT delivery_token,delivery_audience FROM approval_request WHERE id=?',
      [denial.approvalId],
    ),
    { delivery_token: null, delivery_audience: null },
    'a partial audience never reaches the delivery lease',
  );
});

test('bridge: approval references are lookup handles — mismatches and garbage are stale', async (t) => {
  const provider = approvalProv('self');
  const h = await harness(t, { providers: [provider] });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider);

  // Garbage / absent / non-string ids.
  for (const approvalId of [undefined, 42, 'not-a-uuid', randomUUID()]) {
    const r = await (await h.context()).recoverBrokerDenial('acme', { code: 'approval_required', approvalId });
    assert.deepEqual(r, { status: 'stale', provider: 'acme' });
  }
  // A different verified context (user, channel) never delivers someone else's approval.
  const otherUser = await (await h.context({ user: 'U2' })).recoverBrokerDenial('acme', denial);
  assert.deepEqual(otherUser, { status: 'stale', provider: 'acme' });
  const otherChannel = await (await h.context({ channel: 'C9' })).recoverBrokerDenial('acme', denial);
  assert.deepEqual(otherChannel, { status: 'stale', provider: 'acme' });
  assert.equal(h.ephemerals.length, 0, 'nothing was delivered for any mismatch');
});

test('bridge: an approval denial is bound to the verified thread before delivery', async (t) => {
  const provider = approvalProv('self');
  const h = await harness(t, { providers: [provider] });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider);

  const wrongThread = await (await h.context({ thread: 'TH9' })).recoverBrokerDenial('acme', denial);
  assert.deepEqual(wrongThread, { status: 'stale', provider: 'acme' });
  assert.equal(h.ephemerals.length, 0, 'another thread cannot route the stored action surface');
  assert.ok(
    await h.db.get('SELECT 1 AS x FROM approval_request WHERE id=?', [denial.approvalId]),
    'a wrong-context lookup does not destroy the legitimate thread request',
  );
});

test('bridge: an expired session makes the pending action stale before approval delivery', async (t) => {
  const provider = approvalProv('self');
  const h = await harness(t, { providers: [provider] });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const credentialId = await h.vouchr.vault.liveId(userOwner(ID), 'acme');
  assert.ok(credentialId);
  const channelConfig = new ChannelConfig(h.db);
  await writeChannelMode(channelConfig, 'T1', 'C1', 'acme', 'session');
  await new SessionGrants(h.db).grant(ID, 'C1', 'TH1', 'acme', 60_000, credentialId);
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider, { channelConfig });

  await h.db.run(
    'DELETE FROM session_grant WHERE team_id=? AND channel=? AND thread=? AND user_id=? AND provider=?',
    ['T1', 'C1', 'TH1', 'U1', 'acme'],
  );
  const r = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(r, { status: 'stale', provider: 'acme' });
  assert.equal(h.ephemerals.length, 0, 'no unusable action prompt is posted after session expiry');
  assert.equal(
    await h.db.get('SELECT 1 AS x FROM approval_request WHERE id=?', [denial.approvalId]),
    undefined,
    'the invalid pending action cannot revive if a session is granted later',
  );
});

test('bridge: shared approval rechecks live channel class and requester membership', async (t) => {
  for (const scenario of [
    { name: 'Slack Connect conversion', external: true, channelInfo: { is_ext_shared: true }, members: ['U1', 'UADM'] },
    { name: 'requester removed', external: false, channelInfo: {}, members: ['UADM'] },
  ]) {
    await t.test(scenario.name, async (st) => {
      const provider = approvalProv('self');
      const h = await harness(st, {
        providers: [provider],
        slackAdmins: ['UADM'],
        channelInfo: scenario.channelInfo,
        members: scenario.members,
      });
      await sharedModeVia(h, 'UADM', 'acme');
      await h.vouchr.vault.upsert(channelOwner('T1', 'C1'), 'acme', {
        accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
      });
      const { denial } = await brokerApprovalDenial(st, h.db, h.key, provider, {
        owner: 'channel',
        channelConfig: new ChannelConfig(h.db),
      });

      if (scenario.external) {
        await assert.rejects(
          (await h.context()).recoverBrokerDenial('acme', denial),
          /externally shared channels/,
        );
      } else {
        const r = await (await h.context()).recoverBrokerDenial('acme', denial);
        assert.deepEqual(r, { status: 'stale', provider: 'acme' });
      }
      assert.equal(h.ephemerals.length, 0);
      assert.equal(
        await h.db.get('SELECT 1 AS x FROM approval_request WHERE id=?', [denial.approvalId]),
        undefined,
      );
    });
  }
});

test('bridge: cyclic Slack membership pagination fails closed before prompt delivery', async (t) => {
  const provider = approvalProv('self');
  const h = await harness(t, {
    providers: [provider],
    slackAdmins: ['UADM'],
    memberPage: async () => ({
      members: ['UNRELATED'],
      response_metadata: { next_cursor: 'repeated-cursor' },
    }),
  });
  await sharedModeVia(h, 'UADM', 'acme');
  await h.vouchr.vault.upsert(channelOwner('T1', 'C1'), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider, {
    owner: 'channel',
    channelConfig: new ChannelConfig(h.db),
  });

  const result = await (await h.context()).recoverBrokerDenial('acme', denial);
  assert.deepEqual(result, { status: 'stale', provider: 'acme' });
  assert.equal(h.ephemerals.length, 0, 'an incomplete membership proof cannot post a decision surface');
  assert.equal(h.dms.length, 0, 'an incomplete membership proof cannot disclose channel context by DM');
  assert.equal(
    await h.db.get('SELECT delivery_token FROM approval_request WHERE id=?', [denial.approvalId]),
    undefined,
    'membership fails before any delivery lease is claimed and the unusable pending row is removed',
  );
});

test('bridge: hostile membership pages cannot bypass the finite scan budget', async (t) => {
  const scenarios = [
    {
      name: 'oversized page',
      memberPage: async () => ({ members: [...Array(1000).fill('UNRELATED'), 'U1'] }),
    },
    {
      name: 'duplicate-heavy fresh cursors',
      memberPage: async (_payload: any, attempt: number) => ({
        members: attempt === 6
          ? [...Array(999).fill('UNRELATED'), 'U1']
          : Array(1000).fill('UNRELATED'),
        response_metadata: { next_cursor: `cursor-${attempt}` },
      }),
    },
  ];
  for (const scenario of scenarios) {
    await t.test(scenario.name, async (st) => {
      const provider = approvalProv('self');
      const h = await harness(st, {
        providers: [provider],
        slackAdmins: ['UADM'],
        memberPage: scenario.memberPage,
      });
      await sharedModeVia(h, 'UADM', 'acme');
      await h.vouchr.vault.upsert(channelOwner('T1', 'C1'), 'acme', {
        accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
      });
      const { denial } = await brokerApprovalDenial(st, h.db, h.key, provider, {
        owner: 'channel',
        channelConfig: new ChannelConfig(h.db),
      });

      const result = await (await h.context()).recoverBrokerDenial('acme', denial);
      assert.deepEqual(result, { status: 'stale', provider: 'acme' });
      assert.equal(h.ephemerals.length, 0);
      assert.equal(h.dms.length, 0);
      assert.equal(
        await h.db.get('SELECT delivery_token FROM approval_request WHERE id=?', [denial.approvalId]),
        undefined,
      );
    });
  }
});

test('bridge: the approver rule is re-derived from the registry, not the wire or the row', async (t) => {
  const provider = approvalProv('self');
  const h = await harness(t, { providers: [provider] });
  await h.vouchr.vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const { denial } = await brokerApprovalDenial(t, h.db, h.key, provider);
  // A redeploy dropped the approval knob: the pending row is moot and the retry re-evaluates.
  const without = await createVouchr({
    providers: [defineProvider({
      id: 'acme', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
      egressAllow: ['api.acme.test'], egressMethods: ['GET', 'POST'],
      refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
    })],
    baseUrl: 'http://127.0.0.1:1',
    db: h.db,
  });
  const args: any = {
    context: {}, client: h.client,
    event: { team: 'T1', user: 'U1', channel: 'C1', thread_ts: 'TH1' },
    next: async () => {},
  };
  await without.middleware(args);
  const r = await (args.context.vouchr as ConnectContext).recoverBrokerDenial('acme', denial);
  assert.deepEqual(r, { status: 'resolved', provider: 'acme' });
  assert.equal(h.ephemerals.length, 0, 'no decision surface for a rule that no longer exists');
});

test('bridge: a policy deny at recovery time is an audited typed denial, not a prompt', async (t) => {
  const provider = approvalProv('self');
  const h = await harness(t, {
    providers: [provider],
    policy: new Policy({ acme: { defaultAllow: true, denyChannels: ['C1'] } }),
  });
  const ctx = await h.context();
  await assert.rejects(
    ctx.recoverBrokerDenial('acme', { code: 'approval_required', approvalId: randomUUID() }),
    PolicyDeniedError,
  );
  const denied = await h.db.all<any>("SELECT action FROM audit WHERE action='denied'", []);
  assert.equal(denied.length, 1);
  assert.equal(h.ephemerals.length, 0);
});
