// #194 — the trusted broker-to-Slack recovery bridge: ConnectContext.recoverBrokerDenial maps a
// relayed broker denial (untrusted routing guidance) to the correct private Slack recovery action.
// Driven through the PUBLIC API (TEST-2): a real createVouchr, its real middleware, and — for the
// approval outcome — a real in-process createBroker sharing the same PostgreSQL schema, so the
// pending approval row is minted by the actual broker door the hybrid deployment uses.
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { openTestDb } from './support/pg';
import { identityConfig, signIdentity } from './support/identity';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ChannelConfig, writeChannelMode } from '../src/core/channelConfig';
import { setChannelCredentialMode } from '../src/core/channelCredential';
import { defineProvider, type Provider } from '../src/core/providers';
import { channelOwner, userOwner } from '../src/core/owner';
import { Policy } from '../src/core/policy';
import { PolicyDeniedError } from '../src/core/authz';
import { createBroker } from '../src/adapters/http/broker';
import {
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

const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const TOKEN = 'sk-secret-token';

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
} = {}) {
  const key = randomBytes(32);
  process.env.VOUCHR_MASTER_KEY = key.toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: o.providers ?? [oauthGh],
    baseUrl: 'http://127.0.0.1:1',
    db,
    policy: o.policy,
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
  const client = {
    users: { info: async ({ user }: any) => ({ user: { is_admin: admins.has(user) } }) },
    conversations: {
      info: async ({ channel }: any) => ({ channel: { id: channel, is_channel: true, creator: 'UCREATOR' } }),
      members: async () => ({ members }),
    },
    chat: {
      postEphemeral: async (p: any) => { ephemerals.push(p); return {}; },
      postMessage: async (p: any) => { dms.push(p); return {}; },
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
  return { db, key, vouchr, actions, client, ephemerals, dms, context, click };
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
async function brokerApprovalDenial(t: TestContext, db: Db, key: Buffer, provider: Provider): Promise<{
  denial: any;
  deny: () => Promise<{ status: number; json: any }>;
}> {
  const SECRET = 'bridge-test-secret';
  const server = createBroker({
    providers: [provider],
    vault: new Vault(db, key),
    audit: new Audit(db),
    db,
    identitySecret: identityConfig(SECRET),
    allowWrites: true,
  });
  await new Promise<void>((r) => server.listen(0, r));
  t.after(() => new Promise((r) => server.close(() => r(null))));
  const port = (server.address() as any).port;
  const deny = async () => post(port, '/v1/fetch', {
    handle: { provider: provider.id, owner: 'user' },
    method: 'POST',
    path: '/repos',
    body: '{}',
    identityToken: signIdentity(
      { teamId: 'T1', userId: 'U1', channel: 'C1', threadTs: 'TH1', exp: Date.now() + 60_000, jti: randomUUID() },
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

test('bridge: user not_connected posts ONE deduplicated private connect prompt', async (t) => {
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
  const h = await harness(t, { slackAdmins: ['UADM'] });
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
  assert.match(h.ephemerals[1].text, /has been asked/, 'still truthful: an admin was asked this window');
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
