// #360 a worker's request is authorized by a channel member as themselves, and the thread becomes
// that member's session. End to end through the PUBLIC surfaces (TEST-2): a real in-process broker
// (`POST /v1/authorization`, `/v1/fetch`), a real createVouchr control plane on the SAME PostgreSQL
// schema whose delivery pass posts the surface, and the real registered Approve/Deny handlers. Slack's
// Web API is a local fake (the timer path builds a bounded WebClient from the bot token); provider
// egress is a stubbed global fetch (TEST-3).
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { openTestDb } from './support/pg';
import { listen } from './support/http';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { defineProvider, type Provider, type ProviderSpec } from '../src/core/providers';
import { Approvals } from '../src/core/approval';
import { WORKER_SESSION_MAX_TTL_US } from '../src/core/interaction';
import { userOwner } from '../src/core/owner';
import { ChannelConfig, writeChannelIdentity } from '../src/core/channelConfig';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { createBroker } from '../src/adapters/http/broker';
import { createVouchr } from '../src/adapters/bolt';
import { APPROVAL_APPROVE_ACTION, APPROVAL_DENY_ACTION, OAUTH_CONNECT_ACTION } from '../src/adapters/blocks';
import { identityConfig, signIdentity, type IdentityClaims } from './support/identity';
import { BROKER_REQUIRED } from './support/slackOidc';

const SECRET = 'worker-authorization-signing-secret';
const BOT = 'UBOT1';
const TOKEN_U1 = 'tok_u1_secret_never_rendered';
const TOKEN_U2 = 'tok_u2_secret_never_rendered';

const acmeSpec: ProviderSpec = {
  id: 'acme', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.acme.test'], egressMethods: ['GET', 'POST'],
  refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
};
const acme = defineProvider(acmeSpec);

function request(
  port: number, method: string, path: string, body?: unknown, headers: Record<string, string> = {},
): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: '127.0.0.1', port, path, method,
        headers: { ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}), ...headers },
        agent: false,
      },
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

/** A fake Slack Web API as the WebClient's own `fetch`, recording every call the delivery pass makes. */
function fakeSlack(members: string[], channelInfo: Record<string, unknown> = {}) {
  const calls: { method: string; args: any }[] = [];
  const slackFetch = (async (input: any, init?: any) => {
    const raw = typeof init?.body === 'string' ? init.body : await new Response(init?.body).text();
    let args: any;
    try { args = JSON.parse(raw); } catch { args = Object.fromEntries(new URLSearchParams(raw)); }
    if (typeof args.blocks === 'string') args.blocks = JSON.parse(args.blocks);
    const method = new URL(String(input instanceof Request ? input.url : input)).pathname.replace(/^\/api\//, '');
    calls.push({ method, args });
    const body = method === 'conversations.info'
      ? { ok: true, channel: { id: args.channel, is_channel: true, creator: 'U1', ...channelInfo } }
      : method === 'conversations.members' ? { ok: true, members }
      : method === 'users.info' ? { ok: true, user: { is_admin: false } }
      : { ok: true };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { fetch: slackFetch, calls };
}

function stubUpstream(t: TestContext): { url: string; init?: RequestInit }[] {
  const real = globalThis.fetch;
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = (async (url: any, init?: any) => {
    calls.push({ url: String(url), init });
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  t.after(() => { globalThis.fetch = real; });
  return calls;
}

const bearer = (call: { init?: RequestInit }) => new Headers(call.init?.headers).get('authorization');

async function harness(t: TestContext, o: {
  provider?: Provider;
  /** Current channel members, as Slack reports them. */
  members?: string[];
  /** Members holding a connected `acme` credential at start. */
  connected?: Record<string, string>;
  channelInfo?: Record<string, unknown>;
  channelIdentity?: 'person' | 'channel';
} = {}) {
  const provider = o.provider ?? acme;
  const db = await openTestDb(t);
  const key = randomBytes(32);
  process.env.VOUCHR_MASTER_KEY = key.toString('base64');
  const vault = new Vault(db, key);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  if (o.channelIdentity === 'channel') await writeChannelIdentity(channelConfig, 'T1', 'C1', 'acme', 'channel');
  const connected = o.connected ?? { U1: TOKEN_U1 };
  for (const [user, accessToken] of Object.entries(connected)) {
    await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: user }), 'acme', {
      accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  await setChannelToolEnabled(new ChannelTools(db), 'T1', 'C1', 'acme', true);
  const server = createBroker({
    ...BROKER_REQUIRED, providers: [provider], vault, audit, db, identitySecret: identityConfig(SECRET),
    allowWrites: true, channelConfig,
  });
  await listen(t, server);
  const port = (server.address() as any).port;
  const members = o.members ?? [BOT, 'U1', 'U2'];
  const slack = fakeSlack(members, o.channelInfo);
  const vouchr = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', db, botToken: 'xoxb-test-bot-token',
    slackClientOptions: { slackApiUrl: 'https://slack.local/api/', fetch: slack.fetch },
  });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({ command: () => undefined, view: () => undefined, action: (id: string, h: any) => { actions[id] = h; } });
  const clickPosts: { method: string; args: any }[] = [];
  const clickClient = {
    users: { info: async () => ({ user: { is_admin: false } }) },
    conversations: {
      info: async ({ channel }: any) => ({ channel: { id: channel, is_channel: true, creator: 'U1', ...o.channelInfo } }),
      members: async () => ({ members }),
    },
    chat: {
      postEphemeral: async (args: any) => { clickPosts.push({ method: 'chat.postEphemeral', args }); return {}; },
      postMessage: async (args: any) => { clickPosts.push({ method: 'chat.postMessage', args }); return {}; },
    },
  } as any;
  const click = async (id: string, clicker: string, o2: { action?: string; thread?: string | null } = {}) => {
    const responds: any[] = [];
    const thread = o2.thread === undefined ? 'TH1' : o2.thread;
    await actions[o2.action ?? APPROVAL_APPROVE_ACTION]({
      ack: async () => {},
      body: {
        team: { id: 'T1' }, user: { id: clicker }, channel: { id: 'C1' },
        container: { channel_id: 'C1', ...(thread ? { thread_ts: thread } : {}) }, actions: [{ value: id }],
      },
      client: clickClient,
      respond: async (m: any) => { responds.push(m); },
    });
    return responds.map((r) => String(r?.text ?? '')).join('\n');
  };
  const prompts = () => slack.calls.filter((c) => c.method === 'chat.postEphemeral' || c.method === 'chat.postMessage');
  const audits = async (action: string) =>
    (await db.all(`SELECT user_id, actor, meta FROM audit WHERE action=? ORDER BY at`, [action])) as any[];
  const workerClaims = (over: Partial<IdentityClaims> = {}): IdentityClaims => ({
    teamId: 'T1', userId: BOT, channel: 'C1', threadTs: 'TH1', channelType: 'channel', channelEligible: true, worker: true,
    exp: Date.now() + 60_000, jti: randomUUID(), ...over,
  });
  const mint = (over: Partial<IdentityClaims> = {}) => signIdentity(workerClaims(over), SECRET);
  const handle = { provider: 'acme', owner: 'user' };
  const authorize = (over: Record<string, unknown> = {}, claims: Partial<IdentityClaims> = {}) => request(port, 'POST', '/v1/authorization', {
    handle, identityToken: mint(claims), method: 'POST', path: '/repos', reason: 'TICKET-42: open the release issue', ...over,
  });
  const status = (id: string, claims: Partial<IdentityClaims> = {}) =>
    request(port, 'GET', `/v1/authorization/${id}`, undefined, { 'x-vouchr-identity': mint(claims) });
  const fetchAction = (over: Record<string, unknown> = {}, claims: Partial<IdentityClaims> = {}) => request(port, 'POST', '/v1/fetch', {
    handle, identityToken: mint(claims), method: 'POST', path: '/repos', body: '{}', ...over,
  });
  const connect = (user: string, accessToken: string) => vault.upsert(
    userOwner({ enterpriseId: null, teamId: 'T1', userId: user }), 'acme',
    { accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null },
  );
  const sessions = async () => (await db.all(`SELECT thread, member_user_id, credential_id FROM worker_session ORDER BY thread`)) as any[];
  return { db, vault, vouchr, slack, prompts, click, clickPosts, audits, authorize, status, fetchAction, connect, sessions, port, mint, handle };
}

test('#360 full flow: the worker asks, any member is prompted in the channel, a member without a credential is sent Connect, connects, authorizes as themselves, the spend runs with their token and audits requester, actor, owner, thread', async (t) => {
  const upstream = stubUpstream(t);
  const h = await harness(t);

  const created = await h.authorize();
  assert.equal(created.status, 200, JSON.stringify(created.json));
  assert.equal(created.json.status, 'pending');
  assert.equal((await h.authorize({ reason: 'again' })).json.authorizationId, created.json.authorizationId, 'the exact action deduplicates to one request');
  assert.equal(upstream.length, 0);
  const requested = await h.audits('approval_requested');
  assert.equal(requested.length, 1);
  assert.equal(requested[0].user_id, BOT, 'the worker is the requester');
  const stored = await h.db.get<any>(`SELECT owner_kind, owner_id, credential_id, delegated, backchannel FROM approval_request WHERE id=?`, [created.json.authorizationId]);
  assert.equal(stored.delegated, 1);
  assert.equal(stored.backchannel, 1);
  assert.equal(stored.owner_id, BOT, 'unbound: the worker is its own placeholder owner');
  const [session] = await h.sessions();
  assert.equal(session.member_user_id, null);
  assert.equal(stored.credential_id, (await h.db.get<any>(`SELECT id FROM worker_session`)).id, 'the unbound session id is the placeholder generation');

  // Delivery: one channel message any member can act on, naming the worker and the action.
  await h.vouchr.sweepExpired();
  const posted = h.prompts();
  assert.equal(posted.length, 1);
  assert.equal(posted[0].method, 'chat.postMessage');
  assert.equal(posted[0].args.channel, 'C1');
  assert.equal(posted[0].args.thread_ts, 'TH1');
  const rendered = JSON.stringify(posted[0].args.blocks);
  assert.ok(rendered.includes(`<@${BOT}>`), 'names the worker');
  assert.ok(rendered.includes('Authorize with your account'), 'one button, as yourself');
  assert.ok(rendered.includes('POST api.acme.test/repos'));
  assert.ok(rendered.includes('TICKET-42: open the release issue'));
  assert.ok(!rendered.includes(TOKEN_U1) && !rendered.includes(TOKEN_U2), 'SEC-1');
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1, 'the channel message is not re-posted');

  // U2 has no acme credential: the click posts U2 the private Connect prompt in the thread and leaves the request pending.
  const connectFirst = await h.click(created.json.authorizationId, 'U2');
  assert.match(connectFirst, /Connect your \*acme\* account first/);
  assert.match(connectFirst, /stays open for 10 minutes/);
  const connectPrompt = h.clickPosts.find((c) => c.method === 'chat.postEphemeral' && JSON.stringify(c.args.blocks).includes(OAUTH_CONNECT_ACTION));
  assert.ok(connectPrompt, 'a Connect prompt was posted');
  assert.equal(connectPrompt!.args.user, 'U2');
  assert.equal(connectPrompt!.args.channel, 'C1');
  assert.equal(connectPrompt!.args.thread_ts, 'TH1', 'privately, in the same thread');
  assert.equal((await h.status(created.json.authorizationId)).json.status, 'pending');
  assert.equal((await h.sessions())[0].member_user_id, null, 'nothing bound yet');

  // U2 connects, clicks again: the grant binds to U2's credential and the thread becomes U2's session.
  await h.connect('U2', TOKEN_U2);
  const authorized = await h.click(created.json.authorizationId, 'U2');
  assert.match(authorized, /Authorized the \*acme\* action with your account/);
  assert.match(authorized, /will ask you privately/);
  assert.equal((await h.status(created.json.authorizationId)).json.status, 'approved', 'the worker polls approved');
  const bound = await h.db.get<any>(`SELECT owner_kind, owner_id, credential_id FROM approval_request WHERE id=?`, [created.json.authorizationId]);
  assert.deepEqual(bound, { owner_kind: 'user', owner_id: 'U2', credential_id: await h.vault.liveId(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U2' }), 'acme') });
  assert.deepEqual(await h.sessions(), [{ thread: 'TH1', member_user_id: 'U2', credential_id: bound.credential_id }]);
  const approved = await h.audits('approved');
  assert.equal(approved[0].user_id, BOT);
  assert.equal(approved[0].actor, 'U2');
  assert.equal(JSON.parse(approved[0].meta).owner, 'U2');

  // Spend: the worker's fetch runs with U2's token, once.
  const done = await h.fetchAction();
  assert.equal(done.status, 200, JSON.stringify(done.json));
  assert.equal(upstream.length, 1);
  assert.equal(bearer(upstream[0]), `Bearer ${TOKEN_U2}`, 'the authorizing member\'s credential, resolved from the grant');
  const consumed = await h.audits('approval_consumed');
  assert.equal(consumed.length, 1);
  assert.equal(consumed[0].user_id, BOT, 'requester = worker');
  assert.equal(consumed[0].actor, 'U2', 'actor = the bound member');
  const meta = JSON.parse(consumed[0].meta);
  assert.equal(meta.owner, 'U2', 'credential owner = the bound member');
  assert.equal(meta.thread, 'TH1');
  assert.equal(meta.delegated, true);
  assert.equal(meta.reason, 'TICKET-42: open the release issue');
  assert.ok(!consumed[0].meta.includes(TOKEN_U2), 'SEC-1');

  // Edge: the grant cannot be spent twice.
  const twice = await h.fetchAction();
  assert.equal(twice.status, 403);
  assert.equal(twice.json.code, 'approval_required');
  assert.equal(upstream.length, 1);
});

test('#360 thread session: the next action asks the bound member privately and runs as them; another member is refused; a second thread starts a new any-member authorization', async (t) => {
  const upstream = stubUpstream(t);
  const h = await harness(t, { connected: { U1: TOKEN_U1, U2: TOKEN_U2 } });
  const first = await h.authorize();
  await h.vouchr.sweepExpired();
  await h.click(first.json.authorizationId, 'U1');
  assert.equal((await h.fetchAction()).status, 200);
  assert.equal(bearer(upstream[0]), `Bearer ${TOKEN_U1}`);

  // Second action in TH1: minted bound to U1, delivered privately to U1 in the thread, each action asks.
  const second = await h.fetchAction({ path: '/repos/two' });
  assert.equal(second.status, 403);
  assert.equal(second.json.code, 'approval_required');
  const row = await h.db.get<any>(`SELECT owner_id, backchannel, delegated FROM approval_request WHERE id=?`, [second.json.approvalId]);
  assert.deepEqual(row, { owner_id: 'U1', backchannel: 1, delegated: 1 }, 'bound to the session member, delivered by the control plane');
  await h.vouchr.sweepExpired();
  const posted = h.prompts();
  assert.equal(posted.length, 2);
  assert.equal(posted[1].method, 'chat.postEphemeral', 'private');
  assert.equal(posted[1].args.user, 'U1', 'to the bound member, not the worker');
  assert.equal(posted[1].args.thread_ts, 'TH1');
  const rendered = JSON.stringify(posted[1].args.blocks);
  assert.match(rendered, /where you authorized it with your account/);
  assert.ok(rendered.includes('"text":"Approve"'), 'a plain Approve: the session already holds the account');
  const other = await h.click(second.json.approvalId, 'U2');
  assert.match(other, /only the member who authorized this worker in this thread/);
  assert.equal((await h.status(second.json.approvalId)).json.status, 'pending');
  await h.click(second.json.approvalId, 'U1');
  assert.equal((await h.fetchAction({ path: '/repos/two' })).status, 200);
  assert.equal(upstream.length, 2);
  assert.equal(bearer(upstream[1]), `Bearer ${TOKEN_U1}`);
  const consumed = await h.audits('approval_consumed');
  assert.equal(consumed.length, 2);
  assert.equal(consumed[1].actor, 'U1');
  assert.equal(JSON.parse(consumed[1].meta).thread, 'TH1');

  // A denied action in the session is a denial, not a fallback to anyone else.
  const third = await h.fetchAction({ path: '/repos/three' });
  await h.vouchr.sweepExpired();
  assert.match(await h.click(third.json.approvalId, 'U1', { action: APPROVAL_DENY_ACTION }), /Denied/);
  assert.equal((await h.status(third.json.approvalId)).json.status, 'denied');

  // Another thread: no session there, so any member is asked again in the channel.
  const elsewhere = await h.authorize({}, { threadTs: 'TH2' });
  assert.equal(elsewhere.status, 200);
  const unbound = await h.db.get<any>(`SELECT owner_id FROM approval_request WHERE id=?`, [elsewhere.json.authorizationId]);
  assert.equal(unbound.owner_id, BOT, 'a new any-member authorization');
  await h.vouchr.sweepExpired();
  const last = h.prompts().at(-1)!;
  assert.equal(last.method, 'chat.postMessage');
  assert.equal(last.args.thread_ts, 'TH2');
  assert.deepEqual((await h.sessions()).map((s) => [s.thread, s.member_user_id]), [['TH1', 'U1'], ['TH2', null]]);
  await h.click(elsewhere.json.authorizationId, 'U2', { thread: 'TH2' });
  assert.equal((await h.fetchAction({}, { threadTs: 'TH2' })).status, 200);
  assert.equal(bearer(upstream[2]), `Bearer ${TOKEN_U2}`, 'TH2 runs as its own member');
});

test('#360 two members click at once: exactly one authorization, the other sees stale; the grant binds to the winner', async (t) => {
  const upstream = stubUpstream(t);
  const h = await harness(t, { connected: { U1: TOKEN_U1, U2: TOKEN_U2 } });
  const created = await h.authorize();
  await h.vouchr.sweepExpired();
  const [a, b] = await Promise.all([h.click(created.json.authorizationId, 'U1'), h.click(created.json.authorizationId, 'U2')]);
  const outcomes = [a, b];
  assert.equal(outcomes.filter((o) => /Authorized the/.test(o)).length, 1, 'one authorization');
  assert.equal(outcomes.filter((o) => /expired or was already decided/.test(o)).length, 1, 'the other is stale');
  assert.equal((await h.audits('approved')).length, 1);
  const winner = (await h.sessions())[0].member_user_id;
  assert.ok(winner === 'U1' || winner === 'U2');
  assert.equal((await h.fetchAction()).status, 200);
  assert.equal(bearer(upstream[0]), `Bearer ${winner === 'U1' ? TOKEN_U1 : TOKEN_U2}`);
});

test('#360 refusals: a former member, the worker itself, and a Connect abandoned until TTL', async (t) => {
  stubUpstream(t);
  const h = await harness(t, { members: [BOT, 'U1'], connected: { U1: TOKEN_U1, U9: 'tok_u9' } });
  const created = await h.authorize();
  await h.vouchr.sweepExpired();
  // U9 holds a credential but left the channel: refused and audited, the request stays pending.
  assert.match(await h.click(created.json.authorizationId, 'U9'), /not eligible to authorize/);
  assert.equal((await h.audits('denied')).filter((r) => r.meta.includes('not-approver')).length, 1);
  // The worker cannot authorize its own request.
  assert.match(await h.click(created.json.authorizationId, BOT), /other than the worker/);
  // A member with no credential who never connects: pending until the TTL reclaims it, nothing bound.
  const h2 = await harness(t, { members: [BOT, 'U2'], connected: {} });
  const pending = await h2.authorize();
  await h2.vouchr.sweepExpired();
  assert.match(await h2.click(pending.json.authorizationId, 'U2'), /stays open for 10 minutes/);
  assert.equal((await h2.status(pending.json.authorizationId)).json.status, 'pending');
  await h2.db.run(`UPDATE approval_request SET expires_at=0 WHERE id=?`, [pending.json.authorizationId]);
  await h2.vouchr.sweepExpired();
  assert.equal((await h2.status(pending.json.authorizationId)).status, 404);
  assert.equal((await h2.audits('denied')).filter((r) => JSON.parse(r.meta).reason === 'approval-expired').length, 1);
  assert.equal((await h2.sessions())[0].member_user_id, null, 'nothing was bound');
});

test('#360 no team, no authorization: a DM token and an ineligible (Slack Connect) channel are refused by the broker; a Slack Connect channel receives no prompt', async (t) => {
  stubUpstream(t);
  const h = await harness(t);
  const dm = await h.authorize({}, { channel: 'D123', channelType: 'im' });
  assert.equal(dm.status, 403);
  assert.match(dm.json.error, /personal conversation has none/);
  const ineligible = await h.authorize({}, { channelEligible: false });
  assert.equal(ineligible.status, 403);
  assert.match(ineligible.json.error, /ineligible/);
  assert.equal((await h.audits('denied')).filter((r) => r.meta.includes('channel-ineligible')).length, 1);
  assert.equal((await h.db.all(`SELECT 1 FROM approval_request`)).length, 0, 'nothing minted');
  // The signed verdict can be stale: a channel converted to Slack Connect after minting gets no prompt.
  const shared = await harness(t, { channelInfo: { is_ext_shared: true } });
  const created = await shared.authorize();
  assert.equal(created.status, 200);
  await shared.vouchr.sweepExpired();
  assert.equal(shared.prompts().length, 0, 'no channel message into a Slack Connect channel');
  assert.equal((await shared.status(created.json.authorizationId)).status, 404, 'the impossible request is discarded');
  // A worker in a channel whose identity is the shared credential must use the shared path.
  const channelIdentity = await harness(t, { channelIdentity: 'channel' });
  const refused = await channelIdentity.authorize();
  assert.equal(refused.status, 403);
  assert.match(refused.json.error, /ownerKind channel/);
});

test('#360 the bound member disconnects mid-session: pending grants are fenced and the next request goes back to any member; offboarding does the same', async (t) => {
  const upstream = stubUpstream(t);
  const h = await harness(t, { connected: { U1: TOKEN_U1, U2: TOKEN_U2 } });
  const first = await h.authorize();
  await h.vouchr.sweepExpired();
  await h.click(first.json.authorizationId, 'U1');
  const second = await h.fetchAction({ path: '/repos/two' });
  assert.equal(second.json.code, 'approval_required');
  await h.vouchr.sweepExpired();
  await h.click(second.json.approvalId, 'U1');
  assert.equal((await h.status(second.json.approvalId)).json.status, 'approved');

  // U1 disconnects acme: the unspent grant is purged with the credential, the session is dead.
  await h.vouchr.vault.delete(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme');
  assert.equal((await h.status(second.json.approvalId)).status, 404, 'fenced');
  const spend = await h.fetchAction({ path: '/repos/two' });
  assert.equal(spend.status, 403);
  assert.equal(spend.json.code, 'approval_required');
  assert.equal(upstream.length, 0, 'nothing ran as the departed member');
  const row = await h.db.get<any>(`SELECT owner_id FROM approval_request WHERE id=?`, [spend.json.approvalId]);
  assert.equal(row.owner_id, BOT, 'back to any member');
  assert.equal((await h.sessions())[0].member_user_id, null, 'the session was reset');
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().at(-1)!.method, 'chat.postMessage', 'a channel message any member may answer');
  await h.click(spend.json.approvalId, 'U2');
  assert.equal((await h.fetchAction({ path: '/repos/two' })).status, 200);
  assert.equal(bearer(upstream[0]), `Bearer ${TOKEN_U2}`);
  assert.deepEqual((await h.sessions()).map((s) => s.member_user_id), ['U2']);

  // Offboarding the bound member ends the session and its grants.
  const third = await h.fetchAction({ path: '/repos/three' });
  await h.vouchr.sweepExpired();
  await h.click(third.json.approvalId, 'U2');
  await h.vouchr.offboard({ enterpriseId: null, teamId: 'T1', userId: 'U2' });
  assert.equal((await h.status(third.json.approvalId)).status, 404);
  assert.equal((await h.sessions()).length, 0, 'the offboarded member\'s session is gone');
  assert.equal((await h.fetchAction({ path: '/repos/three' })).json.code, 'approval_required');
  assert.equal(upstream.length, 1);
});

test('#360 an idle session expires: the sweep reclaims it and the next request asks any member', async (t) => {
  stubUpstream(t);
  const h = await harness(t, { connected: { U1: TOKEN_U1, U2: TOKEN_U2 } });
  const first = await h.authorize();
  await h.vouchr.sweepExpired();
  await h.click(first.json.authorizationId, 'U1');
  await h.db.run(`UPDATE worker_session SET expires_at=0`);
  await h.vouchr.sweepExpired();
  assert.equal((await h.sessions()).length, 0);
  const next = await h.authorize({ path: '/repos/two' });
  assert.equal((await h.db.get<any>(`SELECT owner_id FROM approval_request WHERE id=?`, [next.json.authorizationId])).owner_id, BOT);
});

// ── Thread placement for a human's private prompts (operator finding on #360) ──────────────────────
// An ephemeral is not a reply: posted under a top-level message it shows no reply indicator and is
// never seen. So a request from a top-level message gets its private prompt at channel level, and a
// request from inside a thread gets it in that thread. The grant still binds to the root either way.
async function boltContext(t: TestContext, request: { event?: Record<string, unknown>; body?: Record<string, unknown> }, connected: boolean) {
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');
  const vouchr = await createVouchr({ providers: [acme], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t) });
  const ephemerals: any[] = [];
  const client = { chat: { postEphemeral: async (p: any) => { ephemerals.push(p); return {}; }, postMessage: async () => ({}) } } as any;
  const args: any = {
    context: {}, client, next: async () => {},
    ...(request.event ? { event: { user: 'U1', team: 'T1', channel: 'C1', ...request.event } } : {}),
    ...(request.body ? { body: { team: { id: 'T1' }, user: { id: 'U1' }, channel: { id: 'C1' }, ...request.body } } : {}),
  };
  await vouchr.middleware(args);
  await setChannelToolEnabled(new ChannelTools(vouchr.db), 'T1', 'C1', 'acme', true);
  if (connected) {
    await vouchr.vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
      accessToken: TOKEN_U1, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  return { ctx: args.context.vouchr, ephemerals, db: vouchr.db };
}

test('thread placement: a top-level mention or a click on an unreplied message gets its Connect and approval prompts at channel level; a mention inside a thread or a click on a replied root gets them in that thread; the grant binds to the root either way', async (t) => {
  stubUpstream(t);
  for (const [request, expectedThread, label] of [
    [{ event: { ts: 'ROOT' } }, undefined, 'top-level'],
    [{ event: { ts: 'REPLY', thread_ts: 'ROOT' } }, 'ROOT', 'in-thread'],
    // block_actions: Slack sends container.thread_ts only for a message that is in a thread. A root
    // with replies carries its own ts as thread_ts; a top-level message without replies carries none.
    [{ body: { container: { channel_id: 'C1', message_ts: 'ROOT' } } }, undefined, 'block_actions top-level'],
    [{ body: { container: { channel_id: 'C1', message_ts: 'ROOT', thread_ts: 'ROOT' } } }, 'ROOT', 'block_actions replied root'],
  ] as const) {
    const unconnected = await boltContext(t, request, false);
    await assert.rejects(unconnected.ctx.connect('acme'), /Consent required/);
    assert.equal(unconnected.ephemerals.length, 1, `${label}: one Connect prompt`);
    assert.equal(unconnected.ephemerals[0].user, 'U1');
    assert.equal(unconnected.ephemerals[0].thread_ts, expectedThread, `${label}: Connect prompt placement`);

    const connected = await boltContext(t, request, true);
    const handle = await connected.ctx.connect('acme');
    await assert.rejects(handle.fetch('https://api.acme.test/repos', { method: 'POST' }), /Approval required/);
    assert.equal(connected.ephemerals.length, 1, `${label}: one approval prompt`);
    assert.equal(connected.ephemerals[0].thread_ts, expectedThread, `${label}: approval prompt placement`);
    const row = await connected.db.get<any>(`SELECT thread FROM approval_request`);
    assert.equal(row.thread, 'ROOT', `${label}: the grant binds to the root`);
  }
});

test('#360 a worker\'s grant is once even when the provider declares grant thread: the prompt says one call once, and the second call in the thread asks the bound member again', async (t) => {
  const upstream = stubUpstream(t);
  const threadAcme = defineProvider({ ...acmeSpec, approval: { grant: 'thread', ttlMs: 60_000 } });
  const h = await harness(t, { provider: threadAcme });
  const created = await h.authorize();
  assert.equal(created.status, 200, JSON.stringify(created.json));
  assert.equal((await h.db.get<any>(`SELECT grant_scope FROM approval_request WHERE id=?`, [created.json.authorizationId])).grant_scope, 'once');
  await h.vouchr.sweepExpired();
  const rendered = JSON.stringify(h.prompts()[0].args.blocks);
  assert.match(rendered, /This covers one call, once/);
  assert.doesNotMatch(rendered, /covers every/);
  await h.click(created.json.authorizationId, 'U1');
  assert.equal((await h.fetchAction()).status, 200);
  assert.equal(bearer(upstream[0]), `Bearer ${TOKEN_U1}`);

  // The identical call, in the same thread, under the same member's session: asks again.
  const again = await h.fetchAction();
  assert.equal(again.status, 403);
  assert.equal(again.json.code, 'approval_required');
  assert.equal(upstream.length, 1, 'nothing ran unasked');
  const row = await h.db.get<any>(`SELECT owner_id, grant_scope, delegated FROM approval_request WHERE id=?`, [again.json.approvalId]);
  assert.deepEqual(row, { owner_id: 'U1', grant_scope: 'once', delegated: 1 }, 'a fresh once grant for the bound member');
  await h.vouchr.sweepExpired();
  const bound = JSON.stringify(h.prompts().at(-1)!.args.blocks);
  assert.match(bound, /It runs as you, once/);
  assert.match(bound, /This covers one call, once/);
  assert.doesNotMatch(bound, /covers every/);
});

test('#360 the worker\'s own requests never extend its session; the bound member\'s decision does, and never past the absolute cap', async (t) => {
  stubUpstream(t);
  const h = await harness(t, { connected: { U1: TOKEN_U1, U2: TOKEN_U2 } });
  const expiresAt = async () => Number((await h.db.get<any>(`SELECT expires_at FROM worker_session WHERE thread='TH1'`)).expires_at);
  const first = await h.authorize();
  await h.vouchr.sweepExpired();
  await h.click(first.json.authorizationId, 'U1');
  // Pin the idle expiry to a known instant, then let the worker poll, request, and spend.
  await h.db.run(`UPDATE worker_session SET expires_at=expires_at-1000000`);
  const pinned = await expiresAt();
  assert.equal((await h.fetchAction()).status, 200, 'the spend of the member\'s own grant');
  const spent = await expiresAt();
  assert.ok(spent >= pinned, 'a spend the member decided may extend the session');
  const second = await h.fetchAction({ path: '/repos/two' });
  assert.equal(second.json.code, 'approval_required');
  await h.authorize({ path: '/repos/three' });
  assert.equal((await h.status(second.json.approvalId)).json.status, 'pending');
  assert.equal((await h.fetchAction({ path: '/repos/two' })).json.code, 'approval_required', 'polling the pending action');
  assert.equal(await expiresAt(), spent, 'none of the worker\'s own requests moved the idle expiry');
  await h.vouchr.sweepExpired();
  await h.click(second.json.approvalId, 'U1');
  assert.ok((await expiresAt()) > spent, 'the member\'s decision extends it');

  // Idle expiry despite a polling worker: once the idle window lapses, the next request is unbound.
  await h.db.run(`UPDATE worker_session SET expires_at=0`);
  const idled = await h.authorize({ path: '/repos/four' });
  assert.equal((await h.db.get<any>(`SELECT owner_id FROM approval_request WHERE id=?`, [idled.json.authorizationId])).owner_id, BOT, 'back to any member');
  await h.vouchr.sweepExpired();
  await h.click(idled.json.authorizationId, 'U1', {});
  assert.equal((await h.sessions()).find((s) => s.thread === 'TH1')!.member_user_id, 'U1', 'U1 binds a fresh session');

  // Absolute cap: however active the member is, a decision cannot extend the session past bound_at + cap.
  await h.db.run(`UPDATE worker_session SET bound_at=bound_at-?`, [WORKER_SESSION_MAX_TTL_US]);
  const capped = await h.fetchAction({ path: '/repos/five' });
  assert.equal(capped.json.code, 'approval_required');
  await h.vouchr.sweepExpired();
  await h.click(capped.json.approvalId, 'U1');
  assert.equal((await h.status(capped.json.approvalId)).json.status, 'approved', 'the decision itself stands');
  const afterCap = await h.authorize({ path: '/repos/six' });
  assert.equal((await h.db.get<any>(`SELECT owner_id FROM approval_request WHERE id=?`, [afterCap.json.authorizationId])).owner_id, BOT, 'the capped session ended; any member is asked');
  assert.equal((await h.sessions()).find((s) => s.thread === 'TH1')!.member_user_id, null, 'replaced by an unbound session');
});

test('#360 /v1/mcp spends a worker\'s grant with the bound member\'s token, and the next MCP call in the session asks that member again', async (t) => {
  const upstream = stubUpstream(t);
  const h = await harness(t, { provider: defineProvider({ ...acmeSpec, mcp: { paths: ['/mcp'] } }) });
  const rpc = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo' } });
  const mcp = () => request(h.port, 'POST', '/v1/mcp', {
    handle: h.handle, identityToken: h.mint(), path: '/mcp', body: rpc,
    headers: { accept: 'application/json, text/event-stream', 'content-type': 'application/json' },
  });
  const unasked = await mcp();
  assert.equal(unasked.status, 403, JSON.stringify(unasked.json));
  assert.equal(unasked.json.code, 'approval_required');
  await h.vouchr.sweepExpired();
  await h.click(unasked.json.approvalId, 'U1');
  const done = await mcp();
  assert.equal(done.status, 200, JSON.stringify(done.json));
  assert.equal(upstream.length, 1);
  assert.equal(bearer(upstream[0]), `Bearer ${TOKEN_U1}`);
  assert.equal(upstream[0].url, 'https://api.acme.test/mcp');
  const consumed = await h.audits('approval_consumed');
  assert.equal(consumed.length, 1);
  assert.equal(consumed[0].user_id, BOT);
  assert.equal(consumed[0].actor, 'U1');
  assert.equal(JSON.parse(consumed[0].meta).thread, 'TH1');
  const again = await mcp();
  assert.equal(again.json.code, 'approval_required');
  assert.equal((await h.db.get<any>(`SELECT owner_id FROM approval_request WHERE id=?`, [again.json.approvalId])).owner_id, 'U1', 'asks the bound member');
  assert.equal(upstream.length, 1);
});

test('#360 a channel turned Slack Connect after the prompt refuses the click on a delegated row, unbound and bound alike', async (t) => {
  stubUpstream(t);
  const info: Record<string, unknown> = {};
  const h = await harness(t, { channelInfo: info, connected: { U1: TOKEN_U1, U2: TOKEN_U2 } });
  const created = await h.authorize();
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1, 'delivered while the channel was eligible');
  info.is_ext_shared = true;
  assert.match(await h.click(created.json.authorizationId, 'U1'), /no longer valid because provider or channel access changed/);
  assert.equal((await h.status(created.json.authorizationId)).status, 404, 'the impossible request is discarded');
  assert.equal((await h.sessions())[0].member_user_id, null, 'nothing bound');

  delete info.is_ext_shared;
  const bind = await h.authorize({ path: '/repos/two' });
  await h.vouchr.sweepExpired();
  await h.click(bind.json.authorizationId, 'U1');
  const later = await h.fetchAction({ path: '/repos/three' });
  assert.equal(later.json.code, 'approval_required');
  await h.vouchr.sweepExpired();
  info.is_ext_shared = true;
  assert.match(await h.click(later.json.approvalId, 'U1'), /no longer valid because provider or channel access changed/);
  assert.equal((await h.status(later.json.approvalId)).status, 404);
  assert.equal((await h.audits('approved')).length, 1, 'only the pre-conversion authorization');
});

test('#360 decideAudited refuses a delegate that does not match the row: none for an unbound row, one for a bound row, one naming another member', async (t) => {
  stubUpstream(t);
  const h = await harness(t, { connected: { U1: TOKEN_U1, U2: TOKEN_U2 } });
  const approvals = new Approvals(h.db);
  const audit = new Audit(h.db);
  const actor = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const credentialId = (await h.vault.liveId(userOwner(actor), 'acme'))!;
  const base = { decision: 'approve' as const, approvedBy: 'U1', actor, issuance: await h.vault.userProvisioningIssuedAt(), ttlMs: 60_000, audit, validate: async () => 'valid' as const };

  const unbound = await h.authorize();
  await assert.rejects(approvals.decideAudited({ ...base, id: unbound.json.authorizationId }), /delegate does not match the request/);
  await assert.rejects(
    approvals.decideAudited({ ...base, id: unbound.json.authorizationId, delegate: { ownerId: 'U2', credentialId } }),
    /must be the deciding member/,
  );
  assert.equal((await h.status(unbound.json.authorizationId)).json.status, 'pending', 'the unbound row is untouched');

  await h.vouchr.sweepExpired();
  await h.click(unbound.json.authorizationId, 'U1');
  const bound = await h.fetchAction({ path: '/repos/two' });
  assert.equal(bound.json.code, 'approval_required');
  await assert.rejects(
    approvals.decideAudited({ ...base, id: bound.json.approvalId, delegate: { ownerId: 'U1', credentialId } }),
    /delegate does not match the request/,
  );
  assert.equal((await h.status(bound.json.approvalId)).json.status, 'pending', 'the bound row is untouched');
  assert.equal((await h.audits('approved')).length, 1, 'only the click\'s authorization was audited');
});
