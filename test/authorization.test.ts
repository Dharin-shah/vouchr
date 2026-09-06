// #296 — backchannel (CIBA-style) authorization for background agents, end to end through the
// PUBLIC surfaces (TEST-2): a real in-process broker (`POST /v1/authorization`,
// `GET /v1/authorization/{id}`, then the normal `/v1/fetch` spend), a real createVouchr control plane
// on the SAME PostgreSQL schema whose sweep/timer delivers the Approve/Deny surface with no relayed
// denial, the real registered Approve/Deny handlers, and the real lifecycle sweep. Slack's Web API is
// a local fake HTTP server (the timer path builds a bounded WebClient from the bot token, so a plain
// object client cannot stand in); provider egress is a stubbed global fetch (TEST-3).
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { openTestDb } from './support/pg';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { defineProvider, type Provider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { MAX_BINDING_MESSAGE_BYTES } from '../src/core/approval';
import { createBroker } from '../src/adapters/http/broker';
import { createVouchr } from '../src/adapters/bolt';
import { APPROVAL_APPROVE_ACTION, APPROVAL_DENY_ACTION } from '../src/adapters/blocks';
import { identityConfig, signIdentity, type IdentityClaims } from './support/identity';

const SECRET = 'authorization-signing-secret';
const TOKEN = 'tok_live_secret_value_never_rendered';
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };

const acme = defineProvider({
  id: 'acme', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.acme.test'], egressMethods: ['GET', 'POST'],
  approval: { approver: 'self' },
  refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', threadTs: 'TH1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}
/** One fresh single-use assertion per broker call — never reused. */
const tok = (over: Partial<IdentityClaims> = {}) => signIdentity(claims(over), SECRET);

function request(
  port: number, method: string, path: string, body?: unknown, headers: Record<string, string> = {},
): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: '127.0.0.1', port, path, method,
        headers: { ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}), ...headers },
        // A fresh connection per call: a pooled keep-alive socket the server closes while a slow
        // sweep runs between requests resets under load (same rule as broker-mcp.test.ts).
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

/** A fake Slack Web API as the WebClient's own `fetch` (it rides global fetch by default, which the
 * provider-egress stub owns): records every call the bounded notification client makes. `fail`
 * makes every call reject at the transport (an ambiguous outcome); `hold` parks each call until
 * it resolves (an in-flight post). */
function fakeSlack(members: string[] = ['U1']): {
  fetch: typeof fetch;
  calls: { method: string; args: any }[];
  fail: Error | null;
  hold: Promise<void> | null;
} {
  const calls: { method: string; args: any }[] = [];
  const state = { fail: null as Error | null, hold: null as Promise<void> | null };
  const slackFetch = (async (input: any, init?: any) => {
    const raw = typeof init?.body === 'string' ? init.body : await new Response(init?.body).text();
    let args: any;
    try { args = JSON.parse(raw); } catch { args = Object.fromEntries(new URLSearchParams(raw)); }
    if (typeof args.blocks === 'string') args.blocks = JSON.parse(args.blocks);
    const method = new URL(String(input instanceof Request ? input.url : input)).pathname.replace(/^\/api\//, '');
    calls.push({ method, args });
    if (state.hold) await state.hold;
    if (state.fail) throw state.fail;
    const body = method === 'conversations.info'
      ? { ok: true, channel: { id: args.channel, is_channel: true, creator: 'U1' } }
      : method === 'conversations.members' ? { ok: true, members }
      : method === 'users.info' ? { ok: true, user: { is_admin: false } }
      : { ok: true };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return {
    fetch: slackFetch,
    calls,
    get fail() { return state.fail; },
    set fail(v) { state.fail = v; },
    get hold() { return state.hold; },
    set hold(v) { state.hold = v; },
  };
}

/** Stub provider egress (TEST-3); restored in t.after. */
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

async function harness(t: TestContext, o: { allowWrites?: boolean; provider?: Provider; members?: string[] } = {}) {
  const provider = o.provider ?? acme;
  const db = await openTestDb(t);
  const key = randomBytes(32);
  process.env.VOUCHR_MASTER_KEY = key.toString('base64'); // createVouchr's keyring == the broker's vault key
  const vault = new Vault(db, key);
  const audit = new Audit(db);
  await vault.upsert(userOwner(ID), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  // Deny-by-default on the Bolt side: the control plane only delivers for an enabled provider.
  await setChannelToolEnabled(new ChannelTools(db), 'T1', 'C1', 'acme', true);
  const server = createBroker({
    providers: [provider], vault, audit, db, identitySecret: identityConfig(SECRET),
    allowWrites: o.allowWrites ?? true,
  });
  await new Promise<void>((r) => server.listen(0, r));
  t.after(() => new Promise<void>((r) => server.close(() => r())));
  const port = (server.address() as any).port;
  const slack = fakeSlack(o.members);
  const vouchr = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', db,
    botToken: 'xoxb-test-bot-token',
    slackClientOptions: { slackApiUrl: 'https://slack.local/api/', fetch: slack.fetch },
  });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, h: any) => { actions[id] = h; },
  });
  const clickClient = {
    users: { info: async () => ({ user: { is_admin: false } }) },
    conversations: {
      info: async ({ channel }: any) => ({ channel: { id: channel, is_channel: true, creator: 'U1' } }),
      members: async () => ({ members: o.members ?? ['U1'] }),
    },
    chat: { postEphemeral: async () => ({}), postMessage: async () => ({}) },
  } as any;
  const click = async (actionId: string, id: string, clicker = 'U1') => {
    const responds: any[] = [];
    await actions[actionId]({
      ack: async () => {},
      body: { team: { id: 'T1' }, user: { id: clicker }, channel: { id: 'C1' }, container: { channel_id: 'C1', thread_ts: 'TH1' }, actions: [{ value: id }] },
      client: clickClient,
      respond: async (m: any) => { responds.push(m); },
    });
    return responds;
  };
  const prompts = () => slack.calls.filter((c) => c.method === 'chat.postEphemeral' || c.method === 'chat.postMessage');
  const audits = async (action: string) =>
    (await db.all(`SELECT user_id, actor, meta FROM audit WHERE action=? ORDER BY at`, [action])) as any[];
  const authorize = (over: Record<string, unknown> = {}) => request(port, 'POST', '/v1/authorization', {
    handle: { provider: 'acme', owner: 'user' }, identityToken: tok(),
    method: 'POST', path: '/repos', bindingMessage: 'Create repository "demo" in org acme', ...over,
  });
  const status = (id: string, token = tok()) => request(port, 'GET', `/v1/authorization/${id}`, undefined, { 'x-vouchr-identity': token });
  const fetchAction = (over: Record<string, unknown> = {}) => request(port, 'POST', '/v1/fetch', {
    handle: { provider: 'acme', owner: 'user' }, identityToken: tok(), method: 'POST', path: '/repos', body: '{}', ...over,
  });
  return { db, port, vouchr, slack, prompts, click, audits, authorize, status, fetchAction };
}

test('#296 initiate → deliver on the control plane → approve → poll → the retried action spends the grant once', async (t) => {
  const upstream = stubUpstream(t);
  const h = await harness(t);

  // ── Initiate: nothing executes, one pending row + one audit row, dedup on repeat. ─────────────
  const first = await h.authorize();
  assert.equal(first.status, 200, JSON.stringify(first.json));
  assert.deepEqual(Object.keys(first.json).sort(), ['authorizationId', 'expiresAt', 'status']);
  assert.equal(first.json.status, 'pending');
  assert.ok(first.json.expiresAt > Date.now(), 'expiresAt is a future epoch-ms instant');
  assert.equal(upstream.length, 0, 'initiation never reaches the provider');
  const again = await h.authorize({ bindingMessage: 'a different statement for the same action' });
  assert.equal(again.json.authorizationId, first.json.authorizationId, 'the exact action deduplicates to one request');
  assert.equal((await h.audits('approval_requested')).length, 1, 'a reused request writes no second audit row');
  const stored = await h.db.get<any>(`SELECT binding_message, status FROM approval_request WHERE id=?`, [first.json.authorizationId]);
  assert.equal(stored.binding_message, 'Create repository "demo" in org acme', 'the first statement is what the human will read');
  assert.equal(stored.status, 'pending');
  assert.ok(!JSON.stringify(await h.db.all(`SELECT meta FROM audit`)).includes('Create repository'), 'the statement is never audited');

  // ── Poll: bound to the requester. ───────────────────────────────────────────────────────────
  assert.equal((await h.status(first.json.authorizationId)).json.status, 'pending');
  assert.equal((await h.status(first.json.authorizationId, tok({ userId: 'U2' }))).status, 404, 'another user reads unknown');
  assert.equal((await h.status(randomUUID())).status, 404);
  assert.equal((await h.status('not-a-uuid')).status, 404);
  assert.equal((await request(h.port, 'GET', `/v1/authorization/${first.json.authorizationId}`)).status, 401, 'identity is required');
  assert.equal((await h.status(first.json.authorizationId, 'garbage')).status, 401);

  // ── Deliver: no Slack turn exists; the control plane's pass posts the decision surface. ──────
  assert.equal(h.prompts().length, 0);
  await h.vouchr.sweepExpired();
  const posted = h.prompts();
  assert.equal(posted.length, 1, 'exactly one prompt');
  assert.equal(posted[0].method, 'chat.postEphemeral');
  assert.equal(posted[0].args.user, 'U1', 'self approval goes to the requester');
  assert.equal(posted[0].args.channel, 'C1');
  assert.equal(posted[0].args.thread_ts, 'TH1', 'delivered into the stored conversation');
  const rendered = JSON.stringify(posted[0].args.blocks);
  assert.ok(rendered.includes(APPROVAL_APPROVE_ACTION) && rendered.includes(APPROVAL_DENY_ACTION));
  assert.ok(rendered.includes('Create repository \\"demo\\" in org acme'), 'the binding message is on the prompt');
  assert.ok(!rendered.includes(TOKEN), 'SEC-1');
  assert.ok(!rendered.includes('/repos'), 'raw path never rendered');
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1, 'a delivered prompt is not re-posted by the next pass');

  // ── Approve → poll reads approved → the retried action spends the single-use grant. ──────────
  await h.click(APPROVAL_APPROVE_ACTION, first.json.authorizationId);
  assert.equal((await h.status(first.json.authorizationId)).json.status, 'approved');
  const done = await h.fetchAction();
  assert.equal(done.status, 200, JSON.stringify(done.json));
  assert.equal(upstream.length, 1, 'the approved action ran exactly once');
  assert.equal((await h.status(first.json.authorizationId)).status, 404, 'a spent grant is gone, not a status');
  const repeat = await h.fetchAction();
  assert.equal(repeat.status, 403);
  assert.equal(repeat.json.code, 'approval_required', 'single-use: the identical action re-prompts');
  assert.equal(upstream.length, 1);
  assert.equal((await h.audits('approval_consumed')).length, 1);
});

test('#322 member approver: the backchannel prompt is a channel message; the requester cannot approve it, a teammate can, once', async (t) => {
  const upstream = stubUpstream(t);
  const member = defineProvider({ ...acme, approval: { approver: 'member' } } as any);
  const h = await harness(t, { provider: member, members: ['U1', 'U2'] });
  const created = await h.authorize();
  assert.equal(created.status, 200, JSON.stringify(created.json));
  await h.vouchr.sweepExpired();
  const posted = h.prompts();
  assert.equal(posted.length, 1, 'exactly one prompt');
  assert.equal(posted[0].method, 'chat.postMessage', 'a regular message the whole channel can act on');
  assert.equal(posted[0].args.channel, 'C1');
  assert.equal(posted[0].args.thread_ts, 'TH1', 'delivered into the stored conversation');
  assert.equal(posted[0].args.user, undefined);
  const rendered = JSON.stringify(posted[0].args.blocks);
  assert.match(rendered, /Another member of this channel must approve it/);
  assert.ok(rendered.includes('Create repository \\"demo\\" in org acme'), 'the binding message is on the prompt');
  assert.ok(!rendered.includes(TOKEN), 'SEC-1');
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1, 'the durable channel message is not re-posted');

  // The requester's own click is refused and audited; the row stays pending for a teammate.
  const own = await h.click(APPROVAL_APPROVE_ACTION, created.json.authorizationId, 'U1');
  assert.match(String(own[0]?.text), /not eligible/i);
  assert.equal((await h.status(created.json.authorizationId)).json.status, 'pending');
  assert.equal((await h.audits('denied')).filter((r) => r.meta.includes('not-approver')).length, 1);

  // A teammate approves; the poller reads approved; the agent's spend runs exactly once.
  await h.click(APPROVAL_APPROVE_ACTION, created.json.authorizationId, 'U2');
  assert.equal((await h.status(created.json.authorizationId)).json.status, 'approved');
  const done = await h.fetchAction();
  assert.equal(done.status, 200, JSON.stringify(done.json));
  assert.equal(upstream.length, 1, 'the approved action ran exactly once');
  const consumed = await h.audits('approval_consumed');
  assert.equal(consumed.length, 1);
  assert.equal(consumed[0].actor, 'U2', 'the approver rides the actor column');
  assert.equal(consumed[0].user_id, 'U1', 'the requester stays the acting user');
});

test('#296 deny persists the outcome for the poller, audits once, and a new request is a new decision', async (t) => {
  stubUpstream(t);
  const h = await harness(t);
  const created = await h.authorize();
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1);
  const responds = await h.click(APPROVAL_DENY_ACTION, created.json.authorizationId);
  assert.match(responds[0]?.text ?? '', /Denied/);
  assert.equal((await h.status(created.json.authorizationId)).json.status, 'denied');
  const denied = await h.audits('denied');
  assert.equal(denied.filter((r) => JSON.parse(r.meta).reason === 'approval-denied').length, 1);
  assert.equal(denied[0].actor, 'U1');

  // A denied row is never pending (a stale click) nor spendable, and the pass never re-delivers it.
  const stale = await h.click(APPROVAL_APPROVE_ACTION, created.json.authorizationId);
  assert.match(stale[0]?.text ?? '', /expired or was already decided/);
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1, 'no re-delivery of a decided request');
  const blocked = await h.fetchAction();
  assert.equal(blocked.json.code, 'approval_required', 'a denial never becomes a grant');

  // Re-requesting the same action replaces the denial with a FRESH pending request.
  const next = await h.authorize();
  assert.equal(next.status, 200);
  assert.notEqual(next.json.authorizationId, created.json.authorizationId);
  assert.equal(next.json.status, 'pending');
  assert.equal((await h.status(created.json.authorizationId)).status, 404, 'the replaced denial is gone');

  // The retained denial is reclaimed by the sweep WITHOUT a second denial audit.
  const third = await h.authorize({ path: '/other' });
  await h.vouchr.sweepExpired();
  await h.click(APPROVAL_DENY_ACTION, third.json.authorizationId);
  await h.db.run(`UPDATE approval_request SET expires_at=0 WHERE id=?`, [third.json.authorizationId]);
  await h.vouchr.sweepExpired();
  assert.equal((await h.status(third.json.authorizationId)).status, 404);
  const after = await h.audits('denied');
  assert.equal(after.filter((r) => JSON.parse(r.meta).reason === 'approval-denied').length, 2, 'one denial audit per human decision');
  assert.equal(after.filter((r) => JSON.parse(r.meta).reason === 'approval-expired').length, 0, 'a reclaimed denial is not an expiry');
});

test('#296 expiry: the poller reads expired, then the sweep reclaims it with the system expiry audit', async (t) => {
  stubUpstream(t);
  const h = await harness(t);
  const created = await h.authorize();
  await h.db.run(`UPDATE approval_request SET expires_at=0 WHERE id=?`, [created.json.authorizationId]);
  assert.equal((await h.status(created.json.authorizationId)).json.status, 'expired');
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 0, 'an expired request is never delivered');
  assert.equal((await h.status(created.json.authorizationId)).status, 404);
  const expiry = await h.audits('denied');
  assert.equal(expiry.length, 1);
  assert.equal(expiry[0].actor, 'system');
  assert.equal(JSON.parse(expiry[0].meta).reason, 'approval-expired');
});

test('#296 install() delivers pending backchannel prompts on its own bounded timer; stop() waits for a pass in flight', async (t) => {
  stubUpstream(t);
  const h = await harness(t);
  const app = { use: () => undefined, command: () => undefined, view: () => undefined, action: () => undefined, event: () => undefined };
  const receiver = { router: { get: () => undefined } };
  assert.throws(() => h.vouchr.install(app, receiver, { sweepIntervalMs: 0, authorizationDeliveryIntervalMs: 1.5 }), /authorizationDeliveryIntervalMs/);
  assert.throws(() => h.vouchr.install(app, receiver, { sweepIntervalMs: 0, authorizationDeliveryIntervalMs: -1 }), /authorizationDeliveryIntervalMs/);
  const created = await h.authorize();
  // Park the Slack post so the first pass is still in flight when stop() is called.
  let release!: () => void;
  h.slack.hold = new Promise<void>((r) => { release = r; });
  const handle = h.vouchr.install(app, receiver, { sweepIntervalMs: 0, authorizationDeliveryIntervalMs: 20 });
  const deadline = Date.now() + 5_000;
  while (h.prompts().length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
  assert.equal(h.prompts().length, 1, 'the timer started exactly one post');
  let stopped = false;
  const stopping = handle.stop().then(() => { stopped = true; });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(stopped, false, 'stop() waits for the in-flight delivery pass');
  release();
  await stopping;
  assert.equal(stopped, true);
  await new Promise((r) => setTimeout(r, 120)); // the timer is gone: no further ticks post anything
  assert.equal(h.prompts().length, 1, 'exactly one prompt, delivered once');
  assert.ok(JSON.stringify(h.prompts()[0].args.blocks).includes(created.json.authorizationId));
  const row = await h.db.get<any>(`SELECT delivered_at FROM approval_request WHERE id=?`, [created.json.authorizationId]);
  assert.ok(row.delivered_at, 'the parked post confirmed its delivery before stop() returned');
});

test('#296 a spend must carry the initiating conversation claims; a mismatch mints an ordinary (undelivered) request', async (t) => {
  const upstream = stubUpstream(t);
  const h = await harness(t);
  const created = await h.authorize();
  await h.vouchr.sweepExpired();
  await h.click(APPROVAL_APPROVE_ACTION, created.json.authorizationId);
  assert.equal((await h.status(created.json.authorizationId)).json.status, 'approved');

  // Same action, same user, but the spend token omits threadTs: the grant does not match.
  const mismatch = await h.fetchAction({ identityToken: tok({ threadTs: undefined }) });
  assert.equal(mismatch.status, 403);
  assert.equal(mismatch.json.code, 'approval_required');
  assert.notEqual(mismatch.json.approvalId, created.json.authorizationId, 'a second, ordinary pending request');
  assert.equal(upstream.length, 0, 'nothing executed');
  assert.equal((await h.status(created.json.authorizationId)).json.status, 'approved', 'the real grant is untouched');
  const other = await h.db.get<any>(`SELECT binding_message, thread FROM approval_request WHERE id=?`, [mismatch.json.approvalId]);
  assert.deepEqual(other, { binding_message: null, thread: '' }, 'the mismatch row is not a backchannel request');
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1, 'the delivery timer never posts the mismatch row');

  // The correctly bound spend still works exactly once.
  assert.equal((await h.fetchAction()).status, 200);
  assert.equal(upstream.length, 1);
});

test('#296 an authorization request spends the provider rate budget like the action would', async (t) => {
  stubUpstream(t);
  const limited = defineProvider({
    id: 'acme', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.acme.test'], egressMethods: ['GET', 'POST'],
    approval: { approver: 'self' }, rateLimit: { perMinute: 2 },
    refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  const h = await harness(t, { provider: limited });
  assert.equal((await h.authorize({ path: '/a' })).status, 200);
  assert.equal((await h.authorize({ path: '/b' })).status, 200);
  const third = await h.authorize({ path: '/c' });
  assert.equal(third.status, 429);
  assert.equal(third.json.code, 'rate_limited');
  assert.ok(third.json.retryAfterMs > 0);
  assert.equal((await h.db.all(`SELECT 1 FROM approval_request`)).length, 2, 'the over-budget request queued no prompt');
  assert.equal((await h.audits('rate_limited')).length, 1);
});

test('#296 an ambiguous Slack failure keeps the delivery lease: no second post until the lease lapses', async (t) => {
  stubUpstream(t);
  const h = await harness(t);
  const created = await h.authorize();
  h.slack.fail = new Error('ECONNRESET');
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1, 'one attempt');
  const afterFailure = await h.db.get<any>(
    `SELECT status, delivered_at, delivery_token FROM approval_request WHERE id=?`, [created.json.authorizationId],
  );
  assert.equal(afterFailure.status, 'pending', 'the row is retained');
  assert.equal(afterFailure.delivered_at, null);
  assert.ok(afterFailure.delivery_token, 'the ambiguous outcome keeps its lease');
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 1, 'no second post while the lease is live');
  // The lease lapses (30s in production; forced here) and Slack recovers: exactly one more post.
  h.slack.fail = null;
  await h.db.run(`UPDATE approval_request SET delivery_lease_expires_at=0 WHERE id=?`, [created.json.authorizationId]);
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 2);
  await h.vouchr.sweepExpired();
  assert.equal(h.prompts().length, 2, 'delivered once the lease lapsed, never again');
  assert.ok((await h.db.get<any>(`SELECT delivered_at FROM approval_request WHERE id=?`, [created.json.authorizationId])).delivered_at);
});

test('#296 input grammar and gates: bindingMessage bounds, non-approval actions, writes, provider, egress', async (t) => {
  stubUpstream(t);
  const h = await harness(t);
  for (const bad of [
    undefined, '', '   ', '\n\t', 42, null, { text: 'x' },
    'x'.repeat(MAX_BINDING_MESSAGE_BYTES + 1), 'é'.repeat(MAX_BINDING_MESSAGE_BYTES),
    'a\u0000b', 'a\u0007b', 'a\u001bb', 'a\u007fb', // NUL (PostgreSQL refuses it), BEL, ESC, DEL
  ]) {
    const r = await h.authorize({ bindingMessage: bad });
    assert.equal(r.status, 400, `bindingMessage ${JSON.stringify(bad)?.slice(0, 20)} → 400`);
    assert.match(r.json.error, /bindingMessage/);
  }
  assert.equal((await h.db.all(`SELECT 1 FROM approval_request`)).length, 0, 'rejected input persists nothing');
  // A 400 is decided before identity verification, so the assertion is not spent by it.
  const spare = tok();
  assert.equal((await h.authorize({ identityToken: spare, bindingMessage: 'a\u0000b' })).status, 400);
  assert.equal((await h.authorize({ identityToken: spare, bindingMessage: 'line one\nline two\ttabbed' })).status, 200, 'newline and tab are allowed');
  assert.equal((await h.authorize({ path: '/bounded', bindingMessage: 'x'.repeat(MAX_BINDING_MESSAGE_BYTES) })).status, 200, 'exactly the bound is accepted');

  const noApproval = await h.authorize({ method: 'GET', path: '/me' });
  assert.equal(noApproval.status, 400);
  assert.match(noApproval.json.error, /does not require approval/);
  assert.equal((await h.authorize({ handle: { provider: 'nope', owner: 'user' } })).status, 404);
  assert.equal((await h.authorize({ method: 'TRACE' })).status, 400, 'invalid method');
  const egress = await h.authorize({ host: 'evil.example' });
  assert.equal(egress.status, 403);
  assert.equal(egress.json.code, 'egress_blocked');
  const replay = tok();
  await h.authorize({ identityToken: replay });
  assert.equal((await h.authorize({ identityToken: replay })).status, 401, 'single-use assertion');
  assert.equal((await h.authorize({ identityToken: tok({ userId: 'U9' }) })).status, 409, 'no credential → not connected');

  const readOnly = await harness(t, { allowWrites: false });
  const refused = await readOnly.authorize();
  assert.equal(refused.status, 405, 'a write the broker would refuse cannot mint a decision for itself');
});
