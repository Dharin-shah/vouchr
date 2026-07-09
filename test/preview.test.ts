import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { ChannelConfig, isPreviewVisibility } from '../src/core/channelConfig';
import { PendingPreviews } from '../src/core/preview';
import { previewBlocks, previewPostBlocks, PREVIEW_SHARE_ACTION, PREVIEW_DISMISS_ACTION } from '../src/adapters/blocks';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { ConnectContext, createVouchr } from '../src/adapters/bolt';

// Private preview mode: per-channel `visibility` bit + the single-use share claim. The security
// property under test end-to-end: provider-derived output in a 'private' channel reaches ONLY the
// requester until that human explicitly shares it — and only the requester can share it.

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_A' };
const CLAIM = { userId: 'U_A', teamId: 'T1', channel: 'C_FIN' };

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

// ── ChannelConfig.visibility: the policy bit ──

test('visibility: no row → public; set/get round-trip; scoped per channel+provider', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const cfg = new ChannelConfig(db);
  assert.equal(await cfg.getVisibility('T1', 'C_FIN', 'mcp'), 'public');
  await cfg.setVisibility('T1', 'C_FIN', 'mcp', 'private');
  assert.equal(await cfg.getVisibility('T1', 'C_FIN', 'mcp'), 'private');
  assert.equal(await cfg.getVisibility('T1', 'C_OTHER', 'mcp'), 'public'); // other channel untouched
  assert.equal(await cfg.getVisibility('T1', 'C_FIN', 'github'), 'public'); // other provider untouched
  await cfg.setVisibility('T1', 'C_FIN', 'mcp', 'public'); // flip back (upsert path)
  assert.equal(await cfg.getVisibility('T1', 'C_FIN', 'mcp'), 'public');
});

test('visibility: the runtime guard refuses a bogus value at the sink (SEC-4)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const cfg = new ChannelConfig(db);
  await assert.rejects(() => cfg.setVisibility('T1', 'C_FIN', 'mcp', 'everyone' as any), /invalid preview visibility/);
  assert.equal(isPreviewVisibility('private'), true);
  assert.equal(isPreviewVisibility('everyone'), false);
});

// ── PendingPreviews: the single-use share claim (the SEC-3 decision) ──

const entry = { teamId: 'T1', userId: 'U_A', channel: 'C_FIN', thread: null, provider: 'mcp', title: 't', lines: ['l'] };

test('pending previews: a claim is single-use and bound to recipient+team+channel', () => {
  const store = new PendingPreviews();
  const id = store.put(entry);
  // A wrong-user claim returns null AND does not consume: the rightful recipient can still claim after.
  assert.equal(store.take(id, { ...CLAIM, userId: 'U_EVIL' }), null);
  assert.equal(store.take(id, { ...CLAIM, channel: 'C_OTHER' }), null); // wrong channel
  assert.equal(store.take(id, { ...CLAIM, teamId: 'T9' }), null); // wrong workspace
  const p = store.take(id, CLAIM);
  assert.equal(p?.provider, 'mcp');
  assert.equal(store.take(id, CLAIM), null); // single-use: a second share of the same preview refuses
});

test('pending previews: entries expire after the TTL and dismiss removes without posting', () => {
  let now = 1_000_000;
  const store = new PendingPreviews(10 * 60_000, 500, () => now);
  const id = store.put(entry);
  now += 10 * 60_000 + 1;
  assert.equal(store.take(id, CLAIM), null); // expired → the button reports "ask again"
  const id2 = store.put(entry);
  assert.equal(store.dismiss(id2, { ...CLAIM, userId: 'U_EVIL' }), false); // dismiss uses the same claim
  assert.equal(store.dismiss(id2, CLAIM), true);
  assert.equal(store.take(id2, CLAIM), null);
});

test('pending previews: the cap evicts oldest-first instead of growing unbounded', () => {
  const store = new PendingPreviews(60_000, 2);
  const a = store.put(entry);
  const b = store.put(entry);
  const c = store.put(entry); // over cap → a evicted
  assert.equal(store.take(a, CLAIM), null);
  assert.notEqual(store.take(b, CLAIM), null);
  assert.notEqual(store.take(c, CLAIM), null);
});

// ── Block templates: escaping + what the buttons carry ──

test('preview blocks escape provider-derived lines and carry ONLY the claim id in buttons', () => {
  const blocks = previewBlocks({
    provider: 'mcp', title: 'Open PRs', lines: ['<https://evil.com|Re-authorize> & <@U_EVIL>'],
    id: 'ID123', where: 'thread', ttlMinutes: 10,
  });
  const json = JSON.stringify(blocks);
  assert.doesNotMatch(json, /<https:\/\/evil\.com/); // a fetched string can't forge a live link/mention
  assert.match(json, /&lt;https:\/\/evil\.com/);
  const buttons = (blocks as any[]).flatMap((b) => b.elements ?? []).filter((e) => e.type === 'button');
  assert.equal(buttons.length, 2);
  for (const b of buttons) assert.equal(b.value, 'ID123'); // no content, no authority in the payload
  assert.deepEqual(buttons.map((b) => b.action_id).sort(), [PREVIEW_DISMISS_ACTION, PREVIEW_SHARE_ACTION].sort());
});

test('shared preview blocks attribute the human who shared', () => {
  const json = JSON.stringify(previewPostBlocks({ provider: 'mcp', title: 't', lines: ['x'], sharedBy: 'U_A' }));
  assert.match(json, /Shared by <@U_A>/);
});

// ── ConnectContext: the admin gate + posting paths ──

async function ctx(opts: { isAdmin?: boolean; visibility?: 'public' | 'private'; thread?: string | null } = {}) {
  const db = await openDb({ dbPath: ':memory:' });
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  if (opts.visibility) await channelConfig.setVisibility('T1', 'C_FIN', 'mcp', opts.visibility);
  const posted: any[] = [];
  const ephemeral: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: opts.isAdmin ?? false } }) },
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator: 'U_X' } }) },
    chat: {
      postMessage: async (m: any) => { posted.push(m); return { ok: true }; },
      postEphemeral: async (m: any) => { ephemeral.push(m); return { ok: true }; },
    },
  } as any;
  const previews = new PendingPreviews();
  const c = new ConnectContext({
    identity: ID, channel: 'C_FIN', client, registry: new ProviderRegistry([provider]),
    vault: new Vault(db, KEY), audit, consent: new Consent(db), policy: new Policy(),
    redirectUri: 'http://x', channelConfig, previews, thread: opts.thread ?? null,
  });
  return { c, db, posted, ephemeral, previews };
}

test('setChannelVisibility: non-admin is denied and audited; admin write is audited as config', async () => {
  const denied = await ctx({ isAdmin: false });
  await assert.rejects(() => denied.c.setChannelVisibility('mcp', 'private'), /admin/);
  let rows = (await denied.db.all(`SELECT action FROM audit`)) as any[];
  assert.deepEqual(rows.map((r) => r.action), ['denied']);

  const admin = await ctx({ isAdmin: true });
  await admin.c.setChannelVisibility('mcp', 'private');
  rows = (await admin.db.all(`SELECT action, provider, meta FROM audit`)) as any[];
  assert.equal(rows[0].action, 'config');
  assert.equal(JSON.parse(rows[0].meta).visibility, 'private');
  assert.equal(JSON.parse(rows[0].meta).owner, 'channel');
});

test('setChannelVisibility: unknown provider is refused BEFORE persist/audit (SEC-4)', async () => {
  const { c, db } = await ctx({ isAdmin: true });
  await assert.rejects(() => c.setChannelVisibility('nope', 'private'));
  assert.equal(((await db.all(`SELECT * FROM audit`)) as any[]).length, 0);
  assert.equal(((await db.all(`SELECT * FROM channel_preview`)) as any[]).length, 0);
});

test('preview(): public (default) posts to the channel; private posts ephemerally to the requester', async () => {
  const pub = await ctx();
  assert.equal(await pub.c.preview('mcp', { title: 'PRs', lines: ['#1'] }), 'posted');
  assert.equal(pub.posted.length, 1);
  assert.equal(pub.posted[0].channel, 'C_FIN');
  assert.equal(pub.ephemeral.length, 0);

  const priv = await ctx({ visibility: 'private', thread: '111.222' });
  assert.equal(await priv.c.preview('mcp', { title: 'PRs', lines: ['#1'] }), 'private');
  assert.equal(priv.posted.length, 0); // nothing reached the channel
  assert.equal(priv.ephemeral.length, 1);
  assert.equal(priv.ephemeral[0].user, 'U_A'); // only the requester sees it
  assert.equal(priv.ephemeral[0].thread_ts, '111.222');
  assert.match(JSON.stringify(priv.ephemeral[0].blocks), /Share to thread/);
});

test('preview(): unknown provider throws and nothing is posted or stored', async () => {
  const { c, posted, ephemeral } = await ctx({ visibility: 'private' });
  await assert.rejects(() => c.preview('nope', { title: 't', lines: [] }));
  assert.equal(posted.length + ephemeral.length, 0);
});

// ── End-to-end through createVouchr: middleware → private preview → Share click (TEST-2) ──

async function harness() {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({ providers: [provider], baseUrl: 'http://127.0.0.1:1', dbPath: ':memory:' });
  const actions: Record<string, any> = {};
  lan.registerCommands({ command: () => undefined, view: () => undefined, action: (id: string, h: any) => (actions[id] = h) });
  const posted: any[] = [];
  const ephemeral: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator: 'U_X' } }) },
    chat: {
      postMessage: async (m: any) => { posted.push(m); return { ok: true }; },
      postEphemeral: async (m: any) => { ephemeral.push(m); return { ok: true }; },
    },
  } as any;
  // Run the real middleware to get the same context.vouchr an agent handler sees.
  const args: any = {
    client,
    event: { channel: 'C_FIN', user: 'U_A', team: 'T1', thread_ts: '111.222' },
    body: { team_id: 'T1', user_id: 'U_A' },
    context: {},
    next: async () => {},
  };
  await lan.middleware(args);
  return { lan, actions, client, posted, ephemeral, vouchr: args.context.vouchr };
}

test('e2e: private preview → only the recipient can share; the share posts publicly, attributed + audited', async () => {
  const { lan, actions, client, posted, ephemeral, vouchr } = await harness();
  await new ChannelConfig(lan.db).setVisibility('T1', 'C_FIN', 'mcp', 'private');

  assert.equal(await vouchr.preview('mcp', { title: 'Open PRs (2)', lines: ['#1 fix', '#2 feat'] }), 'private');
  assert.equal(posted.length, 0);
  const share = JSON.parse(JSON.stringify(ephemeral[0].blocks)).flatMap((b: any) => b.elements ?? [])
    .find((e: any) => e.action_id === PREVIEW_SHARE_ACTION);
  const clickBody = (userId: string) => ({
    user: { id: userId, team_id: 'T1' }, team: { id: 'T1' },
    channel: { id: 'C_FIN' }, actions: [{ value: share.value }],
  });

  // A forged click by someone else: no post, and the preview is NOT consumed.
  const responses: any[] = [];
  await actions[PREVIEW_SHARE_ACTION]({ ack: async () => {}, body: clickBody('U_EVIL'), respond: async (m: any) => responses.push(m), client });
  assert.equal(posted.length, 0);
  assert.match(responses[0].text, /expired/);

  // The recipient's click: posted publicly in the same thread, attributed, audited, single-use.
  await actions[PREVIEW_SHARE_ACTION]({ ack: async () => {}, body: clickBody('U_A'), respond: async () => {}, client });
  assert.equal(posted.length, 1);
  assert.equal(posted[0].channel, 'C_FIN');
  assert.equal(posted[0].thread_ts, '111.222');
  assert.match(JSON.stringify(posted[0].blocks), /Shared by <@U_A>/);
  const rows = (await lan.db.all(`SELECT action, provider, meta FROM audit WHERE action='preview'`)) as any[];
  assert.equal(rows.length, 1);
  assert.equal(rows[0].provider, 'mcp');
  assert.equal(JSON.parse(rows[0].meta).event, 'shared');
  await actions[PREVIEW_SHARE_ACTION]({ ack: async () => {}, body: clickBody('U_A'), respond: async () => {}, client });
  assert.equal(posted.length, 1); // a second click can't double-post
});

test('e2e: toolManifest reports the visibility bit agents plan against', async () => {
  const { lan, vouchr } = await harness();
  assert.equal((await vouchr.toolManifest())[0].visibility, 'public');
  await new ChannelConfig(lan.db).setVisibility('T1', 'C_FIN', 'mcp', 'private');
  assert.equal((await vouchr.toolManifest())[0].visibility, 'private');
});
