import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { defineProvider, type Provider } from '../src/core/providers';
import { createVouchr } from '../src/adapters/bolt';
import { Policy } from '../src/core/policy';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { CONFIG_CALLBACK, DISCONNECT_ACTION } from '../src/adapters/blocks';
import { userOwner } from '../src/core/owner';

// #109: no-arg `/vouchr` opens a config modal. Bolt-fake tests over the real registered handlers
// (command / view / action). The submit diffs each control against the OPEN-TIME state carried in the
// view's private_metadata, so these tests drive the real open→submit round-trip.
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ACTOR' };
const mkProvider = (id: string): Provider => defineProvider({
  id, authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
const provider = mkProvider('mcp');

async function harness(t: TestContext, opts: { slackAdmin?: boolean; providers?: Provider[]; policy?: Policy } = {}) {
  const { slackAdmin = false, providers = [provider], policy } = opts;
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({ providers, baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t), policy });
  let command: any;
  const views: Record<string, any> = {};
  const actions: Record<string, any> = {};
  lan.registerCommands({
    command: (_n: string, h: any) => (command = h),
    view: (id: string, h: any) => (views[id] = h),
    action: (id: string, h: any) => (actions[id] = h),
  });
  let opened: any = null;
  let updated: any = null;
  const client = {
    users: { info: async () => ({ user: { is_admin: slackAdmin } }) },
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator: 'U_OTHER' } }) },
    views: { open: async (a: any) => (opened = a), update: async (a: any) => (updated = a) },
    chat: { postMessage: async () => undefined },
  };
  const body = { team: { id: 'T1' }, user: { id: ID.userId } };
  const defaultMeta = JSON.stringify({ channel: 'C_FIN', open: [] });
  return {
    lan, client,
    /** Run no-arg `/vouchr`, return the opened modal view (with its real private_metadata). */
    openModal: async () => { await command({ command: { team_id: 'T1', user_id: ID.userId, channel_id: 'C_FIN', trigger_id: 'trig', text: '' }, ack: async () => {}, respond: async () => {}, client }); return opened?.view; },
    runCommand: (text: string, respond?: any) => command({ command: { team_id: 'T1', user_id: ID.userId, channel_id: 'C_FIN', trigger_id: 'trig', text }, ack: async () => {}, respond: respond ?? (async () => {}), client }),
    submit: (state: any, ack: any, privateMetadata: string = defaultMeta) => {
      const view = { callback_id: CONFIG_CALLBACK, private_metadata: privateMetadata, state: { values: state } };
      return views[CONFIG_CALLBACK]({ ack, body: { ...body, view }, view, client });
    },
    disconnect: (ack: any, view: any, value = 'mcp') => actions[DISCONNECT_ACTION]({ ack, body: { ...body, actions: [{ value }], view }, client }),
    opened: () => opened,
    updated: () => updated,
  };
}

const modeRow = async (db: any) =>
  ((await db.get('SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp'])) as any)?.mode ?? null;
const auditActions = async (db: any) => ((await db.all('SELECT action FROM audit')) as any[]).map((r) => r.action);
const checked = (v = 'enabled') => ({ enabled: { selected_options: [{ value: v }] } });
const unchecked = () => ({ enabled: { selected_options: [] } });

test('no-arg /vouchr opens the modal; non-admin sees NO admin controls (no submit)', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  const view = await h.openModal();
  assert.equal(view?.callback_id, CONFIG_CALLBACK);
  assert.equal(view.submit, undefined); // nothing to submit → no mutating controls shown
  assert.ok(!view.blocks.some((b: any) => typeof b.block_id === 'string' && b.block_id.startsWith('mode:')));
});

test('no-arg /vouchr opens the modal; admin sees per-provider mode + enable controls', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  const view = await h.openModal();
  assert.equal(view.submit?.text?.text ?? view.submit?.text, 'Save');
  assert.ok(view.blocks.some((b: any) => b.block_id === 'mode:mcp'));
  assert.ok(view.blocks.some((b: any) => b.block_id === 'tool:mcp'));
});

test('no-arg falls back to status text when views.open fails (never silent)', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  h.client.views.open = async () => { throw new Error('expired_trigger_id'); };
  let responded = '';
  await h.runCommand('', async (m: string) => { responded = m; });
  assert.match(responded, /No connected accounts|connected accounts/); // fell through to status text
});

test('forged non-admin submission is rejected by the same authz path (no mutation, audited denied)', async (t) => {
  const h = await harness(t, { slackAdmin: false }); // NOT an admin, but forges a mode-change submission
  let acked: any = null;
  await h.submit({ 'mode:mcp': { mode: { selected_option: { value: 'shared' } } } }, async (r: any) => (acked = r));
  assert.equal(acked?.response_action, 'errors'); // rejected inline
  assert.equal(await modeRow(h.lan.db), null); // nothing written
  assert.deepEqual(await auditActions(h.lan.db), ['denied']);
});

test('admin mode change via the modal == /vouchr mode: same channel_config + audit', async (t) => {
  const viaCommand = await harness(t, { slackAdmin: true });
  await viaCommand.runCommand('mode mcp per-user');
  assert.equal(await modeRow(viaCommand.lan.db), 'per-user');
  assert.deepEqual(await auditActions(viaCommand.lan.db), ['config']);

  const viaModal = await harness(t, { slackAdmin: true });
  let acked = 'unset';
  await viaModal.submit({ 'mode:mcp': { mode: { selected_option: { value: 'per-user' } } } }, async (r?: any) => (acked = r ?? 'ack'));
  assert.equal(acked, 'ack');
  assert.equal(await modeRow(viaModal.lan.db), 'per-user');
  assert.deepEqual(await auditActions(viaModal.lan.db), ['config']);
});

test('forged invalid mode value is ignored server-side, never persisted', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  let acked = 'unset';
  await h.submit({ 'mode:mcp': { mode: { selected_option: { value: 'evil-mode' } } } }, async (r?: any) => (acked = r ?? 'ack'));
  assert.equal(acked, 'ack');
  assert.equal(await modeRow(h.lan.db), null);
  assert.deepEqual(await auditActions(h.lan.db), []);
});

// Finding 1: disabling ONE provider on an unconfigured channel must not silently disable the others.
test('disabling one provider materializes the full allowlist; the others stay enabled', async (t) => {
  const h = await harness(t, { slackAdmin: true, providers: ['a', 'b', 'c'].map(mkProvider) });
  const view = await h.openModal();
  const pm = view.private_metadata; // real open-time state (all enabled, unconfigured)
  await h.submit({ 'tool:a': unchecked(), 'tool:b': checked(), 'tool:c': checked() }, async () => {}, pm);
  const tools = new ChannelTools(h.lan.db);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'a'), false); // the one the admin unchecked
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'b'), true); // NOT silently disabled
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'c'), true);
  assert.deepEqual(await auditActions(h.lan.db), ['config']); // only the real change (a) audited
});

// Finding 2: a stale save (untouched select re-submitting its open value) must not revert a change
// another admin made in between, nor delete the shared credential leaving 'shared' mode.
test('untouched mode select does not revert a concurrent change or delete the shared credential', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  const cfg = new ChannelConfig(h.lan.db);
  await cfg.setMode('T1', 'C_FIN', 'mcp', 'per-user');
  const view = await h.openModal(); // opens with mode 'per-user' as the select's initial
  const pm = view.private_metadata;
  // Between open and save, another admin flips to shared and connects a shared credential.
  await cfg.setMode('T1', 'C_FIN', 'mcp', 'shared');
  await h.lan.vault.upsert({ teamId: 'T1', kind: 'channel', id: 'C_FIN', enterpriseId: null }, 'mcp', { accessToken: 'SHARED', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  // A saves the modal without touching the mode select (it re-submits its open value 'per-user').
  await h.submit({ 'mode:mcp': { mode: { selected_option: { value: 'per-user' } } } }, async () => {}, pm);
  assert.equal(await modeRow(h.lan.db), 'shared'); // NOT reverted to per-user
  assert.ok(await h.lan.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN', enterpriseId: null }, 'mcp')); // cred survived
});

// Finding 3: a policy-denied provider must not be spuriously disabled by an untouched save. The admin
// checkbox reflects the ALLOWLIST bit (enabled), not the policy-intersected manifest, so an untouched
// save is a true no-op.
test('untouched save with a policy-denied provider writes no channel_tool row', async (t) => {
  const h = await harness(t, { slackAdmin: true, policy: new Policy({ mcp: { defaultAllow: true, denyChannels: ['C_FIN'] } }) }); // denies mcp in C_FIN
  const view = await h.openModal();
  const pm = view.private_metadata;
  await h.submit({ 'tool:mcp': checked() }, async () => {}, pm); // checkbox untouched (allowlist-enabled)
  assert.equal(await new ChannelTools(h.lan.db).isConfigured('T1', 'C_FIN'), false); // no allowlist row written
  assert.deepEqual(await auditActions(h.lan.db), []);
});

test('the Disconnect button carries a confirm dialog (no accidental one-click revoke)', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  await h.lan.vault.upsert(userOwner(ID), 'mcp', { accessToken: 'TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const view = await h.openModal();
  const btn = view.blocks.map((b: any) => b.accessory).find((a: any) => a?.action_id === DISCONNECT_ACTION);
  assert.ok(btn?.confirm?.confirm?.text); // Block Kit confirm object present
});

test('disconnect button removes the user connection and refreshes the modal view', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  await h.lan.vault.upsert(userOwner(ID), 'mcp', { accessToken: 'TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await h.disconnect(async () => {}, { id: 'V1', callback_id: CONFIG_CALLBACK, private_metadata: JSON.stringify({ channel: 'C_FIN' }) });
  assert.equal(await h.lan.vault.get(userOwner(ID), 'mcp'), null);
  assert.equal(h.updated()?.view_id, 'V1');
});

// Finding 4/6: the exported DISCONNECT_ACTION must NOT act when the click came from a foreign view
// (a host embedding disconnectConfirmBlocks in their own modal) — else it double-fires + clobbers.
test('disconnect action ignores a non-Vouchr view (no double-fire, no clobber)', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  await h.lan.vault.upsert(userOwner(ID), 'mcp', { accessToken: 'TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await h.disconnect(async () => {}, { id: 'HOST', callback_id: 'host_modal', private_metadata: '{}' });
  assert.ok(await h.lan.vault.get(userOwner(ID), 'mcp')); // NOT disconnected — host owns this action
  assert.deepEqual(await auditActions(h.lan.db), []);
  assert.equal(h.updated(), null); // did not clobber the host's view
});

// Finding 5: an unknown/forged provider value must not be revoked or written to the audit column.
test('disconnect action rejects an unknown provider (no audit pollution)', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  await h.disconnect(async () => {}, { id: 'V1', callback_id: CONFIG_CALLBACK, private_metadata: JSON.stringify({ channel: 'C_FIN' }) }, 'not-a-provider');
  assert.deepEqual(await auditActions(h.lan.db), []); // nothing audited for the bogus provider
});
