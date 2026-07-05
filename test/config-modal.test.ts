import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { defineProvider } from '../src/core/providers';
import { createVouchr } from '../src/adapters/bolt';
import { CONFIG_CALLBACK, DISCONNECT_ACTION } from '../src/adapters/blocks';
import { userOwner } from '../src/core/owner';

// #109: no-arg `/vouchr` opens a config modal. These are bolt-fake tests over the real registered
// handlers (command / view / action), asserting: the modal renders admin controls ONLY for admins;
// a forged non-admin submission is rejected by the SAME authz path; an admin mode change via the
// modal produces the SAME channel_config + audit rows as `/vouchr mode`.
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ACTOR' };
const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

/** Wire a real createVouchr, capture the command/view/action handlers, and expose a fake Slack client
 *  whose users.info reports admin per `slackAdmin`. Mirrors channel-admin.test.ts's harness. */
async function harness(opts: { slackAdmin: boolean } = { slackAdmin: false }) {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({ providers: [provider], baseUrl: 'http://127.0.0.1:1', dbPath: ':memory:' });
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
    users: { info: async () => ({ user: { is_admin: opts.slackAdmin } }) },
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator: 'U_OTHER' } }) },
    views: { open: async (a: any) => (opened = a), update: async (a: any) => (updated = a) },
    chat: { postMessage: async () => undefined },
  };
  const body = { team: { id: 'T1' }, user: { id: ID.userId } };
  return {
    lan, client,
    runCommand: (text: string) => command({ command: { team_id: 'T1', user_id: ID.userId, channel_id: 'C_FIN', trigger_id: 'trig', text }, ack: async () => {}, respond: async () => {}, client }),
    submit: (state: any, ack: any) => views[CONFIG_CALLBACK]({ ack, body: { ...body, view: { private_metadata: JSON.stringify({ channel: 'C_FIN' }), state: { values: state } } }, view: { private_metadata: JSON.stringify({ channel: 'C_FIN' }), state: { values: state } }, client }),
    disconnect: (ack: any, view?: any) => actions[DISCONNECT_ACTION]({ ack, body: { ...body, actions: [{ value: 'mcp' }], view }, client, respond: async () => {} }),
    opened: () => opened,
    updated: () => updated,
  };
}

const modeRow = async (db: any) =>
  ((await db.get('SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp'])) as any)?.mode ?? null;
const auditActions = async (db: any) => ((await db.all('SELECT action FROM audit')) as any[]).map((r) => r.action);

test('no-arg /vouchr opens the modal; non-admin sees NO admin controls (no submit)', async () => {
  const h = await harness({ slackAdmin: false });
  await h.runCommand('');
  const view = h.opened()?.view as any;
  assert.equal(view?.callback_id, CONFIG_CALLBACK);
  assert.equal(view.submit, undefined); // nothing to submit → no mutating controls shown
  assert.ok(!view.blocks.some((b: any) => typeof b.block_id === 'string' && b.block_id.startsWith('mode:')));
});

test('no-arg /vouchr opens the modal; admin sees per-provider mode + enable controls', async () => {
  const h = await harness({ slackAdmin: true });
  await h.runCommand('');
  const view = h.opened()?.view as any;
  assert.equal(view.submit?.text?.text ?? view.submit?.text, 'Save');
  assert.ok(view.blocks.some((b: any) => b.block_id === 'mode:mcp'));
  assert.ok(view.blocks.some((b: any) => b.block_id === 'tool:mcp'));
});

test('forged non-admin submission is rejected by the same authz path (no mutation, audited denied)', async () => {
  const h = await harness({ slackAdmin: false }); // NOT an admin, but forges a mode-change submission
  let acked: any = null;
  await h.submit({ 'mode:mcp': { mode: { selected_option: { value: 'shared' } } } }, async (r: any) => (acked = r));
  assert.equal(acked?.response_action, 'errors'); // rejected inline
  assert.equal(await modeRow(h.lan.db), null); // nothing written
  assert.deepEqual(await auditActions(h.lan.db), ['denied']);
});

test('admin mode change via the modal == /vouchr mode: same channel_config + audit', async () => {
  // Baseline: run `/vouchr mode mcp per-user` as an admin.
  const viaCommand = await harness({ slackAdmin: true });
  await viaCommand.runCommand('mode mcp per-user');
  assert.equal(await modeRow(viaCommand.lan.db), 'per-user');
  assert.deepEqual(await auditActions(viaCommand.lan.db), ['config']);

  // Same change via the modal submit produces the identical DB state + audit row.
  const viaModal = await harness({ slackAdmin: true });
  let acked = 'unset';
  await viaModal.submit({ 'mode:mcp': { mode: { selected_option: { value: 'per-user' } } } }, async (r?: any) => (acked = r ?? 'ack'));
  assert.equal(acked, 'ack'); // ack() with no args = accepted
  assert.equal(await modeRow(viaModal.lan.db), 'per-user');
  assert.deepEqual(await auditActions(viaModal.lan.db), ['config']);
});

test('admin submit with unchanged values writes nothing (no spurious audit)', async () => {
  const h = await harness({ slackAdmin: true });
  // mcp is unconfigured (mode null, tool enabled-by-default). Submit tool checked = current → no-op.
  await h.submit({ 'tool:mcp': { enabled: { selected_options: [{ value: 'enabled' }] } } }, async () => {});
  assert.deepEqual(await auditActions(h.lan.db), []);
});

test('disconnect button removes the user connection and refreshes the modal view', async () => {
  const h = await harness({ slackAdmin: false });
  await h.lan.vault.upsert(userOwner(ID), 'mcp', { accessToken: 'TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await h.disconnect(async () => {}, { id: 'V1', private_metadata: JSON.stringify({ channel: 'C_FIN' }) });
  assert.equal(await h.lan.vault.get(userOwner(ID), 'mcp'), null); // credential gone
  assert.equal(h.updated()?.view_id, 'V1'); // modal re-rendered so the row disappears
});
