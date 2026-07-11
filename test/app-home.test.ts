import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { defineProvider, type Provider } from '../src/core/providers';
import { createVouchr } from '../src/adapters/bolt';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import {
  CONFIGURE_CALLBACK, DISCONNECT_ACTION, homeView,
  HOME_CALLBACK, HOME_CHANNEL_ACTION, HOME_MODE_ACTION, HOME_TOOL_ACTION, HOME_CONFIGURE_ACTION,
} from '../src/adapters/blocks';
import { userOwner, channelOwner } from '../src/core/owner';

// #111 App Home console: bolt-fake tests over the real registered handlers (event/action/command).
// The published view is role-dependent; every mutation routes through the SAME helpers as the slash
// commands (identical rows + audit by construction); and every forgeable interaction field — the
// private_metadata channel, block ids, button values, the mode value — is re-validated server-side.
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ACTOR' };
const mkProvider = (id: string): Provider => defineProvider({
  id, authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
const provider = mkProvider('mcp');
const CRED = { accessToken: 'TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'octo' };

async function harness(t: TestContext, opts: {
  slackAdmin?: boolean; allowCreator?: boolean; creator?: string;
  channelInfo?: Record<string, unknown>; infoThrows?: boolean; providers?: Provider[];
} = {}) {
  const { slackAdmin = false, allowCreator = false, creator = 'U_OTHER', providers = [provider] } = opts;
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers, baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t), allowChannelCreatorConfig: allowCreator,
  });
  let command: any;
  const actions: Record<string, any> = {};
  const events: Record<string, any> = {};
  lan.registerCommands({
    command: (_n: string, h: any) => (command = h),
    view: () => undefined,
    action: (id: string, h: any) => (actions[id] = h),
    event: (n: string, h: any) => (events[n] = h),
  });
  let published: any = null;
  let opened: any = null;
  const dms: string[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: slackAdmin } }) },
    conversations: {
      // Only C_FIN exists (unknown ids error, like Slack) — home handlers must fail closed on a
      // forged metadata channel that names nothing.
      info: async ({ channel }: any) => {
        if (opts.infoThrows || channel !== 'C_FIN') throw new Error('channel_not_found');
        return { channel: { id: channel, is_channel: true, creator, ...(opts.channelInfo ?? {}) } };
      },
    },
    views: { publish: async (a: any) => (published = a), open: async (a: any) => (opened = a), update: async () => undefined },
    chat: { postMessage: async (a: any) => { dms.push(String(a?.text ?? '')); } },
  };
  const body = { team: { id: 'T1' }, user: { id: ID.userId } };
  const view = (metaChannel: string | null) => ({
    id: 'V_HOME', type: 'home', callback_id: HOME_CALLBACK, private_metadata: JSON.stringify({ channel: metaChannel }),
  });
  const act = (id: string, action: any, metaChannel: string | null = 'C_FIN') =>
    actions[id]({ ack: async () => {}, body: { ...body, trigger_id: 'trig', view: view(metaChannel), actions: [action] }, client });
  return {
    lan, client, dms,
    published: () => published,
    opened: () => opened,
    /** Fire app_home_opened with OUR published view (our callback_id + `selected`) echoed back. */
    openHome: (selected: string | null = null) => events.app_home_opened({
      event: { user: ID.userId, tab: 'home', view: { callback_id: HOME_CALLBACK, private_metadata: JSON.stringify({ channel: selected }) } },
      body: { team_id: 'T1' },
      client,
    }),
    /** Fire app_home_opened with a raw event (first-ever open / a foreign host-published view). */
    fireHomeOpened: (event: any) => events.app_home_opened({ event, body: { team_id: 'T1' }, client }),
    /** Fire a registered action with a fully caller-built body (for foreign-view cases). */
    rawAction: (id: string, actionBody: any) => actions[id]({ ack: async () => {}, body: actionBody, client }),
    runCommand: (text: string, respond?: (m: any) => Promise<void>) => command({
      command: { team_id: 'T1', user_id: ID.userId, channel_id: 'C_FIN', trigger_id: 'trig', text },
      ack: async () => {}, respond: respond ?? (async () => {}), client,
    }),
    selectChannel: (channel: string) => act(HOME_CHANNEL_ACTION, { action_id: HOME_CHANNEL_ACTION, selected_conversation: channel }),
    setMode: (p: string, mode: string, metaChannel: string | null = 'C_FIN') =>
      act(HOME_MODE_ACTION, { block_id: `home_mode:${p}`, selected_option: { value: mode } }, metaChannel),
    toggleTool: (value: string, metaChannel: string | null = 'C_FIN') => act(HOME_TOOL_ACTION, { value }, metaChannel),
    configure: (p: string, metaChannel: string | null = 'C_FIN') => act(HOME_CONFIGURE_ACTION, { value: p }, metaChannel),
    disconnect: (p: string) => act(DISCONNECT_ACTION, { value: p }),
  };
}

const auditRows = async (db: any) =>
  (await db.all('SELECT action, provider, channel, meta FROM audit ORDER BY at')) as any[];
const auditActions = async (db: any) => (await auditRows(db)).map((r) => r.action);
const modeRow = async (db: any, channel = 'C_FIN') =>
  ((await db.get('SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?', ['T1', channel, 'mcp'])) as any)?.mode ?? null;
const toolBit = async (db: any) =>
  ((await db.get('SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp'])) as any)?.enabled;

test('app_home_opened: non-admin sees connections only; admin gets the governance selector', async (t) => {
  const nonAdmin = await harness(t, { slackAdmin: false });
  await nonAdmin.lan.vault.upsert(userOwner(ID), 'mcp', CRED);
  await nonAdmin.openHome();
  const pub = nonAdmin.published();
  assert.equal(pub.user_id, ID.userId);
  assert.equal(pub.view.type, 'home');
  assert.equal(pub.view.callback_id, HOME_CALLBACK); // the internal publisher stamps ownership
  let s = JSON.stringify(pub.view.blocks);
  assert.match(s, /mcp/); // the connection row
  assert.match(s, /octo/); // external account shown
  assert.ok(s.includes(DISCONNECT_ACTION)); // per-row Disconnect (same flow as the modal)
  assert.ok(!s.includes(HOME_CHANNEL_ACTION)); // no governance section for non-admins

  const admin = await harness(t, { slackAdmin: true });
  await admin.openHome();
  s = JSON.stringify(admin.published().view.blocks);
  assert.ok(s.includes(HOME_CHANNEL_ACTION)); // channel picker present
  assert.ok(!s.includes(HOME_MODE_ACTION)); // no control rows until a channel is picked
});

test('creator flag: creator gets rows for their channel; a foreign channel degrades to a note', async (t) => {
  const mine = await harness(t, { slackAdmin: false, allowCreator: true, creator: ID.userId });
  await mine.openHome('C_FIN');
  let s = JSON.stringify(mine.published().view.blocks);
  assert.ok(s.includes(HOME_MODE_ACTION)); // the existing eligibility function admitted the creator

  const foreign = await harness(t, { slackAdmin: false, allowCreator: true, creator: 'U_OTHER' });
  await foreign.openHome('C_FIN');
  s = JSON.stringify(foreign.published().view.blocks);
  assert.ok(s.includes(HOME_CHANNEL_ACTION)); // still offered the picker
  assert.ok(!s.includes(HOME_MODE_ACTION)); // but no controls for a channel they didn't create
  assert.match(s, /Only a workspace admin or the channel creator/);
});

test('selecting a channel re-renders rows reflecting the stored mode + enablement', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  await new ChannelConfig(h.lan.db).setMode('T1', 'C_FIN', 'mcp', 'session');
  await new ChannelTools(h.lan.db).setEnabled('T1', 'C_FIN', 'mcp', false);
  await h.selectChannel('C_FIN');
  const view = h.published().view;
  assert.equal(JSON.parse(view.private_metadata).channel, 'C_FIN'); // selection persists for the next render
  const modeBlock = view.blocks.find((b: any) => b.block_id === 'home_mode:mcp');
  assert.equal(modeBlock.accessory.initial_option.value, 'session'); // current mode as the select's initial
  const toolBlock = view.blocks.find((b: any) => b.block_id === 'home_tool:mcp');
  const toggle = toolBlock.elements.find((e: any) => e.action_id === HOME_TOOL_ACTION);
  assert.equal(toggle.value, 'enable:mcp'); // disabled now → the button offers Enable
  assert.ok(toolBlock.elements.some((e: any) => e.action_id === HOME_CONFIGURE_ACTION));
});

test('home mode select == /vouchr mode: identical channel_config row and audit row', async (t) => {
  const viaCommand = await harness(t, { slackAdmin: true });
  await viaCommand.runCommand('mode mcp session');
  const viaHome = await harness(t, { slackAdmin: true });
  await viaHome.setMode('mcp', 'session');
  assert.equal(await modeRow(viaHome.lan.db), 'session');
  assert.deepEqual(await auditRows(viaHome.lan.db), await auditRows(viaCommand.lan.db)); // STR-4 parity
  assert.ok(viaHome.published()); // re-published after the mutation
});

test('forged home mode action from a non-admin: no write, audited denied', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  await h.setMode('mcp', 'shared');
  assert.equal(await modeRow(h.lan.db), null);
  const rows = await auditRows(h.lan.db);
  assert.deepEqual(rows.map((r) => r.action), ['denied']);
  assert.match(rows[0].meta, /not-admin/);
});

test('forged invalid mode value never reaches state: shared cred survives, nothing audited', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  const owner = channelOwner('T1', 'C_FIN');
  await new ChannelConfig(h.lan.db).setMode('T1', 'C_FIN', 'mcp', 'shared');
  await h.lan.vault.upsert(owner, 'mcp', CRED);
  await h.setMode('mcp', 'evil-mode');
  assert.equal(await modeRow(h.lan.db), 'shared');
  assert.ok(await h.lan.vault.get(owner, 'mcp')); // setChannelMode's shared-cred cleanup never ran
  assert.deepEqual(await auditActions(h.lan.db), []);
});

test('home Enable/Disable == /vouchr enable|disable: identical channel_tool row and audit rows', async (t) => {
  const viaCommand = await harness(t, { slackAdmin: true });
  await viaCommand.runCommand('disable mcp');
  const viaHome = await harness(t, { slackAdmin: true });
  await viaHome.toggleTool('disable:mcp');
  assert.equal(await toolBit(viaHome.lan.db), 0);
  assert.equal(await toolBit(viaHome.lan.db), await toolBit(viaCommand.lan.db));
  assert.deepEqual(await auditRows(viaHome.lan.db), await auditRows(viaCommand.lan.db)); // STR-4 parity
});

test('forged home tool action from a non-admin: no write, audited denied', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  await h.toggleTool('disable:mcp');
  assert.equal(await new ChannelTools(h.lan.db).isConfigured('T1', 'C_FIN'), false); // no allowlist row
  assert.deepEqual(await auditActions(h.lan.db), ['denied']);
});

test('home Configure opens the existing configureModal for an admin; a forged non-admin click is denied', async (t) => {
  const admin = await harness(t, { slackAdmin: true });
  await admin.configure('mcp');
  assert.equal(admin.opened()?.trigger_id, 'trig');
  assert.equal(admin.opened()?.view?.callback_id, CONFIGURE_CALLBACK); // the EXISTING modal, not a new one
  assert.deepEqual(JSON.parse(admin.opened().view.private_metadata), { channel: 'C_FIN', provider: 'mcp' });

  const nonAdmin = await harness(t, { slackAdmin: false });
  await nonAdmin.configure('mcp');
  assert.equal(nonAdmin.opened(), null); // no modal
  assert.deepEqual(await auditActions(nonAdmin.lan.db), ['denied']);
});

test('forged nonexistent channel in view metadata: fail-closed, nothing written or audited', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  await h.setMode('mcp', 'shared', 'C_GHOST');
  await h.toggleTool('disable:mcp', 'C_GHOST');
  await h.configure('mcp', 'C_GHOST');
  assert.equal(h.opened(), null);
  assert.equal(await modeRow(h.lan.db, 'C_GHOST'), null);
  assert.deepEqual(await auditActions(h.lan.db), []); // SEC-4: the unverified channel never reached audit
});

test('archived selected channel renders a fail-closed note instead of controls', async (t) => {
  const h = await harness(t, { slackAdmin: true, channelInfo: { is_archived: true } });
  await h.openHome('C_FIN');
  const s = JSON.stringify(h.published().view.blocks);
  assert.ok(!s.includes(HOME_MODE_ACTION));
  assert.match(s, /archived/);
});

test('deleted selected channel (conversations.info fails) still publishes, with no controls', async (t) => {
  const h = await harness(t, { slackAdmin: true, infoThrows: true });
  await h.openHome('C_FIN');
  const view = h.published()?.view;
  assert.ok(view); // rendered gracefully, not crashed
  const s = JSON.stringify(view.blocks);
  assert.ok(s.includes(HOME_CHANNEL_ACTION)); // picker still there to choose another channel
  assert.ok(!s.includes(HOME_MODE_ACTION));
});

test('home Disconnect removes the connection and re-publishes the view without the row', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  await h.lan.vault.upsert(userOwner(ID), 'mcp', CRED);
  await h.disconnect('mcp');
  assert.equal(await h.lan.vault.get(userOwner(ID), 'mcp'), null);
  assert.match(JSON.stringify(h.published().view.blocks), /None yet/); // the re-published home reflects it
});

test('app_home_opened defers to a foreign (host-published) Home view; first open still publishes', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  // The host runs its own Home tab: the event echoes the host's view → Vouchr must not clobber it.
  await h.fireHomeOpened({ user: ID.userId, tab: 'home', view: { callback_id: 'hosts_own_home' } });
  assert.equal(h.published(), null);
  // First-ever open (no current view) → ours to publish.
  await h.fireHomeOpened({ user: ID.userId, tab: 'home' });
  assert.ok(h.published());
  // Our own echoed view → re-publish (the normal refresh path).
  await h.openHome();
  assert.equal(h.published().view.type, 'home');
});

test('first Disable on an unconfigured channel materializes the allowlist: others stay enabled, one audit row', async (t) => {
  const h = await harness(t, { slackAdmin: true, providers: ['a', 'b', 'c'].map(mkProvider) });
  await h.toggleTool('disable:a');
  const tools = new ChannelTools(h.lan.db);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'a'), false); // the one the admin targeted
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'b'), true); // NOT silently disabled
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'c'), true);
  const rows = await auditRows(h.lan.db);
  assert.deepEqual(rows.map((r) => [r.action, r.provider]), [['config', 'a']]); // only the real change audited
});

test('slash and home agree on the unconfigured-channel Disable: same rows, same audit', async (t) => {
  const slash = await harness(t, { slackAdmin: true, providers: ['a', 'b'].map(mkProvider) });
  await slash.runCommand('disable a');
  const home = await harness(t, { slackAdmin: true, providers: ['a', 'b'].map(mkProvider) });
  await home.toggleTool('disable:a');
  for (const h of [slash, home]) {
    const tools = new ChannelTools(h.lan.db);
    assert.equal(await tools.isEnabled('T1', 'C_FIN', 'a'), false);
    assert.equal(await tools.isEnabled('T1', 'C_FIN', 'b'), true);
  }
  assert.deepEqual(await auditRows(home.lan.db), await auditRows(slash.lan.db));
});

test('first Enable on an unconfigured channel does not disable the other providers', async (t) => {
  const h = await harness(t, { slackAdmin: true, providers: ['a', 'b'].map(mkProvider) });
  await h.runCommand('enable a'); // via slash — previously flipped the channel into a one-row allowlist
  const tools = new ChannelTools(h.lan.db);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'a'), true);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'b'), true); // previously: silently disabled
});

test('a stale/deleted metadata channel on a click DMs the actor and resets the view', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  await h.setMode('mcp', 'shared', 'C_GHOST');
  assert.ok(h.dms.some((t) => /no longer available/.test(t))); // feedback, not a silent no-op
  assert.ok(h.published()); // view reset to a selection-less state
  assert.deepEqual(await auditActions(h.lan.db), []); // still nothing persisted or audited
});

test('exported homeView is unstamped; a host Home tab built from it is deferred to (open + disconnect)', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  const hostView: any = homeView({ connections: [], providers: ['mcp'] });
  assert.equal(hostView.callback_id, undefined); // pre-#111 exported shape: no ownership stamp
  assert.equal(hostView.private_metadata, undefined);
  // The host published this view; the app_home_opened echo must NOT be clobbered by our publisher.
  await h.fireHomeOpened({ user: ID.userId, tab: 'home', view: hostView });
  assert.equal(h.published(), null);
  // A Disconnect click inside the host's view is the host's to handle — no revoke, no audit.
  await h.lan.vault.upsert(userOwner(ID), 'mcp', CRED);
  await h.rawAction(DISCONNECT_ACTION, {
    team: { id: 'T1' }, user: { id: ID.userId },
    view: { id: 'V_HOST', ...hostView }, actions: [{ value: 'mcp' }],
  });
  assert.ok(await h.lan.vault.get(userOwner(ID), 'mcp')); // NOT disconnected
  assert.deepEqual(await auditActions(h.lan.db), []);
  assert.equal(h.published(), null); // and no view was clobbered
});

test('concurrent first Disables on an unconfigured channel both land; bystanders stay enabled', async (t) => {
  const h = await harness(t, { slackAdmin: true, providers: ['a', 'b', 'c'].map(mkProvider) });
  await Promise.all([h.toggleTool('disable:a'), h.toggleTool('disable:b')]);
  const tools = new ChannelTools(h.lan.db);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'a'), false);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'b'), false);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'c'), true); // no interleaving re-enabled or dropped it
});

test('service tools: not advertised as connectable; governed via Enable/Disable only', async (t) => {
  const mkSvc = () => defineProvider({
    id: 'svc', identity: 'service', credential: 'key', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t',
    scopesDefault: [], egressAllow: ['api.test'], refresh: 'none', pkce: false,
  });
  const h = await harness(t, { slackAdmin: true, providers: [mkProvider('oauth1'), mkSvc()] });
  await h.openHome('C_FIN');
  const view = h.published().view;
  const avail = view.blocks.find((b: any) => b.type === 'section' && /Available providers/.test(b.text?.text ?? ''));
  assert.match(avail.text.text, /oauth1/); // the brokered provider is advertised
  assert.doesNotMatch(avail.text.text, /svc/); // the service tool is not connect-on-demand
  // #111: ONE ROW PER REGISTERED PROVIDER — the service tool IS governable, Enable/Disable only.
  const svcRow = view.blocks.find((b: any) => b.block_id === 'home_mode:svc');
  assert.ok(svcRow); // present in governance
  assert.equal(svcRow.accessory, undefined); // but no mode select (core refuses modes for it)
  const svcTools = view.blocks.find((b: any) => b.block_id === 'home_tool:svc');
  assert.ok(svcTools.elements.some((e: any) => e.action_id === HOME_TOOL_ACTION)); // Enable/Disable present
  assert.ok(!svcTools.elements.some((e: any) => e.action_id === HOME_CONFIGURE_ACTION)); // no Configure
  const oauthRow = view.blocks.find((b: any) => b.block_id === 'home_mode:oauth1');
  assert.equal(oauthRow.accessory.type, 'static_select'); // brokered rows keep the full control set

  // Enable/Disable on the service tool works end-to-end, identical to the slash equivalent.
  await h.toggleTool('disable:svc');
  assert.equal(await new ChannelTools(h.lan.db).isEnabled('T1', 'C_FIN', 'svc'), false);
  const viaSlash = await harness(t, { slackAdmin: true, providers: [mkProvider('oauth1'), mkSvc()] });
  await viaSlash.runCommand('disable svc');
  assert.deepEqual(await auditRows(h.lan.db), await auditRows(viaSlash.lan.db)); // STR-4 parity
});

test('provider-reported account labels are escaped everywhere they render (SEC-5)', async (t) => {
  const h = await harness(t, { slackAdmin: false });
  await h.lan.vault.upsert(userOwner(ID), 'mcp', { ...CRED, externalAccount: '<!channel> <https://evil|click>' });
  let out: any = null;
  await h.runCommand('status', async (m: any) => { out = m; });
  const text = typeof out === 'string' ? out : JSON.stringify(out);
  assert.match(text, /&lt;!channel&gt;/); // escaped form rendered…
  assert.ok(!text.includes('<!channel>')); // …never the live broadcast syntax
  assert.ok(!text.includes('<https://evil|click>')); // nor a forged link
  await h.openHome(); // the Home row goes through the same renderer
  const s = JSON.stringify(h.published().view.blocks);
  assert.match(s, /&lt;!channel&gt;/);
  assert.ok(!s.includes('<!channel>'));
});

test('forged tool action on an archived or ext-shared channel: no write, refused at the mutation', async (t) => {
  for (const channelInfo of [{ is_archived: true }, { is_ext_shared: true }]) {
    const h = await harness(t, { slackAdmin: true, channelInfo });
    await h.toggleTool('disable:mcp'); // render never showed the button; the payload is forged
    assert.equal(await new ChannelTools(h.lan.db).isConfigured('T1', 'C_FIN'), false); // nothing written
    assert.deepEqual(await auditActions(h.lan.db), []); // mirrors setChannelMode: eligibility refusals aren't authz denials
    assert.ok(h.dms.some((t) => /archived|externally shared/.test(t))); // the core reason reaches the actor
    await h.configure('mcp'); // same wall in front of the credential modal
    assert.equal(h.opened(), null);
  }
});

test('slash enable and configure refuse an ineligible channel class (parity with mode)', async (t) => {
  const h = await harness(t, { slackAdmin: true, channelInfo: { is_ext_shared: true } });
  const out: string[] = [];
  await h.runCommand('enable mcp', async (m: any) => { out.push(String(m)); });
  assert.match(out[0], /externally shared/);
  assert.equal(await new ChannelTools(h.lan.db).isConfigured('T1', 'C_FIN'), false);
  await h.runCommand('configure mcp', async (m: any) => { out.push(String(m)); });
  assert.match(out[1], /externally shared/);
  assert.equal(h.opened(), null); // modal never opened
});
