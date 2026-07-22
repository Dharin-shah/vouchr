import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { defineProvider, type Provider } from '../src/core/providers';
import { createVouchr } from '../src/adapters/bolt';
import { ChannelConfig, writeChannelMode } from '../src/core/channelConfig';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import {
  CONFIGURE_CALLBACK, DISCONNECT_ACTION, homeView,
  HOME_CALLBACK, HOME_CHANNEL_ACTION, HOME_MODE_ACTION, HOME_TOOL_ACTION, HOME_CONFIGURE_ACTION,
} from '../src/adapters/blocks';
import { userOwner, channelOwner } from '../src/core/owner';
import type { Db } from '../src/core/db';
import type { EnvelopeProvider } from '../src/core/crypto';
import type { Resolvers } from '../src/core/injector';
import { countingDb } from './support/counting-db';

// #111 App Home console: bolt-fake tests over the real registered handlers (event/action/command).
// The published view is role-dependent; every mutation routes through the SAME helpers as the slash
// commands (identical rows + audit by construction); and every forgeable interaction field — the
// private_metadata channel, block ids, button values, the mode value — is re-validated server-side.
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ACTOR' };
const mkProvider = (id: string): Provider => defineProvider({
  id, authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
const mkServiceProvider = (): Provider => defineProvider({
  id: 'svc', identity: 'service', credential: 'key', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t',
  scopesDefault: [], egressAllow: ['api.test'], refresh: 'none', pkce: false,
});
const provider = mkProvider('mcp');
const CRED = { accessToken: 'TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'octo' };

async function harness(t: TestContext, opts: {
  slackAdmin?: boolean; allowCreator?: boolean; creator?: string;
  channelInfo?: Record<string, unknown>; infoThrows?: boolean; providers?: Provider[];
  db?: Db; envelope?: EnvelopeProvider; publishThrows?: boolean; resolvers?: Resolvers;
} = {}) {
  const { slackAdmin = false, allowCreator = false, creator = 'U_OTHER', providers = [provider] } = opts;
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers,
    baseUrl: 'http://127.0.0.1:1',
    db: opts.db ?? await openTestDb(t),
    envelope: opts.envelope,
    allowChannelCreatorConfig: allowCreator,
    resolvers: opts.resolvers,
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
  const updates: any[] = [];
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
    views: {
      publish: async (a: any) => {
        if (opts.publishThrows) throw new Error('slack_unavailable');
        published = a;
      },
      open: async (a: any) => {
        opened = a;
        return { view: { id: 'V_LOADING' } };
      },
      update: async (a: any) => { updates.push(a); },
    },
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
    updates: () => updates,
    hydrated: () => [...updates].reverse().find(
      (entry: any) => entry?.view?.callback_id === CONFIGURE_CALLBACK,
    )?.view ?? null,
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
    disconnect: async (p: string) => act(DISCONNECT_ACTION, {
      value: await lan.vault.liveId(userOwner(ID), p),
    }),
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

test('selected App Home keeps production-path reads fixed and performs zero KMS unwraps (#209)', async (t) => {
  const render = async (providerCount: number) => {
    const base = await openTestDb(t);
    const counted = countingDb(base);
    let unwraps = 0;
    const envelope: EnvelopeProvider = {
      wrapDataKey: async (dek) => Buffer.from(dek),
      unwrapDataKey: async (wrapped) => { unwraps++; return Buffer.from(wrapped); },
    };
    const providers = Array.from({ length: providerCount }, (_, i) => mkProvider(`p${i}`));
    const h = await harness(t, { slackAdmin: true, providers, db: counted.db, envelope });
    // Make the no-decrypt claim meaningful: a real envelope-encrypted row is listed in the view.
    await h.lan.vault.upsert(userOwner(ID), providers[0].id, { ...CRED, accessToken: `TOK_${providerCount}` });
    counted.reset();
    unwraps = 0;
    await h.openHome('C_FIN');
    assert.match(JSON.stringify(h.published().view.blocks), /octo/);
    return { counts: { ...counted.counts }, unwraps };
  };

  const few = await render(2);
  const many = await render(51);
  // One metadata-only connection list + two manifest snapshots; admin rows reuse the raw allowlist.
  assert.deepEqual(few.counts, { get: 0, all: 3 });
  assert.deepEqual(many.counts, few.counts);
  assert.equal(few.unwraps, 0);
  assert.equal(many.unwraps, 0);
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
  await writeChannelMode(new ChannelConfig(h.lan.db), 'T1', 'C_FIN', 'mcp', 'session');
  await setChannelToolEnabled(new ChannelTools(h.lan.db), 'T1', 'C_FIN', 'mcp', false);
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
  await writeChannelMode(new ChannelConfig(h.lan.db), 'T1', 'C_FIN', 'mcp', 'shared');
  await h.lan.vault.upsert(owner, 'mcp', CRED);
  await h.setMode('mcp', 'evil-mode');
  assert.equal(await modeRow(h.lan.db), 'shared');
  assert.ok(await h.lan.vault.get(owner, 'mcp')); // setChannelMode's shared-cred cleanup never ran
  assert.deepEqual(await auditActions(h.lan.db), []);
});

test('home Enable/Disable == /vouchr enable|disable: identical channel_tool row and audit rows', async (t) => {
  // Use a real state change (enable on a deny-by-default channel) so both paths actually write a row
  // and audit — a no-op disable now writes nothing, which would compare equal but prove nothing.
  const viaCommand = await harness(t, { slackAdmin: true });
  await viaCommand.runCommand('enable mcp');
  const viaHome = await harness(t, { slackAdmin: true });
  await viaHome.toggleTool('enable:mcp');
  assert.equal(await toolBit(viaHome.lan.db), 1);
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
  assert.equal(admin.opened()?.view?.callback_id, undefined); // authority-free loading view first
  assert.equal(admin.opened()?.view?.private_metadata, undefined);
  const hydrated = admin.hydrated();
  assert.equal(hydrated?.callback_id, CONFIGURE_CALLBACK); // same exported form, hydrated after gates
  assert.deepEqual(Object.keys(JSON.parse(hydrated.private_metadata)), ['requestId']);
  assert.equal(hydrated.blocks.some((block: any) => block.block_id === 'ref'), false);

  const withGcp = await harness(t, { slackAdmin: true, resolvers: { 'gcp-sm': async () => 'secret' } });
  await withGcp.configure('mcp');
  const ref = withGcp.hydrated().blocks.find((block: any) => block.block_id === 'ref');
  assert.match(ref.hint.text, /GCP Secret Manager/);
  assert.ok(!ref.hint.text.includes('AWS'));

  const nonAdmin = await harness(t, { slackAdmin: false });
  await nonAdmin.configure('mcp');
  assert.ok(nonAdmin.opened()); // trigger consumed into a fixed loading view
  assert.equal(nonAdmin.hydrated(), null); // no credential form authority
  assert.match(JSON.stringify(nonAdmin.updates()), /Setup unavailable/);
  assert.deepEqual(await auditActions(nonAdmin.lan.db), ['denied']);
});

test('forged nonexistent channel in view metadata: fail-closed, nothing written or audited', async (t) => {
  const h = await harness(t, { slackAdmin: true });
  await h.setMode('mcp', 'shared', 'C_GHOST');
  await h.toggleTool('disable:mcp', 'C_GHOST');
  await h.configure('mcp', 'C_GHOST');
  assert.ok(h.opened());
  assert.equal(h.hydrated(), null);
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

test('Home/config Disconnect redelivery after reconnect cannot delete the replacement generation', async (t) => {
  for (const surface of ['home', 'modal'] as const) {
    const revoked: string[] = [];
    const revocable = defineProvider({
      ...mkProvider('revocable'),
      revoke: async (_provider, token) => { revoked.push(token); },
    });
    const h = await harness(t, { slackAdmin: false, providers: [revocable] });
    const owner = userOwner(ID);
    await h.lan.vault.upsert(owner, 'revocable', { ...CRED, accessToken: 'TOKEN_A' });
    const generationA = await h.lan.vault.liveId(owner, 'revocable');

    let rendered: any;
    if (surface === 'home') {
      await h.openHome();
      rendered = h.published().view;
    } else {
      await h.runCommand('');
      rendered = h.opened().view;
    }
    const button = rendered.blocks.find(
      (block: any) => block.accessory?.action_id === DISCONNECT_ACTION,
    ).accessory;
    assert.equal(button.value, generationA, `${surface} must bind the rendered row generation`);
    assert.ok(!button.value.includes('revocable'));

    // Reuse this exact Slack body for both deliveries. View refreshes after the first action must not
    // upgrade the authority carried by the already-delivered button.
    const actionBody = {
      team: { id: ID.teamId },
      user: { id: ID.userId },
      view: { id: `V_${surface}`, ...rendered },
      actions: [{ action_id: DISCONNECT_ACTION, value: button.value }],
    };
    await h.rawAction(DISCONNECT_ACTION, actionBody);
    assert.equal(await h.lan.vault.liveId(owner, 'revocable'), null);

    await new Promise((resolve) => setTimeout(resolve, 5));
    await h.lan.vault.upsert(owner, 'revocable', { ...CRED, accessToken: 'TOKEN_B' });
    const generationB = await h.lan.vault.liveId(owner, 'revocable');
    assert.ok(generationB && generationB !== generationA);
    const markerBefore = await h.lan.db.get<{ created_at: number }>(
      `SELECT created_at FROM provisioning_revocation_tombstone
       WHERE provider='revocable' AND scope_kind='team-user'`,
    );

    await new Promise((resolve) => setTimeout(resolve, 5));
    await h.rawAction(DISCONNECT_ACTION, actionBody);

    assert.equal(await h.lan.vault.liveId(owner, 'revocable'), generationB);
    assert.equal((await h.lan.vault.get(owner, 'revocable'))?.accessToken, 'TOKEN_B');
    assert.deepEqual(revoked, ['TOKEN_A']);
    assert.deepEqual(await auditActions(h.lan.db), ['revoke']);
    assert.deepEqual(
      await h.lan.db.get<{ created_at: number }>(
        `SELECT created_at FROM provisioning_revocation_tombstone
         WHERE provider='revocable' AND scope_kind='team-user'`,
      ),
      markerBefore,
      'the stale generation must not advance the provisioning marker',
    );
    assert.match(h.dms.at(-1) ?? '', /Disconnect button is no longer current/);
  }
});

test('a Vouchr-owned Disconnect action cannot use another user\'s opaque generation', async (t) => {
  let revokes = 0;
  const revocable = defineProvider({
    ...mkProvider('revocable'),
    revoke: async () => { revokes++; },
  });
  const h = await harness(t, { slackAdmin: false, providers: [revocable] });
  const other = userOwner({ ...ID, userId: 'U_OTHER' });
  await h.lan.vault.upsert(other, 'revocable', { ...CRED, accessToken: 'OTHER_TOKEN' });
  const otherGeneration = await h.lan.vault.liveId(other, 'revocable');

  await h.rawAction(DISCONNECT_ACTION, {
    team: { id: ID.teamId },
    user: { id: ID.userId },
    view: {
      id: 'V_FORGED',
      type: 'home',
      callback_id: HOME_CALLBACK,
      private_metadata: JSON.stringify({ channel: null }),
    },
    actions: [{ action_id: DISCONNECT_ACTION, value: otherGeneration }],
  });

  assert.equal(await h.lan.vault.liveId(other, 'revocable'), otherGeneration);
  assert.equal(revokes, 0);
  assert.deepEqual(await auditActions(h.lan.db), []);
  assert.equal(
    (await h.lan.db.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone`,
    ))?.n,
    0,
  );
  assert.match(h.dms.at(-1) ?? '', /Disconnect button is no longer current/);
});

test('home Disconnect reports a retired credential outcome even when Home re-publish fails', async (t) => {
  const h = await harness(t, { slackAdmin: false, providers: [], publishThrows: true });
  await h.lan.vault.upsert(userOwner(ID), 'retired', CRED);
  await h.disconnect('retired');
  assert.equal(await h.lan.vault.has(userOwner(ID), 'retired'), false);
  assert.equal(h.published(), null);
  assert.deepEqual(h.dms, [
    'Disconnected *retired* locally, but complete revocation could not be confirmed. Retry `/vouchr disconnect retired` to invalidate older setup requests, and revoke or rotate Vouchr’s access in retired directly if needed.',
  ]);
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

test('deny-by-default: a Disable on an already-disabled provider is a no-op (no write, no audit)', async (t) => {
  const h = await harness(t, { slackAdmin: true, providers: ['a', 'b', 'c'].map(mkProvider) });
  const tools = new ChannelTools(h.lan.db);
  for (const p of ['a', 'b', 'c']) assert.equal(await tools.isEnabled('T1', 'C_FIN', p), false); // nothing usable until enabled
  await h.toggleTool('disable:a'); // false -> false: the core filters the no-op, so nothing is written
  for (const p of ['a', 'b', 'c']) assert.equal(await tools.isEnabled('T1', 'C_FIN', p), false);
  assert.deepEqual(await auditRows(h.lan.db), []); // no fabricated config/tool:disabled row
  assert.equal(await tools.isConfigured('T1', 'C_FIN'), false); // no rows materialized — still unconfigured
});

test('slash and home agree on an unconfigured-channel Enable: same rows, same audit', async (t) => {
  const slash = await harness(t, { slackAdmin: true, providers: ['a', 'b'].map(mkProvider) });
  await slash.runCommand('enable a');
  const home = await harness(t, { slackAdmin: true, providers: ['a', 'b'].map(mkProvider) });
  await home.toggleTool('enable:a');
  for (const h of [slash, home]) {
    const tools = new ChannelTools(h.lan.db);
    assert.equal(await tools.isEnabled('T1', 'C_FIN', 'a'), true); // the one the admin opted in
    assert.equal(await tools.isEnabled('T1', 'C_FIN', 'b'), false); // deny-by-default: never implicitly on
  }
  assert.deepEqual(await auditRows(home.lan.db), await auditRows(slash.lan.db));
});

test('deny-by-default: enabling one provider turns ONLY it on; the rest stay disabled', async (t) => {
  const h = await harness(t, { slackAdmin: true, providers: ['a', 'b'].map(mkProvider) });
  await h.runCommand('enable a'); // via slash
  const tools = new ChannelTools(h.lan.db);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'a'), true);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'b'), false); // deny-by-default: not implicitly enabled
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

test('concurrent first Enables on an unconfigured channel both land; bystanders stay disabled', async (t) => {
  const h = await harness(t, { slackAdmin: true, providers: ['a', 'b', 'c'].map(mkProvider) });
  await Promise.all([h.toggleTool('enable:a'), h.toggleTool('enable:b')]);
  const tools = new ChannelTools(h.lan.db);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'a'), true);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'b'), true);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'c'), false); // no interleaving implicitly enabled it
});

test('service tools: not advertised as connectable; governed via Enable/Disable only', async (t) => {
  const h = await harness(t, { slackAdmin: true, providers: [mkProvider('oauth1'), mkServiceProvider()] });
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
  const viaSlash = await harness(t, { slackAdmin: true, providers: [mkProvider('oauth1'), mkServiceProvider()] });
  await viaSlash.runCommand('disable svc');
  assert.deepEqual(await auditRows(h.lan.db), await auditRows(viaSlash.lan.db)); // STR-4 parity
});

test('service tools cannot mint or render channel credential setup', async (t) => {
  const fixed = 'This tool uses service-managed credentials and cannot be configured here.';
  const providers = [mkProvider('oauth1'), mkServiceProvider()];

  const viaHome = await harness(t, { slackAdmin: true, providers });
  await viaHome.configure('svc'); // forged: the real Home view does not render this action
  assert.equal(viaHome.opened(), null);
  assert.equal(viaHome.hydrated(), null);
  assert.deepEqual(viaHome.dms, [fixed]);
  assert.equal(
    (await viaHome.lan.db.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM channel_provisioning_request`,
    ))?.n,
    0,
  );
  assert.deepEqual(await auditRows(viaHome.lan.db), []);

  const viaSlash = await harness(t, { slackAdmin: true, providers });
  const responses: unknown[] = [];
  await viaSlash.runCommand('connect-shared svc', async (response) => { responses.push(response); });
  assert.equal(viaSlash.opened(), null);
  assert.equal(viaSlash.hydrated(), null);
  assert.deepEqual(responses, [fixed]);
  assert.equal(
    (await viaSlash.lan.db.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM channel_provisioning_request`,
    ))?.n,
    0,
  );
  assert.deepEqual(await auditRows(viaSlash.lan.db), []);
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
    assert.ok(h.opened());
    assert.equal(h.hydrated(), null);
    assert.match(JSON.stringify(h.updates()), /archived|externally shared/);
  }
});

test('slash enable and configure refuse an ineligible channel class (parity with mode)', async (t) => {
  const h = await harness(t, { slackAdmin: true, channelInfo: { is_ext_shared: true } });
  const out: string[] = [];
  await h.runCommand('enable mcp', async (m: any) => { out.push(String(m)); });
  assert.match(out[0], /externally shared/);
  assert.equal(await new ChannelTools(h.lan.db).isConfigured('T1', 'C_FIN'), false);
  await h.runCommand('connect-shared mcp', async (m: any) => { out.push(String(m)); });
  assert.ok(h.opened()); // Slack trigger is consumed before the eligibility read
  assert.equal(h.hydrated(), null);
  assert.match(JSON.stringify(h.updates()), /externally shared/);
});
