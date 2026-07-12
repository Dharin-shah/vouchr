import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig, isChannelMode } from '../src/core/channelConfig';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { ConnectContext, createVouchr } from '../src/adapters/bolt';

// The channel-creator config gate is OPT-IN (`allowChannelCreatorConfig`, default off). When off the
// gate is exactly workspace-admin-only; when on, a channel's CREATOR may also run the config
// mutations. Mirrors governance.test.ts's harness, plus `creator`/`allowCreator` knobs.
const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ACTOR' };

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

async function ctx(opts: {
  slackAdmin?: boolean;      // what the built-in users.info gate reports for ID.userId
  creator?: string;         // channel creator id from conversations.info
  allowCreator?: boolean;   // the opt-in flag
  infoThrows?: boolean;     // conversations.info fails (fail-closed surface)
  adminCheck?: (client: any, userId: string, teamId: string) => Promise<boolean>;
} = {}) {
  const { slackAdmin = false, creator = 'U_SOMEONE_ELSE', allowCreator = false, infoThrows = false, adminCheck } = opts;
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const client = {
    users: { info: async () => ({ user: { is_admin: slackAdmin } }) },
    conversations: {
      info: async () => {
        if (infoThrows) throw new Error('channel_not_found');
        return { channel: { id: 'C_FIN', is_channel: true, creator } };
      },
    },
  } as any;
  const c = new ConnectContext({
    identity: ID, channel: 'C_FIN', client, registry: new ProviderRegistry([provider]), vault, audit,
    consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
    channelConfig: new ChannelConfig(db), adminCheck, allowChannelCreatorConfig: allowCreator,
  });
  return { c, db };
}

const auditActions = async (db: any) =>
  ((await db.all('SELECT action FROM audit')) as any[]).map((r) => r.action);
const mode = async (db: any) =>
  ((await db.get('SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?',
    ['T1', 'C_FIN', 'mcp'])) as any)?.mode ?? null;

// (a) With the flag ON, the channel creator (not a workspace admin) may configure.
test('flag on: channel creator (non-workspace-admin) can setChannelMode', async () => {
  const { c, db } = await ctx({ slackAdmin: false, creator: ID.userId, allowCreator: true });
  await c.setChannelMode('mcp', 'per-user');
  assert.equal(await mode(db), 'per-user');
  assert.deepEqual(await auditActions(db), ['config']);
});

// DEFAULT (flag OFF): workspace-admin-only — the creator is NOT allowed, exactly as pre-PR.
test('flag off (default): channel creator is denied — workspace-admin-only', async () => {
  const { c, db } = await ctx({ slackAdmin: false, creator: ID.userId, allowCreator: false });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /Only a workspace admin can/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// (b) Neither workspace admin nor creator → denied + audited (default-deny intact), flag irrelevant.
test('non-admin non-creator is denied and audited', async () => {
  const { c, db } = await ctx({ slackAdmin: false, creator: 'U_SOMEONE_ELSE', allowCreator: true });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /admin/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// (c) A workspace admin is still allowed, even without the flag and without creating the channel.
test('workspace admin (not creator) is still allowed, flag off', async () => {
  const { c, db } = await ctx({ slackAdmin: true, creator: 'U_SOMEONE_ELSE', allowCreator: false });
  await c.setChannelMode('mcp', 'per-user');
  assert.equal(await mode(db), 'per-user');
  assert.deepEqual(await auditActions(db), ['config']);
});

// (d) A custom adminCheck override fully replaces the default: false blocks even the channel creator.
test('adminCheck override false blocks even the channel creator', async () => {
  const { c, db } = await ctx({ slackAdmin: false, creator: ID.userId, allowCreator: true, adminCheck: async () => false });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /admin/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// Fail-closed on the new API surface: flag on, not a workspace admin, conversations.info throws →
// isChannelAdmin can't confirm the creator → DENIED + audited.
test('flag on: conversations.info error fails closed → denied', async () => {
  const { c, db } = await ctx({ slackAdmin: false, creator: ID.userId, allowCreator: true, infoThrows: true });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /admin/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// The COMMAND paths (enable/disable tool allowlist + the configure pre-modal gate) route through
// commandAdmin, not requireAdmin — assert they honor the same opt-in creator rule.
async function commandHarness(opts: {
  creator: string;
  allowCreator?: boolean;
  isAdmin?: (client: any, userId: string, teamId: string) => Promise<boolean>;
}) {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', dbPath: ':memory:',
    allowChannelCreatorConfig: opts.allowCreator ?? false, isAdmin: opts.isAdmin,
  });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
  const out: string[] = [];
  let opened: any = null;
  const client = {
    users: { info: async () => ({ user: { is_admin: false } }) }, // never a workspace admin
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator: opts.creator } }) },
    views: { open: async (a: any) => { opened = a; } },
  };
  const base = { team_id: 'T1', user_id: ID.userId, channel_id: 'C_FIN', trigger_id: 'trig' };
  const run = (text: string) =>
    handler({ command: { ...base, text }, ack: async () => {}, respond: async (m: string) => out.push(m), client });
  return { lan, run, out, opened: () => opened };
}

// Flag on: channel creator can enable/disable tools and open the configure modal.
test('flag on: channel creator can run enable/disable and pass the configure gate', async () => {
  const h = await commandHarness({ creator: ID.userId, allowCreator: true });
  await h.run('enable mcp');
  assert.match(h.out[0], /Enabled/);
  const row = await h.lan.db.get('SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(row.enabled, 1);

  await h.run('disable mcp');
  assert.match(h.out[1], /Disabled/);

  await h.run('configure mcp');
  assert.equal(h.opened()?.trigger_id, 'trig'); // modal opened → passed the pre-modal gate
});

// Flag off (default): the creator is denied on the same command paths — workspace-admin-only.
test('flag off (default): channel creator is denied on enable/configure', async () => {
  const h = await commandHarness({ creator: ID.userId, allowCreator: false });
  await h.run('enable mcp');
  assert.match(h.out[0], /Only a workspace admin can/);
  await h.run('configure mcp');
  assert.equal(h.opened(), null); // modal never opened
});

// A non-creator non-admin is denied on the command paths even with the flag on.
test('flag on: non-creator non-admin is denied on enable/configure', async () => {
  const h = await commandHarness({ creator: 'U_SOMEONE_ELSE', allowCreator: true });
  await h.run('enable mcp');
  assert.match(h.out[0], /admin or the channel creator/);
  await h.run('configure mcp');
  assert.match(h.out[1], /admin or the channel creator/);
  assert.equal(h.opened(), null);
  assert.ok((await h.lan.db.all('SELECT action FROM audit') as any[]).every((r) => r.action === 'denied'));
});

// commandAdmin override precedence: flag on + a creator, but an isAdmin override returning false
// still blocks the enable/disable path (override fully replaces the built-in gate).
test('flag on: isAdmin override false blocks the creator on the command path', async () => {
  const h = await commandHarness({ creator: ID.userId, allowCreator: true, isAdmin: async () => false });
  await h.run('enable mcp');
  assert.doesNotMatch(h.out[0], /Enabled/);
  const row = await h.lan.db.get('SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(row, undefined); // never written
});

// #196: `union` was removed. It must be rejected at the config boundary BEFORE any persist/audit
// (SEC-4), both at the guard the slash command routes through and at the true sink (ChannelConfig).
test('union mode is rejected at the config boundary, writing nothing (SEC-4)', async () => {
  // The single-source-of-truth guard no longer admits it; the surviving three still pass.
  assert.equal(isChannelMode('union'), false);
  for (const m of ['shared', 'per-user', 'session']) assert.equal(isChannelMode(m), true);

  // Slash command: an admin creator runs `mode mcp union` → the usage message, and NO row is written.
  const h = await commandHarness({ creator: ID.userId, allowCreator: true });
  await h.run('mode mcp union');
  assert.match(h.out[0], /Usage: `\/vouchr mode/);
  const cfgRow = await h.lan.db.get(
    'SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(cfgRow, undefined); // never persisted
  assert.equal((await h.lan.db.all('SELECT 1 FROM audit') as any[]).length, 0); // never audited

  // True sink: ChannelConfig.setMode itself throws on the bogus runtime value and writes nothing.
  const db = await openDb({ dbPath: ':memory:' });
  const cfg = new ChannelConfig(db);
  await assert.rejects(() => cfg.setMode('T1', 'C_FIN', 'mcp', 'union' as any), /invalid channel mode/);
  assert.equal(await cfg.getMode('T1', 'C_FIN', 'mcp'), null);
});
