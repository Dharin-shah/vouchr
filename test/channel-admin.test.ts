import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { ConnectContext, createVouchr } from '../src/adapters/bolt';

// The channel-creator config gate: a channel's CREATOR — not only a workspace admin — may run the
// admin config mutations (here `setChannelMode`). Mirrors governance.test.ts's harness, plus a
// `creator` knob that shapes the mocked conversations.info payload.
const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ACTOR' };

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

async function ctx(opts: {
  slackAdmin?: boolean;      // what the built-in users.info gate reports for ID.userId
  creator?: string;         // channel creator id from conversations.info
  adminCheck?: (client: any, userId: string, teamId: string) => Promise<boolean>;
} = {}) {
  const { slackAdmin = false, creator = 'U_SOMEONE_ELSE', adminCheck } = opts;
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const client = {
    users: { info: async () => ({ user: { is_admin: slackAdmin } }) },
    conversations: {
      info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator } }),
    },
  } as any;
  const c = new ConnectContext({
    identity: ID, channel: 'C_FIN', client, registry: new ProviderRegistry([provider]), vault, audit,
    consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
    channelConfig: new ChannelConfig(db), adminCheck,
  });
  return { c, db };
}

const auditActions = async (db: any) =>
  ((await db.all('SELECT action FROM audit')) as any[]).map((r) => r.action);
const mode = async (db: any) =>
  ((await db.get('SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?',
    ['T1', 'C_FIN', 'mcp'])) as any)?.mode ?? null;

// (a) The channel creator, who is NOT a workspace admin, may configure the channel.
test('channel creator (non-workspace-admin) can setChannelMode', async () => {
  const { c, db } = await ctx({ slackAdmin: false, creator: ID.userId });
  await c.setChannelMode('mcp', 'per-user');
  assert.equal(await mode(db), 'per-user');
  assert.deepEqual(await auditActions(db), ['config']);
});

// (b) Neither workspace admin nor creator → denied, and the denial is audited (default-deny intact).
test('non-admin non-creator is denied and audited', async () => {
  const { c, db } = await ctx({ slackAdmin: false, creator: 'U_SOMEONE_ELSE' });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /admin/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// (c) A workspace admin is still allowed, even when they didn't create the channel.
test('workspace admin (not creator) is still allowed', async () => {
  const { c, db } = await ctx({ slackAdmin: true, creator: 'U_SOMEONE_ELSE' });
  await c.setChannelMode('mcp', 'per-user');
  assert.equal(await mode(db), 'per-user');
  assert.deepEqual(await auditActions(db), ['config']);
});

// (d) A custom adminCheck override fully replaces the default: false blocks even the channel creator.
test('adminCheck override false blocks even the channel creator', async () => {
  const { c, db } = await ctx({ slackAdmin: false, creator: ID.userId, adminCheck: async () => false });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /admin/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// The COMMAND paths (enable/disable tool allowlist + the configure pre-modal gate) route through
// commandAdmin, not requireAdmin — assert they honor the same "workspace admin OR channel creator".
async function commandHarness(creator: string) {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({ providers: [provider], baseUrl: 'http://127.0.0.1:1', dbPath: ':memory:' });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
  const out: string[] = [];
  let opened: any = null;
  const client = {
    users: { info: async () => ({ user: { is_admin: false } }) }, // never a workspace admin
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator } }) },
    views: { open: async (a: any) => { opened = a; } },
  };
  const base = { team_id: 'T1', user_id: ID.userId, channel_id: 'C_FIN', trigger_id: 'trig' };
  const run = (text: string) =>
    handler({ command: { ...base, text }, ack: async () => {}, respond: async (m: string) => out.push(m), client });
  return { lan, run, out, opened: () => opened };
}

// Channel creator (non-workspace-admin) can enable/disable tools and open the configure modal.
test('channel creator can run enable/disable and pass the configure gate', async () => {
  const h = await commandHarness(ID.userId);
  await h.run('enable mcp');
  assert.match(h.out[0], /Enabled/);
  const row = await h.lan.db.get('SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(row.enabled, 1);

  await h.run('disable mcp');
  assert.match(h.out[1], /Disabled/);

  await h.run('configure mcp');
  assert.equal(h.opened()?.trigger_id, 'trig'); // modal opened → passed the pre-modal gate
});

// A non-creator non-admin is still denied on the same command paths.
test('non-creator non-admin is denied on enable/disable/configure', async () => {
  const h = await commandHarness('U_SOMEONE_ELSE');
  await h.run('enable mcp');
  assert.match(h.out[0], /admin or the channel creator/);
  await h.run('configure mcp');
  assert.match(h.out[1], /admin or the channel creator/);
  assert.equal(h.opened(), null); // modal never opened
  assert.ok((await h.lan.db.all('SELECT action FROM audit') as any[]).every((r) => r.action === 'denied'));
});
