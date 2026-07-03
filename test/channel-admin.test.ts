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
import { ConnectContext } from '../src/adapters/bolt';

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
