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

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };
const SECRET = 'sk-super-secret-value-9999';

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

// Mirrors channel.test.ts's ctx() but exposes the two governance knobs. `members` shapes the
// mocked conversations.members: a member-id list, or 'throw' to fail the membership check.
async function ctx(opts: {
  adminCheck?: (client: any, userId: string, teamId: string) => Promise<boolean>;
  requireMembership?: boolean;
  members?: string[] | 'throw';
  slackAdmin?: boolean; // what the built-in users.info gate reports
} = {}) {
  const { adminCheck, requireMembership = false, members = [ID.userId], slackAdmin = true } = opts;
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const client = {
    users: { info: async () => ({ user: { is_admin: slackAdmin } }) },
    conversations: {
      info: async () => ({ channel: { id: 'C_FIN', is_channel: true } }),
      members: async () => {
        if (members === 'throw') throw new Error('channel_not_found');
        return { members };
      },
    },
  } as any;
  const c = new ConnectContext(
    ID, 'C_FIN', client, new ProviderRegistry([provider]), vault, audit,
    new Consent(db), new Policy(), 'http://x', {}, new ChannelConfig(db),
    undefined, undefined, undefined, undefined, // channelTools, inflight, sink, providerIds → defaults
    adminCheck, requireMembership,
  );
  return { c, db, vault, audit };
}

const auditRows = async (db: any) => await db.all('SELECT action, meta FROM audit') as any[];

// isAdmin override: a custom check overrides the built-in Slack gate. slackAdmin:false proves the
// override (not users.info) decides — a non-Slack-admin can configure when the override says yes.
test('isAdmin override: custom true lets a non-Slack-admin configure', async () => {
  const { c, vault, db } = await ctx({ adminCheck: async () => true, slackAdmin: false });
  await c.setChannelSecret('mcp', SECRET);
  assert.equal((await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'))?.accessToken, SECRET);
  assert.deepEqual((await auditRows(db)).map((r) => r.action), ['config']);
});

// Override false blocks even a real Slack admin — default-deny + audited denial stays intact.
test('isAdmin override: custom false blocks and audits denied', async () => {
  const { c, vault, db } = await ctx({ adminCheck: async () => false, slackAdmin: true });
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /admin/);
  assert.equal(await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'), null);
  assert.deepEqual((await auditRows(db)).map((r) => r.action), ['denied']);
});

// A throwing override fails closed (treated as not-admin), denial still audited.
test('isAdmin override: a throwing override fails closed', async () => {
  const { c, db } = await ctx({ adminCheck: async () => { throw new Error('rbac down'); } });
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /admin/);
  assert.deepEqual((await auditRows(db)).map((r) => r.action), ['denied']);
});

// requireChannelMembership ON: a configured shared cred is refused for a non-member, audited
// 'not-member', and allowed for a member.
test('requireChannelMembership: non-member refused + audited, member allowed', async () => {
  const deny = await ctx({ requireMembership: true, members: ['U_OTHER'] });
  await deny.c.setChannelSecret('mcp', SECRET); // admin config is not membership-gated
  await assert.rejects(() => deny.c.connectChannel('mcp'), /member of this channel/);
  assert.ok((await auditRows(deny.db)).some((r) => r.action === 'denied' && r.meta.includes('not-member')));

  const ok = await ctx({ requireMembership: true, members: [ID.userId] });
  await ok.c.setChannelSecret('mcp', SECRET);
  assert.ok(await ok.c.connectChannel('mcp')); // member → handle
});

// requireChannelMembership OFF (default): membership is never checked — a non-member still gets the
// shared cred, exactly as before this feature.
test('requireChannelMembership: off → membership not checked', async () => {
  const { c } = await ctx({ requireMembership: false, members: 'throw' });
  await c.setChannelSecret('mcp', SECRET);
  assert.ok(await c.connectChannel('mcp')); // would throw if membership were consulted
});

// Fail-closed: when membership can't be verified (conversations.members throws), refuse.
test('requireChannelMembership: membership check errors → refused', async () => {
  const { c, db } = await ctx({ requireMembership: true, members: 'throw' });
  await c.setChannelSecret('mcp', SECRET);
  await assert.rejects(() => c.connectChannel('mcp'), /member of this channel/);
  assert.ok((await auditRows(db)).some((r) => r.action === 'denied' && r.meta.includes('not-member')));
});
