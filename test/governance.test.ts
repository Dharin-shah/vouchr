import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { ConnectContext, createVouchr } from '../src/adapters/bolt';
import { CONFIGURE_CALLBACK } from '../src/adapters/blocks';

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };
const SECRET = 'sk-super-secret-value-9999';

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

// Mirrors channel.test.ts's ctx() but exposes the two governance knobs. `members` shapes the
// mocked conversations.members: a member-id list, or 'throw' to fail the membership check.
async function ctx(t: TestContext, opts: {
  adminCheck?: (client: any, userId: string, teamId: string) => Promise<boolean>;
  requireMembership?: boolean;
  members?: string[] | 'throw';
  slackAdmin?: boolean; // what the built-in users.info gate reports
} = {}) {
  const { adminCheck, requireMembership = false, members = [ID.userId], slackAdmin = true } = opts;
  const db = await openTestDb(t);
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
  const c = new ConnectContext({
    identity: ID, channel: 'C_FIN', client, registry: new ProviderRegistry([provider]), vault, audit,
    consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
    channelConfig: new ChannelConfig(db), adminCheck, requireMembership,
  });
  return { c, db, vault, audit };
}

const auditRows = async (db: any) => await db.all('SELECT action, meta FROM audit') as any[];

// isAdmin override: a custom check overrides the built-in Slack gate. slackAdmin:false proves the
// override (not users.info) decides: a non-Slack-admin can configure when the override says yes.
test('isAdmin override: custom true lets a non-Slack-admin configure', async (t) => {
  const { c, vault, db } = await ctx(t, { adminCheck: async () => true, slackAdmin: false });
  await c.setChannelSecret('mcp', SECRET);
  assert.equal((await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'))?.accessToken, SECRET);
  assert.deepEqual((await auditRows(db)).map((r) => r.action), ['config']);
});

// Override false blocks even a real Slack admin. Default-deny + audited denial stays intact.
test('isAdmin override: custom false blocks and audits denied', async (t) => {
  const { c, vault, db } = await ctx(t, { adminCheck: async () => false, slackAdmin: true });
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /admin/);
  assert.equal(await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'), null);
  assert.deepEqual((await auditRows(db)).map((r) => r.action), ['denied']);
});

// A throwing override fails closed (treated as not-admin), denial still audited.
test('isAdmin override: a throwing override fails closed', async (t) => {
  const { c, db } = await ctx(t, { adminCheck: async () => { throw new Error('rbac down'); } });
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /admin/);
  assert.deepEqual((await auditRows(db)).map((r) => r.action), ['denied']);
});

// requireChannelMembership ON: a configured shared cred is refused for a non-member, audited
// 'not-member', and allowed for a member.
test('requireChannelMembership: non-member refused + audited, member allowed', async (t) => {
  const deny = await ctx(t, { requireMembership: true, members: ['U_OTHER'] });
  await deny.c.setChannelSecret('mcp', SECRET); // admin config is not membership-gated
  await assert.rejects(() => deny.c.connectChannel('mcp'), /member of this channel/);
  assert.ok((await auditRows(deny.db)).some((r) => r.action === 'denied' && r.meta.includes('not-member')));

  const ok = await ctx(t, { requireMembership: true, members: [ID.userId] });
  await ok.c.setChannelSecret('mcp', SECRET);
  assert.ok(await ok.c.connectChannel('mcp')); // member → handle
});

// requireChannelMembership OFF (default): membership is never checked, a non-member still gets the
// shared cred, exactly as before this feature.
test('requireChannelMembership: off → membership not checked', async (t) => {
  const { c } = await ctx(t, { requireMembership: false, members: 'throw' });
  await c.setChannelSecret('mcp', SECRET);
  assert.ok(await c.connectChannel('mcp')); // would throw if membership were consulted
});

// Fail-closed: when membership can't be verified (conversations.members throws), refuse.
test('requireChannelMembership: membership check errors → refused', async (t) => {
  const { c, db } = await ctx(t, { requireMembership: true, members: 'throw' });
  await c.setChannelSecret('mcp', SECRET);
  await assert.rejects(() => c.connectChannel('mcp'), /member of this channel/);
  assert.ok((await auditRows(db)).some((r) => r.action === 'denied' && r.meta.includes('not-member')));
});

test('/vouchr commands honor the custom isAdmin override', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [provider],
    baseUrl: 'http://127.0.0.1:1',
    db: await openTestDb(t),
    isAdmin: async () => true, // overrides the mocked Slack users.info=false below
  });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });

  const out: string[] = [];
  let opened: any = null;
  let hydrated: any = null;
  const client = {
    users: { info: async () => ({ user: { is_admin: false } }) },
    // enable/configure now assert channel eligibility at the mutation (like mode always did),
    // so the fake must serve conversations.info for an ordinary eligible channel.
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true } }) },
    views: {
      open: async (a: any) => {
        opened = a;
        return { view: { id: 'V_LOADING' } };
      },
      update: async ({ view }: any) => { hydrated = view; },
    },
    chat: { postMessage: async () => ({}) },
  };
  const base = { team_id: 'T1', user_id: 'U_ADMIN', channel_id: 'C_FIN', trigger_id: 'trig' };

  await handler({
    command: { ...base, text: 'enable mcp' },
    ack: async () => {},
    respond: async (m: string) => out.push(m),
    client,
  });
  assert.match(out[0], /Enabled/);
  const row = await lan.db.get('SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(row.enabled, 1);

  await handler({
    command: { ...base, text: 'configure mcp' },
    ack: async () => {},
    respond: async (m: string) => out.push(m),
    client,
  });
  assert.equal(opened?.trigger_id, 'trig');
  assert.equal(opened?.view?.callback_id, undefined);
  assert.equal(hydrated?.callback_id, CONFIGURE_CALLBACK);
});
