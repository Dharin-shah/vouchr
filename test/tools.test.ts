import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { ConnectContext } from '../src/adapters/bolt';

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };

const mcp = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
const other = defineProvider({
  id: 'other', authorizeUrl: 'https://y/a', tokenUrl: 'https://y/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
const PROVIDER_IDS = ['mcp', 'other'];

// Mirrors test/channel.test.ts: builds a ConnectContext over an in-memory DB + a mocked Slack client.
async function ctx(isAdmin = true, channel: string | null = 'C_FIN') {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const tools = new ChannelTools(db);
  const client = {
    users: { info: async () => ({ user: { is_admin: isAdmin } }) },
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true } }) },
  } as any;
  const c = new ConnectContext(
    ID, channel, client, new ProviderRegistry([mcp, other]), vault, audit,
    new Consent(db), new Policy(), 'http://x', {}, new ChannelConfig(db), tools,
    new Map(), () => {}, PROVIDER_IDS,
  );
  return { c, db, vault, audit, tools };
}

const auditRows = async (db: any) => (await db.all('SELECT action, meta FROM audit')) as any[];
const chOwner = { teamId: 'T1', kind: 'channel', id: 'C_FIN' } as const;

// Backward compat: a channel with no tool rows treats every provider as enabled.
test('no rows => all providers enabled (backward compat)', async () => {
  const { tools } = await ctx();
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'mcp'), true);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'other'), true);
  assert.deepEqual(await tools.listEnabled('T1', 'C_FIN'), []);
});

// Once any provider is set, the channel becomes an allowlist: only enabled ones are allowed.
test('enabling A disables B in that channel; isEnabled/listEnabled correctness', async () => {
  const { tools } = await ctx();
  await tools.setEnabled('T1', 'C_FIN', 'mcp', true);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'mcp'), true);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'other'), false); // unlisted → disabled
  assert.deepEqual(await tools.listEnabled('T1', 'C_FIN'), ['mcp']);

  // Other channels are unaffected (still all-enabled).
  assert.equal(await tools.isEnabled('T1', 'C_OTHER', 'other'), true);

  // Disabling flips it back off and drops it from listEnabled.
  await tools.setEnabled('T1', 'C_FIN', 'mcp', false);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'mcp'), false);
  assert.deepEqual(await tools.listEnabled('T1', 'C_FIN'), []);
});

// connect(): a disabled provider is refused + audited 'denied' reason 'tool-disabled'; an enabled
// one (with a stored user cred) returns a handle.
test("connect() refuses a disabled provider (audited 'tool-disabled') and allows an enabled one", async () => {
  const { c, db, vault, tools } = await ctx();
  await tools.setEnabled('T1', 'C_FIN', 'mcp', true); // mcp on → other off (allowlist)

  await assert.rejects(() => c.connect('other'), /not enabled/);
  const denied = (await auditRows(db)).filter((r) => r.action === 'denied');
  assert.equal(denied.length, 1);
  assert.match(denied[0].meta, /tool-disabled/);

  // Enabled provider with a stored cred → real handle, no prompt.
  await vault.upsert(userOwner(ID), 'mcp', {
    accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  assert.ok(await c.connect('mcp'));
});

// connectChannel(): same gate — disabled refused, enabled (with a shared cred) returns a handle.
test('connectChannel() refuses a disabled provider and allows an enabled one', async () => {
  const { c, vault, tools } = await ctx(true);
  await tools.setEnabled('T1', 'C_FIN', 'mcp', true); // allowlist: mcp on, other off
  await c.setChannelSecret('mcp', 'sk-shared'); // admin config (not tool-gated)

  assert.ok(await c.connectChannel('mcp')); // enabled + shared cred → handle
  assert.equal((await vault.get(chOwner, 'mcp'))?.accessToken, 'sk-shared');
  await assert.rejects(() => c.connectChannel('other'), /not enabled/);
});

// toolManifest(): one entry per registered provider, with enabled flag + channel mode.
test('toolManifest returns the expected shape', async () => {
  const { c, tools } = await ctx();

  // Unconfigured channel → every provider enabled, mode null.
  let m = await c.toolManifest();
  assert.deepEqual(m, [
    { provider: 'mcp', mode: null, enabled: true },
    { provider: 'other', mode: null, enabled: true },
  ]);

  // After configuring: mcp enabled + shared, other implicitly disabled.
  await tools.setEnabled('T1', 'C_FIN', 'mcp', true);
  await c.setChannelMode('mcp', 'per-user');
  m = await c.toolManifest();
  assert.deepEqual(m, [
    { provider: 'mcp', mode: 'per-user', enabled: true },
    { provider: 'other', mode: null, enabled: false },
  ]);
});

// A null channel (DM-less) keeps current behavior: no tool restriction, manifest all-enabled.
test('null channel → no tool restriction; manifest all enabled', async () => {
  const { c } = await ctx(true, null);
  const m = await c.toolManifest();
  assert.deepEqual(m.map((e) => e.enabled), [true, true]);
  assert.deepEqual(m.map((e) => e.mode), [null, null]);
});
