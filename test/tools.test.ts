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
async function ctx(isAdmin = true, channel: string | null = 'C_FIN', policy = new Policy()) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const tools = new ChannelTools(db);
  const client = {
    users: { info: async () => ({ user: { is_admin: isAdmin } }) },
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true } }) },
  } as any;
  const c = new ConnectContext({
    identity: ID, channel, client, registry: new ProviderRegistry([mcp, other]), vault, audit,
    consent: new Consent(db), policy, redirectUri: 'http://x',
    channelConfig: new ChannelConfig(db), channelTools: tools, providerIds: PROVIDER_IDS,
  });
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

// connectChannel(): same gate. Disabled refused, enabled (with a shared cred) returns a handle.
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
    { provider: 'mcp', mode: null, enabled: true, identity: 'acting_human', visibility: 'public' },
    { provider: 'other', mode: null, enabled: true, identity: 'acting_human', visibility: 'public' },
  ]);

  // After configuring: mcp enabled + shared, other implicitly disabled.
  await tools.setEnabled('T1', 'C_FIN', 'mcp', true);
  await c.setChannelMode('mcp', 'per-user');
  m = await c.toolManifest();
  assert.deepEqual(m, [
    { provider: 'mcp', mode: 'per-user', enabled: true, identity: 'acting_human', visibility: 'public' },
    { provider: 'other', mode: null, enabled: false, identity: 'acting_human', visibility: 'public' },
  ]);
});

// toolManifest() must reflect Policy too, not just the channel tool allowlist: a provider the
// channel enables but Policy denies is reported disabled, matching what connect() would do.
test('toolManifest reflects a Policy deny (intersects channel tools and policy)', async () => {
  const deny = new Policy({ other: { defaultAllow: false, allowChannels: [] } });
  const { c, tools } = await ctx(true, 'C_FIN', deny);

  // Channel allowlist enables both, but policy denies 'other' in this channel.
  await tools.setEnabled('T1', 'C_FIN', 'mcp', true);
  await tools.setEnabled('T1', 'C_FIN', 'other', true);

  const m = await c.toolManifest();
  assert.deepEqual(m, [
    { provider: 'mcp', mode: null, enabled: true, identity: 'acting_human', visibility: 'public' },
    { provider: 'other', mode: null, enabled: false, identity: 'acting_human', visibility: 'public' }, // tool-enabled but policy-denied
  ]);

  // Consistency: connect() actually refuses the provider the manifest marks disabled.
  await assert.rejects(() => c.connect('other'), /Policy denies/);
});

// A null channel (DM-less) keeps current behavior: no tool restriction, manifest all-enabled.
test('null channel → no tool restriction; manifest all enabled', async () => {
  const { c } = await ctx(true, null);
  const m = await c.toolManifest();
  assert.deepEqual(m.map((e) => e.enabled), [true, true]);
  assert.deepEqual(m.map((e) => e.mode), [null, null]);
});

// ── #111 ChannelTools.applyEnabled: atomic first-write allowlist materialization ─────────────────
// The configured-ness decision lives INSIDE the materialization statement (NOT EXISTS), and each
// statement is engine-atomic, so concurrent first-writers and mid-sequence failures can never leave
// a PARTIAL allowlist that silently disables bystander providers.
const ALL3 = ['mcp', 'other', 'third'];

async function freshTools() {
  const db = await openDb({ dbPath: ':memory:' });
  return { db, tools: new ChannelTools(db) };
}

test('applyEnabled on an unconfigured channel materializes the full allowlist', async () => {
  const { tools } = await freshTools();
  await tools.applyEnabled('T1', 'C1', [['mcp', false]], ALL3);
  assert.equal(await tools.isEnabled('T1', 'C1', 'mcp'), false); // the targeted provider
  assert.equal(await tools.isEnabled('T1', 'C1', 'other'), true); // bystanders materialized enabled
  assert.equal(await tools.isEnabled('T1', 'C1', 'third'), true);
});

test('applyEnabled on a configured channel touches only the given rows', async () => {
  const { tools } = await freshTools();
  await tools.setEnabled('T1', 'C1', 'other', false); // channel is already an allowlist
  await tools.applyEnabled('T1', 'C1', [['mcp', true]], ALL3);
  assert.equal(await tools.isEnabled('T1', 'C1', 'mcp'), true);
  assert.equal(await tools.isEnabled('T1', 'C1', 'other'), false); // untouched — no revert
  assert.equal(await tools.isEnabled('T1', 'C1', 'third'), false); // unlisted on an allowlist stays off
});

test('applyEnabled: concurrent first writes converge — both targets land, bystanders stay enabled', async () => {
  const { tools } = await freshTools();
  await Promise.all([
    tools.applyEnabled('T1', 'C1', [['mcp', false]], ALL3),
    tools.applyEnabled('T1', 'C1', [['other', false]], ALL3),
  ]);
  assert.equal(await tools.isEnabled('T1', 'C1', 'mcp'), false);
  assert.equal(await tools.isEnabled('T1', 'C1', 'other'), false);
  assert.equal(await tools.isEnabled('T1', 'C1', 'third'), true); // neither writer's fillers clobbered
});

// Failure injection at the Db seam, between/at the two statements. A mid-STATEMENT partial write
// cannot be injected here — that atomicity is the engine's own guarantee (the reason applyEnabled
// is single statements instead of a client-side loop); the PG execution of the same statements is
// covered by the opt-in postgres suite (TEST-4).
function flakyDb(db: any, failOn: () => RegExp | null) {
  return {
    get: db.get.bind(db),
    all: db.all.bind(db),
    exec: db.exec.bind(db),
    close: db.close.bind(db),
    run: async (sql: string, params?: any[]) => {
      const re = failOn();
      if (re?.test(sql)) throw new Error('injected db failure');
      return db.run(sql, params);
    },
  };
}

test('applyEnabled: failing materialization writes NOTHING (channel stays all-enabled)', async () => {
  const { db } = await freshTools();
  let re: RegExp | null = /DO NOTHING/;
  const tools = new ChannelTools(flakyDb(db, () => re) as any);
  await assert.rejects(() => tools.applyEnabled('T1', 'C1', [['mcp', false]], ALL3), /injected/);
  assert.equal(await tools.isConfigured('T1', 'C1'), false); // no partial allowlist
  assert.equal(await tools.isEnabled('T1', 'C1', 'other'), true); // everything still effectively enabled
  re = null; // db recovers → the retry lands the full change
  await tools.applyEnabled('T1', 'C1', [['mcp', false]], ALL3);
  assert.equal(await tools.isEnabled('T1', 'C1', 'mcp'), false);
  assert.equal(await tools.isEnabled('T1', 'C1', 'third'), true);
});

test('applyEnabled: failure after materialization still leaves a COMPLETE allowlist with the change applied', async () => {
  const { db } = await freshTools();
  const tools = new ChannelTools(flakyDb(db, () => /DO UPDATE/) as any);
  await assert.rejects(() => tools.applyEnabled('T1', 'C1', [['mcp', false]], ALL3), /injected/);
  // The materialization statement already carried the desired bit, so the intermediate state is the
  // final state — complete, never a partial allowlist that disables bystanders.
  assert.equal(await tools.isEnabled('T1', 'C1', 'mcp'), false);
  assert.equal(await tools.isEnabled('T1', 'C1', 'other'), true);
  assert.equal(await tools.isEnabled('T1', 'C1', 'third'), true);
});
