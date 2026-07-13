import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { authorizeProvider, buildToolManifest } from '../src/core/authz';
import { ConnectContext } from '../src/adapters/bolt';
import { countingDb } from './support/counting-db';
import type { Db } from '../src/core/db';

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
async function ctx(t: TestContext, isAdmin = true, channel: string | null = 'C_FIN', policy = new Policy()) {
  const db = await openTestDb(t);
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
test('no rows => all providers enabled (backward compat)', async (t) => {
  const { tools } = await ctx(t);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'mcp'), true);
  assert.equal(await tools.isEnabled('T1', 'C_FIN', 'other'), true);
  assert.deepEqual(await tools.listEnabled('T1', 'C_FIN'), []);
});

// Once any provider is set, the channel becomes an allowlist: only enabled ones are allowed.
test('enabling A disables B in that channel; isEnabled/listEnabled correctness', async (t) => {
  const { tools } = await ctx(t);
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
test("connect() refuses a disabled provider (audited 'tool-disabled') and allows an enabled one", async (t) => {
  const { c, db, vault, tools } = await ctx(t);
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
test('connectChannel() refuses a disabled provider and allows an enabled one', async (t) => {
  const { c, vault, tools } = await ctx(t, true);
  await tools.setEnabled('T1', 'C_FIN', 'mcp', true); // allowlist: mcp on, other off
  await c.setChannelSecret('mcp', 'sk-shared'); // admin config (not tool-gated)

  assert.ok(await c.connectChannel('mcp')); // enabled + shared cred → handle
  assert.equal((await vault.get(chOwner, 'mcp'))?.accessToken, 'sk-shared');
  await assert.rejects(() => c.connectChannel('other'), /not enabled/);
});

// toolManifest(): one entry per registered provider, with enabled flag + channel mode.
test('toolManifest returns the expected shape', async (t) => {
  const { c, tools } = await ctx(t);

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
test('toolManifest reflects a Policy deny (intersects channel tools and policy)', async (t) => {
  const deny = new Policy({ other: { defaultAllow: false, allowChannels: [] } });
  const { c, tools } = await ctx(t, true, 'C_FIN', deny);

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
test('null channel → no tool restriction; manifest all enabled', async (t) => {
  const { c } = await ctx(t, true, null);
  const m = await c.toolManifest();
  assert.deepEqual(m.map((e) => e.enabled), [true, true]);
  assert.deepEqual(m.map((e) => e.mode), [null, null]);
});

// ── #111 ChannelTools.applyEnabled: atomic first-write allowlist materialization ─────────────────
// The configured-ness decision lives INSIDE the materialization statement (NOT EXISTS), and each
// statement is engine-atomic, so concurrent first-writers and mid-sequence failures can never leave
// a PARTIAL allowlist that silently disables bystander providers.
const ALL3 = ['mcp', 'other', 'third'];

async function freshTools(t: TestContext) {
  const db = await openTestDb(t);
  return { db, tools: new ChannelTools(db) };
}

test('applyEnabled on an unconfigured channel materializes the full allowlist', async (t) => {
  const { tools } = await freshTools(t);
  await tools.applyEnabled('T1', 'C1', [['mcp', false]], ALL3);
  assert.equal(await tools.isEnabled('T1', 'C1', 'mcp'), false); // the targeted provider
  assert.equal(await tools.isEnabled('T1', 'C1', 'other'), true); // bystanders materialized enabled
  assert.equal(await tools.isEnabled('T1', 'C1', 'third'), true);
});

test('applyEnabled on a configured channel touches only the given rows', async (t) => {
  const { tools } = await freshTools(t);
  await tools.setEnabled('T1', 'C1', 'other', false); // channel is already an allowlist
  await tools.applyEnabled('T1', 'C1', [['mcp', true]], ALL3);
  assert.equal(await tools.isEnabled('T1', 'C1', 'mcp'), true);
  assert.equal(await tools.isEnabled('T1', 'C1', 'other'), false); // untouched — no revert
  assert.equal(await tools.isEnabled('T1', 'C1', 'third'), false); // unlisted on an allowlist stays off
});

test('applyEnabled: concurrent first writes converge — both targets land, bystanders stay enabled', async (t) => {
  const { tools } = await freshTools(t);
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

test('applyEnabled: failing materialization writes NOTHING (channel stays all-enabled)', async (t) => {
  const { db } = await freshTools(t);
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

test('applyEnabled: failure after materialization still leaves a COMPLETE allowlist with the change applied', async (t) => {
  const { db } = await freshTools(t);
  const tools = new ChannelTools(flakyDb(db, () => /DO UPDATE/) as any);
  await assert.rejects(() => tools.applyEnabled('T1', 'C1', [['mcp', false]], ALL3), /injected/);
  // The materialization statement already carried the desired bit, so the intermediate state is the
  // final state — complete, never a partial allowlist that disables bystanders.
  assert.equal(await tools.isEnabled('T1', 'C1', 'mcp'), false);
  assert.equal(await tools.isEnabled('T1', 'C1', 'other'), true);
  assert.equal(await tools.isEnabled('T1', 'C1', 'third'), true);
});

// ── #209 batched manifest reads: query count is bounded by the CHANNEL, not the provider count ────
// The whole point of this change: buildToolManifest (and the App Home admin console) must issue a fixed
// number of channel-scoped reads no matter how many providers are registered. Wrapping the Db to count
// its get/all calls makes that a regression test — pre-batch it was ~4 per-provider gets and grew with N.
function mkProvider(id: string) {
  return defineProvider({
    id, authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
}

test('buildToolManifest issues a fixed 3 reads regardless of provider count (#209)', async (t) => {
  const base = await openTestDb(t);
  // Configure the channel so all three tables have rows — exercises the real batched read paths.
  await new ChannelTools(base).setEnabled('T1', 'C_FIN', 'mcp', true); // allowlist: mcp on, rest off
  await new ChannelConfig(base).setMode('T1', 'C_FIN', 'mcp', 'per-user');
  await new ChannelConfig(base).setVisibility('T1', 'C_FIN', 'mcp', 'private');

  const build = async (extra: number) => {
    const { db, counts } = countingDb(base);
    const ids = ['mcp', ...Array.from({ length: extra }, (_, i) => `p${i}`)];
    const manifest = await buildToolManifest({
      providerIds: ids, registry: new ProviderRegistry(ids.map(mkProvider)),
      channelTools: new ChannelTools(db), channelConfig: new ChannelConfig(db),
      principal: ID, channel: 'C_FIN',
    });
    return { counts, manifest };
  };

  const few = await build(1); // 2 providers
  const many = await build(50); // 51 providers

  // Exactly three channel-scoped reads (tool allowlist + mode + visibility), no per-provider gets, and
  // identical whether the channel has 2 or 51 providers.
  assert.deepEqual(few.counts, { get: 0, all: 3 });
  assert.deepEqual(many.counts, { get: 0, all: 3 });

  // Batching preserved semantics: 'mcp' enabled+per-user+private; every unlisted provider disabled with
  // the unconfigured defaults (mode null from modeSnapshot, visibility 'public' from visibilitySnapshot).
  assert.deepEqual(
    many.manifest.find((e) => e.provider === 'mcp'),
    { provider: 'mcp', mode: 'per-user', enabled: true, identity: 'acting_human', visibility: 'private' },
  );
  assert.ok(many.manifest
    .filter((e) => e.provider !== 'mcp')
    .every((e) => e.enabled === false && e.mode === null && e.visibility === 'public'));

  // Off-channel (channel null): every snapshot short-circuits to its in-memory fallback — ZERO reads,
  // every provider enabled with the null/'public' defaults. Pins that a manifest with no channel queries nothing.
  const off = countingDb(base);
  const offManifest = await buildToolManifest({
    providerIds: ['mcp', 'other'], registry: new ProviderRegistry(['mcp', 'other'].map(mkProvider)),
    channelTools: new ChannelTools(off.db), channelConfig: new ChannelConfig(off.db), principal: ID, channel: null,
  });
  assert.deepEqual(off.counts, { get: 0, all: 0 });
  assert.deepEqual(
    offManifest.map((e) => [e.enabled, e.mode, e.visibility]),
    [[true, null, 'public'], [true, null, 'public']],
  );

  // No registered providers means no channel facts can be consumed, so do not touch Postgres.
  const empty = countingDb(base);
  assert.deepEqual(await buildToolManifest({
    providerIds: [], registry: new ProviderRegistry([]), channelTools: new ChannelTools(empty.db),
    channelConfig: new ChannelConfig(empty.db), principal: ID, channel: 'C_FIN',
  }), []);
  assert.deepEqual(empty.counts, { get: 0, all: 0 });
});

test('buildToolManifest dispatches its three independent channel reads together', async () => {
  let started = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const channelTools = {
    isEnabled: async () => true,
    enabledSnapshot: async () => { started++; await gate; return () => true; },
  } as unknown as ChannelTools;
  const channelConfig = {
    getMode: async () => null,
    getVisibility: async () => 'public' as const,
    modeSnapshot: async () => { started++; await gate; return () => null; },
    visibilitySnapshot: async () => { started++; await gate; return () => 'public' as const; },
  } as unknown as ChannelConfig;

  const pending = buildToolManifest({
    providerIds: ['mcp'], registry: new ProviderRegistry([mcp]), channelTools, channelConfig,
    principal: ID, channel: 'C_FIN',
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(started, 3, 'all batch reads must be dispatched before any one resolves');
  release();
  await pending;
});

test('batched manifests preserve legacy/custom store overrides and runtime parity', async () => {
  // No DB methods on purpose: inherited batch methods would fail, proving the compatibility path
  // really delegates to the pre-existing overrides instead of merely producing the same values.
  const db = {} as Db;
  class CustomTools extends ChannelTools {
    override async isEnabled(): Promise<boolean> { return false; }
  }
  class CustomConfig extends ChannelConfig {
    override async getMode(): Promise<'session'> { return 'session'; }
    override async getVisibility(): Promise<'private'> { return 'private'; }
  }
  const tools = new CustomTools(db);
  const config = new CustomConfig(db);
  const manifest = await buildToolManifest({
    providerIds: ['mcp'], registry: new ProviderRegistry([mcp]), channelTools: tools,
    channelConfig: config, principal: ID, channel: 'C_FIN',
  });
  assert.equal(await authorizeProvider(undefined, tools, ID, 'C_FIN', 'mcp'), 'tool-disabled');
  assert.deepEqual(manifest[0], {
    provider: 'mcp', mode: 'session', enabled: false, identity: 'acting_human', visibility: 'private',
  });

  // isEnabled also delegates to the older public isConfigured hook. Overriding only that hook must
  // likewise force the compatibility path; the inherited batch would read this disabled row and lie.
  const disabledRowDb = {
    all: async () => [{ provider: 'mcp', enabled: 0 }],
  } as unknown as Db;
  class CustomConfiguredTools extends ChannelTools {
    override async isConfigured(): Promise<boolean> { return false; }
  }
  const configuredTools = new CustomConfiguredTools(disabledRowDb);
  const configuredManifest = await buildToolManifest({
    providerIds: ['mcp'], registry: new ProviderRegistry([mcp]), channelTools: configuredTools,
    principal: ID, channel: 'C_FIN',
  });
  assert.equal(await authorizeProvider(undefined, configuredTools, ID, 'C_FIN', 'mcp'), null);
  assert.equal(configuredManifest[0].enabled, true);

  // Existing JavaScript wrappers may implement only the pre-batch public methods. They remain valid.
  const legacyTools = { isEnabled: async () => true } as unknown as ChannelTools;
  const legacyConfig = {
    getMode: async () => 'per-user' as const,
    getVisibility: async () => 'public' as const,
  } as unknown as ChannelConfig;
  const legacy = await buildToolManifest({
    providerIds: ['mcp'], registry: new ProviderRegistry([mcp]), channelTools: legacyTools,
    channelConfig: legacyConfig, principal: ID, channel: 'C_FIN',
  });
  assert.deepEqual(legacy[0], {
    provider: 'mcp', mode: 'per-user', enabled: true, identity: 'acting_human', visibility: 'public',
  });
});

test('enabledSnapshot is one read and matches isEnabled per provider (App Home admin batch, #209)', async (t) => {
  const base = await openTestDb(t);
  await new ChannelTools(base).setEnabled('T1', 'C_FIN', 'mcp', true); // allowlist: mcp on, rest off

  const { db, counts } = countingDb(base);
  const snap = await new ChannelTools(db).enabledSnapshot('T1', 'C_FIN');
  assert.deepEqual(counts, { get: 0, all: 1 }); // one read for the whole channel, no per-provider gets

  // The batched predicate gives the exact same verdict isEnabled gives, provider by provider.
  const plain = new ChannelTools(base);
  for (const p of ['mcp', 'other', 'p0', 'p1']) {
    assert.equal(snap(p), await plain.isEnabled('T1', 'C_FIN', p), `snapshot disagrees with isEnabled for ${p}`);
  }

  // And an unconfigured channel snapshots to all-enabled (backward compat), still one read.
  const fresh = countingDb(base);
  const snap2 = await new ChannelTools(fresh.db).enabledSnapshot('T1', 'C_EMPTY');
  assert.deepEqual(fresh.counts, { get: 0, all: 1 });
  assert.equal(snap2('anything'), true);
});
