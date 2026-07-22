import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig, isChannelMode, writeChannelMode } from '../src/core/channelConfig';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { ConnectContext, createVouchr } from '../src/adapters/bolt';
import { CONFIGURE_CALLBACK } from '../src/adapters/blocks';
import { disconnectChannelShared } from '../src/core/channelCredential';
import { offboardUser } from '../src/core/offboard';
import { ChannelTools } from '../src/core/tools';
import { channelOwner } from '../src/core/owner';

// The channel-creator config gate is OPT-IN (`allowChannelCreatorConfig`, default off). When off the
// gate is exactly workspace-admin-only; when on, a channel's CREATOR may also run the config
// mutations. Mirrors governance.test.ts's harness, plus `creator`/`allowCreator` knobs.
const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ACTOR' };

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

async function ctx(t: TestContext, opts: {
  slackAdmin?: boolean;      // what the built-in users.info gate reports for ID.userId
  creator?: string;         // channel creator id from conversations.info
  allowCreator?: boolean;   // the opt-in flag
  infoThrows?: boolean;     // conversations.info fails (fail-closed surface)
  adminCheck?: (client: any, userId: string, teamId: string) => Promise<boolean>;
} = {}) {
  const { slackAdmin = false, creator = 'U_SOMEONE_ELSE', allowCreator = false, infoThrows = false, adminCheck } = opts;
  const db = await openTestDb(t);
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

test('disconnectChannelShared: removes the shared credential (per-user after); a session channel is a no-op (#2)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const cfg = new ChannelConfig(db);

  // A shared channel with a stored shared credential → removed, and the channel returns to per-user.
  const shared = channelOwner('T1', 'C_SHARED');
  await writeChannelMode(cfg, 'T1', 'C_SHARED', 'mcp', 'shared');
  await vault.upsert(shared, 'mcp', { accessToken: 'shared-sk', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const removed = await disconnectChannelShared({
    vault, audit, channelConfig: cfg, registry: new ProviderRegistry([provider]),
    identity: ID, channel: 'C_SHARED', providerId: 'mcp', issuance: await vault.userProvisioningIssuedAt(),
  });
  assert.equal(removed.status, 'removed');
  assert.equal(await cfg.getMode('T1', 'C_SHARED', 'mcp'), 'per-user'); // returned to per-user
  assert.ok(!(await vault.get(shared, 'mcp'))); // the shared credential is gone

  // A SESSION channel is never downgraded — disconnect-shared is a truthful no-op there (the #2 fix).
  await writeChannelMode(cfg, 'T1', 'C_SESSION', 'mcp', 'session');
  const noop = await disconnectChannelShared({
    vault, audit, channelConfig: cfg, registry: new ProviderRegistry([provider]),
    identity: ID, channel: 'C_SESSION', providerId: 'mcp', issuance: await vault.userProvisioningIssuedAt(),
  });
  assert.equal(noop.status, 'not-shared');
  assert.equal(await cfg.getMode('T1', 'C_SESSION', 'mcp'), 'session'); // thread-approval requirement preserved
});

// The channel-shared revoke truth table must MATCH the personal disconnect (removeUserConnection):
// `ok` = "no upstream revocation debt is left behind", and a committed removal writes a durable
// 'revoke' audit (never the token) with the same attempted/skipped meta shape as the break-glass path.
test('disconnectChannelShared truth table (#3): revoke / non-revocable / unregistered / reference + revoke audit', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const cfg = new ChannelConfig(db);
  const revokedTokens: string[] = [];
  const revProvider = defineProvider({
    id: 'rev', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
    revoke: async (_p, token) => { revokedTokens.push(token); }, // success (no throw)
  });
  const registry = new ProviderRegistry([provider, revProvider]);
  const issuance = () => vault.userProvisioningIssuedAt();
  const setShared = async (channel: string, providerId: string, token: string | null) => {
    await writeChannelMode(cfg, 'T1', channel, providerId, 'shared');
    if (token !== null) {
      await vault.upsert(channelOwner('T1', channel), providerId, { accessToken: token, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
    }
  };
  const revokeAudits = async () =>
    ((await db.all("SELECT provider, meta FROM audit WHERE action='revoke'")) as any[]).map((r) => ({ provider: r.provider, meta: JSON.parse(r.meta) }));

  // (1) registered + revocable + a stored token → removed, ok:true, attempted:true; the token is
  //     handed to the revoke endpoint, and a committed 'revoke' audit records ok:true (owner:channel).
  await setShared('C1', 'rev', 'rev-sk');
  const r1 = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry, identity: ID, channel: 'C1', providerId: 'rev', issuance: await issuance() });
  assert.deepEqual({ status: r1.status, ok: r1.ok, attempted: r1.attempted }, { status: 'removed', ok: true, attempted: true });
  assert.deepEqual(revokedTokens, ['rev-sk']);
  assert.equal(await cfg.getMode('T1', 'C1', 'rev'), 'per-user');
  const a1 = (await revokeAudits()).filter((r) => r.provider === 'rev');
  assert.equal(a1.length, 1);
  assert.deepEqual(a1[0].meta, { owner: 'channel', channel: 'C1', ok: true });

  // (2) registered + NON-revocable (no revoke hook/url) → removed, ok:true (no debt exists), NOT
  //     attempted; the revoke audit marks the call skipped rather than fabricating ok.
  await setShared('C2', 'mcp', 'mcp-sk');
  const r2 = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry, identity: ID, channel: 'C2', providerId: 'mcp', issuance: await issuance() });
  assert.deepEqual({ status: r2.status, ok: r2.ok, attempted: r2.attempted }, { status: 'removed', ok: true, attempted: false });
  const a2 = (await revokeAudits()).filter((r) => r.provider === 'mcp' && r.meta.channel === 'C2');
  // `ok` is ALWAYS recorded (even when the revoke was skipped) so a successful non-revocable removal is
  // distinguishable from unresolved upstream debt — matching the personal disconnect revoke meta.
  assert.deepEqual(a2[0].meta, { owner: 'channel', channel: 'C2', ok: true, upstream: 'skipped' });

  // (3) UNREGISTERED id with a stored shared credential → removed, but ok:FALSE: the revoke contract is
  //     unknown, so upstream debt may remain. The old inverted table wrongly reported ok:true here.
  const bare = new ProviderRegistry([provider]); // 'ghost' is not registered
  await setShared('C3', 'ghost', 'ghost-sk');
  const r3 = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry: bare, identity: ID, channel: 'C3', providerId: 'ghost', issuance: await issuance() });
  assert.deepEqual({ status: r3.status, ok: r3.ok, attempted: r3.attempted }, { status: 'removed', ok: false, attempted: false });

  // (4) reference credential (secret_ref, no token Vouchr holds) on a REVOCABLE provider → removed, but
  //     ok:FALSE: a due upstream revoke could not run because Vouchr never held the token (missing).
  await writeChannelMode(cfg, 'T1', 'C4', 'rev', 'shared');
  await vault.reference(channelOwner('T1', 'C4'), 'rev', { source: 'test', secretRef: 'ref://chan/rev' });
  const r4 = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry, identity: ID, channel: 'C4', providerId: 'rev', issuance: await issuance() });
  assert.deepEqual({ status: r4.status, ok: r4.ok, attempted: r4.attempted }, { status: 'removed', ok: false, attempted: false });

  // (5) dry-run credential → removed, ok:true, NOT attempted: a synthetic row is never POSTed upstream.
  await writeChannelMode(cfg, 'T1', 'C5', 'rev', 'shared');
  await vault.upsertDryRun(channelOwner('T1', 'C5'), 'rev', { accessToken: 'dry-sk', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const before = revokedTokens.length;
  const r5 = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry, identity: ID, channel: 'C5', providerId: 'rev', issuance: await issuance() });
  assert.deepEqual({ status: r5.status, ok: r5.ok, attempted: r5.attempted }, { status: 'removed', ok: true, attempted: false });
  assert.equal(revokedTokens.length, before); // no real upstream call for a dry-run row
});

test('disconnectChannelShared preserves its committed outcome when the revoke audit store fails', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const cfg = new ChannelConfig(db);
  const owner = channelOwner('T1', 'C_AUDIT_FAIL');
  await writeChannelMode(cfg, 'T1', 'C_AUDIT_FAIL', 'mcp', 'shared');
  await vault.upsert(owner, 'mcp', {
    accessToken: 'shared-audit-failure', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const originalRecord = audit.record.bind(audit);
  let attemptedMeta: unknown;
  (audit as any).record = async (...args: Parameters<Audit['record']>) => {
    if (args[0] === 'revoke') {
      attemptedMeta = args[3];
      throw new Error('post-commit audit unavailable');
    }
    return originalRecord(...args);
  };

  const outcome = await disconnectChannelShared({
    vault,
    audit,
    channelConfig: cfg,
    registry: new ProviderRegistry([provider]),
    identity: ID,
    channel: 'C_AUDIT_FAIL',
    providerId: 'mcp',
    issuance: await vault.userProvisioningIssuedAt(),
  });

  assert.deepEqual(outcome, { status: 'removed', ok: true, attempted: false, audited: false });
  assert.equal(await vault.has(owner, 'mcp'), false);
  assert.equal(await cfg.getMode('T1', 'C_AUDIT_FAIL', 'mcp'), 'per-user');
  assert.deepEqual(attemptedMeta, {
    owner: 'channel', channel: 'C_AUDIT_FAIL', ok: true, upstream: 'skipped',
  });
  assert.equal((await db.all(`SELECT 1 FROM audit WHERE action='revoke'`)).length, 0);
});

// The atomic rewrite (#1) must report the truthful outcome AND mutate nothing on a stale snapshot: a
// shared mode with no stored credential is `missing` (still recovered to per-user, no revoke); a newer
// credential generation or an offboarded actor is `stale` and leaves the credential + mode untouched.
test('disconnectChannelShared truthful missing + stale (#1): no-credential, newer generation, offboarded actor', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const cfg = new ChannelConfig(db);
  const registry = new ProviderRegistry([provider]);

  // missing: shared mode with no credential (e.g. a prior break-glass revoke left the mode). Still
  // recover the channel to per-user, but nothing is deleted or revoked and no 'revoke' audit is due.
  await writeChannelMode(cfg, 'T1', 'C_MISS', 'mcp', 'shared');
  const miss = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry, identity: ID, channel: 'C_MISS', providerId: 'mcp', issuance: await vault.userProvisioningIssuedAt() });
  assert.deepEqual({ status: miss.status, ok: miss.ok, attempted: miss.attempted }, { status: 'missing', ok: true, attempted: false });
  assert.equal(await cfg.getMode('T1', 'C_MISS', 'mcp'), 'per-user');
  assert.equal(((await db.all("SELECT 1 FROM audit WHERE action='revoke'")) as any[]).length, 0); // no revoke event

  // stale (newer generation): a credential re-configured AFTER the command was authorized must not be
  // deleted by the delayed command — the current-generation fence leaves it (and the mode) intact.
  await writeChannelMode(cfg, 'T1', 'C_NEW', 'mcp', 'shared');
  await vault.upsert(channelOwner('T1', 'C_NEW'), 'mcp', { accessToken: 'newer-sk', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const staleIssuance = await vault.userProvisioningIssuedAt();
  await db.run(
    "UPDATE connection SET generation_at=? WHERE team_id=? AND owner_kind='channel' AND owner_id=? AND provider=?",
    [staleIssuance + 1000, 'T1', 'C_NEW', 'mcp'],
  );
  const staleGen = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry, identity: ID, channel: 'C_NEW', providerId: 'mcp', issuance: staleIssuance });
  assert.equal(staleGen.status, 'stale');
  assert.equal(await cfg.getMode('T1', 'C_NEW', 'mcp'), 'shared'); // unchanged
  assert.ok(await vault.get(channelOwner('T1', 'C_NEW'), 'mcp')); // the newer credential survives

  // stale (SAME-millisecond replacement, no sleeps): a credential whose generation equals the command
  // issuance to the millisecond must fail closed (`>=`) — it is a replacement racing the command and
  // must not be deleted. Deterministic: set generation_at EXACTLY to the issuance.
  await writeChannelMode(cfg, 'T1', 'C_EQ', 'mcp', 'shared');
  await vault.upsert(channelOwner('T1', 'C_EQ'), 'mcp', { accessToken: 'eq-sk', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const eqIssuance = await vault.userProvisioningIssuedAt();
  await db.run(
    "UPDATE connection SET generation_at=? WHERE team_id=? AND owner_kind='channel' AND owner_id=? AND provider=?",
    [eqIssuance, 'T1', 'C_EQ', 'mcp'],
  );
  const staleEq = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry, identity: ID, channel: 'C_EQ', providerId: 'mcp', issuance: eqIssuance });
  assert.equal(staleEq.status, 'stale');
  assert.equal(await cfg.getMode('T1', 'C_EQ', 'mcp'), 'shared'); // unchanged
  assert.ok(await vault.get(channelOwner('T1', 'C_EQ'), 'mcp')); // the same-ms replacement survives

  // stale (offboarded actor): a command authorized before the acting admin was offboarded must not
  // delete first and reject later — the actor fence rejects it before any mutation.
  await writeChannelMode(cfg, 'T1', 'C_OFF', 'mcp', 'shared');
  await vault.upsert(channelOwner('T1', 'C_OFF'), 'mcp', { accessToken: 'off-sk', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const offIssuance = await vault.userProvisioningIssuedAt();
  await offboardUser(vault, audit, new Consent(db), ID); // tombstone committed at-or-after offIssuance
  const staleOff = await disconnectChannelShared({ vault, audit, channelConfig: cfg, registry, identity: ID, channel: 'C_OFF', providerId: 'mcp', issuance: offIssuance });
  assert.equal(staleOff.status, 'stale');
  assert.equal(await cfg.getMode('T1', 'C_OFF', 'mcp'), 'shared'); // unchanged — no destructive mutation
  assert.ok(await vault.get(channelOwner('T1', 'C_OFF'), 'mcp')); // the channel credential is intact
});

// #2(a): a ConnectContext constructed directly for a DM channel (no explicit governableChannel) must
// derive the ungoverned scope from the id — otherwise `/vouchr tools` in a DM reports every provider
// disabled by deny-by-default. The middleware passes an explicit scope; direct callers rely on the default.
test('#2: a directly-constructed ConnectContext for a DM is ungoverned — toolManifest reports providers enabled', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const make = (channel: string) => new ConnectContext({
    identity: ID, channel, // no governableChannel: exercise the constructor default
    client: {} as any, registry: new ProviderRegistry([provider]), vault, audit,
    consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
    channelConfig: new ChannelConfig(db), channelTools: new ChannelTools(db), providerIds: ['mcp'],
  });
  // A 1:1 DM ('D…') → personal/ungoverned → the provider reports ENABLED with no channel enable.
  assert.equal((await make('D0PERSONAL').toolManifest()).find((m) => m.provider === 'mcp')?.enabled, true);
  // A governed channel with no enable → deny-by-default reports it disabled (the contrast).
  assert.equal((await make('C_GOVERNED').toolManifest()).find((m) => m.provider === 'mcp')?.enabled, false);
});

const auditActions = async (db: any) =>
  ((await db.all('SELECT action FROM audit')) as any[]).map((r) => r.action);
const mode = async (db: any) =>
  ((await db.get('SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?',
    ['T1', 'C_FIN', 'mcp'])) as any)?.mode ?? null;

// (a) With the flag ON, the channel creator (not a workspace admin) may configure.
test('flag on: channel creator (non-workspace-admin) can setChannelMode', async (t) => {
  const { c, db } = await ctx(t, { slackAdmin: false, creator: ID.userId, allowCreator: true });
  await c.setChannelMode('mcp', 'per-user');
  assert.equal(await mode(db), 'per-user');
  assert.deepEqual(await auditActions(db), ['config']);
});

// DEFAULT (flag OFF): workspace-admin-only — the creator is NOT allowed, exactly as pre-PR.
test('flag off (default): channel creator is denied — workspace-admin-only', async (t) => {
  const { c, db } = await ctx(t, { slackAdmin: false, creator: ID.userId, allowCreator: false });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /Only a workspace admin can/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// (b) Neither workspace admin nor creator → denied + audited (default-deny intact), flag irrelevant.
test('non-admin non-creator is denied and audited', async (t) => {
  const { c, db } = await ctx(t, { slackAdmin: false, creator: 'U_SOMEONE_ELSE', allowCreator: true });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /admin/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// (c) A workspace admin is still allowed, even without the flag and without creating the channel.
test('workspace admin (not creator) is still allowed, flag off', async (t) => {
  const { c, db } = await ctx(t, { slackAdmin: true, creator: 'U_SOMEONE_ELSE', allowCreator: false });
  await c.setChannelMode('mcp', 'per-user');
  assert.equal(await mode(db), 'per-user');
  assert.deepEqual(await auditActions(db), ['config']);
});

// (d) A custom adminCheck override fully replaces the default: false blocks even the channel creator.
test('adminCheck override false blocks even the channel creator', async (t) => {
  const { c, db } = await ctx(t, { slackAdmin: false, creator: ID.userId, allowCreator: true, adminCheck: async () => false });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /admin/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// Fail-closed on the new API surface: flag on, not a workspace admin, conversations.info throws →
// isChannelAdmin can't confirm the creator → DENIED + audited.
test('flag on: conversations.info error fails closed → denied', async (t) => {
  const { c, db } = await ctx(t, { slackAdmin: false, creator: ID.userId, allowCreator: true, infoThrows: true });
  await assert.rejects(() => c.setChannelMode('mcp', 'per-user'), /admin/);
  assert.equal(await mode(db), null);
  assert.deepEqual(await auditActions(db), ['denied']);
});

// The COMMAND paths (enable/disable tool allowlist + the configure pre-modal gate) route through
// commandAdmin, not requireAdmin — assert they honor the same opt-in creator rule.
async function commandHarness(t: TestContext, opts: {
  creator: string;
  allowCreator?: boolean;
  isAdmin?: (client: any, userId: string, teamId: string) => Promise<boolean>;
}) {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t),
    allowChannelCreatorConfig: opts.allowCreator ?? false, isAdmin: opts.isAdmin,
  });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
  const out: string[] = [];
  let opened: any = null;
  const updates: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: false } }) }, // never a workspace admin
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator: opts.creator } }) },
    views: {
      open: async (a: any) => {
        opened = a;
        return { view: { id: 'V_LOADING' } };
      },
      update: async (a: any) => { updates.push(a); },
    },
    chat: { postMessage: async () => ({}) },
  };
  const base = { team_id: 'T1', user_id: ID.userId, channel_id: 'C_FIN', trigger_id: 'trig' };
  const run = (text: string) =>
    handler({ command: { ...base, text }, ack: async () => {}, respond: async (m: string) => out.push(m), client });
  return {
    lan,
    run,
    out,
    opened: () => opened,
    hydrated: () => updates.find((entry) => entry?.view?.callback_id === CONFIGURE_CALLBACK)?.view ?? null,
  };
}

// Flag on: channel creator can enable/disable tools and open the configure modal.
test('flag on: channel creator can run enable/disable and pass the configure gate', async (t) => {
  const h = await commandHarness(t, { creator: ID.userId, allowCreator: true });
  await h.run('enable mcp');
  assert.match(h.out[0], /Enabled/);
  const row = await h.lan.db.get('SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(row.enabled, 1);

  await h.run('disable mcp');
  assert.match(h.out[1], /Disabled/);

  await h.run('connect-shared mcp');
  assert.equal(h.opened()?.trigger_id, 'trig'); // loading modal consumed the trigger immediately
  assert.equal(h.hydrated()?.callback_id, CONFIGURE_CALLBACK);
});

// Flag off (default): the creator is denied on the same command paths — workspace-admin-only.
test('flag off (default): channel creator is denied on enable/configure', async (t) => {
  const h = await commandHarness(t, { creator: ID.userId, allowCreator: false });
  await h.run('enable mcp');
  assert.match(h.out[0], /Only a workspace admin can/);
  await h.run('connect-shared mcp');
  assert.ok(h.opened());
  assert.equal(h.hydrated(), null);
});

// A non-creator non-admin is denied on the command paths even with the flag on.
test('flag on: non-creator non-admin is denied on enable/configure', async (t) => {
  const h = await commandHarness(t, { creator: 'U_SOMEONE_ELSE', allowCreator: true });
  await h.run('enable mcp');
  assert.match(h.out[0], /admin or the channel creator/);
  await h.run('connect-shared mcp');
  assert.match(h.out[1], /admin or the channel creator/);
  assert.ok(h.opened());
  assert.equal(h.hydrated(), null);
  assert.ok((await h.lan.db.all('SELECT action FROM audit') as any[]).every((r) => r.action === 'denied'));
});

// commandAdmin override precedence: flag on + a creator, but an isAdmin override returning false
// still blocks the enable/disable path (override fully replaces the built-in gate).
test('flag on: isAdmin override false blocks the creator on the command path', async (t) => {
  const h = await commandHarness(t, { creator: ID.userId, allowCreator: true, isAdmin: async () => false });
  await h.run('enable mcp');
  assert.doesNotMatch(h.out[0], /Enabled/);
  const row = await h.lan.db.get('SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(row, undefined); // never written
});

// #196: `union` was removed. It must be rejected at the config boundary BEFORE any persist/audit
// (SEC-4), both at the guard the slash command routes through and at the true sink (ChannelConfig).
test('union mode is rejected at the config boundary, writing nothing (SEC-4)', async (t) => {
  // The single-source-of-truth guard no longer admits it; the surviving three still pass.
  assert.equal(isChannelMode('union'), false);
  for (const m of ['shared', 'per-user', 'session']) assert.equal(isChannelMode(m), true);

  // Slash command: an admin creator runs `mode mcp union` → the usage message, and NO row is written.
  const h = await commandHarness(t, { creator: ID.userId, allowCreator: true });
  await h.run('mode mcp union');
  assert.match(h.out[0], /Usage: `\/vouchr mode/);
  const cfgRow = await h.lan.db.get(
    'SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(cfgRow, undefined); // never persisted
  assert.equal((await h.lan.db.all('SELECT 1 FROM audit') as any[]).length, 0); // never audited

  // Internal row sink still rejects a bogus runtime value before writing anything.
  const db = await openTestDb(t);
  const cfg = new ChannelConfig(db);
  await assert.rejects(
    () => writeChannelMode(cfg, 'T1', 'C_FIN', 'mcp', 'union' as any),
    /invalid channel mode/,
  );
  assert.equal(await cfg.getMode('T1', 'C_FIN', 'mcp'), null);
});

// #2 atomicity: the 'config' (mode-flip) audit runs INSIDE the locked transaction, so an audit-store
// failure THERE must roll the WHOLE operation back — no credential delete, no mode change, no purge —
// and the post-commit upstream revoke must never run. (Contrast: a POST-COMMIT revoke-audit failure
// preserves the committed outcome and only reports audited:false — covered by a separate test.)
test('disconnectChannelShared: an in-transaction config-audit failure rolls back the delete/mode/purge and skips revoke', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const cfg = new ChannelConfig(db);
  const revoked: string[] = [];
  const rev = defineProvider({
    id: 'rev', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
    revoke: async (_p, tokenStr) => { revoked.push(tokenStr); },
  });
  await writeChannelMode(cfg, 'T1', 'C_RB', 'rev', 'shared');
  await vault.upsert(channelOwner('T1', 'C_RB'), 'rev', { accessToken: 'rev-sk', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const issuance = await vault.userProvisioningIssuedAt(); // after the write ⇒ not stale

  const realAudit = new Audit(db);
  const audit = {
    record: async (action: any, ...rest: any[]) => {
      if (action === 'config') throw new Error('audit-store down'); // the in-transaction mode-flip audit
      return (realAudit.record as any)(action, ...rest);
    },
  } as any;

  await assert.rejects(() => disconnectChannelShared({
    vault, audit, channelConfig: cfg, registry: new ProviderRegistry([rev]),
    identity: ID, channel: 'C_RB', providerId: 'rev', issuance,
  }));

  // FULL rollback: credential, mode, and satellites intact; no upstream revoke attempted or audited.
  assert.ok(await vault.get(channelOwner('T1', 'C_RB'), 'rev'), 'the credential is not deleted');
  assert.equal(await cfg.getMode('T1', 'C_RB', 'rev'), 'shared', 'the mode is unchanged');
  assert.deepEqual(revoked, [], 'the upstream revoke was never attempted');
  assert.equal(((await db.all("SELECT 1 FROM audit WHERE action='revoke'")) as any[]).length, 0, 'no revoke audit row');
});
