import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { sweepExpired } from '../src/core/sweep';
import { userOwner, channelOwner } from '../src/core/owner';
import { github, defineProvider } from '../src/core/providers';
import { ConnectionHandle } from '../src/core/injector';
import { configureChannelCredential, setChannelCredentialMode } from '../src/core/channelCredential';
import { openTestDb, testDbUrl, pgReachable } from './support/pg';

// Runs the security-critical invariants against a REAL Postgres (not a mock).
//   npm run pg:up   # start a throwaway postgres:16 in Docker
//   npm test        # if no PG is reachable these SKIP (suite stays offline-green); otherwise they RUN
//   npm run pg:down
// Each test gets a fresh, migrated, isolated schema via the owned-fixture harness (openTestDb/testDbUrl,
// #204) — no shared TRUNCATE, and the pool is closed + schema dropped on `t.after`. openDb no longer
// runs DDL, so the harness owns migration; a reachable-PG failure is a REAL failure, never a skip.
const SKIP = 'Postgres not reachable. Run `npm run pg:up` to exercise the PG backend';
const KEY = randomBytes(32);
const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

test('postgres backend: channel setup and mode changes serialize in both race directions', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });

  const identity = { enterpriseId: null, teamId: 'TL', userId: 'UA' };
  const channel = 'CL';
  const vaultA = new Vault(dbA, KEY);
  const vaultB = new Vault(dbB, KEY);
  const auditA = new Audit(dbA);
  const auditB = new Audit(dbB);
  const conflict = (mode: 'per-user' | 'session'): never => { throw new Error(`mode conflict: ${mode}`); };

  // Mode wins the lock: it deletes the old shared row and pauses before writing per-user. A setup
  // on the other pool must wait, then observe per-user and refuse instead of resurrecting a row.
  const modeFirst = 'mode-first';
  const configA = new ChannelConfig(dbA);
  const configB = new ChannelConfig(dbB);
  await configureChannelCredential({
    vault: vaultA, audit: auditA, channelConfig: configA, identity, channel, providerId: modeFirst,
    credential: { kind: 'secret', token: tok('old-shared') }, modeConflict: conflict,
  });
  let modeEntered!: () => void;
  let releaseMode!: () => void;
  const atModeWrite = new Promise<void>((resolve) => { modeEntered = resolve; });
  const modeGate = new Promise<void>((resolve) => { releaseMode = resolve; });
  const setModeA = configA.setMode.bind(configA);
  configA.setMode = async (...args) => {
    if (args[2] === modeFirst && args[3] === 'per-user') { modeEntered(); await modeGate; }
    return setModeA(...args);
  };
  const modeChange = setChannelCredentialMode({
    vault: vaultA, audit: auditA, channelConfig: configA, identity, channel,
    providerId: modeFirst, mode: 'per-user',
  });
  await atModeWrite;
  let setupSettled = false;
  const lateSetup = configureChannelCredential({
    vault: vaultB, audit: auditB, channelConfig: configB, identity, channel, providerId: modeFirst,
    credential: { kind: 'secret', token: tok('late-shared') }, modeConflict: conflict,
  }).finally(() => { setupSettled = true; });
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.equal(setupSettled, false, 'setup did not wait for the in-flight mode transaction');
  releaseMode();
  await modeChange;
  await assert.rejects(lateSetup, /mode conflict: per-user/);
  assert.equal(await configB.getMode(identity.teamId, channel, modeFirst), 'per-user');
  assert.equal(await vaultB.get(channelOwner(identity.teamId, channel), modeFirst), null);

  // Setup wins the lock: mode waits until the shared row+mode commit, then atomically deletes that
  // row while moving to per-user. The final state can never retain a dormant shared credential.
  const setupFirst = 'setup-first';
  let setupEntered!: () => void;
  let releaseSetup!: () => void;
  const atSetupModeWrite = new Promise<void>((resolve) => { setupEntered = resolve; });
  const setupGate = new Promise<void>((resolve) => { releaseSetup = resolve; });
  configA.setMode = async (...args) => {
    if (args[2] === setupFirst && args[3] === 'shared') { setupEntered(); await setupGate; }
    return setModeA(...args);
  };
  const setup = configureChannelCredential({
    vault: vaultA, audit: auditA, channelConfig: configA, identity, channel, providerId: setupFirst,
    credential: { kind: 'secret', token: tok('new-shared') }, modeConflict: conflict,
  });
  await atSetupModeWrite;
  let modeSettled = false;
  const lateMode = setChannelCredentialMode({
    vault: vaultB, audit: auditB, channelConfig: configB, identity, channel,
    providerId: setupFirst, mode: 'per-user',
  }).finally(() => { modeSettled = true; });
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.equal(modeSettled, false, 'mode change did not wait for the in-flight setup transaction');
  releaseSetup();
  await Promise.all([setup, lateMode]);
  assert.equal(await configB.getMode(identity.teamId, channel, setupFirst), 'per-user');
  assert.equal(await vaultB.get(channelOwner(identity.teamId, channel), setupFirst), null);
});

test('postgres backend: isolation · crypto-at-rest · reference · ttl · consent · config', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);

  // T3 / owner isolation on the real engine.
  await vault.upsert(channelOwner('T1', 'X'), 'p', tok('chan-T1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p', tok('user-T1'));
  await vault.upsert(channelOwner('T2', 'X'), 'p', tok('chan-T2'));
  assert.equal((await vault.get(channelOwner('T1', 'X'), 'p'))?.accessToken, 'chan-T1');
  assert.equal((await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p'))?.accessToken, 'user-T1');
  assert.equal((await vault.get(channelOwner('T2', 'X'), 'p'))?.accessToken, 'chan-T2');
  assert.equal(await vault.get(channelOwner('T3', 'X'), 'p'), null); // unknown team → nothing

  // Ciphertext at rest: BYTEA round-trips and never holds the plaintext.
  const row = (await db.get(
    `SELECT access_token_enc FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
    ['T1', 'channel', 'X', 'p'],
  )) as any;
  assert.ok(Buffer.isBuffer(row.access_token_enc));
  assert.ok(!row.access_token_enc.toString('utf8').includes('chan-T1'));

  // Referenced secret: only the ARN pointer is stored, never a secret.
  await vault.reference(channelOwner('T1', 'C_FIN'), 'mcp', { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:r:k' });
  const ref = await vault.get(channelOwner('T1', 'C_FIN'), 'mcp');
  assert.equal(ref?.source, 'aws-sm');
  assert.equal(ref?.secretRef, 'arn:aws:secretsmanager:r:k');
  assert.equal(ref?.accessToken, null);

  // listForUser isolation.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'github', tok('g'));
  const mine = (await vault.listForUser({ enterpriseId: null, teamId: 'T1', userId: 'X' })).map((c) => c.provider).sort();
  assert.deepEqual(mine, ['github', 'p']); // channel creds never listed

  // TTL + sweep on a dedicated idle vault/row.
  const idle = new Vault(db, KEY, { idleMs: 1000 });
  await idle.upsert(userOwner({ enterpriseId: null, teamId: 'T9', userId: 'U' }), 'ttlp', tok('t'));
  await db.run(`UPDATE connection SET last_used_at=? WHERE team_id=? AND provider=?`, [Date.now() - 5000, 'T9', 'ttlp']);
  assert.equal(await idle.get(userOwner({ enterpriseId: null, teamId: 'T9', userId: 'U' }), 'ttlp'), null); // idle-expired
  const swept = await sweepExpired(idle, audit, new Consent(db));
  assert.ok(swept >= 1);

  // Consent single-use round-trip.
  const consent = new Consent(db);
  const id = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const { state } = await consent.begin(id, github({ clientId: 'a', clientSecret: 'b' }), 'https://x/cb', 'C1');
  assert.equal((await consent.consume(state))?.identity.userId, 'U1');
  assert.equal(await consent.consume(state), null); // single-use

  // Channel config mode persists.
  const cfg = new ChannelConfig(db);
  await cfg.setMode('T1', 'C_FIN', 'mcp', 'per-user');
  assert.equal(await cfg.getMode('T1', 'C_FIN', 'mcp'), 'per-user');

  // #107 stats rollup on the REAL engine. Postgres returns COUNT/BIGINT as strings and lowercases
  // unquoted aliases, so this is what actually verifies statsByChannel's Number() coercion + lowercase
  // aliases (SQLite would pass even if both were wrong).
  await audit.record('inject', { enterpriseId: null, teamId: 'T1', userId: 'S1' }, 'statp', { channel: 'C_STATS' });
  await audit.record('inject', { enterpriseId: null, teamId: 'T1', userId: 'S2' }, 'statp', { channel: 'C_STATS' });
  const stats = await audit.statsByChannel('T1', 'C_STATS', Date.now() - 24 * 60 * 60 * 1000);
  assert.equal(stats.length, 1);
  assert.equal(stats[0].provider, 'statp');
  assert.equal(stats[0].uses, 2); // strictly === number 2, not "2"
  assert.equal(stats[0].distinctActors, 2);
  assert.equal(typeof stats[0].lastUsed, 'number');
});

// A long-lived pod refreshes many times over its lifetime. The dedicated refresh pool's idle-client
// 'error' handler must attach exactly ONCE (at pool creation), not per withRefreshLock call — else
// listeners grow unbounded and pg logs MaxListenersExceededWarning.
test('postgres backend: withRefreshLock registers the pool error listener exactly once', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  for (let i = 0; i < 15; i++) {
    await db.withRefreshLock!(`leak-probe:${i % 3}`, async () => i); // distinct + repeated keys
  }
  const pool = (db as any).refreshPool;
  assert.equal(pool.listenerCount('error'), 1, 'refresh-pool error listener must attach exactly once');
});

// Cross-process refresh coordination: two SEPARATE connections (two "pods", each its own pool and
// own in-process inflight map) refresh the same (owner, provider) at once. The Postgres advisory
// xact lock + re-read-under-lock must collapse this to exactly one provider /token call; the loser
// reuses the winner's rotated token instead of consuming the (now-invalidated) old refresh token.
test('postgres backend: concurrent cross-process refresh => one /token call, loser reuses winner token', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  // Two pods, ONE shared schema (they must see each other's rows) → two pools opened on the same URL.
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });

  const realFetch = globalThis.fetch;
  try {
    const provider = defineProvider({
      id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
      scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
      clientId: 'id', clientSecret: 'sec',
    });
    const id = { enterpriseId: null, teamId: 'TL', userId: 'UL' };
    const O = userOwner(id);
    const vaultA = new Vault(dbA, KEY);
    const vaultB = new Vault(dbB, KEY);
    await vaultA.upsert(O, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });

    let tokenCalls = 0;
    let validRefresh = 'r1';
    const leaked: string[] = [];
    globalThis.fetch = (async (url: any, init: any) => {
      if (String(url) === 'https://acme.example/token') {
        tokenCalls++;
        const sent = new URLSearchParams(init.body as string).get('refresh_token');
        // Rotating provider: the previous refresh token is invalid the instant it's used once.
        if (sent !== validRefresh) {
          return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400, headers: { 'content-type': 'application/json' } });
        }
        validRefresh = 'r2';
        await new Promise((r) => setTimeout(r, 60)); // hold the advisory lock long enough to force the loser to wait
        return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2', expires_in: 3600 }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      const auth = new Headers(init.headers).get('authorization');
      if (auth === 'Bearer old') return new Response('expired', { status: 401 }); // force a refresh
      return new Response(JSON.stringify({ saw: auth }), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as any;

    const sink = (e: any) => leaked.push(JSON.stringify(e));
    const hA = new ConnectionHandle(provider, O, id, vaultA, new Audit(dbA), {}, new Map(), sink);
    const hB = new ConnectionHandle(provider, O, id, vaultB, new Audit(dbB), {}, new Map(), sink);
    const [ra, rb] = await Promise.all([
      hA.fetch('https://api.acme.example/a'),
      hB.fetch('https://api.acme.example/b'),
    ]);

    assert.equal(ra.status, 200);
    assert.equal(rb.status, 200);
    assert.equal(tokenCalls, 1); // cross-process lock collapsed the two refreshes into one
    assert.equal((await ra.json()).saw, 'Bearer new'); // both retried with the winner's rotated token
    assert.equal((await rb.json()).saw, 'Bearer new');
    assert.equal((await vaultA.get(O, 'acme'))?.refreshToken, 'r2'); // winner's rotation persisted
    // No event (including the new refresh_lock_wait) ever carries a secret/token.
    assert.ok(leaked.some((e) => e.includes('refresh_lock_wait')), 'lock-wait metric was emitted');
    for (const e of leaked) {
      assert.ok(!e.includes('new') && !e.includes('r1') && !e.includes('r2'), `event leaked a token: ${e}`);
    }
  } finally {
    globalThis.fetch = realFetch;
    await dbA.close();
    await dbB.close();
  }
});

test('postgres backend: DbReplayStore makes a jti single-use cluster-wide', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { DbReplayStore } = await import('../src/adapters/http/replayStore.js');
  const db = await openTestDb(t); // baseline schema includes broker_jti
  const podA = new DbReplayStore(db);
  const podB = new DbReplayStore(db); // two "replicas" sharing one Postgres table
  const exp = Date.now() + 60_000;
  assert.equal(await podA.use('pg-jti-1', exp), true);   // fresh on A
  assert.equal(await podB.use('pg-jti-1', exp), false);  // replay rejected on B (cluster-wide)
  // concurrent claim of one jti across both pods admits exactly one
  const race = await Promise.all([podA, podB, podA, podB].map((s) => s.use('pg-race', exp)));
  assert.equal(race.filter(Boolean).length, 1);
});

// #115 master-key rotation on the REAL engine: the rekey pass does keyset pagination on TEXT ids
// and a guarded UPDATE comparing BYTEA equality — both engine-specific enough that SQLite passing
// proves nothing. Same skip contract as the tests above.
test('postgres backend: rekey converges direct rows onto the primary key (BYTEA guard included)', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { rekey } = await import('../src/core/rekey.js');
  const { DbInstallationStore } = await import('../src/adapters/installationStore.js');
  const db = await openTestDb(t);
  const OLD = randomBytes(32);
  const NEW = randomBytes(32);
  const ring = {
    primary: { id: 'k2025' as string | null, key: NEW },
    byId: new Map([['k2025', NEW], ['k2019', OLD]]),
    legacy: [{ id: 'k2019' as string | null, key: OLD }, { id: 'k2025' as string | null, key: NEW }],
  };
  const newOnly = {
    primary: { id: 'k2025' as string | null, key: NEW },
    byId: new Map([['k2025', NEW]]),
    legacy: [{ id: 'k2025' as string | null, key: NEW }],
  };
  const legacyVault = new Vault(db, OLD);
  for (let i = 0; i < 5; i++) {
    await legacyVault.upsert(userOwner({ enterpriseId: null, teamId: 'TR', userId: `U${i}` }), 'p', {
      accessToken: `PG_TOK_${i}`, refreshToken: i % 2 ? `PG_REF_${i}` : null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  await new DbInstallationStore(db, OLD).storeInstallation({
    team: { id: 'TR' }, enterprise: undefined, isEnterpriseInstall: false,
    bot: { token: 'xoxb-pg-secret', scopes: [], id: 'B1', userId: 'UB' },
  } as any);

  const dry = await rekey(db, ring, { dryRun: true, batchSize: 2 }); // batch < rows → pagination runs
  assert.equal(dry.unreadable, 0);
  assert.equal(dry.reencrypted, 9); // 5 access + 2 refresh + bot_token + data
  const r = await rekey(db, ring, { batchSize: 2 });
  assert.equal(r.reencrypted, 9);
  assert.equal(r.skippedConcurrent, 0); // the BYTEA-equality guard matched every row it read
  assert.equal((await rekey(db, ring, { dryRun: true })).reencrypted, 0, 'idempotent');

  const rotated = new Vault(db, newOnly);
  for (let i = 0; i < 5; i++) {
    assert.equal((await rotated.get(userOwner({ enterpriseId: null, teamId: 'TR', userId: `U${i}` }), 'p'))?.accessToken, `PG_TOK_${i}`);
  }
  const inst = await new DbInstallationStore(db, newOnly).fetchInstallation({ teamId: 'TR', enterpriseId: undefined, isEnterpriseInstall: false });
  assert.equal(inst.bot?.token, 'xoxb-pg-secret');
});

// #111: ChannelTools.applyEnabled's atomic materialize-or-upsert statements (UNION ALL + CASTs +
// in-statement NOT EXISTS + ON CONFLICT) on the real engine — a PG-only syntax or type-inference
// mistake in that SQL surfaces here, not in the SQLite-backed unit tests.
test('postgres backend: applyEnabled materializes atomically, then upserts on the configured channel', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  const tools = new ChannelTools(db);
  await tools.applyEnabled('T_PG', 'C1', [['mcp', false]], ['mcp', 'other']);
  assert.equal(await tools.isEnabled('T_PG', 'C1', 'mcp'), false); // the targeted provider
  assert.equal(await tools.isEnabled('T_PG', 'C1', 'other'), true); // materialized, not silently disabled
  await tools.applyEnabled('T_PG', 'C1', [['mcp', true]], ['mcp', 'other']);
  assert.equal(await tools.isEnabled('T_PG', 'C1', 'mcp'), true); // configured path: plain upsert
  assert.equal(await tools.isEnabled('T_PG', 'C1', 'other'), true); // untouched
});
