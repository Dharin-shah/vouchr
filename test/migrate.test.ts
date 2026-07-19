import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { Client, Pool } from 'pg';
import { migrate, openDb, assertSchemaCurrent, SCHEMA_VERSION, type Db } from '../src/core/db';
import { isPostgresUrl } from '../src/core/options';
import { github } from '../src/core/providers';
import { createVouchr } from '../src/adapters/bolt';
import { Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';
import { SECRET_REFERENCE_SOURCES } from '../src/core/reference';
import { TEST_PG_URL, pgReachable, openTestDb } from './support/pg';
import { Approvals } from '../src/core/approval';

const SKIP = 'Postgres not reachable (run `npm run pg:up`)';

// Real-PostgreSQL migration tests (#204). openDb no longer runs DDL — `migrate()` owns the schema and
// `openDb()` fails closed on an un-migrated database. These exercise that split against a REAL Postgres
// in a throwaway schema each. Gated on pgReachable(): if PG is down the test SKIPS; but once PG is
// reachable, any failure is a REAL failure (no catch-and-skip of arbitrary errors).

/** A fresh, EMPTY (un-migrated) schema pinned via search_path. The test drives migrate()/openDb()
 *  against it itself. Schema + admin connection are dropped/closed via t.after. */
async function emptySchema(t: TestContext): Promise<{
  url: string;
  schema: string;
  tableExists: (name: string) => Promise<boolean>;
}> {
  const schema = `mig_${randomBytes(6).toString('hex')}`;
  const admin = new Client(TEST_PG_URL);
  await admin.connect();
  await admin.query(`CREATE SCHEMA "${schema}"`);
  t.after(async () => {
    await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
    await admin.end().catch(() => undefined);
  });
  const url = new URL(TEST_PG_URL);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const tableExists = async (name: string) => {
    const r = await admin.query('SELECT to_regclass($1) AS reg', [`${schema}.${name}`]);
    return r.rows[0].reg !== null;
  };
  return { url: url.toString(), schema, tableExists };
}

/** A minimal Db over a single-connection pool, WITHOUT the openDb schema-version check — so we can
 *  point assertSchemaCurrent at an un-migrated schema (openDb itself would refuse to hand one back). */
function rawDb(t: TestContext, url: string): Db {
  const pool = new Pool({ connectionString: url, max: 1 });
  t.after(() => pool.end().catch(() => undefined));
  return {
    get: async (sql: string, params: any[] = []) => (await pool.query(sql, params)).rows[0],
    all: async (sql: string, params: any[] = []) => (await pool.query(sql, params)).rows,
    run: async (sql: string, params: any[] = []) => ({ changes: (await pool.query(sql, params)).rowCount ?? 0 }),
    exec: async (sql: string) => { await pool.query(sql); },
    close: async () => { await pool.end(); },
  };
}

test('migrate() creates the tables and stamps SCHEMA_VERSION on a fresh schema, and is idempotent', async (t) => {
  if (!(await pgReachable())) return t.skip('Postgres not reachable (run `npm run pg:up`)');
  const { url, tableExists } = await emptySchema(t);

  assert.equal(await tableExists('connection'), false, 'precondition: schema starts empty');

  const first = await migrate({ databaseUrl: url });
  assert.equal(first.version, SCHEMA_VERSION);
  assert.equal(await tableExists('connection'), true, 'migrate must create the baseline tables');
  assert.equal(await tableExists('audit'), true);
  assert.equal(await tableExists('broker_jti'), true);
  assert.equal(await tableExists('session_request'), true);
  assert.equal(await tableExists('user_provisioning_request'), true);
  assert.equal(await tableExists('channel_provisioning_request'), true);
  assert.equal(await tableExists('channel_interaction_tombstone'), true);
  assert.equal(await tableExists('user_offboard_scope_tombstone'), true);
  assert.equal(await tableExists('provisioning_revocation_tombstone'), true);
  assert.equal(await tableExists('channel_preview'), false, 'fresh schemas must not recreate the removed preview store');

  // A second migrate on the same schema must be a no-op (idempotent), not error, same version.
  const second = await migrate({ databaseUrl: url });
  assert.equal(second.version, SCHEMA_VERSION);
});

test('openDb() on an un-migrated schema fails closed and creates NO tables', async (t) => {
  if (!(await pgReachable())) return t.skip('Postgres not reachable (run `npm run pg:up`)');
  const { url, tableExists } = await emptySchema(t);

  await assert.rejects(
    () => openDb({ databaseUrl: url }),
    /has not been initialized|vouchr migrate/,
    'openDb must refuse an un-migrated database with a clear "run vouchr migrate" error',
  );
  // Fail-closed means it MUST NOT have created anything (openDb runs no DDL).
  assert.equal(await tableExists('connection'), false);
  assert.equal(await tableExists('meta'), false);
});

test('openDb() succeeds after migrate()', async (t) => {
  if (!(await pgReachable())) return t.skip('Postgres not reachable (run `npm run pg:up`)');
  const { url } = await emptySchema(t);
  await migrate({ databaseUrl: url });
  const db = await openDb({ databaseUrl: url });
  t.after(() => db.close());
  // A trivial query proves the handle is live against the migrated schema.
  assert.equal((await db.all('SELECT COUNT(*)::int AS n FROM connection'))[0].n, 0);
});

test('current runtime refuses a v8 schema until the drained migration runs', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  const raw = rawDb(t, url);
  await raw.exec('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
  await raw.run(`INSERT INTO meta (key, value) VALUES ('schema_version', '8')`);

  await assert.rejects(
    () => openDb({ databaseUrl: url }),
    new RegExp(`schema version 8.*needs ${SCHEMA_VERSION}.*vouchr migrate`, 'i'),
    'the current runtime must not start against v8 while old replicas are being drained',
  );
});

test('current migration invalidates prerelease-v9 consent and preserves current lifecycle rows', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, tableExists } = await emptySchema(t);
  const raw = rawDb(t, url);
  // Materialize the complete predecessor shape, then remove the v10 relations and restore the v9
  // marker. This catches migrations that work on a synthetic marker-only DB but not a real v9.
  await migrate({ databaseUrl: url });
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at)
     VALUES
       ('pre-v10-state',NULL,'T1','U1','acme','C1','verifier',1)`,
  );
  await raw.run(
    `INSERT INTO offboard_tombstone (team_id,user_id,created_at) VALUES ('T1','U1',123)`,
  );
  await raw.exec('DROP TABLE user_provisioning_request');
  await raw.exec('DROP TABLE channel_provisioning_request');
  await raw.exec('DROP TABLE channel_interaction_tombstone');
  await raw.exec('DROP TABLE user_offboard_scope_tombstone');
  await raw.exec('DROP TABLE provisioning_revocation_tombstone');
  await raw.run(`UPDATE meta SET value='9' WHERE key='schema_version'`);

  await assert.rejects(
    () => openDb({ databaseUrl: url }),
    new RegExp(`schema version 9.*needs ${SCHEMA_VERSION}.*vouchr migrate`, 'i'),
  );
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.equal(await tableExists('user_provisioning_request'), true);
  assert.equal(await tableExists('channel_provisioning_request'), true);
  assert.equal(await tableExists('channel_interaction_tombstone'), true);
  assert.equal(await tableExists('user_offboard_scope_tombstone'), true);
  assert.equal(await tableExists('provisioning_revocation_tombstone'), true);
  const unique = await raw.get<{ indexdef: string }>(
    `SELECT indexdef FROM pg_indexes
     WHERE schemaname=current_schema() AND indexname='uq_user_provisioning_owner_provider'`,
  );
  assert.match(unique?.indexdef ?? '', /UNIQUE.*\(team_id, user_id, provider\)/i);
  const channelUnique = await raw.get<{ indexdef: string }>(
    `SELECT indexdef FROM pg_indexes
     WHERE schemaname=current_schema() AND indexname='uq_channel_provisioning_actor_target'`,
  );
  assert.match(
    channelUnique?.indexdef ?? '',
    /UNIQUE.*\(team_id, channel, user_id, provider\)/i,
  );
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM consent_request WHERE state='pre-v10-state'`))?.n,
    0,
    'a v9 state cannot prove that no artifact-free enterprise offboard happened before v10',
  );
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM offboard_tombstone WHERE team_id='T1' AND user_id='U1'`))?.n,
    1,
    'a PostgreSQL-clock v9 team tombstone remains a useful lifecycle fence',
  );
  await raw.run(
    `INSERT INTO user_provisioning_request
       (id,team_id,user_id,provider,created_at,expires_at) VALUES
       ('00000000-0000-4000-8000-000000000001','T1','U1','acme',1,9999999999999)`,
  );
  await raw.run(
    `INSERT INTO channel_provisioning_request VALUES
       ('00000000-0000-4000-8000-000000000002','T1','C1','U1','acme',1,9999999999999)`,
  );
  await raw.run(
    `INSERT INTO channel_interaction_tombstone VALUES ('T1','C1','acme',1)`,
  );
  await raw.run(
    `INSERT INTO user_offboard_scope_tombstone VALUES ('enterprise','E1','U1',1)`,
  );
  await raw.run(
    `INSERT INTO provisioning_revocation_tombstone VALUES ('acme','global',$1,1)`,
    ['A'.repeat(43)],
  );
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at)
     VALUES
       ('current-state',NULL,'T1','U1','acme','C1','verifier',1)`,
  );
  await assert.rejects(
    raw.run(`INSERT INTO user_offboard_scope_tombstone VALUES ('enterprise','','U2',1)`),
    /check constraint/i,
  );
  await assert.rejects(
    raw.run(`INSERT INTO user_offboard_scope_tombstone VALUES ('global','E1','U2',1)`),
    /check constraint/i,
  );
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM user_provisioning_request`))?.n,
    1,
  );
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM channel_provisioning_request`))?.n,
    1,
  );
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM channel_interaction_tombstone`))?.n,
    1,
  );
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM user_offboard_scope_tombstone`))?.n,
    1,
  );
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone`))?.n,
    1,
  );
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM consent_request WHERE state='current-state'`))?.n,
    1,
    'an idempotent current migration must preserve current-version consent',
  );
});

test('v10 to v12 drains pre-v11 consent authority and installs the single-generation lifecycle schema', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  const raw = rawDb(t, url);

  // Start from the complete current schema, then faithfully remove the v11-only consent lifecycle
  // surface and restore the v10 marker. This exercises the production carry without maintaining a
  // second hand-written copy of every unrelated v10 table.
  await migrate({ databaseUrl: url });
  await raw.exec(`DROP INDEX uq_consent_request_active`);
  await raw.exec(`DROP INDEX idx_consent_request_created_at`);
  await raw.exec(`ALTER TABLE consent_request
    DROP COLUMN consumed_at,
    DROP COLUMN superseded_at,
    DROP COLUMN delivery_token,
    DROP COLUMN delivery_lease_expires_at,
    DROP COLUMN delivered_at`);
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at)
     VALUES ($1,NULL,'T1','U1','acme','C1','verifier',1)`,
    ['A'.repeat(43)],
  );
  await raw.run(`UPDATE meta SET value='10' WHERE key='schema_version'`);

  await assert.rejects(
    () => openDb({ databaseUrl: url }),
    new RegExp(`schema version 10.*needs ${SCHEMA_VERSION}.*vouchr migrate`, 'i'),
  );
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.equal(
    (await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM consent_request`))?.n,
    0,
    'v10 consent cannot prove the v11 single-generation and delivery lifecycle invariants',
  );
  assert.equal(
    (await raw.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`))?.value,
    String(SCHEMA_VERSION),
  );

  const columns = await raw.all<{ column_name: string; is_nullable: string; column_default: string | null }>(
    `SELECT column_name,is_nullable,column_default
       FROM information_schema.columns
      WHERE table_schema=current_schema()
        AND table_name='consent_request'
        AND column_name IN
          ('consumed_at','superseded_at','delivery_token','delivery_lease_expires_at','delivered_at')
      ORDER BY column_name`,
  );
  assert.deepEqual(columns.map((column) => column.column_name), [
    'consumed_at',
    'delivered_at',
    'delivery_lease_expires_at',
    'delivery_token',
    'superseded_at',
  ]);
  const deliveryLease = columns.find((column) => column.column_name === 'delivery_lease_expires_at');
  assert.equal(deliveryLease?.is_nullable, 'NO');
  assert.match(deliveryLease?.column_default ?? '', /0/);
  const activeIndex = await raw.get<{ indexdef: string }>(
    `SELECT indexdef FROM pg_indexes
      WHERE schemaname=current_schema() AND indexname='uq_consent_request_active'`,
  );
  assert.match(
    activeIndex?.indexdef ?? '',
    /UNIQUE.*\(team_id, user_id, provider\).*WHERE \(superseded_at IS NULL\)/i,
  );
  const retentionIndex = await raw.get<{ indexdef: string }>(
    `SELECT indexdef FROM pg_indexes
      WHERE schemaname=current_schema() AND indexname='idx_consent_request_created_at'`,
  );
  assert.match(retentionIndex?.indexdef ?? '', /\(created_at\)/i);

  const currentState = 'B'.repeat(43);
  const deliveryToken = 'C'.repeat(43);
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at,
        delivery_token,delivery_lease_expires_at,delivered_at)
     VALUES ($1,NULL,'T1','U1','acme','C1','verifier',2,$2,3,4)`,
    [currentState, deliveryToken],
  );
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.deepEqual(
    await raw.get<{
      state: string;
      delivery_token: string;
      delivery_lease_expires_at: number;
      delivered_at: number;
    }>(
      `SELECT state,delivery_token,delivery_lease_expires_at,delivered_at
         FROM consent_request WHERE state=$1`,
      [currentState],
    ),
    {
      state: currentState,
      delivery_token: deliveryToken,
      delivery_lease_expires_at: 3,
      delivered_at: 4,
    },
    'an idempotent v11 migration preserves v11-minted consent lifecycle state',
  );
});

test('v11 to v12 installs key-prompt leases and invalidates global approval delivery', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  const raw = rawDb(t, url);
  await migrate({ databaseUrl: url });

  // Reconstruct the complete v11 predecessor shape from the current schema. A v11 approval could
  // say only "delivered somewhere", so preserve its pending action but clear that unsafe marker.
  await raw.exec(`ALTER TABLE user_provisioning_request
    DROP COLUMN delivery_token,
    DROP COLUMN delivery_lease_expires_at,
    DROP COLUMN delivered_at`);
  await raw.exec(`ALTER TABLE approval_request DROP COLUMN delivery_audience`);
  await raw.run(
    `INSERT INTO user_provisioning_request
       (id,team_id,user_id,provider,created_at,expires_at)
     VALUES ('00000000-0000-4000-8000-000000000021','T1','U1','acme',1,9999999999999)`,
  );
  await raw.run(
    `INSERT INTO approval_request
       (id,action_key,team_id,user_id,owner_kind,owner_id,credential_id,provider,method,
        origin,host,path,query_hash,channel,thread,status,approved_by,created_at,expires_at,
        delivery_token,delivery_lease_expires_at,delivered_at)
     VALUES
       ('00000000-0000-4000-8000-000000000022','action','T1','U1','user','U1',
        '00000000-0000-4000-8000-000000000023','acme','POST','https://api.acme.test',
        'api.acme.test','/repos','','C1','TH1','pending',NULL,1,9999999999999,
        '00000000-0000-4000-8000-000000000024',9999999999999,2)`,
  );
  const v11ConsentState = 'D'.repeat(43);
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at)
     VALUES ($1,NULL,'T1','U1','acme','C1','verifier',1)`,
    [v11ConsentState],
  );
  await raw.run(`UPDATE meta SET value='11' WHERE key='schema_version'`);

  await assert.rejects(
    () => openDb({ databaseUrl: url }),
    new RegExp(`schema version 11.*needs ${SCHEMA_VERSION}.*vouchr migrate`, 'i'),
  );
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.deepEqual(
    await raw.get(
      `SELECT delivery_token,delivery_lease_expires_at,delivered_at
         FROM user_provisioning_request
        WHERE id='00000000-0000-4000-8000-000000000021'`,
    ),
    { delivery_token: null, delivery_lease_expires_at: 0, delivered_at: null },
  );
  assert.deepEqual(
    await raw.get(
      `SELECT delivery_token,delivery_lease_expires_at,delivered_at,delivery_audience
         FROM approval_request
        WHERE id='00000000-0000-4000-8000-000000000022'`,
    ),
    {
      delivery_token: null,
      delivery_lease_expires_at: 0,
      delivered_at: null,
      delivery_audience: null,
    },
    'the exact pending action survives, but its unbound v11 delivery cannot suppress v12 recipients',
  );
  assert.equal(
    (await raw.get<{ state: string }>(`SELECT state FROM consent_request WHERE state=$1`, [v11ConsentState]))?.state,
    v11ConsentState,
    'v11 consent already proves the single-generation delivery contract and survives v12',
  );

  await raw.run(
    `UPDATE user_provisioning_request
        SET delivery_token='00000000-0000-4000-8000-000000000025',
            delivery_lease_expires_at=3, delivered_at=4`,
  );
  await raw.run(
    `UPDATE approval_request
        SET delivery_token='00000000-0000-4000-8000-000000000026',
            delivery_lease_expires_at=5, delivered_at=6, delivery_audience=$1`,
    ['a'.repeat(64)],
  );
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.deepEqual(
    await raw.get(
      `SELECT delivery_token,delivery_lease_expires_at,delivered_at
         FROM user_provisioning_request
        WHERE id='00000000-0000-4000-8000-000000000021'`,
    ),
    {
      delivery_token: '00000000-0000-4000-8000-000000000025',
      delivery_lease_expires_at: 3,
      delivered_at: 4,
    },
    'an idempotent v12 migration preserves current key-prompt delivery state',
  );
  assert.equal(
    (await raw.get<{ delivery_audience: string }>(
      `SELECT delivery_audience FROM approval_request
        WHERE id='00000000-0000-4000-8000-000000000022'`,
    ))?.delivery_audience,
    'a'.repeat(64),
    'an idempotent v12 migration preserves audience-bound approval delivery',
  );
});

test('v10 stamps legacy connections with a PostgreSQL credential-generation boundary', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  const raw = rawDb(t, url);
  await migrate({ databaseUrl: url });
  // Recreate the prerelease-v9 connection shape: those rows predate the trusted generation clock
  // used to fence provider-addressed disconnects. The drained migration must conservatively stamp
  // every existing row instead of leaving it addressable by an older delayed assertion/command.
  await raw.exec(`ALTER TABLE connection DROP COLUMN generation_at`);
  await raw.run(
    `INSERT INTO connection
       (id,enterprise_id,team_id,owner_kind,owner_id,provider,source,scopes,dry_run,created_at,updated_at)
     VALUES ('00000000-0000-4000-8000-000000000001',NULL,'T1','user','U1','acme','vault','',0,1,1)`,
  );
  await raw.run(`UPDATE meta SET value='9' WHERE key='schema_version'`);

  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  const migrated = await raw.get<{ generation_at: number }>(
    `SELECT generation_at FROM connection WHERE id='00000000-0000-4000-8000-000000000001'`,
  );
  assert.ok(Number.isSafeInteger(migrated?.generation_at));
  assert.ok((migrated?.generation_at ?? 0) > 0);

  // An idempotent rerun must preserve the row's original boundary, not make an already-valid
  // interaction stale merely because an operator safely repeated `vouchr migrate`.
  const boundary = migrated!.generation_at;
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.equal(
    (await raw.get<{ generation_at: number }>(
      `SELECT generation_at FROM connection WHERE id='00000000-0000-4000-8000-000000000001'`,
    ))?.generation_at,
    boundary,
  );
});

test('CLI top-level failures never serialize database-provided error text (SEC-1)', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  const raw = rawDb(t, url);
  const secret = 'ghp_DATABASE_ERROR_MUST_NOT_REACH_OUTPUT';
  await raw.exec('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
  await raw.run('INSERT INTO meta (key, value) VALUES ($1, $2)', ['schema_version', secret]);

  const result = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'bin/vouchr.ts', 'inventory', '--db', url],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /^vouchr: command failed\s*$/);
  assert.doesNotMatch(result.stderr + result.stdout, new RegExp(secret));
});

test('CLI inventory never selects or prints legacy source/reference values (SEC-1)', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  await migrate({ databaseUrl: url });
  const db = await openDb({ databaseUrl: url });
  const sentinel = 'ghp_LEGACY_REFERENCE_MUST_NOT_REACH_INVENTORY';
  const sourceSentinel = 'ghp_LEGACY_SOURCE_MUST_NOT_REACH_INVENTORY';
  try {
    const vault = new Vault(db, randomBytes(32));
    await vault.reference(
      userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }),
      'legacy',
      { source: sourceSentinel, secretRef: sentinel },
    );
    for (const [index, source] of SECRET_REFERENCE_SOURCES.entries()) {
      await vault.reference(
        userOwner({ enterpriseId: null, teamId: 'T1', userId: `U${index + 2}` }),
        `legacy-${index}`,
        { source, secretRef: `legacy-ref-${index}` },
      );
    }
  } finally {
    await db.close();
  }

  const result = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'bin/vouchr.ts', 'inventory'],
    { encoding: 'utf8', env: { ...process.env, VOUCHR_DATABASE_URL: url } },
  );
  assert.equal(result.status, 0);
  assert.match(result.stdout, /reference/);
  assert.match(result.stdout, /yes/);
  assert.match(result.stdout, /custom/);
  for (const source of SECRET_REFERENCE_SOURCES) assert.match(result.stdout, new RegExp(source));
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(sentinel));
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(sourceSentinel));
});

test('two migrate() calls racing on the same schema both succeed (advisory lock serializes, no pg_type 23505)', async (t) => {
  if (!(await pgReachable())) return t.skip('Postgres not reachable (run `npm run pg:up`)');
  const { url, tableExists } = await emptySchema(t);

  // Without the xact advisory lock, concurrent CREATE TABLE races the internal pg_type row → 23505.
  const [a, b] = await Promise.all([migrate({ databaseUrl: url }), migrate({ databaseUrl: url })]);
  assert.equal(a.version, SCHEMA_VERSION);
  assert.equal(b.version, SCHEMA_VERSION);
  assert.equal(await tableExists('connection'), true);
});

test('readiness: assertSchemaCurrent throws on an un-migrated schema and resolves on a migrated one', async (t) => {
  if (!(await pgReachable())) return t.skip('Postgres not reachable (run `npm run pg:up`)');
  const { url } = await emptySchema(t);

  await assert.rejects(
    () => assertSchemaCurrent(rawDb(t, url)),
    /has not been initialized|vouchr migrate/,
    'an un-migrated schema must read as NOT ready',
  );

  await migrate({ databaseUrl: url });
  const db = await openDb({ databaseUrl: url });
  t.after(() => db.close());
  await assertSchemaCurrent(db); // resolves — ready
});

// ── #196/#204 review findings ─────────────────────────────────────────────────

// Finding 1: the lineage stays monotonic, and migrate() carries a pre-#204 v6 database to head —
// dropping union_optin and converting stored `union` modes.
test('migrate() carries a legacy v6 database to head: accepts it, drops union_optin, converts union→per-user', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, tableExists } = await emptySchema(t);
  const raw = rawDb(t, url);
  // A minimal pre-#204 v6 shape: the union_optin table migrate must drop, a channel_config row in the
  // removed 'union' mode, and the v6 marker (which a reset-to-1 would have wrongly refused as "newer").
  await raw.exec(`CREATE TABLE channel_config (team_id TEXT, channel TEXT, provider TEXT, mode TEXT, PRIMARY KEY(team_id,channel,provider))`);
  await raw.exec(`CREATE TABLE union_optin (team_id TEXT, channel_id TEXT, user_id TEXT, provider TEXT)`);
  await raw.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  await raw.run(`INSERT INTO channel_config (team_id, channel, provider, mode) VALUES ('T1','C1','github','union')`);
  await raw.run(`INSERT INTO meta (key, value) VALUES ('schema_version','6')`);

  const { version } = await migrate({ databaseUrl: url }); // must NOT refuse the v6 DB as "newer"
  assert.equal(version, SCHEMA_VERSION);
  assert.ok(SCHEMA_VERSION > 6, 'lineage must be monotonic past the pre-#204 max of 6');
  assert.equal(await tableExists('union_optin'), false, 'union_optin must be dropped');
  const row = await raw.get<{ mode: string }>(`SELECT mode FROM channel_config WHERE team_id='T1' AND channel='C1' AND provider='github'`);
  assert.equal(row?.mode, 'per-user', 'a stored union mode must convert to per-user');
});

test('migrate() carries v7 to head and deletes the retired preview configuration table', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, tableExists } = await emptySchema(t);
  const raw = rawDb(t, url);
  await raw.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  await raw.exec(`CREATE TABLE channel_preview (
    team_id TEXT NOT NULL, channel TEXT NOT NULL, provider TEXT NOT NULL, visibility TEXT NOT NULL,
    PRIMARY KEY(team_id, channel, provider)
  )`);
  await raw.run(`INSERT INTO channel_preview VALUES ('T1','C1','mcp','private')`);
  await raw.run(`INSERT INTO meta (key, value) VALUES ('schema_version','7')`);

  const { version } = await migrate({ databaseUrl: url });
  assert.equal(version, SCHEMA_VERSION);
  assert.equal(await tableExists('channel_preview'), false);
  assert.equal((await raw.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`))?.value, String(SCHEMA_VERSION));
});

test('migrate() carries v8 to head: clears unbound interaction authority and is idempotent', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, tableExists } = await emptySchema(t);
  const raw = rawDb(t, url);
  await raw.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  await raw.exec(`CREATE TABLE approval_request (
    id TEXT PRIMARY KEY, team_id TEXT NOT NULL, user_id TEXT NOT NULL,
    owner_kind TEXT NOT NULL, owner_id TEXT NOT NULL, provider TEXT NOT NULL,
    method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL, query_hash TEXT NOT NULL,
    channel TEXT NOT NULL, thread TEXT NOT NULL, status TEXT NOT NULL, approved_by TEXT,
    created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL
  )`);
  await raw.exec(`CREATE TABLE session_grant (
    team_id TEXT NOT NULL, channel TEXT NOT NULL, thread TEXT NOT NULL,
    user_id TEXT NOT NULL, provider TEXT NOT NULL, created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (team_id, channel, thread, user_id, provider)
  )`);
  await raw.exec(`CREATE TABLE consent_request (
    state TEXT PRIMARY KEY, enterprise_id TEXT, team_id TEXT NOT NULL, user_id TEXT NOT NULL,
    provider TEXT NOT NULL, channel TEXT, pkce_verifier TEXT NOT NULL, created_at BIGINT NOT NULL
  )`);
  await raw.exec(`CREATE TABLE offboard_tombstone (
    team_id TEXT NOT NULL, user_id TEXT NOT NULL, created_at BIGINT NOT NULL,
    PRIMARY KEY(team_id,user_id)
  )`);
  await raw.run(`INSERT INTO meta (key, value) VALUES ('schema_version', '8')`);
  const values = ['T1', 'U1', 'user', 'U1', 'acme', 'POST', 'api.acme.test', '/pay', 'digest', 'C1', 'TH1'];
  await raw.run(
    `INSERT INTO approval_request VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',NULL,1,9999999999999)`,
    ['a', ...values],
  );
  await raw.run(
    `INSERT INTO approval_request VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',NULL,2,9999999999999)`,
    ['b', ...values],
  );
  const longPath = `/${'long/'.repeat(800)}write`;
  await raw.run(
    `INSERT INTO approval_request VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',NULL,3,9999999999999)`,
    ['c', ...values.slice(0, 7), longPath, ...values.slice(8)],
  );
  await raw.run(`INSERT INTO session_grant VALUES ('T1','C1','TH1','U1','acme',1,9999999999999)`);
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at)
     VALUES ('future-state',NULL,'T1','U1','acme','C1','verifier',9999999999999)`,
  );
  await raw.run(`INSERT INTO offboard_tombstone VALUES ('T1','U1',9999999999999)`);

  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.equal(await tableExists('session_request'), true);
  assert.equal((await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM approval_request`))?.n, 0);
  assert.equal((await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM session_grant`))?.n, 0);
  assert.equal((await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM consent_request`))?.n, 0);
  assert.equal((await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM offboard_tombstone`))?.n, 0);
  const index = await raw.get<{ indexdef: string }>(
    `SELECT indexdef FROM pg_indexes
     WHERE schemaname=current_schema() AND indexname='uq_approval_request_action'`,
  );
  assert.match(index?.indexdef ?? '', /\(action_key\)$/);
  assert.doesNotMatch(index?.indexdef ?? '', /path/);
  const originColumn = await raw.get<{ is_nullable: string }>(
    `SELECT is_nullable FROM information_schema.columns
     WHERE table_schema=current_schema() AND table_name='approval_request' AND column_name='origin'`,
  );
  assert.equal(originColumn?.is_nullable, 'NO');
  const runtime = await openDb({ databaseUrl: url });
  const currentApprovalId = await new Approvals(runtime).request({
    teamId: 'T1', userId: 'U1', ownerKind: 'user', ownerId: 'U1',
    credentialId: '00000000-0000-4000-8000-000000000001', provider: 'acme', method: 'POST',
    origin: 'https://api.acme.test', host: 'api.acme.test', path: '/pay', queryHash: '',
    channel: 'C1', thread: 'TH1',
  });
  await runtime.close();
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at)
     VALUES ('current-state',NULL,'T1','U1','acme','C1','verifier',1)`,
  );
  await raw.run(`INSERT INTO offboard_tombstone VALUES ('T1','U1',1)`);
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.equal((await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM approval_request`))?.n, 1);
  assert.equal(
    (await raw.get<{ origin: string }>(`SELECT origin FROM approval_request WHERE id=$1`, [currentApprovalId]))?.origin,
    'https://api.acme.test',
  );
  assert.equal((await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM consent_request`))?.n, 1);
  assert.equal((await raw.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM offboard_tombstone`))?.n, 1);
});

// Finding 2: only explicit databaseUrl / VOUCHR_DATABASE_URL is honored — no generic DATABASE_URL
// fallback — and a hostless/malformed URL is refused (pg would otherwise resolve ambient defaults).
test('connection selection: DATABASE_URL is refused, and a hostless/malformed URL is rejected', async () => {
  assert.equal(isPostgresUrl('postgres://'), false, 'hostless postgres:// must be rejected');
  assert.equal(isPostgresUrl('postgres:///vouchr'), false, 'socket-style (no host) must be rejected');
  assert.equal(isPostgresUrl('postgres://host'), false, 'no database name → pg uses PGDATABASE; rejected');
  assert.equal(isPostgresUrl('postgres://host/'), false, 'empty database path → rejected');
  assert.equal(isPostgresUrl('postgres://h/db'), true);
  assert.equal(isPostgresUrl('postgresql://u:p@h:5432/db?sslmode=require'), true);
  assert.equal(isPostgresUrl('http://h/db'), false);
  assert.equal(isPostgresUrl('not a url'), false);

  const savedV = process.env.VOUCHR_DATABASE_URL;
  const savedD = process.env.DATABASE_URL;
  delete process.env.VOUCHR_DATABASE_URL;
  process.env.DATABASE_URL = 'postgres://vouchr:vouchr@localhost:5433/vouchr'; // a valid PG URL, wrong var
  try {
    await assert.rejects(() => openDb(), /PostgreSQL connection string is required/, 'openDb must NOT fall back to DATABASE_URL');
    await assert.rejects(() => migrate(), /PostgreSQL connection string is required/, 'migrate must NOT fall back to DATABASE_URL');
  } finally {
    if (savedV === undefined) delete process.env.VOUCHR_DATABASE_URL; else process.env.VOUCHR_DATABASE_URL = savedV;
    if (savedD === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = savedD;
  }
});

// Finding 4: shutdown is idempotent, and an INJECTED db is the caller's — createVouchr's close()
// never ends a pool it didn't open.
test('shutdown: double close() is idempotent (owned), and an injected db is left open', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');
  const prov = () => github({ clientId: 'x', clientSecret: 'y' });

  // Raw handle: a second close() must resolve, not reject (pg-pool rejects a second end()).
  const { url } = await emptySchema(t);
  await migrate({ databaseUrl: url });
  const raw = await openDb({ databaseUrl: url });
  await raw.close();
  await raw.close(); // idempotent

  // Owned pool: createVouchr opened it → close() ends it, twice is safe.
  const { url: url2 } = await emptySchema(t);
  await migrate({ databaseUrl: url2 });
  const owned = await createVouchr({ providers: [prov()], baseUrl: 'https://x.test', databaseUrl: url2 });
  await owned.close();
  await owned.close(); // idempotent

  // Injected pool: the caller owns it → close() must be a no-op, the db stays live.
  const db = await openTestDb(t); // t.after closes this one
  const injected = await createVouchr({ providers: [prov()], baseUrl: 'https://x.test', db });
  await injected.close();
  assert.equal((await db.all('SELECT 1 AS x'))[0].x, 1, 'an injected db must survive createVouchr close()');
});

// Finding 6: the privilege split is real — a DML-only role runs the runtime (openDb + queries) but
// CANNOT create tables; and the migration transaction is all-or-nothing (a throw rolls back its DDL).
test('privilege split: a DML-only role runs the runtime but is denied CREATE', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, schema } = await emptySchema(t);
  await migrate({ databaseUrl: url }); // as the owner (superuser test role)
  const admin = new Client(TEST_PG_URL);
  await admin.connect();
  const role = `dml_${randomBytes(4).toString('hex')}`;
  t.after(async () => {
    await admin.query(`DROP OWNED BY "${role}"`).catch(() => undefined);
    await admin.query(`DROP ROLE IF EXISTS "${role}"`).catch(() => undefined);
    await admin.end().catch(() => undefined);
  });
  await admin.query(`CREATE ROLE "${role}" LOGIN PASSWORD 'x'`);
  await admin.query(`GRANT USAGE ON SCHEMA "${schema}" TO "${role}"`);
  await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "${schema}" TO "${role}"`);

  const roleUrl = new URL(TEST_PG_URL);
  roleUrl.username = role;
  roleUrl.password = 'x';
  roleUrl.searchParams.set('options', `-c search_path=${schema}`);
  const db = await openDb({ databaseUrl: roleUrl.toString() }); // openDb succeeds with no DDL grant
  t.after(() => db.close());
  assert.equal((await db.all('SELECT COUNT(*)::int AS n FROM connection'))[0].n, 0); // DML works
  const lifecycleRows = [
    {
      table: 'user_provisioning_request',
      insert: `INSERT INTO user_provisioning_request
        (id,team_id,user_id,provider,created_at,expires_at) VALUES (?,?,?,?,?,?)`,
      params: ['00000000-0000-4000-8000-000000000011', 'T1', 'U1', 'acme', 1, 2],
    },
    {
      table: 'channel_provisioning_request',
      insert: `INSERT INTO channel_provisioning_request VALUES (?,?,?,?,?,?,?)`,
      params: ['00000000-0000-4000-8000-000000000012', 'T1', 'C1', 'U1', 'acme', 1, 2],
    },
    {
      table: 'channel_interaction_tombstone',
      insert: `INSERT INTO channel_interaction_tombstone VALUES (?,?,?,?)`,
      params: ['T1', 'C1', 'acme', 1],
    },
    {
      table: 'user_offboard_scope_tombstone',
      insert: `INSERT INTO user_offboard_scope_tombstone VALUES (?,?,?,?)`,
      params: ['global', '', 'U1', 1],
    },
    {
      table: 'provisioning_revocation_tombstone',
      insert: `INSERT INTO provisioning_revocation_tombstone VALUES (?,?,?,?)`,
      params: ['acme', 'global', 'A'.repeat(43), 1],
    },
  ] as const;
  for (const row of lifecycleRows) {
    await db.run(row.insert, [...row.params]);
    assert.equal((await db.all(`SELECT COUNT(*)::int AS n FROM ${row.table}`))[0].n, 1);
    await db.run(`DELETE FROM ${row.table}`);
    assert.equal((await db.all(`SELECT COUNT(*)::int AS n FROM ${row.table}`))[0].n, 0);
  }
  await assert.rejects(() => db.exec('CREATE TABLE evil (x int)'), /permission denied|insufficient/i); // no DDL
});

// Finding 5: a REAL failed migration must roll back EVERY mutation — the drops, the mode
// conversion, and the version stamp all run inside migrate()'s one transaction. Here union_optin is
// a real TABLE (so the DROP succeeds) and a CHECK on meta.value forces the FINAL stamp to fail, so
// the failure lands AFTER the drop + conversion — the strongest rollback proof.
test('a failed v6 migration rolls back both drops, conversion, and stamp together', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, tableExists } = await emptySchema(t);
  const raw = rawDb(t, url);
  await raw.exec(`CREATE TABLE channel_config (team_id TEXT, channel TEXT, provider TEXT, mode TEXT, PRIMARY KEY(team_id,channel,provider))`);
  await raw.exec(`CREATE TABLE union_optin (team_id TEXT, channel_id TEXT, user_id TEXT, provider TEXT)`); // a REAL table — DROP will succeed
  await raw.exec(`CREATE TABLE channel_preview (team_id TEXT, channel TEXT, provider TEXT, visibility TEXT)`);
  await raw.run(`INSERT INTO channel_preview VALUES ('T1','C1','github','private')`);
  // CHECK pins value to '6', so migrate()'s final stamp violates it — the deterministic failure.
  await raw.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL CHECK (value = '6'))`);
  await raw.run(`INSERT INTO channel_config (team_id, channel, provider, mode) VALUES ('T1','C1','github','union')`);
  await raw.run(`INSERT INTO meta (key, value) VALUES ('schema_version','6')`);

  await assert.rejects(() => migrate({ databaseUrl: url }), /violates check constraint|check constraint/i);

  // The stamp failed LAST, so a correct migrate rolls back the earlier drop + conversion too: the
  // union_optin table is back, the union mode is unchanged, the marker is still 6, and none of the
  // baseline tables migrate would have created were committed.
  assert.equal((await raw.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`))?.value, '6');
  assert.equal((await raw.get<{ mode: string }>(`SELECT mode FROM channel_config WHERE team_id='T1'`))?.mode, 'union', 'the union→per-user conversion rolled back');
  assert.equal(await tableExists('union_optin'), true, 'the dropped union_optin table was restored by rollback');
  assert.equal(await tableExists('channel_preview'), true, 'the dropped channel_preview table was restored by rollback');
  assert.equal((await raw.get<{ visibility: string }>(`SELECT visibility FROM channel_preview`))?.visibility, 'private');
  assert.equal(await tableExists('session_grant'), false, 'no baseline table migrate would create was committed');
});

// Finding 1: unsupported lineages fail closed rather than being stamped v7 over an unknown shape.
test('migrate() refuses an unsupported lineage: a v1–v5 marker, and a markerless legacy schema', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);

  // A v3 marker (1–5 are unsupported: migrate only knows fresh / v6 / v7).
  const a = await emptySchema(t);
  const rawA = rawDb(t, a.url);
  await rawA.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  await rawA.run(`INSERT INTO meta (key, value) VALUES ('schema_version','3')`);
  await assert.rejects(() => migrate({ databaseUrl: a.url }), /schema version 3 is not supported/);
  assert.equal(await a.tableExists('connection'), false, 'a rejected lineage gets no baseline tables');

  // A markerless legacy schema whose only relation is NON-`connection` (channel_config) must ALSO be
  // refused — "fresh" means genuinely empty, not merely "no connection table".
  const b = await emptySchema(t);
  const rawB = rawDb(t, b.url);
  await rawB.exec(`CREATE TABLE channel_config (team_id TEXT, channel TEXT, provider TEXT, mode TEXT)`);
  await assert.rejects(() => migrate({ databaseUrl: b.url }), /unrecognized database|no schema-version marker/i);
  assert.equal(await b.tableExists('connection'), false, 'the rejected markerless schema got no baseline tables');
});
