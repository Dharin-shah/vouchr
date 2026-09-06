import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { Client, Pool } from 'pg';
import {
  migrate,
  openDb,
  assertSchemaCurrent,
  SCHEMA_VERSION,
  type Db,
} from '../src/core/db';
import { isPostgresUrl } from '../src/core/options';
import { github } from '../src/core/providers';
import { createVouchr } from '../src/adapters/bolt';
import { Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';
import { SECRET_REFERENCE_SOURCES } from '../src/core/reference';
import { TEST_PG_URL, pgReachable, openTestDb } from './support/pg';

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
  assert.equal(await tableExists('session_request'), false, 'the session tables are gone (#350)');
  assert.equal(await tableExists('session_grant'), false);
  assert.equal(await tableExists('user_provisioning_request'), true);
  assert.equal(await tableExists('channel_provisioning_request'), true);
  assert.equal(await tableExists('channel_interaction_tombstone'), true);
  assert.equal(await tableExists('user_offboard_scope_tombstone'), true);
  assert.equal(await tableExists('provisioning_revocation_tombstone'), true);
  const raw = rawDb(t, url);
  // The one DDL carries consent's single-active-generation uniqueness, the consent retention index,
  // and approval dedup uniqueness — the runtime depends on all three.
  const indexdef = async (name: string) =>
    (await raw.get<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1`,
      [name],
    ))?.indexdef ?? '';
  assert.match(
    await indexdef('uq_consent_request_active'),
    /UNIQUE.*\(team_id, user_id, provider\).*WHERE \(superseded_at IS NULL\)/i,
  );
  assert.match(await indexdef('idx_consent_request_created_at'), /\(created_at\)/i);
  assert.match(await indexdef('uq_approval_request_action'), /UNIQUE.*\(action_key\)$/i);
  const governanceColumn = await raw.get<{ is_nullable: string }>(
    `SELECT is_nullable FROM information_schema.columns
      WHERE table_schema=current_schema()
        AND table_name='approval_request'
        AND column_name='governable_channel'`,
  );
  assert.equal(governanceColumn?.is_nullable, 'NO');
  await assert.rejects(
    () => raw.run(
      `INSERT INTO approval_request
         (id,action_key,team_id,user_id,owner_kind,owner_id,credential_id,provider,method,
          origin,host,path,grant_scope,channel,thread,governable_channel,status,created_at,expires_at)
       VALUES
         ('00000000-0000-4000-8000-000000000099','action','T1','U1','user','U1',
          '00000000-0000-4000-8000-000000000098','acme','POST','https://api.acme.test',
          'api.acme.test','/write','once','C1','TH1',NULL,'pending',1,9999999999999)`,
    ),
    /null value.*governable_channel/i,
    'fresh schemas reject approval rows without an explicit governance scope',
  );
  await assert.rejects(
    () => raw.run(
      `INSERT INTO approval_request
         (id,action_key,team_id,user_id,owner_kind,owner_id,credential_id,provider,method,
          origin,host,path,grant_scope,channel,thread,status,created_at,expires_at)
       VALUES
         ('00000000-0000-4000-8000-000000000097','action','T1','U1','user','U1',
          '00000000-0000-4000-8000-000000000096','acme','POST','https://api.acme.test',
          'api.acme.test','/write','once','C1','TH1','pending',1,9999999999999)`,
    ),
    /null value.*governable_channel/i,
    'fresh schemas reject approval writers that omit the governance classification',
  );
  // #350: the grant scope and the channel identity are closed sets at the schema, not just in code.
  await assert.rejects(
    () => raw.run(
      `INSERT INTO approval_request
         (id,action_key,team_id,user_id,owner_kind,owner_id,credential_id,provider,method,
          origin,host,path,grant_scope,channel,thread,governable_channel,status,created_at,expires_at)
       VALUES
         ('00000000-0000-4000-8000-000000000095','action','T1','U1','user','U1',
          '00000000-0000-4000-8000-000000000094','acme','POST','https://api.acme.test',
          'api.acme.test','/write','forever','C1','TH1','C1','pending',1,9999999999999)`,
    ),
    /grant_scope/i,
  );
  await assert.rejects(
    () => raw.run(`INSERT INTO channel_config (team_id, channel, provider, identity) VALUES ('T1','C1','acme','session')`),
    /identity/i,
  );

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

// One schema version (#340): every other recorded marker — the deleted 1.0.0 ladder (v12-v15), an
// older development stamp, or a version newer than this build — gets the same recreate-fresh
// refusal from migrate(), and the runtime independently refuses to open the database.
test('migrate() and openDb() refuse any recorded schema version other than the current one', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, tableExists } = await emptySchema(t);
  const raw = rawDb(t, url);
  await raw.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  for (const version of ['0', '1', '15', String(SCHEMA_VERSION + 1)]) {
    await raw.run(
      `INSERT INTO meta (key, value) VALUES ('schema_version', $1)
       ON CONFLICT (key) DO UPDATE SET value=excluded.value`,
      [version],
    );
    await assert.rejects(
      () => migrate({ databaseUrl: url }),
      new RegExp(`schema version ${version} is not supported for migration.*recreate the database fresh`),
    );
    // The exact-version boot check keeps a mismatched binary off the data — nothing stamps or creates.
    await assert.rejects(
      () => openDb({ databaseUrl: url }),
      new RegExp(`schema version ${version}, but this build needs ${SCHEMA_VERSION}.*vouchr migrate`, 'i'),
    );
    assert.equal(await tableExists('connection'), false, 'a refused marker gets no tables');
  }
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
  assert.match(result.stderr, /^vouchr: command failed\. Run `vouchr doctor` to diagnose\.\s*$/);
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

// Finding 1: an unknown shape fails closed rather than being stamped over.
test('migrate() refuses a markerless legacy schema', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  // A markerless schema whose only relation is NON-`connection` (channel_config) must be refused —
  // "fresh" means genuinely empty, not merely "no connection table".
  const b = await emptySchema(t);
  const rawB = rawDb(t, b.url);
  await rawB.exec(`CREATE TABLE channel_config (team_id TEXT, channel TEXT, provider TEXT, mode TEXT)`);
  await assert.rejects(() => migrate({ databaseUrl: b.url }), /unrecognized database|no schema-version marker/i);
  assert.equal(await b.tableExists('connection'), false, 'the rejected markerless schema got no baseline tables');
});
