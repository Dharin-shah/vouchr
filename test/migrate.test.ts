import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Client, Pool } from 'pg';
import { migrate, openDb, assertSchemaCurrent, SCHEMA_VERSION, type Db } from '../src/core/db';
import { isPostgresUrl } from '../src/core/options';
import { github } from '../src/core/providers';
import { createVouchr } from '../src/adapters/bolt';
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

// Finding 1: the lineage stays monotonic (baseline 7, not a reset to 1), and migrate() carries a
// pre-#204 v6 database to head — dropping union_optin and converting stored `union` modes.
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
  await assert.rejects(() => db.exec('CREATE TABLE evil (x int)'), /permission denied|insufficient/i); // no DDL
});

// Finding 5: a REAL failed v6→7 migration must roll back entirely — the cleanup (drop union_optin,
// convert modes, stamp) is INSIDE the transaction, so a failure leaves the v6 database untouched.
test('a failed v6→7 migration rolls back entirely: v6 marker, union_optin, and the union mode all survive', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, tableExists } = await emptySchema(t);
  const raw = rawDb(t, url);
  await raw.exec(`CREATE TABLE channel_config (team_id TEXT, channel TEXT, provider TEXT, mode TEXT, PRIMARY KEY(team_id,channel,provider))`);
  // union_optin as a VIEW, not a table: migrate()'s `DROP TABLE IF EXISTS union_optin` then errors
  // ("not a table") mid-transaction — a deterministic failure AFTER the baseline DDL + BEFORE stamp.
  await raw.exec(`CREATE VIEW union_optin AS SELECT 1 AS x`);
  await raw.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  await raw.run(`INSERT INTO channel_config (team_id, channel, provider, mode) VALUES ('T1','C1','github','union')`);
  await raw.run(`INSERT INTO meta (key, value) VALUES ('schema_version','6')`);

  await assert.rejects(() => migrate({ databaseUrl: url }), /is not a table|union_optin/i);

  // Nothing partially applied: marker still 6, union mode unchanged, union_optin still present, and
  // NONE of the baseline tables migrate() would have created were committed.
  assert.equal((await raw.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`))?.value, '6');
  assert.equal((await raw.get<{ mode: string }>(`SELECT mode FROM channel_config WHERE team_id='T1'`))?.mode, 'union');
  assert.equal(await tableExists('union_optin'), true, 'the union_optin object survives the rollback');
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

  // A markerless legacy schema (vouchr tables present, no version marker) is also refused.
  const b = await emptySchema(t);
  const rawB = rawDb(t, b.url);
  await rawB.exec(`CREATE TABLE connection (id TEXT PRIMARY KEY)`);
  await assert.rejects(() => migrate({ databaseUrl: b.url }), /unrecognized database|no schema-version marker/i);
});
