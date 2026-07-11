import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Client, Pool } from 'pg';
import { migrate, openDb, assertSchemaCurrent, SCHEMA_VERSION, type Db } from '../src/core/db';
import { TEST_PG_URL, pgReachable } from './support/pg';

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
