import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Client, Pool } from 'pg';
import {
  migrate,
  openDb,
  assertSchemaCurrent,
  SCHEMA_VERSION,
  MIGRATABLE_SCHEMA_VERSIONS,
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
  assert.equal(await tableExists('session_request'), true);
  assert.equal(await tableExists('user_provisioning_request'), true);
  assert.equal(await tableExists('channel_provisioning_request'), true);
  assert.equal(await tableExists('channel_interaction_tombstone'), true);
  assert.equal(await tableExists('user_offboard_scope_tombstone'), true);
  assert.equal(await tableExists('provisioning_revocation_tombstone'), true);
  const raw = rawDb(t, url);
  // These indexes live in migrate(), not schema(): a fresh install must still get consent's
  // single-active-generation uniqueness, the consent retention index, and approval dedup uniqueness.
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
          origin,host,path,channel,thread,governable_channel,status,created_at,expires_at)
       VALUES
         ('00000000-0000-4000-8000-000000000099','action','T1','U1','user','U1',
          '00000000-0000-4000-8000-000000000098','acme','POST','https://api.acme.test',
          'api.acme.test','/write','C1','TH1',NULL,'pending',1,9999999999999)`,
    ),
    /null value.*governable_channel/i,
    'fresh schemas reject approval rows without an explicit governance scope',
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

// No published release ever shipped schemas v6-v11 (v0.2.0 was pre-v6; v1.0.0-beta/-beta.1 are
// v12), so migrate() refuses them with the same recreate-fresh guidance a v1-v5 marker gets.
test('migrate() refuses a pre-beta v6-v11 marker with the recreate-fresh error', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url, tableExists } = await emptySchema(t);
  const raw = rawDb(t, url);
  await raw.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  for (const version of ['6', '8', '11']) {
    await raw.run(
      `INSERT INTO meta (key, value) VALUES ('schema_version', $1)
       ON CONFLICT (key) DO UPDATE SET value=excluded.value`,
      [version],
    );
    await assert.rejects(
      () => migrate({ databaseUrl: url }),
      new RegExp(`schema version ${version} is not supported for migration.*recreate the database fresh`),
    );
    // The runtime independently fails closed on the older marker — nothing stamps or creates.
    await assert.rejects(
      () => openDb({ databaseUrl: url }),
      new RegExp(`schema version ${version}.*needs ${SCHEMA_VERSION}.*vouchr migrate`, 'i'),
    );
    assert.equal(await tableExists('connection'), false, 'a refused pre-beta marker gets no baseline tables');
  }
});

test('v12 to v13 converts every lifecycle-fence timestamp to microseconds exactly once', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  const raw = rawDb(t, url);

  // Materialize the current schema, seed one MILLISECOND-stamped row per fence table, and restore
  // the v12 marker — the exact predecessor state of the #290 cutover. Every stored PostgreSQL-clock
  // value must be multiplied by exactly 1000 exactly once: a second migrate() (previousVersion=13)
  // must NOT multiply again, or every fence would leap ~50 years into the future.
  await migrate({ databaseUrl: url });
  await raw.run(
    `INSERT INTO connection
       (id,enterprise_id,team_id,owner_kind,owner_id,provider,source,scopes,dry_run,
        generation_at,created_at,updated_at)
     VALUES ('00000000-0000-4000-8000-0000000000aa',NULL,'T1','user','U1','acme','vault','',0,777,1,1)`,
  );
  await raw.run(`INSERT INTO channel_interaction_tombstone VALUES ('T1','C1','acme',111)`);
  await raw.run(`INSERT INTO offboard_tombstone (team_id,user_id,created_at) VALUES ('T1','U1',222)`);
  await raw.run(`INSERT INTO user_offboard_scope_tombstone VALUES ('enterprise','E1','U1',333)`);
  await raw.run(
    `INSERT INTO provisioning_revocation_tombstone VALUES ('acme','global',$1,444)`,
    ['A'.repeat(43)],
  );
  const state = 'D'.repeat(43);
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at,
        consumed_at,superseded_at,delivery_lease_expires_at,delivered_at)
     VALUES ($1,NULL,'T1','U1','acme','C1','verifier',1000,NULL,2000,4000,3000)`,
    [state],
  );
  await raw.run(
    `INSERT INTO user_provisioning_request
       (id,team_id,user_id,provider,created_at,expires_at,delivery_lease_expires_at,delivered_at)
     VALUES ('00000000-0000-4000-8000-0000000000ab','T1','U1','acme',1,99,6,5)`,
  );
  await raw.run(
    `INSERT INTO channel_provisioning_request VALUES
       ('00000000-0000-4000-8000-0000000000ac','T1','C1','U1','acme',7,88)`,
  );
  await raw.run(
    `INSERT INTO session_request
       (id,team_id,channel,thread,user_id,provider,credential_id,created_at,expires_at,
        delivery_lease_expires_at,delivered_at)
     VALUES ('00000000-0000-4000-8000-0000000000ad','T1','C1','TH1','U1','acme','cred',9,10,15,16)`,
  );
  await raw.run(
    `INSERT INTO session_grant
       (team_id,channel,thread,user_id,provider,credential_id,created_at,expires_at)
     VALUES ('T1','C1','TH1','U1','acme','cred',11,12)`,
  );
  await raw.run(
    `INSERT INTO approval_request
       (id,action_key,team_id,user_id,owner_kind,owner_id,credential_id,provider,method,origin,
        host,path,channel,thread,governable_channel,status,created_at,expires_at,
        delivery_lease_expires_at,delivered_at)
     VALUES ('00000000-0000-4000-8000-0000000000ae','k1','T1','U1','user','U1','cred','acme','POST',
        'https://api.acme.test','api.acme.test','/x','C1','TH1','C1','pending',13,14,17,18)`,
  );
  // A real v12 catalog also carries the millisecond column DEFAULT, which no baseline DDL
  // rewrites, and vault writers omit generation_at and rely on it.
  await raw.exec(
    `ALTER TABLE connection ALTER COLUMN generation_at
       SET DEFAULT (extract(epoch from clock_timestamp())*1000)::bigint`,
  );
  await raw.run(`UPDATE meta SET value='12' WHERE key='schema_version'`);

  // The exact-version runtime assertion is what keeps a v12 (millisecond) binary off v13 data.
  await assert.rejects(
    () => openDb({ databaseUrl: url }),
    new RegExp(`schema version 12.*needs ${SCHEMA_VERSION}.*vouchr migrate`, 'i'),
  );

  const converted = async () => ({
    generation: (await raw.get<{ generation_at: number }>(
      `SELECT generation_at FROM connection WHERE id='00000000-0000-4000-8000-0000000000aa'`,
    ))!.generation_at,
    appClock: await raw.get<{ created_at: number; updated_at: number }>(
      `SELECT created_at, updated_at FROM connection WHERE id='00000000-0000-4000-8000-0000000000aa'`,
    ),
    channelTomb: (await raw.get<{ created_at: number }>(
      `SELECT created_at FROM channel_interaction_tombstone WHERE team_id='T1'`,
    ))!.created_at,
    offboard: (await raw.get<{ created_at: number }>(
      `SELECT created_at FROM offboard_tombstone WHERE team_id='T1'`,
    ))!.created_at,
    scopeTomb: (await raw.get<{ created_at: number }>(
      `SELECT created_at FROM user_offboard_scope_tombstone WHERE user_id='U1'`,
    ))!.created_at,
    revocation: (await raw.get<{ created_at: number }>(
      `SELECT created_at FROM provisioning_revocation_tombstone WHERE provider='acme'`,
    ))!.created_at,
    consent: await raw.get<Record<string, number>>(
      `SELECT created_at, consumed_at, superseded_at, delivered_at, delivery_lease_expires_at
         FROM consent_request WHERE state=$1`,
      [state],
    ),
    userProv: await raw.get<Record<string, number>>(
      `SELECT created_at, expires_at, delivered_at, delivery_lease_expires_at
         FROM user_provisioning_request WHERE team_id='T1'`,
    ),
    channelProv: await raw.get<Record<string, number>>(
      `SELECT created_at, expires_at FROM channel_provisioning_request WHERE team_id='T1'`,
    ),
    sessionReq: await raw.get<Record<string, number>>(
      `SELECT created_at, expires_at, delivered_at, delivery_lease_expires_at
         FROM session_request WHERE team_id='T1'`,
    ),
    sessionGrant: await raw.get<Record<string, number>>(
      `SELECT created_at, expires_at FROM session_grant WHERE team_id='T1'`,
    ),
    approval: await raw.get<Record<string, number>>(
      `SELECT created_at, expires_at, delivered_at, delivery_lease_expires_at
         FROM approval_request WHERE team_id='T1'`,
    ),
  });

  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  const after = await converted();
  assert.equal(after.generation, 777_000);
  // The migration must also reset the stale v12 millisecond DEFAULT: a post-cutover credential
  // write that omits generation_at (as every vault writer does) must stamp microseconds, or the
  // newest-generation fences never block (fail-open).
  await raw.run(
    `INSERT INTO connection
       (id,enterprise_id,team_id,owner_kind,owner_id,provider,source,scopes,dry_run,
        created_at,updated_at)
     VALUES ('00000000-0000-4000-8000-0000000000af',NULL,'T1','user','U2','acme','vault','',0,1,1)`,
  );
  const defaulted = (await raw.get<{ generation_at: number }>(
    `SELECT generation_at FROM connection WHERE id='00000000-0000-4000-8000-0000000000af'`,
  ))!.generation_at;
  assert.ok(
    defaulted > 1.5e15,
    `post-migration generation_at DEFAULT must stamp microseconds, got ${defaulted}`,
  );
  assert.deepEqual(
    after.appClock,
    { created_at: 1, updated_at: 1 },
    'application-clock connection columns stay epoch-ms — only the PostgreSQL-clock fence converts',
  );
  assert.equal(after.channelTomb, 111_000);
  assert.equal(after.offboard, 222_000);
  assert.equal(after.scopeTomb, 333_000);
  assert.equal(after.revocation, 444_000);
  assert.deepEqual(after.consent, {
    created_at: 1_000_000, consumed_at: null, superseded_at: 2_000_000,
    delivered_at: 3_000_000, delivery_lease_expires_at: 4_000_000,
  });
  assert.deepEqual(after.userProv, {
    created_at: 1_000, expires_at: 99_000, delivered_at: 5_000, delivery_lease_expires_at: 6_000,
  });
  assert.deepEqual(after.channelProv, { created_at: 7_000, expires_at: 88_000 });
  assert.deepEqual(after.sessionReq, {
    created_at: 9_000, expires_at: 10_000, delivered_at: 16_000, delivery_lease_expires_at: 15_000,
  });
  assert.deepEqual(after.sessionGrant, { created_at: 11_000, expires_at: 12_000 });
  assert.deepEqual(after.approval, {
    created_at: 13_000, expires_at: 14_000, delivered_at: 18_000, delivery_lease_expires_at: 17_000,
  });

  // The conversion is gated on the recorded predecessor version: re-running the migration at v13
  // must not multiply anything again.
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.deepEqual(await converted(), after, 'a second migrate() must not convert again');
});

test('v13 to v14 adds the browser-verification columns and leaves converted µs fences untouched (#302)', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  const raw = rawDb(t, url);

  // Materialize head, then recreate the exact v13 predecessor: the #290 µs conversion already ran
  // (values are microseconds), but the #302 columns do not exist yet.
  await migrate({ databaseUrl: url });
  await raw.exec(`ALTER TABLE consent_request DROP COLUMN slack_verified_at`);
  await raw.exec(`ALTER TABLE consent_request DROP COLUMN slack_verify_required`);
  const microsCreated = 1_722_000_000_000_000; // an already-converted µs fence stamp
  const state = 'E'.repeat(43);
  await raw.run(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at)
     VALUES ($1,NULL,'T1','U1','acme','C1','verifier',$2)`,
    [state, microsCreated],
  );
  await raw.run(`INSERT INTO offboard_tombstone (team_id,user_id,created_at) VALUES ('T1','U1',$1)`, [microsCreated]);
  await raw.run(`UPDATE meta SET value='13' WHERE key='schema_version'`);

  // A v14 binary refuses to run on v13 data until migrate converges it.
  await assert.rejects(
    () => openDb({ databaseUrl: url }),
    new RegExp(`schema version 13.*needs ${SCHEMA_VERSION}.*vouchr migrate`, 'i'),
  );

  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  const row = await raw.get<Record<string, unknown>>(
    `SELECT created_at, slack_verified_at, slack_verify_required FROM consent_request WHERE state=$1`,
    [state],
  );
  // The columns arrived; the pre-existing row is unverified and NOT required (its prompt URL never
  // offered the hop), and — critically — the v13 ×1000 conversion did NOT run again on µs data.
  assert.deepEqual(row, {
    created_at: microsCreated,
    slack_verified_at: null,
    slack_verify_required: 0,
  });
  const tomb = await raw.get<{ created_at: number }>(
    `SELECT created_at FROM offboard_tombstone WHERE team_id='T1'`,
  );
  assert.equal(tomb!.created_at, microsCreated, 'a converted µs fence must survive v13→v14 unchanged');

  // Idempotent at head: a second migrate() changes nothing.
  assert.equal((await migrate({ databaseUrl: url })).version, SCHEMA_VERSION);
  assert.deepEqual(
    await raw.get(`SELECT created_at, slack_verified_at, slack_verify_required FROM consent_request WHERE state=$1`, [state]),
    row,
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

// Finding 5: a REAL failed migration must roll back EVERY mutation — the ×1000 fence conversion
// and the version stamp run inside migrate()'s one transaction. A CHECK pins meta.value to '12' so
// the FINAL stamp fails, i.e. the failure lands AFTER the data conversion — the strongest rollback
// proof: a half-committed ×1000 would corrupt every lifecycle fence.
test('a failed v12 migration rolls back the µs conversion and the stamp together', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const { url } = await emptySchema(t);
  const raw = rawDb(t, url);
  await migrate({ databaseUrl: url });
  await raw.run(`INSERT INTO offboard_tombstone (team_id,user_id,created_at) VALUES ('T1','U1',222)`);
  await raw.run(`UPDATE meta SET value='12' WHERE key='schema_version'`);
  await raw.exec(`ALTER TABLE meta ADD CONSTRAINT meta_pin CHECK (value = '12')`);

  await assert.rejects(() => migrate({ databaseUrl: url }), /violates check constraint|check constraint/i);

  assert.equal((await raw.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`))?.value, '12');
  assert.equal(
    (await raw.get<{ created_at: number }>(`SELECT created_at FROM offboard_tombstone WHERE team_id='T1'`))?.created_at,
    222,
    'the ×1000 fence conversion rolled back with the failed stamp',
  );
});

// Finding 1: unsupported lineages fail closed rather than being stamped over an unknown shape.
test('migrate() refuses an unsupported lineage: a v1–v5 marker, and a markerless legacy schema', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);

  // A v3 marker (1–5 are unsupported: migrate only knows fresh / v12–v14).
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

// Guardrail (#304 review): the deployment guide must never claim a migration starting point the
// code refuses. The guide carries one machine-readable marker; this pins it to the runtime set.
test('DEPLOYMENT.md documents exactly the migratable schema versions', () => {
  const guide = readFileSync('guides/DEPLOYMENT.md', 'utf8');
  const markers = [...guide.matchAll(/<!-- migratable-schema-versions: ([0-9,\s]+) -->/g)];
  assert.equal(markers.length, 1, 'guides/DEPLOYMENT.md must carry exactly one migratable-schema-versions marker');
  const documented = markers[0][1]
    .split(',')
    .map((v) => Number(v.trim()))
    .sort((a, b) => a - b);
  const supported = [...MIGRATABLE_SCHEMA_VERSIONS].sort((a, b) => a - b);
  assert.deepEqual(documented, supported, 'the guide and MIGRATABLE_SCHEMA_VERSIONS must agree');
});
