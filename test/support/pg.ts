import { randomBytes } from 'node:crypto';
import type { TestContext } from 'node:test';
import { Client } from 'pg';
import { migrate, openDb, type Db } from '../../src/core/db';

// Many test files run in parallel, each opening isolated-schema pools; keep each pool tiny so their
// combined connections stay well under a single Postgres's ceiling. Set before any openDb runs.
process.env.VOUCHR_PG_POOL_MAX ??= '2';

// The one Postgres the suite runs against (a throwaway `postgres:16` — `npm run pg:up`, or the CI
// service). Vouchr is PostgreSQL-only (#204), so there is no in-memory SQLite substitute; instead
// each test gets an ISOLATED, uniquely-named schema in this shared database, migrated to the real
// production shape. Ownership is explicit: every fixture registers a `t.after` that closes its pool
// and drops its schema, so nothing leaks connections across the parallel suite (the old harness
// leaked a pool per unclosed handle → `53300 too many clients`).
export const TEST_PG_URL = process.env.VOUCHR_TEST_PG_URL ?? 'postgres://vouchr:vouchr@localhost:5433/vouchr';

/** True if the test Postgres is reachable. Retries a few times: under the parallel suite a momentary
 *  connection-pressure blip (a burst of pools near the server ceiling) must NOT be misread as "no PG".
 *  Full npm test/coverage set VOUCHR_REQUIRE_POSTGRES=1, so any later outage THROWS instead of turning
 *  individual files into false-green skips. Directly-invoked focused tests retain the convenient
 *  boolean/skip behavior. A genuinely-down PG still fails fast (~5 attempts ≈ 1s). */
export async function pgReachable(): Promise<boolean> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const c = new Client(TEST_PG_URL);
    try {
      await c.connect();
      await c.end();
      return true;
    } catch {
      await c.end().catch(() => undefined);
      if (attempt < 4) await new Promise((r) => setTimeout(r, 200)); // let a transient burst drain
    }
  }
  if (process.env.VOUCHR_REQUIRE_POSTGRES === '1') {
    throw new Error('required test PostgreSQL is unreachable; run npm run pg:up or set VOUCHR_TEST_PG_URL');
  }
  return false;
}

/** Create a fresh uniquely-named schema, run the real migration into it, and return the URL pinned
 *  to it (via `search_path`) plus a `drop()` that removes it. Internal — callers use the fixtures. */
async function freshSchema(): Promise<{ url: string; drop: () => Promise<void> }> {
  const schema = `t_${randomBytes(8).toString('hex')}`;
  const admin = new Client(TEST_PG_URL);
  await admin.connect();
  try {
    await admin.query(`CREATE SCHEMA IF NOT EXISTS "${schema}"`);
  } finally {
    await admin.end();
  }
  const url = new URL(TEST_PG_URL);
  url.searchParams.set('options', `-c search_path=${schema}`); // every pooled connection pins here
  const target = url.toString();
  await migrate({ databaseUrl: target }); // create the schema's tables (openDb runs no DDL now)
  const drop = async () => {
    const c = new Client(TEST_PG_URL);
    await c.connect();
    try {
      await c.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    } finally {
      await c.end();
    }
  };
  return { url: target, drop };
}

/**
 * A migrated, isolated schema URL for one test. Use when the test opens its OWN db/pool(s) or passes
 * the URL to `createVouchr`/`buildBrokerServer`. The schema is dropped after the test via `t.after`;
 * the test still owns closing any pool it opens from the URL (or inject the Db from `openTestDb`).
 * Reopening the SAME URL reuses the SAME schema, so persistence tests keep working.
 */
export async function testDbUrl(t: TestContext): Promise<string> {
  const { url, drop } = await freshSchema();
  t.after(drop);
  return url;
}

/**
 * Open the real store in a fresh isolated schema for one test — full isolation, real migration path.
 * The pool is closed and the schema dropped automatically when the test ends (`t.after`), so callers
 * never leak connections. Inject the returned Db into `createVouchr({ db })` / `createBroker({ db })`
 * so the whole test shares ONE owned pool.
 */
export async function openTestDb(t: TestContext): Promise<Db> {
  const { url, drop } = await freshSchema();
  const db = await openDb({ databaseUrl: url });
  t.after(async () => {
    await db.close().catch(() => undefined);
    await drop().catch(() => undefined);
  });
  return db;
}
