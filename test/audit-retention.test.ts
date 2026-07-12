import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { Audit } from '../src/core/audit';
import { openTestDb, pgReachable } from './support/pg';
import type { Db } from '../src/core/db';

// #208: audit read paths must use their composite index (not a seq scan) at volume, and retention
// prune must be bounded/restartable/idempotent. Real Postgres only (the plans are the point) — gated
// on pgReachable(); a reachable-PG failure is a REAL failure, never a skip.

const SKIP = 'Postgres not reachable (run `npm run pg:up`)';
const HOUR = 3_600_000;

/** Bulk-insert `n` rows spread across teams/users/channels/providers/time in ONE statement. */
async function seed(db: Db, n: number, now: number): Promise<void> {
  await db.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text,
            'T' || (g % 50), 'U' || (g % 500),
            (ARRAY['github','gitlab','notion'])[1 + (g % 3)],
            CASE WHEN g % 4 = 0 THEN 'config' ELSE 'inject' END,
            NULL, 'C' || (g % 100), '{}',
            ${now} - (g * 1000)
     FROM generate_series(1, ${n}) g`,
  );
  await db.exec(`ANALYZE audit`); // fresh stats so the planner sees the real distribution
}

/** Stringified JSON query plan (EXPLAIN, plan-only) for a parameterized query. */
async function plan(db: Db, sql: string, params: any[]): Promise<string> {
  const rows = await db.all<Record<string, unknown>>(`EXPLAIN (FORMAT JSON) ${sql}`, params);
  return JSON.stringify(rows[0]['QUERY PLAN']);
}

test('audit index plans: owner / channel / stats / prune queries ride their index, not a seq scan', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  const now = Date.now();
  await seed(db, 50_000, now);

  // listByOwnerUser → idx_audit_team_user_at
  const ownerP = await plan(
    db,
    `SELECT provider, action, actor, channel, at FROM audit WHERE team_id = ? AND user_id = ? ORDER BY at DESC LIMIT ?`,
    ['T1', 'U1', 20],
  );
  assert.match(ownerP, /idx_audit_team_user_at/, `owner history must use idx_audit_team_user_at; plan=${ownerP}`);
  assert.doesNotMatch(ownerP, /Seq Scan/, 'owner history must not seq-scan');

  // listByChannel → idx_audit_team_channel_at
  const channelP = await plan(
    db,
    `SELECT provider, action, actor, channel, at FROM audit WHERE team_id = ? AND channel = ? ORDER BY at DESC LIMIT ?`,
    ['T1', 'C1', 20],
  );
  assert.match(channelP, /idx_audit_team_channel_at/, `channel history must use idx_audit_team_channel_at; plan=${channelP}`);
  assert.doesNotMatch(channelP, /Seq Scan/, 'channel history must not seq-scan');

  // statsByChannel → idx_audit_team_channel_at (team+channel+at range; action is a residual filter)
  const statsP = await plan(
    db,
    `SELECT provider, COUNT(*) AS uses, COUNT(DISTINCT COALESCE(actor, user_id)) AS distinct_actors, MAX(at) AS last_used
       FROM audit WHERE team_id = ? AND channel = ? AND action = 'inject' AND at >= ? GROUP BY provider`,
    ['T1', 'C1', now - 24 * HOUR],
  );
  assert.match(statsP, /idx_audit_team_channel_at/, `stats must use idx_audit_team_channel_at; plan=${statsP}`);

  // retention scan → idx_audit_at (the global at<cutoff ORDER BY at LIMIT batch)
  const pruneP = await plan(db, `SELECT id FROM audit WHERE at < ? ORDER BY at LIMIT ?`, [now - 7 * 24 * HOUR, 10_000]);
  assert.match(pruneP, /idx_audit_at/, `retention scan must use idx_audit_at; plan=${pruneP}`);
});

test('pruneOlderThan: bounded batches delete old rows, keep recent, and is idempotent', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  const audit = new Audit(db);
  const now = Date.now();
  const cutoff = now - 30 * 24 * HOUR;

  // 250 rows OLDER than the cutoff + 40 recent rows.
  await db.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text, 'T1','U1','github','inject',NULL,'C1','{}', ${cutoff} - (g*1000) FROM generate_series(1,250) g`,
  );
  await db.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text, 'T1','U1','github','inject',NULL,'C1','{}', ${now} - (g*1000) FROM generate_series(1,40) g`,
  );

  assert.equal(await audit.countOlderThan(cutoff), 250);

  // batch 100 → three bounded statements (100, 100, 50), each its own tx.
  const deleted = await audit.pruneOlderThan(cutoff, 100);
  assert.equal(deleted, 250);
  assert.equal(await audit.countOlderThan(cutoff), 0);

  // The recent rows survive untouched.
  const remaining = await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit`);
  assert.equal(Number(remaining?.n), 40);

  // Idempotent / restartable: a re-run finds nothing to delete.
  assert.equal(await audit.pruneOlderThan(cutoff, 100), 0);
});

test('pruneOlderThan rejects a non-positive batch', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  await assert.rejects(() => new Audit(db).pruneOlderThan(Date.now(), 0), /positive integer/);
});
