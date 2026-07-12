import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { Audit } from '../src/core/audit';
import { openDb, type Db } from '../src/core/db';
import { openTestDb, testDbUrl, pgReachable } from './support/pg';

// #208: audit read paths must use their index (not a seq scan) at volume — including the COMPLETE
// prune DELETE, not just its inner select — and retention prune must be bounded, restartable, and
// safe to confirm. Real Postgres only (the plans + CLI state are the point); gated on pgReachable(),
// and once reachable a failure is a REAL failure, never a skip.

const SKIP = 'Postgres not reachable (run `npm run pg:up`)';
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
// The exact DELETE the prune loop issues — asserted at the plan level so a regression to a
// full-table-scan form (e.g. `id IN (SELECT …)`) fails here.
const PRUNE_DELETE =
  'DELETE FROM audit WHERE id = ANY(ARRAY(SELECT id FROM audit WHERE at < ? ORDER BY at LIMIT ? FOR UPDATE SKIP LOCKED))';

/** Bulk-insert `n` rows spread across teams/users/channels/providers/time in ONE statement. */
async function seed(db: Db, n: number, now: number): Promise<void> {
  await db.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text,
            'T' || (g % 50), 'U' || (g % 500),
            (ARRAY['github','gitlab','notion'])[1 + (g % 3)],
            'inject', NULL, 'C' || (g % 100), '{}',
            ${now} - (g * 1000)
     FROM generate_series(1, ${n}) g`,
  );
}

/** Stringified JSON query plan (EXPLAIN, plan-only — never executes) for a parameterized query. */
async function plan(db: Db, sql: string, params: any[]): Promise<string> {
  const rows = await db.all<Record<string, unknown>>(`EXPLAIN (FORMAT JSON) ${sql}`, params);
  return JSON.stringify(rows[0]['QUERY PLAN']);
}
const seqScans = (planJson: string) => /"Node Type":"Seq Scan"/.test(planJson);

test('audit plans: owner / channel / stats / config / the whole prune DELETE ride an index, not a seq scan', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  const now = Date.now();
  await seed(db, 200_000, now); // a scale where the old `id IN (SELECT …)` DELETE would seq-scan
  // A handful of rare 'config' rows for one (team, channel, provider) — the partial index target.
  await db.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text,'T1','U_ADMIN','github','config',NULL,'C1','{}', ${now} - (g*1000) FROM generate_series(1,20) g`,
  );
  await db.exec(`ANALYZE audit`);

  const ownerP = await plan(db,
    `SELECT provider, action, actor, channel, at FROM audit WHERE team_id = ? AND user_id = ? ORDER BY at DESC LIMIT ?`,
    ['T1', 'U1', 20]);
  assert.match(ownerP, /idx_audit_team_user_at/, `owner history plan=${ownerP}`);
  assert.equal(seqScans(ownerP), false, 'owner history must not seq-scan');

  const channelP = await plan(db,
    `SELECT provider, action, actor, channel, at FROM audit WHERE team_id = ? AND channel = ? ORDER BY at DESC LIMIT ?`,
    ['T1', 'C1', 20]);
  assert.match(channelP, /idx_audit_team_channel_at/, `channel history plan=${channelP}`);
  assert.equal(seqScans(channelP), false, 'channel history must not seq-scan');

  const statsP = await plan(db,
    `SELECT provider, COUNT(*) AS uses, COUNT(DISTINCT COALESCE(actor, user_id)) AS distinct_actors, MAX(at) AS last_used
       FROM audit WHERE team_id = ? AND channel = ? AND action = 'inject' AND at >= ? GROUP BY provider`,
    ['T1', 'C1', now - DAY]);
  assert.match(statsP, /idx_audit_team_channel_at/, `stats plan=${statsP}`);

  // lastChannelConfigActor: the rare-config lookup must ride the PARTIAL index, not scan the channel.
  const cfgP = await plan(db,
    `SELECT user_id FROM audit WHERE team_id=? AND channel=? AND provider=? AND action='config' ORDER BY at DESC LIMIT 1`,
    ['T1', 'C1', 'github']);
  assert.match(cfgP, /idx_audit_config/, `config lookup plan=${cfgP}`);
  assert.equal(seqScans(cfgP), false, 'config lookup must not seq-scan');

  // The COMPLETE prune DELETE (not just its inner select) must ride idx_audit_at and NOT seq-scan —
  // the plain `id IN (SELECT …)` form plans as a seq-scan semi-join, which this catches.
  const cutoff = now - 6 * HOUR; // matches ~28k of the 50k seeded rows
  const deleteP = await plan(db, PRUNE_DELETE, [cutoff, 10_000]);
  assert.match(deleteP, /idx_audit_at/, `prune DELETE must use idx_audit_at; plan=${deleteP}`);
  assert.equal(seqScans(deleteP), false, `prune DELETE must NOT seq-scan audit; plan=${deleteP}`);
});

test('pruneOlderThan: bounded batches delete old rows, keep recent, and is idempotent', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  const audit = new Audit(db);
  const now = Date.now();
  const cutoff = now - 30 * DAY;
  await db.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text, 'T1','U1','github','inject',NULL,'C1','{}', ${cutoff} - (g*1000) FROM generate_series(1,250) g`,
  );
  await db.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text, 'T1','U1','github','inject',NULL,'C1','{}', ${now} - (g*1000) FROM generate_series(1,40) g`,
  );

  assert.equal(await audit.countOlderThan(cutoff), 250);
  const deleted = await audit.pruneOlderThan(cutoff, 100); // 100,100,50
  assert.equal(deleted, 250);
  assert.equal(await audit.countOlderThan(cutoff), 0);
  assert.equal(Number((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit`))?.n), 40, 'recent rows survive');
  assert.equal(await audit.pruneOlderThan(cutoff, 100), 0, 'idempotent re-run deletes nothing');
});

test('prune is restartable: a committed batch survives an "interruption" and a re-run converges', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  const audit = new Audit(db);
  const now = Date.now();
  const cutoff = now - 30 * DAY;
  await db.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text, 'T1','U1','github','inject',NULL,'C1','{}', ${cutoff} - (g*1000) FROM generate_series(1,250) g`,
  );
  // Simulate a crash after ONE committed batch: issue a single prune DELETE (its own tx), then stop.
  const one = await db.run(PRUNE_DELETE, [cutoff, 100]);
  assert.equal(one.changes, 100);
  assert.equal(await audit.countOlderThan(cutoff), 150, 'the committed batch is durable across the "interruption"');
  // Re-running converges — no lost progress, no double-work error.
  assert.equal(await audit.pruneOlderThan(cutoff, 100), 150);
  assert.equal(await audit.countOlderThan(cutoff), 0);
});

test('pruneOlderThan rejects a non-positive batch', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const db = await openTestDb(t);
  await assert.rejects(() => new Audit(db).pruneOlderThan(Date.now(), 0), /positive integer/);
});

test('prune CLI: only a bare --yes deletes; valued/conflicting forms are rejected (real CLI + DB state)', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const url = await testDbUrl(t); // a fresh migrated schema
  const db = await openDb({ databaseUrl: url });
  t.after(() => db.close());
  const old = Date.now() - 2 * DAY;
  const seed5 = async () => {
    await db.exec(`TRUNCATE audit`);
    await db.exec(
      `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
       SELECT gen_random_uuid()::text,'T1','U1','github','inject',NULL,'C1','{}', ${old} - (g*1000) FROM generate_series(1,5) g`,
    );
  };
  const run = (...extra: string[]) =>
    spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'prune', '--older-than-days', '1', '--db', url, ...extra], { encoding: 'utf8' });
  const count = async () => Number((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit`))?.n);

  await seed5();
  let r = run('--yes=false'); // valued --yes → rejected
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /takes no value/);
  assert.equal(await count(), 5, '--yes=false must delete nothing');

  await seed5();
  r = run('--yes', 'no'); // 'no' consumed as --yes's value → rejected
  assert.notEqual(r.status, 0);
  assert.equal(await count(), 5, '--yes no must delete nothing');

  await seed5();
  r = run('--dry-run', '--yes'); // conflicting → rejected
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /mutually exclusive/);
  assert.equal(await count(), 5, '--dry-run --yes must delete nothing');

  await seed5();
  r = run(); // no --yes → dry-run
  assert.equal(r.status, 0);
  assert.match(r.stdout, /DRY-RUN: 5/);
  assert.equal(await count(), 5, 'a dry-run must delete nothing');

  await seed5();
  r = run('--yes'); // bare --yes → deletes
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Pruned 5/);
  assert.equal(await count(), 0, 'a bare --yes deletes');
});
