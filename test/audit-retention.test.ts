import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { Audit, MAX_AUDIT_PRUNE_BATCH, PRUNE_BATCH_SQL } from '../src/core/audit';
import { openDb, type Db } from '../src/core/db';
import { openTestDb, testDbUrl, pgReachable } from './support/pg';

// #208: audit read paths must use their index (not a seq scan) at volume, and retention prune must
// be bounded, restartable, and safe to confirm. Real Postgres only; gated on pgReachable(), and once
// reachable a failure is a REAL failure, never a skip. The plan/bounds assertions run the ACTUAL
// `Audit` methods through a recording Db (below) so a production regression can't stay green.

const SKIP = 'Postgres not reachable (run `npm run pg:up`)';
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

type Call = { sql: string; params: any[]; changes?: number };

/** A Db that delegates to `real` and records every statement (and each `run`'s row count), so a test
 *  can EXPLAIN the SQL a production method actually issued and assert its per-call batch sizes. */
function recordingDb(real: Db): { db: Db; calls: Call[] } {
  const calls: Call[] = [];
  const db: Db = {
    get: (sql, params = []) => { calls.push({ sql, params }); return real.get(sql, params); },
    all: (sql, params = []) => { calls.push({ sql, params }); return real.all(sql, params); },
    run: async (sql, params = []) => { const r = await real.run(sql, params); calls.push({ sql, params, changes: r.changes }); return r; },
    exec: (sql) => { calls.push({ sql, params: [] }); return real.exec(sql); },
    close: () => real.close(),
    transaction: real.transaction ? (fn) => real.transaction!(fn) : undefined,
    withRefreshLock: real.withRefreshLock ? (k, fn) => real.withRefreshLock!(k, fn) : undefined,
  };
  return { db, calls };
}

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
async function explain(db: Db, sql: string, params: any[]): Promise<string> {
  const rows = await db.all<Record<string, unknown>>(`EXPLAIN (FORMAT JSON) ${sql}`, params);
  return JSON.stringify(rows[0]['QUERY PLAN']);
}
const seqScans = (planJson: string) => /"Node Type":"Seq Scan"/.test(planJson);

test('audit plans: the ACTUAL production queries (+ the prune DELETE) ride an index, not a seq scan', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const real = await openTestDb(t);
  const now = Date.now();
  // 50k keeps the seed under the test pool's statement_timeout (the migrated schema has 4 audit
  // indexes to maintain per insert). The plans are deterministic, so this suffices to assert them;
  // the 1M-row EXPLAIN ANALYZE / P95 / WAL reference is the opt-in `bench:audit` harness (#208).
  await seed(real, 50_000, now);
  await real.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text,'T1','U_ADMIN','github','config',NULL,'C1','{}', ${now} - (g*1000) FROM generate_series(1,20) g`,
  );
  await real.exec(`ANALYZE audit`);

  // Capture the SQL each production method actually issues (not a copy), then EXPLAIN THAT.
  const rec = recordingDb(real);
  const audit = new Audit(rec.db);
  const last = () => rec.calls[rec.calls.length - 1];

  await audit.listByOwnerUser({ enterpriseId: null, teamId: 'T1', userId: 'U1' }, 20);
  const owner = await explain(real, last().sql, last().params);
  assert.match(owner, /idx_audit_team_user_at/, `owner history plan=${owner}`);
  assert.equal(seqScans(owner), false);

  await audit.listByChannel('T1', 'C1', 20);
  const channel = await explain(real, last().sql, last().params);
  assert.match(channel, /idx_audit_team_channel_at/, `channel history plan=${channel}`);
  assert.equal(seqScans(channel), false);

  await audit.statsByChannel('T1', 'C1', now - DAY);
  const stats = await explain(real, last().sql, last().params);
  assert.match(stats, /idx_audit_team_channel_at/, `stats plan=${stats}`);

  await audit.lastChannelConfigActor('T1', 'C1', 'github');
  const config = await explain(real, last().sql, last().params);
  assert.match(config, /idx_audit_config/, `config lookup plan=${config}`);
  assert.equal(seqScans(config), false);

  // The prune DELETE is single-sourced (PRUNE_BATCH_SQL is what pruneOlderThan runs). It must ride
  // idx_audit_at and NOT seq-scan — the plain `id IN (SELECT …)` form would seq-scan here.
  const del = await explain(real, PRUNE_BATCH_SQL, [now - 6 * HOUR, 10_000]);
  assert.match(del, /idx_audit_at/, `prune DELETE plan=${del}`);
  assert.equal(seqScans(del), false, `prune DELETE must NOT seq-scan; plan=${del}`);
});

test('pruneOlderThan deletes in BOUNDED batches (100,100,50), keeps recent, is idempotent', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const real = await openTestDb(t);
  const now = Date.now();
  const cutoff = now - 30 * DAY;
  await real.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text, 'T1','U1','github','inject',NULL,'C1','{}', ${cutoff} - (g*1000) FROM generate_series(1,250) g`,
  );
  await real.exec(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text, 'T1','U1','github','inject',NULL,'C1','{}', ${now} - (g*1000) FROM generate_series(1,40) g`,
  );

  // Record the actual DELETEs so the promised per-statement batch sizes are asserted, not just the
  // total — removing the LIMIT would make this a single 250-row delete and fail here.
  const rec = recordingDb(real);
  const deleted = await new Audit(rec.db).pruneOlderThan(cutoff, 100);
  assert.equal(deleted, 250);
  const batches = rec.calls.filter((c) => c.sql === PRUNE_BATCH_SQL).map((c) => c.changes);
  assert.deepEqual(batches, [100, 100, 50], 'each DELETE must be bounded by the batch size');

  assert.equal(await new Audit(real).countOlderThan(cutoff), 0);
  assert.equal(Number((await real.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit`))?.n), 40, 'recent rows survive');
  assert.equal(await new Audit(real).pruneOlderThan(cutoff, 100), 0, 'idempotent re-run deletes nothing');
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
  const one = await db.run(PRUNE_BATCH_SQL, [cutoff, 100]); // one committed batch, then "crash"
  assert.equal(one.changes, 100);
  assert.equal(await audit.countOlderThan(cutoff), 150, 'the committed batch is durable across the "interruption"');
  assert.equal(await audit.pruneOlderThan(cutoff, 100), 150);
  assert.equal(await audit.countOlderThan(cutoff), 0);
});

test('core Audit enforces its own bounds (public export must not accept oversized/unsafe input)', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const audit = new Audit(await openTestDb(t));
  const now = Date.now();
  await assert.rejects(() => audit.pruneOlderThan(now, 0), new RegExp(`1..${MAX_AUDIT_PRUNE_BATCH}`));
  await assert.rejects(() => audit.pruneOlderThan(now, MAX_AUDIT_PRUNE_BATCH + 1), new RegExp(`1..${MAX_AUDIT_PRUNE_BATCH}`));
  await assert.rejects(() => audit.pruneOlderThan(1e100, 100), /safe integer/); // unsafe cutoff, not a DB error
  await assert.rejects(() => audit.countOlderThan(1e100), /safe integer/);
});

test('prune CLI: only a bare --yes deletes; malformed forms are rejected without echoing input (real CLI + DB state)', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const url = await testDbUrl(t);
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

  for (const [label, extra, errRe] of [
    ['valued --yes=false', ['--yes=false'], /takes no value/],
    ['empty --yes=', ['--yes='], /takes no value/],
    ['--yes= then --yes', ['--yes=', '--yes'], /takes no value/],
    ['--yes no (positional)', ['--yes', 'no'], /unexpected positional/],
    ['duplicate --yes', ['--yes', '--yes'], /more than once/],
    ['unknown flag typo', ['--bacth', '1', '--yes'], /unknown flag/],
    ['positional arg', ['github', '--yes'], /unexpected positional/],
    ['--dry-run --yes conflict', ['--dry-run', '--yes'], /mutually exclusive/],
    ['batch over max', ['--batch', '20000', '--yes'], /between 1 and 10000/],
  ] as const) {
    await seed5();
    const r = run(...extra);
    assert.notEqual(r.status, 0, `${label} must exit non-zero`);
    assert.match(r.stderr, errRe, `${label}: stderr`);
    assert.equal(await count(), 5, `${label} must delete nothing`);
  }

  // A days value whose cutoff falls outside the Date range must be rejected BEFORE any DB work (its
  // own invocation — `run` hardcodes --older-than-days, and a duplicate would be rejected as such).
  await seed5();
  const rDays = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'prune', '--older-than-days', '104000000', '--db', url, '--yes'], { encoding: 'utf8' });
  assert.notEqual(rDays.status, 0);
  assert.match(rDays.stderr, /too large/);
  assert.equal(await count(), 5, 'an out-of-range days must delete nothing');

  // SEC-1: a token-shaped positional and an unknown flag carrying a secret must NOT be echoed.
  const secret = 'ghp_TOPSECRETtokenAAAAAAAAAAAAAAAAAAAA';
  let s = run(secret, '--yes');
  assert.notEqual(s.status, 0);
  assert.doesNotMatch(s.stderr + s.stdout, /ghp_TOPSECRET/, 'a positional secret must not be echoed');
  s = run(`--${secret}`, '--yes');
  assert.notEqual(s.status, 0);
  assert.doesNotMatch(s.stderr + s.stdout, /ghp_TOPSECRET/, 'an unknown-flag secret must not be echoed');

  await seed5();
  let r = run(); // no --yes → dry-run
  assert.equal(r.status, 0);
  assert.match(r.stdout, /DRY-RUN: 5/);
  assert.equal(await count(), 5, 'a dry-run must delete nothing');

  await seed5();
  r = run('--yes'); // exact bare --yes → deletes
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Pruned 5/);
  assert.equal(await count(), 0, 'a bare --yes deletes');
});
