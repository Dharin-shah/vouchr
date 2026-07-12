/**
 * Opt-in audit performance harness (#208) — NOT part of `npm test` (it lives outside `test/*.test.ts`
 * and generates ~1M rows). Reproduces the reference measurements the issue asks for:
 *   - EXPLAIN (ANALYZE, BUFFERS) for owner history, channel history, and the 24-hour stats query;
 *   - the prune DELETE plan + per-10k-batch timing (P50/P95/max) and WAL bytes;
 *   - concurrent single-row insert latency WHILE pruning;
 *   - final expired-row count (must reach 0).
 *
 * Run:  npm run bench:audit        (uses VOUCHR_TEST_PG_URL, or --db-style VOUCHR_BENCH_PG_URL)
 * Rows: BENCH_ROWS=1000000 (default). Uses a dedicated `audit_bench` schema it creates and drops.
 */
import { Client } from 'pg';
import { migrate, openDb } from '../../src/core/db';
import { Audit, PRUNE_BATCH_SQL } from '../../src/core/audit';

const BASE = process.env.VOUCHR_BENCH_PG_URL ?? process.env.VOUCHR_TEST_PG_URL ?? 'postgres://vouchr:vouchr@localhost:5433/vouchr';
const ROWS = Number(process.env.BENCH_ROWS ?? 1_000_000);
const SCHEMA = 'audit_bench';

function schemaUrl(base: string): string {
  const u = new URL(base);
  u.searchParams.set('options', `-c search_path=${SCHEMA}`);
  return u.toString();
}
const pctl = (xs: number[], p: number) => xs.slice().sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor((p / 100) * xs.length))];

async function main(): Promise<void> {
  const admin = new Client(BASE);
  await admin.connect();
  await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
  await admin.query(`CREATE SCHEMA ${SCHEMA}`);
  const url = schemaUrl(BASE);
  await migrate({ databaseUrl: url });
  await admin.query(`SET search_path=${SCHEMA}`);

  const db = await openDb({ databaseUrl: url });
  const now = Date.now();
  console.log(`Seeding ${ROWS.toLocaleString()} audit rows…`);
  const t0 = Date.now();
  // Seed via the raw admin connection (no statement_timeout), the way a real bulk load would run —
  // the runtime pool caps statements at 10s, which a one-shot 1M-row load exceeds.
  await admin.query(
    `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     SELECT gen_random_uuid()::text, 'T'||(g%50), 'U'||(g%500),
            (ARRAY['github','gitlab','notion'])[1+(g%3)],
            CASE WHEN g%997=0 THEN 'config' ELSE 'inject' END, NULL, 'C'||(g%100), '{}', ${now} - (g*1000)
     FROM generate_series(1, ${ROWS}) g`,
  );
  await admin.query('ANALYZE audit');
  console.log(`  seeded in ${((Date.now() - t0) / 1000).toFixed(1)}s\n`);

  const analyze = async (label: string, sql: string, params: any[]) => {
    const rows = await db.all<Record<string, unknown>>(`EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) ${sql}`, params);
    console.log(`### ${label}`);
    console.log(rows.map((r) => r['QUERY PLAN']).join('\n'), '\n');
  };
  await analyze('owner history', `SELECT provider, action, actor, channel, at FROM audit WHERE team_id=? AND user_id=? ORDER BY at DESC LIMIT ?`, ['T1', 'U1', 50]);
  await analyze('channel history', `SELECT provider, action, actor, channel, at FROM audit WHERE team_id=? AND channel=? ORDER BY at DESC LIMIT ?`, ['T1', 'C1', 50]);
  await analyze('24h stats', `SELECT provider, COUNT(*), COUNT(DISTINCT COALESCE(actor,user_id)), MAX(at) FROM audit WHERE team_id=? AND channel=? AND action='inject' AND at>=? GROUP BY provider`, ['T1', 'C1', now - 24 * 3_600_000]);
  await analyze('prune DELETE (10k)', PRUNE_BATCH_SQL, [now - 6 * 3_600_000, 10_000]);

  // Concurrent single-row inserts WHILE pruning, plus per-batch timing + WAL bytes.
  const inserter = new Client(BASE);
  await inserter.connect();
  await inserter.query(`SET search_path=${SCHEMA}`);
  let pruning = true;
  const insertMs: number[] = [];
  const insertLoop = (async () => {
    while (pruning) {
      const s = Date.now();
      await inserter.query(`INSERT INTO audit (id,team_id,user_id,provider,action,actor,channel,meta,at) VALUES (gen_random_uuid()::text,'T1','U1','github','inject',NULL,'C1','{}',$1)`, [Date.now()]);
      insertMs.push(Date.now() - s);
    }
  })();

  const cutoff = now - 6 * 3_600_000;
  const audit = new Audit(db);
  const batchMs: number[] = [];
  const walBefore = (await admin.query('SELECT pg_current_wal_lsn() AS l')).rows[0].l;
  let totalDeleted = 0;
  for (;;) {
    const s = Date.now();
    const { changes } = await db.run(PRUNE_BATCH_SQL, [cutoff, 10_000]);
    batchMs.push(Date.now() - s);
    totalDeleted += changes;
    if (changes < 10_000) break;
  }
  const walAfter = (await admin.query('SELECT pg_current_wal_lsn() AS l')).rows[0].l;
  const walBytes = (await admin.query('SELECT pg_wal_lsn_diff($1,$2)::bigint AS b', [walAfter, walBefore])).rows[0].b;
  pruning = false;
  await insertLoop;
  await inserter.end();

  console.log(`### prune: ${totalDeleted.toLocaleString()} rows in ${batchMs.length} batches of 10k`);
  console.log(`  batch ms  P50=${pctl(batchMs, 50)}  P95=${pctl(batchMs, 95)}  max=${Math.max(...batchMs)}`);
  console.log(`  WAL generated: ${(Number(walBytes) / 1_048_576).toFixed(1)} MiB`);
  console.log(`  concurrent inserts during prune: n=${insertMs.length}  P50=${pctl(insertMs, 50)}ms  P95=${pctl(insertMs, 95)}ms  max=${Math.max(...insertMs)}ms`);
  const remaining = await audit.countOlderThan(cutoff);
  console.log(`  expired rows remaining: ${remaining}`);

  await db.close();
  await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
  await admin.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
