import type { Db } from '../../src/core/db';

/** Read-only instrumentation for production-path query-count regressions. Writes and lifecycle
 *  methods pass through unchanged; callers can reset after fixture setup so only the action under
 *  test is measured. */
export function countingDb(base: Db): {
  db: Db;
  counts: { get: number; all: number };
  reads: { kind: 'get' | 'all'; sql: string }[];
  reset(): void;
} {
  const counts = { get: 0, all: 0 };
  const reads: { kind: 'get' | 'all'; sql: string }[] = [];
  const db: Db = {
    get: (sql, params) => {
      counts.get++;
      reads.push({ kind: 'get', sql });
      return base.get(sql, params);
    },
    all: (sql, params) => {
      counts.all++;
      reads.push({ kind: 'all', sql });
      return base.all(sql, params);
    },
    run: (sql, params) => base.run(sql, params),
    exec: (sql) => base.exec(sql),
    close: () => base.close(),
    ...(base.withRefreshLock ? { withRefreshLock: base.withRefreshLock.bind(base) } : {}),
    ...(base.transaction ? { transaction: base.transaction.bind(base) } : {}),
  };
  return {
    db,
    counts,
    reads,
    reset: () => {
      counts.get = 0;
      counts.all = 0;
      reads.length = 0;
    },
  };
}
