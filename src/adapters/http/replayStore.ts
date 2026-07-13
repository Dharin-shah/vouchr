import type { Db } from '../../core/db';
import { IDENTITY_SKEW_MS } from './identity';

/** Exact production statements, reused by readiness EXPLAIN so schema/privilege checks cannot drift. */
export const INSERT_REPLAY_SQL = `INSERT INTO broker_jti (jti, exp) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING`;
export const PRUNE_REPLAY_SQL = `DELETE FROM broker_jti WHERE exp <= ?`;

/**
 * The durable PostgreSQL replay store over the shared `Db`. This is what makes a signed
 * identity token's `jti` single-use CLUSTER-WIDE: every broker replica shares one `broker_jti` table,
 * so a jti used on pod A is rejected on pod B within the same bounded acceptance window. This is the
 * only production broker store; `ReplayGuard` remains only a low-level, single-process utility.
 *
 * `use()` is atomic per row via `INSERT ... ON CONFLICT DO NOTHING`: exactly one concurrent caller
 * gets `changes === 1` (fresh), the rest get `0` (already used).
 *
 * The `broker_jti` table is part of the baseline schema (see `schema()` in core/db) — no DDL runs
 * here, so two replicas constructing a store on one DB can't race `CREATE TABLE`.
 */
export class DbReplayStore {
  private lastPrune = 0;

  constructor(
    private db: Db,
    /** Injectable only so the cross-replica clock-skew regression is deterministic. */
    private now: () => number = Date.now,
  ) {}

  /**
   * Non-mutating readiness probe for the exact relation and privileges `use()` needs. Checking only
   * the schema-version marker is insufficient: a missing table or a DML-only role missing one grant
   * would leave the pod green while every authenticated request fails at replay consumption.
   */
  async ready(): Promise<void> {
    try {
      // Plain EXPLAIN never mutates. PostgreSQL still resolves the exact relation, columns, BIGINT
      // parameter, ON CONFLICT arbiter, and INSERT/DELETE/SELECT privileges used by production.
      await this.db.all(`EXPLAIN ${INSERT_REPLAY_SQL}`, ['__vouchr_ready__', 0]);
      await this.db.all(`EXPLAIN ${PRUNE_REPLAY_SQL}`, [0]);
    } catch {
      throw new Error('vouchr: replay store is unavailable');
    }
  }

  async use(jti: string, exp: number): Promise<boolean> {
    const now = this.now();
    const retentionGraceMs = replayRetentionGrace();
    if (
      !Number.isSafeInteger(now) ||
      !Number.isSafeInteger(exp) ||
      !Number.isSafeInteger(exp + retentionGraceMs) ||
      exp + retentionGraceMs <= now
    ) {
      return false;
    }
    // Opportunistic, time-gated prune keeps the table bounded by the live token window without a
    // table scan on every request. Store raw token expiry (the stable schema meaning) and subtract
    // the bounded grace only from the prune cutoff. Every #212 replica therefore preserves a spent
    // jti through every verifier's acceptance window. Pre-#212 replicas do not know this grace, so
    // the one-time format upgrade is an explicitly drained cutover rather than mixed-version rolling.
    if (now - this.lastPrune > 60_000) {
      this.lastPrune = now;
      await this.db.run(PRUNE_REPLAY_SQL, [now - retentionGraceMs]);
    }
    const { changes } = await this.db.run(INSERT_REPLAY_SQL, [jti, exp]);
    return changes === 1; // inserted -> fresh; 0 -> already used (rejected)
  }
}

/**
 * Retention grace after raw token expiry for a consumed assertion in a multi-replica deployment.
 * The verifier accepts until `exp + skew` on its own clock. At the same instant a pruning replica
 * may be two skew windows ahead of a verifier at the opposite documented clock extreme, so
 * retaining through `exp + 3*skew` covers the verifier's tolerance plus the maximum inter-replica
 * difference. The extra bounded window is 90 seconds with the fixed 30-second skew.
 */
export function replayRetentionGrace(): number {
  return 3 * IDENTITY_SKEW_MS;
}
