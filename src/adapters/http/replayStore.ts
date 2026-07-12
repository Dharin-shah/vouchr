import type { Db } from '../../core/db';
import type { ReplayStore } from './identity';

/**
 * A durable PostgreSQL {@link ReplayStore} over the shared `Db`. This is what makes a signed
 * identity token's `jti` single-use CLUSTER-WIDE: every broker replica shares one `broker_jti` table,
 * so a jti used on pod A is rejected on pod B within the same bounded acceptance window. This is the
 * production broker default; `ReplayGuard` remains only a low-level, single-process utility.
 *
 * `use()` is atomic per row via `INSERT ... ON CONFLICT DO NOTHING`: exactly one concurrent caller
 * gets `changes === 1` (fresh), the rest get `0` (already used).
 *
 * The `broker_jti` table is part of the baseline schema (see `schema()` in core/db) — no DDL runs
 * here, so two replicas constructing a store on one DB can't race `CREATE TABLE`.
 */
export class DbReplayStore implements ReplayStore {
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
    const row = await this.db.get<{
      relation: string | null;
      can_insert: boolean;
      can_delete: boolean;
    }>(`
      SELECT
        to_regclass('broker_jti')::text AS relation,
        COALESCE(has_table_privilege(current_user, to_regclass('broker_jti'), 'INSERT'), false) AS can_insert,
        COALESCE(has_table_privilege(current_user, to_regclass('broker_jti'), 'DELETE'), false) AS can_delete
    `);
    if (!row?.relation || !row.can_insert || !row.can_delete) {
      throw new Error('vouchr: replay store is unavailable');
    }
  }

  async use(jti: string, exp: number): Promise<boolean> {
    const now = this.now();
    // Opportunistic, time-gated prune keeps the table bounded by the live token window without a
    // table scan on every request. Expired jtis are safe to drop — verifyIdentity already rejects an
    // expired token before the replay check, so a pruned-then-reused jti can never pass.
    if (now - this.lastPrune > 60_000) {
      this.lastPrune = now;
      await this.db.run(`DELETE FROM broker_jti WHERE exp <= ?`, [now]);
    }
    const { changes } = await this.db.run(
      `INSERT INTO broker_jti (jti, exp) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING`,
      [jti, exp],
    );
    return changes === 1; // inserted -> fresh; 0 -> already used (rejected)
  }
}

/**
 * Latest safe deletion time for a consumed assertion in a multi-replica deployment. The verifier
 * accepts until `exp + skew` on its own clock. At the same instant a pruning replica may be two skew
 * windows ahead of a verifier at the opposite documented clock extreme, so retaining through
 * `exp + 3*skew` covers the verifier's tolerance plus the maximum inter-replica difference. The
 * extra bounded window is at most 90 seconds with the default 30-second skew.
 */
export function replayExpiryHorizon(exp: number, skewMs: number): number {
  return exp + 3 * skewMs;
}
