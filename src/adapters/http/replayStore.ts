import type { Db } from '../../core/db';
import type { ReplayStore } from './identity';

/**
 * A durable, backend-agnostic {@link ReplayStore} over the shared `Db`. This is what makes a signed
 * identity token's `jti` single-use CLUSTER-WIDE: every broker replica shares one `broker_jti` table,
 * so a jti used on pod A is rejected on pod B within the same (<=5min) window. Required for a
 * multi-replica headless broker — the default in-memory `ReplayGuard` is per-process only.
 *
 * `use()` is atomic per row via `INSERT ... ON CONFLICT DO NOTHING`: exactly one concurrent caller
 * gets `changes === 1` (fresh), the rest get `0` (already used). Works on Postgres (production) and
 * SQLite (single-replica / tests) unchanged — `?` placeholders and `ON CONFLICT` are portable here.
 */
export class DbReplayStore implements ReplayStore {
  private ready: Promise<void>;
  private lastPrune = 0;

  constructor(private db: Db) {
    // exp is epoch-ms (IdentityClaims.exp). BIGINT on PG; INTEGER affinity on SQLite — both fine.
    this.ready = db.exec(`CREATE TABLE IF NOT EXISTS broker_jti (jti TEXT PRIMARY KEY, exp BIGINT NOT NULL)`);
  }

  async use(jti: string, exp: number): Promise<boolean> {
    await this.ready;
    const now = Date.now();
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
