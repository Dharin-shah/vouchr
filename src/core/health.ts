import type { Db } from './db';
import type { Owner } from './owner';

/**
 * Credential-health event (#117): the connection needs (or is about to need) human attention.
 * DELIBERATELY separate from `VouchrEvent`/EventSink, whose no-user-ids contract is load-bearing:
 * this hook exists precisely to tell the OWNER, so it carries identity (the owning principal) —
 * and, like every Vouchr surface, NEVER token material, secret refs, or error text.
 *
 *  - 'refresh_dead':   a token refresh failed DEFINITIVELY (invalid_grant / 400/401 from the token
 *                      endpoint — see TokenEndpointError in tokens.ts). Only reconnecting fixes it.
 *                      Never fired on transient failures (network blip, 5xx, timeout).
 *  - 'expiring_soon':  the connection is within the sweep's warn window of its TTL ceiling
 *                      (idle/max-age — see Vault.listExpiringSoon). `expiresAt` = that ceiling.
 *  - 'expired':        the sweep just deleted the connection (past its TTL).
 *
 * Fired via safeEmit: a throwing hook never affects the request or the sweep. The hook itself is
 * NOT debounced ('refresh_dead' fires per definitive failure, 'expiring_soon' per sweep pass) —
 * user-facing notifiers debounce with {@link NotificationState} (the Bolt default wiring does).
 */
export interface CredentialHealthEvent {
  type: 'refresh_dead' | 'expiring_soon' | 'expired';
  owner: Owner;
  provider: string;
  /** ms epoch of the connection's TTL ceiling. Present on 'expiring_soon' only. */
  expiresAt?: number;
}

/** Fire-and-forget credential-health hook. May be sync or async (`=> void` admits async
 *  functions); a throwing OR rejecting hook must never affect behavior — fire points route
 *  through safeEmit, which swallows both failure shapes. Typed `=> void`, not
 *  `void | Promise<void>`, to keep `(e) => arr.push(e)`-style consumers compiling (see EventSink). */
export type CredentialHealthHook = (e: CredentialHealthEvent) => void;

/** At most one user-facing notification per (owner, provider, type) per 24h. */
export const HEALTH_NOTIFY_DEBOUNCE_MS = 24 * 60 * 60 * 1000;

/**
 * Persistent per-(connection, type) notification debounce (#117). DB-backed on purpose: the 24h
 * window spans process restarts and a multi-day sweep cadence, so an in-memory map would re-notify
 * on every deploy. Rows are satellites of a `connection` row — Vault purges them whenever the
 * connection is (re)written or deleted, so a RECONNECT resets the debounce (fresh connection ⇒
 * fresh state) and deleted connections never leak state rows. Rows carry identity + a timestamp
 * only, never token material (SEC-1); callers validate `provider` before writing (SEC-4).
 *
 * Delivery contract: {@link claim} the window FIRST (atomic — exactly one caller wins per window,
 * even across pods sharing a Postgres), then send; if the send fails, {@link release} the claim so
 * the next event retries. The deliberate trade, in this order: a process that claims and then
 * CRASHES before sending loses that window's notification (the next window retries) — accepted,
 * because the alternative (mark after send) lets two pods double-notify, and a duplicate DM is
 * worse than a 24h-late one.
 */
export class NotificationState {
  constructor(private db: Db) {}

  /**
   * Atomically claim the 24h window for (owner, provider, type): true only for the ONE caller that
   * wins it. A single conditional upsert — INSERT wins a missing row; the DO UPDATE fires only when
   * the stored timestamp is older than the window, so a concurrent/duplicate claimer reports 0 rows
   * changed and loses. Same statement on both backends (SQLite `changes` / Postgres `rowCount`,
   * already normalized by Db.run).
   */
  async claim(owner: Owner, provider: string, type: CredentialHealthEvent['type'], now = Date.now()): Promise<boolean> {
    const { changes } = await this.db.run(
      `INSERT INTO notification_state (team_id, owner_kind, owner_id, provider, type, last_notified_at)
       VALUES (?,?,?,?,?,?)
       ON CONFLICT(team_id, owner_kind, owner_id, provider, type) DO UPDATE SET last_notified_at=excluded.last_notified_at
       WHERE notification_state.last_notified_at <= ?`,
      [owner.teamId, owner.kind, owner.id, provider, type, now, now - HEALTH_NOTIFY_DEBOUNCE_MS],
    );
    return changes > 0;
  }

  /**
   * Best-effort release of a claim whose send FAILED, so the next event retries instead of waiting
   * out the window. Conditional on the exact claimed timestamp: only OUR claim is released, never a
   * later successful one (deleting is equivalent to the pre-claim state — an absent row, or one
   * older than the window, both allow the next claim).
   */
  async release(owner: Owner, provider: string, type: CredentialHealthEvent['type'], claimedAt: number): Promise<void> {
    await this.db.run(
      `DELETE FROM notification_state WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=? AND type=? AND last_notified_at=?`,
      [owner.teamId, owner.kind, owner.id, provider, type, claimedAt],
    );
  }
}
