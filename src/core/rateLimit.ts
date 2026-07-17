/**
 * Per-(owner, provider) rate limiting at the injection boundary (#114). Without a throttle, a
 * looping (or prompt-injected) agent can hammer a provider with a human's credential until the
 * PROVIDER rate-bans that human's account — the user pays for the agent's bug. The check runs in
 * `ConnectionHandle.fetch` BEFORE the vault read, so a rate-limited request never touches the
 * secret — the same discipline the egress gates follow.
 */

/**
 * Thrown when the (owner, provider) token bucket is empty. Carries structured, NO-SECRET fields so
 * each surface renders its own message: the Bolt adapter posts an ephemeral "Slow down …", the HTTP
 * broker maps it to 429 with a `Retry-After` header. The core safe mapper derives fixed copy from
 * the structured retry hint; constructor message text is not itself a rendering trust boundary.
 */
export class RateLimitedError extends Error {
  readonly code = 'rate_limited' as const;

  constructor(
    /** Provider id, from the registry-validated provider (never raw caller input). */
    public provider: string,
    /** The provider's configured sustained limit, for user-facing messaging. */
    public perMinute: number,
    /** How long until one request's worth of budget refills, in ms (always > 0). */
    public retryAfterMs: number,
  ) {
    super(`Rate limited: "${provider}" allows ${perMinute} requests/min. Try again in ${Math.ceil(retryAfterMs / 1000)}s.`);
    this.name = 'RateLimitedError';
  }
}

/**
 * Pluggable token-bucket store. `take` atomically removes `cost` tokens from `key`'s bucket
 * (created full at `capacity`, refilling at `refillPerMs` tokens per millisecond, capped at
 * `capacity`). On deny it consumes nothing and reports how long until `cost` tokens will be
 * available. May be async so a multi-instance deployment can back it with a shared store. Supply one
 * via `VouchrOptions.rateLimitStore` / `BrokerOptions.rateLimitStore`.
 */
export interface RateLimitStore {
  take(
    key: string,
    cost: number,
    refillPerMs: number,
    capacity: number,
  ): { ok: boolean; retryAfterMs?: number } | Promise<{ ok: boolean; retryAfterMs?: number }>;
}

interface Bucket {
  tokens: number;
  last: number; // epoch ms of the last take() against this bucket
  // The refill/capacity the bucket was last used with, kept so the prune sweep can decide fullness
  // per bucket (different providers carry different limits).
  refillPerMs: number;
  capacity: number;
}

/**
 * Default in-process token-bucket store.
 * ponytail: per-process limiting only — a fleet of N broker/bolt replicas multiplies the effective
 * limit by N (each process refills its own buckets). Upgrade path: a DB- or Redis-backed
 * `RateLimitStore` (atomic take via UPSERT/Lua) plugged in through the same interface via
 * `rateLimitStore`; do not fork this class.
 */
export class MemoryRateLimitStore implements RateLimitStore {
  private buckets = new Map<string, Bucket>();
  private lastPrune = 0;

  take(key: string, cost: number, refillPerMs: number, capacity: number): { ok: boolean; retryAfterMs?: number } {
    const now = Date.now();
    // ponytail: prune cadence 60s, mirroring ReplayGuard (adapters/http/identity.ts) — only the O(n)
    // sweep is throttled; the take below runs on every call (correctness). A bucket refilled back to
    // capacity is indistinguishable from a fresh one, so dropping it loses nothing; memory stays
    // bounded by the keys active within one refill-to-full window.
    if (now - this.lastPrune > 60_000) {
      this.lastPrune = now;
      for (const [k, b] of this.buckets) {
        if (b.tokens + (now - b.last) * b.refillPerMs >= b.capacity) this.buckets.delete(k);
      }
    }
    const b = this.buckets.get(key);
    const tokens = b ? Math.min(capacity, b.tokens + (now - b.last) * b.refillPerMs) : capacity;
    if (tokens < cost) {
      // Deny consumes nothing; persist the refilled level so the retry math stays exact.
      this.buckets.set(key, { tokens, last: now, refillPerMs, capacity });
      return { ok: false, retryAfterMs: Math.ceil((cost - tokens) / refillPerMs) };
    }
    this.buckets.set(key, { tokens: tokens - cost, last: now, refillPerMs, capacity });
    return { ok: true };
  }
}
