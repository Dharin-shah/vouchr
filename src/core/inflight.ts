/**
 * In-process in-flight admission control (#209). Two ceilings — a per-process GLOBAL cap on
 * concurrent work and a PER-PROVIDER cap — bound how many requests can be in flight at once, so a
 * burst of slow or hung upstreams (or a looping agent) cannot pin unbounded sockets and buffered
 * memory. This is NOT the rate limiter (`rateLimit.ts`, requests-per-window per owner+provider): this
 * counts SIMULTANEOUS in-flight work and admits/rejects at the moment of entry.
 *
 * Deliberately in-process: a fleet of N replicas admits up to N × the per-process ceiling,
 * and that product IS the documented capacity envelope (guides/DEPLOYMENT.md). #209 explicitly rules
 * out Redis / distributed semaphores / cluster-wide admission; per-process counters are the whole
 * design.
 */

import { MAX_TIMER_MS } from './options';

/** One runtime invariant for every in-flight limiter construction path (STR-2). */
export function assertInflightLimits(
  globalMax: number,
  providerMax: number,
  label = 'InflightLimiter',
): void {
  if (!Number.isSafeInteger(globalMax) || globalMax <= 0) {
    throw new Error(`${label}: maxInflight must be a positive safe integer.`);
  }
  if (!Number.isSafeInteger(providerMax) || providerMax <= 0) {
    throw new Error(`${label}: maxInflightPerProvider must be a positive safe integer.`);
  }
  if (providerMax > globalMax) {
    throw new Error(`${label}: maxInflightPerProvider must be <= maxInflight.`);
  }
}

/**
 * Thrown when an in-flight ceiling is full. Carries a NO-SECRET scope + retry hint so each surface
 * renders its own message: the HTTP broker maps it to 503 with a `Retry-After` header. The message is
 * Vouchr-authored and secret-free.
 */
export class OverloadedError extends Error {
  constructor(
    /** Which ceiling rejected the request — for the operator-facing metric, never a secret. */
    public scope: 'global' | 'provider',
    /** How long to advise the caller to wait before retrying, in ms (always > 0). */
    public retryAfterMs: number,
  ) {
    super(`Overloaded: too many concurrent requests (${scope}). Retry after ${Math.ceil(retryAfterMs / 1000)}s.`);
    this.name = 'OverloadedError';
  }
}

/**
 * A live counter of concurrent in-flight work, shared across every request (constructed once per
 * broker, like the `inflight` refresh map and the rate-limit store). `enter()` admits one unit
 * against the global ceiling; `enterProvider(id)` admits against that provider's ceiling. Each returns
 * an idempotent release function to call in a `finally` — a double release (finally + an error path)
 * is a no-op, so the counters can never drift below zero.
 */
export class InflightLimiter {
  private global = 0;
  private perProvider = new Map<string, number>();

  constructor(
    /** Max concurrent in-flight requests across all providers. */
    private readonly globalMax: number,
    /** Max concurrent in-flight requests for any single provider. */
    private readonly providerMax: number,
    /** Retry-After hint returned on rejection (ms). We can't know when a slot frees, so this is a
     *  small fixed nudge, not a promise. */
    private readonly retryAfterMs = 1_000,
  ) {
    assertInflightLimits(globalMax, providerMax);
    if (!Number.isSafeInteger(retryAfterMs) || retryAfterMs <= 0 || retryAfterMs > MAX_TIMER_MS) {
      throw new Error(`InflightLimiter: retryAfterMs must be a positive safe integer no greater than ${MAX_TIMER_MS}.`);
    }
  }

  /** Admit one unit against the GLOBAL ceiling, or throw {@link OverloadedError}. */
  enter(): () => void {
    if (this.global >= this.globalMax) throw new OverloadedError('global', this.retryAfterMs);
    this.global++;
    return this.releaser(() => { this.global--; });
  }

  /** Admit one unit against `provider`'s ceiling, or throw {@link OverloadedError}. */
  enterProvider(provider: string): () => void {
    const cur = this.perProvider.get(provider) ?? 0;
    if (cur >= this.providerMax) throw new OverloadedError('provider', this.retryAfterMs);
    this.perProvider.set(provider, cur + 1);
    return this.releaser(() => {
      const n = (this.perProvider.get(provider) ?? 1) - 1;
      if (n <= 0) this.perProvider.delete(provider);
      else this.perProvider.set(provider, n);
    });
  }

  /** Snapshot for tests/metrics: current global in-flight count. */
  inFlight(): number {
    return this.global;
  }

  private releaser(dec: () => void): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      dec();
    };
  }
}
