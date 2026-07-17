import type { EventSink, VouchrEvent } from '../../src/core/injector';

/**
 * ─── Prometheus over EventSink, dependency-free ──────────────────────────────────────────────
 * `EventSink` (src/core/injector.ts) is the designed NO-SECRET observability hook: every
 * `VouchrEvent` carries provider id / host / status / counts only — never a token, secretRef,
 * user id, or team id. That makes it a clean feed for metrics.
 *
 * This aggregates events into in-memory counters + histograms and renders the Prometheus text
 * exposition format BY HAND — no `prom-client`, no new runtime dependency (keeps the repo's
 * 4-runtime-dep discipline). Every label below is an already-no-secret field straight off the
 * event, so nothing here can leak.
 *
 * Cardinality: `host` is only ever an ALLOWLISTED host (egress is rejected before any event fires
 * for a non-allowlisted target), and `provider`/`reason`/`owner_kind`/`ok` are all small closed
 * sets — so the label space is bounded, not user-driven.
 */

/** Histogram bucket upper bounds (ms): sub-ms cache hits through multi-second refreshes. */
const BUCKETS = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500];

interface Hist {
  buckets: number[]; // count of observations <= BUCKETS[i]
  sum: number;
  count: number;
}

type Labels = Record<string, string | number>;

// Metric name -> HELP text. Which map a metric lives in (counters vs hists) decides its TYPE.
const HELP: Record<string, string> = {
  vouchr_injected_total: 'Outbound provider calls with a credential injected at egress.',
  vouchr_inject_duration_ms: 'Wall-clock latency of the injected provider fetch (ms).',
  vouchr_refreshed_total: 'OAuth token refreshes performed.',
  vouchr_refresh_lock_wait_ms: 'Time spent waiting for the cross-process refresh lock (ms).',
  vouchr_refresh_reused_total: 'Refreshes that lost the race and reused a concurrent winner rotated token.',
  vouchr_kms_decrypt_total: 'Real KMS/envelope DEK unwraps performed reading credentials.',
  vouchr_egress_denied_total: 'Egress attempts rejected by an allowlist/policy gate.',
  vouchr_egress_error_total: 'Upstream failures (network throw or refresh throw) on an allowed target.',
  vouchr_rate_limited_total: 'Requests refused by the per-(owner, provider) rate limit before any secret was read.',
  vouchr_resolver_failed_total: 'Configured external resolver throws or Vouchr-owned deadlines.',
  vouchr_connect_prompted_total: 'Connect prompts shown to a user.',
  vouchr_connected_total: 'Successful provider connections.',
  vouchr_policy_denied_total: 'Requests denied by policy.',
  vouchr_revoked_total: 'Credential revocations attempted.',
  vouchr_expired_total: 'Expired credentials pruned.',
};

export interface Metrics {
  /** Wire this as the `EventSink` on ConnectionHandle / the broker. Never throws. */
  sink: EventSink;
  /** Render the current state as Prometheus text exposition format (content-type text/plain; version=0.0.4). */
  render(): string;
}

/** Render a label object to a stable, escaped `k="v",k2="v2"` string (empty for no labels). */
function labels(l: Labels): string {
  return Object.entries(l)
    .map(([k, v]) => `${k}=${JSON.stringify(String(v))}`) // JSON.stringify escapes quotes/backslashes/newlines
    .join(',');
}

export function metricsSink(): Metrics {
  const counters = new Map<string, Map<string, number>>(); // name -> labelKey -> value
  const hists = new Map<string, Map<string, Hist>>(); // name -> labelKey -> hist

  const inc = (name: string, l: Labels, by = 1): void => {
    const series = counters.get(name) ?? new Map<string, number>();
    counters.set(name, series);
    const k = labels(l);
    series.set(k, (series.get(k) ?? 0) + by);
  };
  const observe = (name: string, l: Labels, v: number): void => {
    const series = hists.get(name) ?? new Map<string, Hist>();
    hists.set(name, series);
    const k = labels(l);
    const h = series.get(k) ?? { buckets: BUCKETS.map(() => 0), sum: 0, count: 0 };
    series.set(k, h);
    h.sum += v;
    h.count += 1;
    BUCKETS.forEach((b, i) => {
      if (v <= b) h.buckets[i] += 1;
    });
  };

  const sink: EventSink = (e: VouchrEvent): void => {
    switch (e.type) {
      case 'injected':
        inc('vouchr_injected_total', { provider: e.provider, host: e.host, status: e.status, owner_kind: e.ownerKind });
        observe('vouchr_inject_duration_ms', { provider: e.provider }, e.ms);
        break;
      case 'refreshed':
        inc('vouchr_refreshed_total', { provider: e.provider });
        break;
      case 'refresh_lock_wait':
        observe('vouchr_refresh_lock_wait_ms', { provider: e.provider }, e.waitMs);
        if (e.reused) inc('vouchr_refresh_reused_total', { provider: e.provider });
        break;
      case 'kms_decrypt':
        inc('vouchr_kms_decrypt_total', { provider: e.provider }, e.count);
        break;
      case 'egress_denied':
        // No `host` label: a denied target is by definition NOT allowlisted, so the requested host
        // is caller/model-controlled and unbounded — it would blow up Prometheus cardinality. The
        // `reason` label (host/method/path/validator) is the bounded signal you actually alert on.
        inc('vouchr_egress_denied_total', { provider: e.provider, reason: e.reason });
        break;
      case 'egress_error':
        inc('vouchr_egress_error_total', { provider: e.provider, host: e.host, reason: e.reason });
        break;
      case 'rate_limited':
        // `host` is safe cardinality here (unlike egress_denied): a rate_limited event only fires
        // AFTER the allowlist gates passed, so the label space is the bounded allowlisted set.
        inc('vouchr_rate_limited_total', { provider: e.provider, host: e.host });
        break;
      case 'resolver_failed':
        inc('vouchr_resolver_failed_total', { provider: e.provider, source: e.source });
        break;
      case 'connect_prompted':
        inc('vouchr_connect_prompted_total', { provider: e.provider });
        break;
      case 'connected':
        inc('vouchr_connected_total', { provider: e.provider });
        break;
      case 'policy_denied':
        inc('vouchr_policy_denied_total', { provider: e.provider });
        break;
      case 'revoked':
        inc('vouchr_revoked_total', { provider: e.provider, ok: String(e.ok) });
        break;
      case 'expired':
        inc('vouchr_expired_total', {}, e.count);
        break;
    }
  };

  function render(): string {
    const out: string[] = [];
    for (const [name, series] of counters) {
      out.push(`# HELP ${name} ${HELP[name]}`);
      out.push(`# TYPE ${name} counter`);
      for (const [k, v] of series) out.push(`${name}${k ? `{${k}}` : ''} ${v}`);
    }
    for (const [name, series] of hists) {
      out.push(`# HELP ${name} ${HELP[name]}`);
      out.push(`# TYPE ${name} histogram`);
      for (const [k, h] of series) {
        const prefix = k ? `${k},` : '';
        BUCKETS.forEach((b, i) => out.push(`${name}_bucket{${prefix}le="${b}"} ${h.buckets[i]}`));
        out.push(`${name}_bucket{${prefix}le="+Inf"} ${h.count}`);
        out.push(`${name}_sum${k ? `{${k}}` : ''} ${h.sum}`);
        out.push(`${name}_count${k ? `{${k}}` : ''} ${h.count}`);
      }
    }
    return out.join('\n') + '\n';
  }

  return { sink, render };
}
