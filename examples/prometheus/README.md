# Vouchr → Prometheus metrics (over EventSink, dependency-free)

Turn Vouchr's no-secret observability hook into scrapeable Prometheus metrics, **without adding a
runtime dependency**. `EventSink` (`src/core/injector.ts`, type `VouchrEvent`) already emits a
structured, non-secret event on every meaningful broker action; this example aggregates those into
in-memory counters/histograms and renders the Prometheus text exposition format **by hand** (no
`prom-client`, no `prom-*` anything — the repo keeps a 4-runtime-dependency discipline).

- [`metrics.ts`](./metrics.ts) — `metricsSink()`: an `EventSink` plus a `render()` that produces
  exposition text. ~40 lines of rendering, zero dependencies.
- [`serve.ts`](./serve.ts) — a plain Node `http` server exposing `GET /metrics`.

## Running

```bash
node --import tsx examples/prometheus/serve.ts     # http://127.0.0.1:9464/metrics
curl -s http://127.0.0.1:9464/metrics
```

`serve.ts` seeds a short demo sequence of events so a standalone scrape returns non-empty, valid
exposition text with no DB, provider creds, or network. In a real deployment you drop the demo seed
and instead pass `metrics.sink` as the `EventSink` when the broker builds a handle:

```ts
const metrics = metricsSink();
new ConnectionHandle(provider, owner, acting, vault, audit, resolvers, inflight, metrics.sink);
// then mount metrics.render() at GET /metrics on whatever router you already run.
```

## Metrics

| Metric | Type | Labels | Source event |
| --- | --- | --- | --- |
| `vouchr_injected_total` | counter | `provider,host,status,owner_kind` | `injected` |
| `vouchr_inject_duration_ms` | histogram | `provider` | `injected.ms` |
| `vouchr_refreshed_total` | counter | `provider` | `refreshed` |
| `vouchr_refresh_lock_wait_ms` | histogram | `provider` | `refresh_lock_wait.waitMs` |
| `vouchr_refresh_reused_total` | counter | `provider` | `refresh_lock_wait.reused` |
| `vouchr_kms_decrypt_total` | counter | `provider` | `kms_decrypt.count` (incremented by count) |
| `vouchr_egress_denied_total` | counter | `provider,host,reason` | `egress_denied` |
| `vouchr_egress_error_total` | counter | `provider,host,reason` | `egress_error` |
| `vouchr_resolver_failed_total` | counter | `provider,source` | `resolver_failed` |
| `vouchr_connect_prompted_total` | counter | `provider` | `connect_prompted` |
| `vouchr_connected_total` | counter | `provider` | `connected` |
| `vouchr_policy_denied_total` | counter | `provider` | `policy_denied` |
| `vouchr_revoked_total` | counter | `provider,ok` | `revoked` |
| `vouchr_expired_total` | counter | — | `expired.count` (incremented by count) |

These are exactly the `VouchrEvent` kinds that exist in `src/core/injector.ts` — nothing is
invented. Every label is an already-no-secret field copied straight off the event.

## Cardinality is bounded by design

Prometheus dies on unbounded label cardinality. This mapping is safe because every label is a
small, closed set:

- **`host`** is labelled only on `injected` and `egress_error`, where it is always an **allowlisted**
  host: the egress allowlist is checked *before* those events fire, so the set of hosts is your
  provider config, not caller-controlled input. `egress_denied` deliberately does **not** carry a
  `host` label — a denied target is by definition *not* allowlisted, so the requested host is
  caller/model-controlled and unbounded. Alert on its `reason` label instead.
- **`provider`**, **`reason`** (`host`/`method`/`path`/`validator` for denials; static strings like
  `fetch_failed`/`refresh_failed` for errors), **`owner_kind`** (`user`/`channel`), and **`ok`**
  (`true`/`false`) are all fixed enums.
- **`status`** is the set of HTTP status codes your providers actually return — small in practice.

## No user or team identity, by design

`VouchrEvent` **never carries a user id, team id, token, or `secretRef` value** — that is a core
invariant, enforced by `test/observability.test.ts` ("no event ever carries a token, user id, or
team id"). So these metrics are safe to scrape and store: they tell you *what* happened per provider
and host, never *who* it happened to. If you need per-actor attribution, that lives in the audit
table (and the separate audit-stream sink), not in metrics.
