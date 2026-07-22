# Dry-run: test your integration with no external network

`dryRun: true` runs your real Vouchr wiring — consent state, channel modes, policy, tool
allowlists, egress gates, vault, audit — under one invariant: **no real network call leaves the
process on any edge** (outbound fetch, OAuth token exchange, token refresh, upstream revoke). No
Slack app, no provider OAuth app; only the required local PostgreSQL.

Run the suite:

```bash
npm run example:dry-run   # or: node --import tsx --test examples/dry-run/app.test.ts
```

Note: [`app.test.ts`](./app.test.ts) imports `testDbUrl` from this repo's internal test support —
in your own repo, point `databaseUrl` at a fresh, dedicated PostgreSQL schema instead.

## What is real, what is synthetic

- **Deny-by-default:** a channel enables nothing until an admin opts a provider in, so a test first
  calls `vouchr.dryRun.enableTool(admin, channel, providerId)` — the programmatic form of an admin
  running `/vouchr enable <provider>` (or the App Home toggle). Without it the first `connect()` in a
  channel is refused with `ToolDisabledError` before any consent. (DMs are personal/ungoverned and
  need no enable.)
- `connect()` posts the real Connect prompt, but the authorize URL is a local,
  instantly-succeeding redirect into the real OAuth callback. Complete it by "clicking" it, or from
  a test with `vouchr.dryRun.completeConsent(user, provider)` — either way the real callback writes
  a synthetic credential marked `external_account: 'dry-run'` through the real vault path.
- `handle.fetch()` passes every request gate (policy, tool allowlist, host/path/method/https, rate
  limits), reads the (synthetic) credential from the vault, and then returns a synthetic
  `200 { dryRun: true, method, url, wouldInjectAs }` echo instead of calling the provider. The
  credential value never appears in the echo; token refresh and upstream revoke are likewise
  skipped for dry-run credentials.
- Request-side denials are real: a host missing from `egressAllow` or a policy-denied channel
  throws exactly the production error — that is the point: validate your allowlists and consent
  handling in CI.

## Safety rails

- Provenance is a system-only `dry_run` column on the credential row (never the
  user/provider-controlled account label), so a real account legitimately named "dry-run" is never
  mistaken for synthetic.
- Startup hard-fails if the database already holds any non-dry-run credential ("refusing dryRun
  against a vault with real credentials"), so the flag can't be flipped on non-empty production
  state; a real row written *after* startup is refused per-request and never overwritten (the
  synthetic write is an atomic conditional).
- Dry-run requires a **local master key** — an external KMS envelope is refused at startup (its
  wrap/unwrap are real network calls).
- Audit rows written in dry-run carry a `dry_run: true` marker in `meta`.

## Headless

The broker takes the same flag (`BrokerOptions.dryRun`, or `VOUCHR_DRY_RUN=1` for the packaged
`vouchr-broker`): `/v1/connect` mints a URL pointing at the broker's own callback — GETting it
completes consent — and `/v1/fetch` returns the echo.
