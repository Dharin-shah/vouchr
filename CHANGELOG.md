# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/). Pre-1.0: minor versions may carry breaking changes.

## [Unreleased]

### Added

- `/vouchr stats` — admin per-channel usage analytics (last 30 days). For each brokered tool enabled in
  the channel: total injections, distinct acting humans, last-used time, and a `never used` flag for
  enabled-but-idle tools (dead weight to prune), ending with a `disable` hint. Admin-gated (same gate as
  `mode`/`enable`) + audited on refusal; ephemeral. New `Audit.statsByChannel` (one GROUP BY, backend-
  agnostic — coerces Postgres's string COUNT/BIGINT and lowercased aliases) and a `statsBlocks` renderer.

- `/vouchr audit` — a self-service, in-Slack view of credential usage. A user sees the last ~20 audit
  events attributed to them (their own credential's usage across channels, including union-mode
  borrows); a channel admin can additionally run `/vouchr audit channel` for the current channel's
  channel-owned usage. Strictly scoped — a non-admin never sees another user's or another channel's
  rows — and `meta` is never rendered (the read query omits it). New `Audit.listByOwnerUser` /
  `Audit.listByChannel` read methods and an `auditBlocks` renderer. In union mode the inject audit now
  also populates the `actor` column with the real triggerer (a plain userId, already in `meta`), so the
  owner's view shows *who* borrowed their credential; the renderer escapes Slack mrkdwn so a stored
  value can never forge a link or mention.

- Headless broker audit-read parity: `POST /v1/audit` returns the caller's own last ~20 audit events
  (headless analogue of `/vouchr audit`), and `POST /v1/admin/audit` returns the signed channel's
  events (all activity tagged with the channel) behind the SIGNED `isAdmin` claim (analogue of
  `/vouchr audit channel`). Same
  invariants as the Slack side: strict per-user / per-channel scoping enforced in the core read query,
  `team_id` always constrained, and NO `meta` in the response. Adds the `BrokerAuditResponse` wire type
  (exported from both entry points) and wire-contract goldens. Closes the last surface-parity gap
  (raw-secret ingest stays intentionally Bolt-only).

### Security

- Headless broker OAuth landing page: `landingHtml()` now HTML-escapes its `title`/`body` internally
  instead of relying on every call site to pre-escape (#52 hardening). No active reflected-XSS path
  existed — the two call sites already escaped — but the helper shape allowed a future caller to
  reintroduce one; escaping at the choke point removes that footgun. Adds a regression test.

## [0.2.0-rc.1] - 2026-07-03

### Breaking

- Removed the production self-gating feature: the `production` option (Bolt `VouchrOptions` and the
  broker), the `VOUCHR_PRODUCTION` env var, and the `assertProductionConfig` / `isProduction` exports
  from `src/core/options`. Vouchr no longer refuses to boot on SQLite or without a KMS envelope —
  it boots with whatever backend it is given and lets the integrating/hosting system decide its own
  infra requirements. Postgres + a KMS envelope remain the recommended configuration for
  multi-instance / production deployments (see `guides/DEPLOYMENT.md`), just no longer enforced.
- `ConnectContext`'s constructor now takes a single `ConnectContextDeps` object instead of ~20
  positional arguments (`new ConnectContext({ identity, channel, client, ... })`). Optional fields
  keep their previous defaults, so runtime behavior is identical — this is a source-level change
  only. `ConnectContext` is effectively internal (it types `context.vouchr`), but it is publicly
  exported, so this is technically a breaking source change. `ConnectContextDeps` is now exported
  from the package root for consumers that construct it directly.

### Added

- Bolt-free `./headless` entry point (`@vouchr/core/headless`): re-exports exactly the headless broker
  surface (`createBroker`, `buildBrokerServer`, identity minting/verification, providers, owner model)
  plus the low-level building blocks (`openDb`/`Db`, `Vault`, `Audit`, `Consent`, `SessionGrants`,
  `sweepExpired`, `Policy`, `ChannelTools`) so a pure-headless consumer can construct a broker without
  pulling `@slack/*` into the module graph (enforced by `test/headless-boltfree.test.ts`). Typed wire
  response types (`BrokerFetchResponse`, `BrokerStatusResponse`, `BrokerResolveResponse`, etc.) are
  exported from both entry points.
- Headless admin config routes — `POST /v1/admin/mode`, `POST /v1/admin/tools`, `GET /v1/admin/config`
  — mirroring the Bolt `/vouchr` channel-governance commands, gated on the SIGNED `isAdmin` claim
  (admin authority never comes from the request body). Adds `BrokerAdminOkResponse` /
  `BrokerAdminConfigResponse` types. Raw-secret ingest stays Bolt-only; the headless broker remains
  reference-only for credential ingest.
- Bolt Block Kit template builders exported from the package root: `connectedBlocks`,
  `consentDeniedBlocks`, `statusBlocks`, `disconnectConfirmBlocks`, and `homeView`.
- Opt-in `allowChannelCreatorConfig` flag (default off) and `isChannelAdmin` helper: when enabled, a
  Slack channel's creator — not only a workspace admin — may run `/vouchr` admin config commands.
  Default off preserves workspace-admin-only behavior. Bolt-only.

### Changed

- `safeEmit` extraction and `toBuffer` deduplication (internal refactors, no behavior change).

### Fixed

- Egress-failure telemetry: a provider outage or refresh breakage now fires an `egress_error` event and
  writes an attributable (no-secret) audit row instead of being a silent 502. Typed errors
  `EgressBlockedError` and `NoConnectionError` replace opaque throws (mapped to `403` / `409` on the
  broker). Credentials are verified before enumeration, and union-mode non-repudiation now records the
  real triggerer alongside the acted-as member on the failure path too (`triggeredBy`).

## [0.1.0]: production target (pending external validation)

The 0.1.0 line is the first production-intended release. Everything below is on `main` and
green in CI (typecheck + full suite incl. a real Postgres backend). It is **not declared
production until an independent security review / pen test is completed**. That is the one gate
that can't be self-served. There is intentionally no `v0.1.0` git tag yet; cut it after external
validation passes.

### Core capability

- Capability-handle broker: `context.vouchr.connect(provider)` returns a handle whose `fetch()`
  injects the secret only at the outbound HTTP boundary: the agent, LLM, and chat never see it.
- Per-user and per-channel (admin-configured, shared) credential ownership; owner vs acting-human
  kept separate for audit attribution.
- Declarative provider model: OAuth2 + static-key providers, custom header injection, PKCE,
  Basic token auth, form/JSON token bodies, per-provider egress allowlists; built-ins for
  GitHub, Google, GitLab, Notion.
- Storage: SQLite (default) or Postgres, behind a small async driver.

### Security

- At-rest AES-256-GCM (fresh IV per secret); optional KMS-style **envelope encryption** via an
  `EnvelopeProvider` (per-secret data key wrapped by an external KEK), backward compatible.
- External secret references (e.g. AWS Secrets Manager ARN) resolved just-in-time, never persisted.
- Egress allowlist checked before any secret is read; **https required** (loopback exempt);
  redirects not auto-followed with the credential attached. Optional path/method/validator egress refinement.
- Single-use OAuth `state` (atomic `DELETE … RETURNING`) + PKCE; full owner-key tenant isolation.
- **Upstream token revocation** on disconnect/offboard (best-effort, audited), per-provider.
- Defensive **audit redaction** of credential-shaped values; channel is a first-class audit column.
- Channel-class restriction: shared channel creds refused in Slack Connect / externally shared,
  DM/group-DM, and archived channels (fail-closed).
- Policy gate applied consistently to per-user and shared-channel paths; optional global default-deny.
- Opt-in `isAdmin` override and `requireChannelMembership` enforcement.

### Lifecycle & operations

- Token auto-refresh (single-flight per owner+provider), idle/max-age TTL + sweep, offboarding on
  Slack deactivation, and cross-team `offboardUserEverywhere` for SCIM/Enterprise-Grid deprovisioning.
- Multi-workspace support via a DB-backed `DbInstallationStore` (per-workspace bot token resolution).
- No-secret observability `EventSink` (connect/inject/refresh/deny/revoke/expire events).
- Operator CLI (`bin/vouchr.ts`): credential inventory, channel config, `doctor`, provider `health`.

### Channel tool plane

- Per-channel provider enablement (`channel_tool`), channel-filtered `toolManifest()`, and
  `/vouchr tools | enable | disable | mode` (admin-gated). Backward compatible (a channel with no
  rows enables all).

### Developer & supply-chain

- Transport-agnostic core enforced by `test/architecture.test.ts`, enabling a sidecar + thin
  clients (reference implementation in `examples/sidecar`).
- CI: typecheck + tests (with Postgres) and a security workflow (npm audit, gitleaks, CycloneDX
  SBOM) + dependabot. Property/fuzz tests for egress, redaction, policy, state, and URL building.
- Docs: README, SECURITY.md, THREAT-MODEL.md, ARCHITECTURE.md, SECURITY-WHITEPAPER.md, DEPLOYMENT.md
  (incl. key-rotation and backup/restore runbooks), plus examples for Bolt, Google, internal API keys,
  AWS Secrets Manager, MCP gateway, sidecar, SCIM, and a Postgres+KMS production template.
- Node ≥ 20.6.

### Deferred (intentionally out of 0.1.0)

- Intent/session narrowing (enterprise; egress path/method limits provide a baseline today).
- Signed releases / provenance (needs publish infrastructure; `release.yml` is manual-only for now).
- External security review / pen test (the production gate).
