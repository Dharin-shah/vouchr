# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/). Pre-1.0: minor versions may carry breaking changes.

## [Unreleased]

### Added

- **Human-in-the-loop approval for sensitive writes** (#113). New declarative provider knob
  `approval: { methods?, paths?, approver: 'self' | 'admin', ttlMs? }` (default: every non-GET/HEAD
  method, all paths, 5-minute grant TTL) — between "never allowed" (egress) and "always allowed"
  there is now "allowed when a human clicks yes". Enforced in the injector, strictly AFTER every
  egress/allowlist/method/rate-limit gate (an additional gate, never a bypass) and BEFORE the
  secret is read: a matching request with no live grant records a pending approval, posts
  Approve/Deny Block Kit buttons (to the acting user for `'self'`; ephemerally to each eligible
  admin — the same eligibility gate as the channel config commands — for `'admin'`) showing the
  provider, method, and host+path, **never the request body**, and throws the new exported
  `ApprovalRequiredError` (catch-and-stop-turn, exactly like `ConsentRequiredError`). On Approve
  the retried call consumes the grant — SINGLE-USE via the same atomic `DELETE … RETURNING` as the
  OAuth consent state, so two concurrent retries cannot both spend it — and matches only the exact
  (method, host, path) it was minted for (never the payload bytes; tradeoff documented in the
  threat model) **and the exact credential owner**: a union member switch or a per-user→shared mode
  change re-prompts instead of running against a credential the human didn't approve, and a grant is
  purged the moment its credential is deleted or replaced (disconnect / offboard / bulk-revoke /
  reconnect / TTL-expiry — all via the one vault mutation surface, alongside the notification-state
  purge), so it can't outlive a revocation. An `approval.paths` lock inherits the egress guard's
  fail-closed encoded-separator rule (`%2f`/`%5c` requires approval). Method/path knob values are
  validated canonical and normalized (trim + upper-case) at definition time in both `defineProvider`
  and the env loader — a non-matching form like `'POST '` or `'repos'` is rejected/normalized rather
  than silently disabling approval (fail-open). The knob threads through the built-in provider
  configs too (`github({ approval })`, google/gitlab/notion/databricks). Every step is audited
  (`approval_requested` / `approved` / `denied` / `approval_consumed`, approver in the actor column;
  button clicks re-validate the provider against the registry and re-check approver eligibility
  server-side — an ineligible click is rejected and audited) with matching no-secret `approval_*`
  events. The headless broker enforces the same gate and returns
  `403 { "error": "approval_required", "approvalId" }` — the approval surface stays the Slack app.
  Expired prompts/grants are reclaimed (and audited, actor `system`) by the existing TTL sweep. The
  knob is env-declarable on the standalone broker (`VOUCHR_PROVIDERS`), validated fail-closed at
  config load and at `defineProvider`. New `approval_request` table (schema version 4, purely
  additive); new exports `ApprovalRequiredError` + `Approvals` (root and `./headless`). Providers
  without the knob are byte-for-byte unchanged.

- **Dry-run mode** (#116). `createVouchr({ dryRun: true })` / `BrokerOptions.dryRun`
  (`VOUCHR_DRY_RUN=1` for the packaged `vouchr-broker`): the full consent → policy → channel-tools
  → egress → vault → audit machine runs for real, under the invariant that no real network call
  leaves the process on any edge. The OAuth token exchange yields a synthetic credential; the
  Connect button's authorize URL becomes a local, instantly-succeeding redirect into the real
  callback; the outbound provider fetch — after every request gate has passed and the vaulted
  credential was read — returns a `200 { dryRun: true, method, url, wouldInjectAs }` echo that never
  contains the credential (the provider's inject hook runs exactly once, with a redacted
  placeholder); and token refresh / upstream revoke are skipped for dry-run credentials.
  Request-side denials (egress, policy, mode) throw exactly the production errors. Provenance is a
  new system-only `dry_run` column on the connection row (schema v4, additive migration) — never
  the user/provider-controlled account label — so a real account legitimately named "dry-run" is
  never mistaken for synthetic and always revokes normally. Safety rails: startup hard-fails against
  a database holding any non-dry-run credential row ("refusing dryRun against a vault with real
  credentials"); a real row written after startup is refused per-request and never overwritten (the
  synthetic write is an atomic conditional); an external KMS envelope is refused at startup (its
  wrap/unwrap are real network calls); a refused broker reports `/readyz` 503 while `/healthz` stays
  200; and every audit row written in dry-run carries `meta.dry_run: true`. New
  `vouchr.dryRun.completeConsent(user, provider)` test helper completes a prompted consent
  programmatically; `examples/dry-run/` is a fully offline `node:test` suite of a Bolt handler.
  Zero behavior change when the flag is absent.

- **App Home config dashboard** (#111). The app's Home tab (published on `app_home_opened`, and
  re-published after every mutation) is now a console: everyone sees and disconnects their own
  connections (provider + external account, same confirm + revoke flow as the config modal);
  workspace admins — and channel creators when `allowChannelCreatorConfig` is on — additionally
  pick a channel (public/private only; DMs and Slack Connect are filtered AND re-checked
  server-side) and govern it per provider: credential-mode select, tool Enable/Disable, and the
  existing channel-credential modal. Every control routes through the same helpers as the `/vouchr`
  slash equivalents, so authorization gates, DB writes, and audit rows are identical by
  construction; forged block actions (non-admin clicks, invalid modes, nonexistent channels smuggled
  through view metadata) are re-validated server-side, rejected fail-closed, and audited `denied`
  where a slash denial would be. An archived/deleted/ineligible selected channel degrades to a note.
  Requires the `app_home_opened` bot event, the Home tab, and the `channels:read` + `groups:read`
  scopes (see `examples/slack-manifest.yml`); `homeView()` gains an optional `governance` argument
  (backward compatible). Vouchr's publisher defers to a foreign (host-published) Home view instead
  of clobbering it; residual caveat: on a user's very first open there is no current view, so a
  host with its own Home tab races Vouchr once — from the next open the `callback_id` decides.

  **Behavior change:** the first `/vouchr enable|disable` (or Home Enable/Disable click) on a
  channel with no explicit tool rows now materializes the full allowlist, so flipping one provider
  no longer silently disables every other. Previously a first `/vouchr disable X` flipped the
  channel into allowlist mode and knocked out all unlisted providers channel-wide while auditing
  only X; the config modal already materialized — the shared helper now applies the same rule to
  all surfaces. Only the provider the admin actually targeted is audited. Additionally,
  `/vouchr enable|disable` and `/vouchr configure` (and their App Home buttons) now refuse
  ineligible channel classes — archived, externally shared / Slack Connect, DMs — with the same
  fail-closed rule `mode` already enforced; previously the tool-allowlist bit could be flipped and
  the credential modal opened in an externally shared channel.

- **Credential health notifications** (#117). When a token refresh fails DEFINITIVELY
  (`invalid_grant`, or a bare 400/401 from the token endpoint — classified by the new exported
  `TokenEndpointError`; transient blips never count, and neither do operator-side OAuth errors
  like `invalid_client` that no user reconnect can fix) the owner gets a DM whose Connect button
  mints a fresh single-use consent state on click (so the link cannot expire before it's read);
  the TTL sweep additionally warns owners within 72h of a connection's idle/max-age ceiling
  (only for TTL dimensions longer than 72h — a shorter TTL would make every live connection
  permanently "expiring" and nag daily forever) and reports actual deletions. Channel-owned
  credentials notify the last configuring admin (skipped
  when unknown — the channel is never spammed). DMs are debounced to one per (owner, provider,
  type) per 24h via the new persistent `notification_state` table (additive migration; schema
  version 3): the window is CLAIMED atomically before sending — no duplicates across replicas —
  and released if the send fails so the next event retries (a process crashing between claim and
  send loses that window's DM; the next window retries). Reconnect/disconnect clear the state,
  atomically with the connection write itself. New `createVouchr`/`BrokerOptions` option
  `onCredentialHealth` replaces the default DMs
  with your own notifier (headless brokers have no Slack client, so they only get the hook); the
  same hook passed to `sweepExpired` hears `expiring_soon`/`expired`. New exports:
  `CredentialHealthEvent`, `CredentialHealthHook`, `NotificationState`,
  `HEALTH_NOTIFY_DEBOUNCE_MS`, `TokenEndpointError` (also on `./headless`). Events carry the
  owning principal and provider — never token material. All fire-and-forget hooks
  (`onCredentialHealth`, `onEvent`, `auditSink`) now accept async functions safely: their
  `=> void` signatures always admitted async functions, and a rejection is now swallowed exactly
  like a throw — never an unhandled rejection (which kills modern Node).


- **MCP-aware egress proxy on the headless broker** (#65) — new route `POST /v1/mcp` for providers
  whose tool surface is an MCP server over Streamable HTTP. Same envelope style and the same
  fail-closed pipeline as `/v1/fetch` (signed identity — never the body, single-use `jti` replay
  guard, policy + channel-tool checks, egress host/https/method allowlist enforced BEFORE the
  credential is read, same inject/denied audit rows), with the credential injected inside the
  broker and never revealed to the caller. What `/v1/fetch` can't do, this adds: the upstream
  response passes through **as-is and streamed** (`text/event-stream` included, never buffered),
  and the MCP plumbing headers (`Mcp-Session-Id`, `MCP-Protocol-Version`, plus request
  `Accept`/`Content-Type`) pass through in both directions. The route is a **declarative
  per-provider opt-in**: the new `defineProvider` knob `mcp: { paths, allowContentTypes? }`
  (validated at definition time) is required or `/v1/mcp` refuses the provider (403, audited like
  an egress denial) even when it is POST-enabled for `/v1/fetch` — `paths` locks the reachable
  endpoint with the `egressPaths` matching semantics (shared matcher; encoded separators refused),
  and a response outside `allowContentTypes` (default `application/json` + `text/event-stream`,
  bare-type match) is withheld unread, closing the raw-passthrough gap around `/v1/fetch`'s
  response gates (`allowedContentTypes`/`maxResponseBytes` do not run here). Session ids are
  opaque and potentially sensitive (MCP security guidance): relayed verbatim, never stored,
  logged, or audited, and never accepted as authentication — the broker stays a stateless
  credential-injecting proxy (the MCP session lifecycle remains the host's MCP client's job; mint
  a fresh `identityToken` per JSON-RPC call). Per the MCP spec, the unsupported optional GET
  listening stream and client-initiated DELETE termination answer `405` + `Allow: POST`. MCP
  `callTool` can mutate, so the route sits behind the same two write opt-ins as a `/v1/fetch`
  POST (`allowWrites` + provider `egressMethods` including POST). Open streams get ceilings: new
  `BrokerOptions.maxStreamBytes` (default 8 MiB; a counting transform terminates the stream when
  exceeded — upstream aborted, socket destroyed, never a clean end) and
  `BrokerOptions.maxStreamMs` (default 5 min; a timer aborts the upstream fetch) — both validated
  finite and > 0 at `createBroker` (a NaN/Infinity cap would silently fail open). A provider's
  `egressResponse.maxBytes` (#110) still applies first and the stricter cap wins (413, nothing
  relayed) — but the injector enforces it by buffering up to that cap, so leave it unset on
  streaming providers. The standalone broker (`vouchr-broker` / GHCR image) declares the knob in
  its `VOUCHR_PROVIDERS` JSON — `"mcp": { "paths": ["/mcp"] }` is now an allowed, config-validated
  declarative field (see `guides/DEPLOYMENT.md` § Provider config). New export: `BrokerMcpRequest`
  (also on `./headless`). Docs in `guides/HEADLESS.md` § MCP servers.


- **Union mode: explicit opt-in + owner notification** (#112). New `createVouchr` option
  `unionRequiresOptIn` — when `true`, `union` resolution only borrows channel members with an
  explicit opt-in row for that (channel, provider), stored in the new `union_optin` table
  (additive migration; schema version 2). Opt in by completing a Connect prompted from the union
  channel (the OAuth callback records it via the consent row's channel, only when that channel is
  in union mode) or with the new `/vouchr union join <provider>` (requires a connected credential,
  else you get the Connect prompt); `/vouchr union leave <provider>` is effective on the next
  resolution, and disconnect / offboarding / break-glass revoke purge opt-ins with the credential.
  Joins/leaves are audited as a new `union` action (`{ channel, event: 'join'|'leave' }`).
  Separately (regardless of the flag), when a borrowed union credential actually serves a request
  by someone other than its owner, the owner gets a courtesy DM (who/where, `/vouchr audit` to review,
  `/vouchr union leave` to stop), debounced per-process to one per (owner, provider, channel) per
  hour and never sent on self-use; the audit table remains the record. New exports: `UnionOptin`,
  `eligibleUnionMembers`, `joinUnion`, `leaveUnion` (also on `./headless`) — the broker trusts
  the host's signed `actingMemberId`, so a headless host applies the same rule itself; broker-
  hosted OAuth callbacks record opt-ins like Bolt ones when `channelConfig` is wired.

  **DEPRECATION: `unionRequiresOptIn` defaults to `false`** (any connected member is borrowable —
  today's behavior, byte-compatible). The default **flips to `true` at the next breaking
  release** — set it explicitly now.

- **Signed GHCR images** (#131) — the release workflow now keyless-signs every published
  `vouchr-broker` image with cosign (Sigstore), attaches a CycloneDX SBOM attestation, and embeds
  BuildKit SLSA provenance (`mode=max`). The job then verifies the signature and the attestation
  against the pushed digest in-job, so a release cannot go green with an unverifiable image.
  Copy-paste verification + digest-pinning recipe in `guides/DEPLOYMENT.md`
  § *Verifying the GHCR image (cosign, SBOM, provenance)*.

- **Structural response constraints at the injection boundary** (#110) — new declarative provider
  knob `egressResponse: { maxBytes?, allowContentTypes?, stripHeaders? }`, enforced in the injector
  after the fetch returns and before the Response reaches the caller, so the Bolt handle and the
  headless broker inherit it identically. `maxBytes` caps the response body: fast-fail on a
  declared Content-Length, then a real byte counter while streaming — an over-cap body is aborted
  at the cap (the stream is cancelled, never buffered past it) and **never returned, not even
  partially**. `allowContentTypes` is a case-insensitive allowlist matched exactly against the
  bare media type (parameters ignored; a missing header fails closed), checked before any body
  byte is read. Breaches throw (`ResponseBlockedError` internally;
  the broker maps size → 413, content-type → 502, both as a static `response blocked`), emit a new
  no-secret `response_denied` `VouchrEvent` (`reason: 'content_type' | 'size'`), and write a
  `denied` audit row in the egress-denial meta shape (hostname + static reason + byte count — never
  the header value or body content). Additionally — opt-in or not — **`Set-Cookie` is now always
  stripped from every provider response** (3xx included): a credential-adjacent artifact the agent
  has no business seeing. Compliant responses pass through byte-identical minus stripped headers;
  providers without the knob are otherwise unchanged.

- **Per-handle rate limiting at the injection boundary** (#114) — new declarative provider knob
  `rateLimit: { perMinute, burst? }` (absent = unlimited; nothing changes for existing providers).
  The token bucket is keyed `(owner, provider)` and checked in the injector BEFORE the vault read,
  so a throttled request never touches the secret — the same discipline as the egress gates. On
  deny: the new exported `RateLimitedError` (carrying `retryAfterMs`), a no-secret `rate_limited`
  `VouchrEvent`, and a `rate_limited` audit row (hostname + owner kind only, never the url). Bolt
  tells the acting user ephemerally ("Slow down: … try again in Xs"); the headless broker maps it
  to HTTP 429 with a `Retry-After` header (`BrokerError.retryAfterMs` documents the payload).
  Buckets live in an in-memory per-process store by default; a multi-instance deployment can plug
  a shared backend via the new `VouchrOptions.rateLimitStore` / `BrokerOptions.rateLimitStore`
  (`RateLimitStore` interface). New exports: `RateLimitedError` and `RateLimitStore` (also on
  `./headless`).

- **Master-key rotation for the direct (non-KMS) path** (#115). New env `VOUCHR_MASTER_KEYS` =
  comma-separated `id:base64key` entries: the first entry encrypts all new writes (a new keyed
  ciphertext scheme that stores the key id), every entry is a decryption candidate, and an unknown
  stored key id fails closed with an error naming the id. `VOUCHR_MASTER_KEY` alone keeps working
  bit-for-bit unchanged — no forced migration. New CLI verb `vouchr rekey [--dry-run]` re-encrypts
  every stored ciphertext (connection token columns + installation bot token/data) under the
  primary key: idempotent, interrupt-safe, concurrent-refresh-safe, counts-only output; `--dry-run`
  reports blobs per key id/scheme (the runbook's "zero old-key rows" check). Envelope (KMS) rows
  are untouched — that path rotates in the KMS. Rotation runbook + direct-vs-KMS decision note in
  `guides/DEPLOYMENT.md` § Key rotation. New exports: `loadKeyring`, `Keyring`, `MasterKeys` (also
  on `./headless`); `Vault` and `DbInstallationStore` now accept a `Buffer` or a `Keyring`.
  Internal `loadMasterKey` (never exported from the package root) is superseded by `loadKeyring`.

- **Schema version marker + downgrade guard** — `openDb()` now records a monotonic
  `schema_version` in a new `meta` table and fails closed (with an error naming both versions and
  the remedy) when the database was written by a NEWER vouchr, instead of running old migrations
  against a newer schema. Fresh databases are stamped with the current version; existing
  marker-less databases are assumed to be pre-marker (≤ v0.2.x) — safe, because every schema change
  up to the marker's introduction is an idempotent in-place migration `openDb()` already runs —
  and are stamped after migrating. Schema *upgrade* tests (`test/migration-upgrade.test.ts`) now
  seed a database from a frozen v0.2.0 fixture (`test/fixtures/schema-v0.2.0.ts`) and prove, on
  SQLite and Postgres, that migrations are lossless (every row survives, encrypted tokens still
  decrypt, connect/egress work on the migrated store) and idempotent.

- **Private previews** — a per-channel, per-provider preview-visibility bit, orthogonal to the
  credential mode. With `/vouchr preview <provider> private` (admin-gated + audited, also a checkbox
  in the no-arg `/vouchr` config modal), agent output posted through the new
  `context.vouchr.preview(provider, { title, lines })` goes ephemerally to the requester only, with
  a Share button: a single-use, recipient-bound claim (checked server-side, like the OAuth `state`)
  that reposts the reviewed content publicly, attributed to the sharer and audited as `preview`.
  Default `public` posts normally — no behavior change for unconfigured channels. `preview()`
  enforces the same `authorizeProvider` decision as `connect()` (a policy-denied or tool-disabled
  provider posts nothing, with the same audited denial), and the pending store holds only
  render-normalized content (clipped to what the recipient could actually have reviewed).
  `ToolManifestEntry` gains `visibility`; new exports: `PreviewVisibility`, `PREVIEW_VISIBILITIES`,
  `isPreviewVisibility`, `PendingPreviews`, `previewBlocks`, `previewPostBlocks`,
  `PREVIEW_SHARE_ACTION`, `PREVIEW_DISMISS_ACTION` (also on `./headless`). Pending previews live in
  memory with a 10-minute TTL and are never persisted (provider data stays out of the database).

- `POST /v1/manifest` — the channel-scoped tool manifest for the verified identity (the headless
  analogue of Bolt's `toolManifest()`), so non-Bolt hosts can read `visibility`/`mode`/`enabled`
  before posting output. One shared core builder (`buildToolManifest` in `core/authz`) feeds both
  transports, and `enabled` is exactly "`authorizeProvider` would allow it". The channel-independent
  `GET /v1/manifest` is unchanged. New wire type `BrokerChannelManifestResponse`.

### Fixed

- **Approval grants could be spent on changed query parameters** (GHSA-pg84-mp83-2p82). The
  human-in-the-loop approval key bound only (method, host, path), so an approval of
  `POST /transfer?to=alice&amount=10` was indistinguishable from — and spendable by —
  `POST /transfer?to=attacker&amount=1000000`. The grant now also binds the query BYTE-EXACT, as
  a digest of the exact query string sent upstream (no sorting/normalization — upstream parsers
  treat reordered or duplicated parameters differently, so any textual change re-prompts). Query
  parameter names and values are BOTH caller-controlled and may carry PII/secrets, so neither is
  ever persisted, audited, or rendered: the Approve/Deny prompt shows only the parameter COUNT
  and states the exact query string is bound byte-for-byte; the threat model / README now state
  explicitly that the request body remains outside the key, so approval must not be treated as
  covering the exact action for body-parameterized endpoints. New `approval_request.query_hash`
  column (schema version 5, purely additive) lands as ONE atomic ALTER whose `DEFAULT 'pre-v5'`
  marks anything a pre-v5 writer creates as unmatchable, and the migration purges all existing
  (minutes-lived) approval rows whenever the stored schema version is below 5 — crash-safe: the
  version stamp lands only after the purge, so an interrupted upgrade re-heals on the next open.
  `ApprovalRequiredError` gains a display-only `queryParamCount` field and `approvalBlocks` a
  required `queryParamCount` input. **Rolling-deploy note:** pods running code older than this
  change consume grants WITHOUT the query binding — drain pre-upgrade pods promptly; the
  protection is complete only once every replica enforces `query_hash`.

- **Provider id unescaped in the connect prompt** (#178). `connectBlocks` and its three plain-text
  fallback notifications interpolated the provider id into Slack mrkdwn without `escapeMrkdwn`. The
  id is registry-validated, so this was defense-in-depth, but SEC-5 takes no exception; the connect
  prompt now escapes it like `connectionLine`/`connectedBlocks`. (The button label is Slack
  `plain_text`, which renders literally, so it is intentionally left raw.) Remaining mrkdwn sites
  that still interpolate a provider id or raw slash argument are tracked in a follow-up.

- **Reflected HTML injection on the OAuth callback error path** (#177). A hostile provider holding a
  valid in-flight `state` could redirect the victim back with `?error=<markup>`; the callback echoes
  it into `OAuth error: <x>` and the Bolt route served it with Express's default `text/html`,
  executing the markup on the Vouchr host origin. Error responses are now served as
  `text/plain; charset=utf-8` with `X-Content-Type-Options: nosniff`, so any echoed value is inert.
  (The headless broker route already routed these through the escaping `landingHtml`.)

- **Unescaped provider-controlled labels in two post-connect surfaces** (#176). The OAuth-callback
  confirmation DM and `connectedBlocks` interpolated the provider-reported external account label
  (and, in `connectedBlocks`, the token-response scope string) into mrkdwn raw, so a hostile
  provider's account probe could render a live `<!channel>` broadcast or a forged
  `<https://evil|click>` link (SEC-5). Both now escape via `escapeMrkdwn`, matching
  `connectionLine`.

- **Connection leak on refresh-signalling failure** (#168). When a provider call came back `401`
  and the refresh signalling itself threw (vault/db error), the discarded 401 response body was
  never read or cancelled, pinning its socket until GC. The injector now cancels the abandoned
  body before rethrowing the refresh error; a refresh that yields no new token still returns the
  401 with its body intact.

## [0.2.0] - 2026-07-06

### Added

- `/vouchr` with **no subcommand** now opens an interactive config modal (discoverability). Everyone
  sees their connected accounts (each with a confirm-gated Disconnect button) and the channel's tool
  manifest; admins additionally get a per-provider mode select + Enabled checkbox that route to the
  same `setChannelMode` / `ChannelTools.setEnabled` mutations as the slash commands, with authorization
  re-checked server-side on submit (a forged `view_submission` from a non-admin is rejected + audited).
  The text subcommands (`status`, `mode`, `enable`/`disable`, …) are unchanged. New `configModal`
  Block Kit builder + `CONFIG_CALLBACK`, exported for headless hosts. (#109)

- `vouchr revoke` CLI — break-glass bulk revocation for incident response:
  `vouchr revoke --provider <id> [--team|--user|--channel] [--yes]`. Dry-run by default (prints a
  no-secret table, mutates nothing); `--yes` deletes each matched credential locally FIRST, then
  best-effort upstream revoke, and clears pending consent + thread grants for the scope (even where no
  live connection matched). Local deletion is guaranteed even if the master key / provider config is
  unavailable; refuses to run without `--provider` or with an empty scope flag. (#103)

- `/vouchr stats` — admin per-channel usage analytics (last 30 days). For each brokered tool enabled in
  the channel: total injections, distinct acting humans, last-used time, and a `never used` flag for
  enabled-but-idle tools (dead weight to prune), ending with a `disable` hint. Admin-gated (same gate as
  `mode`/`enable`) + audited on refusal; ephemeral. New `Audit.statsByChannel` (one GROUP BY, backend-
  agnostic) and a `statsBlocks` renderer. Distinct-humans counts the requester (`COALESCE(actor,
  user_id)`), so union usage is attributed to the caller, not the borrowed member.

### Changed

- Inject audit rows now record the **origin channel** for every credential mode, not just channel-owned
  (`shared`). Per-user (the default), `session`, and `union` usage previously left `channel` null, so
  per-channel analytics (`/vouchr stats`) could not see them. The `ConnectionHandle` gains an optional
  trailing `originChannel` argument (defaults to null → prior behavior); Bolt and the broker pass the
  request's channel.

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
