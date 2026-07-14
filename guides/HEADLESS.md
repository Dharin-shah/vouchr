# Headless HTTP Broker

Use `createBroker()` when your Slack-facing service and agent worker are separate processes.
The Slack-facing service verifies the user, mints a short-lived identity token, and workers call
Vouchr over HTTP. The token stays inside Vouchr.

If Slack should remain the built-in human/admin experience, start with the
[hybrid Slack control-plane guide](./HYBRID.md). This document is the lower-level HTTP/API contract.

> [!WARNING]
> On the current stock packaged broker, Slack-written channel tool settings are not enforced
> ([#240](https://github.com/Dharin-shah/vouchr/issues/240)), declarative static channel policy is not
> loaded ([#236](https://github.com/Dharin-shah/vouchr/issues/236)), reference-route validation remains
> open ([#53](https://github.com/Dharin-shah/vouchr/issues/53)), and broker denials do not automatically
> render Slack recovery prompts ([#194](https://github.com/Dharin-shah/vouchr/issues/194)). The low-level
> `createBroker()` API exposes the relevant stores/hooks, but do not mistake that programmatic surface
> for complete packaged hybrid behavior.

Import from the Bolt-free entry point so no `@slack/*` package is loaded:

```ts
import { createBroker, loadIdentityConfig, mintIdentity } from '@vouchr/core/headless';
```

`@vouchr/core/headless` re-exports exactly the headless surface — `createBroker`, `buildBrokerServer`
(env → wired server), identity minting/verification, providers, the owner model, and the low-level
building blocks (`openDb`, `Vault`, `Audit`, `Consent`, `SessionGrants`, `sweepExpired`, `Policy`,
`ChannelTools`) — plus the typed wire response types (`BrokerFetchResponse`, `BrokerStatusResponse`,
`BrokerAdminConfigResponse`, …). The root `@vouchr/core` entry still exports everything, including the
Bolt adapter.

Headless is primarily the credential **use path**, not a replacement for Slack consent. Users still
connect or approve access through the Slack app first (or through the headless OAuth flow when it is
mounted).

## Making a request

The Slack-facing service verifies Slack, loads the same deployment identity as the broker, and mints
a fresh short-lived `identityToken` for each call:

```ts
const identity = loadIdentityConfig(process.env);
const identityToken = mintIdentity({ teamId, userId, channel, threadTs }, identity);
```

The worker then calls `POST /v1/fetch`:

```json
{
  "handle": { "provider": "github", "owner": "user" },
  "identityToken": "<signed by your Slack-facing service>",
  "method": "GET",
  "path": "/user"
}
```

The broker resolves the user from the signed token, performs the provider request inside Vouchr, and
returns only the provider response.

### Bounded failure and retry contract

The exported `BrokerError` type describes functional-route JSON errors (`/readyz` deliberately uses
only `{ "ok": false }`). Resource-bound responses that a worker should handle explicitly are:

| HTTP | Body | Caller action |
| --- | --- | --- |
| `413` | `{ "error": "request body too large" }`, `{ "error": "response too large; narrow your query or endpoint" }`, or `{ "error": "response blocked" }` | Do not retry unchanged. Reduce the request or choose a narrower provider endpoint. |
| `429` | `{ "error": "rate limited", "retryAfterMs": 1000 }` | Honour `Retry-After`, then retry if the operation itself is safe to retry. |
| `503` | `{ "error": "overloaded", "scope": "global", "retryAfterMs": 1000 }` (scope may instead be `provider`) | Honour `Retry-After`. The scope is a fixed operator signal, never a provider id or request value. |
| `504` | `{ "error": "upstream timed out" }` | Treat the outcome as unknown. Retry only a known-idempotent operation; never automatically replay an uncertain write. |

Identity assertions are single-use. **Mint a fresh `identityToken` for every retry**, including a
retry after `429`, `503`, or `504`; never infer from the error scope whether the earlier assertion
was consumed. This rule keeps clients correct if admission moves or another gate consumes the token
before returning. A `Retry-After` value is a back-pressure hint, not a guarantee that capacity will
be available at that instant.

## Capability matrix: Bolt vs headless

One core, two front doors — both reach the same credential boundary.

| Capability | Bolt (`/vouchr`) | Headless broker |
| --- | --- | --- |
| Use a user's own credential | ✅ `connect()` | ✅ `POST /v1/fetch` (`owner:"user"`) |
| Use a `shared` channel credential | ✅ | ✅ `owner:"channel"`, opt-in `VOUCHR_CHANNEL_MODES=1` + signed channel-fact claims (#51) |
| Set the channel mode (`shared`/`per-user`/`session`) | ✅ `/vouchr mode` | ✅ `POST /v1/admin/mode` (admin claim) |
| Toggle a channel's tool allowlist | ✅ `/vouchr enable`/`disable` | ⚠️ route exists with injected `ChannelTools`, but first-write parity and packaged wiring both remain #240 |
| Read the channel's modes + tool allowlist | ✅ (implicit) | ⚠️ route exists, but packaged broker has no persisted tool store (#240) |
| See where a credential was used (audit) | ✅ `/vouchr audit` · `/vouchr audit channel` (admin) | ✅ `POST /v1/audit` (self) · `POST /v1/admin/audit` (channel, admin claim) |
| Call an MCP server (Streamable HTTP, SSE + session headers) | ✅ in-process via the `connect()` handle's `fetch` | ✅ `POST /v1/mcp` (streamed passthrough; opt-in `mcp` provider knob) |
| Ingest a **raw** key/secret | ✅ private modal (`configure` / key setup) | ⚠️ intended reference-only boundary; current validation gap is #53, so path-block the routes |
| Point a credential at a secret-manager **reference** | ✅ | ⚠️ routes exist; reference validation parity/readiness remains #53 |
| Approve a human-in-the-loop write (`approval` provider knob, #113) | ✅ Approve/Deny buttons for in-process use | ⚠️ broker enforces 403 `approval_required`; no automatic Slack bridge (#194) |
| Test the integration offline (dry-run #116) | ✅ `createVouchr({ dryRun: true })` + `vouchr.dryRun.completeConsent` | ✅ `BrokerOptions.dryRun` / `VOUCHR_DRY_RUN=1` |

## Writes are opt-in

The HTTP broker is read-only by default: non-`GET`/`HEAD` requests return `405` before any credential
lookup. Write requests require two explicit opt-ins:

```ts
const broker = createBroker({
  providers: [
    github({ egressMethods: ['GET', 'POST'] }), // provider-level method allowlist
  ],
  allowWrites: true,                            // broker-level write switch
  identitySecret: loadIdentityConfig(process.env),
  // vault, audit, db...
});
```

Providers without `egressMethods` remain `GET`/`HEAD`-only even when `allowWrites` is enabled.
Write bodies are small JSON/text payloads, capped at 64 KiB, and still go through the same identity
verification, replay guard, policy, channel-tool, host/path/method, and HTTPS checks as reads.

## Human-in-the-loop approvals (#113)

A provider declaring the `approval` knob (`{ methods?, paths?, approver: 'self' | 'admin',
ttlMs? }`; default = every non-GET/HEAD method) requires a live, single-use human approval per
matching action — enforced in the shared injector, so this door inherits it identically: strictly
AFTER every egress gate (never a bypass) and BEFORE the credential is read. The broker **cannot
render Approve/Deny buttons**, so the split is deliberate:

- A matching `/v1/fetch` (or `/v1/mcp`) with no live grant records a pending approval, audits
  `approval_requested`, and returns:

  ```json
  { "error": "approval_required", "approvalId": "…" }   // HTTP 403
  ```

- The Bolt adapter renders Approve/Deny automatically only when its own in-process handle starts the
  write. A headless 403 does not trigger that UI. The Slack-facing host must implement the bridge,
  re-check approver eligibility, and retry with a fresh identity token; the complete supported bridge
  remains [#194](https://github.com/Dharin-shah/vouchr/issues/194). A host can use the exported
  `Approvals` store, but the current package does not export the Bolt approval blocks/action IDs as a
  ready-made headless surface.

The grant matches ONLY the exact (method, host, path) it was minted for, expires after `ttlMs`
(default 5 minutes), and is consumed atomically on first use — a second identical call returns a
fresh 403 with a new `approvalId`. The `approvalId` is a lookup handle, not authority and not a
secret. Expired prompts/grants are reclaimed by the standard TTL sweep (audited, actor `system`).

## MCP servers (Streamable HTTP): `POST /v1/mcp`

Many tools ship as MCP servers over Streamable HTTP — which is just HTTP with a bearer. `/v1/mcp`
is the `/v1/fetch` pipeline (identical identity, replay, policy, channel-tool, and egress gates;
identical credential injection inside the broker; identical audit rows) with the two things a
JSON-envelope route can't carry:

- the upstream response passes through **as-is and streamed** — status, `Content-Type`
  (`text/event-stream` included), body bytes as they arrive, never buffered;
- the MCP plumbing headers `Mcp-Session-Id` and `MCP-Protocol-Version` pass through in **both**
  directions, and the request may carry `Accept` and `Content-Type` (Streamable HTTP requires
  `Accept: application/json, text/event-stream`). Every other header is stripped exactly like
  `/v1/fetch`; the caller's `Authorization` is always dropped — the broker injects the credential.

The request is the same envelope style as `/v1/fetch`, with the upstream method fixed to POST (a
JSON-RPC message) and the JSON-RPC payload in `body`:

```json
{
  "handle": { "provider": "github", "owner": "user" },
  "identityToken": "<signed; mint a FRESH one per JSON-RPC call — tokens are single-use>",
  "path": "/mcp",
  "headers": { "accept": "application/json, text/event-stream", "content-type": "application/json", "mcp-session-id": "…" },
  "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\", …}"
}
```

Point your MCP client's transport at the broker: wrap each outgoing JSON-RPC message in this
envelope (minting a fresh `identityToken` — the replay guard rejects a reused one) and hand the raw
response back to the client. `initialize` / `tools/list` / `tools/call` then work end to end with
the broker injecting the per-user credential.

Rules and limits:

- **Opt-in per provider, with an endpoint + content-type lock.** `/v1/mcp` refuses (403) any
  provider that does not declare the `mcp` knob on `defineProvider`:

  ```ts
  defineProvider({
    // …
    egressMethods: ['POST'],  // JSON-RPC rides POST (write gating below)
    mcp: { paths: ['/mcp'] }, // REQUIRED to be reachable via /v1/mcp
    // mcp.allowContentTypes defaults to ['application/json', 'text/event-stream']
  });
  ```

  Being POST-enabled for `/v1/fetch` is NOT enough: the raw streamed passthrough skips
  `/v1/fetch`'s broker-level response gates (the `allowedContentTypes` allowlist and the 1 MiB
  `maxResponseBytes` cap), so reaching it must be a deliberate declaration. `mcp.paths` locks the
  reachable endpoint with the same matching semantics as `egressPaths` (one shared matcher;
  encoded path separators refused fail-closed), and the response's bare media type must match
  `mcp.allowContentTypes` (default: the two MCP transport types) or the body is **withheld
  unread** — which is what stops an allowlisted-but-hostile upstream reflecting the injected
  `Authorization` header into a `text/plain` error body. Provider-level `egressResponse`
  constraints additionally apply if set (enforced in the injector, at the buffering cost below).
  On the standalone broker, declare the same `mcp` shape in the `VOUCHR_PROVIDERS` JSON — see the
  [deployment guide](./DEPLOYMENT.md)'s provider-config section.
- **Writes gating.** MCP `callTool` can mutate, so the route also requires the same double opt-in
  as a `/v1/fetch` POST: `allowWrites: true` on the broker **and** the provider's `egressMethods`
  including `'POST'`. Without either, the request is refused before any credential lookup.
- **The session header is NOT auth — and treat it as sensitive.** `Mcp-Session-Id` is opaque
  transport plumbing the MCP server issues and expects back, and per MCP security guidance it is
  potentially hijackable: Vouchr relays it verbatim and never stores, logs, or audits it — and
  never accepts one as authentication (every request still needs a fresh signed `identityToken`
  and passes every gate). Hosts must handle session ids to the same standard: use MCP servers that
  issue secure, non-deterministic ids, and keep them out of your own logs. The broker holds
  **no MCP session state** (session lifecycle is your MCP client's job); the optional GET
  listening stream and client-initiated DELETE termination are answered with `405` +
  `Allow: POST` — the MCP-spec response of a server that doesn't offer them — never proxied.
- **Stream ceilings.** A streamed response has no whole-body cap to buffer to, so two broker
  options bound it: `maxStreamBytes` (default 8 MiB) counts bytes while relaying and *terminates*
  the stream when exceeded — upstream fetch aborted, client socket destroyed, never a clean end —
  and `maxStreamMs` (default 5 minutes) aborts the upstream fetch on a deadline. Both must be
  finite and > 0: `createBroker` rejects NaN/Infinity/zero at construction (a NaN cap would
  silently fail open).
- **Interplay with `egressResponse.maxBytes` (#110).** A provider-level response cap still applies
  and the stricter of the two wins (over-cap → `413`, nothing relayed) — but the injector enforces
  it by buffering up to that cap before the relay starts, which defeats incremental delivery.
  Leave `egressResponse.maxBytes` unset on streaming (SSE) providers and rely on `maxStreamBytes`.

## Channel governance over HTTP

Channel governance mirrors the Bolt `/vouchr` commands: `POST /v1/admin/mode` sets a provider's
channel mode, `POST /v1/admin/tools` toggles a provider in the channel's tool allowlist, and
`GET /v1/admin/config` reads both back. All three are gated on the SIGNED `isAdmin` claim — admin
authority comes only from the verified identity token, never the request body — and are scoped to
the signed channel.

Those routes require their stores to be supplied to `createBroker()`. The packaged
`buildBrokerServer()` currently wires `ChannelConfig` but not `ChannelTools`, so its tools route is
unavailable and it cannot enforce rows written by Bolt; see
[#240](https://github.com/Dharin-shah/vouchr/issues/240). It also does not load static `Policy`; see
[#236](https://github.com/Dharin-shah/vouchr/issues/236).

The intended boundary keeps raw-key ingest in Bolt's private modal and lets headless accept only
secret-manager references (`/v1/admin/reference` for channels, `/v1/user/reference` for self-service).
Current validation does not yet enforce that boundary completely. Until
[#53](https://github.com/Dharin-shah/vouchr/issues/53) closes, use the Bolt modal and deny both routes
at broker ingress. Bolt restricts recognized schemes, but a successful save still does not prove
resolver/IAM readiness.

## Operations

- **Deployment identity.** Build `identitySecret` with `loadIdentityConfig(process.env)` in both the
  trusted Slack verifier/minter and every broker replica. Keep the signing keys out of arbitrary
  workers, and keep them distinct from the Slack signing secret, encryption keys, broker bearer, and
  provider OAuth client secrets. See the deployment guide for the required upgrade and rotation order.
- **Replay protection.** Automatic when you use a shared database — every db-configured broker
  uses the durable PostgreSQL `DbReplayStore`, so a `jti` spent on one pod is rejected on the others.
  The replay store is not configurable; the exported in-memory `ReplayGuard` is only for direct
  verifier unit tests, never broker construction or production.
- **Not connected yet?** Route the user back through the Slack connect/approval flow.
- **OAuth dependency deadline.** Set `oauthTimeoutMs` on a provider definition when its token,
  revoke, or account endpoint legitimately needs longer than the 10-second default. The same finite
  bound applies to token exchange/refresh, revoke, and built-in account probes on both front doors.
- **Extension cancellation.** Custom `authorize` hooks and external-secret `Resolvers` receive an
  optional `AbortSignal`; use it to cancel their own network work when the caller disconnects or the
  fetch deadline expires. Vouchr also races the signal at its boundary, so a legacy hook that ignores
  it cannot retain an in-flight admission slot forever.
- **Credential health.** There is no Slack client here, so nothing is DM'd for you: pass
  `onCredentialHealth` (a `BrokerOptions` field, e.g. `buildBrokerServer(env, { onCredentialHealth })`)
  to hear `refresh_dead` — a DEFINITIVELY dead refresh token (`invalid_grant`, or a bare 400/401
  from the token endpoint; never a transient network blip, nor an operator-side error such as
  `invalid_client` — see `TokenEndpointError`). The same hook passed to `sweepExpired` also fires
  `expiring_soon` (within 72h of the idle/max-age TTL ceiling, for dimensions longer than the 72h
  window; re-fired on every sweep pass) and
  `expired` (the sweep deleted the connection). Events carry the owning principal + provider, never
  token material. Debounce your notifier with the exported `NotificationState`: `claim()` the 24h
  window atomically (exactly one winner per (owner, provider, type), across replicas sharing a
  Postgres), send, and `release()` the claim if the send fails so the next event retries; reconnect
  and disconnect clear the state. Known trade: a replica that claims and then crashes before
  sending loses that window's notification (the next window retries) — deliberate, because the
  alternative is cross-replica duplicates.
- **Probes.** Two unauthenticated endpoints for orchestrators: `GET /healthz` (liveness — a bare
  `{"ok":true}` whenever the process is serving, no db touched) and `GET /readyz` (readiness —
  `{"ok":true}` only if the schema and cluster-wide replay store are usable within ~2s, else
  `503 {"ok":false}`). Both
  are exempt from auth, identity, and replay, and return a bare status with no secrets or error text.

## Dry-run (offline integration tests)

`BrokerOptions.dryRun` (or `VOUCHR_DRY_RUN=1` for the packaged `vouchr-broker`) runs every gate —
identity verification, replay, policy, channel tools, owner resolution, egress — for real, and no
real network call leaves the process on any edge: outbound fetch, token exchange, refresh, and
upstream revoke are all stubbed or skipped (#116):

- `POST /v1/connect` mints an authorize URL that points at **this broker's own callback** with a
  synthetic code; a test client completes consent by simply GETting it. The callback consumes the
  real single-use state and writes a synthetic credential marked `external_account: 'dry-run'`.
- `POST /v1/fetch` reads that credential from the vault and returns a
  `200` body of `{ dryRun: true, method, url, wouldInjectAs }` instead of calling the provider;
  denials map to the same errors as production (403 egress blocked, 409 not connected, …).

Safety rails: provenance is a system-only `dry_run` column (never the account label). The packaged
broker hard-fails at boot if the database holds any non-dry-run credential ("refusing dryRun against
a vault with real credentials"); a programmatically constructed `createBroker` fails every request
closed and reports `/readyz` 503 (while `/healthz` stays 200) until the same check passes; and a
real row written AFTER boot is refused per-request — never injected, never overwritten by a dry-run
consent (the synthetic write is an atomic conditional). Dry-run requires a **local master key**: an
external KMS envelope (`VOUCHR_KMS_KEY_ID`) is refused at startup, since its wrap/unwrap are real
network calls. Audit rows carry `meta.dry_run: true`. Never set it against production state.

## Other-language workers

Run the packaged `vouchr-broker` and call this documented HTTP contract from Python, Go, Rust, or an
MCP runtime; do not build a second sidecar that trusts caller-supplied owner ids. The trusted
Slack-facing service mints a fresh deployment-bound `identityToken` for each broker call, while the
worker receives only that short-lived assertion and never the signing key. The TypeScript flow in
[`examples/broker-client`](../examples/broker-client) is the reference request shape to reproduce in
another language.
