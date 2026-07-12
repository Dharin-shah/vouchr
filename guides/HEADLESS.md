# Headless HTTP Broker

Use `createBroker()` when your Slack-facing service and agent worker are separate processes.
The Slack-facing service verifies the user, mints a short-lived identity token, and workers call
Vouchr over HTTP. The token stays inside Vouchr.

Import from the Bolt-free entry point so no `@slack/*` package is loaded:

```ts
import { createBroker, signIdentity } from '@vouchr/core/headless';
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

The Slack-facing service verifies Slack, mints a short-lived `identityToken` with `signIdentity()`,
and the worker calls `POST /v1/fetch`:

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

## Capability matrix: Bolt vs headless

One core, two front doors — both reach the same credential boundary.

| Capability | Bolt (`/vouchr`) | Headless broker |
| --- | --- | --- |
| Use a user's own credential | ✅ `connect()` | ✅ `POST /v1/fetch` (`owner:"user"`) |
| Use a `shared` channel credential | ✅ | ✅ `owner:"channel"`, opt-in `VOUCHR_CHANNEL_MODES=1` + signed channel-fact claims (#51) |
| Set the channel mode (`shared`/`per-user`/`session`) | ✅ `/vouchr mode` | ✅ `POST /v1/admin/mode` (admin claim) |
| Toggle a channel's tool allowlist | ✅ `/vouchr enable`/`disable` | ✅ `POST /v1/admin/tools` (admin claim) |
| Read the channel's modes + tool allowlist | ✅ (implicit) | ✅ `GET /v1/admin/config` (admin claim) |
| See where a credential was used (audit) | ✅ `/vouchr audit` · `/vouchr audit channel` (admin) | ✅ `POST /v1/audit` (self) · `POST /v1/admin/audit` (channel, admin claim) |
| Call an MCP server (Streamable HTTP, SSE + session headers) | ✅ in-process via the `connect()` handle's `fetch` | ✅ `POST /v1/mcp` (streamed passthrough; opt-in `mcp` provider knob) |
| Ingest a **raw** key/secret | ✅ private modal (`configure` / key setup) | ❌ reference-only |
| Point a credential at a secret-manager **reference** | ✅ | ✅ `/v1/admin/reference` (channel, admin) · `/v1/user/reference` (user, self-service) |
| Approve a human-in-the-loop write (`approval` provider knob, #113) | ✅ Approve/Deny buttons | ⚠️ enforced (403 `approval_required`) — the approval **surface** is the Slack app |
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
  // vault, audit, db, identitySecret...
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

- The approval **surface is the Bolt app** (Approve/Deny buttons, approver eligibility re-checked
  server-side at the click): the Slack-facing service routes the human there, then the worker
  retries with a fresh identity token. A host with no Bolt surface can drive its own approve/deny
  with the exported `Approvals` store (`./headless`), re-checking approver eligibility itself.

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

What stays Bolt-only is ingesting a **raw** key/secret: the headless broker takes secret-manager
**references** (`/v1/admin/reference` for channels, `/v1/user/reference` for self-service), never a
raw key over the wire. Raw-key ingest remains the Bolt private modal's job.

## Operations

- **Identity secret.** Keep `identitySecret` with the Slack verifier and broker, not arbitrary
  workers.
- **Replay protection.** Automatic when you use a shared database — every db-configured broker
  defaults to a durable `DbReplayStore`, so a `jti` spent on one pod is rejected on the others. You
  may still pass a custom `replayStore`.
- **Not connected yet?** Route the user back through the Slack connect/approval flow.
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
  `{"ok":true}` only if a `SELECT 1` round-trip succeeds within ~2s, else `503 {"ok":false}`). Both
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

## Local sidecar

When a Python, Go, Rust, or MCP runtime wants a tiny localhost contract instead of a network broker,
see [`examples/sidecar`](../examples/sidecar).
