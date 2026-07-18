# Headless HTTP Broker

Use `createBroker()` when your Slack-facing service and agent worker are separate processes.
The Slack-facing service verifies the user, mints a short-lived identity token, and workers call
Vouchr over HTTP. The token stays inside Vouchr.

If Slack should remain the built-in human/admin experience, start with the
[hybrid Slack control-plane guide](./HYBRID.md). This document is the lower-level HTTP/API contract.

> [!NOTE]
> The stock packaged broker enforces both declarative static channel policy
> (`VOUCHR_POLICY` / `VOUCHR_POLICY_FILE`) and Slack-written `ChannelTools` settings from shared
> PostgreSQL. They are independent gates: both must allow a provider.
>
> [!WARNING]
> Broker denials do not automatically render Slack recovery prompts
> ([#194](https://github.com/Dharin-shah/vouchr/issues/194)); the trusted Slack-facing host still owns
> that bridge.

Import from the Bolt-free entry point so no `@slack/*` package is loaded:

```ts
import { createBroker, loadIdentityConfig, mintIdentity } from '@vouchr/core/headless';
```

`@vouchr/core/headless` re-exports exactly the headless surface — `createBroker`, its `BrokerServer`
type, `buildBrokerServer` (env → wired server), identity minting/verification, providers, the owner
model, and the low-level building blocks (`openDb`, `Vault`, `Audit`, `Consent`, `sweepExpired`,
`Policy`, `ChannelTools`) — plus the typed wire response types (`BrokerFetchResponse`,
`BrokerStatusResponse`, `BrokerAdminConfigResponse`, …), typed operational errors, and the Bolt-free
`mapSafeError` recovery mapper. The root `@vouchr/core` entry exports the same error contract plus the
Bolt adapter; neither entry exports the internal session/approval mutation stores.

A directly constructed broker owns those private stores. Schedule the safe method on the returned
server, not a separately constructed interaction store:

```ts
const broker = createBroker({ providers, vault, audit, db, identitySecret });
const sweepTimer = setInterval(
  () => void broker.sweepExpired().catch(() => console.error('[vouchr] lifecycle sweep failed')),
  3_600_000,
);
sweepTimer.unref();
```

`broker.sweepExpired()` reclaims expired credentials and stale consent, approval, session, and
provisioning state through one idempotent lifecycle facade. It does not expose interaction mutators.
Configured `onEvent` and `onCredentialHealth` hooks receive the sweep's `expired` events only after
the cleanup commits.
The lower-level core `sweepExpired(vault, audit, consent, …)` export remains for non-broker lifecycle
integrations, but it does not own a broker's private interaction stores and is not a substitute for
this method. For compatibility, the returned number counts expired credential deletions only; all
interaction families are still swept on every call.

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

### Typed errors: exported classes

Both package entrypoints (`@vouchr/core` and `@vouchr/core/headless`) export the same Bolt-free
error contract. `mapSafeError()` returns `{ code, message, retryable, recovery, retryAfterMs? }`;
`retryAfterMs` is always milliseconds, and `recovery` is one of `connect`, `request_approval`,
`resolve_again`, `retry_later`, `fix_configuration`, or `contact_admin`. The exported
`VOUCHR_ERROR_CODES` / `VOUCHR_RECOVERY_ACTIONS` are the runtime registries, and token failures
also publish the closed `TOKEN_ENDPOINT_FAILURE_KINDS` registry (`credential`, `configuration`, or
`transient`). The fixed `message` is safe to render privately, but remains presentation text, not
control flow. Foreign errors — including custom provider, resolver, KMS, and database messages —
map to fixed `internal_error` copy without revealing their message or class name. `UserFacingError`
is the deliberate exception: constructing it explicitly opts Vouchr-authored fixed text into
rendering; never wrap a caught third-party error with it. JavaScript callers cannot extend the
recovery vocabulary through `UserFacingError`: an invalid runtime recovery value fails closed to
`internal_error`. `safeUserMessage(error)` remains the text-only convenience wrapper and delegates
to the same core mapper. `retryable: true` means the condition can clear later; it never authorizes
automatic replay of an uncertain or non-idempotent write.

| Exported error | Stable code | Recovery | Meaning |
| --- | --- | --- | --- |
| `ConsentRequiredError` | `consent_required` | `connect` | A private connection prompt was posted; stop the turn. |
| `SessionApprovalRequiredError` | `session_approval_required` | `request_approval` | A thread-scoped session prompt was posted; stop the turn. |
| `ApprovalRequiredError` | `approval_required` | `request_approval` | The exact write needs a human decision; stop the turn. |
| `ApprovalPathTooLongError` | `approval_path_too_large` | `fix_configuration` | The approval endpoint exceeds the bounded exact-action path; narrow it before retrying. |
| `InteractionStateChangedError` | `interaction_state_changed` | `resolve_again` | The credential generation or current authorization changed; discard the stale handle and resolve current access before retrying. |
| `PolicyDeniedError` | `policy_denied` | `contact_admin` | Provider/channel policy denied the request; retrying cannot change governance. |
| `ToolDisabledError` | `tool_disabled` | `contact_admin` | The channel allowlist disabled the provider; an eligible admin must change it. |
| `NoConnectionError` | `not_connected` | `connect` for user credentials; `fix_configuration` for shared channel credentials | No usable credential exists for the resolved owner. |
| `EgressBlockedError` | `egress_blocked` | `fix_configuration` | Host/path/method/validator policy refused the request before credential use. |
| `ResponseBlockedError` | `response_blocked` | `fix_configuration` | Provider response policy withheld the response. |
| `ResolverConfigurationError` | `resolver_configuration_error` | `fix_configuration` | Resolver wiring, a stored reference, or a fulfilled resolver value is missing/malformed; unchanged retries cannot repair it. |
| `ResolverFailedError` | `resolver_failed` | `retry_later` | A configured resolver threw or timed out before provider egress, so a later retry can be safe. |
| `UpstreamTimeoutError` | `upstream_timeout` | `retry_later`, but `retryable: false` | Provider outcome may be unknown; never authorize an automatic replay. |
| `RateLimitedError` | `rate_limited` | `retry_later` | Back pressure includes a millisecond retry hint. |
| `SecretReferenceError` | `invalid_reference`, `source_mismatch`, `invalid_scopes`, or `resolver_unavailable` | `fix_configuration` | Reference input/configuration failed before persistence. Existing codes are unchanged. |
| `TokenEndpointError` | `token_endpoint_failed` | `connect` for `credential`; `fix_configuration` for `configuration`; `retry_later` for `transient` | Distinguishes `invalid_grant`, OAuth client/configuration rejection, and RFC transient codes plus 408/429/5xx/network/timeout failures. The legacy `definitive` boolean remains true only for `credential`. |
| `UserFacingError` | `user_facing` | chosen at construction (default `fix_configuration`) | Explicit opt-in for fixed Vouchr-authored refusal/validation copy. |

The broker maps the same codes and recovery fields onto its HTTP responses — the wire view follows.

### Bounded failure and retry contract

The exported `BrokerError` type describes functional-route JSON errors (`/readyz` deliberately uses
only `{ "ok": false }`). Failures a worker should handle explicitly include:

| HTTP | Body | Caller action |
| --- | --- | --- |
| `400` | `{ "error": "…", "code": "invalid_reference", "retryable": false, "recovery": "fix_configuration" }` (also `source_mismatch`, `invalid_scopes`, or `resolver_unavailable`) | Correct the submitted reference/configuration. Branch on `code`, not message text. |
| `403` | `{ "error": "egress blocked", "code": "egress_blocked", "retryable": false, "recovery": "fix_configuration" }` | Correct the provider/egress configuration; unchanged retries remain denied. |
| `403` | `{ "error": "approval_required", "approvalId": "…", "code": "approval_required", "retryable": false, "recovery": "request_approval" }` | Stop the turn. The broker currently enforces this gate but exposes no supported headless decision bridge; do not treat the opaque id as authority. |
| `403` / `409` | `{ "error": "authorization changed; resolve and retry", "code": "interaction_state_changed", "retryable": false, "recovery": "resolve_again" }` (`409` uses connection-changed prose) | Discard the stale handle, re-resolve current credential/mode/tool/session authority, mint a fresh identity token, and retry only if the operation is still allowed. |
| `403` | `{ "error": "policy denies this provider in this channel", "code": "policy_denied", "retryable": false, "recovery": "contact_admin" }` | Static/channel policy denied use. Retrying cannot change governance; contact an eligible admin. |
| `403` | `{ "error": "provider is not enabled in this channel", "code": "tool_disabled", "retryable": false, "recovery": "contact_admin" }` | The channel tool allowlist disabled the provider; contact an eligible admin. |
| `409` | `{ "error": "not connected", "code": "not_connected", "retryable": false, "recovery": "connect" }` | Start personal connection recovery. For a shared-owner request, `recovery` is `fix_configuration` so an eligible admin configures the channel credential instead. |
| `413` | `{ "error": "approval action path too large", "code": "approval_path_too_large", "retryable": false, "recovery": "fix_configuration" }` | Narrow the provider endpoint; an unchanged request cannot create a bounded exact-action approval. |
| `413` / `502` | `{ "error": "response blocked", "code": "response_blocked", "retryable": false, "recovery": "fix_configuration" }` | Provider response policy withheld the body. The broker's default content-type denial retains `error: "disallowed content-type"` but uses the same machine fields. Generic byte caps retain their established prose-only shape. |
| `429` | `{ "error": "rate limited", "code": "rate_limited", "retryable": true, "recovery": "retry_later", "retryAfterMs": 1000 }` | Honour `Retry-After`, then retry only if the operation itself is safe to replay. |
| `502` | `{ "error": "credential resolution failed", "code": "resolver_configuration_error", "retryable": false, "recovery": "fix_configuration" }` | Resolver wiring, the stored reference, or a fulfilled resolver value is missing/malformed. Correct configuration; unchanged retries cannot repair it. |
| `502` | `{ "error": "credential resolution failed", "code": "resolver_failed", "retryable": true, "recovery": "retry_later" }` | A configured resolver threw or timed out before provider egress. Retry later when replaying the requested operation is otherwise safe. |
| `502` | `{ "error": "upstream fetch failed", "code": "token_endpoint_failed", "retryable": false, "recovery": "connect" }` | The stored grant is dead (`kind: credential`). Configuration failures use `fix_configuration`; RFC transient codes and 408/429/5xx/network/timeout failures use `retry_later` with `retryable: true`. In-process callers can inspect `TokenEndpointError.kind`. |
| `502` | `{ "error": "upstream fetch failed", "code": "internal_error", "retryable": false, "recovery": "contact_admin" }` | Unknown extension/upstream throws are deliberately not guessed retryable; inspect private operator logs. |
| `503` | `{ "error": "overloaded", "code": "overloaded", "scope": "global", "retryable": true, "recovery": "retry_later", "retryAfterMs": 1000 }` (scope may instead be `provider`) | Honour `Retry-After`. The scope is a fixed operator signal, never a provider id or request value. |
| `500` | `{ "error": "internal error", "code": "internal_error", "retryable": false, "recovery": "contact_admin" }` | Pre-handle database/KMS/internal failures use fixed metadata and never expose the foreign error. |
| `504` | `{ "error": "upstream timed out", "code": "upstream_timeout", "retryable": false, "recovery": "retry_later" }` | Treat the outcome as unknown. Retry only a known-idempotent operation; never automatically replay an uncertain write. |

Typed `/v1/fetch` and `/v1/mcp` failures use the same `code`, `retryable`, `recovery`, and
`retryAfterMs` policy. Authenticated reads and mutations also use the exact typed `409
interaction_state_changed` / `resolve_again` response when the verified actor assertion predates
offboarding; replaying that consumed assertion returns `401`. Other validation/authentication
failures retain established prose where no exported typed outcome exists, so `BrokerError` fields
remain optional.
`retryAfterMs` is explicitly milliseconds; the HTTP `Retry-After` header remains whole seconds.

In-process hosts can use the identical contract without parsing HTTP prose:

```ts
import {
  mapSafeError,
  VOUCHR_ERROR_CODES,
  VOUCHR_RECOVERY_ACTIONS,
  type VouchrSafeError,
} from '@vouchr/core/headless';

const safe: VouchrSafeError = mapSafeError(caught);
```

Every exported typed error (`ConsentRequiredError`, `SessionApprovalRequiredError`,
`ApprovalRequiredError`, `ApprovalPathTooLongError`, `InteractionStateChangedError`,
`PolicyDeniedError`, `ToolDisabledError`, `NoConnectionError`,
`EgressBlockedError`, `ResponseBlockedError`,
`ResolverConfigurationError`, `ResolverFailedError`, `RateLimitedError`, `SecretReferenceError`,
`TokenEndpointError`, `UpstreamTimeoutError`, and the explicit `UserFacingError` marker) is available
from both package entrypoints. Unknown errors never
expose their message or class name. `UserFacingError` is an explicit opt-in for fixed,
Vouchr-authored copy—never wrap a caught resolver/provider/KMS/database error in it. See the root
README's [typed error table](../README.md#typed-errors-and-recovery) for thrown control-flow vs
operational meanings.

Identity assertions are single-use. **Mint a fresh `identityToken` for every retry**, including a
retry after `429`, `503`, or `504`; never infer from the error scope whether the earlier assertion
was consumed. This rule keeps clients correct if admission moves or another gate consumes the token
before returning. A `Retry-After` value is a back-pressure hint, not a guarantee that capacity will
be available at that instant.

### Disconnecting a credential

`POST /v1/disconnect` accepts `{ "handle": { "provider": "github", "credentialId": "…" },
"identityToken": "…" }`. Identity comes from the verified assertion, so the caller can remove only
its own user credential. Obtain the opaque id by calling `/v1/resolve` with
`"includeCredentialId": true`; the ordinary resolve response remains unchanged when that opt-in is
absent. The id is a lookup handle, not authority: disconnect repeats actor, provider, and exact-row
validation under the lifecycle locks. The response keeps committed local deletion separate from
upstream/audit confirmation:

| Response | Meaning |
| --- | --- |
| `200 { "ok": true, "revoked": ["github"] }` | The local row was removed and every applicable upstream/audit obligation was confirmed. |
| `200 { "ok": false, "revoked": ["github"] }` | The local row was removed, but upstream revocation or authoritative auditing is unconfirmed. A revocable external reference is one such case because no vaulted token is available to send to the provider; rotate it at its source. |
| `200 { "ok": true, "revoked": [] }` | The registered provider already had no user credential; this is an idempotent no-op. |
| `409 { "error": "connection changed; resolve and retry", "code": "interaction_state_changed", "retryable": false, "recovery": "resolve_again" }` | The actor assertion or exact credential generation is stale. Resolve current state; the request cannot delete a credential connected after its issuance. |
| `404 { "error": "unknown provider" }` | The id is neither registered nor an exact stored row owned by the caller; nothing was mutated or audited. |

`revoked` therefore means “removed from Vouchr”, not “every possible provider-side credential was
invalidated”. Error text never includes the submitted provider value, a credential reference, or a
raw dependency error. The identity assertion is consumed on the first authenticated attempt, so its
replay returns `401` even after a `409`.
For backward compatibility, a provider-only handle is still accepted when PostgreSQL can prove the
row predates the assertion's conservative issuance boundary. A recently connected row can be
clock-ambiguous across the minter and broker, so that legacy form returns the same `409`; resolve the
current opaque id and retry instead of waiting or blindly replaying.

### Admin offboarding

`POST /v1/admin/offboard` accepts `{ "identityToken": "…", "targetUserId": "…" }`; admin
authority comes only from the signed assertion. A single-team response keeps every committed local
deletion in `revoked`, but returns `ok: false` if supported upstream revocation or its authoritative
audit row could not be confirmed. An Enterprise/Grid assertion must also bind the exact target in
signed `offboardTargetUserId`; any incomplete workspace adds to `incompleteTeams`. Both paths may
return HTTP 200 with `ok: false` because successful local deletion is retained—directory hooks must
inspect the body and reconcile until `ok` is true.

## Capability matrix: Bolt vs headless

One core, two front doors — both reach the same credential boundary.

| Capability | Bolt (`/vouchr`) | Headless broker |
| --- | --- | --- |
| Use a user's own credential | ✅ `connect()` | ✅ `POST /v1/fetch` (`owner:"user"`) |
| Use a `shared` channel credential | ✅ | ✅ `owner:"channel"`, opt-in `VOUCHR_CHANNEL_MODES=1` + signed channel-fact claims (#51) |
| Set the channel mode (`shared`/`per-user`/`session`) | ✅ `/vouchr mode` | ✅ `POST /v1/admin/mode` (admin claim) |
| Toggle a channel's tool allowlist | ✅ `/vouchr enable`/`disable` | ✅ `POST /v1/admin/tools` (signed admin; packaged broker or injected `ChannelTools`) |
| Apply static provider-by-channel policy | ✅ `Policy` option | ✅ `Policy` option; packaged broker loads `VOUCHR_POLICY` or `VOUCHR_POLICY_FILE` |
| Read the channel's modes + tool allowlist | ✅ (implicit) | ✅ `GET /v1/admin/config` · channel-scoped `POST /v1/manifest` |
| See where a credential was used (audit) | ✅ `/vouchr audit` · `/vouchr audit channel` (admin) | ✅ `POST /v1/audit` (self) · `POST /v1/admin/audit` (channel, admin claim) |
| Call an MCP server (Streamable HTTP, SSE + session headers) | ✅ in-process via the `connect()` handle's `fetch` | ✅ `POST /v1/mcp` (streamed passthrough; opt-in `mcp` provider knob) |
| Ingest a **raw** key/secret | ✅ private modal (`configure` / key setup) | ❌ rejected; reference routes never accept raw values |
| Point a credential at a secret-manager **reference** | ✅ | ✅ `POST /v1/admin/reference` (channel) · `POST /v1/user/reference` (self) |
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

- A matching `/v1/fetch` (or `/v1/mcp`) with no live grant records and audits one pending approval
  atomically, and returns. Concurrent/repeated identical actions reuse the same opaque id and do not
  duplicate the request audit:

  ```json
  {
    "error": "approval_required",
    "approvalId": "…",
    "code": "approval_required",
    "retryable": false,
    "recovery": "request_approval"
  }
  ```

- The Bolt adapter renders Approve/Deny automatically only when its own in-process handle starts the
  write. A headless 403 does not trigger that UI. The package does not yet expose a safe headless
  decision/session facade: the required Slack eligibility checks, lifecycle locks, current-state
  validation, mutation, and audit must stay one canonical operation. Do not mutate interaction
  tables or import internal stores. The supported broker-to-Slack bridge remains a later focused
  slice of [#194](https://github.com/Dharin-shah/vouchr/issues/194).

Therefore approval on a headless-only request path is currently **enforcement-only**: it will deny
the matching write, but there is no supported API that can complete the human decision. Leave the
provider's `approval` knob disabled for such a path until the #194 bridge lands, or route that action
through the packaged in-process Bolt surface that owns its private prompt and handlers.

The grant matches ONLY the exact (method, origin, path, byte-exact query digest) it was minted for.
Origin includes scheme, hostname, and effective port; the human/audit surface still shows hostname only. It
expires after `ttlMs`
(default 5 minutes), and is consumed atomically on first use — a second identical call returns a
fresh 403 with a new `approvalId`. The `approvalId` is a lookup handle, not authority and not a
secret. On the packaged Bolt path, decisions and spends commit with their audit companions, current
owner/credential/mode/policy/tool/conversation state is revalidated, and mode/tool changes purge old
pending controls and grants so flip-back cannot revive them. Expired prompts/grants are reclaimed by
the standard TTL sweep (audited, actor `system`). These lifecycle guarantees do not imply a supported
custom headless decision UI before the bridge above lands.

Bolt prompts and approval audits expose only method, host, parameter count, and a salted action
fingerprint. Raw paths/queries may contain secrets or PII and stay out of Slack, public errors, and
audit. A path over 16 KiB fails before rate budget, interaction state, credential reads, or egress.

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

Direct `createBroker()` callers opt into the mutable gate by supplying the read-only `channelTools` store.
The packaged `buildBrokerServer()` constructs it from its existing PostgreSQL handle unconditionally,
so the broker admin routes and Bolt write through one audited, lifecycle-locked core mutation, while
admin config, the channel manifest, `/v1/fetch`, and `/v1/mcp` read and enforce that same state. No
allowlist cache or additional environment switch is involved. Service tools are included in admin
config and the channel manifest and may be enabled or disabled there; because Vouchr never executes
their service-authenticated egress, the trusted host must refuse a service call when its manifest row
has `enabled:false`.

The packaged broker separately loads static operator `Policy` from exactly one of `VOUCHR_POLICY`
or `VOUCHR_POLICY_FILE`; see the deployment guide's
[strict JSON contract](./DEPLOYMENT.md#static-channel-policy-declarative). Policy keys are validated
against the configured provider registry at boot and evaluation uses only the signed channel claim.
Static policy and mutable `ChannelTools` intersect, so an admin enable cannot override an operator
deny and a policy allow cannot override a disabled channel tool.

`ChannelConfig` and `ChannelTools` are public read stores. Their former raw `setMode`, `setEnabled`,
and `applyEnabled` methods are removed in v10 because they could bypass interaction invalidation and
audit. Use `POST /v1/admin/mode` and `POST /v1/admin/tools` (or packaged Bolt/App Home) for writes.

The enforced boundary keeps raw-key ingest in Bolt's private modal and lets headless accept only
secret-manager references (`/v1/admin/reference` for channels, `/v1/user/reference` for self-service).
Both routes validate a bounded supported reference form, derive its source server-side, and require a
configured resolver function before any credential, mode, or audit write. A compatibility
`source` field may be supplied only when it exactly matches that derived source; optional scopes
must be a bounded unique subset of the provider's declared scopes. Saving does not invoke the
resolver or prove IAM, network, or secret availability; resolution remains just in time at
credential use. Validation errors include a stable `code` for recovery UI. Missing/malformed
resolver configuration or a fulfilled undefined, non-string, or empty value returns non-retryable
`resolver_configuration_error`; a configured resolver's throw or deadline returns retryable
`resolver_failed`. Neither exposes resolver error text or the stored reference. Resolvers must
fulfill with a non-empty string, and invalid output fails closed before provider egress; explicit
caller cancellation still propagates.

User provisioning, authenticated reads and mutations, and retained credential use are bound to the
verified assertion that initiated them. The broker maps the deployment-bound token's observed age
into PostgreSQL's clock domain and compares that conservative issuance with the durable offboard
fence. Presenting a token minted before offboarding therefore cannot mint a fresh OAuth state or
referenced credential afterward; callers must resolve current access and mint a new verified
identity after legitimate re-onboarding. Before provider/config/registry/audit discovery, the
current-actor check covers `/v1/resolve`, `/v1/status`, `/v1/audit`, `/v1/admin/audit`, `GET
/v1/admin/config`, the channel manifest, and the connect, reference, mode, tools, offboard, and
disconnect mutations. `/v1/fetch` and `/v1/mcp` make the same early check, then the retained handle
checks again before secret access and at provider send; every credential/governance mutation retains
its final under-lock fence. A newly presented pre-offboard assertion receives exact `409
interaction_state_changed` with `recovery: "resolve_again"`, and its replay receives `401`. It cannot
use a surviving shared channel credential; that credential remains available to another current
actor with fresh authority. Pending or granted approvals requested by the offboarded user are
removed, while tombstone checks at decision and consumption keep them unusable if cleanup fails.
Once a request passes the final provider-send fence and is dispatched, later offboarding cannot
recall it. Under
the documented ±30-second minter, broker, and PostgreSQL clock bounds, wait the conservative
90-second cluster-skew horizon before minting the replacement assertion. `/v1/admin/reference`
applies the same age-preserving fence to the acting admin while it atomically writes the channel
reference, shared mode, and config audit; an assertion minted before that admin's offboarding cannot
gain fresh channel-setup authority by being replayed later. Enterprise/global offboarding writes its
scope
before artifact discovery, so this also holds for a Grid workspace with no existing Vouchr row.
Legacy assertions without a verified `iat` fail closed at the production broker boundary.

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
  `invalid_client` — see `TokenEndpointError`). The broker-owned `sweepExpired()` method uses that
  same hook for `expiring_soon` (within 72h of the idle/max-age TTL ceiling, for dimensions longer
  than the 72h window; re-fired on every sweep pass) and
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
