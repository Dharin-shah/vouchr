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
| Use a `shared` / `union` channel credential | ✅ | ✅ `owner:"channel"`, opt-in `VOUCHR_CHANNEL_MODES=1` + signed channel-fact claims (#51) |
| Set the channel mode (`shared`/`union`/`per-user`/`session`) | ✅ `/vouchr mode` | ✅ `POST /v1/admin/mode` (admin claim) |
| Toggle a channel's tool allowlist | ✅ `/vouchr enable`/`disable` | ✅ `POST /v1/admin/tools` (admin claim) |
| Read the channel's modes + tool allowlist | ✅ (implicit) | ✅ `GET /v1/admin/config` (admin claim) |
| See where a credential was used (audit) | ✅ `/vouchr audit` · `/vouchr audit channel` (admin) | ✅ `POST /v1/audit` (self) · `POST /v1/admin/audit` (channel, admin claim) |
| Ingest a **raw** key/secret | ✅ private modal (`configure` / key setup) | ❌ reference-only |
| Point a credential at a secret-manager **reference** | ✅ | ✅ `/v1/admin/reference` (channel, admin) · `/v1/user/reference` (user, self-service) |

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
- **Probes.** Two unauthenticated endpoints for orchestrators: `GET /healthz` (liveness — a bare
  `{"ok":true}` whenever the process is serving, no db touched) and `GET /readyz` (readiness —
  `{"ok":true}` only if a `SELECT 1` round-trip succeeds within ~2s, else `503 {"ok":false}`). Both
  are exempt from auth, identity, and replay, and return a bare status with no secrets or error text.

## Local sidecar

When a Python, Go, Rust, or MCP runtime wants a tiny localhost contract instead of a network broker,
see [`examples/sidecar`](../examples/sidecar).
