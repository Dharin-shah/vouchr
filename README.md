# Vouchr

[![CI](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml/badge.svg)](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml)
[![Security](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml/badge.svg)](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2022-3c873a.svg)](#setup)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

**Vouchr is a self-hostable credential broker for Slack agents. Users connect or approve access in
Slack, your agent receives a safe handle, and Vouchr injects the right credential only at the
outbound HTTP request.**

Bolt is the default integration. For split-process systems, the same core also exposes a headless
HTTP broker: a verified Slack identity goes in, a provider response comes out, and the token stays
inside Vouchr.

## Why Vouchr

When an agent needs to write to a user's tools, teams often fall into one of two unsafe patterns:

- give the agent one broad bot/service token, so every action looks like "the bot did it"
- pass user tokens through prompts, tool code, or logs, where they can leak

Vouchr gives the agent a narrower path:

- credentials are keyed to the Slack user or channel that authorized them
- the agent gets a `ConnectionHandle`, not a token
- `handle.fetch(url)` enforces the provider allowlist and attaches the credential inside Vouchr
- audit entries keep actions tied to the Slack identity or channel that actually authorized access

## What Users See

Vouchr's Slack surfaces are intentionally small. These are illustrative Block Kit mockups; Slack
renders the live UI with your app's name and workspace styling.

For OAuth providers, Vouchr sends a private Connect prompt:

![Vouchr Slack connect prompt](./assets/slack-connect-prompt.svg)

For session-scoped providers, approval is limited to the current Slack thread:

![Vouchr Slack session approval](./assets/slack-session-thread.svg)

For non-OAuth APIs or shared channel credentials, Vouchr opens a private Slack modal:

![Vouchr Slack credential modal](./assets/slack-secret-modal.svg)

## Example: Meeting From Slack

John is discussing a production issue in Slack and asks:

> `@company-agent create a follow-up meeting from this thread tomorrow with everyone here`

The agent can read the thread and draft the title, attendees, agenda, and links. When it needs to
write to Google Calendar, it calls `context.vouchr.connect('google')` and uses the returned handle to
make the Calendar API request. Vouchr supplies John's Google credential at the HTTP boundary, so the
event is created from John's calendar, not from a shared bot account.

If someone else asks for a meeting, Vouchr checks that person's own connection and approval. In
session mode, that approval is scoped to the Slack thread where it was granted.

## How It Works

Vouchr sits between your Slack agent and provider APIs. It owns consent, storage, policy checks, and
credential injection; your handler only asks for a connection and uses the returned handle.

![Vouchr credential flow](./assets/vouchr-flow.svg)

The request flow is deliberately small:

1. Your Bolt handler calls `context.vouchr.connect('github')`.
2. Vouchr resolves the channel's credential mode: `per-user`, `session`, or `shared`.
3. If access is missing, Slack shows a private prompt or modal and the current turn stops.
4. Your handler receives a `ConnectionHandle`, never the credential itself.
5. The handler calls `handle.fetch(url)`.
6. Vouchr checks the destination, injects the credential inside Vouchr, and sends the provider
   request.

**Security boundary:** tokens live in Vouchr's encrypted store and the provider request. They do not
enter the model, Slack transcript, tool schema, or application logs.

For the deeper model, see the [architecture](./guides/ARCHITECTURE.md),
[threat model](./guides/THREAT-MODEL.md), and [deployment guide](./guides/DEPLOYMENT.md).

## Embedded or Headless

Vouchr has one security boundary and multiple ways to reach it:

- **Bolt middleware** for the simplest path: Slack prompts, OAuth callback, approvals, and
  `context.vouchr.connect()` in one app.
- **Headless HTTP broker** when a Slack-facing service verifies the user, then separate workers call
  Vouchr over HTTP.
- **Local sidecar** when a Python, Go, Rust, or MCP runtime wants a tiny localhost contract. See
  [`examples/sidecar`](./examples/sidecar).

Headless is primarily the credential **use path**, not a replacement for Slack consent. Users still
connect or approve access through the Slack app first (or through the headless OAuth flow when it is
mounted).

**One core, two front doors — but not full parity.** Both doors reach the same credential boundary,
but *configuration* of channel governance lives only in the Bolt path today. Don't assume the headless
broker can do everything the slash command can:

| Capability | Bolt (`/vouchr`) | Headless broker |
| --- | --- | --- |
| Use a user's own credential | ✅ `connect()` | ✅ `POST /v1/fetch` (`owner:"user"`) |
| Use a `shared` / `union` channel credential | ✅ | ✅ `owner:"channel"`, opt-in `VOUCHR_CHANNEL_MODES=1` + signed channel-fact claims (#51) |
| Set the channel mode (`shared`/`union`/`per-user`/`session`) | ✅ `/vouchr mode` | ❌ no route |
| Toggle a channel's tool allowlist | ✅ `/vouchr enable`/`disable` | ❌ no route |
| Ingest a **raw** key/secret | ✅ private modal (`configure` / key setup) | ❌ reference-only |
| Point a credential at a secret-manager **reference** | ✅ | ✅ `/v1/admin/reference` (channel, admin) · `/v1/user/reference` (user, self-service) |

The headless broker is deliberately **reference-only** for credential ingest: `/v1/admin/reference`
and `/v1/user/reference` accept secret-manager references (e.g. an AWS Secrets Manager ARN), never a
raw key over the wire. Setting channel mode and the tool allowlist stay Bolt-only; the headless broker
only *reads* the modes a Slack admin configured.

## Credential Modes

Each channel can choose how a provider is authorized:

| Mode | What it means | Typical use |
| --- | --- | --- |
| `per-user` | Each person uses their own connected account. | GitHub, Google, Jira |
| `session` | A person's account is usable only inside the approving thread. | Sensitive write actions |
| `shared` | The channel uses one admin-configured credential. | Team-owned tools or internal APIs |
| `union` | Any connected channel member's account may satisfy the request, acting as that member. | Shared team channels where one member's connection can unblock the workflow |

Admins set the mode in Slack:

```text
/vouchr mode github     session
/vouchr mode confluence shared
/vouchr mode gdocs      per-user
/vouchr mode jira       union
```

Your handler stays scope-agnostic; `connect(provider)` reads the mode and routes automatically:

```ts
const gh = await context.vouchr.connect('github');     // thread session
const cf = await context.vouchr.connect('confluence');  // channel credential
const gd = await context.vouchr.connect('gdocs');       // user's own credential
```

In **session** mode, the provider is usable only inside the thread the user approved it in. Grants
expire after a TTL ceiling (`sessionTtlMs`, default 8h) and are cleared on offboarding.

In **union** mode, `connect()` resolves to a connected channel member and acts as that member: their
credential is used, and that member is the audited actor. It is still a per-user credential, not a
shared channel token. If no member is connected yet, the caller gets the normal Connect prompt and
can become the first connected member.

## Human Tools vs Service Tools

Vouchr brokers credentials when a tool acts as a human. Service-to-service tools are different: they
act as the agent or host system, so there is no human credential to connect or approve.

| Tool type | Acts as | Credential path |
| --- | --- | --- |
| Per-human tool, `identity: 'acting_human'` | The human in the channel | Vouchr runs consent, resolves the credential, and audits the acting human. |
| Service tool, `identity: 'service'` | The agent or host service | The host wires its own service auth; Vouchr refuses `connect()` with no consent flow. |

`toolManifest()` reports each provider's identity so a host can render both kinds side by side. See
[`examples/channel-tool-manifest.ts`](./examples/channel-tool-manifest.ts) for a mixed manifest.

## Minimal Example

```ts
app.event('app_mention', async ({ context, say }) => {
  const gh = await context.vouchr.connect('github');
  const me = await (await gh.fetch('https://api.github.com/user')).json();

  await say(`You're *${me.login}* on GitHub.`);
});
```

If the user has not connected GitHub yet, `connect('github')` posts the private Slack prompt shown
above and throws `ConsentRequiredError`. Catch it and stop the turn. The user clicks once, finishes
OAuth in the browser, then asks again.

## Setup

Requires Node >=22.

```bash
npm install
cp .env.example .env     # set VOUCHR_MASTER_KEY, Slack secrets, and provider OAuth credentials
npm test                 # unit + integration tests, fully offline
```

Wire Vouchr into your existing Bolt app:

```ts
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github } from '@vouchr/core';

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

const vouchr = await createVouchr({ providers: [github()], baseUrl: process.env.PUBLIC_URL! });

vouchr.install(app, receiver); // middleware + OAuth callback + /vouchr command + offboarding + TTL sweep
```

`install()` is the one-call path for the common case. It bundles the middleware, the
`/vouchr/oauth/callback` route, the `/vouchr` slash command, the deactivation→offboard hook, and the
hourly TTL sweep, and returns `{ stop }` to clear the sweep timer on shutdown. Need finer control?
Call the pieces yourself instead:

```ts
app.use(vouchr.middleware);
vouchr.mountRoutes(receiver.router);   // /vouchr/oauth/callback
vouchr.registerCommands(app);          // /vouchr status | disconnect | configure | mode | tools | enable | disable
vouchr.registerOffboarding(app);       // revoke a user's connections when Slack deactivates them
setInterval(() => vouchr.sweepExpired(), 3_600_000); // hourly TTL sweep
```

The full `/vouchr` slash command surface:

| Subcommand | What it does |
| --- | --- |
| `status` | List your connected accounts (the default when no subcommand is given). |
| `disconnect <provider>` | Revoke your own connection for a provider. |
| `configure <provider>` | Admin: open a private modal to set the channel's shared credential (raw key or secret-manager reference). |
| `mode <provider> <shared\|per-user\|session\|union>` | Admin: set the channel's credential mode for a provider. |
| `tools` | List this channel's tool manifest: which providers an agent may use here and their mode. |
| `enable <provider>` / `disable <provider>` | Admin: toggle a provider in this channel's tool allowlist — a per-channel governance gate `connect()` enforces. |

Vouchr uses **your agent's Slack app**, not a separate Vouchr app. Enable these on that Slack app:

- **Bot scopes:** `app_mentions:read`, `chat:write`, `commands`, `users:read`
- **Events:** `app_mention`, `user_change`
- **Interactivity:** on
- **Slash command:** `/vouchr`

If you do not have an agent app yet, create one from
[`examples/slack-manifest.yml`](./examples/slack-manifest.yml), which has the Slack settings
pre-filled.

For each OAuth provider, register that provider's OAuth app with callback
`$PUBLIC_URL/vouchr/oauth/callback`. For the GitHub demo, run:

```bash
npm run example:github   # then @-mention the bot in a channel
```

## Providers

Built-ins: `github()`, `google()`, `gitlab()`, `notion()`.

Any OAuth2 provider can be declared with `defineProvider`; non-OAuth APIs can use
`credential: 'key'` and an `inject` function.

```ts
const linear = defineProvider({
  id: 'linear',
  authorizeUrl: 'https://linear.app/oauth/authorize',
  tokenUrl: 'https://api.linear.app/oauth/token',
  scopesDefault: ['read', 'write'],
  egressAllow: ['api.linear.app'],
  refresh: 'none',
  pkce: false,
  clientId: process.env.LINEAR_CLIENT_ID!,
  clientSecret: process.env.LINEAR_CLIENT_SECRET!,
});
```

More examples:

- [Google user credentials](./examples/google-user)
- [Internal API keys](./examples/internal-api-key)
- [AWS Secrets Manager references](./examples/aws-secrets-manager)
- [Postgres + KMS deployment](./examples/postgres-kms)
- [Sidecar broker](./examples/sidecar)

## Headless HTTP Broker

Use `createBroker()` when your Slack-facing service and agent worker are separate. The Slack-facing
service verifies Slack, mints a short-lived `identityToken` with `signIdentity()`, and the worker
calls `POST /v1/fetch`:

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

Keep `identitySecret` with the Slack verifier and broker, not arbitrary workers. For multi-instance
brokers, pass a shared `replayStore`; the default replay guard is process-local. If the user has not
connected yet, route them back through the Slack connect/approval flow.

## Production Notes

- **Treat consent prompts as control flow.** `ConsentRequiredError` and
  `SessionApprovalRequiredError` mean Vouchr has already prompted the user. Catch them and stop the
  turn; do not log them as failures.
- **Protect storage and keys.** Token columns are encrypted with `VOUCHR_MASTER_KEY`, but the
  database and key still need normal production controls.
- **Review the deployment checklist.** The [deployment guide](./guides/DEPLOYMENT.md) covers Postgres,
  multi-workspace setup, KMS/envelope encryption, and production readiness.

## Status

**Alpha. Not yet tested in a live deployment.** CI runs the full suite, including Postgres coverage,
plus security checks on every push and PR. Review the
[production readiness checklist](./guides/DEPLOYMENT.md#production-readiness-checklist) before adopting,
and see [CONTRIBUTING.md](./CONTRIBUTING.md) to help.

License: [Apache-2.0](./LICENSE).
