# Vouchr

[![CI](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml/badge.svg)](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml)
[![Security](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml/badge.svg)](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2022-3c873a.svg)](#setup)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

**Vouchr is a self-hostable credential broker for Slack agents. Users connect or approve access in
Slack, your agent receives a safe handle, and Vouchr injects the right credential only at the
outbound HTTP request.**

It is built for [Slack Bolt](https://slack.dev/bolt-js) agents that need to act as the human who
asked: open a GitHub issue, create a Google Calendar event, update Jira, call an internal API, or use
another provider without handing raw tokens to the LLM, tool schema, Slack transcript, or app logs.

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

## What Vouchr Includes

- Slack-native connect prompts, session approvals, OAuth callback handling, and private key modals.
- Encrypted SQLite storage by default, with Postgres support for multi-instance deployments.
- A safe HTTP boundary with provider host allowlists and HTTPS checks.
- Per-user, thread-scoped, shared channel, and union credential modes.
- Token refresh, TTLs, disconnect, offboarding cleanup, and optional external secret references.
- Audit records that attribute credential use to the Slack user or channel that authorized it.

Need the deeper model? See [ARCHITECTURE.md](./ARCHITECTURE.md),
[THREAT-MODEL.md](./THREAT-MODEL.md), [SECURITY-WHITEPAPER.md](./SECURITY-WHITEPAPER.md), and
[DEPLOYMENT.md](./DEPLOYMENT.md).

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
import { createVouchr, github } from 'vouchr';

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

const vouchr = await createVouchr({ providers: [github()], baseUrl: process.env.PUBLIC_URL! });

app.use(vouchr.middleware);
vouchr.mountRoutes(receiver.router);   // /vouchr/oauth/callback
vouchr.registerCommands(app);          // /vouchr status | disconnect | configure | mode
vouchr.registerOffboarding(app);       // revoke a user's connections when Slack deactivates them
setInterval(() => vouchr.sweepExpired(), 3_600_000); // hourly TTL sweep
```

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

## Production Notes

- **Treat consent prompts as control flow.** `ConsentRequiredError` and
  `SessionApprovalRequiredError` mean Vouchr has already prompted the user. Catch them and stop the
  turn; do not log them as failures.
- **Protect storage and keys.** Token columns are encrypted with `VOUCHR_MASTER_KEY`, but the
  database and key still need normal production controls.
- **Review the deployment checklist.** [DEPLOYMENT.md](./DEPLOYMENT.md) covers Postgres,
  multi-workspace setup, KMS/envelope encryption, and production readiness.

## Status

**Alpha. Not yet tested in a live deployment.** CI runs the full suite, including Postgres coverage,
plus security checks on every push and PR. Review the
[production readiness checklist](./DEPLOYMENT.md#production-readiness-checklist) before adopting,
and see [CONTRIBUTING.md](./CONTRIBUTING.md) to help.

License: [Apache-2.0](./LICENSE).
