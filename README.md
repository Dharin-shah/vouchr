<div align="center">
<h1>Vouchr</h1>

**Your Slack agent acts as the person asking — and never holds their tokens.**

![Status: Beta](https://img.shields.io/badge/status-beta-yellow?style=for-the-badge) [![CI](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/ci.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml) [![Security](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/security.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Security)](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml) [![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](./LICENSE)

</div>

> [!IMPORTANT]
> **Beta.** `1.0.0-beta` is the current release (PostgreSQL-only, deny-by-default) and the
> recommended build. Feedback and issues are very welcome.

When a Slack agent needs to touch GitHub, Google, or Jira, teams pick between two bad options:
one broad bot token (every action is "the bot", wielding everyone's power at once), or user
tokens passed through prompts and logs (where they leak).

**Vouchr is the third option.** Each person connects their own account once, in Slack. Your
agent code gets a handle — never a token — and Vouchr attaches the credential only at the
moment the request leaves for the provider.

Ask `@agent create a follow-up meeting from this thread` and the event lands on **your**
calendar, created as **you**. When a colleague asks, the agent acts as *them* — their
permissions, their consent.

## What you get

- **The agent acts as real people.** Every request runs with the asking user's own account and
  permissions — no shared god-token.
- **Tokens never reach the model.** Not the prompt, not the transcript, not your logs. Injection
  happens inside Vouchr, at the outbound HTTP request.
- **Guardrails on every call.** Allowlisted hosts and paths, per-user rate limits, response caps,
  and human Approve/Deny for sensitive writes.
- **Governed in Slack, deny-by-default.** A provider is off in a channel until an admin enables it
  there; then they pick the model per channel. Direct messages are personal, not governed.
- **Accountable and revocable.** Every action ties to the Slack identity that authorized it, and
  deactivating someone in Slack revokes their credentials. For a full compromise there is a tested
  break-glass — see [SECURITY.md](./SECURITY.md).
- **Self-hosted.** Your infrastructure, your PostgreSQL, your keys (or your KMS).

## Quickstart

**[QUICKSTART.md](./QUICKSTART.md)** is the full zero-to-running walkthrough: a Slack workspace and
app, a GitHub OAuth app, and the bot acting as you in ~5 minutes.

```ts
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github, ConsentRequiredError } from '@vouchr/core';

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

const vouchr = await createVouchr({ providers: [github()], baseUrl: process.env.PUBLIC_URL! });
vouchr.install(app, receiver);

app.event('app_mention', async ({ context, say }) => {
  try {
    const gh = await context.vouchr.connect('github');
    const me = await (await gh.fetch('https://api.github.com/user')).json();
    await say(`You're *${me.login}* on GitHub.`);
  } catch (error) {
    if (!(error instanceof ConsentRequiredError)) throw error;
    // Vouchr already posted a private Connect prompt — stop the turn.
  }
});
```

Channels are **deny-by-default**: before first use in a channel an admin runs
`/vouchr enable github` (or flips the App Home toggle). A direct message needs no enable. Then
`connect()` privately prompts the user; one click and a browser OAuth later, the agent just works.

![Vouchr Slack connect prompt](./assets/slack-connect-prompt.svg)

Run the in-repo demo (Node ≥ 22 and PostgreSQL required):

```bash
npm install && cp .env.example .env   # VOUCHR_MASTER_KEY, Slack secrets, provider OAuth creds
export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
npm run cli -- migrate                # package consumers: npx vouchr migrate
npm run example:github                # then @-mention the bot in a channel
```

Handling `ConsentRequiredError`, custom Slack transports, and wiring without `install()`:
[architecture guide](./guides/ARCHITECTURE.md). Slack scopes, provider OAuth apps, migrations,
multi-workspace installs, KMS, and Kubernetes: [deployment guide](./guides/DEPLOYMENT.md).

## Credential modes

Each channel chooses how a provider is authorized; your handler code never changes —
`connect(provider)` routes automatically.

| Mode | What it means | Typical use |
| --- | --- | --- |
| `per-user` | Each person uses their own connected account. | GitHub, Google, Jira |
| `session` | Usable only inside the approving thread, time-bounded. | Sensitive write actions |
| `shared` | The channel uses one admin-configured credential. | Team-owned tools, internal APIs |

## Providers

Built-ins: `github()`, `google()`, `gitlab()`, `notion()`, `databricks()`. One connection covers a
whole account — a single `google()` consent can span Calendar, Gmail, and more, scoped as narrowly
as you choose. Any other OAuth2 API takes ~10 lines with `defineProvider`; API-key tools and
secret-manager-backed credentials (AWS, GCP, Azure, Vault) work too.

Request only the scopes you use — `github({ scopes: ['read:user'] })` shows the user "Read your
profile", not the broad `repo` default. See
[provider configuration](./guides/DEPLOYMENT.md#provider-config-declarative) for declarative
providers and for running one provider at different scopes in different channels.

Twelve runnable examples — Google, Databricks, internal API keys, every major secret manager, the
headless broker client, MCP gateway, Prometheus, SCIM — live in [`examples/`](./examples).

## Test without any external service

`dryRun: true` runs your real Vouchr wiring — consent, channel modes, policy, egress checks, audit —
with zero outbound network calls and no Slack or provider OAuth apps. Validate your allowlists and
consent handling in CI: [`examples/dry-run/`](./examples/dry-run).

## Headless and hybrid

Slack-facing service and agent workers in separate processes? A private HTTP broker performs
credential use under the same rules — the token still never leaves Vouchr, in any language. When the
broker denies, the trusted Slack side relays the typed denial to
`context.vouchr.recoverBrokerDenial(provider, denial)` and Vouchr posts the correct private recovery
prompt from verified state. See the [hybrid architecture](./guides/HYBRID.md) and the
[headless guide](./guides/HEADLESS.md).

## Learn more

| | |
| --- | --- |
| [Architecture](./guides/ARCHITECTURE.md) | How consent, injection, and audit fit together |
| [Threat model](./guides/THREAT-MODEL.md) | What Vouchr defends against — and its honest limits |
| [Deployment](./guides/DEPLOYMENT.md) | PostgreSQL, KMS, Kubernetes, runbooks, production checklist |
| [Headless](./guides/HEADLESS.md) | Broker API, error contract, replay protection |
| [Vision](./vision.md) | Product scope and roadmap |
| [SECURITY.md](./SECURITY.md) | Security model and how to report issues |

## Status

Beta. Every push runs the full test suite against real PostgreSQL, plus CodeQL and dependency
checks. Want to help? See [CONTRIBUTING.md](./CONTRIBUTING.md).

License: [Apache-2.0](./LICENSE).
