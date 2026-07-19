<div align="center">
<h1>Vouchr</h1>

**Your Slack agent acts as the person asking — and never holds their tokens.**

![Status: Alpha](https://img.shields.io/badge/status-alpha-orange?style=for-the-badge) [![CI](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/ci.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml) [![Security](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/security.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Security)](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml) [![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](./LICENSE)

</div>

> [!IMPORTANT]
> **Alpha — not yet proven in a live deployment**, and the last published package (`v0.2.0`)
> is far behind `main`: **build from source** until the next release is cut. Feedback and
> issues are very welcome.

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

- **The agent acts as real people.** Every request runs with the asking user's own account
  and permissions — no shared god-token.
- **Tokens never reach the model.** Not the prompt, not the transcript, not your logs.
  Injection happens inside Vouchr, at the outbound HTTP request.
- **Guardrails on every call.** Allowlisted hosts and paths, per-user rate limits, response
  caps, and human Approve/Deny for sensitive writes.
- **Governed in Slack.** Admins choose per channel: personal accounts, thread-scoped
  approvals, or one shared team credential — via `/vouchr` or the App Home tab.
- **Accountable and revocable.** Every action is tied to the Slack identity that authorized
  it; deactivating someone in Slack revokes their credentials. For a full compromise, one tested
  break-glass — `vouchr revoke --all --confirm ALL-CREDENTIALS` plus `VOUCHR_LOCKDOWN` containment —
  wipes every stored credential and denies all serving before secret access (see [SECURITY.md](./SECURITY.md)).
- **Self-hosted.** Your infrastructure, your PostgreSQL, your keys (or your KMS).

## Quickstart

> In a hurry? **[QUICKSTART.md](./QUICKSTART.md)** is the full zero-to-running walkthrough — create a
> Slack workspace + app, a GitHub OAuth app, and see the bot act as you in ~5 minutes (with a script
> for recording a demo).

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

On first use, `connect()` privately prompts the user. One click and a browser OAuth later,
the agent just works:

![Vouchr Slack connect prompt](./assets/slack-connect-prompt.svg)

`ConsentRequiredError` carries a `promptState`: `'posted'` means a fresh prompt was just
posted; `'reused'` means a still-live prompt from a moment ago was reused rather than
re-posted — and an in-channel prompt is an ephemeral, so it may no longer be visible.
Branch on the class or `code`, never on message text (the `mapSafeError` copy differs by
state). If your Bolt `App` uses a non-default Slack transport (a proxy, a custom
`slackApiUrl`, or a TLS agent), pass the same options as `slackClientOptions` to
`createVouchr` so Vouchr's prompt and DM posts use your transport too — Vouchr always
layers a finite timeout, zero retries, rate-limit rejection, and lease-safe queue concurrency
on top.

Run the in-repo demo (Node ≥ 22 and PostgreSQL required; Slack app config starts from
[`examples/slack-manifest.yml`](./examples/slack-manifest.yml)):

```bash
npm install && cp .env.example .env   # VOUCHR_MASTER_KEY, Slack secrets, provider OAuth creds
export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
npm run cli -- migrate                # package consumers: npx vouchr migrate
npm run example:github                # then @-mention the bot in a channel
```

Full setup — Slack scopes, provider OAuth apps, migrations, KMS, Kubernetes:
[deployment guide](./guides/DEPLOYMENT.md).

For a multi-workspace Slack app, construct `DbInstallationStore(db, keyring, envelope)` and pass
that same store to Bolt's OAuth receiver and `createVouchr`. The third argument is the same
`EnvelopeProvider` used by `createVouchr`; production installation `bot_token`/`data` then receive
the same per-secret KMS envelope as provider credentials.
Envelope-enabled installation reads reject direct rows by default; the fourth-argument
`{ allowDirectRowsDuringMigration: true }` option exists only for an explicit, temporary cutover.
The built-in store automatically honors `VOUCHR_LOCKDOWN`; direct hosts may also pass
`{ lockdown: true }`, and `false` never overrides the deployment flag. Custom installation stores
must enforce the same external containment gate.

## Credential modes

Each channel chooses how a provider is authorized; your handler code never changes —
`connect(provider)` routes automatically.

| Mode | What it means | Typical use |
| --- | --- | --- |
| `per-user` | Each person uses their own connected account. | GitHub, Google, Jira |
| `session` | Usable only inside the approving thread, time-bounded. | Sensitive write actions |
| `shared` | The channel uses one admin-configured credential. | Team-owned tools, internal APIs |

## Providers

Built-ins: `github()`, `google()`, `gitlab()`, `notion()`, `databricks()`. One connection
covers a whole account — a single `google()` consent can span Calendar, Gmail, and more,
scoped as narrowly as you choose. Any other OAuth2 API takes ~10 lines with
`defineProvider`; API-key tools and secret-manager-backed credentials (AWS, GCP, Azure,
Vault) work too — see [provider configuration](./guides/DEPLOYMENT.md#provider-config-declarative).

**Least privilege — request only the scopes you use.** Scopes come from the provider
definition, so pass exactly what you need: `github({ scopes: ['read:user'] })` shows the
user only "Read your profile", not the broad `repo` default. Need *different* scopes for the
same provider in different channels? Scopes are per-provider, not per-channel (yet —
[#272](https://github.com/Dharin-shah/vouchr/issues/272)), so define the provider twice under
distinct ids and gate them with channel tools/policy — explicit and easy:

```ts
providers: [
  github({ scopes: ['read:user'] }),                                       // id: 'github' — read-only
  defineProvider({ ...github({ scopes: ['read:user', 'repo'] }), id: 'github-write' }),
]
// then: enable `github-write` only where writes are needed, `github` elsewhere.
```

Runnable examples: [Google user credentials](./examples/google-user) ·
[internal API keys](./examples/internal-api-key) · [Databricks](./examples/databricks) ·
[AWS Secrets Manager](./examples/aws-secrets-manager) ·
[GCP Secret Manager](./examples/gcp-secret-manager) ·
[Azure Key Vault](./examples/azure-key-vault) ·
[HashiCorp Vault](./examples/hashicorp-vault) · [Postgres + KMS](./examples/postgres-kms) ·
[headless broker client](./examples/broker-client) · [MCP gateway](./examples/mcp-gateway) ·
[Prometheus metrics](./examples/prometheus) · [SCIM offboarding](./examples/scim)

## Test without any external service

`dryRun: true` runs your real Vouchr wiring — consent, channel modes, policy, egress
checks, audit — with zero outbound network calls and no Slack or provider OAuth apps.
Validate your allowlists and consent handling in CI: [`examples/dry-run/`](./examples/dry-run).

## Headless and hybrid

Slack-facing service and agent workers in separate processes? A private HTTP broker
performs credential use under the same rules — the token still never leaves Vouchr, in any
language. When the broker denies (`not_connected`, `session_approval_required`,
`approval_required`), the trusted Slack side relays the typed denial to
`context.vouchr.recoverBrokerDenial(provider, denial)` and Vouchr posts the correct private
recovery prompt from verified state. See the [hybrid architecture](./guides/HYBRID.md) and the
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

Alpha. Every push runs the full test suite against real PostgreSQL, plus CodeQL and
dependency checks. Want to help? See [CONTRIBUTING.md](./CONTRIBUTING.md).

License: [Apache-2.0](./LICENSE).
