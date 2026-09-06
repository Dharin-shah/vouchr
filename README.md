<div align="center">
<h1>Vouchr</h1>

**Your Slack agent acts as the person asking, and never holds their tokens.**

[![npm](https://img.shields.io/npm/v/%40vouchr%2Fcore?style=for-the-badge&label=npm)](https://www.npmjs.com/package/@vouchr/core) [![CI](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/ci.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml) [![Security](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/security.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Security)](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml) [![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](./LICENSE)

</div>

Vouchr is a self-hosted credential broker for Slack agents.

When a Slack agent calls GitHub, Google, or Jira, it usually holds one bot token with everyone's
power, or it carries user tokens through prompts and logs. Vouchr removes both. Each person
connects their own account once, in Slack. Your code gets a handle, never a token, and Vouchr adds
the credential only when the request leaves for the provider. Vouchr does not read or filter provider
responses, so what the model does with data it is allowed to see stays your responsibility.

Token vaults and integration platforms hand the token to your code or to a hosted service. Vouchr
keeps it out of your code, your model, and your logs, and asks the owning team before sensitive
actions. It is self-hosted and PostgreSQL-only.

## Example

```bash
npm install @vouchr/core
```

```ts
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github, ConsentRequiredError, safeUserMessage } from '@vouchr/core';

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

// Needs VOUCHR_DATABASE_URL and VOUCHR_MASTER_KEY in the environment, and a one-time `npx vouchr migrate`.
const vouchr = await createVouchr({ providers: [github()], baseUrl: process.env.PUBLIC_URL! });
vouchr.install(app, receiver);

app.event('app_mention', async ({ context, event, client, say }) => {
  try {
    const gh = await context.vouchr.connect('github');
    const me = await (await gh.fetch('https://api.github.com/user')).json();
    await say(`You're *${me.login}* on GitHub.`);
  } catch (error) {
    if (error instanceof ConsentRequiredError) return; // Vouchr already posted a private Connect prompt.
    // Any other refusal: show the user Vouchr's fixed, secret-free message, then let Bolt log it.
    await client.chat.postEphemeral({ channel: event.channel, user: event.user!, text: safeUserMessage(error) });
    throw error;
  }
});
```

Channels are deny-by-default. Before first use in a channel, a member of that channel runs
`/vouchr enable github`. Direct messages need no enable. `connect()` then prompts the user
privately. After one browser OAuth, the agent works.

![Vouchr Slack connect prompt](./assets/slack-connect-prompt.svg)

## Quickstart

[QUICKSTART.md](./QUICKSTART.md) goes from nothing to a bot acting as you on GitHub. Plan on about
ten minutes of Slack and GitHub app setup, then a few minutes to run. It needs Node 22 or newer and
PostgreSQL.

## Credential modes

Each channel picks how a provider is authorized. Your handler code does not change;
`connect(provider)` follows the channel's mode.

| Mode | What it means | Typical use |
| --- | --- | --- |
| `per-user` | Each person uses their own connected account. | GitHub, Google, Jira |
| `session` | Usable only inside the approving thread, for a limited time. | Sensitive writes |
| `shared` | The channel uses one credential a channel member configures. | Team tools, internal APIs |

## Human approval from any agent

An agent can do most of a task on its own and stop at each sensitive step. The team decides
those steps. Mark a provider's sensitive actions with the `approval` knob, for example
`github({ approval: { approver: 'member', methods: ['POST', 'PUT'] } })`. When the agent reaches
one, Vouchr posts a prompt in the channel that owns the credential. It shows who asked, the
provider, the method, and the host. Any other member of that channel clicks Approve or Deny. On
approval the agent runs exactly that action, once. Then it asks again for the next sensitive step.

For example, an agent drafts a release and reviews the changes on its own. It pauses to publish the
release and to merge the pull request. The team approves each in Slack. The agent finishes.

`approver: 'self'` asks the person driving the agent instead. In a direct message there is no
team, so `member` behaves like `self`. This also works for agents outside Slack. They call the
broker, and the same prompt lands in the same channel. See the
[headless guide](./guides/HEADLESS.md#backchannel-authorization-for-background-agents-296).
A job with no human requester, such as a ticket-driven worker or a cron, runs as the app's bot user
and any channel member approves; see
[Autonomous workers](./guides/HEADLESS.md#autonomous-workers).

## Providers

Built in: `github()`, `google()`, `gitlab()`, `notion()`, `databricks()`. Any other OAuth2 API takes
about ten lines with `defineProvider`. API keys and secret-manager references (AWS, GCP, Azure,
Vault) work too. Request only the scopes you use: `github({ scopes: ['read:user'] })` asks for
"Read your profile", not the default `repo`. See
[provider configuration](./guides/DEPLOYMENT.md#provider-config-declarative).

## Headless

Agent workers in another process or language call a private HTTP broker instead of Bolt. The token
still never leaves Vouchr. A background agent with no Slack turn (cron, CI, a durable workflow)
initiates the human decision itself with `POST /v1/authorization` and polls for the outcome. See
the [headless guide](./guides/HEADLESS.md) and the [hybrid guide](./guides/HYBRID.md).

## Learn more

| | |
| --- | --- |
| [Quickstart](./QUICKSTART.md) | Zero to a working demo |
| [Examples](./examples/README.md) | Google, Databricks, API keys, secret managers, broker client, MCP, Prometheus, SCIM, dry-run |
| [Architecture](./guides/ARCHITECTURE.md) | How consent, injection, and audit fit together |
| [Threat model](./guides/THREAT-MODEL.md) | What Vouchr defends against, and its limits |
| [Deployment](./guides/DEPLOYMENT.md) | PostgreSQL, KMS, Kubernetes, runbooks |
| [Headless](./guides/HEADLESS.md) | Broker API, error contract, replay protection |
| [Hybrid](./guides/HYBRID.md) | Slack app plus a private broker, in separate processes |
| [Operator CLI](./guides/CLI.md) | migrate, inventory, channels, revoke, rekey, prune, doctor |
| [Vision](./vision.md) | Product scope and roadmap |
| [Security](./SECURITY.md) | Security model and how to report issues |
| [Contributing](./CONTRIBUTING.md) | How to help |

## License

[Apache-2.0](./LICENSE).
