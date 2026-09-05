<div align="center">
<h1>Vouchr</h1>

**Your Slack agent acts as the person asking, and never holds their tokens.**

![Status: Beta](https://img.shields.io/badge/status-beta-yellow?style=for-the-badge) [![CI](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/ci.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml) [![Security](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/security.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Security)](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml) [![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](./LICENSE)

</div>

Vouchr is a self-hosted credential broker for Slack agents.

When a Slack agent calls GitHub, Google, or Jira, it usually holds one bot token with everyone's
power, or it carries user tokens through prompts and logs. Vouchr removes both. Each person
connects their own account once, in Slack. Your code gets a handle, never a token, and Vouchr adds
the credential only when the request leaves for the provider.

## Example

```bash
npm install @vouchr/core
```

```ts
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github, ConsentRequiredError, safeUserMessage } from '@vouchr/core';

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

const vouchr = await createVouchr({ providers: [github()], baseUrl: process.env.PUBLIC_URL! });
vouchr.install(app, receiver);

app.event('app_mention', async ({ context, event, client, say }) => {
  try {
    const gh = await context.vouchr.connect('github');
    const me = await (await gh.fetch('https://api.github.com/user')).json();
    await say(`You're *${me.login}* on GitHub.`);
  } catch (error) {
    if (error instanceof ConsentRequiredError) return; // Vouchr already posted a private Connect prompt.
    // Other refusals (provider not enabled here, blocked host, ...): tell the user privately in
    // Vouchr's fixed, secret-free copy, then let Bolt log the error.
    if (event.user) await client.chat.postEphemeral({ channel: event.channel, user: event.user, text: safeUserMessage(error) });
    throw error;
  }
});
```

Channels are deny-by-default. Before first use in a channel, an admin runs `/vouchr enable github`.
Direct messages need no enable. `connect()` then prompts the user privately. After one browser
OAuth, the agent works.

## Quickstart

[QUICKSTART.md](./QUICKSTART.md) goes from nothing to a bot acting as you on GitHub in about five
minutes. It needs Node 22 or newer and PostgreSQL.

## Credential modes

Each channel picks how a provider is authorized. Your handler code does not change;
`connect(provider)` follows the channel's mode.

| Mode | What it means | Typical use |
| --- | --- | --- |
| `per-user` | Each person uses their own connected account. | GitHub, Google, Jira |
| `session` | Usable only inside the approving thread, for a limited time. | Sensitive writes |
| `shared` | The channel uses one admin-configured credential. | Team tools, internal APIs |

## Providers

Built in: `github()`, `google()`, `gitlab()`, `notion()`, `databricks()`. Any other OAuth2 API takes
about ten lines with `defineProvider`. API keys and secret-manager references (AWS, GCP, Azure,
Vault) work too. Request only the scopes you use: `github({ scopes: ['read:user'] })` asks for
"Read your profile", not the default `repo`. See
[provider configuration](./guides/DEPLOYMENT.md#provider-config-declarative).

## Headless

Agent workers in another process or language call a private HTTP broker instead of Bolt. The token
still never leaves Vouchr. See the [headless guide](./guides/HEADLESS.md) and the
[hybrid guide](./guides/HYBRID.md).

## Learn more

| | |
| --- | --- |
| [Quickstart](./QUICKSTART.md) | Zero to a working demo |
| [Examples](./examples) | Google, Databricks, API keys, secret managers, broker client, MCP, Prometheus, SCIM, dry-run |
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
