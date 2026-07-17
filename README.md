<div align="center">
<h1>Vouchr: Credential Broker for Slack Agents</h1>

![Status: Alpha](https://img.shields.io/badge/status-alpha-orange?style=for-the-badge) [![CI](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/ci.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml) [![Security](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/security.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Security)](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml) [![Node](https://img.shields.io/badge/node-%E2%89%A5%2022-3c873a?style=for-the-badge&logo=nodedotjs&logoColor=white)](#quickstart) [![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](./LICENSE)

<p>
  <a href="#quickstart">Quickstart</a> |
  <a href="./vision.md">Vision</a> |
  <a href="#how-it-works">How It Works</a> |
  <a href="#credential-modes">Credential Modes</a> |
  <a href="#providers">Providers</a> |
  <a href="#headless">Headless</a> |
  <a href="./guides/DEPLOYMENT.md">Deployment</a>
</p>
</div>

---

> [!IMPORTANT]
> **Vouchr is in alpha** and not yet tested in a live deployment. The latest published package and
> image (`v0.2.0`) predate the current PostgreSQL-only architecture and the fixes listed under
> [Unreleased](./CHANGELOG.md) — **build from source** until the next release is cut. Review the
> [production readiness checklist](./guides/DEPLOYMENT.md#production-readiness-checklist) before
> adopting — feedback and issues are very welcome!

**Vouchr is a self-hostable credential broker for Slack agents. A user connects or approves access
in Slack, your agent receives a safe handle — never a token — and Vouchr injects the right
credential only at the outbound HTTP request.**

When an agent needs to act on a user's tools, teams usually pick one of two unsafe patterns: one
broad bot token (every action looks like "the bot did it"), or user tokens passed through prompts,
tool code, and logs (where they leak). Vouchr is the narrower third path:

- credentials are keyed to the Slack user or channel that authorized them
- the agent gets a `ConnectionHandle`, not a token
- `handle.fetch(url)` enforces the provider allowlist and attaches the credential inside Vouchr
- audit rows tie every action to the Slack identity that authorized it

Example: John asks `@company-agent create a follow-up meeting from this thread tomorrow`. The agent
calls `connect('google')` and makes the Calendar request through the handle — the event lands on
**John's** calendar, not a shared bot account. When someone else asks, Vouchr resolves *their*
connection and approval.

The supported product scope, deliberate removals, and the definition of production-ready live in
the canonical [vision](./vision.md).

## Quickstart

Requires Node >= 22 and a **PostgreSQL** database (Vouchr is Postgres-only — there is no
embedded/SQLite mode).

```ts
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github, ConsentRequiredError } from '@vouchr/core';

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

const vouchr = await createVouchr({ providers: [github()], baseUrl: process.env.PUBLIC_URL! });
vouchr.install(app, receiver); // middleware + OAuth callback + /vouchr command + offboarding + TTL sweep

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

On first use, `connect()` posts a private prompt and throws `ConsentRequiredError`. The user clicks
once, finishes OAuth in the browser, and asks again:

![Vouchr Slack connect prompt](./assets/slack-connect-prompt.svg)

Thread-scoped [session approvals](./assets/slack-session-thread.svg) and private
[credential modals](./assets/slack-secret-modal.svg) for non-OAuth keys are built in — prompts are
deduplicated and idempotent under double-clicks, Slack retries, and replicas (semantics in the
[architecture guide](./guides/ARCHITECTURE.md#lifecycle)). The App Home tab is a config console:
everyone manages their own connections there, and admins set per-channel modes, tool availability,
and shared credentials through the same server-side gates and audit rows as the `/vouchr` commands.
Selected Block Kit renderers are exported for customization (`connectedBlocks`, `statusBlocks`,
`homeView`, …).

**Slack app setup** — Vouchr uses your agent's Slack app: bot scopes `app_mentions:read`,
`chat:write`, `commands`, `users:read`, `channels:read`, `groups:read`; events `app_mention`,
`app_home_opened`, `user_change`; the App Home tab; interactivity; and the `/vouchr` slash command
(start from [`examples/slack-manifest.yml`](./examples/slack-manifest.yml)). Register each OAuth
provider's app with callback `$PUBLIC_URL/vouchr/oauth/callback`. Then, to run the in-repo demo:

```bash
npm install && cp .env.example .env   # VOUCHR_MASTER_KEY, Slack secrets, provider OAuth creds
export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
npm run cli -- migrate                # once per deploy/upgrade, with a schema-owner role
npm run example:github                # then @-mention the bot in a channel
```

(As a package consumer, the equivalent is `npx vouchr migrate`.) The runtime connects with a
DML-only role, never creates tables, and fails closed on an unmigrated database — see
[migrations](./guides/DEPLOYMENT.md#migrations).

Prefer finer control than `install()`? Each piece is callable individually:

```ts
app.use(vouchr.middleware);
vouchr.mountRoutes(receiver.router);   // /vouchr/oauth/callback
vouchr.registerCommands(app);          // /vouchr slash command
vouchr.registerOffboarding(app);       // revoke connections when Slack deactivates a user
setInterval(() => vouchr.sweepExpired(), 3_600_000);
```

## How It Works

![Vouchr credential flow](./assets/vouchr-flow.svg)

1. Your handler calls `context.vouchr.connect('github')`.
2. Vouchr resolves the channel's credential mode; if access is missing, Slack shows a private
   prompt or modal and the turn stops.
3. Your handler receives a `ConnectionHandle` and calls `handle.fetch(url)`.
4. Vouchr validates the destination, attaches the credential inside Vouchr, and sends the request.

**Security boundary:** tokens live in Vouchr's encrypted store and the provider request. They never
enter the model, Slack transcript, tool schema, or application logs. Provider **responses** return
to your host: your host decides what reaches the model or Slack — Vouchr does not render or retain
provider output (see [SECURITY.md](./SECURITY.md)).

Deeper dives: [architecture](./guides/ARCHITECTURE.md) · [threat model](./guides/THREAT-MODEL.md) ·
[deployment](./guides/DEPLOYMENT.md) · [hybrid Slack + headless](./guides/HYBRID.md).

## Credential Modes

Each channel chooses how a provider is authorized; your handler stays scope-agnostic —
`connect(provider)` reads the mode and routes automatically.

| Mode | What it means | Typical use |
| --- | --- | --- |
| `per-user` | Each person uses their own connected account. | GitHub, Google, Jira |
| `session` | A person's account is usable only inside the approving thread (TTL-bounded, default 8h). | Sensitive write actions |
| `shared` | The channel uses one admin-configured credential. | Team-owned tools, internal APIs |

Admins govern this in Slack: `/vouchr mode <provider> <mode>`, `enable`/`disable <provider>`,
`configure <provider>` (private modal for shared credentials), `tools`, `status [page]`,
`disconnect`, and `help` — bare `/vouchr` opens an interactive modal that routes to the same
server-side mutations. Admin commands are workspace-admin-only by default
(`allowChannelCreatorConfig: true` adds the channel's creator). Disconnect controls are
generation-fenced: a stale button or delayed request can never delete or reuse a credential
connected after it was issued (semantics in the
[headless guide](./guides/HEADLESS.md#disconnecting-a-credential)).

Vouchr brokers credentials for tools that act **as a human**. Service-to-service tools
(`identity: 'service'`) act as the agent itself: the host wires its own auth and Vouchr refuses
`connect()`. `toolManifest()` reports each provider's identity — see
[`examples/channel-tool-manifest.ts`](./examples/channel-tool-manifest.ts).

## Providers

Built-ins: `github()`, `google()`, `gitlab()`, `notion()`, and `databricks({ host })`. A built-in
is one credential, not one API product — a single `google()` connection covers Calendar, Gmail,
People, …; pick scopes and egress paths and the user consents once:

```ts
const gcal = google({
  scopes: ['openid', 'email', 'https://www.googleapis.com/auth/calendar.events'],
  egressPaths: ['/calendar/v3/'],
  rateLimit: { perMinute: 60 }, // optional per-user throttle at the injection boundary
});
```

Every provider takes the same guardrail knobs (full semantics in the
[deployment guide](./guides/DEPLOYMENT.md#provider-config-declarative) and
[threat model](./guides/THREAT-MODEL.md)):

- **`rateLimit: { perMinute, burst? }`** — bounds how fast an agent can spend each owner's
  credential, refused **before** the token is read. A looping (or prompt-injected) agent gets a
  private "slow down" in Bolt or `429` + `Retry-After` from the broker (`RateLimitedError`) —
  instead of getting the human's account rate-banned by the provider.
- **`egressResponse: { maxBytes?, allowContentTypes?, stripHeaders? }`** — structural constraints
  on the provider **response**: a streaming byte cap and an exact media-type allowlist, denied like
  an egress breach. `Set-Cookie` is always stripped from every provider response, opt-in or not.
- **`approval: { methods?, paths?, approver: 'self' | 'admin', ttlMs? }`** — human-in-the-loop for
  sensitive writes: a matching request posts private Approve/Deny buttons and throws
  `ApprovalRequiredError` (catch and stop the turn); on Approve, the retried call executes. Grants
  are single-use, TTL-bounded, and bound to the exact method + origin + path + query **and** the
  exact credential generation. Approval runs after every egress gate and before the secret is read.
  **Caveat:** the headless broker enforces the gate but has no decision bridge yet — do not enable
  `approval` on a headless-only request path
  ([#194](https://github.com/Dharin-shah/vouchr/issues/194)).

Any OAuth2 provider can be declared with `defineProvider` (hosts outside a built-in's egress
allowlist, e.g. `docs.googleapis.com`, need this too); non-OAuth APIs use `credential: 'key'` and
an `inject` function:

```ts
const linear = defineProvider({
  id: 'linear',
  authorizeUrl: 'https://linear.app/oauth/authorize',
  tokenUrl: 'https://api.linear.app/oauth/token',
  scopesDefault: ['read', 'write'],
  egressAllow: ['api.linear.app'],
  refresh: 'none',
  pkce: false,
  oauthTimeoutMs: 10_000, // token exchange/refresh, revoke, and account-probe deadline
  clientId: process.env.LINEAR_CLIENT_ID!,
  clientSecret: process.env.LINEAR_CLIENT_SECRET!,
});
```

More examples: [Google user credentials](./examples/google-user) ·
[internal API keys](./examples/internal-api-key) ·
[Databricks](./examples/databricks) ·
[AWS Secrets Manager](./examples/aws-secrets-manager) ·
[GCP Secret Manager](./examples/gcp-secret-manager) ·
[Azure Key Vault](./examples/azure-key-vault) ·
[HashiCorp Vault](./examples/hashicorp-vault) ·
[Postgres + KMS](./examples/postgres-kms) ·
[headless broker client](./examples/broker-client) ·
[MCP gateway](./examples/mcp-gateway) ·
[Prometheus metrics](./examples/prometheus) ·
[SCIM offboarding](./examples/scim)

## Typed Errors

Both package entrypoints export the same Bolt-free error contract — branch on `code` and
`recovery`, never on message text:

```ts
import { mapSafeError } from '@vouchr/core'; // also available from @vouchr/core/headless

try {
  await handle.fetch(url);
} catch (error) {
  const { code, recovery, retryable, retryAfterMs } = mapSafeError(error);
}
```

Three errors are control flow, not failures: `ConsentRequiredError`,
`SessionApprovalRequiredError`, and `ApprovalRequiredError` mean Vouchr already prompted the user —
catch them and stop the turn. Foreign errors (provider, resolver, KMS, database) collapse to fixed
`internal_error` copy without leaking their text, and `retryable: true` never authorizes automatic
replay of an uncertain write. The full error/code/recovery table for every exported class — used
identically by the HTTP broker's JSON errors — is in the
[headless guide](./guides/HEADLESS.md#typed-errors-exported-classes).

## Test Your Integration

`dryRun: true` runs the whole machine — consent state, channel modes, policy, tool allowlists,
egress gates, vault, audit — under one invariant: **no real network call leaves the process on any
edge**. Your test suite exercises its real Vouchr wiring with zero Slack or provider OAuth apps
configured (it still uses the required local PostgreSQL). Request-side denials are real — a host
missing from `egressAllow` throws exactly the production error; the provider call itself returns a
synthetic echo that never contains the credential:

```ts
const vouchr = await createVouchr({
  dryRun: true, // the only change vs production wiring
  providers: [github({ clientId: 'dry-run', clientSecret: 'dry-run' })], // dummies, no OAuth app
  baseUrl: 'https://my-app.test', // never contacted
  databaseUrl: process.env.VOUCHR_DATABASE_URL, // a fresh, dedicated schema for the dry run
});

await assert.rejects(() => ctx.vouchr.connect('github'), ConsentRequiredError); // real prompt
await vouchr.dryRun!.completeConsent('U1', 'github'); // "click Connect" programmatically
const res = await (await ctx.vouchr.connect('github')).fetch('https://api.github.com/user');
await res.json(); // { dryRun: true, method: 'GET', url: …, wouldInjectAs: 'authorization: Bearer <redacted>' }
```

Dry-run refuses to start against a vault holding real credentials and never overwrites a real row;
the headless broker takes the same flag (`VOUCHR_DRY_RUN=1`). Safety rails and a complete
no-network `node:test` suite: [`examples/dry-run/`](./examples/dry-run).

## Headless

Slack-facing service and agent workers in separate processes? Use the
[hybrid architecture](./guides/HYBRID.md): Bolt stays the trusted Slack control plane while a
private HTTP broker performs credential use — a short-lived, single-use, deployment-bound identity
assertion goes in, a provider response comes out, and the token stays inside Vouchr.

```ts
import { createBroker, loadIdentityConfig, mintIdentity } from '@vouchr/core/headless'; // Bolt-free

const identity = loadIdentityConfig(process.env); // strong key + issuer + deployment audience
const identityToken = mintIdentity({ teamId, userId, channel }, identity); // fresh per broker call
```

The broker is read-only by default (writes are a double opt-in), reference-only for secrets (raw
key values are rejected; AWS/GCP/Azure/Vault resolvers run only at use), replay-protected across
replicas, offboard-fenced, and governed by the same PostgreSQL channel allowlist Bolt writes plus
an optional static config-as-code policy. Providers shipped as MCP servers over Streamable HTTP get
a dedicated stateless proxy, `POST /v1/mcp`. Wire format, capability matrix vs Bolt, replay
protection, and the recovery contract: [headless guide](./guides/HEADLESS.md).

## Production Notes

- **Consent and approval prompts are control flow.** `ConsentRequiredError` /
  `SessionApprovalRequiredError` / `ApprovalRequiredError` mean Vouchr already prompted the user —
  catch them and stop the turn; don't log them as failures.
- **Protect storage and keys.** Token columns are encrypted with `VOUCHR_MASTER_KEY` (or per-secret
  KMS envelope encryption); rotate without orphaning rows via `VOUCHR_MASTER_KEYS` + `vouchr rekey`
  — see the [key-rotation runbook](./guides/DEPLOYMENT.md#key-rotation).
- **Resource bounds are finite and tunable.** Provider-call deadlines, per-process in-flight
  ceilings (`503` + `Retry-After`), inbound header/body limits, and graceful drain are all
  configured — see [resource bounds and the scaling envelope](./guides/DEPLOYMENT.md)
  (`npm run bench:perf` measures your configured envelope).
- **Credential health DMs.** When a refresh token dies for real or a connection nears its TTL
  ceiling, the owner gets at most one private DM per day (claimed atomically across replicas);
  route these yourself with `onCredentialHealth` — the event never carries token material
  ([details](./guides/HEADLESS.md)).
- **Follow the [deployment guide](./guides/DEPLOYMENT.md)** for Postgres, KMS, multi-workspace, and
  the production readiness checklist.

## Status

**Alpha. Not yet tested in a live deployment.** Every push and PR runs the full suite against a
real PostgreSQL container, plus CodeQL and dependency security checks. Review the
[production readiness checklist](./guides/DEPLOYMENT.md#production-readiness-checklist) before
adopting, and see [CONTRIBUTING.md](./CONTRIBUTING.md) to help.

License: [Apache-2.0](./LICENSE).
