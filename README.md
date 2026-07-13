<div align="center">
<h1>Vouchr: Credential Broker for Slack Agents</h1>

![Status: Alpha](https://img.shields.io/badge/status-alpha-orange?style=for-the-badge) [![CI](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/ci.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI)](https://github.com/Dharin-shah/vouchr/actions/workflows/ci.yml) [![Security](https://img.shields.io/github/actions/workflow/status/Dharin-shah/vouchr/security.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Security)](https://github.com/Dharin-shah/vouchr/actions/workflows/security.yml) ![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen?style=for-the-badge) [![Node](https://img.shields.io/badge/node-%E2%89%A5%2022-3c873a?style=for-the-badge&logo=nodedotjs&logoColor=white)](#quickstart) [![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](./LICENSE)

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
> **Vouchr is in alpha** and not yet tested in a live deployment. APIs may change between
> releases. Review the [production readiness checklist](./guides/DEPLOYMENT.md#production-readiness-checklist)
> before adopting — feedback and issues are very welcome!

The supported product, deliberate removals, simplification rules, execution order, and
production-ready definition live in the canonical [vision](./vision.md).

**Vouchr is a self-hostable credential broker for Slack agents. Users connect or approve access in
Slack, your agent receives a safe handle, and Vouchr injects the right credential only at the
outbound HTTP request.**

When an agent needs to write to a user's tools, teams usually pick one of two unsafe patterns: one
broad bot token (every action looks like "the bot did it"), or user tokens passed through prompts,
tool code, and logs (where they leak). Vouchr gives the agent a narrower path:

- credentials are keyed to the Slack user or channel that authorized them
- the agent gets a `ConnectionHandle`, not a token
- `handle.fetch(url)` enforces the provider allowlist and attaches the credential inside Vouchr
- audit entries tie every action to the Slack identity that authorized it

Example: John asks `@company-agent create a follow-up meeting from this thread tomorrow`. The agent
calls `connect('google')` and makes the Calendar request through the handle — the event is created
from **John's** calendar, not a shared bot account. If someone else asks, Vouchr resolves *their*
connection and approval.

## Quickstart

Requires Node >= 22 and a **PostgreSQL** database (Vouchr is Postgres-only — there is no
embedded/SQLite mode).

```ts
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github } from '@vouchr/core';

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

const vouchr = await createVouchr({ providers: [github()], baseUrl: process.env.PUBLIC_URL! });
vouchr.install(app, receiver); // middleware + OAuth callback + /vouchr command + offboarding + TTL sweep

app.event('app_mention', async ({ context, say }) => {
  const gh = await context.vouchr.connect('github');
  const me = await (await gh.fetch('https://api.github.com/user')).json();
  await say(`You're *${me.login}* on GitHub.`);
});
```

If the user hasn't connected yet, `connect()` posts a private prompt and throws
`ConsentRequiredError` — catch it and stop the turn. The user clicks once, finishes OAuth in the
browser, and asks again:

![Vouchr Slack connect prompt](./assets/slack-connect-prompt.svg)

Session approvals ([thread-scoped](./assets/slack-session-thread.svg)) and private credential
modals ([non-OAuth keys](./assets/slack-secret-modal.svg)) are built in too. The app's **App Home
tab is a config console**: everyone manages their own connections there, and admins (plus channel
creators when `allowChannelCreatorConfig` is on) pick a channel and set per-provider modes, tool
availability, and shared credentials — the same server-side gates and audit rows as the `/vouchr`
equivalents. All Block Kit surfaces are exported for customization (`connectedBlocks`,
`statusBlocks`, `homeView`, …).

To run it: Vouchr uses **your agent's Slack app** — enable bot scopes `app_mentions:read`,
`chat:write`, `commands`, `users:read`, `channels:read`, `groups:read`, events `app_mention` +
`app_home_opened` + `user_change`, the App Home tab, interactivity, and the `/vouchr` slash command
(or start from [`examples/slack-manifest.yml`](./examples/slack-manifest.yml)).
Register each OAuth provider's app with callback `$PUBLIC_URL/vouchr/oauth/callback`. Then:

```bash
npm install && cp .env.example .env   # VOUCHR_MASTER_KEY, Slack secrets, provider OAuth creds
# Point at your PostgreSQL database (fails closed at boot if unset or non-postgres://):
export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
npm run cli -- migrate                # create/upgrade the schema (once per deploy; schema-owner role)
npm run example:github                # then @-mention the bot in a channel
```

`vouchr migrate` creates the schema and is run **once per deploy/upgrade** with a schema-owner DB
role; the runtime connects with a DML-only role and never creates tables (it fails closed if the
database hasn't been migrated). See the [deployment guide](./guides/DEPLOYMENT.md#migrations) for the
migrate-vs-runtime role split.

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
4. Vouchr checks the destination, attaches the credential inside Vouchr, and sends the request.

**Security boundary:** tokens live in Vouchr's encrypted store and the provider request. They never
enter the model, Slack transcript, tool schema, or application logs.

Deeper dives: [architecture](./guides/ARCHITECTURE.md) · [threat model](./guides/THREAT-MODEL.md) ·
[deployment](./guides/DEPLOYMENT.md).

## Credential Modes

Each channel chooses how a provider is authorized; your handler stays scope-agnostic —
`connect(provider)` reads the mode and routes automatically.

| Mode | What it means | Typical use |
| --- | --- | --- |
| `per-user` | Each person uses their own connected account. | GitHub, Google, Jira |
| `session` | A person's account is usable only inside the approving thread (TTL-bounded, default 8h). | Sensitive write actions |
| `shared` | The channel uses one admin-configured credential. | Team-owned tools, internal APIs |

Admins govern this in Slack with `/vouchr`: `mode <provider> <mode>`, `enable`/`disable <provider>`
(per-channel tool allowlist enforced by `connect()`), `configure <provider>` (private modal for
shared credentials), `tools` (list the channel's manifest), `status`, and `disconnect`. Admin
commands are workspace-admin-only by default (`allowChannelCreatorConfig: true` extends them to the
channel's creator).

Running `/vouchr` with **no subcommand** opens an interactive modal: everyone sees their connected
accounts (with a Disconnect button each) and the channel's tool manifest; admins additionally get a
per-provider mode select, Enabled checkbox, and Private-previews checkbox that route to the same
mutations as the commands above (authorization is re-checked server-side on submit). The text
subcommands are unchanged. The Block Kit builder (`configModal`) and its callback id
(`CONFIG_CALLBACK`) are exported for headless hosts.

### Private previews

Orthogonal to the credential mode, each channel can set a provider's **preview visibility**
(`/vouchr preview <provider> <public|private>`, or the checkbox in the config modal). In a
`private` channel, output the agent posts through `context.vouchr.preview(provider, { title,
lines })` goes **ephemerally to the requester only**, with a Share button — provider data never
reaches the rest of the thread unless the human who saw it explicitly shares it (a single-use,
recipient-bound claim; the public post is attributed to them and audited as `preview`). `public`
(the default) posts normally. Agents discover the bit via `toolManifest()` in Bolt or
`POST /v1/manifest` on the headless broker — one core builder feeds both, so the two transports
can't drift; a host rendering with its own client is expected to honor it, and the `previewBlocks` /
`previewPostBlocks` builders are exported so that surface matches Vouchr's. Pending previews are
held in memory with a 10-minute TTL — a restart or timeout just means "preview expired, ask again".

Vouchr brokers credentials for tools that act **as a human**. Service-to-service tools
(`identity: 'service'`) act as the agent itself: the host wires its own auth and Vouchr refuses
`connect()`. `toolManifest()` reports each provider's identity — see
[`examples/channel-tool-manifest.ts`](./examples/channel-tool-manifest.ts).

## Providers

Built-ins: `github()`, `google()`, `gitlab()`, `notion()`.

A built-in is one credential, not one API product. A single `google()` connection covers Calendar,
Gmail, People, … — pick scopes and egress paths, and the user consents once:

```ts
const gcal = google({
  scopes: ['openid', 'email', 'https://www.googleapis.com/auth/calendar.events'],
  egressPaths: ['/calendar/v3/'],
  rateLimit: { perMinute: 60 }, // optional per-user throttle at the injection boundary
});
```

`rateLimit: { perMinute, burst? }` bounds how fast an agent can spend each owner's credential — a
looping (or prompt-injected) agent is refused **before the token is read**, so it can't get the
human's account rate-banned by the provider. Past the limit, Bolt tells the user ephemerally ("Slow
down…") and the headless broker returns 429 with a `Retry-After` header; callers can catch the
exported `RateLimitedError`. Absent = unlimited. Buckets are per-process by default — a
multi-replica deployment may pass a shared `rateLimitStore` when it needs a fleet-wide limit.

`egressResponse: { maxBytes?, allowContentTypes?, stripHeaders? }` adds structural constraints on
the provider's **response** at the same boundary — shape only, deliberately no content/PII
inspection. `maxBytes` caps the body (fast-fail on Content-Length, then enforced while streaming;
an over-cap body is aborted at the cap, never returned even partially — a `SELECT *` gone wrong
can't blow out the model context). `allowContentTypes` allowlists exact bare media
types — parameters like `; charset=` ignored, so `['application/json']` admits
`application/json; charset=utf-8` but never `application/jsonp-evil` — and an HTML login page is
refused instead of being fed to the model as data. `stripHeaders` removes extra
response headers — and `Set-Cookie` is **always** stripped from every provider response, opt-in or
not, 3xx included: it's a credential-adjacent artifact the agent has no business seeing. A breach
denies like an egress denial: a thrown error (never the body), a `response_denied` event, and an
audit row. Absent = unchanged behavior (bar the unconditional cookie strip).

`approval: { methods?, paths?, approver: 'self' | 'admin', ttlMs? }` adds **human-in-the-loop
approval** for sensitive writes at the same boundary. Between "never allowed" (egress) and "always
allowed" there is "allowed when a human clicks yes": a matching request (default: any non-GET/HEAD
method; `paths` narrows like `egressPaths`) with no live grant posts Approve/Deny buttons in
Slack — to the acting user for `'self'`, to eligible admins for `'admin'` (the same eligibility
gate as the channel config commands) — showing the provider, method, host+path, and the COUNT of
query parameters (names and values are both caller-controlled and can carry secrets/PII, so
neither is displayed; the exact query string is bound byte-for-byte), never the request body. It
then throws the exported `ApprovalRequiredError` (catch and stop the turn,
exactly like `ConsentRequiredError`); on Approve the retried call finds the grant, spends it, and
executes. A grant is **single-use**, expires after `ttlMs` (default 5 minutes), and matches only
the exact (method, host, path, query) it was minted for — the query byte-exact as a digest, so
raw values are never persisted and any reordering re-prompts; not a prefix, not the payload
bytes — **and** the exact
credential owner: a per-user→shared mode change re-prompts rather than
running against a credential the human didn't approve, and disconnecting/reconnecting the credential
purges the grant (see the [threat model](./guides/THREAT-MODEL.md)). Approval runs **after** every
egress gate (an additional gate, never a bypass) and **before** the secret is read; every step —
requested, approved, denied, consumed, expired — is audited with the approver as the actor. The
headless broker enforces the same gate and returns `403 { "error": "approval_required",
"approvalId" }`; the approval surface stays the Slack app. Enable it on a built-in via typed config
(`github({ approval: { approver: 'admin' } })`) or on any `defineProvider`. Absent = unchanged
behavior.

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
[AWS Secrets Manager](./examples/aws-secrets-manager) ·
[GCP Secret Manager](./examples/gcp-secret-manager) ·
[Azure Key Vault](./examples/azure-key-vault) ·
[HashiCorp Vault](./examples/hashicorp-vault) ·
[Postgres + KMS](./examples/postgres-kms) ·
[headless broker client](./examples/broker-client)

## Test Your Integration

`dryRun: true` runs the whole machine — consent state, channel modes, policy, tool allowlists,
egress gates, vault, audit — under one invariant: **no real network call leaves the process on any
edge** (outbound fetch, OAuth token exchange, token refresh, upstream revoke). Your app's test
suite exercises its real Vouchr wiring with no external network, with zero Slack or provider OAuth
apps configured (it still uses the required local PostgreSQL):

- `connect()` posts the real Connect prompt, but the authorize URL is a local,
  instantly-succeeding redirect into the real OAuth callback. Complete it by "clicking" it, or from
  a test with `vouchr.dryRun.completeConsent(user, provider)` — either way the real callback writes
  a synthetic credential marked `external_account: 'dry-run'` through the real vault path.
- `handle.fetch()` passes every request gate (policy, tool allowlist, host/path/method/https, rate
  limits), reads the (synthetic) credential from the vault, and then returns a synthetic
  `200 { dryRun: true, method, url, wouldInjectAs }` echo instead of calling the provider. The
  credential value never appears in the echo; token refresh and upstream revoke are likewise
  skipped for dry-run credentials.
- Request-side denials are real: a host missing from `egressAllow` or a policy-denied channel
  throws exactly the production error — that is the point: validate your allowlists and consent
  handling in CI.
- Safety rails: provenance is a system-only `dry_run` column on the credential row (never the
  user/provider-controlled account label), so a real account legitimately named "dry-run" is never
  mistaken for synthetic. Startup hard-fails if the database already holds any non-dry-run
  credential ("refusing dryRun against a vault with real credentials"), so the flag can't be flipped
  on non-empty production state; a real row written *after* startup is refused per-request and never
  overwritten (the synthetic write is an atomic conditional). Dry-run also requires a **local master
  key** — an external KMS envelope is refused at startup (its wrap/unwrap are real network calls).
  Audit rows written in dry-run carry a `dry_run: true` marker in `meta`.

```ts
const vouchr = await createVouchr({
  dryRun: true, // the only change vs production wiring
  providers: [github({ clientId: 'dry-run', clientSecret: 'dry-run' })], // dummies, no OAuth app
  baseUrl: 'https://my-app.test', // never contacted
  databaseUrl: process.env.VOUCHR_DATABASE_URL, // a fresh, dedicated Postgres schema for the dry run
});

await assert.rejects(() => ctx.vouchr.connect('github'), ConsentRequiredError); // real prompt
await vouchr.dryRun!.completeConsent('U1', 'github'); // "click Connect" programmatically
const res = await (await ctx.vouchr.connect('github')).fetch('https://api.github.com/user');
await res.json(); // { dryRun: true, method: 'GET', url: …, wouldInjectAs: 'authorization: Bearer <redacted>' }
```

The headless broker takes the same flag (`BrokerOptions.dryRun`, or `VOUCHR_DRY_RUN=1` for the
packaged `vouchr-broker`): `/v1/connect` mints a URL pointing at the broker's own callback —
GETting it completes consent — and `/v1/fetch` returns the echo. A complete
no-external-network `node:test` suite of a Bolt handler lives in
[`examples/dry-run/`](./examples/dry-run).

## Headless

Slack-facing service and agent workers in separate processes? The same core exposes an HTTP broker:
a verified Slack identity goes in, a provider response comes out, and the token stays inside Vouchr.

```ts
import { createBroker, loadIdentityConfig, mintIdentity } from '@vouchr/core/headless'; // Bolt-free

const identity = loadIdentityConfig(process.env); // strong key + issuer + deployment audience
const identityToken = mintIdentity({ teamId, userId, channel }, identity); // fresh per broker call
```

Read-only by default (writes are a double opt-in), reference-only for secrets (raw keys stay in the
Bolt modal), with channel governance mirrored behind a signed admin claim. Providers that ship as
MCP servers over Streamable HTTP get a dedicated stateless proxy, `POST /v1/mcp` — the same gates
and credential injection as `/v1/fetch`, plus SSE stream passthrough and `Mcp-Session-Id` relay.
It is opt-in per provider (the declarative `mcp: { paths, allowContentTypes? }` knob locks the
endpoint and response types) and bounded by the `maxStreamBytes`/`maxStreamMs` broker options.
Full details — capability matrix vs Bolt, wire format, replay protection, health probes, and the
HTTP contract for Python/Go/Rust/MCP runtimes — in the [headless guide](./guides/HEADLESS.md). The
packaged broker requires `VOUCHR_DEPLOYMENT_ID`; every trusted minter and broker replica uses the same
issuer, audience, and bounded active/overlap key set so assertions cannot cross deployments.

## Production Notes

- **Consent and approval prompts are control flow.** `ConsentRequiredError` /
  `SessionApprovalRequiredError` / `ApprovalRequiredError` mean Vouchr already prompted the user —
  catch them and stop the turn; don't log them as failures. For `ApprovalRequiredError` the human
  clicks Approve and asks again; the grant is single-use and covers only the exact
  method+host+path+query that was prompted (the request body is not inspected).
- **Credential health notifications.** When a refresh token dies for real (`invalid_grant` or a
  bare 400/401 from the token endpoint — never a transient blip or an operator-side error like
  `invalid_client`) or a connection is within 72h of its idle/max-age TTL ceiling (dimensions
  longer than 72h only — shorter ones would always be "expiring"), Vouchr DMs the credential owner
  (the configuring admin for a channel-owned credential): a reconnect button for a dead refresh
  (it mints a fresh consent link on click, so it can't expire unread), a heads-up for an upcoming
  expiry. At most one DM per (owner, provider, type) per 24h: the window is claimed atomically in
  the `notification_state` table before sending (no duplicates across replicas; a process that
  crashes between claim and send loses that window's DM — the next window retries), and
  reconnecting resets it. To route these yourself instead, set
  `createVouchr({ onCredentialHealth })` (or `BrokerOptions.onCredentialHealth` headless) — the
  exported `CredentialHealthEvent` carries the owning principal and provider, never token material.
- **Protect storage and keys.** Token columns are encrypted with `VOUCHR_MASTER_KEY`, but the
  database and key still need normal production controls. To rotate the master key without
  orphaning rows, set `VOUCHR_MASTER_KEYS` (first entry encrypts new writes, all entries decrypt)
  and run `vouchr rekey` — see the deployment guide's key-rotation runbook.
- **Resource bounds are finite and tunable.** Ordinary provider calls have deadlines, the HTTP
  broker enforces per-instance global + per-provider in-flight ceilings
  (`VOUCHR_MAX_INFLIGHT` / `VOUCHR_MAX_INFLIGHT_PER_PROVIDER` → `503` + `Retry-After`), and inbound
  header/request/keep-alive plus graceful-shutdown limits are set. The global fleet upper bound is
  `replicas × VOUCHR_MAX_INFLIGHT`; one provider is additionally bounded by
  `replicas × VOUCHR_MAX_INFLIGHT_PER_PROVIDER`. See the deployment guide's *Resource bounds and
  the scaling envelope* section (`npm run bench:perf` measures the configured envelope).
- **Follow the [deployment guide](./guides/DEPLOYMENT.md)** for Postgres, multi-workspace, KMS, and
  the production readiness checklist.

## Status

**Alpha. Not yet tested in a live deployment.** Every push and PR runs the full suite against a
real PostgreSQL container — plus CodeQL and dependency security checks. Review the
[production readiness checklist](./guides/DEPLOYMENT.md#production-readiness-checklist) before
adopting, and see [CONTRIBUTING.md](./CONTRIBUTING.md) to help.

License: [Apache-2.0](./LICENSE).
