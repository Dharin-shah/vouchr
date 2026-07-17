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
  <a href="./guides/HYBRID.md">Hybrid</a> |
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
browser, and asks again. Repeated demand across replicas shares one active workspace/user/provider
generation and one Slack delivery lease: a delivered prompt is reused, a definite Slack rejection
only releases that exact lease, and an ambiguous transport failure retains it briefly. No adapter
may delete a still-live OAuth URL merely because its own presentation failed.

![Vouchr Slack connect prompt](./assets/slack-connect-prompt.svg)

OAuth callback failures use fixed browser copy. When the consumed state identifies a user, Bolt also
attempts at most one immediate, best-effort private next-step DM for denial, incomplete authorization,
expiry, supersession, setup changes, and provider/token failure. Raw provider errors are never
rendered. The browser response does not wait for Slack; a process failure can drop the DM, and
replaying the callback cannot trigger another attempt. A successful later connection sends the normal
private confirmation.

For low-level core integrations, `Consent.begin()` and `beginFenced()` return the minimal
`ConsentRequest` `{ authorizeUrl, state }`; `Consent.consume()` returns the classified claim directly.
This is a greenfield breaking contract: there is no legacy nullable-row wrapper, and the internal
callback row (including PKCE material) is not a root-package export. Prefer the packaged Bolt or
broker callback path unless implementing another trusted adapter.

Session approvals ([thread-scoped](./assets/slack-session-thread.svg)) are persisted, opaque,
single-use controls: repeated turns reuse one durable request, with a live delivery lease suppressing
immediate duplicate prompts; a click is bound to the exact signed thread and rechecks current access
at the mutation, and duplicate/stale clicks get fixed recovery instead of silence. The pending request
and audit commit together before Slack delivery; a delivery
API rejection has an unknown acceptance outcome, so Vouchr retains the short delivery lease and
keeps a possibly-visible button decidable while preventing an immediate duplicate. Only a known
pre-delivery render/no-recipient failure removes the request. Private credential modals
([non-OAuth keys](./assets/slack-secret-modal.svg)) are built in too. Channel setup consumes the
Slack trigger into a fixed loading view before admin/channel lookups, then hydrates it with an
opaque, actor-bound, single-use request; channel and provider are never trusted from modal metadata,
and duplicate submits cannot rotate the credential or duplicate its config audit. The app's **App Home
tab is a config console**: everyone manages their own connections there, and admins (plus channel
creators when `allowChannelCreatorConfig` is on) pick a channel and set per-provider modes, tool
availability, and shared credentials — the same server-side gates and audit rows as the `/vouchr`
equivalents. Selected renderers are exported for customization (`connectedBlocks`, `statusBlocks`,
`homeView`, …); approval/session builders and action IDs are not a turnkey composition API, so a
host-owned Home or headless approval UI must own its handlers.

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

Deeper dives: [architecture](./guides/ARCHITECTURE.md) · [hybrid Slack + headless](./guides/HYBRID.md) ·
[threat model](./guides/THREAT-MODEL.md) · [deployment](./guides/DEPLOYMENT.md).

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
channel's creator). `/vouchr help` lists the supported commands, and an unrecognized subcommand points back
to it instead of silently doing nothing. A provider removed from the current registry remains
disconnectable while its user-owned credential exists. The exported `disconnectProvider` reports
`{ recognized, removed, ok, audited }`, so callers can distinguish unknown input, committed local
deletion, upstream-revocation uncertainty, and an audit-store failure without inspecting raw errors.
Its five-argument public form captures trusted PostgreSQL time itself; built-in transports retain
their earlier verified receipt through an internal receipt-bound primitive.
Vouchr-owned Home/config Disconnect buttons carry an opaque credential-generation id. Redelivering
an old button after reconnect is stale and cannot delete, revoke, or audit the replacement row.
Provider-addressed `/vouchr disconnect` and legacy `/v1/disconnect` requests that omit a row id use
the connection's PostgreSQL `generation_at` boundary. A delayed command/assertion can act only on a
row that already existed at its trusted receipt; it cannot retarget a later reconnect.
Headless callers can avoid cross-service clock ambiguity by asking `/v1/resolve` for the optional
opaque `credentialId` and returning it with `/v1/disconnect`; exact actor/provider/generation checks
repeat under the mutation locks, and the default resolve wire shape stays unchanged.
Channel setup first opens an authority-free loading view, then binds one opaque, single-use request
in PostgreSQL. A credential, mode, or tool change committed after the verified Slack receipt fences
that older setup before a secret-entry form can overwrite newer state; same-value governance retries
preserve the form. External KMS wrapping completes before lifecycle locks are acquired.

Running `/vouchr` with **no subcommand** opens an interactive modal: everyone sees a bounded first
set of connected accounts with Disconnect buttons and the channel's tool manifest; paged
`/vouchr status [page]` reaches every connection when the complete status exceeds Slack's message
limit. Admins additionally get a per-provider mode select and Enabled checkbox that route to the
same mutations as the commands above (authorization is re-checked
server-side on submit). The ordinary text-subcommand responses are unchanged. The Block Kit builder
(`configModal`) and its callback id (`CONFIG_CALLBACK`) are exported for headless hosts.

### Provider responses and rendering

Vouchr returns provider responses to the trusted host and does not render or retain them. The host
decides what reaches the model or Slack and owns output redaction, data-loss prevention, audience,
and presentation. Accordingly, channel manifests contain credential/tool policy only; there is no
Vouchr preview API, preview-visibility setting, or process-local provider-response store. See
[`SECURITY.md`](./SECURITY.md) for this boundary and [`vision.md`](./vision.md) for the product scope.

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
method; `paths` narrows like `egressPaths`) with no live grant persists one deduplicated request and
posts Approve/Deny buttons on the
in-process Bolt path—to the acting user for `'self'`, to eligible admins for `'admin'` (the same
eligibility gate as the channel config commands)—showing the provider, method, host, a salted action
fingerprint, and the COUNT of query parameters. Raw paths, parameter names/values, and bodies are
caller-controlled and may carry secrets or PII, so none is displayed; the fingerprint binds the
exact owner/origin/method/path/query without making a low-entropy path guessable. The origin binds
scheme, hostname, and effective port even though the prompt keeps displaying hostname only. It
then throws the exported `ApprovalRequiredError` (catch and stop the turn,
exactly like `ConsentRequiredError`); on Approve the retried call finds the grant, spends it, and
executes. A grant is **single-use**, expires after `ttlMs` (default 5 minutes), and matches only
the exact (method, origin, path, query) it was minted for — the query byte-exact as a digest, so
raw values are never persisted and any reordering re-prompts; not a prefix, not the payload
bytes — **and** the exact credential row generation: a per-user→shared mode change or reconnect
invalidates the old handle and re-prompts rather than
running against a credential the human didn't approve, and disconnecting/reconnecting the credential
purges the grant. Effective mode or tool-governance changes also purge pending requests and grants, so a
disable→enable or mode flip-back cannot resurrect an old decision. Clicks recheck the current
provider rule, owner, credential, mode, policy, tool bit, signed conversation, and approver before
the decision commits. Raw paths are never copied into Slack, public errors, or audit. Approval paths
are capped at 16 KiB before rate budget, persistence, audit, credential reads, or Slack delivery; an
oversized path gets fixed recovery guidance and leaves no pending request (see the
[threat model](./guides/THREAT-MODEL.md)). Approval runs **after** every
egress gate (an additional gate, never a bypass) and **before** the secret is read. Request audits
are attributed to the requester, approve/deny/consume records carry the deciding approver when one
exists, and expiry is attributed to `system`; each
request/decision/consume mutation and its audit companion is one PostgreSQL transaction. The
headless broker enforces the same gate and returns `403 { "error": "approval_required",
"approvalId": "…", "code": "approval_required", "retryable": false,
"recovery": "request_approval" }`, but it does not post Slack buttons. The opaque id is not
authority, and the package intentionally does not expose the low-level decision stores. The trusted
Slack-facing host will need a private decision bridge that re-checks the approver and retries with a
fresh identity assertion, but that safe facade is not public yet. Until the complete built-in bridge
lands, the headless surface is enforcement-only: do not enable an `approval` rule on a headless-only
request path because the resulting write cannot be approved through supported APIs. The bridge is a focused slice of
[#194](https://github.com/Dharin-shah/vouchr/issues/194). Enable
the gate on a built-in via typed config (`github({ approval: { approver: 'admin' } })`) or on any
`defineProvider`. Absent = unchanged behavior.

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

## Typed Errors and Recovery

Both supported package entrypoints export the same Bolt-free error contract:

```ts
import {
  mapSafeError,
  type VouchrSafeError,
} from '@vouchr/core'; // also available from @vouchr/core/headless

try {
  await handle.fetch(url);
} catch (error) {
  const safe: VouchrSafeError = mapSafeError(error);
  // Branch on safe.code / safe.recovery, never safe.message.
}
```

`mapSafeError()` returns `{ code, message, retryable, recovery, retryAfterMs? }`.
`retryAfterMs` is always milliseconds. `recovery` is one of `connect`, `request_approval`,
`resolve_again`, `retry_later`, `fix_configuration`, or `contact_admin`; the exported
`VOUCHR_ERROR_CODES` / `VOUCHR_RECOVERY_ACTIONS` are the runtime registries. Token failures also
publish the closed `TOKEN_ENDPOINT_FAILURE_KINDS` registry (`credential`, `configuration`, or
`transient`). The fixed `message` is
safe to render privately, but remains presentation text, not control flow. Foreign errors—including
custom provider, resolver, KMS, and database messages—map to fixed `internal_error` copy without
revealing their message or class name. `UserFacingError` is the deliberate exception: constructing
it explicitly opts Vouchr-authored fixed text into rendering; never wrap a caught third-party error
with it. JavaScript callers cannot extend the recovery vocabulary through `UserFacingError`: an
invalid runtime recovery value fails closed to `internal_error`.

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

`safeUserMessage(error)` remains the text-only convenience wrapper and delegates to the same core
mapper. `retryable: true` means the condition can clear later; it never authorizes automatic replay
of an uncertain or non-idempotent write. The HTTP broker additionally uses the same codes and
recovery fields for typed `/v1/fetch` and `/v1/mcp` failures, including unknown-outcome timeouts,
default response-type denials, MCP policy denials, and fixed internal failures; see the
[headless error table](./guides/HEADLESS.md#bounded-failure-and-retry-contract).
Authenticated broker reads and mutations also return the exact typed `409
interaction_state_changed` / `resolve_again` contract when the verified actor assertion predates
offboarding; the spent assertion then replays as `401`.

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

Slack-facing service and agent workers in separate processes? Use the
[hybrid architecture](./guides/HYBRID.md): the Bolt service remains the public Slack control plane,
while a private HTTP broker performs credential use. A verified Slack identity goes in, a provider
response comes out, and the token stays inside Vouchr.

```ts
import { createBroker, loadIdentityConfig, mintIdentity } from '@vouchr/core/headless'; // Bolt-free

const identity = loadIdentityConfig(process.env); // strong key + issuer + deployment audience
const identityToken = mintIdentity({ teamId, userId, channel }, identity); // fresh per broker call
```

Direct `createBroker()` deployments schedule `broker.sweepExpired()` on the returned `BrokerServer`.
That safe facade reclaims expired credentials plus the broker's private consent, approval, session,
and provisioning state without exporting raw interaction mutators; its numeric result remains the
expired credential count. The packaged `vouchr-broker` schedules the same method automatically.

Read-only by default (writes are a double opt-in), with an enforced reference-only headless secret
boundary. Both reference routes accept only bounded, structurally valid AWS Secrets Manager, GCP
Secret Manager, Azure Key Vault, or HashiCorp Vault reference forms, derive the resolver source
server-side, and require that resolver to be configured before any credential, channel mode, or
audit row is written. Raw secret values are rejected; the configured resolver is invoked only when
the credential is used. Validation failures carry a stable `code`. A configured resolver throw or
deadline returns `code: "resolver_failed"`, `retryable: true`, and `recovery: "retry_later"` without
exposing resolver text or the stored reference. Missing/malformed resolver configuration, or a
fulfilled `undefined`, non-string, or empty value, instead returns non-retryable
`resolver_configuration_error` with `fix_configuration`; unchanged retries cannot repair that
contract violation. Invalid fulfilled values are never coerced or sent upstream. A resolver
deadline is not `upstream_timeout` because provider egress has not begun. Bolt user-key prompts and
headless user provisioning are offboard-fenced across
replicas: Slack controls carry one short-lived opaque request minted with the prompt, while headless
OAuth/reference writes preserve the verified identity token's age in PostgreSQL's clock domain.
Retained Bolt handles and broker assertions preserve that same acting-user receipt: Vouchr rechecks
it before secret access and at the provider-send boundary. A shared channel credential remains
available to other current users, but a departed user cannot keep using it through an old handle or
assertion. Offboarding also removes approvals requested by that user; decision and consumption
remain tombstone-fenced if bounded-state cleanup fails. After offboarding, discard old prompts,
handles, and tokens and resolve current identity before attempting setup or use again. Once a
request passes the final provider-send fence and is dispatched, later offboarding cannot recall it. Confirmed
`vouchr revoke --yes` similarly records one exact hashed provider+owner scope before cleanup, fencing
older matching user and shared-channel writes while allowing a new post-incident setup. Outstanding
channel setup forms are counted and cleared in their channel/team/global break-glass scope. The exported
channel-owner `Vault.upsert`, `upsertDryRun`, and `reference` paths participate in that fence too.
Ordinary Disconnect/delete establishes the same exact owner/provider boundary before local removal,
so a cleanup fallback cannot let an older key form or OAuth callback silently recreate access.
Programmatic channel-governance routes sit behind a signed admin claim. Bolt and the packaged broker order
shared setup and mode changes through `Vault.withCredentialLock()`; custom low-level control planes
should use the same owner/provider transaction boundary rather than calling the stores separately.
Providers that ship as MCP servers over Streamable HTTP get a dedicated stateless proxy,
`POST /v1/mcp` — the same gates that are actually
wired on the chosen broker path, plus credential injection, SSE passthrough, and `Mcp-Session-Id` relay.
It is opt-in per provider (the declarative `mcp: { paths, allowContentTypes? }` knob locks the
endpoint and response types) and bounded by the `maxStreamBytes`/`maxStreamMs` broker options.
Full details — capability matrix vs Bolt, wire format, replay protection, health probes, and the
HTTP contract for Python/Go/Rust/MCP runtimes — in the [headless guide](./guides/HEADLESS.md). The
packaged broker requires `VOUCHR_DEPLOYMENT_ID`; every trusted minter and broker replica uses the same
issuer, audience, and bounded active/overlap key set so assertions cannot cross deployments.

The packaged broker loads the same PostgreSQL-backed channel tool allowlist Bolt writes and enforces
it on channel-scoped manifests, brokered fetches, and MCP calls. Operators can also load a static,
config-as-code channel policy from exactly one of `VOUCHR_POLICY` or `VOUCHR_POLICY_FILE`; its
provider rules are validated against the configured provider registry at boot and evaluate only the
signed channel claim. Static `Policy` and mutable `ChannelTools` are independent gates: a provider
is usable only when both allow it. See the
[deployment guide](./guides/DEPLOYMENT.md#static-channel-policy-declarative) for the strict JSON
shape and default-deny examples.

## Production Notes

- **Consent and approval prompts are control flow.** On the in-process Bolt handle,
  `ConsentRequiredError` / `SessionApprovalRequiredError` / `ApprovalRequiredError` mean Vouchr
  already prompted the user—catch them and stop the turn; don't log them as failures. A headless
  broker 403 does not automatically render that Slack UI. For in-process `ApprovalRequiredError`, the
  human clicks Approve and asks again; the grant is single-use and covers only the exact
  method+origin+path+query bound by the displayed action fingerprint (the raw path/query and request
  body are not displayed).
- **Credential health notifications.** When a refresh token dies for real (`invalid_grant` or a
  bare 400/401 from the token endpoint — never a transient blip or an operator-side error like
  `invalid_client`) or a connection is within 72h of its idle/max-age TTL ceiling (dimensions
  longer than 72h only — shorter ones would always be "expiring"), Vouchr DMs the credential owner
  (the configuring admin for a channel-owned credential): ask-the-agent-again guidance for a dead
  refresh (no long-lived control can mint fresh authority after offboarding), or a heads-up for an
  upcoming expiry. At most one DM per (owner, provider, type) per 24h: the window is claimed atomically in
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
