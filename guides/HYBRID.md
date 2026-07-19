# Hybrid Slack control plane + headless data plane

Use this deployment when Slack should own the human experience, but the agent or MCP worker runs in
a separate process, service, or language. The public Slack/Bolt service handles connection,
configuration, Slack interactions, and offboarding. A private headless broker resolves and injects
credentials for the worker.

This guide describes both the target architecture and the honest current behavior. The canonical
product boundaries remain in [`vision.md`](../vision.md); the security model remains in
[`SECURITY.md`](../SECURITY.md).

## Pick the smallest deployment that fits

| Shape | Choose it when | Slack experience | Credential-use path |
| --- | --- | --- | --- |
| Embedded Bolt | The agent and Vouchr run in the same Node/Bolt process. | Built in | `context.vouchr.connect()` then `handle.fetch()` |
| **Hybrid** | Slack and the agent/MCP worker are separate services or languages. | Admin, connect, session, and the broker-denial recovery bridge (`recoverBrokerDenial`) are built in | Private `/v1/fetch` or `/v1/mcp` broker call |
| Pure headless | There is no Slack control plane, or the host intentionally owns every UI. | Host-built | Private broker API |

If the agent already runs in the same Bolt process, embedded Bolt is simpler. Hybrid is not a
security upgrade by itself; it is a process boundary for workers that cannot use the in-process
handle.

## Architecture

```mermaid
flowchart LR
    U["Slack user or admin"] --> S["Slack"]
    S -->|"events, /vouchr, interactivity"| C["Public Bolt control service"]
    O["Provider OAuth"] -->|"/vouchr/oauth/callback"| C
    C -->|"connections, channel config, audit"| P[("PostgreSQL")]
    C -->|"fresh signed identity per call"| W["Trusted request/transport router"]
    W -->|"private /v1/fetch or /v1/mcp"| B["Headless broker replicas"]
    B -->|"credentials, replay, policy state"| P
    B -->|"JIT secret resolution"| M["AWS Secrets Manager"]
    B -->|"validated HTTPS egress"| R["Provider or MCP server"]
```

Slack never calls the private broker. There is no persistent control-plane-to-broker connection and
no second credential database. The two planes form one Vouchr deployment through four shared facts:

1. one migrated PostgreSQL database;
2. compatible master-key/KMS configuration;
3. the same Vouchr version, provider IDs, and provider credential semantics; and
4. deployment-bound identity configuration understood by the trusted minter and every broker.

### Responsibilities

| Component | Owns | Must not own |
| --- | --- | --- |
| Bolt control service | Slack signature verification, `/vouchr`, App Home, modals, provider OAuth callback, Slack-derived identity/admin/channel facts | Provider egress for remote workers; a public broker route |
| Trusted request router/minter | Map the verified Slack event to a provider and owner, preflight Slack UX, mint one assertion for one broker call, and add it out of band after tool planning | Let the model choose identity claims; expose the assertion as a tool argument; expose the signing key to a generic worker |
| Headless broker | Replay protection, credential lookup/decryption/refresh, policy and egress checks, HTTP/MCP call, audit | Slack UI, Slack admin discovery, arbitrary identity minting |
| PostgreSQL | Authoritative connections, config, sessions, replay records, and audit | Encryption-key storage |
| Host/operator | Provider scopes, network perimeter, IAM, response handling/DLP, semantic write confirmation | Passing credentials through prompts, tools, logs, or Slack |

## 1. Reuse or create the Slack app

Install Vouchr in the agent's existing Slack app for the complete hybrid flow. A separate Vouchr app
can own App Home and `/vouchr` administration, but it does not automatically receive the agent app's
verified event or request-bound `context.vouchr`; on-demand per-user/session preflight then needs a
trusted cross-app handoff that remains host-owned under #194. Slack sends one command/event URL to one
receiver, so when reusing an app, install Vouchr in that app's existing Bolt ingress process or route
the same ingress endpoint to the combined receiver.

Start from [`examples/slack-manifest.yml`](../examples/slack-manifest.yml). Point all Slack-facing
requests at the **control service**, not the broker:

```text
Events:       https://CONTROL_HOST/slack/events
Interactivity:https://CONTROL_HOST/slack/events
/vouchr:      https://CONTROL_HOST/slack/events
Provider OAuth callback: https://CONTROL_HOST/vouchr/oauth/callback
```

Required for Vouchr's control surface:

- bot scopes: `chat:write`, `commands`, `users:read`, `channels:read`, `groups:read`;
- events: `app_home_opened` and `user_change`;
- App Home enabled;
- interactivity enabled; and
- the `/vouchr` slash command.

Add `app_mentions:read` and the `app_mention` event only when the same Slack app is also the agent.
`channels:read` and `groups:read` are security inputs: they let Vouchr verify channel type, creator,
membership, and shared-credential eligibility. Invite the app to private channels it must govern;
when Slack will not reveal a channel, shared access fails closed.

Provider OAuth and Slack app installation OAuth are different flows. Provider redirect URIs use
`/vouchr/oauth/callback`. A multi-workspace Slack app separately uses Bolt's installer routes and a
shared `DbInstallationStore`.

### App Home ownership

A Slack app has one Home tab. Choose one arrangement deliberately:

- let Vouchr own App Home;
- keep the agent's existing Home and use `/vouchr` as the built-in control UI; or
- build a host-owned Home with host-owned rendering and action handlers.

Vouchr avoids replacing a view with a foreign callback ID after it can identify it, but two
publishers can still race on the first Home open. Installing Vouchr does not merge two independent
Home interfaces automatically. Its built-in handlers intentionally ignore a foreign Home view, and
the complete action surface is not exported as a turnkey composition API; custom composition is
host integration work tracked by #194.

## 2. Run the Bolt control service

The usual single-workspace wiring is below. The published package currently exposes CommonJS
`require` conditions, so run these TypeScript examples through `tsx`/`tsc` CommonJS resolution; do
not copy them into a native `.mts`/`.mjs` entrypoint.

```ts
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, defineProvider, Policy } from '@vouchr/core';

async function main() {
  const receiver = new ExpressReceiver({
    signingSecret: process.env.SLACK_SIGNING_SECRET!,
  });
  const app = new App({
    token: process.env.SLACK_BOT_TOKEN!,
    receiver,
  });

  const internalMcp = defineProvider({
    id: 'internal-mcp',
    credential: 'key',
    authorizeUrl: '',
    tokenUrl: '',
    scopesDefault: [],
    egressAllow: ['mcp.internal.example'],
    egressPaths: ['/mcp'],
    egressMethods: ['POST'],
    mcp: { paths: ['/mcp'] },
    refresh: 'none',
    pkce: false,
    // Default injection is Authorization: Bearer <resolved secret>.
  });

  const providers = [internalMcp];
  const allowedChannels = (process.env.INTERNAL_MCP_CHANNEL_IDS ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const policy = new Policy(
    {
      'internal-mcp': {
        defaultAllow: false,
        allowChannels: allowedChannels,
      },
    },
    { defaultDeny: true },
  );

  const vouchr = await createVouchr({
    providers,
    baseUrl: process.env.PUBLIC_URL!,
    databaseUrl: process.env.VOUCHR_DATABASE_URL!,
    policy,
    allowChannelCreatorConfig: false,
    requireChannelMembership: true,
  });

  // The control plane owns periodic cleanup in this example.
  const lifecycle = vouchr.install(app, receiver);

  await app.start(Number(process.env.PORT ?? 3000)).catch(async (error) => {
    await lifecycle.stop();
    throw error;
  });

  let stopping: Promise<void> | undefined;
  const stop = () => stopping ??= (async () => {
    try {
      await app.stop(); // stop Slack admission first
    } finally {
      await lifecycle.stop(); // then stop the sweep and Vouchr-owned database pool
    }
  })();
  const requestStop = () => {
    void stop().catch(() => { process.exitCode = 1; });
  };
  process.once('SIGTERM', requestStop);
  process.once('SIGINT', requestStop);
}

void main().catch(() => { process.exitCode = 1; });
```

`install()` registers Vouchr's middleware, provider OAuth callback, `/vouchr`, App Home/actions and
modals, `user_change` offboarding, and (unless disabled above) the TTL sweep. The control service
writes connections and configuration directly to PostgreSQL. Its built-in Slack configuration path
does **not** call `/v1/admin/*` and does not need an `isAdmin` identity claim.

The provider uses Vouchr's default bearer injection. The packaged broker's JSON format cannot encode
an `inject` function, so stock hybrid configuration is bearer-only. A non-Bearer header or custom
signing scheme requires the low-level in-code `createBroker()` path and all of its deployment wiring;
setting `inject` only on the control-plane provider would create unsafe plane drift. Lock the real
provider to its exact HTTPS hosts, paths, methods, response shapes, and provider-side scopes.
`/v1/mcp` uses HTTP `POST`, so the broker also needs its explicit write opt-in; this is transport
permission, not semantic permission to run every MCP tool. The static policy above fails closed when
the channel allowlist is empty. Materialize the same provider/channel rules in the packaged broker's
`VOUCHR_POLICY` or `VOUCHR_POLICY_FILE`; the broker validates rule keys against its configured
providers and evaluates only the signed channel claim.

### Multi-workspace and Enterprise Grid

Use one injected database pool and the same `DbInstallationStore` instance for Bolt and Vouchr.
Because this app uses a custom `ExpressReceiver`, Bolt's OAuth installer options belong on that
receiver, not `new App()`. Inside `main()`, replace the single-workspace receiver/app construction
with:

```ts
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, DbInstallationStore, loadKeyring, openDb } from '@vouchr/core';

const db = await openDb({ databaseUrl: process.env.VOUCHR_DATABASE_URL! });
const store = new DbInstallationStore(db, loadKeyring());

const receiver = new ExpressReceiver({
  signingSecret: process.env.SLACK_SIGNING_SECRET!,
  clientId: process.env.SLACK_CLIENT_ID!,
  clientSecret: process.env.SLACK_CLIENT_SECRET!,
  stateSecret: process.env.SLACK_STATE_SECRET!,
  scopes: ['chat:write', 'commands', 'users:read', 'channels:read', 'groups:read'],
  installationStore: store,
});
const app = new App({ receiver });

const vouchr = await createVouchr({
  providers,
  baseUrl: process.env.PUBLIC_URL!,
  db,
  installationStore: store,
});
```

Channel state remains scoped by workspace and channel. `user_change` offboards one workspace;
Enterprise-wide deprovisioning requires the documented SCIM/admin offboarding path across every
workspace. Because `db` was injected, `install().stop()` does not close it; shutdown must stop Bolt,
stop the Vouchr lifecycle, and then `await db.close()`.

> [!WARNING]
> `DbInstallationStore` currently direct-master encrypts Slack installation tokens even when Vault
> credentials use a KMS envelope. That contradicts the production KMS boundary and is tracked by
> [#241](https://github.com/Dharin-shah/vouchr/issues/241); multi-workspace hybrid is not production-
> ready until it is fixed and migration/restore behavior is proven.

## 3. Run the private broker

Configure the packaged `vouchr-broker` from the same release as the control service. In hybrid,
leave `VOUCHR_BASE_URL` unset: the public OAuth callback belongs to Bolt. The broker should be
reachable only from trusted workers/tool routers.

```text
VOUCHR_DATABASE_URL=postgres://vouchr_app:...@postgres/vouchr?sslmode=verify-full
VOUCHR_MASTER_KEY=<same key material as the control service>
VOUCHR_IDENTITY_SECRET=<random identity-only signing key>
VOUCHR_DEPLOYMENT_ID=vouchr-production-eu1
VOUCHR_IDENTITY_ISSUER=vouchr-slack-control
VOUCHR_CHANNEL_MODES=1
VOUCHR_ALLOW_WRITES=1
VOUCHR_SWEEP_INTERVAL_MS=0
VOUCHR_PROVIDERS_FILE=/run/config/providers.json
VOUCHR_POLICY_FILE=/run/config/policy.json
VOUCHR_BROKER_TOKEN=<required unless mTLS/mesh or authorize authenticates callers>
```

Do not copy literal values from this example. Keep the identity key distinct from the Slack signing
secret, master/KMS keys, broker bearer, and every provider client secret. The control minter and all
broker replicas need the same deployment ID, issuer, and active/previous verification key set.

For the example above, `providers.json` contains the same declarative provider shape used by the
control service:

```json
[
  {
    "id": "internal-mcp",
    "credential": "key",
    "authorizeUrl": "",
    "tokenUrl": "",
    "scopesDefault": [],
    "egressAllow": ["mcp.internal.example"],
    "egressPaths": ["/mcp"],
    "egressMethods": ["POST"],
    "mcp": { "paths": ["/mcp"] },
    "refresh": "none",
    "pkce": false
  }
]
```

The matching `policy.json` keeps the operator boundary identical on the private data plane (replace
the channel id with the real Slack channel from this deployment):

```json
{
  "defaultDeny": true,
  "rules": {
    "internal-mcp": {
      "defaultAllow": false,
      "allowChannels": ["C0OPSROOM"]
    }
  }
}
```

Use exactly one policy source: inline `VOUCHR_POLICY` or file-backed `VOUCHR_POLICY_FILE`. Both set
is a startup error, not a merge. Unknown fields, wrong types, and rule ids absent from the configured
providers also fail startup. A `defaultDeny: true` policy with empty or missing rules is valid and
denies every provider; the broker warns at startup for that zero-rule lockdown.

`VOUCHR_ALLOW_WRITES=1` is present because MCP Streamable HTTP uses `POST`; the provider's own
method/path/MCP declarations still have to allow the request. It is not a general authorization to
run every MCP tool. `VOUCHR_SWEEP_INTERVAL_MS=0` makes the control plane the cleanup owner in this
example.

For OAuth providers, the broker also needs client configuration because refresh can happen at egress.
Deploy provider definitions and static policy as versioned artifacts for both planes and test that
their IDs, credential semantics, and channel rules match. The Bolt path is code-configured while the
packaged broker reads `VOUCHR_PROVIDERS` / `VOUCHR_PROVIDERS_FILE` and `VOUCHR_POLICY` /
`VOUCHR_POLICY_FILE`; deployment automation must prevent drift.

When using KMS envelope encryption, the packaged broker wires `VOUCHR_KMS_KEY_ID`, but
`createVouchr()` needs the matching `envelope` option explicitly. Both planes must use the same KMS
key identity/region and possess the encrypt/decrypt rights needed for their reads and writes. Do not
mistake KMS envelope encryption for an external-reference resolver; they are separate integrations.
The AWS KMS SDK dependency is not bundled in the published package/image, so KMS deployments need a
custom package/image layer containing it. Multi-workspace installation tokens remain outside the
envelope until [#241](https://github.com/Dharin-shah/vouchr/issues/241) closes.

> [!NOTE]
> The packaged broker enforces both the static operator `Policy` above and PostgreSQL-backed
> `ChannelTools` state shared with Bolt; neither gate can override a denial by the other.
> `VOUCHR_CHANNEL_MODES=1` is separate and only permits channel-owned credential modes.

Both `/v1/admin/reference` and `/v1/user/reference` enforce the reference-only boundary before any
credential, mode, or audit write: the broker validates a bounded supported reference form, derives its
source, and confirms that an own resolver function is configured without invoking it. Raw values,
unknown or malformed schemes, source mismatches, scopes outside the provider's declaration, and
missing resolvers fail with fixed errors that do not reflect caller input.

### External-secret resolver hook

The packaged builder allows a thin wrapper to inject resolvers without replacing identity,
database, provider, replay, or egress configuration.

> [!CAUTION]
> The following is a construction fragment, not a production entrypoint. A wrapper that calls
> `listen()` must also preserve the standalone binary's error handling, readiness, bounded graceful
> drain, database close, and—unless another plane owns it—periodic sweep lifecycle.

```ts
import { buildBrokerServer } from '@vouchr/core/headless';
import { awsSecretsManager } from './aws-secrets-manager.js';

async function main() {
  const built = await buildBrokerServer(process.env, {
    resolvers: awsSecretsManager(),
  });

  built.server.listen(built.port);
}

void main().catch(() => { process.exitCode = 1; });
```

The repository's [`examples/aws-secrets-manager`](../examples/aws-secrets-manager) contains a
reference resolver. It is an example, not part of the published npm package; the wrapper must install
`@aws-sdk/client-secrets-manager` and own the small adapter. A production resolver must accept the
provided `AbortSignal` and pass it into the SDK/network request so a deadline or disconnect cancels
the underlying call, not only Vouchr's wait. The repository example demonstrates this by passing
the signal to the AWS SDK `send` call.
Production wrappers must also preserve graceful draining and must schedule periodic cleanup unless
the control plane owns it. The standalone binary already owns both lifecycles, so preserve its
shutdown ordering when replacing its entrypoint.

Run one schema migration from the exact rollout image before starting either long-running service.
Use a schema-owner role only for `vouchr migrate`; both runtimes use DML-only credentials.

## 4. Mint identity only from verified Slack facts

The trusted Slack service or a narrow internal gateway mints a fresh, single-use assertion for each
broker request. Never let a model, untrusted MCP client, or generic worker supply `teamId`, `userId`,
`channel`, `threadTs`, `isAdmin`, `enterpriseId`, `offboardTargetUserId`, `ownerKind`, or
`channelEligible`.

```ts
import {
  channelIneligibleReason,
  loadIdentityConfig,
  mintIdentity,
} from '@vouchr/core/headless';

const identity = loadIdentityConfig(process.env);

type VerifiedSlackFacts = {
  teamId: string;
  userId: string;
  channel: string;
  threadTs: string;
  enterpriseId?: string;
};

type SlackChannelReader = {
  conversations: {
    info(input: { channel: string }): Promise<{
      channel?: Parameters<typeof channelIneligibleReason>[0];
    }>;
  };
};

async function mintForBrokerCall(
  facts: VerifiedSlackFacts,
  serverMode: 'shared' | 'per-user' | 'session' | null,
  client: SlackChannelReader,
) {
  // `facts` came from one verified Bolt request; `serverMode` came from Vouchr's
  // server-side manifest after preflight. Neither came from the worker/model.
  if ([facts.teamId, facts.userId, facts.channel, facts.threadTs].some((v) => !v.trim())) {
    throw new Error('Verified Slack identity is incomplete.');
  }
  const common = {
    teamId: facts.teamId,
    userId: facts.userId,
    channel: facts.channel,
    threadTs: facts.threadTs,
    ...(facts.enterpriseId ? { enterpriseId: facts.enterpriseId } : {}),
  };

  if (serverMode === 'shared') {
    let info: Parameters<typeof channelIneligibleReason>[0] = null;
    try {
      // Fetch by the exact channel being signed so eligibility cannot be borrowed
      // accidentally from another Slack response.
      info = (await client.conversations.info({ channel: facts.channel })).channel;
    } catch {
      // null is intentionally ineligible: Slack/API failure is fail closed.
    }
    if (channelIneligibleReason(info) !== null) {
      throw new Error('Channel is not eligible for a shared credential.');
    }
    return mintIdentity(
      { ...common, ownerKind: 'channel', channelEligible: true },
      identity,
    );
  }

  return mintIdentity({ ...common, ownerKind: 'user' }, identity);
}
```

Bolt payload shapes vary by event and action. Normalize them once, immediately after Slack signature
verification, and fail closed when a required fact is missing. `serverMode` above must be read from
Vouchr's current server-side manifest/config, never accepted from the worker. For a channel-owned
assertion, the signed `ownerKind: 'channel'` and `channelEligible: true` must agree with the request
handle. The broker rejects disagreement.

`channelEligible` proves the **channel class** only; it is not a signed membership claim. When
`requireChannelMembership: true`, the Bolt `connect()` preflight below must also run for shared mode,
because that is where membership is rechecked. A custom minter that skips Bolt preflight must verify
membership itself before minting channel ownership.

If the worker is not trusted with the identity signing key, keep minting in the control service and
either call the broker on the worker's behalf or expose a narrow internal gateway that accepts only
the already-authenticated action. Never expose a generic “mint arbitrary claims” endpoint.

`isAdmin: true` is only for custom callers of `/v1/admin/*`. Set it after the same fail-closed Slack
admin predicate used by the UI; never copy a boolean from request input. The built-in Slack control
path does not need this claim. For Enterprise Grid `/v1/admin/offboard`, also sign
`offboardTargetUserId` from the authenticated SCIM/directory subject and require the body
`targetUserId` to repeat that exact value. Never derive this claim from the generic request body;
admin status alone does not authorize choosing an arbitrary global user.

## 5. Bridge the Slack experience to the worker

The broker has no Slack client. Shared PostgreSQL lets both planes see the same state, but a broker
`403` or `409` does not automatically post a prompt. The trusted Bolt control plane owns the
user-facing transition through the supported bridge: relay the broker's typed denial body to
`context.vouchr.recoverBrokerDenial(provider, denial)` from the same verified Slack event context
that produced the worker's identity assertion, and Vouchr takes the correct private recovery action.
The denial body is routing guidance only — every identity, owner, mode, policy, and eligibility fact
is re-resolved from verified state, and again at any button click.

Provider OAuth callbacks mounted on the Bolt control plane are already closed-loop: one active
owner/provider generation is finalized transactionally, fixed browser outcomes return without
waiting for Slack, and attributable failures make at most one immediate, best-effort private
recovery-DM attempt. A process failure can drop that message.

For **every brokered mode**, preflight with the in-process Bolt context before dispatching the remote
worker. In shared mode this rechecks current mode, policy/tool state, credential presence, channel
class, and optional membership; in per-user/session mode it also renders the recovery prompt:

![Private connect prompt](../assets/slack-connect-prompt.svg)

Session mode uses the same preflight but binds the grant to the verified Slack thread:

![Thread-scoped session prompt](../assets/slack-session-thread.svg)

```ts
app.event('app_mention', async ({ context, event, client, say }) => {
  try {
    // Resolve mode and show the built-in OAuth/key/session prompt when needed.
    await context.vouchr.connect('internal-mcp');
  } catch (error) {
    // ConsentRequiredError / SessionApprovalRequiredError are control flow: the
    // private prompt is already posted, so stop this turn without calling the worker.
    if (isVouchrPrompt(error)) return;
    throw error;
  }

  const tool = (await context.vouchr.toolManifest())
    .find((entry) => entry.provider === 'internal-mcp');
  if (!tool?.enabled || tool.identity !== 'acting_human') {
    throw new Error('Internal MCP is not available in this channel.');
  }
  const ownerKind = tool.mode === 'shared' ? 'channel' : 'user';

  const result = await dispatchTrustedGateway({
    teamId: context.teamId,
    userId: event.user,
    channel: event.channel,
    threadTs: event.thread_ts ?? event.ts,
    provider: 'internal-mcp',
    ownerKind,
  });
  if (result.brokerDenial) {
    // The supported #194 bridge: relay the typed broker denial body from this verified context.
    // Vouchr re-resolves everything server-side and takes the correct private action — the
    // connect/key prompt, the thread session prompt, admin configuration direction, or the
    // Approve/Deny decision surface for the pending approvalId.
    const recovery = await context.vouchr.recoverBrokerDenial('internal-mcp', result.brokerDenial);
    if (recovery.status === 'resolved' || recovery.status === 'stale') {
      // Current state must be resolved again. Do NOT reuse the spent assertion or automatically
      // replay this operation: it may be a non-idempotent write. A new user-triggered turn starts
      // again at preflight and mints a fresh single-use assertion.
      await client.chat.postEphemeral({
        channel: event.channel,
        user: event.user,
        text: 'Vouchr state changed. Ask the agent to try the tool again.',
      });
      return;
    }
    if (recovery.status === 'not_bridgeable') {
      // The bridge owns only connect/session/approval denials. Keep every other safe broker
      // failure private; never fall through and publish it to the channel with say().
      await client.chat.postEphemeral({
        channel: event.channel,
        user: event.user,
        text: result.safeText,
      });
      return;
    }
    return; // a private prompt or configuration direction is live — stop this turn
  }
  await say(result.safeText);
});
```

The host-specific `isVouchrPrompt` and `dispatchTrustedGateway` functions are intentionally not Vouchr
APIs. The important ordering is: verified Slack event → Vouchr preflight → stop on prompt → trusted
server-side mode lookup → identity mint → private broker call → on a typed broker denial, relay the
body to `recoverBrokerDenial` from the same verified context. Prompt/configuration outcomes stop the
turn. `resolved` and `stale` mean only that a new attempt may re-resolve current state; they are not
replay authority. The example asks the user to start a new turn so the host repeats preflight and
mints a fresh assertion instead of automatically replaying a possibly non-idempotent operation.
`not_bridgeable` stays private and follows the broker's safe typed guidance. If the model chooses a
tool only after planning, intercept the proposed tool in the trusted host, run the same preflight,
and add the identity assertion out of band. It must never be a model-visible tool argument. A mode
change between preflight and egress fails closed; rerun preflight instead of guessing.

For a broker call, the worker sends only a handle and request shape; the signed assertion determines
the owner:

```json
{
  "handle": { "provider": "internal-mcp", "owner": "channel" },
  "identityToken": "<fresh single-use assertion>",
  "path": "/mcp",
  "headers": {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json"
  },
  "body": "<one MCP JSON-RPC message>"
}
```

Send that envelope to private `POST /v1/mcp`. Mint a new identity assertion for every JSON-RPC
message and every retry. Never put the assertion in a prompt, tool schema, Slack message, or log.

### Write-only protection

Vouchr can restrict provider hosts, paths, and HTTP methods and can make the broker read-only unless
`VOUCHR_ALLOW_WRITES=1`. It cannot infer whether an MCP `tools/call` JSON-RPC body is semantically a
read or a write because every MCP message uses HTTP `POST`.

There are two honest designs:

1. **Vouchr-enforced channel boundary.** Physically split read and write into different endpoints and
   provider IDs. The read credential/endpoint must be incapable of mutation. Apply default-deny
   static `Policy` to the write provider, keep the mutable channel enablement as a second admin
   control, and use a least-privilege write credential. The packaged broker enforces both boundaries;
   the request proceeds only when static policy and mutable channel enablement allow it.
2. **Host/MCP-server boundary.** Keep one MCP endpoint and let the trusted host/server classify tool
   names, authorize them, perform transaction-specific confirmation, and supply idempotency or
   reconciliation for consequential writes. Vouchr still protects the credential, owner, channel,
   and endpoint, but its policy applies to the whole provider endpoint—not an individual JSON-RPC
   tool name or body.

## What an admin and channel member actually do

“Admin” means a Slack workspace admin or owner by default. There can be any number of admins; Vouchr
does not maintain an admin table. `allowChannelCreatorConfig: true` additionally permits the exact
Slack channel creator, but it is off by default because ordinary members can create public channels.
A custom `isAdmin(client, userId, teamId)` callback replaces both rules and fails closed on errors.
It is workspace/user-scoped; it cannot currently express per-channel custom RBAC.

The Bolt predicate also governs channel audit/stats and `approver: 'admin'` recipients. Automatic
`user_change` offboarding is separate and does not ask for an interactive admin. On the headless
surface, one signed `isAdmin` boolean gates configuration, channel audit, and the offboard route;
Enterprise Grid offboarding additionally requires the signed `offboardTargetUserId` to equal the
body target. Scoped headless roles are not supported.

Owning the Vouchr service or PostgreSQL grants infrastructure control, not Slack UI authority. An
operator must still satisfy the Slack/admin predicate to use the built-in control surface.

### App Home flow

1. Every user sees **Your connections** and available on-demand providers.
2. With the default rule, workspace admins/owners see **Channel governance**. When
   `allowChannelCreatorConfig` is enabled, users may see the channel picker first; controls appear
   only after selecting a channel they created, and other selections fail closed.
3. The admin picks an internal public/private channel.
4. Each brokered provider row shows mode, Enable/Disable, and Configure credential controls.
5. Mode and enablement changes persist immediately and the Home view refreshes.
6. Errors and denials are private.

An `identity: 'service'` provider shows only Enable/Disable: its authentication belongs to the host.
An internal MCP that should use a Vouchr-managed bearer/key must therefore be a brokered key provider,
not a service provider. A service provider is outside Vouchr's credential/egress path, so its
Enable/Disable bit is manifest metadata that the trusted host—not Vouchr—must enforce. The packaged
admin route persists that bit in the same table as Bolt, and admin config plus the channel manifest
report it consistently; Vouchr's fetch/MCP routes still refuse service credentials outright.

Enable/Disable is backward-compatible runtime state, not deny-by-default policy. A channel with no
`channel_tool` rows treats all registered providers as enabled. Bolt's first toggle materializes the
full current provider list so changing one provider does not change the others. Static `Policy` is
the outer “only these channels” boundary; mutable tool state is the inner admin switch.

The equivalent slash-command flow is:

```text
/vouchr tools
/vouchr mode internal-mcp shared
/vouchr enable internal-mcp
/vouchr configure internal-mcp
/vouchr audit channel
/vouchr stats
```

Bare `/vouchr` opens the settings modal. Everyone sees connections and a read-only manifest; admins
can edit mode and enabled state and press **Save**. Provider-output rendering and data-loss
prevention belong to the trusted host; Vouchr does not retain provider responses or publish a
preview-visibility policy. The modal does not contain the shared-credential input; use App Home's
Configure credential action or `/vouchr configure <provider>`.

### Channel-member experience

- `shared`: the person asks the agent; no personal connection is required. Preflight checks the
  channel credential and optional membership, and the eventual use is audited as the acting human.
- `per-user`: first use posts a private OAuth/key prompt. The person connects, then retries the
  original request.
- `session`: the person acts in a Slack thread, approves the thread-scoped grant there, then retries
  before the grant expires.

### Channel credential modal

The private modal is titled **Channel credential** and accepts exactly one value:

- **External secret reference** — shown only for secret-manager resolvers configured in the Bolt
  process, with the available sources named in the hint; or
- **…or paste a key directly**. When Bolt has no resolver, this is the only field shown.

```text
Channel credential
Only you can see this input; it is never posted to the channel.

External secret reference
[ paste a reference supported by this deployment       ]

...or paste a key directly
[                                                      ]

                                      [Cancel] [Save]
```

In a split hybrid deployment, that modal can verify only the Bolt process's resolver configuration.
If the broker owns resolution, configure references through `/v1/admin/reference` or
`/v1/user/reference` so validation happens against the process that will use them. Do not register a
resolver in Bolt merely to make the field appear when the broker lacks the same capability.

Slack has no password/masked text input. Vouchr does not echo, post, or audit the submitted value,
but a reference is safer than a raw key. If the channel is unconfigured, successfully saving a
credential sets its mode to `shared`. If it is already `per-user` or `session`, the save is refused;
switch to `shared` first. Switching away from `shared` deletes the channel credential. Successful
configuration is confirmed privately by DM.

Shared credentials are refused for Slack Connect/externally shared or pending-shared channels, DMs,
group DMs, archived channels, and channels whose type cannot be verified. For private channels, invite
the app so the check can succeed.

### AWS Secrets Manager example

The ARN stored by Vouchr should point to the bearer/API key expected by the internal MCP server. The
broker resolves it just in time, so rotating the AWS secret changes the next request without a Vouchr
database update.

- configure the ARN through the Bolt modal or the appropriate headless reference route;
- register the matching resolver function in every process that accepts references (the Bolt
  control plane and broker here), but grant network/IAM access only where egress resolves it;
- give the broker workload role `secretsmanager:GetSecretValue` only on the exact ARNs and
  `kms:Decrypt` only when the secret uses a customer-managed KMS key; and
- smoke-test an actual resolution—saving the ARN proves persistence, not IAM access or secret shape.

For AWS API access itself, prefer workload IAM rather than storing long-lived AWS access keys. A
generic bearer/key injector does not implement AWS SigV4 request signing.

## Shared configuration contract

| Setting | Control service | Broker | Rule |
| --- | --- | --- | --- |
| `VOUCHR_DATABASE_URL` | yes | yes | Same migrated cluster/database; runtime roles are DML-only |
| Master key/keyring | yes | yes | Required even with envelope encryption; both planes must decrypt existing/direct-key rows |
| KMS envelope (production) | explicit `envelope` option | `VOUCHR_KMS_KEY_ID` + SDK layer | Required by the production vision; same KMS key identity/region and compatible IAM, additional to the master keyring |
| Provider IDs and credential semantics | yes | yes | Deploy from one versioned source; broker also needs refresh client credentials |
| `ChannelTools` runtime state | writes through Bolt/App Home | reads, writes, and enforces the same PostgreSQL rows | Brokered manifest/fetch/MCP enforce it; service-tool egress remains host-enforced |
| Identity deployment ID/issuer/keys | minter only | verifier | Same values and bounded rotation set |
| Slack signing secret/bot tokens | yes | no | Public Slack ingress only |
| `PUBLIC_URL`/provider callback | yes | no | OAuth callback stays on Bolt in hybrid |
| Broker perimeter auth | no | yes | mTLS/mesh, `authorize`, or a coarse bearer alternative; `authorize` replaces the bearer check |
| External-secret resolver and IAM | resolver entry wherever references are accepted; IAM only where egress runs | resolver entry + IAM | Saving validates that a matching resolver function is configured but does not invoke it; the egress process resolves JIT and needs network/IAM access |
| Resource bounds | control HTTP server | yes | Finite ingress, egress, pool, stream, and shutdown limits |

Do not give PostgreSQL ownership/DDL rights to either runtime. Budget database connections as
`(VOUCHR_PG_POOL_MAX + 4) × replicas` per plane that opens its own pool; share a pool inside one
process where possible.

## Failure and retry contract

Typed broker egress failures include stable `code`, `retryable`, and `recovery` fields from the same
core mapper exported by `@vouchr/core` and `@vouchr/core/headless`. Branch on those fields, never the
human-readable `error` prose. The trusted bridge still derives owner/channel/thread facts from verified Slack
state; recovery metadata is routing guidance, not authority.

| Signal | Meaning | Safe response |
| --- | --- | --- |
| `409`, code `not_connected` | No usable owner credential | Relay to `recoverBrokerDenial`: user ownership gets the private connect/key flow; shared ownership directs an eligible admin to channel configuration. Do not loop broker retries |
| `403`, code `session_approval_required` | No live thread grant | Relay to `recoverBrokerDenial` from the verified thread context: it creates/reuses the one thread-scoped approval prompt, and the click re-validates everything at the mutation. Retry only after the grant, with a fresh assertion |
| `403`, code `approval_required` | A write needs a human grant | Relay to `recoverBrokerDenial`: the opaque `approvalId` is a lookup handle, never authority — the bridge re-reads the pending row, re-derives the self/admin rule from the registry, and delivers the decision surface. Retry only after one live grant, with a fresh assertion |
| `policy_denied` or `tool_disabled` | Provider is not authorized here | Follow non-retryable `contact_admin`; never silently widen scope or loop retries |
| `429` code `rate_limited` or `503` code `overloaded` | Bounded back-pressure | Only `retry_later` outcomes are retryable; honor `Retry-After`, mint a fresh assertion, and retry only when the operation is safe |
| `504`, code `upstream_timeout`, `retryable: false` | Provider outcome may be unknown | `retry_later` describes the operator/user action, not replay permission. Retry only a known-idempotent operation; never auto-replay an uncertain write |
| identity `401` | Bad/expired/replayed assertion or config drift | Mint once more from verified facts; repeated failure is an issuer/audience/key/clock incident |
| `/readyz` `503` | Schema, database, or replay store unavailable | Remove the replica from traffic; `/healthz` may remain 200 by design |
| code `resolver_configuration_error` | Resolver wiring/reference is missing or malformed, or the resolver fulfilled with an invalid value | Follow `fix_configuration`; fail closed with no plaintext fallback and do not loop unchanged retries. `/readyz` may remain green |
| code `resolver_failed` | A configured resolver threw or timed out before provider egress | Follow retryable `retry_later`; never expose resolver output or failure text. `/readyz` may remain green |
| code `token_endpoint_failed` | Refresh grant, OAuth client configuration, or token dependency failed | Follow the returned recovery: `connect` for a dead grant, `fix_configuration` for client/config rejection, or retryable `retry_later` for RFC transient codes and 408/429/5xx/network/timeout |
| code `internal_error` | Unclassified extension/provider failure | Follow `contact_admin`; fixed wire copy reveals neither foreign message nor class name |

Identity assertions are single-use. Every retry needs a new assertion even when the previous request
was rejected before provider egress. Never use a retry response to infer that the earlier assertion
is reusable.

The broker cannot post credential-health DMs. Forward `onCredentialHealth` events to a trusted
notification path in the Slack control service, using `NotificationState` to debounce across
replicas.

Audit table writes are authoritative but best-effort relative to an upstream provider action: an
upstream action can succeed before a later audit insert fails. `EventSink` and `AuditSink` are
fire-and-forget callbacks, and `AuditSink` is explicitly lossy; neither is an archive or proof of
completeness. Feed no-secret events into an operator-owned durable/idempotent pipeline as an
independent reconciliation signal, monitor database health, and never promise transactional
provider+audit atomicity.

### Component outages

- When Slack or the Slack API is unavailable, admin/channel verification and new prompts fail closed.
  The minter must never replace missing Slack facts with worker-supplied values.
- When the control service is unavailable, App Home, `/vouchr`, provider OAuth callback, and new
  assertions from a colocated minter are unavailable. The broker must not become a fallback admin UI.
- When the broker is unavailable or overloaded, agent use fails without weakening policy. Honor
  bounded back-pressure only for retry-safe operations and mint a fresh assertion per attempt.
- When PostgreSQL, the schema, or the replay store is unavailable, `/readyz` returns 503 and the
  replica leaves traffic. `/healthz` remains a process-liveness probe.
- Readiness does not prove Slack, KMS, an external resolver, or a provider is healthy. Monitor those
  dependencies separately and keep every failure path credential-free.

## Security and operations checklist

Before a production claim, verify all of the following with the exact image and configuration:

- The broker is private behind mTLS/mesh or a fail-closed `authorize` hook; a static bearer alone is
  only coarse perimeter authentication.
- PostgreSQL uses TLS and encrypted, access-controlled storage. Migration runs once as schema owner;
  both runtimes use DML-only roles.
- Provider host/path/method rules are exact, HTTPS-only, and tested for redirects and encoded paths.
- Provider tokens/scopes and AWS resolver IAM are least privilege.
- The model, worker schemas, request logs, Slack surfaces, audit metadata, and error text never contain
  credentials, identity assertions, secret references where treated as sensitive, or MCP session IDs.
- The host treats provider/MCP responses as untrusted and owns DLP and Slack/model rendering.
- One component owns scheduled TTL cleanup. Overlapping sweeps are safe, but one owner is simpler.
- Resolver deadlines cancel the underlying SDK/network operation, not only Vouchr's wait; prove no
  work remains after caller disconnect or timeout.
- `user_change`, disconnect, SCIM/org offboarding, and upstream revoke failure paths are exercised.
- `SIGTERM` stops admission, closes idle sockets, drains active work, and exits nonzero after the hard
  timeout.
- Database backups are restorable only together with the required keyring/KMS versions and resolver
  IAM; test one credential in every supported mode after restore.
- Alerts cover broker readiness, identity rejection spikes, provider timeouts, refresh-dead events,
  resolver/KMS failure, database health, external-event delivery, and pool saturation. There is no
  direct built-in “audit insert failed” signal today, so reconcile the table against external events.
- Audit retention/archive requirements are chosen explicitly and the bounded prune path is tested on
  representative volume.
- The configured concurrency, pool, stream, body, response, KMS, and provider-timeout envelope is
  measured with the exact image under representative load.

This checklist is not sufficient by itself. The canonical release contract remains
[#226](https://github.com/Dharin-shah/vouchr/issues/226): complete the containment/recovery gate in
[#239](https://github.com/Dharin-shah/vouchr/issues/239), the multi-workspace envelope boundary in
[#241](https://github.com/Dharin-shah/vouchr/issues/241), the exact-image, two-replica,
failover/rolling/load proof in [#216](https://github.com/Dharin-shah/vouchr/issues/216), the
protected reproducible scanned release gate in
[#217](https://github.com/Dharin-shah/vouchr/issues/217), and the independent source-assisted
assessment plus retest in [#225](https://github.com/Dharin-shah/vouchr/issues/225) before a
production-ready claim.

### Rotation order

- **Identity key:** pre-stage the new key as the overlap key on every minter and broker; activate it
  everywhere with the old key as previous; after the last old token plus the documented 6m30s
  horizon, retire the old key. Keep the deployment ID stable unless intentionally invalidating all
  in-flight assertions.
- **Direct master key (development/transition rows):** deploy new primary + old fallback to both
  planes, run `vouchr rekey`, verify zero old/unreadable blobs, then remove the old key only after
  dependent backups expire. The production vision additionally requires KMS envelope encryption.
- **KMS envelope key:** rotate behind a stable KMS key ID/alias and retain versions required by stored
  and backed-up wrapped data keys.
- **External secret:** rotate at the same ARN; the broker resolves the new value on the next request.

See [`DEPLOYMENT.md`](./DEPLOYMENT.md) for the complete migration, rollout, key rotation, image,
resource-bound, retention, and backup procedures.

## End-to-end staging proof

Run this proof against at least two broker replicas and one shared PostgreSQL database:

1. Migrate with the exact release image, then prove both runtime roles lack DDL privileges.
2. Connect a per-user provider in Slack; retry and prove the remote worker uses only that user's
   credential without receiving it.
3. Set a provider to `session`; prove the verified thread prompts, grants, expires, and cannot be
   reused from another thread.
4. Configure an AWS ARN as a channel credential; prove another eligible member can use it in that
   channel, a non-member is refused when membership is required, and a different channel cannot use
   it.
5. Disable the provider in App Home and prove the **separate packaged broker** refuses it before
   credential resolution or upstream I/O.
6. Apply default-deny static policy through `VOUCHR_POLICY_FILE` and prove an unlisted channel is
   refused by the packaged broker.
7. Prove Slack Connect, DM, archived, unverifiable, and forged-channel requests fail closed.
8. Replay one assertion against two replicas and prove exactly one succeeds.
9. Exercise provider timeout after dispatch; prove no automatic write retry occurs.
10. Deactivate/offboard a user while OAuth is in flight and prove the credential cannot reappear.
11. Prove both reference routes reject raw, malformed, mismatched-source, invalid-scope, and
    unconfigured-resolver input without creating a credential, channel mode, or audit row. Then deny
    resolver/KMS IAM and prove there is no plaintext fallback and no secret in output/audit. Cancel
    one resolver call and prove the underlying SDK work ends.
12. Prove a remote `approval_required` stops the turn, exposes no decision authority, and performs
    no credential read or upstream I/O. Then relay the denial to `recoverBrokerDenial` and prove
    decision, expiry, double-click, and single-use convergence through the delivered surface
    (`test/broker-bridge.test.ts` is the repository's two-process reference proof).
13. Drain one broker under load, restore PostgreSQL from backup, prove #239's containment state
    prevents post-backup deletes/offboarding/replay windows from resurrecting access, and complete
    one request in every supported credential mode before returning traffic.

Do not replace these behavioral checks with GitHub mergeability or green CI. Checks are useful
signals; production readiness requires the current-head behavior and deployment to satisfy the
vision and the open blocker set above.

## Troubleshooting map

- **Users see no App Home controls:** confirm `app_home_opened`, App Home enablement, scopes, and that
  another component is not publishing the app's Home tab.
- **Private channel cannot use shared credentials:** invite the app, then verify
  `conversations.info` succeeds and the channel is internal and active.
- **Admin is refused:** default checks Slack `is_admin`/`is_owner`; a custom `isAdmin` replaces that
  behavior entirely and fails closed on errors.
- **Slack configuration changes but broker still permits use:** verify both planes use the same
  PostgreSQL database/schema and provider id, the assertion carries the intended signed team/channel,
  and every broker runs the current release. There is no channel-allowlist cache to wait out.
- **ARN saves but egress fails:** verify the resolver is wired on the broker, region/IAM/KMS rights,
  and the secret value is the exact credential shape the provider expects.
- **Broker returns session/approval denial with no Slack prompt:** shared storage alone does not
  bridge UI; relay the typed denial body to `recoverBrokerDenial` from the verified event context
  (or run Bolt preflight before dispatch). Never mutate interaction tables directly — the bridge and
  the click handlers own those mutations.
- **Identity fails only on some replicas:** compare deployment ID, issuer, active/previous key set,
  clock sync, and rollout phase across minters and every broker.
- **OAuth succeeds but worker cannot use the connection:** compare provider IDs/config, database,
  keyring/KMS access, owner kind, and channel/thread claims across both planes.
