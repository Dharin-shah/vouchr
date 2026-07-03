# Deploying Vouchr

Concrete recipes for the deployments Vouchr actually supports. Every option named here is real
(`src/adapters/bolt.ts` → `VouchrOptions`). For the security model and what
Vouchr does *not* protect against, see [SECURITY.md](../SECURITY.md), which is not repeated here.

Common to every deploy: a 32-byte `VOUCHR_MASTER_KEY` (`openssl rand -base64 32`) and a public
HTTPS `baseUrl` reachable at the OAuth callback (`$baseUrl/vouchr/oauth/callback`).

## SQLite (local / single instance): the default

Zero config. With no `databaseUrl`, Vouchr opens a SQLite file (`vouchr.db` by default).

```ts
const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  // dbPath: '/data/vouchr.db',   // or set VOUCHR_DB; defaults to ./vouchr.db
});
```

Path resolution: `dbPath` option → `VOUCHR_DB` env → `vouchr.db`. Fine for a single instance
(the file is local). The file is **not** fully encrypted at rest (only token columns are), so put
it on an encrypted, access-controlled volume.

## Postgres (multi-instance / stateless)

For more than one instance, use Postgres so any instance can serve any request. `databaseUrl`
(or `VOUCHR_DATABASE_URL`) takes precedence over `dbPath`.

```ts
const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  databaseUrl: process.env.VOUCHR_DATABASE_URL!, // postgres://user:pass@host:5432/vouchr
});
```

Local Postgres for development (throwaway Docker container on port 5433):

```bash
npm run pg:up   # postgres:16-alpine, db/user/pass all "vouchr"
export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5433/vouchr
npm test        # exercises the Postgres backend
npm run pg:down # tear it down
```

Multi-instance notes:
- All instances share one Postgres; credentials are isolated by `team_id`, so multiple workspaces
  are safe on one database.
- For an app installed to **many** workspaces, also wire a `DbInstallationStore` (next section).
  It persists per-workspace bot tokens in the `installation` table so any instance can post the
  post-OAuth confirmation DM with the connecting user's own workspace token.

## Multi-workspace install (`DbInstallationStore`)

A single-workspace app just sets `botToken` (or `SLACK_BOT_TOKEN`). For multi-workspace / org-wide,
construct one `DbInstallationStore` over the shared DB handle and master key, and pass the **same
instance** to both Bolt's OAuth `installationStore` and `createVouchr`:

```ts
const store = new DbInstallationStore(db, masterKey);

const app = new App({ /* ...OAuth config... */, installationStore: store });

const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  databaseUrl: process.env.VOUCHR_DATABASE_URL!,
  installationStore: store, // confirmation DM uses the connecting user's workspace token
});
```

## AWS Secrets Manager resolver

Instead of storing a raw secret, point a credential at a secret-manager **reference**; Vouchr stores
the reference and calls a resolver just-in-time at the HTTP boundary. Resolvers are keyed by source
id (`Resolvers = Record<string, (ref) => Promise<string>>`).

```ts
import { awsSecretsManager } from './examples/aws-secrets-manager/resolver';

const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  resolvers: awsSecretsManager(), // { 'aws-sm': resolveArn }
});
```

An admin then runs `/vouchr configure github` and pastes an ARN into the private modal. Full setup,
auth (ambient IAM role, no static creds), and the least-privilege policy
(`secretsmanager:GetSecretValue` scoped to the specific ARNs, `kms:Decrypt` if the secret uses a CMK)
are in [`examples/aws-secrets-manager/README.md`](../examples/aws-secrets-manager/README.md).

## KMS envelope encryption (optional)

By default token columns are encrypted directly with `VOUCHR_MASTER_KEY`. Supply an
`EnvelopeProvider` and new writes instead wrap a fresh per-secret data key (DEK) with your KMS key
(KEK), storing the wrapped DEK alongside the ciphertext. It's **optional and back-compatible**:
existing rows still decrypt either way.

The interface (`src/core/crypto.ts`) is two async methods:

```ts
interface EnvelopeProvider {
  wrapDataKey(dek: Buffer): Promise<Buffer>;
  unwrapDataKey(wrapped: Buffer): Promise<Buffer>;
}
```

A real AWS KMS provider (no SDK added to Vouchr, you bring `@aws-sdk/client-kms`):

```ts
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';

const kms = new KMSClient({});
const KEY_ID = process.env.VOUCHR_KMS_KEY_ID!;

const kmsEnvelope: EnvelopeProvider = {
  // seal() mints its own DEK, so we KMS-Encrypt it to get the wrapped form.
  // (GenerateDataKey, which returns plaintext + ciphertext DEK in one call, is the
  //  alternative if you let KMS mint the DEK instead.)
  async wrapDataKey(dek) {
    const r = await kms.send(new EncryptCommand({ KeyId: KEY_ID, Plaintext: dek }));
    return Buffer.from(r.CiphertextBlob!);
  },
  async unwrapDataKey(wrapped) {
    const r = await kms.send(new DecryptCommand({ KeyId: KEY_ID, CiphertextBlob: wrapped }));
    return Buffer.from(r.Plaintext!);
  },
};

const vouchr = await createVouchr({ /* ... */, envelope: kmsEnvelope });
```

IAM: `kms:Encrypt` and `kms:Decrypt` on that one key. See `test/envelope.test.ts` for the worked
sketch this is drawn from.

## Standalone headless broker (no Slack)

Run Vouchr as a plain HTTP service for non-Bolt agent runtimes. Same core (encrypted store, egress
allowlist, refresh, audit); the front door is signed identity tokens instead of Slack. It injects
credentials at egress, and — when the OAuth flow is mounted (`VOUCHR_BASE_URL`, #52) — can also run
per-user consent end-to-end, so a headless host needs **no Slack app** to onboard users. See
*Provisioning* below for the other ways credentials get into the store.

Entrypoint: `dist/bin/broker-server.js` (dev: `npm run broker`). It serves `POST /v1/fetch`,
`POST /v1/resolve`, `POST /v1/disconnect`, `POST /v1/admin/offboard`, `POST /v1/status`,
`POST /v1/user/reference`, `GET /v1/manifest`, `GET /healthz` (alias `/health`), and — when channel
modes are enabled — `POST /v1/admin/reference`, on `VOUCHR_PORT` (default 3000), and runs the TTL
sweep on a timer (see *Lifecycle*). With `VOUCHR_BASE_URL` set it additionally serves
`POST /v1/connect` and the OAuth callback (below).

### OAuth connect flow (headless consent, #52)

Set `VOUCHR_BASE_URL` (this broker's public HTTPS origin) to mount the consent handshake — the same
core state/PKCE/exchange the Bolt adapter uses, no duplicated crypto:

- `POST /v1/connect` — body `{ handle: { provider }, identityToken }`. Returns `{ authorizeUrl, state }`
  for the **verified** user (state is bound to the signed identity, never the body). Your host presents
  `authorizeUrl` to the user however it likes — the broker owns **no** chat/messaging surface.
- `GET <callbackPath>` (default `/oauth/callback`, override with `VOUCHR_CALLBACK_PATH`) — the OAuth
  redirect target. Consumes the single-use state, exchanges the code, vaults the token, audits, and
  returns a minimal HTML landing page. Register `"$VOUCHR_BASE_URL$callbackPath"` as the provider's
  redirect URI. A `?error=` denial fires the `consent_denied` audit and stores nothing.

When a `/v1/resolve` returns `needs_consent`, drive the user through `POST /v1/connect`; the next
`/v1/fetch` for that user then succeeds. The broker never handles a raw token itself — it is only ever
written to the vault inside the callback.

### Convenience: batch status + manifest (#55)

Two non-secret helpers so a host needn't loop `/v1/resolve` or re-derive the provider list:

- `POST /v1/status` — body `{ identityToken }`. Returns the acting user's state across ALL brokered
  providers in one call: `{ providers: [{ provider, connected, consentState }] }` (service tools
  omitted). No secret material — the batched form of `/v1/resolve`.
- `GET /v1/manifest` — `{ providers: [{ provider, identity }] }`, where `identity` is `acting_human`
  (Vouchr brokers it) or `service` (host wires its own auth). Non-secret policy metadata; behind the
  perimeter gate.

### Trust model

The broker trusts a **signed identity token** (HS256, `VOUCHR_IDENTITY_SECRET` shared only with your
upstream minter), never the request body — the owner is always the verified acting user. Each token
carries a `jti` that is single-use; on Postgres this is enforced **cluster-wide** (see *Replay*). A
network perimeter (`VOUCHR_BROKER_TOKEN`, or a pluggable `authorize` hook) is a coarse gate in front,
NOT identity.

Mint tokens on the caller side with the exported `mintIdentity(acting, secret)` helper — it fills a
fresh `jti` and a short, ceiling-clamped `exp` so you don't hand-roll the replay/expiry rules. See
[`examples/broker-client/client.ts`](../examples/broker-client/client.ts) for the full call.

### Channel-owned credentials headless (`owner: "channel"`)

By default the broker is **user-only**: a `handle.owner` of `"channel"` is refused. Set
`VOUCHR_CHANNEL_MODES=1` to enable the transport-agnostic channel gate (#51), which lets a headless
caller reach the same `shared` / `union` channel modes the Bolt adapter offers — **without** a Slack
client in the broker. The broker has no way to read Slack, so **the caller supplies the Slack-derived
facts as signed claims** and the broker trusts them at the same level as `teamId`/`userId`:

- `ownerKind: "channel"` — the request targets a channel-owned credential. It must match `handle.owner`
  or the request is refused, so a forged body alone can never reach a channel credential.
- `channelEligible` — the caller's `channelIneligibleReason(conversations.info) === null` verdict. The
  caller **must** compute this with the exported `channelIneligibleReason` (refuse externally-shared /
  Slack-Connect / DM / archived channels — the cross-org leak case). The broker **fails closed**: a
  channel request with this absent or false is refused.
- `actingMemberId` — for `union` mode, the connected member the caller elected to act as. That member
  is the vault owner **and** the audited actor — never the channel, never the caller.

Mint them via `mintIdentity`'s optional fields:

```ts
const token = mintIdentity(
  { teamId, userId, channel, ownerKind: 'channel', channelEligible: channelIneligibleReason(info) === null,
    actingMemberId /* union only */ },
  process.env.VOUCHR_IDENTITY_SECRET!,
);
```

`shared` resolves to the channel's credential (audited as the acting human); `union` resolves to the
signed member's own credential (audited as that member). `per-user` / `session` channels are **not**
reachable this way — those are user-owned modes, so the caller uses `owner: "user"`.

#### Admin channel-credential config (`POST /v1/admin/reference`, #53)

With channel modes enabled (`VOUCHR_CHANNEL_MODES=1`), an admin can point a channel's **shared**
credential at an external secret manager over HTTP — **reference only, never a raw secret**:

```
POST /v1/admin/reference
{ "handle": { "provider": "<id>" }, "identityToken": "<signed>",
  "source": "aws-sm", "secretRef": "arn:aws:secretsmanager:…" }
```

- Admin authority comes from the **signed `isAdmin` claim** (your minter sets it after its own
  workspace-admin check — the broker can't verify Slack admin itself); fail closed.
- Channel eligibility is enforced on the signed `channelEligible` claim (shared creds refused on
  ineligible / externally-shared channels).
- It stores only the non-secret reference (`vault.reference`) and flips the channel to `shared`; the
  configured `resolvers` resolve it JIT at egress. **No raw secret ever crosses the broker** — the
  broker deliberately has no raw-key HTTP ingest. A headless host wanting static keys points at a
  secret manager instead. Returns `{ ok: true }`.

### Environment contract

| Var | Required | Purpose |
| --- | --- | --- |
| `VOUCHR_IDENTITY_SECRET` | yes | HS256 secret shared with the identity-token minter. |
| `VOUCHR_MASTER_KEY` | yes | base64 of 32 bytes; encrypts tokens at rest (`openssl rand -base64 32`). |
| `VOUCHR_DATABASE_URL` | prod | `postgres://…` → Postgres. Unset → SQLite (`VOUCHR_DB`, single replica). `DATABASE_URL` is read as a fallback, so a platform-injected one selects the backend. |
| `VOUCHR_PROVIDERS` / `VOUCHR_PROVIDERS_FILE` | yes | provider config (inline JSON / file path); see below. |
| `VOUCHR_PROVIDER_<ID>_CLIENT_ID` / `_CLIENT_SECRET` | per OAuth provider | client creds, kept out of the JSON. |
| `VOUCHR_KMS_KEY_ID` | prod | enables the KMS envelope (KEK). Needs `@aws-sdk/client-kms` in the image. |
| `VOUCHR_BROKER_TOKEN` | no | static bearer for the coarse perimeter gate on `/v1/*`. |
| `VOUCHR_TTL_IDLE_MS` / `VOUCHR_TTL_MAX_AGE_MS` | no | credential idle / max-age TTL (#54). Default 7d / 30d (matches the Bolt path); `0` disables that dimension. |
| `VOUCHR_SWEEP_INTERVAL_MS` | no | TTL sweep interval (#54). Default hourly; `0` defers to an external scheduler. |
| `VOUCHR_BASE_URL` | for OAuth | public HTTPS origin of this broker; setting it mounts `POST /v1/connect` + the OAuth callback (#52). |
| `VOUCHR_CALLBACK_PATH` | no | OAuth redirect path under `VOUCHR_BASE_URL` (default `/oauth/callback`). |
| `VOUCHR_ALLOW_WRITES` | no | `1`/`true` opts into the write path (still per-provider `egressMethods`). |
| `VOUCHR_CHANNEL_MODES` | no | `1`/`true` enables `owner:"channel"` handles (shared/union) via signed channel-fact claims (#51). Off → user-only broker. |
| `VOUCHR_PRODUCTION` | prod | `1` → boot fails fast unless Postgres **and** a KMS envelope are configured. |
| `VOUCHR_PORT` | no | listen port (default 3000). |
| `VOUCHR_SEED_ACCESS_TOKEN` | seed only | `broker-seed key` reads the token from here (preferred over the argv flag). |
| `AWS_REGION` | with KMS | region for the KMS client (else SDK default chain). |

Boot validation is fail-fast and names the missing variable; nothing sensitive is logged (startup
prints one line: port, backend, provider ids, `allowWrites`, mode).

### Provider config (declarative)

Declare providers without editing source. Declarative fields only — a provider needing function
fields (`inject`, `egressValidate`, `revoke`) must be registered in code. Unknown fields are
rejected (fail closed). Secrets come from the per-provider env vars above, never the JSON:

```json
[
  {
    "id": "confluence",
    "authorizeUrl": "https://auth.atlassian.com/authorize",
    "tokenUrl": "https://auth.atlassian.com/oauth/token",
    "scopesDefault": ["read:confluence-content.all"],
    "egressAllow": ["api.atlassian.com"],
    "refresh": "rotating",
    "pkce": true
  }
]
```

With no `egressMethods`, the broker default-denies non-GET/HEAD — a read-only provider. Opt into
writes with `VOUCHR_ALLOW_WRITES=1` **and** an explicit `egressMethods` on the provider.

### Provisioning (how credentials get in)

- **Shared / referenced credential** (channel- or team-owned): seed it without Slack.
  ```bash
  # a pointer to an external secret manager (nothing sensitive stored by Vouchr):
  npm run seed -- reference --provider confluence --team T1 --channel C1 \
      --source aws-sm --secret-ref arn:aws:secretsmanager:…:secret/confluence
  # or a static token — pass it in the environment, NOT on the command line:
  VOUCHR_SEED_ACCESS_TOKEN="$TOKEN" npm run seed -- key --provider internal --team T1 --channel C1
  ```
  Prefer `VOUCHR_SEED_ACCESS_TOKEN`: a `--access-token` flag lands in `process.argv`, visible via
  `ps`/`/proc` to any co-tenant. The flag exists only for interactive use.
- **Per-user credentials** (each human's own account): either mount the headless OAuth flow
  (`VOUCHR_BASE_URL`, #52) and drive users through `POST /v1/connect` → callback directly, **or** run
  the Bolt control-plane Vouchr against the **same Postgres database** so users connect in Slack and
  the headless broker reads what they consented to. One store, two front doors.

  > ⚠️ **Two doors → two OAuth redirect URIs.** The two front doors default to **different** callback
  > paths: the Bolt adapter defaults to `/vouchr/oauth/callback`, the standalone broker defaults to
  > `/oauth/callback`. If BOTH mount the OAuth flow against the same shared DB, the same provider OAuth
  > app must register **both** redirect URIs (`$PUBLIC_URL/vouchr/oauth/callback` **and**
  > `$VOUCHR_BASE_URL/oauth/callback`), or a connect started on one door will fail its redirect. To
  > avoid the mismatch, either drive consent through only one door, or align them explicitly
  > (`callbackPath` on `createVouchr`, `VOUCHR_CALLBACK_PATH` on the broker) and register the one path.
- **Per-user *referenced* credentials** (a user's own key for a non-OAuth provider): the user points
  their credential at an external secret-manager reference with `POST /v1/user/reference` (#58) —
  body `{ handle: { provider }, identityToken, source, secretRef, scopes? }`. Self-service (identity
  from the signed token), **reference only** — no raw secret crosses the broker; the configured
  `resolvers` resolve it JIT at egress. Raw-key ingest stays out of the broker by design.

### Lifecycle: disconnect, offboard, TTL sweep (#54)

The headless broker can **revoke** credentials, not just inject them — the two checklist items
"deactivated users lose access" and "TTL sweep scheduled" are satisfied without the Bolt control plane.

- `POST /v1/disconnect` — body `{ handle: { provider }, identityToken }`. The acting user revokes their
  OWN connection for one provider (identity from the signed token; a forged body can't disconnect
  someone else). Local delete first, best-effort upstream revoke. Returns `{ ok, revoked: string[] }`.
- `POST /v1/admin/offboard` — body `{ identityToken, targetUserId }`. Removes ALL of the target's
  connections + pending consent + thread grants (wire it to your directory/deprovision hook). Admin
  authority comes from the **signed `isAdmin` claim** — the broker can't verify workspace admin itself,
  so your minter sets it after its own check; fail closed. A signed `enterpriseId` routes the
  cross-workspace (Grid/SCIM) case to `offboardUserEverywhere`.
- **TTL sweep** — `broker-server` runs the sweep at startup and every `VOUCHR_SWEEP_INTERVAL_MS`
  (default hourly; `0` to defer to your own scheduler). It deletes connections past the TTL policy
  (`VOUCHR_TTL_IDLE_MS` / `VOUCHR_TTL_MAX_AGE_MS`, default 7d / 30d) plus stale consent and expired
  thread grants. The sweep is idempotent, so overlapping runs across replicas are safe. **Note:** the
  default TTL now matches the Bolt path — a pure-headless deployment that previously kept credentials
  forever will start expiring them; set both TTL vars to `0` to preserve unbounded lifetime.

For in-process control, `offboardUser`, `sweepExpired`, and `disconnectProvider` are exported from the
package root.

### Replay (multi-replica)

A signed `jti` must be single-use across the fleet. On Postgres the broker installs a shared
`DbReplayStore` (`INSERT … ON CONFLICT DO NOTHING` on a `broker_jti` table) automatically, so a token
replayed against a different pod is rejected. This is why `replicas > 1` is safe on Postgres and
**not** on SQLite (the in-memory guard is per-process — run a single replica there).

### Perimeter auth

`VOUCHR_BROKER_TOKEN` gives a static shared-bearer gate. When your platform issues rotating service
tokens (serviceauth/SPIFFE/mesh mTLS), don't try to express that as a static token — either enforce
it at the mesh/sidecar in front of the broker, or inject a `BrokerOptions.authorize(req)` hook from a
thin wrapper around `buildBrokerServer` (throw to reject). `authorize` replaces the static gate;
setting both is rejected at boot.

### Consuming Vouchr: library vs image

Vouchr ships two ways; pick by how your platform builds:

- **npm library (`@vouchr/core`)** — the primary artifact. `npm install @vouchr/core`, then a thin
  service that calls `buildBrokerServer`. This is the right fit when your platform builds images from
  its own base and needs to inject a rotating-serviceauth `authorize` hook (see below). A ~15-line
  wrapper:

  ```ts
  // server.ts — your repo, your base image, your auth
  import { buildBrokerServer } from '@vouchr/core/broker-server';
  import { readFileSync } from 'node:fs';

  const built = await buildBrokerServer(process.env, {
    // Verify your platform's per-request service token (read fresh each call). Throw to reject.
    authorize: (req) => verifyServiceauth(req, readFileSync('/var/run/secrets/serviceauth/...','utf8')),
  });
  built.server.listen(built.port);
  ```
  Then your own `Dockerfile FROM <your-registry>/node:22` + `npm ci && npm run build`, and your Helm
  chart. Vouchr stays a versioned dependency you bump. GYG-style deployments use this path.

- **Container image (GHCR)** — `ghcr.io/dharin-shah/vouchr-broker:<tag>` for a quick `docker run`
  without a build. Best for non-GYG/self-host quick starts; the perimeter must then be enforced at
  the mesh (there's no code hook in a prebuilt image).

### Container & Kubernetes

A [`Dockerfile`](../Dockerfile) (ARG base images so you can pin an internal mirror, `npm ci` build,
non-root, `HEALTHCHECK` on `/healthz`) and a reference [`deploy/k8s.yaml`](../deploy/k8s.yaml)
(multi-replica, readiness on `/healthz`, process-only TCP liveness, `envFrom` a synced Secret,
commented ServiceAccount for IRSA) ship in the repo. Both are shapes to adapt — no registry or IAM
ARN is hardcoded. For KMS, add `@aws-sdk/client-kms` to the image and bind an IRSA ServiceAccount;
the SDK default credential chain does the rest.

**SQLite in a container** (non-prod only): the default `vouchr.db` path is not writable under a
non-root, read-only-root-filesystem pod. Set `VOUCHR_DB` to a mounted writable volume, or use
`:memory:` for ephemeral tests. Production is Postgres (and `VOUCHR_PRODUCTION=1` refuses SQLite).

### Production mode

Set `VOUCHR_PRODUCTION=1` to make the broker refuse to boot unless it is multi-instance safe:
Postgres **and** a KMS envelope. This turns the two easy-to-forget footguns (SQLite in prod, no
envelope) into a startup failure instead of a silent weakness. Enabling it in the reference manifest
means uncommenting `VOUCHR_PRODUCTION`, `VOUCHR_KMS_KEY_ID`, **and** adding `@aws-sdk/client-kms` to
the image together — turning on production alone (without KMS) is a deliberate boot failure.

## Slack app + OAuth install flow

Create the app from [`examples/slack-manifest.yml`](../examples/slack-manifest.yml)
(api.slack.com/apps → From a manifest), replacing `YOUR_PUBLIC_URL`. The manifest sets:

- **Bot scopes:** `app_mentions:read`, `chat:write`, `commands`, `users:read`.
- **Events:** `app_mention`, `user_change` (the latter drives auto-revoke on deactivation).
- **Interactivity:** enabled, and **required** for the Connect button and the key/configure modals.
- **Slash command:** `/vouchr` — full surface: `status` (default), `disconnect <provider>`,
  `configure <provider>` (admin channel-credential modal), `mode <provider> <shared|per-user|session|union>`
  (admin), `tools` (list the channel's tool manifest), and `enable <provider>` / `disable <provider>`
  (admin: the per-channel tool allowlist `connect()` enforces).

Wire the four hooks (see the README example):

```ts
app.use(vouchr.middleware);
vouchr.mountRoutes(receiver.router);  // OAuth callback at $baseUrl/vouchr/oauth/callback
vouchr.registerCommands(app);         // /vouchr + the modals (mandatory for key/configure flows)
vouchr.registerOffboarding(app);      // user_change → revoke a deactivated user's connections
setInterval(() => vouchr.sweepExpired(), 3_600_000); // hourly TTL sweep
```

Single-workspace: set `botToken` (or `SLACK_BOT_TOKEN`). Multi-workspace: use a `DbInstallationStore`
in both Bolt's OAuth config and `createVouchr` (see *Multi-workspace install* above).

## Production readiness checklist

Honest pre-launch list. "Vouchr helps" = the library does part of the work; "operator" = entirely
yours. Don't go live until each holds.

| Item | Owner |
|---|---|
| Strong `VOUCHR_MASTER_KEY` (32 random bytes) in a secret manager, never in source control | operator |
| Credential store (SQLite file or Postgres) encrypted at rest and access-controlled at the infra layer | operator (Vouchr encrypts only token columns) |
| Public URL is HTTPS. Egress also requires https, loopback exempt | operator (Vouchr enforces https egress) |
| Least-privilege IAM for any resolver (read-only on the specific secrets) | operator (example policy provided) |
| Slack scopes / events / interactivity applied from the manifest | operator (manifest provided) |
| TTL sweep scheduled (`sweepExpired()` on a timer) | Vouchr provides; Bolt: schedule it. Headless: `broker-server` runs it automatically (#54) |
| Offboarding wired so deactivated users lose access | Vouchr provides; Bolt: `registerOffboarding`. Headless: `POST /v1/admin/offboard` from your deprovision hook (#54) |
| Envelope encryption considered for token columns (`EnvelopeProvider` + KMS) | Vouchr provides hook; operator opts in |
| Backups of the credential store (and a restore drill) | operator |
| Monitoring/alerting on resolver and KMS failures, and on auth/refresh errors | operator |
| Multi-instance? Postgres + `DbInstallationStore` wired into Bolt and Vouchr | Vouchr provides; operator wires |

CI green (typecheck + tests, including the Postgres backend) is necessary but **not** the same as
having run this in production. Vouchr has not yet been run in production. Treat this list as the gap.

## Key rotation

How rotation works depends on which at-rest mode you run (`src/core/crypto.ts`).

### Direct master-key mode (default)

Token columns are encrypted *directly* under `VOUCHR_MASTER_KEY` (legacy format, no
version byte). The same key encrypts and decrypts every vaulted row, so:

- **Rotating `VOUCHR_MASTER_KEY` makes every existing encrypted row undecryptable.**
  `open()` will fail the GCM tag check and throw; `vault.get()` then breaks for those
  connections. A key change here is only safe if every row is re-encrypted under the
  new key.
- **There is no built-in re-encryption tool yet.** Re-encrypting means, for each
  vaulted `connection` row (and each `installation` row), decrypting
  `access_token_enc` / `refresh_token_enc` (and `bot_token` / `data`) under the old
  key and re-sealing under the new one. External-reference rows (`source != 'vault'`)
  hold no ciphertext and are unaffected. Until such a tool exists, plan a maintenance
  window and write a one-off migration, or take the simpler path: have users
  reconnect (a reconnect re-vaults under the current key via `upsert`).
- **Compromise response in this mode** is therefore disruptive: rotate the key, and
  either re-encrypt or force reconnect. Revoke the affected provider tokens upstream
  regardless. A leaked master key means the ciphertext may already be decrypted.

For any deployment where you expect to rotate, **prefer envelope mode** below.

### Envelope mode (KMS-wrapped data keys): recommended for rotatable deploys

With an `EnvelopeProvider`, each secret has its own data key (DEK) wrapped by your
external key-encryption key (KEK) in KMS/Vault. Scheme `0x01` rows store the *wrapped*
DEK alongside the ciphertext; decryption calls `unwrapDataKey` (a KMS `Decrypt`).

- **Rotate the KEK in KMS, not the rows.** AWS KMS (and equivalents) version the key
  under a stable key id / alias: rotation creates a new backing key while the old
  versions stay available for decrypt. Existing `0x01` rows keep decrypting because
  KMS still unwraps their DEKs: **no row re-encryption needed.** New writes are
  wrapped under the new KEK version automatically.
- **What rotation requires** is only that the KEK (every version any stored DEK was
  wrapped under) remains available to `unwrapDataKey`. Do not disable or schedule
  deletion of an old KEK version while rows wrapped under it still exist.
- **`VOUCHR_MASTER_KEY` in envelope mode** still encrypts any *legacy* rows written
  before you enabled envelope (reads dispatch on format). Don't drop it until those
  rows are gone (re-vaulted via reconnect or a future re-encryption pass).

## Backup and restore

The credential store and the key that protects it must be backed up **separately**.

### What to back up, and the cardinal rule

- **Direct mode:** the DB (SQLite file or Postgres dump) holds only ciphertext for
  token columns; the master key (`VOUCHR_MASTER_KEY`) is what makes it readable.
  Back up the key separately, in your secret manager, **never alongside the DB
  backup.** A backup that contains both the ciphertext and the key is a single point
  of compromise that leaks everything; a DB backup without the key is useless to an
  attacker (and useless to you for restore, hence "separately", not "not at all").
- **Envelope mode:** token DEKs are wrapped by the KMS KEK, so a DB backup is inert
  without KMS access. Back up nothing key-related yourself: just ensure the KEK
  (and every version any backed-up row was wrapped under) is retained in KMS for the
  life of the backup. Treat scheduled KEK deletion as a backup-invalidating event.
- **External-reference rows** contain no secret at all (only an ARN-style `secret_ref`);
  the secret lives in the external manager and is backed up there, on its own policy.
- **Never commit `VOUCHR_MASTER_KEY`** (or any key) to source control or bake it into
  an image. Keep it in a secret manager; the DB backup goes to encrypted, access-
  controlled storage.

### Backing up

- **SQLite:** stop writers or use SQLite's online backup / `VACUUM INTO` to get a
  consistent copy (the DB runs in WAL mode, so copying the bare `.db` file mid-write can
  miss the `-wal`/`-shm` sidecars). Store the copy encrypted at rest.
- **Postgres:** `pg_dump` (or your managed-DB snapshot mechanism) on its own schedule.

### Restoring

1. Restore the DB (SQLite file in place, or `pg_restore` / snapshot).
2. Make the key available to the *same* process: set `VOUCHR_MASTER_KEY` to the exact
   key the rows were sealed under (direct mode), or grant the restored process KMS
   access to the KEK that wraps their DEKs (envelope mode). A wrong/missing key fails
   closed: decrypt throws, it does not silently return garbage.
3. External-reference rows need their resolver IAM/role intact for the restored
   environment; the secrets themselves are restored on the external manager's policy.
4. Verify: a `connect()` + `handle.fetch()` against one connection per mode confirms
   decrypt works end to end before you cut traffic over.
