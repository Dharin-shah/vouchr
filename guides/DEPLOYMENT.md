# Deploying Vouchr

Concrete recipes for the deployments Vouchr actually supports. Every option named here is real
(`src/adapters/bolt.ts` → `VouchrOptions`). For the security model and what
Vouchr does *not* protect against, see [SECURITY.md](../SECURITY.md), which is not repeated here.

Common to every deploy: a 32-byte `VOUCHR_MASTER_KEY` (`openssl rand -base64 32`) and a public
HTTPS `baseUrl` reachable at the OAuth callback (`$baseUrl/vouchr/oauth/callback`).

## PostgreSQL (required)

Vouchr is PostgreSQL-only: it stores credentials in Postgres and nothing else. A connection
string is **required** — supply it as the `databaseUrl` option, the `VOUCHR_DATABASE_URL` env var,
or the CLI `--db` flag. Vouchr **fails closed at boot** if the value is missing or is not a
`postgres://` URL. There is **no** embedded/SQLite mode and **no** generic `DATABASE_URL` fallback:
only `VOUCHR_DATABASE_URL` (or the explicit option/flag) is read.

```ts
const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  databaseUrl: process.env.VOUCHR_DATABASE_URL!, // postgres://user:pass@host:5432/vouchr?sslmode=require
});
```

**Migrate first.** The schema is created by the `vouchr migrate` command, not by the runtime — see
[Migrations](#migrations) below. The runtime connects with a DML-only role and **never** creates
tables; it verifies the schema version at boot and **fails closed** if the database has not been
migrated (or is on a different schema version).

**Connection config:**

- **TLS is native.** There is no separate TLS knob — put `sslmode=require` (or stricter, e.g.
  `verify-full` with `sslrootcert=`) in the connection string and the `pg` driver negotiates it.
- **Pool size** is `VOUCHR_PG_POOL_MAX` (a validated positive integer; the driver's default of 10
  applies when unset). It caps only the MAIN pool (`application_name=vouchr`). On first token
  refresh each replica ALSO lazily opens a separate bounded refresh pool of up to **4** connections
  (`application_name=vouchr-refresh`), so budget **`VOUCHR_PG_POOL_MAX + 4` per replica** against
  your Postgres `max_connections`. Both names are visible in `pg_stat_activity`.
- **Pool shutdown.** `createVouchr(...).close()` and the async `install(...).stop()` close the pool
  **Vouchr opened**. If you inject your own `db` (see below), Vouchr does **not** close it — its
  lifecycle is yours.

**One pool across workspaces.** `createVouchr` accepts an injected `db` (from `openDb`) so a
deployment that also builds a `DbInstallationStore` (or otherwise wants its own pool) shares **one**
Postgres pool instead of opening two — e.g. the [Postgres + KMS template](../examples/postgres-kms).
Open it once, pass it as `db`, and close it on shutdown.

Postgres is stateless: one migrated database backs the whole fleet, so any instance can serve any
request and `replicas > 1` is safe (the cluster-wide replay table is part of the schema — see
*Replay*). Concurrent `vouchr migrate` runs are serialized by an advisory lock. The database is
**not** fully encrypted at rest (only token columns are), so run it on encrypted, access-controlled
storage.

Local Postgres for development (throwaway Docker container on port 5433):

```bash
npm run pg:up   # postgres:16-alpine, db/user/pass all "vouchr"
export VOUCHR_TEST_PG_URL=postgres://vouchr:vouchr@localhost:5433/vouchr
npm test        # the suite migrates a throwaway schema and exercises the Postgres backend
npm run pg:down # tear it down
```

## Migrations

The schema is owned by the `vouchr migrate` command, and the runtime is DML-only — a deliberate
split so the long-running process holds no DDL privileges.

- **`vouchr migrate`** creates/converges the schema to this build's version. Run it **once per
  deploy/upgrade**, with a **schema-owner** DB role (may `CREATE`/`ALTER` tables). It is idempotent
  and advisory-locked, so re-running it or racing concurrent runs across replicas is safe.

  ```bash
  # built package / container image (the `vouchr` bin is dist/bin/vouchr.js):
  VOUCHR_DATABASE_URL=postgres://vouchr_owner:...@host:5432/vouchr node dist/bin/vouchr.js migrate
  # from a source checkout (Node >= 22 runs the TS entry via tsx):
  VOUCHR_DATABASE_URL=postgres://vouchr_owner:...@host:5432/vouchr npm run cli -- migrate
  ```

- **The runtime** (`createVouchr`, the broker) connects with a **DML-only** role that has no
  `CREATE`. It never creates tables — `openDb()` only verifies the schema version and fails closed
  if the database isn't migrated. Run the migrate step (a Job / initContainer) to completion
  **before** the runtime rolls out.

Example roles and grants (adjust names to taste):

```sql
-- Schema-owner role: runs `vouchr migrate` only.
CREATE ROLE vouchr_owner LOGIN PASSWORD '...';
GRANT ALL ON SCHEMA public TO vouchr_owner;

-- DML-only runtime role: what createVouchr / the broker connect as. No CREATE.
CREATE ROLE vouchr_app LOGIN PASSWORD '...';
GRANT USAGE ON SCHEMA public TO vouchr_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vouchr_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vouchr_app;
-- so a later `vouchr migrate` (as vouchr_owner) auto-grants DML on tables it creates:
ALTER DEFAULT PRIVILEGES FOR ROLE vouchr_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vouchr_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vouchr_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO vouchr_app;
```

Point the migrate step at `vouchr_owner` and the runtime at `vouchr_app`. The `/readyz` probe
reflects schema readiness: it returns `503` until the database has been migrated to the current
version, and `200` once the runtime can reach a current schema.

### Breaking upgrade — no SQLite import

Vouchr is greenfield/pre-1.0 and PostgreSQL-only. There is **no** SQLite importer and **no** data
migration from any prior embedded store: the upgrade path is a **fresh PostgreSQL database** that
you `vouchr migrate`. Any data in a previous SQLite file is not imported — re-connect accounts in
the new Postgres-backed deployment.

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
  db,                       // inject the SAME handle the store uses → one shared pool, not two
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
`POST /v1/audit` (the caller's own credential-usage trail), `POST /v1/user/reference`,
`GET /v1/manifest`, `GET /healthz` (liveness, alias `/health`),
`GET /readyz` (readiness), and — when channel
modes are enabled — `POST /v1/admin/reference` and `POST /v1/admin/audit` (that channel's usage, admin claim), on `VOUCHR_PORT` (default 3000), and runs the TTL
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
NOT identity. The signing algorithm is fixed (HS256); the token carries no `alg` header, so there is
no algorithm-substitution surface.

### Deployment-bound assertions (#212)

The packaged broker binds every assertion to **one deployment** so a token minted for deployment A
cannot be replayed against deployment B, and fails closed on weak configuration:

- **`VOUCHR_DEPLOYMENT_ID`** (required) — the `audience` every token is bound to. The broker rejects a
  token whose audience is not its own. `VOUCHR_IDENTITY_ISSUER` (default `vouchr`) is the verified
  `iss`.
- **`VOUCHR_IDENTITY_SECRET`** must be **≥ 32 bytes** of random key material (`openssl rand -base64 32`)
  and **distinct** from the Slack signing secret, encryption master keys, broker bearer, and every
  provider OAuth client secret — one value must not serve two purposes. A short, placeholder,
  missing, or reused secret fails the broker at startup.
- Each token also carries `iat` (issued-at); one issued in the future beyond a small clock-skew
  allowance (30s) is rejected, as is one whose lifetime exceeds the 5-minute ceiling.
- **Every replica and every minter must share the same `VOUCHR_DEPLOYMENT_ID`, issuer, and bounded
  verification key set.** A replica configured for a different deployment or key will reject the
  fleet's tokens. During a staged rotation, active-key order differs temporarily by design while the
  two-key verification set remains compatible.

**Upgrade from an older bare-secret broker.** The packaged broker now requires deployment-bound
configuration. Do not roll brokers before their trusted minter:

1. Keep the existing signing secret, choose `VOUCHR_DEPLOYMENT_ID`, and upgrade the minter first so it
   uses `loadIdentityConfig` and emits `iss`/`aud`/`iat`/`kid`. An older broker verifies that signature
   with the same secret and ignores the additive bound claims.
2. After every minter emits bound assertions, let the old 5-minute maximum token lifetime plus the
   30-second verifier allowance elapse. This avoids turning an already-issued unbound assertion into
   a user-visible failure when the new broker intentionally rejects it.
3. Perform the broker format change as a **drained cutover, not an ordinary rolling overlap**. Stop
   all old broker replicas and pause broker traffic; after the last old replica stops, keep the
   broker unavailable for the conservative 90-second cluster-skew horizon, then start the new
   replicas together with the same deployment id, issuer, and secret. Old replicas prune replay rows
   at raw expiry, while new replicas deliberately retain them through clock tolerance; the short
   no-broker gap ensures a row removed by an old pruner cannot be accepted by a new verifier.
4. Resume broker traffic, then rotate the signing key only after every replica is on the bound
   format. Normal active/previous key rotations below remain rolling and downtime-free.

If the existing secret is shorter than 32 bytes, a known placeholder, or reused for another purpose,
it cannot enter the overlap set. Drain identity-token traffic for the old token lifetime plus clock
tolerance, stop every old broker for the same conservative 90-second gap, then cut the minter and
brokers over together during a maintenance window with a new random secret. Do not weaken the
validator to carry an unsafe legacy key forward.

**Rolling key rotation (no downtime, after the format upgrade).** Use two rollout phases; changing the
active key everywhere in one ordinary rolling deployment is unsafe because a new token can land on an
old replica that has never seen that key.

1. **Pre-stage:** keep the old key in `VOUCHR_IDENTITY_SECRET` and put the new key in
   `VOUCHR_IDENTITY_SECRET_PREVIOUS` on every minter and broker. Despite the historical variable name,
   it is the one bounded overlap slot; all processes still mint with the old active key but can verify
   either key.
2. **Activate:** after pre-stage completes everywhere, roll again with the new key active and the old
   key in `VOUCHR_IDENTITY_SECRET_PREVIOUS`. Phase-1 replicas already know the new key, and phase-2
   replicas still know the old one, so mixed-version routing accepts both.
3. **Retire:** after the last old-key token's 5-minute maximum lifetime **plus the conservative
   90-second cluster-skew horizon** (6m30s), remove `VOUCHR_IDENTITY_SECRET_PREVIOUS`. That horizon
   covers the verifier's 30-second tolerance plus the maximum 60-second difference between replicas
   at opposite documented clock extremes. The retired `kid` then fails closed.

Mint tokens with the exported `mintIdentity(acting, identity)` helper and an `IdentityConfig` from
`loadIdentityConfig(process.env)`. It fills a fresh `jti` and a short, ceiling-clamped `exp` so you do
not hand-roll replay/expiry rules. Bare-secret signing is a low-level legacy compatibility helper, not
a broker deployment mode. See [`examples/broker-client/client.ts`](../examples/broker-client/client.ts)
for the full call.

### Channel-owned credentials headless (`owner: "channel"`)

By default the broker is **user-only**: a `handle.owner` of `"channel"` is refused. Set
`VOUCHR_CHANNEL_MODES=1` to enable the transport-agnostic channel gate (#51), which lets a headless
caller reach the `shared` channel mode the Bolt adapter offers — **without** a Slack
client in the broker. The broker has no way to read Slack, so **the caller supplies the Slack-derived
facts as signed claims** and the broker trusts them at the same level as `teamId`/`userId`:

- `ownerKind: "channel"` — the request targets a channel-owned credential. It must match `handle.owner`
  or the request is refused, so a forged body alone can never reach a channel credential.
- `channelEligible` — the caller's `channelIneligibleReason(conversations.info) === null` verdict. The
  caller **must** compute this with the exported `channelIneligibleReason` (refuse externally-shared /
  Slack-Connect / DM / archived channels — the cross-org leak case). The broker **fails closed**: a
  channel request with this absent or false is refused.

Mint them via `mintIdentity`'s optional fields:

```ts
const identity = loadIdentityConfig(process.env); // deployment-bound; same config the broker uses
const token = mintIdentity(
  { teamId, userId, channel, ownerKind: 'channel', channelEligible: channelIneligibleReason(info) === null },
  identity,
);
```

`shared` resolves to the channel's credential (audited as the acting human). `per-user` / `session`
channels are **not** reachable this way — those are user-owned modes, so the caller uses
`owner: "user"`.

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
| `VOUCHR_IDENTITY_SECRET` | yes | HS256 secret shared with the identity-token minter. Must be **≥ 32 bytes** and distinct from Slack signing, master/KMS, broker-bearer, and provider client secrets (#212). |
| `VOUCHR_DEPLOYMENT_ID` | yes | the deployment every identity assertion is bound to (`aud`); a token minted for another deployment is rejected (#212). |
| `VOUCHR_IDENTITY_SECRET_PREVIOUS` | no | the single overlap key during staged rotation (the previous key after activation, or next key during pre-stage); drop the retired key only after the 6m30s maximum token + cluster-skew horizon (#212). |
| `VOUCHR_IDENTITY_ISSUER` | no | the verified `iss` claim (default `vouchr`). |
| `VOUCHR_MASTER_KEY` | yes* | base64 of 32 bytes; encrypts tokens at rest (`openssl rand -base64 32`). *Or `VOUCHR_MASTER_KEYS`. |
| `VOUCHR_MASTER_KEYS` | no | comma-separated `id:base64key` entries for master-key rotation; the FIRST entry encrypts new writes, every entry decrypts (see [Key rotation](#key-rotation)). |
| `VOUCHR_DATABASE_URL` | yes | `postgres://…` connection string. Required — boot fails closed if unset or non-`postgres://`. No `DATABASE_URL` fallback. Put `sslmode=require` (or stricter) in the URL for TLS. Migrate first with `vouchr migrate` (schema-owner role); the runtime connects DML-only. |
| `VOUCHR_PG_POOL_MAX` | no | pool size (validated positive integer; `pg`'s default of 10 when unset). The pool sets `application_name=vouchr`. |
| `VOUCHR_PROVIDERS` / `VOUCHR_PROVIDERS_FILE` | yes | provider config (inline JSON / file path); see below. |
| `VOUCHR_PROVIDER_<ID>_CLIENT_ID` / `_CLIENT_SECRET` | per OAuth provider | client creds, kept out of the JSON. |
| `VOUCHR_KMS_KEY_ID` | prod | enables the KMS envelope (KEK). Needs `@aws-sdk/client-kms` in the image. |
| `VOUCHR_BROKER_TOKEN` | no | static bearer for the coarse perimeter gate on `/v1/*`. |
| `VOUCHR_TTL_IDLE_MS` / `VOUCHR_TTL_MAX_AGE_MS` | no | credential idle / max-age TTL (#54). Default 7d / 30d (matches the Bolt path); `0` disables that dimension. |
| `VOUCHR_SWEEP_INTERVAL_MS` | no | TTL sweep interval (#54). Default hourly; `0` defers to an external scheduler. |
| `VOUCHR_BASE_URL` | for OAuth | public HTTPS origin of this broker; setting it mounts `POST /v1/connect` + the OAuth callback (#52). |
| `VOUCHR_CALLBACK_PATH` | no | OAuth redirect path under `VOUCHR_BASE_URL` (default `/oauth/callback`). |
| `VOUCHR_ALLOW_WRITES` | no | `1`/`true` opts into the write path (still per-provider `egressMethods`). |
| `VOUCHR_DRY_RUN` | no | `1`/`true` enables dry-run (#116): real gates, no real network on any edge — consent yields a synthetic credential (marked by a system-only `dry_run` column) and `/v1/fetch` returns a `{ dryRun, method, url, wouldInjectAs }` echo. Boot hard-fails if the database holds any non-dry-run credential row; a real row written later is refused per-request. Requires a **local master key** — an external KMS envelope (`VOUCHR_KMS_KEY_ID`) is refused at startup. Never set on production state. |
| `VOUCHR_CHANNEL_MODES` | no | `1`/`true` enables `owner:"channel"` handles (shared) via signed channel-fact claims (#51). Off → user-only broker. |
| `VOUCHR_PORT` | no | listen port (default 3000). |
| `VOUCHR_SEED_ACCESS_TOKEN` | seed only | `broker-seed key` reads the token from here (preferred over the argv flag). |
| `AWS_REGION` | with KMS | region for the KMS client (else SDK default chain). |

Boot validation is fail-fast and names the missing variable; nothing sensitive is logged (startup
prints one line: port, backend, provider ids, `allowWrites`, and `dryRun=true` when dry-run is on).

### Provider config (declarative)

Declare providers without editing source. Declarative fields only — a provider needing function
fields (`inject`, `egressValidate`, `revoke`, `accountProbe`) must be registered in code. Unknown
fields are rejected (fail closed). A JSON provider goes through the **same core validator** as the
built-in factories and any code-registered provider, so the three paths cannot disagree about OAuth,
egress, or supported behavior. Secrets come from the per-provider env vars above, never the JSON:

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

The validator is strict and fail-fast at config load:

- **`id`** — letters, digits, `.`, `_`, `-`, ≤ 63 chars, starting alphanumeric. Duplicate ids, and
  two ids that normalize to the same client-secret env key (`a.b` and `a-b` → `VOUCHR_PROVIDER_A_B_*`),
  are rejected.
- **`authorizeUrl` / `tokenUrl` / `revokeUrl`** — must be `https` (a loopback host may use `http` for
  local testing), with no embedded credentials, fragment, or explicit port. The token
  exchange and revoke POSTs are not behind the egress gate, so a downgraded endpoint would leak the
  code / client secret / token in cleartext — hence the check. Token, refresh, revoke, and built-in
  account-probe requests also refuse redirects rather than forwarding credentials to another URL.
- **`egressAllow`** hosts are lower-cased and must be bare hostnames (no scheme/port/path);
  **`egressPaths`** must be absolute (`/repos`); **`egressMethods`** are normalized (`" post "` →
  `POST`). Canonicalizing once at load means the value the injector compares at egress is exactly what
  you wrote — no silent never-match. Path locks reject encoded separators/traversal even when nested
  across multiple decode layers, before Vouchr reads or forwards the credential.
- **`authorizeParams`** may add provider-specific query params (e.g. `{"prompt": "consent"}`) but may
  **not** carry a Vouchr-owned key (`client_id`, `redirect_uri`, `scope`, `state`, `response_type`,
  `code_challenge`, `code_challenge_method`) — those are set by Vouchr and overriding `state`/
  `redirect_uri` would defeat the single-use CSRF `state`.
- The full declarative surface also includes `scopeDescriptions` (non-blank, escaped per-scope
  consent copy; scope ids/descriptions are at most 512 characters and the default list at most 48),
  `publicClient` (PKCE-only, no secret), `revokeAuth` (`none`/`body`), `egressResponse`
  (`maxBytes` / `allowContentTypes` / `stripHeaders`), and `rateLimit` (`perMinute` / `burst`) —
  each validated identically to its in-code form.

Validation produces the immutable snapshot used at runtime; mutating the object originally passed by
code cannot add an egress host, path, or method after registration. `callbackPath` is likewise a
canonical literal pathname such as `/oauth/callback`—not a relative path, URL, encoded path,
route pattern, query, or fragment—and must resolve to an HTTPS URL on the configured `baseUrl` origin
(loopback local testing excepted).

With no `egressMethods`, the broker default-denies non-GET/HEAD — a read-only provider. Opt into
writes with `VOUCHR_ALLOW_WRITES=1` **and** an explicit `egressMethods` on the provider.

**Write/approval boundary (plain language).** Enabling writes lets the agent use the connected
credential at the endpoints and methods you allowlisted — nothing more. A generic session approval is
permission to *use the credential at that endpoint/method*, not transaction-level sign-off on an
arbitrary request body: Vouchr does not inspect or fingerprint payloads. A provider that needs a human
to confirm the specific action (an amount, a recipient) must either keep generic writes off, or the
host must implement that confirmation with a tool-specific step — see the `approval` knob below for
per-endpoint human-in-the-loop approval, which binds a grant to the exact method + host + path +
query, single-use.

To expose a provider on `POST /v1/mcp` (#65), declare the `mcp` knob too — it is a separate opt-in
on top of the write gating above, and locks the reachable endpoint + response media types
(`allowContentTypes` optional; default `application/json` + `text/event-stream`). See the
[headless guide](./HEADLESS.md)'s MCP section for the route's semantics:

```json
[
  {
    "id": "internal-mcp",
    "credential": "key",
    "egressAllow": ["mcp.internal.example"],
    "egressMethods": ["POST"],
    "mcp": { "paths": ["/mcp"] }
  }
]
```

To require **human-in-the-loop approval** for a provider's writes (#113), declare the `approval`
knob — `approver` is required (`"self"` or `"admin"`); `methods` defaults to every non-GET/HEAD
method, `paths` to all (same matcher as `egressPaths`), `ttlMs` to 5 minutes. Invalid shapes are
rejected fail-closed at config load. A matching request with no live grant gets
`403 { "error": "approval_required", "approvalId" }` from the broker — the Approve/Deny surface is
the Slack app (see the [headless guide](./HEADLESS.md)'s approvals section):

```json
[
  {
    "id": "internal",
    "credential": "key",
    "egressAllow": ["api.internal.example"],
    "egressMethods": ["GET", "POST"],
    "approval": { "approver": "admin", "methods": ["POST"], "ttlMs": 300000 }
  }
]
```

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

A signed `jti` must be single-use across the fleet. Shared replay protection is automatic: every
broker uses the durable `DbReplayStore` (`INSERT … ON CONFLICT DO NOTHING` on the baseline
`broker_jti` table), so a token replayed against a different pod is rejected. Replay storage is not
configurable on either `createBroker` or `buildBrokerServer`: one shared PostgreSQL table backs the
whole fleet, and `/readyz` fails when that exact dependency is unusable. `ReplayGuard` remains only a
low-level direct-verifier test utility.

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
  its own base and needs to inject code hooks (`authorize`, secret `resolvers`, safe event/audit sinks,
  or `onCredentialHealth`). The builder rejects every configuration/security override; use direct
  `createBroker` construction when you intentionally need the full lower-level surface. A ~15-line wrapper:

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

### Verifying the GHCR image (cosign, SBOM, provenance)

Every released image is keyless-signed with [cosign](https://docs.sigstore.dev/) by the release
workflow, which also attaches a CycloneDX SBOM attestation and BuildKit SLSA provenance
(`mode=max`). The release job runs the exact verification below against the pushed digest before it
goes green, so an image that doesn't verify never ships. Use cosign **v3+**: the workflow signs with
cosign v3, whose bundle format cosign v2 does not understand — a v2 client fails with a misleading
`no matching signatures` even though the image is signed. Check the image really came from this
repo's release CI (not merely pushed by someone with registry access):

```bash
IMAGE=ghcr.io/dharin-shah/vouchr-broker:<tag>

# Signature — the certificate identity is this repo's release workflow on a v* tag:
cosign verify "$IMAGE" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Dharin-shah/vouchr/\.github/workflows/release\.yml@refs/tags/v'

# SBOM attestation (CycloneDX) — same identity; the trailing jq prints the SBOM itself:
cosign verify-attestation "$IMAGE" --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Dharin-shah/vouchr/\.github/workflows/release\.yml@refs/tags/v' \
  | jq -r '.payload' | head -n1 | base64 -d | jq '.predicate'
```

BuildKit provenance travels inside the image index itself (not as a cosign attestation); inspect it
with `docker buildx imagetools inspect "$IMAGE" --format '{{ json .Provenance }}'`.

Then deploy the **digest** you verified, never the mutable tag — a tag can be repointed after you
verified it, a digest cannot. Resolve the tag to its (index) digest with
`docker buildx imagetools inspect "$IMAGE" --format '{{.Manifest.Digest}}'` and pin `name@digest` in
your manifests:

```yaml
# docker-compose.yml
services:
  vouchr-broker:
    image: ghcr.io/dharin-shah/vouchr-broker@sha256:<digest>

# Kubernetes (the image: field in deploy/k8s.yaml)
containers:
  - name: vouchr-broker
    image: ghcr.io/dharin-shah/vouchr-broker@sha256:<digest>
```

### Container & Kubernetes

A [`Dockerfile`](../Dockerfile) (ARG base images so you can pin an internal mirror, `npm ci` build,
non-root, `HEALTHCHECK` on `/healthz`) and a reference [`deploy/k8s.yaml`](../deploy/k8s.yaml)
(multi-replica, readiness on `/readyz`, liveness on `/healthz`, `envFrom` a synced Secret,
commented ServiceAccount for IRSA) ship in the repo. Both are shapes to adapt — no registry or IAM
ARN is hardcoded. For KMS, add `@aws-sdk/client-kms` to the image and bind an IRSA ServiceAccount;
the SDK default credential chain does the rest.

Health probes: `GET /healthz` is liveness (a bare `{"ok":true}` while the process serves, no DB call —
a DB blip must never restart the fleet); `GET /readyz` is readiness (`{"ok":true}` only if the schema is
current and the cluster-wide replay store is usable within ~2s, else `503 {"ok":false}` so the pod drains
from the Service). A pod stays `503` until `vouchr migrate` has brought the database to the current
version and the runtime role can use `broker_jti` — run the migrate step before the runtime rolls out. Both
probes are unauthenticated, exempt from identity/replay, and return a bare status with no secrets. Wire
them as:

```yaml
readinessProbe:
  httpGet: { path: /readyz, port: http }
  initialDelaySeconds: 5
  periodSeconds: 10
livenessProbe:
  httpGet: { path: /healthz, port: http }
  initialDelaySeconds: 10
  periodSeconds: 20
```

**Read-only rootfs / non-root container**: nothing is written to the container filesystem —
Vouchr's only store is Postgres. Point `VOUCHR_DATABASE_URL` at an external Postgres and the pod
needs no writable volume for the database.

### Recommended production configuration

Postgres (`VOUCHR_DATABASE_URL`) is **required** — Vouchr fails closed at boot without it — and is
stateless, so `replicas > 1` is safe out of the box. Beyond that, for a **production** deployment we
recommend:

- **A KMS envelope** (`VOUCHR_KMS_KEY_ID`) — per-secret KMS-wrapped data keys, not just
  storage-level encryption. Add `@aws-sdk/client-kms` to the image and bind an IRSA ServiceAccount.

The KMS envelope is a recommendation, not an enforced precondition: Vouchr will boot without it.
Enabling KMS in the reference manifest means uncommenting `VOUCHR_KMS_KEY_ID` and adding
`@aws-sdk/client-kms` to the image together.

## Slack app + OAuth install flow

Create the app from [`examples/slack-manifest.yml`](../examples/slack-manifest.yml)
(api.slack.com/apps → From a manifest), replacing `YOUR_PUBLIC_URL`. The manifest sets:

- **Bot scopes:** `app_mentions:read`, `chat:write`, `commands`, `users:read`.
- **Events:** `app_mention`, `user_change` (the latter drives auto-revoke on deactivation).
- **Interactivity:** enabled, and **required** for the Connect button and the key/configure modals.
- **Slash command:** `/vouchr` — full surface: `status` (default), `disconnect <provider>`,
  `configure <provider>` (admin channel-credential modal), `mode <provider> <shared|per-user|session>`
  (admin), `tools` (list the channel's tool manifest), and `enable <provider>` / `disable <provider>`
  (admin: the per-channel tool allowlist `connect()` enforces).
- **Who may configure:** by default the `configure`/`mode`/`enable`/`disable` commands are
  **workspace-admin-only**. Set `allowChannelCreatorConfig: true` to also let a channel's **creator**
  self-serve their own channel's config (off by default — in Slack anyone can create a public channel,
  so `creator` isn't a privileged role). A custom `isAdmin` still fully overrides either default.

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
| PostgreSQL credential store encrypted at rest and access-controlled at the infra layer | operator (Vouchr encrypts only token columns) |
| Public URL is HTTPS. Egress also requires https, loopback exempt | operator (Vouchr enforces https egress) |
| Least-privilege IAM for any resolver (read-only on the specific secrets) | operator (example policy provided) |
| Slack scopes / events / interactivity applied from the manifest | operator (manifest provided) |
| TTL sweep scheduled (`sweepExpired()` on a timer) | Vouchr provides; Bolt: schedule it. Headless: `broker-server` runs it automatically (#54) |
| Offboarding wired so deactivated users lose access | Vouchr provides; Bolt: `registerOffboarding`. Headless: `POST /v1/admin/offboard` from your deprovision hook (#54) |
| Envelope encryption considered for token columns (`EnvelopeProvider` + KMS) | Vouchr provides hook; operator opts in |
| Backups of the credential store (and a restore drill) | operator |
| Monitoring/alerting on resolver and KMS failures, and on auth/refresh errors | operator |
| `EventSink` wired to durable metrics/logging (redundant signal for best-effort audit writes — see [SECURITY.md](../SECURITY.md#what-vouchr-does-not-protect-against)) | operator (Vouchr provides the hook) |
| Multi-instance? Postgres + `DbInstallationStore` wired into Bolt and Vouchr | Vouchr provides; operator wires |

CI green (typecheck + tests, including the Postgres backend) is necessary but **not** the same as
having run this in production. Vouchr has not yet been run in production. Treat this list as the gap.

## Key rotation

How rotation works depends on which at-rest mode you run (`src/core/crypto.ts`).

### Direct master-key mode (default)

By default token columns are encrypted under the master key directly. With the single
`VOUCHR_MASTER_KEY` every row is sealed under that one key (the legacy format, no
version byte), so changing the variable alone would orphan every existing ciphertext.
Rotation is instead built in via `VOUCHR_MASTER_KEYS` (#115):

- `VOUCHR_MASTER_KEYS` is a comma-separated list of `id:base64key` entries (ids are
  `[A-Za-z0-9._-]`, max 32 chars). The **first** entry is the primary: it encrypts all
  new writes, which then carry its key id in the ciphertext. **Every** entry is a
  decryption candidate; a row whose stored key id is not in the list fails closed with
  an error naming the id. Old id-less rows keep decrypting via `VOUCHR_MASTER_KEY`
  and/or the listed keys.
- `vouchr rekey` (see [CLI.md](./CLI.md)) re-encrypts every stored ciphertext —
  `connection.access_token_enc`/`refresh_token_enc` and `installation.bot_token`/`data` —
  under the primary. It is idempotent, interrupt-safe (row-at-a-time writes; a crash
  leaves a mixed but fully readable table), never clobbers a row a live refresh
  touched mid-run, and prints counts only, never secrets. External-reference rows
  (`source != 'vault'`) hold no ciphertext and are unaffected; envelope (KMS) rows are
  skipped — their rotation happens in the KMS.

**Rotation procedure** (no maintenance window needed; every step keeps all rows readable):

1. Generate the new key and make it the primary while keeping the old key available,
   e.g. go from `VOUCHR_MASTER_KEY=<old>` to:

   ```bash
   VOUCHR_MASTER_KEYS=k2026:$(openssl rand -base64 32),k2019:<old>
   # (keeping VOUCHR_MASTER_KEY=<old> set instead of listing it also works)
   ```

2. Deploy. New writes now carry `k2026`; old rows still decrypt via the old key.
3. Run `vouchr rekey` (same env as the app). Re-run freely if interrupted.
4. Verify: `vouchr rekey --dry-run` must report **zero** blobs under the old key
   (everything "already under primary") and zero unreadable.
5. Remove the old key (`k2019:…` and any `VOUCHR_MASTER_KEY`) from the environment and
   redeploy. Keep a copy of the old key in your secret manager until backups that
   predate the rotation have aged out — restoring such a backup needs it.

**Compromise response**: rotate as above, but treat the data as exposed — a leaked
master key means the ciphertext may already be decrypted. Revoke the affected provider
tokens upstream (`vouchr revoke`) regardless; rekeying does not un-leak them.

**Direct vs envelope — which to run?** Direct multi-key mode is zero-dependency and
fine when the DB and the env-managed key live in separate trust domains and rotations
are occasional, operator-driven events (each rotation rewrites every row). Choose
envelope mode when you already run a KMS, want rotation without touching rows, need
per-secret keys/audit at the KMS level, or must satisfy "keys never appear in process
env" requirements. For any deployment where you expect frequent rotation, prefer
envelope mode below.

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
- **`VOUCHR_MASTER_KEY`/`VOUCHR_MASTER_KEYS` in envelope mode** still decrypt any
  *direct* rows written before you enabled envelope (reads dispatch on format). Don't
  drop them until those rows are gone. Note `vouchr rekey` rotates direct rows between
  *direct* keys; it does not convert rows to envelope — that happens as users
  reconnect (each `upsert` re-seals in the current mode).

## Audit retention (#208)

The `audit` table is append-only and grows with usage, so at production volume you must choose a
retention policy. Vouchr keeps this bounded without owning an archival/partitioning/legal-hold
platform.

**Indexes.** The read paths are backed by composite indexes so they stay fast as the table grows
(they are part of the schema `vouchr migrate` creates — no action needed):

- owner history (`/vouchr audit`) → `idx_audit_team_user_at (team_id, user_id, at DESC)`
- channel history + `/vouchr stats` → `idx_audit_team_channel_at (team_id, channel, at DESC)`
- "who configured this" lookups → partial `idx_audit_config (team_id, channel, provider, at DESC) WHERE action='config'`
- retention pruning → `idx_audit_at (at)`

**Retention is an explicit choice — there is no automatic pruning.** Keeping rows forever is a
deliberate default; to bound storage, run the prune command on a schedule (a cron / k8s `CronJob`):

```bash
# Dry-run first (counts only), then delete rows older than 90 days in bounded batches:
node dist/bin/vouchr.js prune --older-than-days 90            # DRY-RUN: N rows …
node dist/bin/vouchr.js prune --older-than-days 90 --yes      # deletes, in 10k-row batches
#   --batch <N>   rows per DELETE (default 10000)
```

Each batch is its own transaction, so pruning **bounds the WAL and lock held per statement** — it
never takes a long lock or monopolizes the pool. (Deletes still generate WAL and leave dead tuples;
autovacuum reclaims that space over time, so expect vacuum activity after a large prune.) It is
**restartable and idempotent** — an interrupted or repeated run just deletes whatever is now old, and
`FOR UPDATE SKIP LOCKED` lets two prune jobs take disjoint batches. Pick a `--batch` your
`max_connections` / WAL / autovacuum headroom is comfortable with.

**Estimating storage.** A row is on the order of a few hundred bytes plus the index entries; multiply
by your injection/consent rate to size the disk, or set a retention window that keeps the table
within a target row count. The current footprint:

```sql
SELECT count(*) AS rows, pg_size_pretty(pg_total_relation_size('audit')) AS total_size FROM audit;
```

**Long retention / compliance.** The `audit` TABLE is the authoritative record; do NOT prune based on
`auditSink` — it is a lossy, fire-and-forget convenience copy (a capped stream may drop events and it
does not carry every audited action), so it cannot stand in for the table. For durable long-term or
compliance archives, run an operator-owned durable pipeline off PostgreSQL itself — logical
replication / CDC (e.g. a replication slot) to a warehouse, or periodic `pg_dump`/`COPY` exports to
object storage — and **verify delivery and a test restore before you prune**. Only prune rows you
have confirmed are safely archived. Vouchr deliberately does not implement archive tiers or
legal-hold workflows.

## Backup and restore

The credential store and the key that protects it must be backed up **separately**.

### What to back up, and the cardinal rule

- **Direct mode:** the Postgres dump holds only ciphertext for
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

- **Postgres:** `pg_dump` (or your managed-DB snapshot mechanism) on its own schedule.
  Store the copy encrypted at rest.

### Restoring

1. Restore the DB (`pg_restore` / snapshot).
2. Make the key available to the *same* process: set `VOUCHR_MASTER_KEY` to the exact
   key the rows were sealed under — or, if the backup predates a key rotation, list the
   old key in `VOUCHR_MASTER_KEYS` under the **same id** it had when the rows were
   written (direct mode) — or grant the restored process KMS access to the KEK that
   wraps their DEKs (envelope mode). A wrong/missing key fails closed: decrypt throws
   (naming the missing key id, if the row carries one), it does not silently return
   garbage.
3. External-reference rows need their resolver IAM/role intact for the restored
   environment; the secrets themselves are restored on the external manager's policy.
4. Verify: a `connect()` + `handle.fetch()` against one connection per mode confirms
   decrypt works end to end before you cut traffic over.
