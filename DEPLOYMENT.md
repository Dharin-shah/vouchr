# Deploying Vouchr

Concrete recipes for the deployments Vouchr actually supports. Every option named here is real
(`src/adapters/bolt.ts` → `VouchrOptions`); nothing is invented. For the security model and what
Vouchr does *not* protect against, see [SECURITY.md](./SECURITY.md) — not repeated here.

Common to every deploy: a 32-byte `VOUCHR_MASTER_KEY` (`openssl rand -base64 32`) and a public
HTTPS `baseUrl` reachable at the OAuth callback (`$baseUrl/vouchr/oauth/callback`).

## SQLite (local / single instance) — the default

Zero config. With no `databaseUrl`, Vouchr opens a SQLite file (`vouchr.db` by default).

```ts
const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  // dbPath: '/data/vouchr.db',   // or set VOUCHR_DB; defaults to ./vouchr.db
});
```

Path resolution: `dbPath` option → `VOUCHR_DB` env → `vouchr.db`. Fine for a single instance
(the file is local). The file is **not** fully encrypted at rest — only token columns are — so put
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
- For an app installed to **many** workspaces, also wire a `DbInstallationStore` (next section) —
  it persists per-workspace bot tokens in the `installation` table so any instance can post the
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
are in [`examples/aws-secrets-manager/README.md`](./examples/aws-secrets-manager/README.md).

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

A real AWS KMS provider — no SDK added to Vouchr, you bring `@aws-sdk/client-kms`:

```ts
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';

const kms = new KMSClient({});
const KEY_ID = process.env.VOUCHR_KMS_KEY_ID!;

const kmsEnvelope: EnvelopeProvider = {
  // seal() mints its own DEK, so we KMS-Encrypt it to get the wrapped form.
  // (GenerateDataKey — which returns plaintext + ciphertext DEK in one call — is the
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

## Slack app + OAuth install flow

Create the app from [`examples/slack-manifest.yml`](./examples/slack-manifest.yml)
(api.slack.com/apps → From a manifest), replacing `YOUR_PUBLIC_URL`. The manifest sets:

- **Bot scopes:** `app_mentions:read`, `chat:write`, `commands`, `users:read`.
- **Events:** `app_mention`, `user_change` (the latter drives auto-revoke on deactivation).
- **Interactivity:** enabled — **required** for the Connect button and the key/configure modals.
- **Slash command:** `/vouchr` (status | disconnect | configure).

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
| Public URL is HTTPS — egress also requires https, loopback exempt | operator (Vouchr enforces https egress) |
| Least-privilege IAM for any resolver (read-only on the specific secrets) | operator (example policy provided) |
| Slack scopes / events / interactivity applied from the manifest | operator (manifest provided) |
| TTL sweep scheduled (`sweepExpired()` on a timer) | Vouchr provides; operator schedules |
| Offboarding wired (`registerOffboarding`) so deactivated users lose access | Vouchr provides; operator wires |
| Envelope encryption considered for token columns (`EnvelopeProvider` + KMS) | Vouchr provides hook; operator opts in |
| Backups of the credential store (and a restore drill) | operator |
| Monitoring/alerting on resolver and KMS failures, and on auth/refresh errors | operator |
| Multi-instance? Postgres + `DbInstallationStore` wired into Bolt and Vouchr | Vouchr provides; operator wires |

CI green (typecheck + tests, including the Postgres backend) is necessary but **not** the same as
having run this in production — Vouchr has not yet been run in production. Treat this list as the gap.
