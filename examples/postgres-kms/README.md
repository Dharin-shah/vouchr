# Production template: Postgres + KMS envelope encryption

A production wiring template: install the optional AWS KMS SDK, set the environment, and run it.
It wires the three things a real deployment wants:

- **`db`**: one PostgreSQL pool (Vouchr is Postgres-only), opened once with `openDb` and shared by
  both `createVouchr` and the installation store — so the deployment opens a **single** pool, not
  two. The deployment is stateless and can run multiple instances behind a load balancer. Run
  `vouchr migrate` once (schema-owner role) before starting; the runtime connects DML-only and never
  creates tables.
- **`envelope`**: KMS envelope encryption for at-rest secrets. Each secret gets a
  fresh data key wrapped by your KMS key; rotating the KMS key never touches the rows.
- **`installationStore`**: a db-backed `DbInstallationStore` so one deployment serves
  many workspaces (and Enterprise Grid org-wide installs). Wire the **same** store
  into Bolt's OAuth installer.

```ts
const db = await openDb({ databaseUrl: process.env.VOUCHR_DATABASE_URL }); // one shared pool
const envelope = kmsEnvelope(
  process.env.VOUCHR_KMS_KEY_ID!,
  await awsKmsClient(process.env.AWS_REGION ? { region: process.env.AWS_REGION } : {}),
);
const installationStore = new DbInstallationStore(db, loadKeyring(), envelope);
const receiver = new ExpressReceiver({
  signingSecret: process.env.SLACK_SIGNING_SECRET!,
  clientId: process.env.SLACK_CLIENT_ID!,
  clientSecret: process.env.SLACK_CLIENT_SECRET!,
  stateSecret: process.env.SLACK_STATE_SECRET!,
  scopes: ['app_mentions:read', 'chat:write', 'commands', 'users:read', 'channels:read', 'groups:read'],
  installationStore, // Bolt persists every workspace installation through the envelope-backed store
});
const vouchr = await createVouchr({
  providers: [github(), google()],
  baseUrl: process.env.PUBLIC_URL!,
  db, // share the pool; an injected db is the caller's to close on shutdown
  envelope,
  installationStore,
});
```

## AWS KMS dependency

The template uses Vouchr's `awsKmsClient()` adapter, which loads the AWS SDK dynamically.
`@aws-sdk/client-kms` is intentionally **not** a dependency of this repo; add it in your own
project or deployment image:

```
npm install @aws-sdk/client-kms
```

KMS access uses the **ambient IAM role** (task role / instance profile / IRSA). No
static credentials in code. Grant `kms:Encrypt` + `kms:Decrypt` on the one key id.

## Direct-to-envelope transition

Vault transition rows remain readable while their direct key stays configured. Installation
rows are stricter: construct the store temporarily as
`new DbInstallationStore(db, loadKeyring(), envelope, { allowDirectRowsDuringMigration: true })`,
then reinstall/re-auth every workspace so its next write uses the envelope. Remove the migration
option and perform a strict installation fetch/auth smoke for every workspace before retiring any
direct key needed by the remaining Vault rows or backups. Do not classify rows by the first byte
alone: an old unprefixed IV can collide with the envelope scheme byte.

## Env

```
SLACK_SIGNING_SECRET=...
SLACK_CLIENT_ID=...
SLACK_CLIENT_SECRET=...
SLACK_STATE_SECRET=...  # random secret used by Bolt's OAuth installer
PUBLIC_URL=https://your.domain
VOUCHR_DATABASE_URL=postgres://user:pass@host:5432/vouchr
VOUCHR_MASTER_KEY=$(openssl rand -base64 32)   # 32 bytes, base64
VOUCHR_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/...
```
