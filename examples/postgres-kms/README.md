# Production template: Postgres + KMS envelope encryption

A **template**, not a runnable demo: you must fill in the KMS provider before use.
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
const vouchr = await createVouchr({
  providers: [github(), google()],
  baseUrl: process.env.PUBLIC_URL!,
  db, // share the pool; an injected db is the caller's to close on shutdown
  envelope: kmsEnvelope,
  installationStore,
});
```

## Fill in the KMS provider

`kmsEnvelope` in `app.ts` fails closed until you replace its bodies with
`EncryptCommand` / `DecryptCommand` calls (the real implementation is in the
file's comment). That needs `@aws-sdk/client-kms`, which is intentionally
**not** a dependency of this repo. Add it in your own project:

```
npm install @aws-sdk/client-kms
```

KMS access uses the **ambient IAM role** (task role / instance profile / IRSA). No
static credentials in code. Grant `kms:Encrypt` + `kms:Decrypt` on the one key id.

## Migration

Envelope rows start with a `0x01` scheme byte; direct-encrypted rows have no prefix. A
vault with an `envelope` provider still reads old rows, so you can switch an existing
deploy to KMS without a backfill: new writes use the envelope, old reads fall back
automatically.

## Env

```
SLACK_SIGNING_SECRET=...
SLACK_BOT_TOKEN=xoxb-...
PUBLIC_URL=https://your.domain
VOUCHR_DATABASE_URL=postgres://user:pass@host:5432/vouchr
VOUCHR_MASTER_KEY=$(openssl rand -base64 32)   # 32 bytes, base64
VOUCHR_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/...
```
