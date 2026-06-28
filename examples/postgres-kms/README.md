# Production template: Postgres + KMS envelope encryption

A **template**, not a runnable demo — you must fill in the KMS provider before use.
It wires the three things a real deployment wants:

- **`databaseUrl`** — Postgres instead of the SQLite default, so the deployment is
  stateless and can run multiple instances behind a load balancer.
- **`envelope`** — KMS envelope encryption for at-rest secrets. Each secret gets a
  fresh data key wrapped by your KMS key; rotating the KMS key never touches the rows.
- **`installationStore`** — a db-backed `DbInstallationStore` so one deployment serves
  many workspaces (and Enterprise Grid org-wide installs). Wire the **same** store
  into Bolt's OAuth installer.

```ts
const vouchr = await createVouchr({
  providers: [github(), google()],
  baseUrl: process.env.PUBLIC_URL!,
  databaseUrl: process.env.VOUCHR_DATABASE_URL,
  envelope: kmsEnvelope,
  installationStore,
});
```

## Fill in the KMS provider

`kmsEnvelope` in `app.ts` fails closed until you replace its bodies with
`EncryptCommand` / `DecryptCommand` calls (the real implementation is in the
file's comment). That needs `@aws-sdk/client-kms`, which is intentionally
**not** a dependency of this repo — add it in your own project:

```
npm install @aws-sdk/client-kms
```

KMS access uses the **ambient IAM role** (task role / instance profile / IRSA) — no
static credentials in code. Grant `kms:Encrypt` + `kms:Decrypt` on the one key id.

## Migration

Envelope rows start with a `0x01` scheme byte; legacy direct-encrypted rows have no
prefix. A vault with an `envelope` provider still reads old rows, so you can switch
an existing local/SQLite deploy to KMS without a backfill — new writes use the
envelope, old reads fall back automatically.

## Env

```
SLACK_SIGNING_SECRET=...
SLACK_BOT_TOKEN=xoxb-...
PUBLIC_URL=https://your.domain
VOUCHR_DATABASE_URL=postgres://user:pass@host:5432/vouchr
VOUCHR_MASTER_KEY=$(openssl rand -base64 32)   # 32 bytes, base64
VOUCHR_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/...
```
