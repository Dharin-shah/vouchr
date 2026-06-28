# Deploying Vouchr

Concrete recipes for the deployments Vouchr actually supports. Every option named here is real
(`src/adapters/bolt.ts` → `VouchrOptions`). For the security model and what
Vouchr does *not* protect against, see [SECURITY.md](./SECURITY.md), which is not repeated here.

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

## Slack app + OAuth install flow

Create the app from [`examples/slack-manifest.yml`](./examples/slack-manifest.yml)
(api.slack.com/apps → From a manifest), replacing `YOUR_PUBLIC_URL`. The manifest sets:

- **Bot scopes:** `app_mentions:read`, `chat:write`, `commands`, `users:read`.
- **Events:** `app_mention`, `user_change` (the latter drives auto-revoke on deactivation).
- **Interactivity:** enabled, and **required** for the Connect button and the key/configure modals.
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
| Public URL is HTTPS. Egress also requires https, loopback exempt | operator (Vouchr enforces https egress) |
| Least-privilege IAM for any resolver (read-only on the specific secrets) | operator (example policy provided) |
| Slack scopes / events / interactivity applied from the manifest | operator (manifest provided) |
| TTL sweep scheduled (`sweepExpired()` on a timer) | Vouchr provides; operator schedules |
| Offboarding wired (`registerOffboarding`) so deactivated users lose access | Vouchr provides; operator wires |
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
