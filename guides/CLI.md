# vouchr operator CLI

A secret-free CLI for self-hosted operators. It connects to the **same** credential
store the app uses; reads are metadata-only, and the mutating commands (`migrate`,
`revoke`, `rekey`, `prune`) never print tokens, refresh tokens, key material, or
secret ciphertext.

## Run

```bash
npm run cli -- <command> [options]
# or directly:
node --import tsx bin/vouchr.ts <command> [options]
```

(The file has a `#!/usr/bin/env -S node --import tsx` shebang, so after `chmod +x`
and `npm link`/install it can also be invoked as `vouchr`.)

## Store selection (same env as the app)

| Var / flag            | Purpose                                                       |
| --------------------- | ------------------------------------------------------------ |
| `VOUCHR_DATABASE_URL` | Postgres connection string (`postgres://…`) — required; boot fails closed if unset or non-`postgres://` (no `DATABASE_URL` fallback). Add `sslmode=require` to the URL for TLS. |
| `--db <url>`          | Postgres connection string (overrides `VOUCHR_DATABASE_URL`) |
| `VOUCHR_MASTER_KEY`   | base64 32-byte id-less key (validated by `doctor`; used by `revoke`/`rekey`) |
| `VOUCHR_MASTER_KEYS`  | comma-separated `id:base64key` entries; first = primary (encrypts new writes), all decrypt — see DEPLOYMENT.md § Key rotation |

## Commands

### `migrate`
Creates/converges the PostgreSQL schema to this build's version. Run it **once per
deploy/upgrade** with a **schema-owner** DB role (may `CREATE`/`ALTER` tables) — the runtime
connects DML-only and never creates tables, and fails closed until the database is migrated.
Idempotent and advisory-locked, so re-running it or racing concurrent runs across replicas is safe.
See [DEPLOYMENT.md § Migrations](./DEPLOYMENT.md#migrations) for the schema-owner vs DML-only roles
and example `GRANT`s.

```bash
VOUCHR_DATABASE_URL=postgres://vouchr_owner:...@host:5432/vouchr vouchr migrate
```

### `inventory`
Lists stored connections from the `connection` table: team, owner_kind, owner_id,
provider, allowlisted source kind (`vault` | `aws-sm` | `gcp-sm` | `azure-kv` | `custom`), reference
presence (`yes` | `no`), created_at, last_used_at, expires_at. Token ciphertext and raw
reference/source values are never selected; this also keeps malformed legacy metadata out of
terminal output.

```bash
vouchr inventory --team T123 --provider github
```

### `channels`
Per-channel policy at a glance from `channel_config` + `channel_tool`: team, channel,
provider, mode (`shared` | `per-user` | `session`), enabled (`yes` | `no` | `-`).

```bash
vouchr channels --team T123
```

### `revoke`

Break-glass incident response for one provider. Dry-run is the default: it reads matching connection
and pending-authority counts, writes no revocation marker, and deletes nothing. An exact bare `--yes`
first commits a durable provider+scope fence, then clears matching pending authority (including
opaque user and channel credential-setup requests), deletes local
credentials, and attempts supported upstream revocation best-effort. A matching setup that began
before the fence either finishes first and is found by the post-fence scan or is refused; a genuinely
new setup begun afterward remains possible.

```bash
vouchr revoke --provider github                         # dry-run, all owners
vouchr revoke --provider github --team T123 --yes       # users + channels in one team
vouchr revoke --provider github --user U123 --yes       # this user's own rows across teams
vouchr revoke --provider github --channel C123 --yes    # this shared channel owner across teams
```

`--team` composes with either owner scope. `--user` and `--channel` are mutually exclusive: the
consent row's channel is request origin, not shared-credential ownership. Durable markers store only
a fixed hash of the selected scope. A provider must be currently registered or already present under
that exact validated id in Vouchr's durable state; an unrecognized typo cannot create a marker. The
command exits non-zero if the fence cannot be established or matching local access remains. Upstream
attempted, failed, and skipped counts are reported separately; a skip is never called success.

### `doctor`
Diagnostics printed as `PASS`/`FAIL` (plus `INFO` lines). Exits non-zero if any check
fails. Checks: the master key(s) (`VOUCHR_MASTER_KEY` / `VOUCHR_MASTER_KEYS`) parse and
decode to 32 bytes (never printed; a keyring reports the key count and primary id),
DB reachable, and counts of connections / consent rows. Reports which backend is in use.

```bash
vouchr doctor
```

### `rekey`
Master-key rotation for the direct (non-KMS) path (#115): re-encrypts every stored
ciphertext (`connection` token columns, `installation` bot token + data) under the
PRIMARY key — the first `VOUCHR_MASTER_KEYS` entry. Rows are decrypted with whichever
configured key authenticates; envelope (KMS-wrapped) rows are skipped, their rotation
happens in the KMS. Idempotent, safe to interrupt and re-run (row-at-a-time guarded
writes: a crash leaves a mixed but fully readable store, and a row refreshed mid-run
is never clobbered). Output is counts per key id/scheme — never secrets.

`--dry-run` classifies and counts without writing; the rotation runbook
(DEPLOYMENT.md § Key rotation) uses it as the "zero old-key rows" check before the
old key is removed from the environment. Exits non-zero if any blob decrypts under
no configured key (the error names the missing key id).

```bash
VOUCHR_MASTER_KEYS="k2026:$NEW_KEY,k2019:$OLD_KEY" vouchr rekey --dry-run
VOUCHR_MASTER_KEYS="k2026:$NEW_KEY,k2019:$OLD_KEY" vouchr rekey
```

### `prune`
Audit retention (#208): delete `audit` rows older than a cutoff, in **bounded batches**
(each ≤ 10000 rows, its own transaction) so it **bounds** the WAL and locks held per
statement and never monopolizes the pool. (Deletes still generate WAL and dead tuples;
autovacuum makes that space reusable over time — it does not necessarily shrink the table
on disk.) Restartable and idempotent — an interrupted or repeated run just deletes
whatever is now old. Deletion needs an **exact bare `--yes`** (a valued `--yes=…`, a
`--yes` with `--dry-run`, an unknown/duplicate flag, or a positional is rejected, not
obeyed). Dry-run by default (counts only); retention is an explicit choice (nothing prunes
automatically). Run it on a schedule (cron / k8s `CronJob`). See DEPLOYMENT.md § Audit retention.

```bash
vouchr prune --older-than-days 90            # DRY-RUN: N rows older than 90 days
vouchr prune --older-than-days 90 --yes      # delete, in bounded batches
#   --batch <N>   rows per DELETE (1..10000; default 10000)
```

### `health [provider|host ...]`
Best-effort HTTPS reachability of each provider's authorize/token **hosts** (no
credentials are ever sent). Defaults to the built-ins `github google gitlab notion`;
extra args are treated as provider ids or bare hostnames.

```bash
vouchr health
vouchr health github example.com
```

### `help`
Usage.
