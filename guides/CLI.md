# vouchr operator CLI

A secret-free CLI for self-hosted operators. It connects to the **same** credential
store the app uses; reads are metadata-only, and the mutating commands (`revoke`,
`rekey`) never print tokens, refresh tokens, key material, or secret ciphertext.

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
| `--db <path>`         | SQLite file path (overrides `VOUCHR_DB`; default `vouchr.db`) |
| `VOUCHR_DB`           | SQLite file path                                             |
| `VOUCHR_DATABASE_URL` | Postgres connection string (takes precedence over SQLite)   |
| `VOUCHR_MASTER_KEY`   | base64 32-byte id-less key (validated by `doctor`; used by `revoke`/`rekey`) |
| `VOUCHR_MASTER_KEYS`  | comma-separated `id:base64key` entries; first = primary (encrypts new writes), all decrypt — see DEPLOYMENT.md § Key rotation |

## Commands

### `inventory`
Lists stored connections from the `connection` table: team, owner_kind, owner_id,
provider, source (`vault` | `aws-sm` | …), secret_ref (non-secret external pointer),
created_at, last_used_at, expires_at. Token ciphertext columns are never selected.

```bash
vouchr inventory --team T123 --provider github
```

### `channels`
Per-channel policy at a glance from `channel_config` + `channel_tool`: team, channel,
provider, mode (`shared` | `per-user`), enabled (`yes` | `no` | `-`).

```bash
vouchr channels --team T123
```

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
