# vouchr operator CLI

A read-only, secret-free CLI for self-hosted operators. It connects to the **same**
credential store the app uses and only ever reads metadata. It never decrypts or
prints tokens, refresh tokens, or secret ciphertext.

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
| `VOUCHR_MASTER_KEY`   | base64 32-byte key, only loaded/validated by `doctor`      |

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
fails. Checks: `VOUCHR_MASTER_KEY` present and decodes to 32 bytes (never printed),
DB reachable, and counts of connections / consent rows. Reports which backend is in use.

```bash
vouchr doctor
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
