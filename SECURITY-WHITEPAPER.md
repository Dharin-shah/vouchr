# Vouchr Security Whitepaper

For buyers and security reviewers evaluating Vouchr. It synthesizes the security
posture; it does not restate the details. Read alongside
[ARCHITECTURE.md](./ARCHITECTURE.md) (design), [THREAT-MODEL.md](./THREAT-MODEL.md)
(trust boundaries, attacker model, invariants), and [SECURITY.md](./SECURITY.md)
(non-goals, operator responsibilities, reporting). Every claim here is grounded in
`src/core/*`; where a limit exists it is stated plainly, not glossed.

## The problem

A Slack agent often needs to act *as a user* against a third-party API — open a
GitHub issue as them, read their calendar — which means it needs the user's token.
The naive design hands that token to agent code, and from there it leaks: into the
LLM context, the chat transcript, logs, error strings, the audit trail. An agent
needs **delegated authority without ever holding the secret that carries it.**

## The model

Vouchr is a credential *boundary*. Five mechanisms compose it:

- **Capability handle, not a secret.** The agent (and therefore the LLM and any
  tool runtime) receives a `ConnectionHandle` exposing `fetch()` and `account()`
  only. There is no API that returns the token to caller code
  (`src/core/injector.ts`).
- **Injection boundary.** The token is attached to the outbound request *inside*
  `handle.fetch()`, at the HTTP call — the single point where a secret leaves the
  process.
- **Egress allowlist.** Before the secret is ever read, the destination host must
  be in the provider's `egressAllow` list; HTTPS is required (loopback exempt) so
  the bearer can't be downgraded to cleartext, and `redirect: 'manual'` prevents a
  3xx from carrying it off-host. Optional path/method/validator constraints are
  additive on top.
- **Owner / acting separation.** The principal that *owns* a credential (a user, or
  a channel) keys the vault; the human who *triggered* the call keys the audit.
  A shared channel credential is used under the channel owner but always audited as
  the human who acted — a shared cred never launders away who used it.
- **Channel scoping.** Per-user by default. Channel-shared credentials are
  admin-gated and refused (fail-closed) in ineligible channel classes — externally
  shared / Slack Connect, DMs/MPIMs, archived — re-checked at *use* time, not just
  config time, so a channel that turns Slack Connect stops working immediately.

## Cryptography at rest

Token material — `access_token_enc`, `refresh_token_enc`, and the installation
`bot_token`/`data` columns — is encrypted with **AES-256-GCM**. The rest of each
row, and the SQLite file as a whole, is *not* encrypted by Vouchr (see Limits).

- **Per-secret IV.** Each encryption generates a fresh random 12-byte IV.
  Layout: `iv(12) | tag(16) | ciphertext` (`src/core/crypto.ts`, `encrypt`). GCM's
  authentication tag means tampering or corruption fails closed on decrypt.
- **Master-key default.** The 32-byte key comes from `VOUCHR_MASTER_KEY`
  (base64, validated to decode to exactly 32 bytes; `loadMasterKey`). Secrets are
  encrypted directly under it. This format carries no version byte.
- **Optional envelope mode.** Supply an `EnvelopeProvider` (a KMS/Vault binding with
  `wrapDataKey`/`unwrapDataKey`) and new writes instead mint a fresh per-secret data
  key (DEK), encrypt the secret under the DEK, and store the DEK *wrapped* by your
  external KEK alongside the ciphertext. Scheme byte `0x01`, layout:
  `0x01 | dekLen(2, big-endian) | wrappedDek | iv(12) | tag(16) | ciphertext`
  (`seal`). The plaintext DEK is scrubbed from memory after use; only the wrapped
  copy persists. Vouchr ships no cloud SDK — the KMS binding is operator-supplied.
- **Format dispatch, back-compatible.** Reads dispatch on the stored format
  (`open`): no provider → always legacy direct decrypt; provider + leading byte
  `0x01` → envelope path, falling back to legacy on any failure (covering the
  1-in-256 legacy IV that happens to start `0x01`). Both modes read existing rows;
  enabling envelope is non-destructive.
- **External references.** A credential can instead store a *non-secret* pointer
  (e.g. an AWS Secrets Manager ARN) plus a resolver `source` id. The secret stays in
  the external manager and is resolved just-in-time at the injection boundary —
  never persisted, cached, or logged (`injector.ts`, `resolveRef`). Rotation stays
  where the secret lives, and Vouchr never holds it.

## Tenant isolation, OAuth, audit

- **Full owner-key tenant isolation.** Every vault read/write is scoped by the full
  owner key `(team_id, owner_kind, owner_id, provider)`, backed by a matching UNIQUE
  constraint (`vault.ts`, `db.ts`). `team_id` is always the authenticated user's,
  never derived from a channel id. One workspace cannot read or overwrite another's
  credential.
- **Single-use OAuth state + PKCE.** `state` is 32 random bytes, single-use and
  10-minute-expiring; `consume()` is an atomic `DELETE ... RETURNING` (no
  get-then-delete race, correct on multi-instance Postgres). PKCE (S256) is sent when
  the provider enables it, with the verifier stored server-side in the consent row,
  not in the redirect (`src/core/consent.ts`).
- **Audit + redaction.** The audit log is keyed to the acting human. Vouchr's own
  code keeps secrets out of `audit.meta`, and the audit layer redacts
  credential-shaped values as defense in depth (`src/core/audit.ts`).

## What it does NOT protect against

Vouchr is a credential boundary, not a complete authorization system. See
[SECURITY.md → "What Vouchr does not protect against"](./SECURITY.md) for the full
list. In brief: it is **not provider-side authorization** (egress checks can narrow
host/path/method, but the token's own scopes still decide what the provider allows);
**provider response bodies flow back** to your agent once fetched; **raw keys typed
into a Slack modal transit Slack** (prefer an external reference);
**disconnect/offboard revocation is best-effort upstream** after local delete;
**audit metadata is caller-supplied**; and **the store file is not wholly encrypted
at rest** — only token columns are.

## Operational posture

- **Self-hosted custody.** Vouchr runs on your infrastructure; tokens and the master
  key never leave it.
- **Scale.** SQLite (embedded, zero-config) by default; Postgres for stateless /
  multi-instance deploys, with credentials isolated per `team_id` on a shared DB.
- **Observability.** A no-secret `EventSink` emits structured events
  (provider/host/status/counts only — never tokens, refs, or user content) for
  metrics and alerting (`injector.ts`).
- **Revocation & lifecycle.** TTL sweep (idle + max-age), lazy expiry on read,
  single-flight token refresh that cannot defer the max-age TTL, declarative
  RFC-7009 revoke, and `/vouchr disconnect`.
- **Offboarding.** On Slack `user_change` deactivation, the user's own connections
  are deleted and pending consent purged so an in-flight "Connect" click can't
  resurrect access; upstream revoke is best-effort (`src/core/offboard.ts`).

## Due-diligence checklist

A buyer/security team can run this against the repository:

- **Build & test.** Node ≥ 20.6. `npm install && npm test` (unit + integration,
  fully offline). `npm run pg:up && npm test` exercises the Postgres backend. CI runs
  typecheck + tests (including Postgres) on every push and PR.
- **Architecture boundary.** Confirm `src/core/` imports nothing from `@slack/*` or
  `src/adapters/` — enforced by `test/architecture.test.ts`. Security logic lives in
  core; the Bolt adapter only supplies inputs.
- **Threat model.** Walk [THREAT-MODEL.md](./THREAT-MODEL.md) — trust boundaries, the
  attacker model (prompt injection, malicious user, DB reader, Slack Connect cross-org
  exposure, replayed OAuth), and the nine enforced invariants — against the code it
  cites.
- **Crypto review.** Read `src/core/crypto.ts` (AES-256-GCM, per-secret IV, scheme
  `0x01` envelope, format dispatch) and `test/envelope.test.ts`.
- **Deployment & custody.** Work through the
  [production readiness checklist](./DEPLOYMENT.md#production-readiness-checklist) and
  the [Key rotation](./DEPLOYMENT.md#key-rotation) and
  [Backup and restore](./DEPLOYMENT.md#backup-and-restore) runbooks.
- **Residual risks.** Confirm the non-goals in
  [SECURITY.md](./SECURITY.md#what-vouchr-does-not-protect-against) are acceptable for
  your use, and that operator responsibilities (master-key custody, at-rest encryption
  of the store, least-privilege resolver IAM) are assigned.

**Status:** pre-1.0. CI is green including the Postgres backend, but Vouchr has not
yet been run in production. Treat CI green as necessary, not sufficient.
