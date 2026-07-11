# Vouchr Threat Model

Vouchr is a self-hosted Slack-native credential broker. Its job is to let a Slack
agent act *as a user* against third-party APIs without the user's token ever
reaching the agent code, the LLM, the chat transcript, logs, or the audit table.
The token is injected only at the outbound HTTP call, after an egress check.

This document is a formal, honest threat model: trust boundaries, an attacker
model with concrete mitigations (and where there are none), and the security
invariants the code and tests enforce. It cross-references
[SECURITY.md](../SECURITY.md) rather than restating it; read that for the reporting
process and the explicit non-goals.

Every claim here is grounded in `src/core/*` and `src/adapters/*`.

## Trust boundaries

```mermaid
flowchart TB
    subgraph slack["Slack (external, semi-trusted)"]
        user["Slack user / channel"]
        slackapi["Slack Web API\n(users.info, conversations.info,\nchat.postMessage)"]
    end

    subgraph agent["Agent application (untrusted w.r.t. secrets)"]
        llm["LLM / model"]
        tools["MCP / tool runtime"]
        handler["Bolt event handler\n(your code)"]
    end

    subgraph vouchr["Vouchr process (trust anchor)"]
        adapter["Bolt adapter\n(src/adapters)"]
        core["Core broker\n(src/core: vault, injector,\nconsent, tokens, crypto)"]
    end

    subgraph store["Credential store"]
        db[("SQLite / Postgres\nencrypted token columns")]
    end

    subgraph ext["External services"]
        kms["KMS / secret manager\n(EnvelopeProvider, Resolvers)"]
        provapi["Provider APIs\n(GitHub, Google, ...)"]
    end

    user -->|verified events,\nOAuth authorize in browser| adapter
    handler -->|context.vouchr.connect / handle.fetch| adapter
    adapter --> core
    core -->|handle only,\nNEVER the secret| handler
    handler -.->|may pass response data| llm
    handler -.-> tools
    core <-->|encrypted blobs| db
    core <-->|wrap/unwrap DEK,\nresolve secretRef JIT| kms
    core -->|token injected at\nHTTP boundary, egress-checked| provapi
    adapter <-->|admin check, channel class,\nconfirm DM| slackapi
```

Boundaries, and what crosses each:

- **Slack ↔ Vouchr.** Vouchr trusts Slack-verified event payloads for identity
  and channel binding (signature verification is Bolt's responsibility, upstream of
  the adapter). The acting identity and channel are read from the verified event,
  never from caller-supplied arguments (`resolveIdentity`, `middleware` in
  `src/adapters/bolt.ts`). Raw keys typed into a Slack modal transit Slack's
  infrastructure (see SECURITY.md, "Raw keys typed into a Slack modal").
- **Agent app ↔ Vouchr.** The hard boundary. The agent (and therefore the LLM and
  any tool runtime) receives a `ConnectionHandle`, never the secret
  (`src/core/injector.ts`). The handle exposes `fetch()` and `account()` only.
- **Vouchr ↔ database.** Token material is stored encrypted (AES-256-GCM, optional
  KMS envelope); the rest of the row and the SQLite file are not encrypted by
  Vouchr (`src/core/crypto.ts`, `src/core/db.ts`). At-rest protection of the file
  itself is the operator's job.
- **Vouchr ↔ external secret manager.** Two distinct integrations: `EnvelopeProvider`
  wraps/unwraps per-secret data keys (`crypto.ts`); `Resolvers` resolve a non-secret
  `secretRef` (e.g. an AWS Secrets Manager ARN) to a secret just-in-time, never
  persisted or cached (`injector.ts:resolveRef`). Both are operator-supplied; Vouchr
  ships no cloud SDK.
- **Vouchr ↔ provider API.** The only place a secret leaves the process. Egress is
  restricted to the provider's `egressAllow` host list, forced to HTTPS, and can be
  narrowed further by optional path/method/validator controls (`injector.ts:fetch`).
- **LLM / MCP / tool runtime.** Treated as fully untrusted for secrets. They sit
  *inside* the agent boundary and never receive a token by construction.

## Attacker model

For each attacker: the capability, then how Vouchr mitigates it (or honestly does
not).

### Malicious prompt / prompt injection

A crafted message or tool output tries to make the agent exfiltrate the token or
call an arbitrary host.

- **Token exfiltration: mitigated by construction.** The model never holds a token;
  it only ever sees a `ConnectionHandle`. There is no API that returns the secret to
  caller code; `fetch()` attaches it internally (`injector.ts`).
- **Arbitrary host call: mitigated.** Even if the prompt coerces the agent into
  calling `handle.fetch(attackerUrl)`, the egress allowlist rejects any host not in
  `provider.egressAllow`, *before any secret is read* (`injector.ts:fetch`, the
  allowlist check precedes `vault.get`). HTTP is also rejected (HTTPS-only, loopback
  exempt) so the bearer can't be downgraded to cleartext.
- **Not mitigated:** what the agent does with a *response body* it legitimately
  fetched. Vouchr keeps the token from the model, not the data the API returns (see
  SECURITY.md, "Provider responses flow back to your agent").

### Malicious user

A Slack user tries to use someone else's credential or read another tenant's data.

- **Mitigated.** Per-user connections are keyed by the verified acting identity
  (`userOwner(identity)`), which comes from the Slack event, not from any argument.
  A user can only `connect()` to their own connection. Tenant isolation is enforced
  by the full owner key on every query (invariant: full-key tenant isolation).
- A user cannot self-grant a channel credential: channel config is admin-gated
  (`requireAdmin`).

### Compromised channel

A channel is used to trick the agent into using a shared credential inappropriately,
or a channel changes class after a shared credential was configured.

- **Mitigated.** Shared (channel-owned) credentials are refused in ineligible channel
  classes (externally shared / Slack Connect, DMs/MPIMs, archived) at both config
  time and *use* time (`assertChannelEligible` is re-checked in `connectChannel`,
  `src/adapters/bolt.ts`). A channel turned Slack Connect after configuration stops
  working immediately.
- The eligibility rule lives in core (`channelIneligibleReason`,
  `src/core/channelConfig.ts`) and **fails closed**: if the channel class can't be
  read, the credential is refused.

### Compromised provider response

A provider (or a man-in-the-middle on the provider connection) returns a redirect or
malicious payload aiming to leak the bearer or pivot.

- **Redirect leak: mitigated.** `fetch` uses `redirect: 'manual'` so a 3xx is never
  auto-followed off the allowlisted host with the bearer attached (`injector.ts`).
- **Token-endpoint failures: mitigated against leakage.** Token/refresh/revoke errors
  never include the token in the error string (`src/core/tokens.ts`).
- **Not mitigated:** the contents of a 2xx response body, which flows back to the
  caller (same non-goal as prompt injection above).

### Rogue custom provider / accountProbe

A custom `Provider` (its `inject`, `revoke`, `accountProbe`) is itself the attacker,
or buggy.

- **Partially mitigated.** A custom provider runs inside the Vouchr process and is
  trusted with the token it is given. By design it must attach the secret somewhere.
  Vouchr constrains *where* outbound calls go (egress allowlist applies to
  `handle.fetch`), but a malicious `accountProbe`/`revoke`/`inject` could send the
  token to an arbitrary host or place caller-supplied data into audit metadata.
- This is an explicit operator-responsibility / non-goal: audit metadata is
  caller-supplied (SECURITY.md, "Audit metadata is caller-supplied"). Defense in
  depth: the audit layer redacts credential-shaped values anyway (`src/core/audit.ts`,
  `looksSecret`). Treat custom providers as trusted code.

### Database reader

An attacker with read access to the SQLite file or Postgres.

- **Mitigated for token material.** `access_token_enc` / `refresh_token_enc` and the
  installation `bot_token`/`data` columns are AES-256-GCM encrypted with the master
  key; with an `EnvelopeProvider`, each secret has its own DEK wrapped by an external
  KEK (`crypto.ts:seal`, `vault.ts`, `installationStore.ts`).
- **Not mitigated by Vouchr:** the rest of each row (provider id, scopes, owner key,
  `secret_ref`, timestamps) and the SQLite file as a whole are plaintext. The master
  key in memory/env is also out of scope here. Operator must encrypt the store at rest
  and access-control it (SECURITY.md, "The SQLite file is not wholly encrypted at
  rest"; "Operator responsibilities").

### Network redirect / egress bypass

An attacker manipulates the request URL or DNS to send the bearer somewhere
unintended.

- **Mitigated before secret access.** Egress allowlist (`provider.egressAllow`) + HTTPS
  enforcement + `redirect: 'manual'` (`injector.ts`). Optional path/method/validator
  controls are checked in the same pre-secret block. URLs with embedded userinfo are
  refused before vault access.
- **Not fully mitigated:** provider-side scope/action restriction. Even with path/method
  narrowing, Vouchr is not the provider's authorization engine; constrain the token's
  own scopes and permissions at the provider. DNS rebinding against an allowlisted host
  is not specifically defended.

### Approval replay / bypass (human-in-the-loop writes, #113)

An attacker (a looping or prompt-injected agent) tries to stretch one human approval
into many actions, or to skip the approval entirely.

- **Mitigated.** The gate runs in the injector strictly AFTER every egress gate (an
  egress-denied target never even prompts — approval can widen nothing) and BEFORE the
  secret is read. A grant is SINGLE-USE — consumed with the same atomic
  `DELETE ... RETURNING` as the OAuth `state`, so two concurrent retries cannot both
  spend it — TTL-bound (default 5 minutes), and matches ONLY the exact
  (method, host, path, query) it was minted for: not a prefix, not a pattern, never a
  class of actions. The query is bound BYTE-EXACT, as a digest of the exact query string
  sent upstream — no sorting or normalization, since upstream parsers legitimately treat
  reordered or duplicated parameters differently — so a replanning or prompt-injected
  agent cannot spend an approval of `POST /transfer?to=alice&amount=10` on
  `?to=attacker&amount=1000000` (or on any reordering); any textual change re-prompts.
  Raw query values may carry tokens, signed-URL signatures, or PII, so they are never
  persisted, audited, logged, or rendered: the prompt lists the parameter NAMES and
  states that their exact values are bound. When `approval.paths` is set it
  inherits the egress path lock's fail-closed
  encoded-separator rule (a `%2f`/`%5c` in the path REQUIRES approval, so `/pay%2Fx`
  can't slip past a `/pay` lock unconfirmed). The grant is also bound to the **credential
  owner** it was minted against (user vs channel, and which user), so a later resolution
  switch — a union member A→B, or a per-user→shared mode change — no longer matches and
  re-prompts: the write can never run against a different credential than the human
  approved. And a grant is purged the moment its credential is deleted or replaced
  (disconnect, offboard, bulk-revoke, reconnect, TTL-expiry — all route through the one
  vault mutation surface), so it can't survive a revocation or be spent after a
  reconnect. Approve/Deny clicks are re-authorized server-side (provider re-validated
  against the registry, approver eligibility re-checked at the mutation; ineligible
  clicks are rejected and audited) — nothing in the interaction payload is trusted.
- **Accepted tradeoff:** the request BODY is not hashed into the grant key. Bodies are
  legitimately rebuilt on retry (fresh timestamps, idempotency keys), so binding to the
  payload bytes would break the approve-then-retry flow outright. Be explicit about what
  that means: for an API whose write target or amount lives in the BODY (JSON/RPC), an
  approval pins the endpoint + method + query but NOT the body parameters — an agent
  that rebuilds the body differently between the prompt and the retry spends the grant
  on the rebuilt payload. Do not treat approval as covering the exact action for such
  endpoints; scope `approval.paths` tightly and prefer APIs that carry the
  action-defining parameters in the URL. (A digest over declared-stable body fields, or
  a provider-supplied action fingerprint, would close this; no built-in provider ships
  one today.) This is also why approval prompts show the method, host+path, and query,
  and deliberately never render the body (which may carry user content).

### Replayed OAuth callback / state

An attacker replays or forges an OAuth `state` to bind a connection to the wrong
user or reuse a callback.

- **Mitigated.** `state` is 32 random bytes, single-use, and expiring. `consume()`
  does an atomic `DELETE ... RETURNING` so two concurrent callbacks can't both pass
  (no get-then-delete TOCTOU, correct even on multi-instance Postgres), and rejects
  rows older than the 10-minute TTL (`src/core/consent.ts`). PKCE (S256) is sent when
  the provider enables it; the verifier is stored server-side in the consent row, not
  in the redirect.

### Deactivated user

A user is deactivated in Slack but a pending OAuth or stored connection could let the
agent keep acting as them.

- **Mitigated.** On Slack's `user_change` with `deleted: true`, `offboardUser` deletes
  all the user's own connections **and** purges any in-flight consent so a pending
  "Connect" click can't resurrect a connection after offboarding
  (`src/core/offboard.ts`, `consent.deleteForUser`; wired in
  `registerOffboarding`). Local delete happens first (the security-meaningful action);
  upstream revoke is best-effort.
- **Honest limit:** disconnect/offboard guarantees local deletion first, but upstream
  provider revocation is best-effort only. The Slack event path is scoped to the
  `(team_id, user_id)` the event carries; org-wide Grid deprovisioning should go
  through SCIM (SECURITY.md, "Disconnect/offboard revoke is best-effort"; offboarding
  scoping note in `bolt.ts`).

### Slack Connect cross-org exposure

A credential configured in a workspace becomes usable by members of a different
org via an externally shared channel.

- **Mitigated.** This is the security-critical channel case. Shared channel
  credentials are refused in `is_ext_shared` / `is_shared` / `is_pending_ext_shared`
  channels at config time and re-verified at use time, failing closed if the class
  can't be read (`channelIneligibleReason`, `connectChannel`). Per-user credentials
  are unaffected. Each member uses their own.

## Security invariants

These mirror what the code (and the test suite) enforce:

1. **Secrets never appear in model schemas, Slack messages, logs, the audit table, or
   returned handles.** The agent gets a `ConnectionHandle`, not a token
   (`injector.ts`). Errors in token/refresh/revoke never interpolate the secret
   (`tokens.ts`). Audit `meta` is redacted for credential-shaped values
   (`audit.ts`). Modal-submitted secrets are never echoed/logged/put in audit meta
   (`handleSecretSubmit`, `bolt.ts`).
2. **Egress is checked before the secret is read.** In `injector.ts:fetch`, the
   allowlist + HTTPS checks run before `vault.get`.
3. **Owner vs acting human are never conflated.** `owner` keys the vault; `acting`
   keys the audit. A shared channel credential is used under the channel owner but
   audited as the human who triggered the call (`injector.ts`, `owner.ts`).
4. **Channel credentials are refused in externally shared channels** (and other
   ineligible classes), fail-closed (`channelConfig.ts`).
5. **OAuth `state` is single-use and expiring**: atomic `DELETE ... RETURNING` +
   10-minute TTL (`consent.ts`).
6. **Offboarding clears pending consent** so a deactivated user's in-flight OAuth
   can't resurrect a connection (`offboard.ts`).
7. **Refresh cannot bypass the max-age TTL.** Silent refresh uses `updateTokens`,
   which leaves `created_at` intact; only a reconnect (`upsert`) resets it
   (`vault.ts`, `injector.ts:doRefresh`).
8. **Full-key tenant isolation.** Every connection read/write is scoped by the full
   owner key `(team_id, owner_kind, owner_id, provider)`, with a matching UNIQUE
   constraint (`vault.ts`, `db.ts`). `teamId` is always the authenticated user's,
   never derived from the channel id (`owner.ts:channelOwner`).
9. **Channel-credential config is admin-gated, default-closed.** `isSlackAdmin`
   fails closed on any API error; non-admin attempts are audited as `denied`
   (`adapters/slack-identity.ts`, `bolt.ts:requireAdmin`).

## Non-goals (cross-reference)

Vouchr is a credential *boundary*, not a complete authorization system. The explicit
non-goals live in [SECURITY.md -> "What Vouchr does not protect against"](../SECURITY.md):

- Not provider-side authorization: egress checks can narrow host/path/method, but provider scopes
  still decide what the credential can actually do.
- Provider response bodies flow back to the agent once fetched.
- Raw keys typed into a Slack modal pass through Slack (prefer external references).
- Disconnect/offboard deletes locally first; upstream revocation is best-effort.
- Audit metadata is caller-supplied; don't put secrets in it.
- The SQLite file is not wholly encrypted at rest.
- Audit completeness is best-effort, not guaranteed (see below).

### Audit completeness is best-effort by design

The authoritative audit table is written on a best-effort basis, never guaranteed-complete.
Every audit write on the injection path — the successful-injection row and the
failure/refresh rows — swallows its own error (`.catch(() => undefined)` in
`injector.ts:fetch`, `egressError`, `doRefresh`).

- **Why.** The audit write happens *after* the provider call has already executed. A
  provider request is non-idempotent (a `POST` that already fired, a refresh that already
  rotated a single-use token), so a bookkeeping failure must not roll back or fail the
  request — the caller could otherwise retry an operation that already took effect. Recording
  that a call happened must never be able to undo the call.
- **The failure window.** The audit `INSERT` fails (DB down, disk full, connection dropped)
  *after* the outbound provider call has already succeeded. The action occurred; the audit
  row for it is missing. Nothing in the request path detects or retries this.
- **Mitigations available today.** The `injected` (and `refreshed`) `VouchrEvent` fires on the
  exact same path and is an **independent, redundant signal** of the same event. Wire an
  `EventSink` to a durable external metrics/log pipeline so the record survives even when the
  audit `INSERT` fails, and monitor database health. Note the audit-insert failure itself is
  swallowed (`.catch(() => undefined)`) and is **not** logged today — precisely why the `EventSink`
  is the signal to rely on, not application logs. See
  [SECURITY.md -> "Audit completeness is best-effort"](../SECURITY.md)
  and the deployment production-readiness checklist
  ([DEPLOYMENT.md](./DEPLOYMENT.md#production-readiness-checklist)).

Operator responsibilities (master key handling, least-privilege resolver IAM, at-rest
encryption, understanding the workspace-wide admin gate) are likewise enumerated in
SECURITY.md.
