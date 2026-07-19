# Security Policy

Vouchr is a credential broker. Security reports are taken seriously and prioritized.

For the detailed trust-boundary review, see the [threat model](./guides/THREAT-MODEL.md).
For production setup, see the [deployment guide](./guides/DEPLOYMENT.md).

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Use GitHub's private vulnerability
reporting: the repository's **Security → Report a vulnerability** tab (GitHub Security
Advisories). If that is unavailable, contact the maintainers privately rather than filing a
public issue.

Please include: affected version/commit, a description, reproduction steps or a proof of
concept, and the impact you foresee. We aim to acknowledge within a few business days and to
coordinate a fix and disclosure timeline with you.

## Scope

Of particular interest:

- **Secret leakage**: any path where a credential reaches logs, Slack messages, the audit
  table, error strings, an LLM/tool schema, or a resolved external-reference secret being
  persisted or cached.
- **Tenant / owner isolation**: any query or code path that lets one `(team, owner_kind,
  owner_id, provider)` read or overwrite another's credential.
- **Authorization**: bypassing the admin gate on channel-credential configuration, or using
  a channel credential without proven authorization for that channel.
- **OAuth flow**: `state` reuse/fixation, PKCE downgrade, or open-redirect / egress-allowlist
  bypass at the injection boundary.

## What Vouchr does not protect against

Vouchr is a credential *boundary*, not a complete authorization system. Know its limits:

- **It is not provider-side authorization.** The egress allowlist always restricts which *hosts* a
  token may be sent to, and providers may optionally add path, method, and validator constraints.
  Those checks still do not replace provider-side scopes or permissions. Constrain the token's own
  scopes at the provider.
- **Provider responses flow back to your agent.** Vouchr keeps the *token* from the agent/LLM, but
  the response body is returned to your handler. If that data is sensitive, your code (and prompt)
  must decide what reaches the model or the Slack reply.
- **A verbatim-relaying response is a token-reflection path.** The response body is returned as-is
  (the headless `/v1/fetch` relays the provider response verbatim; `handle.fetch()` hands you the raw
  `Response`). Vouchr injects the bearer into the *outbound* request, so if an allowlisted host exposes
  a header-reflecting / echo endpoint (e.g. a debug route that returns the request headers), the
  injected `Authorization` header can be echoed back to the caller — a same-tenant token-reflection
  leak. Egress host-allowlisting alone does not stop this. **Mitigation:** for providers brokering
  human credentials, constrain the reachable paths so echo/debug routes are unreachable — use the
  provider's `egressPaths` (path-prefix allowlist) and/or `egressValidate` (per-request validator) in
  addition to `egressAllow`. Both are checked before the secret is read.
- **Raw keys typed into a Slack modal pass through Slack.** The value is in the modal submission
  payload. Vouchr never echoes, logs, or stores it unsafely, but an external secret reference (an
  ARN resolved just in time) avoids putting the secret in Slack at all. Prefer it.
- **Disconnect/offboard revoke is best-effort.** Removing a connection deletes Vouchr's stored
  credential first. For a real (non-dry-run) row, when the provider declares a revoke path and the
  claimed row contains a usable vaulted token, Vouchr then attempts upstream revocation. If that
  revocable row is an external reference or its token cannot be read, local removal still commits but
  Disconnect reports upstream revocation as unconfirmed; a successful audit write records the skip.
  Rotate referenced credentials in their source manager. Providers without revocation support and
  trusted dry-run rows are intentional skips. A network/provider failure likewise cannot keep local
  access alive, but upstream revocation is not guaranteed.
- **Local offboarding is a durable user-authority fence.** User OAuth, static-key, and reference
  writes are ordered against a PostgreSQL tombstone. Slack setup controls and deployment-bound
  headless assertions minted before that fence cannot recreate local access afterward. Retained
  Bolt handles and broker assertions are checked before secret access and again immediately before
  provider send, including when the credential belongs to a shared channel and therefore remains
  available to other current users. Pending and granted approvals requested by the departed user are
  removed best-effort; their creation time is also checked against the tombstone at decision and
  consumption, and an approver's stale control receipt is refused. Callers must obtain a fresh setup
  or use receipt after legitimate re-onboarding. Enterprise/global offboarding records its scope
  before discovering rows, so the fence also applies to an artifact-free Grid workspace. Once a
  request passes the final provider-send fence and is dispatched, later offboarding cannot recall it.
- **Disconnect and shared-channel changes fence older setup authority.** Ordinary credential
  deletion commits an exact provider/owner provisioning marker before removal; a failed bounded-row
  cleanup therefore cannot let an already-exposed key form or OAuth callback recreate access after
  Disconnect reports completion. For shared credentials, every effective credential, mode, or tool
  mutation advances a channel/provider tombstone atomically with dependent-state cleanup. Setup
  received before that marker cannot hydrate or commit afterward, including when Slack modal or
  admin checks delayed request persistence. Same-value governance retries leave current forms valid.
- **Confirmed break-glass revoke is a scoped provisioning fence.** `vouchr revoke --yes` commits a
  provider+scope marker before it enumerates pending or live state. Older matching user and shared
  channel writes cannot land after the command reports no local access; outstanding opaque channel
  setup requests are counted and purged with their channel/team/global scope. A fresh setup begun
  after the marker remains possible. `--user` and `--channel` are distinct owner scopes, dry-run
  writes no marker, and raw scope ids are represented durably only by fixed server-derived hashes.
- **Deployment-wide compromise has its own break-glass.** Distinguish two incidents. A **read-only
  PostgreSQL dump with the KMS/master key uncompromised** exposes owner/provider/scope/timestamp
  metadata but not token plaintext — contain the database incident and check KMS access logs; global
  revocation is a risk decision, not automatically required. A **database dump *plus* a decryption
  path** (leaked master key, compromised KMS/workload role, or a compromised live replica) must be
  treated as full credential exposure. For that case, `vouchr revoke --all --confirm ALL-CREDENTIALS`
  locally deletes every stored credential, external reference, pending consent, session grant/request,
  action approval, notification-state row, and Slack installation, then attempts best-effort upstream
  revocation per provider and reports real attempted counts separately from success/failure. A
  refresh-capable revocable provider must declare whether invalidation targets the access token,
  refresh token, both, or the whole grant; Vouchr does not infer that contract. Local deletion is
  guaranteed even with the master key or provider config unavailable; it is dry-run by default and
  requires the exact confirmation token to execute. **Local deletion is not upstream revocation.** A token an attacker
  already copied stays valid at the provider until it expires or is rotated; providers without a
  revoke endpoint, undecryptable tokens, and external references require manual rotation; invalidated
  Slack installations require each workspace to reinstall the app. Rotate master keys, OAuth client
  secrets, Slack credentials, database and resolver roles per the incident scope, and require users to
  reconnect, before serving traffic again. Remove a compromised direct key from every active keyring
  and revoke/disable the old KMS grant or key for serving workloads; merely adding a new primary still
  decrypts old rows. A pre-incident backup may be restored only into an isolated locked-down deployment
  for an explicit global invalidation before ingress returns. The command exits non-zero while any
  local credential/authorization row remains.
- **Containment must come from outside the credential database.** Set `VOUCHR_LOCKDOWN=1` on the
  deployment (never a flag inside the potentially-compromised database) to fail closed: readiness
  reports 503 (so an orchestrator pulls the replica from rotation) and credential serving, refresh,
  OAuth-callback writes, resolver access, and credential/reference setup are all denied *before* any
  secret is read, on every replica configured with it. Break-glass deletion and metadata reads stay
  available so `vouchr revoke` still works during lockdown. This is defense-in-depth on top of, not a
  replacement for, infrastructure containment (removing ingress/egress and quarantining replicas when
  the running workload itself may be compromised).
- **Audit metadata is caller-supplied.** Vouchr's own code keeps secrets out of `audit.meta`
  (and tests enforce it), but a custom provider/`accountProbe` or caller could put sensitive data
  in metadata. Don't.
- **Audit completeness is best-effort, not guaranteed.** Audit writes on the injection path are
  swallowed on failure so a bookkeeping error can't fail or roll back a provider call that already
  executed; wire an `EventSink` (the `injected` event is a redundant independent signal) into a
  durable operator-owned pipeline. The callback itself is fire-and-forget and can be lost, so it is
  not the durable backstop by itself. See the
  [threat model](./guides/THREAT-MODEL.md#audit-completeness-is-best-effort-by-design).
- **The Postgres database is not wholly encrypted at rest.** Credential-bearing columns are
  encrypted; the rest of the row and the database are not. Use disk/database encryption and access
  control at the infra layer (envelope encryption via an `EnvelopeProvider` raises the bar on Vault
  connection tokens; multi-workspace installation tokens remain direct-master encrypted until #241).

## Operator responsibilities

Vouchr is self-hosted; some of the security posture is yours to own:

- Set a strong `VOUCHR_MASTER_KEY` (32 random bytes) and store it in a secret manager, not
  in source control.
- Scope the IAM/role used by any external-secret resolver to least privilege (read-only on the
  specific secrets it resolves).
- Keep the PostgreSQL credential store encrypted at rest and access-controlled
  at the infrastructure layer.
- Understand the admin gate's trust boundary: channel-credential configuration is gated on
  Slack **workspace** admin/owner status (`users.info` `is_admin`/`is_owner`), which is
  workspace-wide, not channel-membership-scoped. By design, a workspace admin can configure a
  shared credential for a channel they are not a member of.
