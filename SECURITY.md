# Security Policy

Vouchr is a credential broker. Security reports are taken seriously and prioritized.

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
- **Raw keys typed into a Slack modal pass through Slack.** The value is in the modal submission
  payload. Vouchr never echoes, logs, or stores it unsafely, but an external secret reference (an
  ARN resolved just in time) avoids putting the secret in Slack at all. Prefer it.
- **Disconnect/offboard revoke is best-effort.** Removing a connection deletes Vouchr's stored
  credential first; Vouchr then attempts upstream provider revocation when the provider declares a
  revoke path. A network/provider failure cannot keep local access alive, but upstream revocation is
  not guaranteed.
- **Audit metadata is caller-supplied.** Vouchr's own code keeps secrets out of `audit.meta`
  (and tests enforce it), but a custom provider/`accountProbe` or caller could put sensitive data
  in metadata. Don't.
- **The SQLite file is not wholly encrypted at rest.** Token columns are encrypted; the rest of the
  row and the file are not. Use disk/database encryption and access control at the infra layer
  (envelope encryption via an `EnvelopeProvider` raises the bar on the token columns).

## Operator responsibilities

Vouchr is self-hosted; some of the security posture is yours to own:

- Set a strong `VOUCHR_MASTER_KEY` (32 random bytes) and store it in a secret manager, not
  in source control.
- Scope the IAM/role used by any external-secret resolver to least privilege (read-only on the
  specific secrets it resolves).
- Keep the credential store (SQLite file or Postgres) encrypted at rest and access-controlled
  at the infrastructure layer.
- Understand the admin gate's trust boundary: channel-credential configuration is gated on
  Slack **workspace** admin/owner status (`users.info` `is_admin`/`is_owner`), which is
  workspace-wide, not channel-membership-scoped. By design, a workspace admin can configure a
  shared credential for a channel they are not a member of.
