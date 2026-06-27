# Security Policy

Vouchr is a credential broker — security reports are taken seriously and prioritized.

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

- **Secret leakage** — any path where a credential reaches logs, Slack messages, the audit
  table, error strings, an LLM/tool schema, or a resolved external-reference secret being
  persisted or cached.
- **Tenant / owner isolation** — any query or code path that lets one `(team, owner_kind,
  owner_id, provider)` read or overwrite another's credential.
- **Authorization** — bypassing the admin gate on channel-credential configuration, or using
  a channel credential without proven authorization for that channel.
- **OAuth flow** — `state` reuse/fixation, PKCE downgrade, or open-redirect / egress-allowlist
  bypass at the injection boundary.

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
