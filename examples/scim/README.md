# SCIM / admin-API offboarding (Enterprise Grid)

Reference for revoking a user's connections across **every** workspace when they're
deprovisioned org-wide, the cross-team counterpart to the Slack app's per-team
`registerOffboarding()` (which only fires on `user_change` for a single team).

## Why this is separate from the Slack app

- **Connect / consent stays in the Slack app.** Minting credentials is interactive and
  per-workspace (the in-Slack Connect button → OAuth). This endpoint only removes;
  it never mints.
- **Deprovisioning is org-wide and not driven by Slack.** Your IdP (Okta, Entra ID, …)
  or your own admin tooling owns the SCIM lifecycle. When it deactivates a user it calls
  *you*; Slack doesn't. A single Grid user spans many workspaces, so a one-team offboard
  leaves live connections behind in the others.

`offboardUserEverywhere` closes that gap: given `{ enterpriseId?, userId }` it first records a
durable enterprise/global scope tombstone, then finds every team where the user has a connection or
pending consent/session/setup/approval artifact and replays the normal per-team offboard (local delete →
best-effort upstream revoke → audit → bounded-state cleanup), using the full owner key per team so it
never touches another user's rows. Shared channel credentials remain for other current actors, while
the departed user's older handles, assertions, and requested approvals remain tombstone-fenced. The
scope tombstone also fences an artifact-free workspace. It is
best-effort and non-fatal per workspace and returns a `{ teamId, providers[], ok }[]` summary; callers
must treat any `ok: false` as incomplete and retry. No secrets are logged or returned.

## Integration

1. **Point at the same store + master key as the Slack app.** The webhook service reads
   the connections the app wrote: `VOUCHR_DATABASE_URL` (Postgres, so this can run
   standalone) and `VOUCHR_MASTER_KEY` must match the app's.
2. **Authenticate the caller** before acting (shared secret / mTLS / signed IdP request).
   This endpoint deletes credentials; treat it as privileged.
3. **Map your event to `{ enterpriseId?, userId }`** and call `onDeprovision` (see
   `handler.ts`). Pass the authenticated `enterpriseId` whenever the directory event supplies it;
   that writes an enterprise-scoped fence. Omit it only when the integration intentionally means a
   global deprovision across every enterprise that may contain the same Slack user id.

```ts
import { onDeprovision } from './handler';

// from your SCIM webhook or admin API, after authenticating the caller:
await onDeprovision({ enterpriseId: 'E0123', userId: 'U0456' });
```

## Env

| Var | Purpose |
|-----|---------|
| `VOUCHR_DATABASE_URL` | Postgres URL, the **same** store the Slack app writes to |
| `VOUCHR_MASTER_KEY`   | base64 32-byte key, the **same** key the app uses |

## Scope note

When `enterpriseId` is supplied, discovery includes both exact-org rows and legacy/unscoped rows
whose `enterprise_id` is `NULL`; this avoids stranding a credential written before org metadata was
available. Omitting it intentionally creates a global user-id fence, so use that only when your
authenticated directory subject is known to be global.
