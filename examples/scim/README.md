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

`offboardUserEverywhere` closes that gap: given `{ enterpriseId?, userId }` it finds every
team where the user has a connection **or** a pending consent, and replays the normal
per-team offboard (local delete → best-effort upstream revoke → audit → purge pending
consent) against each, using the full owner key per team so it never touches another user's
rows. It's best-effort and non-fatal per workspace and returns a `{ teamId, providers[] }[]`
summary. No secrets are logged or returned.

## Integration

1. **Point at the same store + master key as the Slack app.** The webhook service reads
   the connections the app wrote: `VOUCHR_DATABASE_URL` (Postgres, so this can run
   standalone) and `VOUCHR_MASTER_KEY` must match the app's.
2. **Authenticate the caller** before acting (shared secret / mTLS / signed IdP request).
   This endpoint deletes credentials; treat it as privileged.
3. **Map your event to `{ enterpriseId?, userId }`** and call `onDeprovision` (see
   `handler.ts`). Prefer passing `userId` only. The Slack userId is unique org-wide, so
   it's a complete span key. `enterpriseId` is an optional narrowing filter.

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

## Caveat

Vault currently persists `connection.enterprise_id` as `NULL` (see `Vault.upsert`), so
passing `enterpriseId` under-matches *connections* today (consent rows do store it). Until
those writes populate it, span by `userId` alone.
