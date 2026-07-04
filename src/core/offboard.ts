import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { ProviderRegistry } from './providers';
import { revokeToken } from './tokens';
import { userOwner } from './owner';
import { SessionGrants } from './session';

/**
 * Disconnect ONE provider for a user: delete the local credential (the security-meaningful action)
 * FIRST, then best-effort upstream token revocation. A revoke failure is non-fatal — local access is
 * already gone. Audited as 'revoke' (never the token). Transport-agnostic, so the Bolt `/vouchr
 * disconnect` command and the headless broker's `/v1/disconnect` route share ONE implementation.
 * Returns whether a credential existed and whether the upstream revoke succeeded.
 */
export async function disconnectProvider(
  vault: Vault,
  audit: Audit,
  registry: ProviderRegistry | undefined,
  identity: SlackIdentity,
  provider: string,
): Promise<{ removed: boolean; ok: boolean }> {
  const owner = userOwner(identity);
  // Read the token BEFORE deleting: needed both to detect existence and to hand to the upstream revoke.
  const cred = await vault.get(owner, provider);
  await vault.delete(owner, provider); // local delete FIRST
  let ok = true;
  if (registry?.has(provider)) {
    try {
      if (cred?.accessToken) await revokeToken(registry.get(provider), cred.accessToken);
    } catch {
      ok = false; // network/HTTP failure: local access is already gone; nothing is faked
    }
  }
  await audit.record('revoke', identity, provider, { ok }); // never the token
  return { removed: cred != null, ok };
}

/**
 * Remove ALL of a user's own connections: the offboarding cleanup. Triggered
 * automatically when Slack deactivates the account (see the Bolt adapter's
 * registerOffboarding), and callable from a SCIM deprovision hook or an admin.
 *
 * Also purges any in-flight consent AND any thread session grants for the user, so neither a
 * pending "Connect" click nor a lingering thread grant can resurrect access after offboarding.
 *
 * Only the user's own connections are removed. Channel/shared connections belong
 * to the channel, not the person, so they are intentionally left in place and
 * reviewed separately by an admin. Idempotent. Returns the providers removed.
 */
export async function offboardUser(
  vault: Vault,
  audit: Audit,
  consent: Consent,
  identity: SlackIdentity,
  // Optional: when supplied, also revoke each token upstream (best-effort). Omitted callers
  // keep the prior local-only behavior.
  registry?: ProviderRegistry,
  reason = 'offboarded',
  // Optional: when supplied, also clear the user's thread session grants. Centralized here so
  // every offboarding path (per-team and the Grid/SCIM sweep) gets the same cleanup.
  sessions?: SessionGrants,
): Promise<string[]> {
  await consent.deleteForUser(identity); // kill pending OAuth so it can't resurrect a connection
  await sessions?.revokeForUser(identity); // thread grants must not outlive the user
  const owner = userOwner(identity);
  const providers = (await vault.listForUser(identity)).map((c) => c.provider); // user-owned only
  for (const provider of providers) {
    // Read the token BEFORE deleting so we can hand it to the upstream revoke.
    const cred = registry?.has(provider) ? await vault.get(owner, provider) : null;
    await vault.delete(owner, provider); // local delete FIRST (the security-meaningful action)
    // Best-effort upstream revocation: swallow per-connection errors so offboarding always completes.
    const meta: Record<string, unknown> = { reason };
    if (registry) {
      let ok = true;
      try {
        if (cred?.accessToken) await revokeToken(registry.get(provider), cred.accessToken);
      } catch {
        ok = false; // network/HTTP failure: local access is already gone; nothing is faked
      }
      meta.ok = ok; // never the token, just whether the upstream call succeeded
    }
    await audit.record('revoke', identity, provider, meta);
  }
  return providers;
}

/**
 * Enterprise Grid / SCIM offboarding: remove a user across EVERY workspace, not just one.
 *
 * The Vault API is team-scoped (the full owner key is team_id + kind + id), so "everywhere" can
 * only mean "every team this user touches". We discover those teams honestly at the DB level:
 * the distinct team_ids where the user has an own connection, an in-flight consent, OR a thread
 * session grant, then replay {@link offboardUser} once per team. That keeps the upstream-revoke +
 * audit + consent-purge + session-purge logic in exactly one place and each per-team call still
 * uses the FULL owner key
 * (team_id + 'user' + userId), so the cross-team sweep can never reach beyond this user's own rows.
 *
 * In Enterprise Grid the Slack userId is unique org-wide, so `userId` alone is a complete span key.
 * `enterpriseId`, when passed, further narrows connection/consent discovery to that org's rows.
 * Prefer userId-only: Vault.upsert persists `enterprise_id` only when the owner carries one
 * (`owner.enterpriseId ?? null`), so rows written outside Grid store NULL — passing enterpriseId
 * adds an `enterprise_id=?` predicate that under-matches those NULL rows. userId-only spans them all.
 *
 * Best-effort and non-fatal per team: one workspace's DB/revoke failure never blocks the others.
 * Returns what was removed per team. Never logs or returns secrets.
 */
export async function offboardUserEverywhere(
  db: Db,
  vault: Vault,
  audit: Audit,
  consent: Consent,
  user: { enterpriseId?: string | null; userId: string },
  registry?: ProviderRegistry,
  reason = 'offboarded',
): Promise<{ teamId: string; providers: string[] }[]> {
  const ent = user.enterpriseId != null;
  const sessions = new SessionGrants(db);
  // The ONLY query that spans teams. UNION so a team with only a pending "Connect" or only a
  // lingering thread session grant (no live connection) is still found and purged. session_grant
  // has no enterprise_id column, so it is always matched by user_id alone (userId is org-unique).
  const rows = (await db.all(
    `SELECT team_id FROM connection WHERE owner_kind='user' AND owner_id=?${ent ? ' AND enterprise_id=?' : ''}
     UNION
     SELECT team_id FROM consent_request WHERE user_id=?${ent ? ' AND enterprise_id=?' : ''}
     UNION
     SELECT team_id FROM session_grant WHERE user_id=?`,
    ent
      ? [user.userId, user.enterpriseId, user.userId, user.enterpriseId, user.userId]
      : [user.userId, user.userId, user.userId],
  )) as { team_id: string }[];

  const summary: { teamId: string; providers: string[] }[] = [];
  for (const { team_id: teamId } of rows) {
    // Full owner key per team, never a partial key. offboardUser does the local delete first, then
    // best-effort upstream revoke + audit, and purges this team's pending consent + session grants.
    const identity: SlackIdentity = { enterpriseId: user.enterpriseId ?? null, teamId, userId: user.userId };
    try {
      summary.push({ teamId, providers: await offboardUser(vault, audit, consent, identity, registry, reason, sessions) });
    } catch {
      // Non-fatal per team; local deletes were already attempted inside offboardUser. Record the
      // team with no providers rather than aborting the whole sweep. Never surface the error (it
      // could carry connection detail). Secrets stay out of logs/returns.
      summary.push({ teamId, providers: [] });
    }
  }
  return summary;
}
