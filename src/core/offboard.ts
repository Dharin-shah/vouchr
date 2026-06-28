import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { ProviderRegistry } from './providers';
import { revokeToken } from './tokens';
import { userOwner } from './owner';

/**
 * Remove ALL of a user's own connections — the offboarding cleanup. Triggered
 * automatically when Slack deactivates the account (see the Bolt adapter's
 * registerOffboarding), and callable from a SCIM deprovision hook or an admin.
 *
 * Also purges any in-flight consent for the user, so a pending "Connect" click
 * can't complete after offboarding and resurrect a live connection.
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
): Promise<string[]> {
  await consent.deleteForUser(identity); // kill pending OAuth so it can't resurrect a connection
  const owner = userOwner(identity);
  const providers = (await vault.listForUser(identity)).map((c) => c.provider); // user-owned only
  for (const provider of providers) {
    // Read the token BEFORE deleting so we can hand it to the upstream revoke.
    const cred = registry?.has(provider) ? await vault.get(owner, provider) : null;
    await vault.delete(owner, provider); // local delete FIRST — the security-meaningful action
    // Best-effort upstream revocation: swallow per-connection errors so offboarding always completes.
    const meta: Record<string, unknown> = { reason };
    if (registry) {
      let ok = true;
      try {
        if (cred?.accessToken) await revokeToken(registry.get(provider), cred.accessToken);
      } catch {
        ok = false; // network/HTTP failure — local access is already gone; nothing is faked
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
 * only mean "every team this user touches". We discover those teams honestly at the DB level —
 * the distinct team_ids where the user has either an own connection OR an in-flight consent — then
 * replay {@link offboardUser} once per team. That keeps the upstream-revoke + audit + consent-purge
 * logic in exactly one place and, crucially, each per-team call still uses the FULL owner key
 * (team_id + 'user' + userId), so the cross-team sweep can never reach beyond this user's own rows.
 *
 * In Enterprise Grid the Slack userId is unique org-wide, so `userId` alone is a complete span key;
 * `enterpriseId`, when given, additionally narrows discovery to that org's rows. (Caveat: vault
 * writes currently persist connection.enterprise_id as NULL — see Vault.upsert — so passing
 * enterpriseId under-matches *connections* today; consent rows do store it. Prefer userId-only.)
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
  // The ONLY query that spans teams. UNION so a team with a pending "Connect" but no live
  // connection is still found and purged (otherwise that consent could resurrect a connection).
  const rows = (await db.all(
    `SELECT team_id FROM connection WHERE owner_kind='user' AND owner_id=?${ent ? ' AND enterprise_id=?' : ''}
     UNION
     SELECT team_id FROM consent_request WHERE user_id=?${ent ? ' AND enterprise_id=?' : ''}`,
    ent
      ? [user.userId, user.enterpriseId, user.userId, user.enterpriseId]
      : [user.userId, user.userId],
  )) as { team_id: string }[];

  const summary: { teamId: string; providers: string[] }[] = [];
  for (const { team_id: teamId } of rows) {
    // Full owner key per team — never a partial key. offboardUser does the local delete first, then
    // best-effort upstream revoke + audit, and purges this team's pending consent.
    const identity: SlackIdentity = { enterpriseId: user.enterpriseId ?? null, teamId, userId: user.userId };
    try {
      summary.push({ teamId, providers: await offboardUser(vault, audit, consent, identity, registry, reason) });
    } catch {
      // Non-fatal per team; local deletes were already attempted inside offboardUser. Record the
      // team with no providers rather than aborting the whole sweep. Never surface the error (it
      // could carry connection detail) — secrets stay out of logs/returns.
      summary.push({ teamId, providers: [] });
    }
  }
  return summary;
}
