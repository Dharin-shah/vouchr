import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { ProviderRegistry } from './providers';
import { revokeToken } from './tokens';
import { userOwner, type Owner } from './owner';
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

/** Break-glass bulk revocation filter. `provider` is REQUIRED (revoking across every provider is too
 *  blunt); team/user/channel narrow the blast radius and compose (provider+team, provider+user, …). */
export interface RevokeFilter {
  provider: string;
  teamId?: string;
  userId?: string;
  channel?: string;
}

/** One matched connection row — METADATA ONLY, never a secret. Feeds both the dry-run table and the
 *  execution loop. */
export interface RevokeRow {
  teamId: string;
  ownerKind: 'user' | 'channel';
  ownerId: string;
  externalAccount: string | null;
  createdAt: number;
}

/** {@link RevokeRow} plus the per-row outcome. `removed` is the security-meaningful local delete;
 *  `upstreamOk` is the best-effort provider revoke (a no-revoke provider stays true). */
export interface RevokeOutcome extends RevokeRow {
  removed: boolean;
  upstreamOk: boolean;
}

/**
 * Rows a {@link RevokeFilter} matches, metadata only (no ciphertext columns selected). The dry-run
 * prints these and exits; the execution loop iterates them. Reuses the same `connection` predicate
 * shape as the CLI `inventory` query, extended with owner-kind-aware --user/--channel filters.
 */
export async function selectRevocations(db: Db, f: RevokeFilter): Promise<RevokeRow[]> {
  const where = ['provider=?'];
  const params: unknown[] = [f.provider];
  if (f.teamId) { where.push('team_id=?'); params.push(f.teamId); }
  // --user/--channel select a specific owner; user and channel ids can collide, so scope by kind too.
  if (f.userId) { where.push("owner_kind='user' AND owner_id=?"); params.push(f.userId); }
  if (f.channel) { where.push("owner_kind='channel' AND owner_id=?"); params.push(f.channel); }
  const rows = (await db.all(
    `SELECT team_id, owner_kind, owner_id, external_account, created_at
     FROM connection WHERE ${where.join(' AND ')} ORDER BY team_id, owner_kind, owner_id`,
    params,
  )) as any[];
  return rows.map((r) => ({
    teamId: r.team_id, ownerKind: r.owner_kind, ownerId: r.owner_id,
    externalAccount: r.external_account, createdAt: r.created_at,
  }));
}

/** Scoped predicate for pending consent / session grants — `provider` plus whichever of team/user/
 *  channel the filter narrows to. Both `consent_request` and `session_grant` carry these columns. */
function pendingWhere(f: RevokeFilter): { where: string; params: unknown[] } {
  const where = ['provider=?'];
  const params: unknown[] = [f.provider];
  if (f.teamId) { where.push('team_id=?'); params.push(f.teamId); }
  if (f.userId) { where.push('user_id=?'); params.push(f.userId); }
  if (f.channel) { where.push('channel=?'); params.push(f.channel); }
  return { where: where.join(' AND '), params };
}

/**
 * Pending OAuth consents + thread session grants a {@link RevokeFilter} matches — counted, NOT deleted
 * (for the dry-run). These exist INDEPENDENTLY of a live connection row: a `/vouchr connect` click that
 * never completed, or a thread grant that outlived its connection, both match the provider but not
 * `selectRevocations`, so break-glass must report + clear them separately or they resurrect access.
 */
export async function countPendingForProvider(db: Db, f: RevokeFilter): Promise<{ consents: number; grants: number }> {
  const { where, params } = pendingWhere(f);
  const c = (await db.get(`SELECT COUNT(*) AS n FROM consent_request WHERE ${where}`, params)) as { n: number } | undefined;
  const s = (await db.get(`SELECT COUNT(*) AS n FROM session_grant WHERE ${where}`, params)) as { n: number } | undefined;
  return { consents: c?.n ?? 0, grants: s?.n ?? 0 };
}

/**
 * Delete every pending consent + thread session grant matching the scope, so a pending "Connect" or a
 * lingering thread grant can't complete after the break-glass run and resurrect the revoked provider.
 * Runs regardless of whether any live connection matched (that's the whole point). Returns the counts.
 */
export async function purgePendingForProvider(db: Db, f: RevokeFilter): Promise<{ consents: number; grants: number }> {
  const { where, params } = pendingWhere(f);
  const consents = (await db.run(`DELETE FROM consent_request WHERE ${where}`, params)).changes;
  const grants = (await db.run(`DELETE FROM session_grant WHERE ${where}`, params)).changes;
  return { consents, grants };
}

/**
 * Revoke ONE already-selected connection row: local delete FIRST (the security-meaningful action,
 * done even if the token can't be decrypted — e.g. a KMS row with no KMS client wired into the CLI),
 * then best-effort upstream revoke, then audit ('revoke', no token) and — for a USER owner — clear
 * that user's pending consent + thread session grants for the provider so neither can resurrect the
 * credential. Mirrors {@link disconnectProvider}'s order but handles BOTH user- and channel-owned rows
 * and never throws on a decrypt/upstream failure. Channel owners have no user-scoped consent/grants.
 */
export async function revokeConnection(
  vault: Vault,
  audit: Audit,
  consent: Consent,
  sessions: SessionGrants,
  registry: ProviderRegistry | undefined,
  row: RevokeRow,
  provider: string,
): Promise<RevokeOutcome> {
  const owner: Owner = { teamId: row.teamId, kind: row.ownerKind, id: row.ownerId, enterpriseId: null };
  // Read the token for the upstream revoke, but a decrypt failure must NEVER block the local delete.
  let token: string | null = null;
  try { token = (await vault.get(owner, provider))?.accessToken ?? null; } catch { /* still delete locally */ }
  let removed = true;
  try { await vault.delete(owner, provider); } catch { removed = false; } // local delete FIRST
  let upstreamOk = true;
  if (registry?.has(provider) && token) {
    try { await revokeToken(registry.get(provider), token); } catch { upstreamOk = false; }
  }
  // Attribute the audit row to the OWNER (team + owner id); a channel row has no Slack user actor.
  const actor: SlackIdentity = { enterpriseId: null, teamId: row.teamId, userId: row.ownerId };
  await audit.record('revoke', actor, provider, { ok: upstreamOk, owner: row.ownerKind, reason: 'break-glass' });
  if (row.ownerKind === 'user') {
    await consent.deleteForUserProvider(row.teamId, row.ownerId, provider);
    await sessions.clearForProvider(row.teamId, row.ownerId, provider);
  }
  return { ...row, removed, upstreamOk };
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
