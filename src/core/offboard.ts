import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { ProviderRegistry } from './providers';
import { revokeToken } from './tokens';
import { userOwner, type Owner } from './owner';
import { SessionGrants } from './session';
import { UnionOptin } from './unionOptin';

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
  // Optional (#112): also drop the user's union opt-ins for this provider, so a later reconnect
  // (e.g. from a DM) can't silently resurrect delegation they walked away from.
  unionOptin?: UnionOptin,
): Promise<{ removed: boolean; ok: boolean }> {
  const owner = userOwner(identity);
  // Read the token BEFORE deleting: needed both to detect existence and to hand to the upstream revoke.
  const cred = await vault.get(owner, provider);
  await vault.delete(owner, provider); // local delete FIRST
  await unionOptin?.deleteForUserProvider(identity.teamId, identity.userId, provider);
  let ok = true;
  if (registry?.has(provider)) {
    try {
      // #116: a dry-run credential is synthetic — an upstream revoke would be a REAL network call
      // POSTing it to the provider. Keyed off the trusted dry_run column (no flag here), so the CLI
      // is covered too, and a REAL account labelled "dry-run" still revokes normally.
      if (cred?.accessToken && !cred.dryRun) {
        await revokeToken(registry.get(provider), cred.accessToken);
      }
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
  // Optional (#112): when supplied, also delete the user's union opt-ins — an offboarded user's
  // credentials are gone, so their delegation rows must not linger.
  unionOptin?: UnionOptin,
): Promise<string[]> {
  await consent.deleteForUser(identity); // kill pending OAuth so it can't resurrect a connection
  await sessions?.revokeForUser(identity); // thread grants must not outlive the user
  await unionOptin?.deleteForUser(identity); // union delegation must not outlive the user either
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
        // #116: never POST a synthetic (dry-run) token to a real revoke endpoint. Keyed off the
        // trusted dry_run column, so a REAL "dry-run"-labelled account still revokes normally.
        if (cred?.accessToken && !cred.dryRun) {
          await revokeToken(registry.get(provider), cred.accessToken);
        }
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
  /** #116 trusted synthetic-provenance marker; a dry-run row's upstream revoke is skipped. */
  dryRun: boolean;
  createdAt: number;
}

/** {@link RevokeRow} plus the per-row outcome. `removed` is the security-meaningful local delete.
 *  `upstreamAttempted` is true only when a real upstream revoke call was actually made (the provider
 *  has a revoke endpoint AND a token was decryptable); when false the upstream revoke was SKIPPED, not
 *  succeeded — don't report a skip as a success. `upstreamOk` is meaningful only when attempted. */
export interface RevokeOutcome extends RevokeRow {
  removed: boolean;
  upstreamAttempted: boolean;
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
    `SELECT team_id, owner_kind, owner_id, external_account, dry_run, created_at
     FROM connection WHERE ${where.join(' AND ')} ORDER BY team_id, owner_kind, owner_id`,
    params,
  )) as any[];
  return rows.map((r) => ({
    teamId: r.team_id, ownerKind: r.owner_kind, ownerId: r.owner_id,
    externalAccount: r.external_account, dryRun: r.dry_run === 1, createdAt: r.created_at,
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
 * Runs regardless of whether any live connection matched (that's the whole point). Also drops union
 * opt-ins (#112) in scope whose owner has NO remaining connection for the provider — stale delegation
 * must not survive the sweep and resurrect on a later reconnect (opt-ins backed by a live connection
 * outside the revocation scope are kept). Returns the consent/grant counts.
 */
export async function purgePendingForProvider(db: Db, f: RevokeFilter): Promise<{ consents: number; grants: number }> {
  const { where, params } = pendingWhere(f);
  const consents = (await db.run(`DELETE FROM consent_request WHERE ${where}`, params)).changes;
  const grants = (await db.run(`DELETE FROM session_grant WHERE ${where}`, params)).changes;
  // union_optin's channel column is channel_id, so it can't share pendingWhere verbatim.
  const uw = ['provider=?'];
  const up: unknown[] = [f.provider];
  if (f.teamId) { uw.push('team_id=?'); up.push(f.teamId); }
  if (f.userId) { uw.push('user_id=?'); up.push(f.userId); }
  if (f.channel) { uw.push('channel_id=?'); up.push(f.channel); }
  await db.run(
    `DELETE FROM union_optin WHERE ${uw.join(' AND ')} AND NOT EXISTS (
       SELECT 1 FROM connection WHERE owner_kind='user' AND owner_id=union_optin.user_id
         AND team_id=union_optin.team_id AND provider=union_optin.provider)`,
    up,
  );
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
  // Optional (#112): user rows also drop that user's union opt-ins for the provider (same
  // resurrection reasoning as disconnectProvider). Channel owners have no opt-ins.
  unionOptin?: UnionOptin,
): Promise<RevokeOutcome> {
  const owner: Owner = { teamId: row.teamId, kind: row.ownerKind, id: row.ownerId, enterpriseId: null };
  // Read the token for the upstream revoke, but a decrypt failure must NEVER block the local delete.
  let token: string | null = null;
  try { token = (await vault.get(owner, provider))?.accessToken ?? null; } catch { /* still delete locally */ }
  let removed = true;
  try { await vault.delete(owner, provider); } catch { removed = false; } // local delete FIRST
  // Upstream revoke is ATTEMPTED only when the provider actually has a revoke endpoint and we hold a
  // token — otherwise it's a no-op that must be reported as SKIPPED, never as a success. A dry-run
  // row (#116) is always SKIPPED: its token is synthetic and must never be POSTed to a real endpoint.
  let upstreamAttempted = false;
  let upstreamOk = true;
  if (registry?.has(provider) && token && !row.dryRun) {
    const p = registry.get(provider);
    if (p.revoke || p.revokeUrl) {
      upstreamAttempted = true;
      try { await revokeToken(p, token); } catch { upstreamOk = false; }
    }
  }
  // Attribute the audit row to the OWNER (team + owner id); a channel row has no Slack user actor.
  // Everything after the local delete is BEST-EFFORT and wrapped so one row's audit/consent/session
  // failure (e.g. a transient DB error) can never throw out of the bulk-revoke loop and strand the
  // remaining rows. The security-meaningful delete already happened above.
  const actor: SlackIdentity = { enterpriseId: null, teamId: row.teamId, userId: row.ownerId };
  const meta: Record<string, unknown> = { owner: row.ownerKind, reason: 'break-glass' };
  if (upstreamAttempted) meta.ok = upstreamOk; else meta.upstream = 'skipped';
  try { await audit.record('revoke', actor, provider, meta); } catch { /* best-effort */ }
  if (row.ownerKind === 'user') {
    try { await consent.deleteForUserProvider(row.teamId, row.ownerId, provider); } catch { /* best-effort */ }
    try { await sessions.clearForProvider(row.teamId, row.ownerId, provider); } catch { /* best-effort */ }
    try { await unionOptin?.deleteForUserProvider(row.teamId, row.ownerId, provider); } catch { /* best-effort */ }
  }
  return { ...row, removed, upstreamAttempted, upstreamOk };
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
  const unionOptin = new UnionOptin(db); // #112: opt-ins are purged per team alongside sessions
  // The ONLY query that spans teams. UNION so a team with only a pending "Connect", only a lingering
  // thread session grant, or only a union opt-in (#112 — no live connection) is still found and
  // purged. session_grant and union_optin have no enterprise_id column, so they are always matched by
  // user_id alone (userId is org-unique).
  const rows = (await db.all(
    `SELECT team_id FROM connection WHERE owner_kind='user' AND owner_id=?${ent ? ' AND enterprise_id=?' : ''}
     UNION
     SELECT team_id FROM consent_request WHERE user_id=?${ent ? ' AND enterprise_id=?' : ''}
     UNION
     SELECT team_id FROM session_grant WHERE user_id=?
     UNION
     SELECT team_id FROM union_optin WHERE user_id=?`,
    ent
      ? [user.userId, user.enterpriseId, user.userId, user.enterpriseId, user.userId, user.userId]
      : [user.userId, user.userId, user.userId, user.userId],
  )) as { team_id: string }[];

  const summary: { teamId: string; providers: string[] }[] = [];
  for (const { team_id: teamId } of rows) {
    // Full owner key per team, never a partial key. offboardUser does the local delete first, then
    // best-effort upstream revoke + audit, and purges this team's pending consent + session grants.
    const identity: SlackIdentity = { enterpriseId: user.enterpriseId ?? null, teamId, userId: user.userId };
    try {
      summary.push({ teamId, providers: await offboardUser(vault, audit, consent, identity, registry, reason, sessions, unionOptin) });
    } catch {
      // Non-fatal per team; local deletes were already attempted inside offboardUser. Record the
      // team with no providers rather than aborting the whole sweep. Never surface the error (it
      // could carry connection detail). Secrets stay out of logs/returns.
      summary.push({ teamId, providers: [] });
    }
  }
  return summary;
}
