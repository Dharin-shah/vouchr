import { credentialLockKey, type Vault } from './vault';
import type { Audit } from './audit';
import {
  markProvisioningRevoked,
  markUserOffboardedEverywhere,
  Consent,
} from './consent';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import { isValidProviderId, type ProviderRegistry } from './providers';
import { revokeProviderCredential } from './tokens';
import { channelOwner, userOwner, type Owner } from './owner';
import { SessionGrants } from './session';
import { ChannelProvisioningRequests, UserProvisioningRequests } from './provisioning';
import { Approvals } from './approval';
import { InteractionStateChangedError, isInteractionId } from './interaction';

type DisconnectOutcome = {
  recognized: boolean;
  removed: boolean;
  ok: boolean;
  audited: boolean;
};

/**
 * The ONE local-delete/claim → decode → upstream-revoke sequence for a user-owned credential, shared by
 * {@link disconnectProvider} and {@link offboardUser} (STR-3). Hardened per GHSA-25m2 so the local
 * delete — the security-meaningful action — always runs:
 *  - DELETE ... RETURNING atomically claims the row, so only the delete winner can revoke upstream;
 *  - decoding is TTL-independent (a row expired here may still be live upstream) and happens after
 *    the delete, so a decrypt/KMS failure only skips the upstream revoke;
 *  - `removed` comes from the committed delete claim, not from whether the token was readable.
 */
async function removeUserConnection(
  vault: Vault,
  registry: ProviderRegistry | undefined,
  identity: SlackIdentity,
  provider: string,
  prepared?: {
    expectedId: string;
    fenced: boolean;
    identity: SlackIdentity;
    issuedAt: number;
  },
): Promise<{ removed: boolean; ok: boolean; attempted: boolean; fenced: boolean }> {
  const owner = userOwner(identity);
  const current = registry?.has(provider) ? registry.get(provider) : null;
  const registered = current != null;
  // The atomic delete returns token material only to its winner. Stale/unregistered rows are never
  // decrypted; their trusted dry_run bit is enough to distinguish synthetic state from real debt.
  const claimed = await vault.deleteForRevoke(owner, provider, registered, prepared);
  const removed = claimed.removed;
  // `ok` = "no upstream revocation debt was left behind"; `attempted` = a real revoke call was made.
  // A revocation that was DUE (revocable provider, row existed) but couldn't run because the token
  // was unreadable is ok:false — the upstream token may still be live, and reporting ok:true for a
  // revoke that never happened would be a lie (GHSA-25m2 review r3).
  let ok = !removed || registered || claimed.dryRun;
  let attempted = false;
  if (current) {
    const p = current;
    const revocable = !!(p.revoke || p.revokeUrl);
    // #116: a dry-run credential is synthetic — an upstream revoke would be a REAL network call
    // POSTing it to the provider. Keyed off the trusted dry_run column (no flag here), so the CLI
    // is covered too, and a REAL account labelled "dry-run" still revokes normally.
    if (revocable && removed && !claimed.dryRun) {
      const upstream = await revokeProviderCredential(p, claimed);
      attempted = upstream.attempted;
      if (!upstream.ok) ok = false;
    }
  }
  return { removed, ok, attempted, fenced: claimed.fenced };
}

/**
 * Disconnect ONE provider for a user: delete the local credential (the security-meaningful action)
 * FIRST, then best-effort upstream token revocation. A revoke failure is non-fatal — local access is
 * already gone. Audited as 'revoke' (never the token). Transport-agnostic, so the Bolt `/vouchr
 * disconnect` command and the headless broker's `/v1/disconnect` route share ONE implementation.
 * A provider is recognized before mutation when it is registered now OR is the id of an exact
 * stored connection owned by the acting user. The latter keeps removed-from-config providers
 * locally removable without letting arbitrary external values reach a lifecycle marker or audit
 * row (SEC-4).
 *
 * This public compatibility form represents a current-state, in-process call and captures its
 * server-trusted PostgreSQL issuance itself. Transport adapters with an earlier trusted receipt use
 * the internal-path `disconnectProviderAtReceipt` form so delayed requests retain their true age.
 *
 * `ok` means the full disconnect is complete: no upstream revocation debt remains and the durable
 * provisioning fence was established. `audited` reports whether the audit obligation is complete
 * (a committed delete was recorded, or no row existed so no revoke audit was due). Audit failure
 * never discards an already-committed delete/revoke outcome.
 */
export async function disconnectProvider(
  vault: Vault,
  audit: Audit,
  registry: ProviderRegistry | undefined,
  identity: SlackIdentity,
  provider: string,
): Promise<DisconnectOutcome> {
  return disconnectProviderAtReceipt(
    vault,
    audit,
    registry,
    identity,
    provider,
    await vault.userProvisioningIssuedAt(),
  );
}

/** Receipt-bound form for trusted adapters. `issuedAt` is the server-trusted Slack receipt or
 * verified headless assertion issuance in PostgreSQL's clock domain. Core checks it while holding
 * the actor's offboard fence and snapshots the exact credential generation before writing the
 * setup-revocation marker. The later delete is conditional on that generation, so an
 * offboard/reconnect between authorization and deletion cannot redirect the request onto the
 * replacement credential. This transport primitive is deliberately not exported from the package
 * root: arbitrary callers must not supply a future timestamp. */
export async function disconnectProviderAtReceipt(
  vault: Vault,
  audit: Audit,
  registry: ProviderRegistry | undefined,
  identity: SlackIdentity,
  provider: string,
  issuedAt: number,
  expectedId?: string,
): Promise<DisconnectOutcome> {
  const outcome = await disconnectProviderAtGeneration(
    vault,
    audit,
    registry,
    identity,
    provider,
    issuedAt,
    expectedId,
  );
  if (!outcome) throw new InteractionStateChangedError('connection', 'credential');
  return outcome;
}

/** Internal exact-generation form shared by provider-addressed public calls and Vouchr-owned Slack
 * controls. `null` is a stale generation verdict: it is reached before a provisioning marker,
 * credential delete, upstream revoke, or audit write. */
async function disconnectProviderAtGeneration(
  vault: Vault,
  audit: Audit,
  registry: ProviderRegistry | undefined,
  identity: SlackIdentity,
  provider: string,
  issuedAt: number,
  expectedId?: string,
): Promise<DisconnectOutcome | null> {
  if (!isValidProviderId(provider)) {
    return { recognized: false, removed: false, ok: false, audited: false };
  }
  const registered = registry?.has(provider) ?? false;
  // Establish recognition before deleteForRevoke persists its lifecycle fence. A registered id is
  // declaratively trusted; a retired id must match this actor's exact stored row. If that row then
  // disappears concurrently, retaining the marker is valid—it fenced a provider that was known at
  // this request's authorization point. Arbitrary valid-looking input reaches no write (SEC-4).
  if (!registered && !(await vault.has(userOwner(identity), provider))) {
    return { recognized: false, removed: false, ok: false, audited: false };
  }
  const prepared = await vault.prepareUserDisconnect(identity, provider, issuedAt, expectedId);
  if (prepared.status === 'offboarded') {
    throw new InteractionStateChangedError('connection', 'authorization');
  }
  if (prepared.status === 'stale') return null;
  const outcome = prepared.expectedId
      ? await removeUserConnection(vault, registry, identity, provider, {
          expectedId: prepared.expectedId,
          fenced: prepared.fenced,
          identity,
          issuedAt,
        })
    : { removed: false, ok: true, attempted: false, fenced: prepared.fenced };
  if (!outcome.removed && prepared.expectedId && await vault.has(userOwner(identity), provider)) {
    throw new InteractionStateChangedError('connection', 'credential');
  }
  const ok = outcome.ok && outcome.fenced;
  // A no-op is not a revoke event. Keep duplicate/idempotent calls quiet: there is no committed
  // mutation to audit, and adapters use `removed` to suppress the matching metrics event (#226).
  if (!outcome.removed) return { recognized: true, removed: false, ok, audited: true };
  // meta.ok keeps its shape; upstream:'skipped' (same key as revokeConnection, STR-4) marks that no
  // real revoke call was made. An ok:false outcome can mean upstream debt, a failed provisioning
  // fence, or both; the public copy gives recovery for both without exposing internal failure text.
  let audited = true;
  try {
    await audit.record('revoke', identity, provider, { ok, ...(outcome.attempted ? {} : { upstream: 'skipped' }) }); // never the token
  } catch {
    audited = false; // the structured mutation/revoke outcome must survive an audit-store failure
  }
  return { recognized: true, removed: outcome.removed, ok, audited };
}

/** Disconnect the exact opaque connection generation rendered in a Vouchr-owned Slack surface.
 * The UUID reveals no provider or identity. Core first resolves it against the verified actor, then
 * repeats actor ownership + exact generation under the destructive mutation's locks. */
export async function disconnectConnectionGeneration(
  vault: Vault,
  audit: Audit,
  registry: ProviderRegistry | undefined,
  identity: SlackIdentity,
  credentialId: unknown,
  issuedAt: number,
): Promise<
  | { status: 'stale' }
  | {
      status: 'current';
      provider: string;
      outcome: DisconnectOutcome;
    }
> {
  if (!isInteractionId(credentialId)) return { status: 'stale' };
  const provider = await vault.providerForUserGeneration(identity, credentialId);
  if (!provider) return { status: 'stale' };
  const outcome = await disconnectProviderAtGeneration(
    vault,
    audit,
    registry,
    identity,
    provider,
    issuedAt,
    credentialId,
  );
  if (!outcome?.recognized) return { status: 'stale' };
  return { status: 'current', provider, outcome };
}

/**
 * Remove ALL of a user's own connections: the offboarding cleanup. Triggered
 * automatically when Slack deactivates the account (see the Bolt adapter's
 * registerOffboarding), and callable from a SCIM deprovision hook or an admin.
 *
 * Also purges in-flight consent, setup/session state, and requester-bound approvals for the user.
 * The tombstone remains the load-bearing barrier: retained credential use and approval
 * decision/consumption compare their trusted receipt times even if bounded-state cleanup fails.
 *
 * Only the user's own connections are removed. Channel/shared connections belong to the channel,
 * not the person, so they are intentionally left in place for current actors and reviewed
 * separately by an admin. Idempotent. Returns the providers removed.
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
  // Optional: clear opaque private-modal provisioning requests. The tombstone remains the
  // load-bearing fence; this is bounded-state cleanup and makes stale controls converge promptly.
  provisioning?: UserProvisioningRequests,
  // Optional: clear channel-setup requests issued to this actor. Channel credentials themselves
  // belong to the channel and remain; only the deactivated user's outstanding modal authority goes.
  channelProvisioning?: ChannelProvisioningRequests,
  // Optional bounded-state cleanup. The tombstone is still load-bearing: approval decision and
  // consumption compare their own trusted creation times, so a failed cleanup cannot revive one.
  approvals?: Approvals,
): Promise<string[]> {
  return (await offboardUserDetailed(
    vault,
    audit,
    consent,
    identity,
    registry,
    reason,
    sessions,
    provisioning,
    channelProvisioning,
    approvals,
  )).providers;
}

/** Complete, no-secret offboarding outcome for trusted transport adapters. Intentionally not
 * re-exported from the package root: the long-standing public {@link offboardUser} contract remains
 * `Promise<string[]>`, while transports also need to report upstream/audit debt truthfully. */
export interface OffboardUserOutcome {
  providers: string[];
  ok: boolean;
}

export async function offboardUserDetailed(
  vault: Vault,
  audit: Audit,
  consent: Consent,
  identity: SlackIdentity,
  registry?: ProviderRegistry,
  reason = 'offboarded',
  sessions?: SessionGrants,
  provisioning?: UserProvisioningRequests,
  channelProvisioning?: ChannelProvisioningRequests,
  approvals?: Approvals,
): Promise<OffboardUserOutcome> {
  // The durable fail-closed gate FIRST (GHSA-25m2): once the tombstone is written, no consent
  // minted at or before this instant can ever complete (Consent.consume checks it), so a pending
  // "Connect" cannot resurrect a credential even if the row purge below transiently fails.
  let gated = true;
  try { await consent.markOffboarded(identity); } catch { gated = false; }
  // Auxiliary cleanup, each isolated (GHSA-25m2 review): a cleanup failure must never prevent the
  // credential deletes below — they are the security-meaningful action. Session grants are
  // TTL-bound and swept.
  // Best-effort: the tombstone above is the fence, so a failed consent-row purge is not fatal —
  // the stale rows are reclaimed by the retention sweep (consent.sweepStale).
  try { await consent.deleteForUser(identity); } catch { /* fenced by the tombstone; retention-swept */ }
  try { await sessions?.revokeForUser(identity); } catch { /* thread grants are TTL-bound */ }
  try { await provisioning?.revokeForUser(identity); } catch { /* provisioning requests are TTL-bound */ }
  try { await channelProvisioning?.revokeForUser(identity); } catch { /* provisioning requests are TTL-bound */ }
  try { await approvals?.revokeForUser(identity); } catch { /* approvals are TTL-bound + tombstone-fenced */ }
  const providers = (await vault.listForUser(identity)).map((c) => c.provider); // user-owned only, enumerated without decrypting
  const removed: string[] = [];
  let deleteFailures = 0;
  let complete = true;
  for (const provider of providers) {
    // Per-row isolation (GHSA-25m2): one row's decrypt/delete/audit failure must never strand the
    // remaining credentials — every row gets its own delete attempt, and the return value only
    // claims what was actually removed.
    let outcome: Awaited<ReturnType<typeof removeUserConnection>>;
    try {
      outcome = await removeUserConnection(vault, registry, identity, provider);
    } catch {
      deleteFailures++; // this row's DELETE failed (transient DB error): keep going, surface below
      continue;
    }
    if (!outcome.removed) {
      // This invocation observed the row but lost the delete claim. A concurrent winner owns its
      // revoke/audit outcome, which this transaction cannot prove complete. Registry-backed
      // transports therefore fail closed for this response; a later reconciliation after the row
      // is gone can establish a clean no-op independently.
      if (registry) complete = false;
      continue;
    }
    removed.push(provider);
    // Registry-backed callers requested upstream cleanup. A failed call, unreadable externally
    // referenced token, or retired provider leaves known debt even though local deletion won.
    if (registry && !outcome.ok) complete = false;
    const meta: Record<string, unknown> = { reason };
    if (registry) {
      meta.ok = outcome.ok; // never the token, just whether upstream revocation debt remains
      if (!outcome.attempted) meta.upstream = 'skipped'; // same key as revokeConnection (STR-4)
    }
    try {
      await audit.record('revoke', identity, provider, meta);
    } catch {
      // audit is best-effort per row here: the delete already happened and later rows must run
      complete = false;
    }
  }
  // Every delete above was attempted regardless — but a failure that left state behind must not
  // read as success (GHSA-25m2 review r3): surface it so the caller retries.
  // The durable tombstone is the LOAD-BEARING fence: if it could not be written, a pending consent
  // (or a callback still in token exchange) is not blocked and could resurrect this user after we
  // return — so a tombstone failure makes the offboarding incomplete ON ITS OWN, regardless of the
  // best-effort consent-row purge (which the TTL sweep reclaims anyway). Reporting success with the
  // fence down is the exact resurrection this whole path exists to prevent.
  if (!gated) {
    throw new Error('offboarding incomplete: offboard fence could not be established; retry offboarding'); // no ids/secrets
  }
  if (deleteFailures > 0) {
    throw new Error(`offboarding incomplete: ${deleteFailures} credential deletion(s) failed; retry offboarding`); // no ids/secrets
  }
  return { providers: removed, ok: complete };
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
  /** Resolver id (`vault` for a Vouchr-held token; a source id for an externally-referenced secret).
   *  Never a secret — it is the reference *kind*, not the reference value (SEC-1). */
  source: string;
  /** True when the row stores an external `secret_ref` instead of a vaulted token: local deletion
   *  removes the pointer, NOT the upstream secret, which must be rotated in its source manager. */
  hasReference: boolean;
  /** #116 trusted synthetic-provenance marker; a dry-run row's upstream revoke is skipped. */
  dryRun: boolean;
  createdAt: number;
}

/** {@link RevokeRow} plus the per-row outcome. `removed` is the security-meaningful local delete.
 *  `upstreamAttempted` is true only when at least one real upstream revoke call was made. `upstreamOk`
 *  is false when a required call failed or a provider-required token was unreadable/missing; the
 *  companion flags preserve that distinction without returning secret material. */
export interface RevokeOutcome extends RevokeRow {
  removed: boolean;
  upstreamAttempted: boolean;
  upstreamOk: boolean;
  upstreamUnreadable: boolean;
  upstreamMissing: boolean;
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
    `SELECT team_id, owner_kind, owner_id, external_account, source, (secret_ref IS NOT NULL) AS has_reference, dry_run, created_at
     FROM connection WHERE ${where.join(' AND ')} ORDER BY team_id, owner_kind, owner_id`,
    params,
  )) as any[];
  return rows.map((r) => ({
    teamId: r.team_id, ownerKind: r.owner_kind, ownerId: r.owner_id,
    externalAccount: r.external_account, source: r.source,
    // pg BOOLEAN → true/false; a defensive `=== 1` also covers a 1/0 shim. Fail closed to "referenced".
    hasReference: r.has_reference === true || r.has_reference === 1,
    dryRun: r.dry_run === 1, createdAt: r.created_at,
  }));
}

/** Scoped predicate for pending consent / session requests / session grants — `provider` plus
 *  whichever of team/user/channel the filter narrows to. All three tables carry these columns. */
function pendingWhere(f: RevokeFilter): { where: string; params: unknown[] } {
  // --channel selects a channel-owned credential. A consent/session row is USER authority whose
  // channel column is only request origin, never ownership; do not widen a channel kill into users.
  if (f.channel) return { where: 'FALSE', params: [] };
  const where = ['provider=?'];
  const params: unknown[] = [f.provider];
  if (f.teamId) { where.push('team_id=?'); params.push(f.teamId); }
  if (f.userId) { where.push('user_id=?'); params.push(f.userId); }
  if (f.channel) { where.push('channel=?'); params.push(f.channel); }
  return { where: where.join(' AND '), params };
}

/** User key-setup requests have team/user scope but no channel: a channel-only break-glass run must
 * not widen into unrelated personal setup authority. */
function provisioningWhere(f: RevokeFilter): { where: string; params: unknown[] } {
  if (f.channel) return { where: 'FALSE', params: [] };
  const where = ['provider=?'];
  const params: unknown[] = [f.provider];
  if (f.teamId) { where.push('team_id=?'); params.push(f.teamId); }
  if (f.userId) { where.push('user_id=?'); params.push(f.userId); }
  return { where: where.join(' AND '), params };
}

/** Channel setup authority belongs to its channel target, not to the admin actor who opened it.
 * Therefore a user-scoped break-glass run excludes these rows; channel/team/global scopes include
 * the exact channel requests they can turn into. */
function channelProvisioningWhere(f: RevokeFilter): { where: string; params: unknown[] } {
  if (f.userId) return { where: 'FALSE', params: [] };
  const where = ['provider=?'];
  const params: unknown[] = [f.provider];
  if (f.teamId) { where.push('team_id=?'); params.push(f.teamId); }
  if (f.channel) { where.push('channel=?'); params.push(f.channel); }
  return { where: where.join(' AND '), params };
}

export interface PendingProviderAuthority {
  consents: number;
  requests: number;
  grants: number;
  provisioning: number;
  channelProvisioning: number;
}

/**
 * Pending OAuth consents + thread/session/key-setup authority a {@link RevokeFilter} matches —
 * counted, NOT deleted (for the dry-run). These exist INDEPENDENTLY of a live connection row, so
 * break-glass must report + clear them separately or they can recreate access.
 */
export async function countPendingForProvider(
  db: Db,
  f: RevokeFilter,
): Promise<PendingProviderAuthority> {
  const { where, params } = pendingWhere(f);
  const provisioning = provisioningWhere(f);
  const channelProvisioning = channelProvisioningWhere(f);
  const c = (await db.get(`SELECT COUNT(*) AS n FROM consent_request WHERE ${where}`, params)) as { n: number } | undefined;
  const r = (await db.get(`SELECT COUNT(*) AS n FROM session_request WHERE ${where}`, params)) as { n: number } | undefined;
  const s = (await db.get(`SELECT COUNT(*) AS n FROM session_grant WHERE ${where}`, params)) as { n: number } | undefined;
  const p = (await db.get(
    `SELECT COUNT(*) AS n FROM user_provisioning_request WHERE ${provisioning.where}`,
    provisioning.params,
  )) as { n: number } | undefined;
  const cp = (await db.get(
    `SELECT COUNT(*) AS n FROM channel_provisioning_request WHERE ${channelProvisioning.where}`,
    channelProvisioning.params,
  )) as { n: number } | undefined;
  return {
    consents: c?.n ?? 0,
    requests: r?.n ?? 0,
    grants: s?.n ?? 0,
    provisioning: p?.n ?? 0,
    channelProvisioning: cp?.n ?? 0,
  };
}

/** A retired provider remains a valid break-glass target when its exact id already exists in any
 * canonical durable store. This keeps local deletion available when provider config is broken,
 * without persisting an arbitrary CLI value as a revocation fence (SEC-4). */
async function providerKnownToStore(db: Db, provider: string): Promise<boolean> {
  const row = await db.get(
    `SELECT 1 AS known FROM (
       SELECT provider FROM connection WHERE provider=?
       UNION ALL SELECT provider FROM consent_request WHERE provider=?
       UNION ALL SELECT provider FROM user_provisioning_request WHERE provider=?
       UNION ALL SELECT provider FROM channel_provisioning_request WHERE provider=?
       UNION ALL SELECT provider FROM session_request WHERE provider=?
       UNION ALL SELECT provider FROM session_grant WHERE provider=?
       UNION ALL SELECT provider FROM approval_request WHERE provider=?
       UNION ALL SELECT provider FROM channel_config WHERE provider=?
       UNION ALL SELECT provider FROM channel_tool WHERE provider=?
       UNION ALL SELECT provider FROM provisioning_revocation_tombstone WHERE provider=?
     ) AS known_provider LIMIT 1`,
    Array(10).fill(provider),
  );
  return row != null;
}

/**
 * Delete every matching pending OAuth/session/key-setup authority. Key-setup rows are first
 * snapshotted, then their canonical credential locks are acquired in one transaction. If a writer
 * already consumed a ticket but has not committed, PostgreSQL still exposes the old row to the
 * snapshot; this purge waits for that writer before returning. The caller must reselect connections
 * after this settles, because that writer may have committed a credential while the purge waited.
 */
export async function purgePendingForProvider(
  db: Db,
  f: RevokeFilter,
  options: { providerRegistered?: boolean } = {},
): Promise<PendingProviderAuthority> {
  if (!isValidProviderId(f.provider)) throw new Error('invalid provider revocation scope');
  if (!options.providerRegistered && !(await providerKnownToStore(db, f.provider))) {
    throw new Error('provider revocation scope is not recognized');
  }
  // Load-bearing fence FIRST, in its own short transaction. Every matching writer either committed
  // before this marker (and is visible to the caller's post-fence connection scan) or sees the newer
  // marker and refuses. Never retain this scope lock while taking credential locks below.
  await markProvisioningRevoked(db, f);
  const { where, params } = pendingWhere(f);
  const provisioning = provisioningWhere(f);
  const channelProvisioning = channelProvisioningWhere(f);
  const userScopes = (await db.all(
    `SELECT team_id, user_id FROM user_provisioning_request WHERE ${provisioning.where}`,
    provisioning.params,
  )) as { team_id: string; user_id: string }[];
  const channelScopes = (await db.all(
    `SELECT team_id, channel FROM channel_provisioning_request WHERE ${channelProvisioning.where}`,
    channelProvisioning.params,
  )) as { team_id: string; channel: string }[];
  const purge = async (tx: Db): Promise<PendingProviderAuthority> => {
    const consents = (await tx.run(`DELETE FROM consent_request WHERE ${where}`, params)).changes;
    const requests = (await tx.run(`DELETE FROM session_request WHERE ${where}`, params)).changes;
    const grants = (await tx.run(`DELETE FROM session_grant WHERE ${where}`, params)).changes;
    const removedProvisioning = (await tx.run(
      `DELETE FROM user_provisioning_request WHERE ${provisioning.where}`,
      provisioning.params,
    )).changes;
    const removedChannelProvisioning = (await tx.run(
      `DELETE FROM channel_provisioning_request WHERE ${channelProvisioning.where}`,
      channelProvisioning.params,
    )).changes;
    return {
      consents,
      requests,
      grants,
      provisioning: removedProvisioning,
      channelProvisioning: removedChannelProvisioning,
    };
  };
  const keys = [...new Set([
    ...userScopes.map(({ team_id: teamId, user_id: userId }) =>
      credentialLockKey({ teamId, kind: 'user', id: userId }, f.provider)),
    ...channelScopes.map(({ team_id: teamId, channel }) =>
      credentialLockKey(channelOwner(teamId, channel), f.provider)),
  ])];
  if (keys.length && db.withRefreshLocks) return db.withRefreshLocks(keys, purge);
  return db.transaction ? db.transaction(purge) : purge(db);
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
  options: { auditScope?: 'owner' | 'deployment' } = {},
): Promise<RevokeOutcome> {
  const owner: Owner = { teamId: row.teamId, kind: row.ownerKind, id: row.ownerId, enterpriseId: null };
  const current = registry?.has(provider) ? registry.get(provider) : null;
  const registered = current != null;
  const revocable = isRegisteredRevocable(registry, provider);
  // Atomically claim the row before decoding: a concurrent revoke loser receives no token and cannot
  // double-call the provider. A decrypt/delete failure stays per-row best-effort for the bulk loop.
  let claimed = {
    removed: false,
    accessToken: null as string | null,
    refreshToken: null as string | null,
    accessUnreadable: false,
    refreshUnreadable: false,
    dryRun: false,
    fenced: true,
  };
  try { claimed = await vault.deleteForRevoke(owner, provider, revocable); } catch { /* removed stays false */ }
  const removed = claimed.removed;
  if (!removed) {
    return {
      ...row,
      removed: false,
      upstreamAttempted: false,
      upstreamOk: false,
      upstreamUnreadable: false,
      upstreamMissing: false,
    };
  }
  // Upstream revoke is ATTEMPTED only when the provider actually has a revoke endpoint and we hold a
  // token — otherwise it's a no-op that must be reported as SKIPPED, never as a success. A dry-run
  // row (#116) is always SKIPPED: its token is synthetic and must never be POSTed to a real endpoint.
  let upstreamAttempted = false;
  let upstreamOk = true;
  let upstreamUnreadable = false;
  let upstreamMissing = false;
  if (current && revocable && !claimed.dryRun) {
    const p = current;
    const upstream = await revokeProviderCredential(p, claimed);
    upstreamAttempted = upstream.attempted;
    upstreamOk = upstream.ok;
    upstreamUnreadable = upstream.unreadable;
    upstreamMissing = upstream.missing;
  }
  // A surgical revoke attributes to the owner. The deployment-wide path assumes the database may
  // be attacker-controlled, so it records only fixed system identity plus a registry-trusted
  // provider id (or the constant `unregistered`) — never stored owner/provider text (SEC-1/SEC-4).
  // Everything after the local delete is BEST-EFFORT and wrapped so one row's audit/consent/session
  // failure (e.g. a transient DB error) can never throw out of the bulk-revoke loop and strand the
  // remaining rows. The security-meaningful delete already happened above.
  const deployment = options.auditScope === 'deployment';
  const actor: SlackIdentity = deployment
    ? { enterpriseId: null, teamId: 'system', userId: 'system' }
    : { enterpriseId: null, teamId: row.teamId, userId: row.ownerId };
  const auditProvider = deployment ? (registered ? provider : 'unregistered') : provider;
  const meta: Record<string, unknown> = {
    owner: deployment ? 'deployment' : row.ownerKind,
    reason: 'break-glass',
  };
  if (upstreamAttempted) meta.ok = upstreamOk; else meta.upstream = 'skipped';
  try { await audit.record('revoke', actor, auditProvider, meta, deployment ? 'system' : undefined); }
  catch { /* best-effort */ }
  if (row.ownerKind === 'user') {
    try { await consent.deleteForUserProvider(row.teamId, row.ownerId, provider); } catch { /* best-effort */ }
    try { await sessions.clearForProvider(row.teamId, row.ownerId, provider); } catch { /* best-effort */ }
  }
  return {
    ...row,
    ...(removed ? { dryRun: claimed.dryRun } : {}),
    removed,
    upstreamAttempted,
    upstreamOk,
    upstreamUnreadable,
    upstreamMissing,
  };
}

/**
 * Enterprise Grid / SCIM offboarding: remove a user across EVERY workspace, not just one.
 *
 * The Vault API is team-scoped (the full owner key is team_id + kind + id). A cross-team tombstone
 * first fences even an artifact-free workspace, then we discover every team with an own connection,
 * in-flight consent, pending session request, thread grant, approval, or setup request and replay
 * {@link offboardUser} once per team. That keeps upstream revoke + audit + bounded-state cleanup in
 * one place, and each delete still uses the FULL owner key (team_id + 'user' + userId).
 *
 * In Enterprise Grid the Slack userId is unique org-wide, so `userId` alone is a complete span key.
 * `enterpriseId`, when passed, narrows connection/consent discovery to that org's rows PLUS rows
 * with a NULL enterprise_id: Vault.upsert persists `enterprise_id` only when the owner carries one
 * (`owner.enterpriseId ?? null`), so rows written outside Grid store NULL — excluding them would
 * skip a team whose only artifact is such a row and strand its credential (GHSA-25m2).
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
): Promise<{ teamId: string; providers: string[]; ok: boolean }[]> {
  const ent = user.enterpriseId != null;
  const sessions = new SessionGrants(db);
  const provisioning = new UserProvisioningRequests(db, vault);
  const channelProvisioning = new ChannelProvisioningRequests(db, vault);
  const approvals = new Approvals(db);
  // Establish the cross-team fence BEFORE taking the artifact snapshot. A provisioning mutation
  // holds the matching scope lock through commit: it either commits first and appears below, or
  // this tombstone commits first and every old issuance on an artifact-free team is refused.
  // Never retain the scope lock while deleting team credentials (credential -> scope is the one
  // mutation lock order); markUserOffboardedEverywhere commits its own short transaction here.
  await markUserOffboardedEverywhere(db, user);
  // The ONLY query that spans teams. UNION so a team with only a pending "Connect" or only a lingering
  // thread session artifact (no live connection) is still found and purged. Session tables have no
  // enterprise_id column, so they are always matched by user_id alone (userId is org-unique).
  const rows = (await db.all(
    `SELECT team_id FROM connection WHERE owner_kind='user' AND owner_id=?${ent ? ' AND (enterprise_id=? OR enterprise_id IS NULL)' : ''}
     UNION
     SELECT team_id FROM consent_request WHERE user_id=?${ent ? ' AND (enterprise_id=? OR enterprise_id IS NULL)' : ''}
     UNION
     SELECT team_id FROM session_request WHERE user_id=?
     UNION
     SELECT team_id FROM session_grant WHERE user_id=?
     UNION
     SELECT team_id FROM user_provisioning_request WHERE user_id=?
     UNION
     SELECT team_id FROM channel_provisioning_request WHERE user_id=?
     UNION
     SELECT team_id FROM approval_request WHERE user_id=?`,
    ent
      ? [user.userId, user.enterpriseId, user.userId, user.enterpriseId, user.userId, user.userId, user.userId, user.userId, user.userId]
      : [user.userId, user.userId, user.userId, user.userId, user.userId, user.userId, user.userId],
  )) as { team_id: string }[];

  const summary: { teamId: string; providers: string[]; ok: boolean }[] = [];
  for (const { team_id: teamId } of rows) {
    // Full owner key per team, never a partial key. The detailed helper does the local delete first,
    // then best-effort upstream revoke + audit, and purges this team's pending consent + grants.
    const identity: SlackIdentity = { enterpriseId: user.enterpriseId ?? null, teamId, userId: user.userId };
    try {
      const outcome = await offboardUserDetailed(
        vault,
        audit,
        consent,
        identity,
        registry,
        reason,
        sessions,
        provisioning,
        channelProvisioning,
        approvals,
      );
      summary.push({ teamId, providers: outcome.providers, ok: outcome.ok });
    } catch {
      // Non-fatal per team so later teams still run — but the failure must be SURFACED, not buried
      // (GHSA-25m2 r3): mark this team ok:false so the caller can report the enterprise offboard as
      // incomplete rather than a blanket success. Never surface the error itself (it could carry
      // connection detail); secrets stay out of logs/returns.
      summary.push({ teamId, providers: [], ok: false });
    }
  }
  return summary;
}

// ---------------------------------------------------------------------------------------------
// #239 deployment-wide emergency invalidation (`vouchr revoke --all`). The provider-scoped path
// above is surgical ("provider X is compromised"); this one is for a compromise of the Vouchr
// database/decryption boundary itself, where every reachable credential must be assumed exposed.
// ---------------------------------------------------------------------------------------------

/** Every secret-bearing or resurrection-path table a global revoke must clear. Deliberately EXCLUDES:
 *  the `*_tombstone` fences (they are the anti-resurrection barrier — deleting them removes
 *  protection), `audit` (incident evidence), `broker_jti` (single-use identity replay guard),
 *  `channel_config`/`channel_tool` (policy, not credentials — the surgical revoke leaves them too),
 *  and `meta`. `connection` and `installation` are handled with their own counts, so this list is the
 *  authorization/resurrection set. Adding a new secret-bearing table without adding it here (or to the
 *  documented keep-list) is the "'all' silently omits another secret table" failure the issue calls
 *  out — `test/revoke-all.test.ts` diffs this set against the live schema to catch exactly that. */
export const RESURRECTION_TABLES = [
  'consent_request',
  'session_request',
  'session_grant',
  'approval_request',
  'user_provisioning_request',
  'channel_provisioning_request',
  'notification_state',
] as const;

/** Per-connection disposition of the local delete + upstream revoke attempt. Reported in aggregate,
 *  never per-owner, so the report carries no owner-identifying or secret data (SEC-1). */
export type RevokeCategory =
  /** dry-run only: metadata says this row would enter the provider revoke path. */
  | 'would_attempt'
  /** registered revocable provider, token decrypted, upstream revoke returned success. */
  | 'revoked'
  /** registered revocable provider, but the required operation did not fully succeed. */
  | 'revoke_failed'
  /** provider has no revoke endpoint, or is unregistered/removed — no upstream call is possible. */
  | 'unsupported'
  /** registered revocable provider, but the stored token could not be decrypted (KMS/key missing). */
  | 'undecryptable'
  /** the row could not be claimed or its provider-required token was absent; manual review remains. */
  | 'unresolved'
  /** the secret lives in an external manager (`secret_ref`); rotate it THERE — deleting the pointer
   *  is not upstream invalidation. */
  | 'external_reference'
  /** #116 dry-run synthetic row: never POSTed to a real endpoint. */
  | 'synthetic';

const REVOKE_CATEGORIES: readonly RevokeCategory[] = [
  'would_attempt', 'revoked', 'revoke_failed', 'unsupported', 'undecryptable', 'unresolved',
  'external_reference', 'synthetic',
];

const zeroCategories = (): Record<RevokeCategory, number> =>
  Object.fromEntries(REVOKE_CATEGORIES.map((c) => [c, 0])) as Record<RevokeCategory, number>;

export interface RevokeAllDeps {
  vault: Vault;
  audit: Audit;
  /** Best-effort: absent/broken config disables upstream revoke + decrypt, never the local wipe. */
  registry?: ProviderRegistry;
}

export interface RevokeLocalCounts {
  connections: number;
  consents: number;
  sessionRequests: number;
  sessionGrants: number;
  approvals: number;
  userProvisioning: number;
  channelProvisioning: number;
  notifications: number;
  installations: number;
}

/** Per-provider upstream disposition. `provider` comes only from the trusted runtime registry;
 * removed/unregistered database values are aggregated separately and never leave core. */
export interface RevokeProviderReport {
  provider: string;
  connections: number;
  /** Connection rows for which at least one real provider revoke call was made. */
  attempted: number;
  upstream: Record<RevokeCategory, number>;
}

/** No-secret result of a global revoke. Safe counts + registry-trusted provider ids only. */
export interface RevokeAllReport {
  executed: boolean;
  /** Distinct stored provider ids, including removed/unregistered ones; raw DB values are not returned. */
  providerCount: number;
  /** Registered providers can be named safely because the id comes from trusted deployment config. */
  byProvider: RevokeProviderReport[];
  /** Removed/unregistered DB provider values are counts only (the compromised DB is untrusted output). */
  unregistered: RevokeProviderReport & { provider: 'unregistered'; providers: number };
  /** Rows present at the initial inventory. Never means they were deleted. */
  matched: RevokeLocalCounts;
  /** Local connection deletes that actually committed (0 on dry-run). */
  removedLocal: number;
  /** Aggregate upstream disposition. Dry-run uses `would_attempt`, never `revoked`. */
  upstream: Record<RevokeCategory, number>;
  /** Connection rows for which at least one real provider revoke call was made (always 0 on dry-run). */
  upstreamAttempted: number;
  /** Rows actually removed from each authorization/resurrection table + installations (0 on dry-run; a `-1`
   *  marks a table whose blanket delete threw — surfaced, never a partial silent success). */
  cleared: RevokeLocalCounts;
  /** Rows still present after the sweep. On a clean execute every field is 0. */
  remaining: { credentials: number; authorizations: number; installations: number };
  /** True only when execute completed AND nothing remains. The CLI returns non-zero when false. */
  ok: boolean;
}

/** Distinct provider ids present anywhere credentials or authorization can originate, INCLUDING ids
 *  that are no longer in the runtime registry (removed/renamed providers). `installation` has no
 *  provider column (Slack workspace tokens) and is handled separately. */
export async function enumerateStoredProviders(db: Db): Promise<string[]> {
  const rows = (await db.all(
    `SELECT provider FROM connection
     UNION SELECT provider FROM consent_request
     UNION SELECT provider FROM session_request
     UNION SELECT provider FROM session_grant
     UNION SELECT provider FROM approval_request
     UNION SELECT provider FROM user_provisioning_request
     UNION SELECT provider FROM channel_provisioning_request
     UNION SELECT provider FROM notification_state`,
  )) as { provider: string }[];
  return rows.map((r) => r.provider).sort();
}

/** Whether `provider` is registered AND declares an upstream revoke capability. */
function isRegisteredRevocable(registry: ProviderRegistry | undefined, provider: string): boolean {
  if (!registry?.has(provider)) return false;
  const p = registry.get(provider);
  return !!(p.revoke || p.revokeUrl);
}

/** Classify one row from METADATA alone (dry-run preview): no decrypt and no upstream call. */
function previewCategory(row: RevokeRow, revocable: boolean): RevokeCategory {
  if (row.dryRun) return 'synthetic';
  if (row.source !== 'vault' || row.hasReference) return 'external_reference';
  return revocable ? 'would_attempt' : 'unsupported';
}

/** Classify one row after execution, using the actual delete/upstream outcome. */
function executeCategory(row: RevokeRow, outcome: RevokeOutcome, revocable: boolean): RevokeCategory {
  if (row.dryRun) return 'synthetic';
  if (row.source !== 'vault' || row.hasReference) return 'external_reference';
  if (!revocable) return 'unsupported';
  if (!outcome.removed) return 'unresolved';
  // A partial `both` operation can revoke one readable token while another required token remains
  // unreadable or absent. Report the actionable uncertainty instead of disguising it as an HTTP
  // failure merely because at least one provider call was attempted.
  if (outcome.upstreamUnreadable) return 'undecryptable';
  if (outcome.upstreamMissing) return 'unresolved';
  if (outcome.upstreamAttempted) return outcome.upstreamOk ? 'revoked' : 'revoke_failed';
  return 'unresolved';
}

async function countRows(db: Db, table: string): Promise<number> {
  const row = (await db.get(`SELECT COUNT(*) AS n FROM ${table}`)) as { n: number } | undefined;
  return Number(row?.n ?? 0);
}

const zeroLocalCounts = (): RevokeLocalCounts => ({
  connections: 0,
  consents: 0,
  sessionRequests: 0,
  sessionGrants: 0,
  approvals: 0,
  userProvisioning: 0,
  channelProvisioning: 0,
  notifications: 0,
  installations: 0,
});

async function localCounts(db: Db): Promise<RevokeLocalCounts> {
  return {
    connections: await countRows(db, 'connection'),
    consents: await countRows(db, 'consent_request'),
    sessionRequests: await countRows(db, 'session_request'),
    sessionGrants: await countRows(db, 'session_grant'),
    approvals: await countRows(db, 'approval_request'),
    userProvisioning: await countRows(db, 'user_provisioning_request'),
    channelProvisioning: await countRows(db, 'channel_provisioning_request'),
    notifications: await countRows(db, 'notification_state'),
    installations: await countRows(db, 'installation'),
  };
}

function authorizationCount(c: RevokeLocalCounts): number {
  return c.consents + c.sessionRequests + c.sessionGrants + c.approvals
    + c.userProvisioning + c.channelProvisioning + c.notifications;
}

/**
 * Deployment-wide emergency invalidation. Dry-run (`execute:false`) enumerates and classifies with
 * ZERO mutation and ZERO decryption. Execute:
 *  1. per enumerated provider, runs the shared {@link revokeConnection} (local delete FIRST, then
 *     best-effort bounded upstream revoke, audit, and per-user consent/grant clear) so upstream
 *     reporting and the mutation+audit contract are the SAME code the surgical path uses (STR-3);
 *  2. then BLANKET-deletes every authorization/resurrection table + `connection` + `installation`,
 *     which needs no decryption/KMS/provider config and also removes pending authority that has no
 *     connection row (a bare "Connect" consent), malformed-provider rows, and anything a concurrent
 *     writer committed during step 1 — making the command idempotent and complete;
 *  3. recounts and reports residual rows. `ok` is false (CLI exit 1) while any local credential or
 *     authorization row remains.
 *
 * Concurrency: the anti-resurrection guarantee during an incident is the deployment lockdown gate
 * (VOUCHR_LOCKDOWN — the running workload refuses to serve/mint), established by the runbook BEFORE
 * this runs. This command itself neither reads nor trusts that DB state; a row a writer commits after
 * the sweep is caught by the recount and reported as remaining (non-zero), never a silent success.
 * Containment is the operator's lockdown/quarantine step, not a fence this command writes —
 * writing a permanent global fence here would block legitimate post-recovery reconnects.
 */
export async function revokeAllCredentials(
  db: Db,
  deps: RevokeAllDeps,
  opts: { execute: boolean },
): Promise<RevokeAllReport> {
  const storedProviders = await enumerateStoredProviders(db);
  const matched = await localCounts(db);
  const upstream = zeroCategories();
  const byProvider: RevokeProviderReport[] = [];
  const unregistered: RevokeAllReport['unregistered'] = {
    provider: 'unregistered',
    providers: 0,
    connections: 0,
    attempted: 0,
    upstream: zeroCategories(),
  };
  let removedLocal = 0;
  let upstreamAttempted = 0;

  const bucketFor = (provider: string): RevokeProviderReport => {
    if (deps.registry?.has(provider)) {
      const report = {
        provider: deps.registry.get(provider).id,
        connections: 0,
        attempted: 0,
        upstream: zeroCategories(),
      };
      byProvider.push(report);
      return report;
    }
    unregistered.providers++;
    return unregistered;
  };
  const mark = (bucket: RevokeProviderReport, category: RevokeCategory): void => {
    bucket.upstream[category]++;
    upstream[category]++;
  };

  if (!opts.execute) {
    for (const provider of storedProviders) {
      const bucket = bucketFor(provider);
      const revocable = isRegisteredRevocable(deps.registry, provider);
      for (const row of await selectRevocations(db, { provider })) {
        bucket.connections++;
        mark(bucket, previewCategory(row, revocable));
      }
    }
    return {
      executed: false,
      providerCount: storedProviders.length,
      byProvider,
      unregistered,
      matched,
      removedLocal: 0,
      upstream,
      upstreamAttempted: 0,
      cleared: zeroLocalCounts(),
      remaining: {
        credentials: matched.connections,
        authorizations: authorizationCount(matched),
        installations: matched.installations,
      },
      ok: false,
    };
  }

  const consent = new Consent(db);
  const sessions = new SessionGrants(db);
  // Phase 1: per-provider upstream revoke + attributed local delete, via the shared helper.
  for (const provider of storedProviders) {
    const bucket = bucketFor(provider);
    const revocable = isRegisteredRevocable(deps.registry, provider);
    for (const row of await selectRevocations(db, { provider })) {
      bucket.connections++;
      let outcome: RevokeOutcome;
      try {
        outcome = await revokeConnection(
          deps.vault,
          deps.audit,
          consent,
          sessions,
          deps.registry,
          row,
          provider,
          { auditScope: 'deployment' },
        );
      } catch {
        // A provider/KMS extension may throw with credential material inside; never serialize it
        // (SEC-1). The blanket delete below still removes this row, so the sweep stays complete.
        mark(bucket, 'unresolved');
        continue;
      }
      if (outcome.removed) removedLocal++;
      if (outcome.upstreamAttempted) {
        bucket.attempted++;
        upstreamAttempted++;
      }
      mark(bucket, executeCategory(row, outcome, revocable));
    }
  }

  // Phase 2: blanket local purge. Guarantees every resurrection path is gone regardless of provider
  // validity, decryptability, or a connection existing — and makes a second run converge to zero.
  const del = async (table: string): Promise<number> => {
    try {
      return (await db.run(`DELETE FROM ${table}`)).changes; // table name is a fixed literal, not input
    } catch {
      return -1; // a failed table delete is surfaced (and caught by the recount), never hidden
    }
  };
  const cleared = {
    connections: await del('connection'),
    consents: await del('consent_request'),
    sessionRequests: await del('session_request'),
    sessionGrants: await del('session_grant'),
    approvals: await del('approval_request'),
    userProvisioning: await del('user_provisioning_request'),
    channelProvisioning: await del('channel_provisioning_request'),
    notifications: await del('notification_state'),
    installations: await del('installation'),
  };

  // Phase 3: honest residual accounting. Non-zero exit while ANY local credential/authorization row
  // remains (a delete that failed, or a row a concurrent writer committed after containment lapsed).
  const credentials = await countRows(db, 'connection');
  let authorizations = 0;
  for (const table of RESURRECTION_TABLES) authorizations += await countRows(db, table);
  const remainingInstallations = await countRows(db, 'installation');
  return {
    executed: true,
    providerCount: storedProviders.length,
    byProvider,
    unregistered,
    matched,
    removedLocal,
    upstream,
    upstreamAttempted,
    cleared,
    remaining: { credentials, authorizations, installations: remainingInstallations },
    ok: credentials === 0 && authorizations === 0 && remainingInstallations === 0,
  };
}
