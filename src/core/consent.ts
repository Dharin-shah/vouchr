import { randomBytes } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { Owner } from './owner';
import { isValidProviderId, type Provider } from './providers';
import { sha256base64url } from './crypto';
import { DRY_RUN_CODE } from './dryRun';
import {
  isInteractionId,
  newInteractionId,
  POSTGRES_NOW_MS_SQL,
  PROMPT_DELIVERY_LEASE_MS,
  PROMPT_REDELIVERY_DEBOUNCE_MS,
  type PromptDeliveryClaim,
  type PromptDeliveryOptions,
} from './interaction';

export const STATE_TTL_MS = 10 * 60 * 1000;
/** Expired state has no authority, but its owner-bound row remains briefly so the callback can give
 * precise private recovery instead of becoming indistinguishable from hostile random input. */
export const STATE_RECOVERY_RETENTION_MS = 24 * 60 * 60 * 1000;
export const MAX_CONSENT_SWEEP_BATCH = 1_000;
/** One bounded retention statement. The created_at subquery rides
 * idx_consent_request_created_at; the state array lets PostgreSQL use the primary key when that is
 * cheaper than scanning a small or mostly-expired table. */
export const CONSENT_SWEEP_BATCH_SQL =
  `DELETE FROM consent_request WHERE state = ANY(ARRAY(` +
  `SELECT state FROM consent_request ` +
  `WHERE created_at < ? ` +
  `ORDER BY created_at LIMIT ? FOR UPDATE SKIP LOCKED))`;

/** OAuth state is exactly one 32-byte base64url value. Reject malformed/oversized callback input
 * before a database lookup; the random value remains the authority, not this shape check. */
export function isConsentState(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
}

/**
 * The ONE offboarding-tombstone rule (GHSA-25m2): does a tombstone disqualify a consent minted at
 * `mintedAt`? Both stamps come from PostgreSQL's clock, so their ordering is exact across replicas.
 * Shared by
 * {@link Consent.consume} (single-use gate) and the callback write-gate (`Vault.upsert`'s `gate`) so
 * the rule lives in exactly one place.
 */
export function tombstoneBlocks(tombCreatedAt: number | null | undefined, mintedAt: number): boolean {
  return tombCreatedAt != null && tombCreatedAt >= mintedAt;
}

/** Serialize the durable offboard fence with mutations that can recreate user authority. The key
 *  representation lives here once; session grants and markOffboarded share it so either the grant
 *  commits first and cleanup removes it, or the tombstone commits first and the grant refuses. */
export function offboardLockKey(teamId: string, userId: string): string {
  return `offboard:${teamId}:${userId}`;
}

type OffboardScopeKind = 'enterprise' | 'unscoped' | 'global';
interface OffboardScope {
  kind: OffboardScopeKind;
  id: string;
}

const GLOBAL_OFFBOARD_SCOPE: OffboardScope = { kind: 'global', id: '' };
const UNSCOPED_OFFBOARD_SCOPE: OffboardScope = { kind: 'unscoped', id: '' };

function identityOffboardScopes(
  enterpriseId: string | null,
): readonly [OffboardScope, OffboardScope] {
  if (enterpriseId === null) return [GLOBAL_OFFBOARD_SCOPE, UNSCOPED_OFFBOARD_SCOPE];
  if (enterpriseId.length === 0) throw new Error('enterprise offboard scope is invalid');
  return [GLOBAL_OFFBOARD_SCOPE, { kind: 'enterprise', id: enterpriseId }];
}

function everywhereOffboardScopes(enterpriseId: string | null | undefined): readonly OffboardScope[] {
  if (enterpriseId == null) return [GLOBAL_OFFBOARD_SCOPE];
  if (enterpriseId.length === 0) throw new Error('enterprise offboard scope is invalid');
  // Enterprise sweeps have always included NULL-enterprise artifacts. The unscoped tombstone keeps
  // that fail-closed contract for an artifact-free team without denying a named identity in a
  // different enterprise that happens to carry the same user id.
  return [{ kind: 'enterprise', id: enterpriseId }, UNSCOPED_OFFBOARD_SCOPE];
}

function offboardScopeLockKey(scope: OffboardScope, userId: string): string {
  return `offboard-scope:${scope.kind}:${scope.id}:${userId}`;
}

async function withOffboardLocks<T>(
  db: Db,
  keys: readonly string[],
  fn: (tx: Db) => Promise<T>,
): Promise<T> {
  if (db.withRefreshLocks) return db.withRefreshLocks(keys, fn);
  if (keys.length === 1 && db.withRefreshLock) return db.withRefreshLock(keys[0], fn);
  if (db.transaction) return db.transaction(fn);
  throw new Error('offboard fencing requires database transaction support');
}

function userOffboardLockKeys(identity: SlackIdentity): string[] {
  return [
    offboardLockKey(identity.teamId, identity.userId),
    ...identityOffboardScopes(identity.enterpriseId).map((scope) =>
      offboardScopeLockKey(scope, identity.userId)),
  ];
}

async function writeTeamOffboardMarker(tx: Db, identity: SlackIdentity): Promise<void> {
  await tx.run(
    `INSERT INTO offboard_tombstone (team_id, user_id, created_at) VALUES (?,?,${POSTGRES_NOW_MS_SQL})
     ON CONFLICT(team_id, user_id) DO UPDATE SET created_at=GREATEST(
       offboard_tombstone.created_at,
       excluded.created_at
     )`,
    [identity.teamId, identity.userId],
  );
}

async function writeScopeOffboardMarkers(
  tx: Db,
  userId: string,
  scopes: readonly OffboardScope[],
): Promise<void> {
  const clock = await tx.get<{ created_at: number }>(
    `SELECT ${POSTGRES_NOW_MS_SQL} AS created_at`,
  );
  if (!Number.isSafeInteger(clock?.created_at)) {
    throw new Error('could not establish cross-team offboard fence');
  }
  for (const scope of scopes) {
    await tx.run(
       `INSERT INTO user_offboard_scope_tombstone
         (scope_kind, scope_id, user_id, created_at) VALUES (?,?,?,?)
       ON CONFLICT(scope_kind, scope_id, user_id)
       DO UPDATE SET created_at=GREATEST(
         user_offboard_scope_tombstone.created_at,
         excluded.created_at
       )`,
      [scope.kind, scope.id, userId, clock!.created_at],
    );
  }
}

type ProvisioningScopeKind =
  | 'global'
  | 'team'
  | 'user'
  | 'team-user'
  | 'channel'
  | 'team-channel';

interface ProvisioningScope {
  kind: ProvisioningScopeKind;
  key: string;
}

/** The exact operator scope whose pre-existing provisioning authority a confirmed break-glass
 * revoke invalidates. Scope ids are hashed before persistence: the durable table stores only a
 * fixed server-derived selector, never an unchecked CLI value. */
export interface ProvisioningRevocationFilter {
  provider: string;
  teamId?: string;
  userId?: string;
  channel?: string;
}

function provisioningScope(kind: ProvisioningScopeKind, ...parts: string[]): ProvisioningScope {
  return { kind, key: sha256base64url(JSON.stringify([kind, ...parts])) };
}

function exactProvisioningScope(f: ProvisioningRevocationFilter): ProvisioningScope {
  if (!isValidProviderId(f.provider)) throw new Error('invalid provider revocation scope');
  if (f.userId !== undefined && f.channel !== undefined) {
    throw new Error('user and channel revocation scopes are mutually exclusive');
  }
  for (const value of [f.teamId, f.userId, f.channel]) {
    if (value !== undefined && (typeof value !== 'string' || value.length === 0)) {
      throw new Error('invalid provisioning revocation scope');
    }
  }
  if (f.userId !== undefined) {
    return f.teamId === undefined
      ? provisioningScope('user', f.userId)
      : provisioningScope('team-user', f.teamId, f.userId);
  }
  if (f.channel !== undefined) {
    return f.teamId === undefined
      ? provisioningScope('channel', f.channel)
      : provisioningScope('team-channel', f.teamId, f.channel);
  }
  return f.teamId === undefined
    ? provisioningScope('global')
    : provisioningScope('team', f.teamId);
}

function ownerProvisioningScopes(owner: Owner): readonly ProvisioningScope[] {
  const shared = [provisioningScope('global'), provisioningScope('team', owner.teamId)];
  return owner.kind === 'user'
    ? [
        ...shared,
        provisioningScope('user', owner.id),
        provisioningScope('team-user', owner.teamId, owner.id),
      ]
    : [
        ...shared,
        provisioningScope('channel', owner.id),
        provisioningScope('team-channel', owner.teamId, owner.id),
      ];
}

function provisioningRevocationLockKey(provider: string, scopeKey: string): string {
  return `provisioning-revoke:${provider}:${scopeKey}`;
}

/** Serialize one credential writer with every break-glass scope that can match its exact owner.
 * The caller already holds the credential lifecycle lock. Revoke writes only its scope marker in a
 * short transaction and releases it before taking credential locks, so the order cannot invert. */
export function withProvisioningRevocationLock<T>(
  db: Db,
  owner: Owner,
  provider: string,
  fn: (tx: Db) => Promise<T>,
): Promise<T> {
  if (!isValidProviderId(provider)) throw new Error('invalid provider provisioning fence');
  const keys = ownerProvisioningScopes(owner).map((scope) =>
    provisioningRevocationLockKey(provider, scope.key));
  return withOffboardLocks(db, keys, fn);
}

/** Hold both lifecycle fences applicable to a user writer: scoped break-glass revocation first,
 * then team/enterprise/global offboarding. */
export function withUserProvisioningLock<T>(
  db: Db,
  identity: SlackIdentity,
  provider: string,
  fn: (tx: Db) => Promise<T>,
): Promise<T> {
  const owner: Owner = {
    teamId: identity.teamId,
    kind: 'user',
    id: identity.userId,
    enterpriseId: identity.enterpriseId,
  };
  return withProvisioningRevocationLock(db, owner, provider, (revocationTx) =>
    withUserOffboardLock(revocationTx, identity, fn));
}

/** Newest confirmed break-glass marker applicable to this exact credential owner/provider. */
export async function latestProvisioningRevocationTombstone(
  db: Db,
  owner: Owner,
  provider: string,
): Promise<number | null> {
  if (!isValidProviderId(provider)) throw new Error('invalid provider provisioning fence');
  const keys = ownerProvisioningScopes(owner).map((scope) => scope.key);
  const row = await db.get<{ created_at: number }>(
    `SELECT created_at FROM provisioning_revocation_tombstone
      WHERE provider=? AND scope_key IN (?,?,?,?)
      ORDER BY created_at DESC LIMIT 1`,
    [provider, ...keys],
  );
  return row?.created_at ?? null;
}

/** Commit the exact scoped break-glass fence before any pending/live authority is enumerated.
 * The timestamp is sampled only after its advisory lock is held and never moves backward. */
export async function markProvisioningRevoked(
  db: Db,
  filter: ProvisioningRevocationFilter,
): Promise<number> {
  const scope = exactProvisioningScope(filter);
  const key = provisioningRevocationLockKey(filter.provider, scope.key);
  const mark = async (tx: Db): Promise<number> => {
    const clock = await tx.get<{ created_at: number }>(
      `SELECT ${POSTGRES_NOW_MS_SQL} AS created_at`,
    );
    if (!Number.isSafeInteger(clock?.created_at)) {
      throw new Error('could not establish provisioning revocation fence');
    }
    await tx.run(
      `INSERT INTO provisioning_revocation_tombstone
         (provider, scope_kind, scope_key, created_at) VALUES (?,?,?,?)
       ON CONFLICT(provider, scope_key) DO UPDATE SET created_at=GREATEST(
         provisioning_revocation_tombstone.created_at,
         excluded.created_at
       )`,
      [filter.provider, scope.kind, scope.key, clock!.created_at],
    );
    return clock!.created_at;
  };
  if (db.withRefreshLock) return db.withRefreshLock(key, mark);
  if (db.transaction) return db.transaction(mark);
  throw new Error('provisioning revocation requires database transaction support');
}

export async function withOffboardLock<T>(
  db: Db,
  teamId: string,
  userId: string,
  fn: (tx: Db) => Promise<T>,
): Promise<T> {
  const key = offboardLockKey(teamId, userId);
  if (db.withRefreshLock) return db.withRefreshLock(key, fn);
  if (db.transaction) return db.transaction(fn);
  throw new Error('offboard fencing requires database transaction support');
}

/** Hold every durable offboard fence applicable to one user identity. Credential provisioning
 * acquires its credential lifecycle lock first, then enters here; cross-team offboarding commits its
 * scope tombstone before discovering/deleting credentials, so no reverse lock order exists. */
export function withUserOffboardLock<T>(
  db: Db,
  identity: SlackIdentity,
  fn: (tx: Db) => Promise<T>,
): Promise<T> {
  return withOffboardLocks(db, userOffboardLockKeys(identity), fn);
}

/** Newest team, enterprise/unscoped, or global tombstone applicable to this exact identity. */
export async function latestUserOffboardTombstone(
  db: Db,
  identity: SlackIdentity,
): Promise<number | null> {
  const [, specific] = identityOffboardScopes(identity.enterpriseId);
  const row = await db.get<{ created_at: number }>(
    `SELECT created_at FROM (
       SELECT created_at FROM offboard_tombstone WHERE team_id=? AND user_id=?
       UNION ALL
       SELECT created_at FROM user_offboard_scope_tombstone
        WHERE user_id=? AND (
          (scope_kind='global' AND scope_id='') OR
          (scope_kind=? AND scope_id=?)
        )
     ) AS applicable_tombstone
     ORDER BY created_at DESC LIMIT 1`,
    [identity.teamId, identity.userId, identity.userId, specific.kind, specific.id],
  );
  return row?.created_at ?? null;
}

export type UserInteractionFenceResult<T> =
  | { status: 'current'; value: T }
  | { status: 'offboarded' };

export type UserInteractionFencesResult<T> =
  | { status: 'current'; value: T }
  | { status: 'offboarded'; index: number };

export interface UserInteractionReceipt {
  identity: SlackIdentity;
  issuedAt: number;
}

/** Compare one trusted interaction/assertion issuance with the newest applicable user tombstone.
 * The caller owns any lock needed to carry this verdict into a mutation; read-only use validators
 * use it as their exact authorization linearization check. */
export async function userInteractionIsCurrent(
  db: Db,
  identity: SlackIdentity,
  issuedAt: number,
): Promise<boolean> {
  if (!Number.isSafeInteger(issuedAt)) throw new Error('invalid user interaction issuance');
  return !tombstoneBlocks(await latestUserOffboardTombstone(db, identity), issuedAt);
}

/** Hold every acting/requesting user's complete offboard scope in canonical order through one
 * authority mutation. The returned index identifies which caller-supplied receipt was stale. */
export function withUserInteractionFences<T>(
  db: Db,
  receipts: readonly UserInteractionReceipt[],
  fn: (tx: Db) => Promise<T>,
): Promise<UserInteractionFencesResult<T>> {
  if (receipts.length === 0) throw new Error('user interaction fencing requires a receipt');
  for (const receipt of receipts) {
    if (!Number.isSafeInteger(receipt.issuedAt)) {
      throw new Error('invalid user interaction issuance');
    }
  }
  return withOffboardLocks(
    db,
    receipts.flatMap(({ identity }) => userOffboardLockKeys(identity)),
    async (tx) => {
      for (const [index, receipt] of receipts.entries()) {
        if (!(await userInteractionIsCurrent(tx, receipt.identity, receipt.issuedAt))) {
          return { status: 'offboarded', index };
        }
      }
      return { status: 'current', value: await fn(tx) };
    },
  );
}

/** Hold the acting user's complete offboard scope through one authority mutation and reject an
 * interaction/assertion received before the newest applicable tombstone. Adapters own the trusted
 * receipt-to-PostgreSQL timestamp conversion; core owns the mutation-time lock and comparison. */
export async function withUserInteractionFence<T>(
  db: Db,
  identity: SlackIdentity,
  issuedAt: number,
  fn: (tx: Db) => Promise<T>,
): Promise<UserInteractionFenceResult<T>> {
  const result = await withUserInteractionFences(db, [{ identity, issuedAt }], fn);
  return result.status === 'current' ? result : { status: 'offboarded' };
}

/** Atomically authorize a team-scoped admin offboard intent and establish the target tombstone.
 * Actor and target locks are acquired in canonical order so two admins offboarding each other do
 * not deadlock. Cleanup runs only after this short authority mutation commits. */
export function markUserOffboardedByActor(
  db: Db,
  actor: SlackIdentity,
  actorIssuedAt: number,
  target: SlackIdentity,
): Promise<boolean> {
  if (!Number.isSafeInteger(actorIssuedAt)) throw new Error('invalid admin offboard issuance');
  if (actor.teamId !== target.teamId) throw new Error('admin offboard target must share the actor team');
  const keys = [...userOffboardLockKeys(actor), offboardLockKey(target.teamId, target.userId)];
  return withOffboardLocks(db, keys, async (tx) => {
    if (tombstoneBlocks(await latestUserOffboardTombstone(tx, actor), actorIssuedAt)) return false;
    await writeTeamOffboardMarker(tx, target);
    return true;
  });
}

/** Enterprise/Grid form of {@link markUserOffboardedByActor}. The signed actor and bound target
 * share one enterprise; all actor and target scope locks are taken canonically before the target
 * scope tombstones commit. */
export function markUserOffboardedEverywhereByActor(
  db: Db,
  actor: SlackIdentity,
  actorIssuedAt: number,
  target: { enterpriseId: string; userId: string },
): Promise<boolean> {
  if (!Number.isSafeInteger(actorIssuedAt)) throw new Error('invalid admin offboard issuance');
  if (actor.enterpriseId !== target.enterpriseId) {
    throw new Error('admin offboard target must share the actor enterprise');
  }
  const scopes = everywhereOffboardScopes(target.enterpriseId);
  const keys = [
    ...userOffboardLockKeys(actor),
    ...scopes.map((scope) => offboardScopeLockKey(scope, target.userId)),
  ];
  return withOffboardLocks(db, keys, async (tx) => {
    if (tombstoneBlocks(await latestUserOffboardTombstone(tx, actor), actorIssuedAt)) return false;
    await writeScopeOffboardMarkers(tx, target.userId, scopes);
    return true;
  });
}

/** Establish the cross-team fence before an Enterprise Grid / SCIM artifact snapshot. The timestamp
 * is sampled only after every canonical scope lock is held; both enterprise + legacy-unscoped rows
 * therefore share one exact PostgreSQL linearization point. */
export async function markUserOffboardedEverywhere(
  db: Db,
  user: { enterpriseId?: string | null; userId: string },
): Promise<void> {
  const scopes = everywhereOffboardScopes(user.enterpriseId);
  const keys = scopes.map((scope) => offboardScopeLockKey(scope, user.userId));
  await withOffboardLocks(db, keys, (tx) => writeScopeOffboardMarkers(tx, user.userId, scopes));
}

interface ConsentRow {
  state: string;
  identity: SlackIdentity;
  provider: string;
  channel: string | null;
  pkceVerifier: string;
  /** When the consent state was minted — the callback write-gate compares it to the tombstone. */
  createdAt: number;
}

export interface ConsentRequest {
  authorizeUrl: string;
  state: string;
}

type ConsentCallbackClaim =
  | { status: 'active'; row: ConsentRow }
  | { status: 'expired' | 'superseded'; row: ConsentRow }
  | { status: 'invalidated'; reason: 'offboarded' | 'revoked'; row: ConsentRow }
  | { status: 'unavailable' };

function consentRow(row: any): ConsentRow {
  return {
    state: row.state,
    identity: {
      enterpriseId: row.enterprise_id,
      teamId: row.team_id,
      userId: row.user_id,
    },
    provider: row.provider,
    channel: row.channel,
    pkceVerifier: row.pkce_verifier,
    createdAt: row.created_at,
  };
}

/** Manages the single-use OAuth `state` + PKCE for a consent round-trip. */
export class Consent {
  /** `dryRun` (#116): begin() then returns a LOCAL authorize URL — the redirect target itself with
   *  a synthetic code — instead of the provider's, so clicking Connect completes instantly and
   *  offline. The state row, single-use consume, and TTL stay exactly the real machinery. */
  constructor(
    private db: Db,
    private dryRun = false,
  ) {}

  /** Create a single-use consent request and return the provider authorize URL. */
  async begin(
    i: SlackIdentity,
    provider: Provider,
    redirectUri: string,
    channel: string | null,
  ): Promise<ConsentRequest> {
    const clock = await this.db.get<{ issued_at: number }>(
      `SELECT ${POSTGRES_NOW_MS_SQL} AS issued_at`,
    );
    if (!Number.isSafeInteger(clock?.issued_at)) throw new Error('could not issue consent fence');
    const pending = await this.beginFenced(
      i,
      provider,
      redirectUri,
      channel,
      clock!.issued_at,
    );
    if (!pending) throw new Error('credential setup was invalidated');
    return pending;
  }

  /** Headless OAuth initiation fenced by the verified assertion's issuance in PostgreSQL's clock
   * domain. Locking makes initiation linearize with offboarding: state commits first and cleanup
   * removes it, or the tombstone commits first and this returns null without minting a URL. */
  async beginFenced(
    i: SlackIdentity,
    provider: Provider,
    redirectUri: string,
    channel: string | null,
    issuedAt: number,
  ): Promise<ConsentRequest | null> {
    if (!Number.isSafeInteger(issuedAt)) throw new Error('invalid consent issuance');
    return withUserProvisioningLock(this.db, i, provider.id, async (tx) => {
      const owner: Owner = {
        teamId: i.teamId,
        kind: 'user',
        id: i.userId,
        enterpriseId: i.enterpriseId,
      };
      const offboardedAt = await latestUserOffboardTombstone(tx, i);
      const revokedAt = await latestProvisioningRevocationTombstone(tx, owner, provider.id);
      if (tombstoneBlocks(offboardedAt, issuedAt) || tombstoneBlocks(revokedAt, issuedAt)) {
        return null;
      }
      return this.beginAt(
        tx,
        i,
        provider,
        redirectUri,
        channel,
        issuedAt,
        offboardedAt,
        revokedAt,
      );
    });
  }

  private async beginAt(
    db: Db,
    i: SlackIdentity,
    provider: Provider,
    redirectUri: string,
    channel: string | null,
    issuedAt: number,
    offboardedAt: number | null,
    revokedAt: number | null,
  ): Promise<ConsentRequest | null> {
    const existing = await db.get<any>(
      `SELECT *, ${POSTGRES_NOW_MS_SQL} AS observed_at
       FROM consent_request
       WHERE team_id=? AND user_id=? AND provider=? AND superseded_at IS NULL
       FOR UPDATE`,
      [i.teamId, i.userId, provider.id],
    );
    if (existing) {
      const sameContext = existing.enterprise_id === i.enterpriseId
        && existing.channel === channel;
      const live = existing.consumed_at == null
        && existing.observed_at - existing.created_at <= STATE_TTL_MS;
      const lifecycleCurrent = !tombstoneBlocks(offboardedAt, existing.created_at)
        && !tombstoneBlocks(revokedAt, existing.created_at);
      if (sameContext && live && lifecycleCurrent) {
        return this.requestFor(
          provider,
          redirectUri,
          existing.state,
          existing.pkce_verifier,
        );
      }
      // A delayed older request may reuse an already-visible prompt in the same context, but it may
      // not replace a newer generation or move that prompt to another channel.
      if (existing.created_at > issuedAt || existing.observed_at - issuedAt > STATE_TTL_MS) {
        return null;
      }
      await db.run(
        `UPDATE consent_request
         SET superseded_at=${POSTGRES_NOW_MS_SQL}
         WHERE state=? AND superseded_at IS NULL`,
        [existing.state],
      );
    } else {
      const clock = await db.get<{ observed_at: number }>(
        `SELECT ${POSTGRES_NOW_MS_SQL} AS observed_at`,
      );
      if (!Number.isSafeInteger(clock?.observed_at)) {
        throw new Error('could not establish consent generation');
      }
      if (clock!.observed_at - issuedAt > STATE_TTL_MS) return null;
    }

    const state = randomBytes(32).toString('base64url');
    const pkceVerifier = randomBytes(48).toString('base64url');

    await db.run(
      `INSERT INTO consent_request
         (state, enterprise_id, team_id, user_id, provider, channel, pkce_verifier, created_at)
       VALUES (?,?,?,?,?,?,?,?)`,
      [state, i.enterpriseId, i.teamId, i.userId, provider.id, channel, pkceVerifier, issuedAt],
    );

    return this.requestFor(provider, redirectUri, state, pkceVerifier);
  }

  private requestFor(
    provider: Provider,
    redirectUri: string,
    state: string,
    pkceVerifier: string,
  ): ConsentRequest {
    // #116 dry-run: the authorize URL is the ONLY thing replaced — an instantly-succeeding local
    // redirect into the real callback. The code is synthetic; the single-use `state` above is what
    // the callback verifies, exactly as in production.
    if (this.dryRun) {
      const u = new URL(redirectUri);
      u.searchParams.set('code', DRY_RUN_CODE);
      u.searchParams.set('state', state);
      return { authorizeUrl: u.toString(), state };
    }

    const url = new URL(provider.authorizeUrl);
    // Provider extras FIRST, so the Vouchr-owned params below always win even if one slipped past the
    // definition-time reserved-key guard (RESERVED_AUTHORIZE_PARAMS in defineProvider). Belt and
    // suspenders on the single-use `state` / `redirect_uri` (SEC-2): render order can't clobber them.
    for (const [k, v] of Object.entries(provider.authorizeParams ?? {})) {
      url.searchParams.set(k, v);
    }
    url.searchParams.set('client_id', provider.clientId!); // guaranteed for oauth providers (defineProvider)
    url.searchParams.set('redirect_uri', redirectUri);
    if (provider.scopesDefault.length) {
      url.searchParams.set('scope', provider.scopesDefault.join(' '));
    }
    url.searchParams.set('state', state);
    url.searchParams.set('response_type', 'code');
    if (provider.pkce) {
      url.searchParams.set('code_challenge', sha256base64url(pkceVerifier));
      url.searchParams.set('code_challenge_method', 'S256');
    }
    return { authorizeUrl: url.toString(), state };
  }

  /** Delete any in-flight consent for a user, preventing a pending OAuth from
   *  resurrecting a connection for a just-offboarded user. */
  async deleteForUser(i: SlackIdentity): Promise<void> {
    await this.db.run(`DELETE FROM consent_request WHERE team_id=? AND user_id=?`, [i.teamId, i.userId]);
  }

  /**
   * Durable fail-closed offboarding gate (GHSA-25m2): record that this user was offboarded NOW.
   * `consume()` refuses any consent state minted at or before this instant, so even if the row purge
   * in {@link deleteForUser} transiently
   * fails, a pending pre-offboarding "Connect" can never complete and resurrect a credential.
   * Tombstones are permanent and tiny (one row per offboarded user); a legitimately re-onboarded
   * user starts a NEW consent after the tombstone and passes. Re-offboarding refreshes the timestamp.
   */
  async markOffboarded(i: SlackIdentity): Promise<void> {
    await withOffboardLock(this.db, i.teamId, i.userId, (tx) => writeTeamOffboardMarker(tx, i));
  }

  /** Delete in-flight consent for ONE provider (break-glass bulk revocation), so a pending "Connect"
   *  click can't resurrect the credential we just revoked. */
  async deleteForUserProvider(teamId: string, userId: string, provider: string): Promise<void> {
    await this.db.run(`DELETE FROM consent_request WHERE team_id=? AND user_id=? AND provider=?`, [teamId, userId, provider]);
  }

  /** Delete consent rows after the longer authority-free recovery window. Every statement is
   * bounded, limiting statement work. Ordinary runtime calls autocommit each batch; a caller that
   * deliberately supplies a transaction-bound Db retains its outer transaction semantics. */
  async sweepStale(): Promise<number> {
    // Sample PostgreSQL time once. A volatile clock_timestamp() inside the row predicate becomes a
    // per-row filter instead of an index condition and can make an empty sweep scan the whole table.
    const rawCutoff = await this.db.get<{ cutoff: unknown }>(
      `SELECT ${POSTGRES_NOW_MS_SQL} - ? AS cutoff`,
      [STATE_RECOVERY_RETENTION_MS],
    );
    const cutoff = Number(rawCutoff?.cutoff);
    if (!Number.isSafeInteger(cutoff)) throw new Error('consent retention cutoff is unavailable');
    let total = 0;
    for (;;) {
      const { changes } = await this.db.run(CONSENT_SWEEP_BATCH_SQL, [
        cutoff,
        MAX_CONSENT_SWEEP_BATCH,
      ]);
      total += changes;
      if (changes < MAX_CONSENT_SWEEP_BATCH) return total;
    }
  }

  /** Newest pending state for (user, provider) — the dry-run completeConsent lookup (#116). Scoped
   *  to a team when one is given. Read-only: consume() stays the single-use gate. */
  async latestStateFor(userId: string, provider: string, teamId?: string): Promise<string | null> {
    const row = (await this.db.get(
      `SELECT state FROM consent_request WHERE user_id=? AND provider=?${teamId ? ' AND team_id=?' : ''}
         AND superseded_at IS NULL AND consumed_at IS NULL
         AND created_at >= ${POSTGRES_NOW_MS_SQL} - ?
       ORDER BY created_at DESC LIMIT 1`,
      teamId ? [userId, provider, teamId, STATE_TTL_MS] : [userId, provider, STATE_TTL_MS],
    )) as any;
    return row?.state ?? null;
  }

  /** Atomically spend one callback state while retaining its bounded row long enough to classify an
   * expired or superseded authentic link. Replays and unknown values are intentionally identical. */
  async consume(state: string): Promise<ConsentCallbackClaim> {
    if (!isConsentState(state)) return { status: 'unavailable' };
    const raw = await this.db.get<any>(
      `UPDATE consent_request
       SET consumed_at=${POSTGRES_NOW_MS_SQL}
       WHERE state=? AND consumed_at IS NULL
       RETURNING *, ${POSTGRES_NOW_MS_SQL} AS observed_at`,
      [state],
    );
    if (!raw) return { status: 'unavailable' };
    const row = consentRow(raw);
    const identity = row.identity;
    const owner: Owner = {
      teamId: identity.teamId,
      kind: 'user',
      id: identity.userId,
      enterpriseId: identity.enterpriseId,
    };
    const [offboardedAt, revokedAt] = await Promise.all([
      latestUserOffboardTombstone(this.db, identity),
      latestProvisioningRevocationTombstone(this.db, owner, row.provider),
    ]);
    const offBlocks = tombstoneBlocks(offboardedAt, row.createdAt);
    const revBlocks = tombstoneBlocks(revokedAt, row.createdAt);
    if (offBlocks || revBlocks) {
      // A blocking tombstone wins over supersession/expiry UNLESS a supersession happened strictly
      // after every blocking tombstone — that is a legitimately re-onboarded generation minted
      // post-offboard/revoke, so "use the newest prompt" is correct. Expiry, or a supersession at or
      // before the block, cannot mask a lifecycle invalidation the user must actually act on
      // (offboarding tolerates a failed consent-row purge, so the row can outlive the tombstone).
      const blockingTime = Math.max(
        offBlocks ? (offboardedAt as number) : Number.NEGATIVE_INFINITY,
        revBlocks ? (revokedAt as number) : Number.NEGATIVE_INFINITY,
      );
      if (!(raw.superseded_at != null && raw.superseded_at > blockingTime)) {
        return offBlocks
          ? { status: 'invalidated', reason: 'offboarded', row }
          : { status: 'invalidated', reason: 'revoked', row };
      }
    }
    // finalizeProvisioning() re-checks the tombstones inside the credential transaction, so an
    // offboard/revoke that wins during token exchange still blocks the write.
    if (raw.superseded_at != null) return { status: 'superseded', row };
    if (raw.observed_at - raw.created_at > STATE_TTL_MS) return { status: 'expired', row };
    return { status: 'active', row };
  }

  /** Resolve the callback's issuance (the consent's mint time) inside Vault's credential
   * transaction. Deleting only the exact still-active generation makes token exchange lose safely
   * to a newer prompt; Vault's unconditional newest-generation fence then prevents this issuance
   * from overwriting a credential written after it, while still letting a generation minted over an
   * older live credential replace it, so deliberate re-auth cannot dead-end. */
  async finalizeProvisioning(
    row: ConsentRow,
    db: Db,
  ): Promise<number | null> {
    const current = await db.get<{ created_at: number }>(
      `DELETE FROM consent_request
       WHERE state=? AND team_id=? AND user_id=? AND provider=?
         AND superseded_at IS NULL AND consumed_at IS NOT NULL
       RETURNING created_at`,
      [row.state, row.identity.teamId, row.identity.userId, row.provider],
    );
    if (current) return current.created_at;

    // Offboard/revoke cleanup may have deleted the row while token exchange was in flight. Preserve
    // that more precise lifecycle result by letting Vault evaluate the original issuance against the
    // tombstone under the same locks. With no matching tombstone, absence means a newer generation
    // or unrelated cleanup won and the old callback stays stale.
    const owner: Owner = {
      teamId: row.identity.teamId,
      kind: 'user',
      id: row.identity.userId,
      enterpriseId: row.identity.enterpriseId,
    };
    const offboardedAt = await latestUserOffboardTombstone(db, row.identity);
    const revokedAt = await latestProvisioningRevocationTombstone(db, owner, row.provider);
    return tombstoneBlocks(offboardedAt, row.createdAt) || tombstoneBlocks(revokedAt, row.createdAt)
      ? row.createdAt
      : null;
  }

  /** Cross-replica lease for the private Connect prompt. Transient surfaces may explicitly reclaim
   * a delivered generation after the debounce; durable surfaces remain delivered. */
  async claimDelivery(
    state: string,
    options: PromptDeliveryOptions = {},
  ): Promise<PromptDeliveryClaim> {
    if (!isConsentState(state)) return { status: 'stale' };
    for (let attempt = 0; attempt < 3; attempt++) {
      const token = newInteractionId();
      const claimed = await this.db.get<{ state: string }>(
        `UPDATE consent_request
         SET delivery_token=?, delivery_lease_expires_at=${POSTGRES_NOW_MS_SQL}+?, delivered_at=NULL
         WHERE state=? AND superseded_at IS NULL AND consumed_at IS NULL
           AND created_at >= ${POSTGRES_NOW_MS_SQL}-?
           AND (
             delivered_at IS NULL
             OR (?::boolean AND delivered_at <= ${POSTGRES_NOW_MS_SQL}-?)
           )
           AND (delivery_token IS NULL OR delivery_lease_expires_at<=${POSTGRES_NOW_MS_SQL})
         RETURNING state`,
        [
          token,
          PROMPT_DELIVERY_LEASE_MS,
          state,
          STATE_TTL_MS,
          options.redeliverDelivered === true,
          PROMPT_REDELIVERY_DEBOUNCE_MS,
        ],
      );
      if (claimed) return { status: 'claimed', token };
      const current = await this.db.get<{
        delivered_at: number | null;
        delivery_lease_expires_at: number;
        now_ms: number;
      }>(
        `SELECT delivered_at, delivery_lease_expires_at, ${POSTGRES_NOW_MS_SQL} AS now_ms
         FROM consent_request
         WHERE state=? AND superseded_at IS NULL AND consumed_at IS NULL
           AND created_at >= ${POSTGRES_NOW_MS_SQL}-?`,
        [state, STATE_TTL_MS],
      );
      if (!current) return { status: 'stale' };
      if (current.delivered_at != null) return { status: 'delivered' };
      if (current.delivery_lease_expires_at > current.now_ms) return { status: 'in-flight' };
    }
    return { status: 'in-flight' };
  }

  async confirmDelivery(state: string, token: string): Promise<boolean> {
    if (!isConsentState(state) || !isInteractionId(token)) return false;
    return (await this.db.run(
      `UPDATE consent_request
       SET delivered_at=${POSTGRES_NOW_MS_SQL}, delivery_token=NULL, delivery_lease_expires_at=0
       WHERE state=? AND delivery_token=? AND superseded_at IS NULL AND consumed_at IS NULL
         AND delivered_at IS NULL AND created_at >= ${POSTGRES_NOW_MS_SQL}-?`,
      [state, token, STATE_TTL_MS],
    )).changes === 1;
  }

  /** Release only this delivery claim. A Slack rejection never deletes OAuth authority: another
   * adapter may already have presented the same URL, and the TTL bounds abandoned state. */
  async abandonDelivery(state: string, token: string): Promise<boolean> {
    if (!isConsentState(state) || !isInteractionId(token)) return false;
    return (await this.db.run(
      `UPDATE consent_request SET delivery_token=NULL, delivery_lease_expires_at=0
       WHERE state=? AND delivery_token=? AND superseded_at IS NULL
         AND consumed_at IS NULL AND delivered_at IS NULL`,
      [state, token],
    )).changes === 1;
  }
}
