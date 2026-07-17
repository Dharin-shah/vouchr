import { randomUUID } from 'node:crypto';
import type { Audit } from './audit';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import {
  latestProvisioningRevocationTombstone,
  latestUserOffboardTombstone,
  tombstoneBlocks,
  withProvisioningRevocationLock,
  withUserOffboardLock,
  withUserProvisioningLock,
} from './consent';
import {
  isInteractionId,
  latestChannelInteractionTombstone,
  PENDING_INTERACTION_TTL_MS,
  POSTGRES_NOW_MS_SQL,
} from './interaction';
import { channelOwner, userOwner } from './owner';
import { isValidProviderId } from './providers';
import type { SecretReference } from './reference';
import type { ChannelProvisioningIssuance } from './channelCredential';
import type {
  StoredToken,
  UserProvisioningIssuance,
  UserProvisioningResult,
  Vault,
} from './vault';

/** Opaque, short-lived authority-free handle for one Slack key-setup prompt. Provider and actor
 * bindings live in PostgreSQL; the prompt button carries only the UUID. Repeated prompts for the
 * same user/provider reuse one live row, so sibling buttons/modals converge on one final consume. */
export class UserProvisioningRequests {
  constructor(
    private db: Db,
    private vault?: Vault,
  ) {}

  async issue(identity: SlackIdentity, provider: string): Promise<string | null> {
    if (!this.vault) throw new Error('user provisioning issue requires a vault');
    return issueUserProvisioningRequest(this.vault, identity, provider);
  }

  /** Resolve a setup-button click without consuming or extending it. Identity comes from Slack's
   * signed interaction; provider comes only from the bound row. A pre-offboard request is refused
   * even if bounded-state cleanup failed, while a concurrent later offboard is caught again by the
   * final Vault fence on modal submit. */
  async resolveForModal(id: unknown, identity: SlackIdentity): Promise<string | null> {
    if (!isInteractionId(id)) return null;
    const row = await this.db.get<{ provider: string; created_at: number }>(
      `SELECT provider, created_at FROM user_provisioning_request
       WHERE id=? AND team_id=? AND user_id=?
         AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [id, identity.teamId, identity.userId],
    );
    if (typeof row?.provider !== 'string') return null;
    const owner = userOwner(identity);
    const [offboardedAt, revokedAt] = await Promise.all([
      latestUserOffboardTombstone(this.db, identity),
      latestProvisioningRevocationTombstone(this.db, owner, row.provider),
    ]);
    if (
      tombstoneBlocks(offboardedAt, row.created_at) ||
      tombstoneBlocks(revokedAt, row.created_at)
    ) return null;
    // Read-only early feedback; the final ticket consume repeats this live-absence predicate under
    // the credential lock, so a write racing this check still cannot be overwritten.
    if (this.vault && await this.vault.hasLive(userOwner(identity), row.provider)) return null;
    return row.provider;
  }

  /** Build the issuance resolver consumed by Vault under the credential + offboard locks. Exact
   * actor/provider binding and expiry are checked in the DELETE itself; a wrong or duplicate id
   * mutates nothing. A later audit/write failure rolls the delete back with the outer transaction. */
  issuance(
    id: unknown,
    identity: SlackIdentity,
    provider: string,
  ): UserProvisioningIssuance {
    return async (tx) => {
      if (!isInteractionId(id)) return null;
      const row = await tx.get<{ created_at: number }>(
        `DELETE FROM user_provisioning_request
         WHERE id=? AND team_id=? AND user_id=? AND provider=?
           AND expires_at>${POSTGRES_NOW_MS_SQL}
         RETURNING created_at`,
        [id, identity.teamId, identity.userId, provider],
      );
      return row ? row.created_at : null;
    };
  }

  async revokeForUser(identity: SlackIdentity): Promise<void> {
    await this.db.run(
      `DELETE FROM user_provisioning_request WHERE team_id=? AND user_id=?`,
      [identity.teamId, identity.userId],
    );
  }

  async sweepExpired(): Promise<number> {
    return (await this.db.run(
      `DELETE FROM user_provisioning_request WHERE expires_at<${POSTGRES_NOW_MS_SQL}`,
    )).changes;
  }
}

export interface ChannelProvisioningRequest {
  channel: string;
  provider: string;
}

/** Opaque, actor-bound authority for one channel-credential modal. Slack carries only the UUID;
 * PostgreSQL owns the trusted actor, channel, provider, issuance, expiry, and single-use consume. */
export class ChannelProvisioningRequests {
  constructor(
    private db: Db,
    private vault: Vault,
  ) {}

  /** Mint or reuse one live request. `issuedAt` is the original handler receipt mapped into
   * PostgreSQL time before any slow authorization work, so a revoke that won during that work
   * cannot be bypassed by issuing the request afterward. */
  async issue(
    identity: SlackIdentity,
    channel: string,
    provider: string,
    issuedAt: number,
  ): Promise<string | null> {
    if (
      !identity.teamId ||
      !identity.userId ||
      !channel ||
      !isValidProviderId(provider) ||
      !Number.isSafeInteger(issuedAt)
    ) throw new Error('invalid channel provisioning request');
    const id = randomUUID();
    const owner = channelOwner(identity.teamId, channel);
    return this.vault.withCredentialLock(owner, provider, async (_locked, tx) =>
      withProvisioningRevocationLock(tx, owner, provider, (revocationTx) =>
        withUserOffboardLock(revocationTx, identity, async (fencedTx) => {
          // `fencedTx` owns one checked-out pg client; keep reads sequential (pg v9 removes
          // concurrent client.query calls) while the credential lock preserves the snapshot.
          const revokedAt = await latestProvisioningRevocationTombstone(fencedTx, owner, provider);
          const offboardedAt = await latestUserOffboardTombstone(fencedTx, identity);
          const changedAt = await latestChannelInteractionTombstone(
            fencedTx,
            identity.teamId,
            channel,
            provider,
          );
          if (
            tombstoneBlocks(revokedAt, issuedAt) ||
            tombstoneBlocks(offboardedAt, issuedAt) ||
            tombstoneBlocks(changedAt, issuedAt)
          ) return null;
          const clock = await fencedTx.get<{ now: number }>(
            `SELECT ${POSTGRES_NOW_MS_SQL} AS now`,
          );
          if (
            !Number.isSafeInteger(clock?.now) ||
            issuedAt + PENDING_INTERACTION_TTL_MS <= clock!.now
          ) return null;
          const existing = await fencedTx.get<{
            id: string;
            created_at: number;
            expires_at: number;
          }>(
            `SELECT id, created_at, expires_at FROM channel_provisioning_request
             WHERE team_id=? AND channel=? AND user_id=? AND provider=?`,
            [identity.teamId, channel, identity.userId, provider],
          );
          if (
            existing &&
            existing.expires_at > clock!.now &&
            !tombstoneBlocks(revokedAt, existing.created_at) &&
            !tombstoneBlocks(offboardedAt, existing.created_at) &&
            !tombstoneBlocks(changedAt, existing.created_at)
          ) return isInteractionId(existing.id) ? existing.id : null;
          const row = await fencedTx.get<{ id: string }>(
            `INSERT INTO channel_provisioning_request
               (id, team_id, channel, user_id, provider, created_at, expires_at)
             VALUES (?,?,?,?,?,?,?)
             ON CONFLICT (team_id, channel, user_id, provider) DO UPDATE SET
               id=excluded.id, created_at=excluded.created_at, expires_at=excluded.expires_at
             RETURNING id`,
            [
              id,
              identity.teamId,
              channel,
              identity.userId,
              provider,
              issuedAt,
              issuedAt + PENDING_INTERACTION_TTL_MS,
            ],
          );
          if (!isInteractionId(row?.id)) {
            throw new Error('could not issue channel provisioning request');
          }
          return row.id;
        })));
  }

  /** Resolve trusted modal facts without consuming them. This is only early UX feedback; the final
   * mutation consumes the same row in its credential transaction and repeats the revocation fence. */
  async resolveForModal(
    id: unknown,
    identity: SlackIdentity,
  ): Promise<ChannelProvisioningRequest | null> {
    if (!isInteractionId(id)) return null;
    const row = await this.db.get<{
      channel: string;
      provider: string;
      created_at: number;
    }>(
      `SELECT channel, provider, created_at FROM channel_provisioning_request
       WHERE id=? AND team_id=? AND user_id=?
         AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [id, identity.teamId, identity.userId],
    );
    if (
      typeof row?.channel !== 'string' ||
      !row.channel ||
      typeof row.provider !== 'string' ||
      !isValidProviderId(row.provider)
    ) return null;
    const owner = channelOwner(identity.teamId, row.channel);
    const [revokedAt, offboardedAt, changedAt] = await Promise.all([
      latestProvisioningRevocationTombstone(this.db, owner, row.provider),
      latestUserOffboardTombstone(this.db, identity),
      latestChannelInteractionTombstone(this.db, identity.teamId, row.channel, row.provider),
    ]);
    if (
      tombstoneBlocks(revokedAt, row.created_at) ||
      tombstoneBlocks(offboardedAt, row.created_at) ||
      tombstoneBlocks(changedAt, row.created_at)
    ) return null;
    return { channel: row.channel, provider: row.provider };
  }

  /** Consume the exact actor/channel/provider request inside the caller's final transaction. A
   * duplicate submit returns null; rollback restores the request if the credential or audit fails. */
  issuance(
    id: unknown,
    identity: SlackIdentity,
    channel: string,
    provider: string,
  ): ChannelProvisioningIssuance {
    return async (tx) => {
      if (!isInteractionId(id)) return null;
      const row = await tx.get<{ created_at: number }>(
        `DELETE FROM channel_provisioning_request
         WHERE id=? AND team_id=? AND channel=? AND user_id=? AND provider=?
           AND expires_at>${POSTGRES_NOW_MS_SQL}
         RETURNING created_at`,
        [id, identity.teamId, channel, identity.userId, provider],
      );
      return Number.isSafeInteger(row?.created_at) ? row!.created_at : null;
    };
  }

  async revokeForUser(identity: SlackIdentity): Promise<void> {
    await this.db.run(
      `DELETE FROM channel_provisioning_request WHERE team_id=? AND user_id=?`,
      [identity.teamId, identity.userId],
    );
  }

  async sweepExpired(): Promise<number> {
    return (await this.db.run(
      `DELETE FROM channel_provisioning_request WHERE expires_at<${POSTGRES_NOW_MS_SQL}`,
    )).changes;
  }
}

/** Issue one actor/provider-bound key-setup request through the same cross-replica lifecycle fence
 * used by every user credential write. This is internal adapter plumbing, not a package export:
 * direct ConnectContext consumers only provide their existing Vault dependency. When connect()
 * already captured its PostgreSQL start time, passing it here prevents later reads or lock waits
 * from turning a pre-offboard request into post-offboard authority. */
export async function issueUserProvisioningRequest(
  vault: Vault,
  identity: SlackIdentity,
  provider: string,
  alreadyIssuedAt?: number,
): Promise<string | null> {
  // Capture before either lifecycle lock when the caller has not already captured even earlier.
  // Both this stamp and every tombstone use PostgreSQL's clock domain.
  const issuedAt = alreadyIssuedAt ?? await vault.userProvisioningIssuedAt();
  if (!Number.isSafeInteger(issuedAt)) throw new Error('invalid user provisioning request issuance');
  const id = randomUUID();
  const owner = userOwner(identity);
  return vault.withCredentialLock(owner, provider, async (locked, tx) =>
    withUserProvisioningLock(tx, identity, provider, async (fencedTx) => {
      const offboardedAt = await latestUserOffboardTombstone(fencedTx, identity);
      const revokedAt = await latestProvisioningRevocationTombstone(
        fencedTx,
        owner,
        provider,
      );
      if (
        tombstoneBlocks(offboardedAt, issuedAt) ||
        tombstoneBlocks(revokedAt, issuedAt)
      ) return null;
      // connect() observed absence before entering this helper; reassert it under the exact
      // credential lock so a sibling write cannot land between that read and ticket issuance.
      if (await locked.hasLive(owner, provider)) return null;
      const now = await fencedTx.get<{ now: number }>(`SELECT ${POSTGRES_NOW_MS_SQL} AS now`);
      if (!Number.isSafeInteger(now?.now) || issuedAt + PENDING_INTERACTION_TTL_MS <= now!.now) return null;
      const existing = await fencedTx.get<{ id: string; created_at: number; expires_at: number }>(
        `SELECT id, created_at, expires_at FROM user_provisioning_request
         WHERE team_id=? AND user_id=? AND provider=?`,
        [identity.teamId, identity.userId, provider],
      );
      if (
        existing &&
        existing.expires_at > now!.now &&
        !tombstoneBlocks(offboardedAt, existing.created_at) &&
        !tombstoneBlocks(revokedAt, existing.created_at)
      ) return isInteractionId(existing.id) ? existing.id : null;
      const row = await fencedTx.get<{ id: string }>(
        `INSERT INTO user_provisioning_request
           (id, team_id, user_id, provider, created_at, expires_at)
         VALUES (?,?,?,?,?,?)
         ON CONFLICT (team_id, user_id, provider) DO UPDATE SET
           id=excluded.id, created_at=excluded.created_at, expires_at=excluded.expires_at
         RETURNING id`,
        [id, identity.teamId, identity.userId, provider, issuedAt, issuedAt + PENDING_INTERACTION_TTL_MS],
      );
      if (!isInteractionId(row?.id)) throw new Error('could not issue user provisioning request');
      return row.id;
    }));
}

type UserCredentialInput =
  | { kind: 'secret'; token: StoredToken }
  | { kind: 'ref'; reference: SecretReference };

/** The one user secret/reference mutation + canonical audit pair. Issuance is resolved and checked
 * by Vault inside the cross-replica lifecycle transaction, so no caller can commit a credential or
 * config audit after an earlier offboard tombstone. */
export async function configureUserCredential(input: {
  vault: Vault;
  audit: Audit;
  identity: SlackIdentity;
  providerId: string;
  credential: UserCredentialInput;
  issuance: UserProvisioningIssuance;
}): Promise<UserProvisioningResult> {
  const owner = userOwner(input.identity);
  if (input.credential.kind === 'secret') {
    return input.vault.upsertUser(
      owner,
      input.providerId,
      input.credential.token,
      input.issuance,
      (tx) => input.audit.record(
        'config',
        input.identity,
        input.providerId,
        { owner: 'user', kind: 'secret' },
        undefined,
        tx,
      ),
    );
  }
  const reference = input.credential.reference;
  return input.vault.referenceUser(
    owner,
    input.providerId,
    reference,
    input.issuance,
    (tx) => input.audit.record(
      'config',
      input.identity,
      input.providerId,
      { owner: 'user', kind: 'ref', source: reference.source },
      undefined,
      tx,
    ),
  );
}
