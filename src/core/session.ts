import type { Audit } from './audit';
import {
  userInteractionIsCurrent,
  withUserInteractionFence,
} from './consent';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import {
  isInteractionId,
  InteractionStateChangedError,
  newInteractionId,
  PENDING_INTERACTION_TTL_MS,
  POSTGRES_NOW_MS_SQL,
  PROMPT_DELIVERY_LEASE_MS,
  PROMPT_REDELIVERY_DEBOUNCE_MS,
  type PromptDeliveryClaim,
  type PromptDeliveryOptions,
} from './interaction';
import { channelOwner, userOwner, type Owner } from './owner';
import type { Vault } from './vault';

/** One pending session request. The Slack control carries only `id`; every binding and the provider
 *  are reloaded from this row and compared with the verified click context before mutation. */
export interface SessionRequestRow {
  id: string;
  teamId: string;
  userId: string;
  channel: string;
  thread: string;
  provider: string;
  credentialId: string;
  createdAt: number;
  expiresAt: number;
}

export type SessionRequestResult = { id: string; created: boolean };
export type AuditedSessionRequestResult =
  | { status: 'requested'; id: string; created: boolean }
  | { status: 'already-granted' };
export type SessionGrantResult =
  | { status: 'granted'; provider: string }
  | { status: 'stale' }
  | { status: 'actor-stale' }
  | { status: 'invalidated' };

function toRequest(r: any): SessionRequestRow {
  return {
    id: r.id,
    teamId: r.team_id,
    userId: r.user_id,
    channel: r.channel,
    thread: r.thread,
    provider: r.provider,
    credentialId: r.credential_id,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
  };
}

/** The context columns that make one live request unique. Kept in one helper so the insert-conflict
 *  target and fallback lookup cannot drift. */
function requestKey(i: SlackIdentity, channel: string, thread: string, provider: string): unknown[] {
  return [i.teamId, channel, thread, i.userId, provider];
}

/**
 * Thread-scoped session state. A grant says the acting user may use `provider` only inside the exact
 * Slack thread until `expires_at`. Missing grants are represented by short-lived, PostgreSQL-backed
 * requests; Block Kit receives only their opaque ids.
 */
export class SessionGrants {
  constructor(private db: Db) {}

  /** Create or reuse the one live request for this exact verified context. The schema's context
   *  uniqueness closes the two-replica race; an expired row is atomically replaced with a fresh id. */
  async request(
    i: SlackIdentity,
    channel: string,
    thread: string,
    provider: string,
    credentialId: string,
  ): Promise<SessionRequestResult> {
    if (!isInteractionId(credentialId)) throw new Error('session request requires a valid credential generation id');
    const key = requestKey(i, channel, thread, provider);
    for (let attempt = 0; attempt < 3; attempt++) {
      const id = newInteractionId();
      const row = await this.db.get<{ id: string }>(
        `INSERT INTO session_request
           (id, team_id, channel, thread, user_id, provider, credential_id, created_at, expires_at)
         VALUES (?,?,?,?,?,?,?,${POSTGRES_NOW_MS_SQL},${POSTGRES_NOW_MS_SQL}+?)
         ON CONFLICT(team_id, channel, thread, user_id, provider) DO UPDATE SET
           id=excluded.id, credential_id=excluded.credential_id,
           created_at=excluded.created_at, expires_at=excluded.expires_at,
           delivery_token=NULL, delivery_lease_expires_at=0, delivered_at=NULL
         WHERE session_request.expires_at<=${POSTGRES_NOW_MS_SQL}
            OR session_request.credential_id<>excluded.credential_id
         RETURNING id`,
        [id, ...key, credentialId, PENDING_INTERACTION_TTL_MS],
      );
      if (row) return { id: row.id, created: true };

      // The conflict was a live row. Read it in a fresh statement so a concurrent INSERT/UPDATE
      // that ON CONFLICT waited for is visible under READ COMMITTED.
      const live = await this.db.get<{ id: string }>(
        `SELECT id FROM session_request
         WHERE team_id=? AND channel=? AND thread=? AND user_id=? AND provider=?
           AND credential_id=? AND expires_at>${POSTGRES_NOW_MS_SQL}`,
        [...key, credentialId],
      );
      if (live) return { id: live.id, created: false };
      // A concurrent click/sweep may have removed the conflict between the two statements. Retry
      // with a new opaque id rather than returning a handle that does not exist.
    }
    throw new Error('session request could not be recorded; retry');
  }

  /** Deduplicated request plus its canonical `request` audit companion in one transaction. The
   * creator alone writes the audit row; a repeated turn reuses the live opaque id without duplicate
   * request/audit. Slack delivery happens afterward; an unknown transport outcome retains its short
   * lease so a possibly-visible button remains decidable and an immediate retry cannot duplicate it. */
  async requestAudited(input: {
    identity: SlackIdentity;
    channel: string;
    thread: string;
    provider: string;
    credentialId: string;
    /** Trusted Bolt/headless receipt issuance in PostgreSQL's clock domain. */
    actorIssuedAt: number;
    audit: Audit;
    vault: Pick<Vault, 'withCredentialLocks'>;
    validate: (tx: Db) => Promise<boolean>;
  }): Promise<AuditedSessionRequestResult> {
    return input.vault.withCredentialLocks([
      { owner: channelOwner(input.identity.teamId, input.channel), provider: input.provider },
      { owner: userOwner(input.identity), provider: input.provider },
    ], async (locked, tx) => {
      const fenced = await withUserInteractionFence(
        tx,
        input.identity,
        input.actorIssuedAt,
        async (fencedTx): Promise<AuditedSessionRequestResult> => {
          if ((await locked.liveId(userOwner(input.identity), input.provider)) !== input.credentialId) {
            throw new InteractionStateChangedError('session', 'credential');
          }
          if (await new SessionGrants(fencedTx).isGranted(
            input.identity,
            input.channel,
            input.thread,
            input.provider,
            input.credentialId,
          )) {
            return { status: 'already-granted' };
          }
          if (!(await input.validate(fencedTx))) {
            throw new InteractionStateChangedError('session', 'authorization');
          }
          const result = await new SessionGrants(fencedTx).request(
            input.identity,
            input.channel,
            input.thread,
            input.provider,
            input.credentialId,
          );
          if (result.created) {
            await input.audit.record('session', input.identity, input.provider, {
              channel: input.channel,
              thread: input.thread,
              event: 'request',
            }, undefined, fencedTx);
          }
          return { status: 'requested', ...result };
        },
      );
      if (fenced.status === 'offboarded') {
        throw new InteractionStateChangedError('session', 'authorization');
      }
      return fenced.value;
    });
  }

  /** Claim Slack delivery without holding a DB transaction during the network call. Exactly one
   * replica owns the short lease; a delivered row is reusable, a live lease is reported honestly as
   * in-flight, and an expired lease can be taken over after a process crash. */
  async claimDelivery(
    id: string,
    options: PromptDeliveryOptions = {},
  ): Promise<PromptDeliveryClaim> {
    if (!isInteractionId(id)) return { status: 'stale' };
    for (let attempt = 0; attempt < 3; attempt++) {
      const token = newInteractionId();
      const claimed = await this.db.get<{ id: string }>(
        `UPDATE session_request
         SET delivery_token=?, delivery_lease_expires_at=${POSTGRES_NOW_MS_SQL}+?, delivered_at=NULL
         WHERE id=? AND expires_at>${POSTGRES_NOW_MS_SQL}
           AND (
             delivered_at IS NULL
             OR (?::boolean AND delivered_at <= ${POSTGRES_NOW_MS_SQL}-?)
           )
           AND (delivery_token IS NULL OR delivery_lease_expires_at<=${POSTGRES_NOW_MS_SQL})
         RETURNING id`,
        [
          token,
          PROMPT_DELIVERY_LEASE_MS,
          id,
          options.redeliverDelivered === true,
          PROMPT_REDELIVERY_DEBOUNCE_MS,
        ],
      );
      if (claimed) return { status: 'claimed', token };
      const row = await this.db.get<{
        delivered_at: number | null;
        delivery_lease_expires_at: number;
        now_ms: number;
      }>(
        `SELECT delivered_at, delivery_lease_expires_at, ${POSTGRES_NOW_MS_SQL} AS now_ms
         FROM session_request WHERE id=? AND expires_at>${POSTGRES_NOW_MS_SQL}`,
        [id],
      );
      if (!row) return { status: 'stale' };
      if (row.delivered_at != null) return { status: 'delivered' };
      if (row.delivery_lease_expires_at > row.now_ms) return { status: 'in-flight' };
    }
    return { status: 'in-flight' };
  }

  async confirmDelivery(id: string, token: string): Promise<boolean> {
    if (!isInteractionId(id) || !isInteractionId(token)) return false;
    return (await this.db.run(
      `UPDATE session_request SET delivered_at=${POSTGRES_NOW_MS_SQL}, delivery_token=NULL, delivery_lease_expires_at=0
       WHERE id=? AND delivery_token=? AND delivered_at IS NULL AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [id, token],
    )).changes === 1;
  }

  /** Release a failed delivery claim. A newly-created row is removed (the caller promised no
   * prompt); a takeover of a crashed older row retains the action/audit and becomes immediately
   * claimable by the next turn. */
  async abandonDelivery(id: string, token: string, remove: boolean): Promise<boolean> {
    if (!isInteractionId(id) || !isInteractionId(token)) return false;
    const result = remove
      ? await this.db.run(
        `DELETE FROM session_request WHERE id=? AND delivery_token=? AND delivered_at IS NULL`,
        [id, token],
      )
      : await this.db.run(
        `UPDATE session_request SET delivery_token=NULL, delivery_lease_expires_at=0
         WHERE id=? AND delivery_token=? AND delivered_at IS NULL`,
        [id, token],
      );
    return result.changes === 1;
  }

  /** Prompt-post rollback: remove only the row minted by this caller, never a context-wide row that
   *  a later request may have replaced. */
  async discardRequest(id: string): Promise<boolean> {
    if (!isInteractionId(id)) return false;
    return (await this.db.run(`DELETE FROM session_request WHERE id=?`, [id])).changes === 1;
  }

  /** Resolve only a live request bound to the verified click context. This authority-free read is
   *  used solely to choose the canonical provider lock; grantRequested() reloads and locks the row
   *  before any mutation. */
  async getRequest(
    id: string,
    identity: SlackIdentity,
    channel: string,
    thread: string,
  ): Promise<SessionRequestRow | null> {
    if (!isInteractionId(id)) return null;
    const row = await this.db.get<any>(
       `SELECT * FROM session_request
       WHERE id=? AND team_id=? AND user_id=? AND channel=? AND thread=?
         AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [id, identity.teamId, identity.userId, channel, thread],
    );
    return row ? toRequest(row) : null;
  }

  /**
   * Consume one request, create its thread grant, and append the canonical audit row in one
   * PostgreSQL transaction. The row is locked before `validate` re-resolves current provider/mode/
   * policy/tool state through the transaction-bound Db. A wrong context never consumes another
   * user's request. The signed click receipt and stored request creation are checked against every
   * applicable user-offboard scope under the same locks: a stale actor leaves the row untouched,
   * while a stale request or changed authorization is consumed without creating a grant.
   */
  async grantRequested(input: {
    id: string;
    identity: SlackIdentity;
    channel: string;
    thread: string;
    ttlMs: number;
    /** Trusted Bolt receipt issuance in PostgreSQL's clock domain. */
    actorIssuedAt: number;
    audit: Audit;
    validate: (row: SessionRequestRow, tx: Db) => Promise<boolean>;
  }): Promise<SessionGrantResult> {
    if (!isInteractionId(input.id)) return { status: 'stale' };
    const fenced = await withUserInteractionFence(
      this.db,
      input.identity,
      input.actorIssuedAt,
      async (tx): Promise<SessionGrantResult> => {
        const raw = await tx.get<any>(
          `SELECT * FROM session_request
           WHERE id=? AND team_id=? AND user_id=? AND channel=? AND thread=?
             AND expires_at>${POSTGRES_NOW_MS_SQL}
           FOR UPDATE`,
          [input.id, input.identity.teamId, input.identity.userId, input.channel, input.thread],
        );
        if (!raw) return { status: 'stale' };
        const row = toRequest(raw);
        if (!(await userInteractionIsCurrent(tx, input.identity, row.createdAt))) {
          await tx.run(`DELETE FROM session_request WHERE id=?`, [row.id]);
          return { status: 'invalidated' };
        }
        if (!(await input.validate(row, tx))) {
          await tx.run(`DELETE FROM session_request WHERE id=?`, [row.id]);
          return { status: 'invalidated' };
        }

        await tx.run(`DELETE FROM session_request WHERE id=?`, [row.id]);
        await tx.run(
          `INSERT INTO session_grant (team_id, channel, thread, user_id, provider, credential_id, created_at, expires_at)
           VALUES (?,?,?,?,?,?,${POSTGRES_NOW_MS_SQL},${POSTGRES_NOW_MS_SQL}+?)
           ON CONFLICT(team_id, channel, thread, user_id, provider) DO UPDATE SET
             credential_id=excluded.credential_id, created_at=excluded.created_at, expires_at=excluded.expires_at`,
          [row.teamId, row.channel, row.thread, row.userId, row.provider, row.credentialId, input.ttlMs],
        );
        await input.audit.record(
          'session',
          input.identity,
          row.provider,
          { channel: row.channel, thread: row.thread, event: 'grant' },
          undefined,
          tx,
        );
        return { status: 'granted', provider: row.provider };
      },
    );
    return fenced.status === 'current' ? fenced.value : { status: 'actor-stale' };
  }

  /** Direct grant for trusted/headless callers. The Bolt action path uses grantRequested() so its
   *  pending-row consume and audit companion are atomic. */
  async grant(
    i: SlackIdentity,
    channel: string,
    thread: string,
    provider: string,
    ttlMs: number,
    credentialId: string,
  ): Promise<void> {
    if (!isInteractionId(credentialId)) throw new Error('session grant requires a valid credential generation id');
    await this.db.run(
      `INSERT INTO session_grant (team_id, channel, thread, user_id, provider, credential_id, created_at, expires_at)
       VALUES (?,?,?,?,?,?,${POSTGRES_NOW_MS_SQL},${POSTGRES_NOW_MS_SQL}+?)
       ON CONFLICT(team_id, channel, thread, user_id, provider) DO UPDATE SET
         credential_id=excluded.credential_id, created_at=excluded.created_at, expires_at=excluded.expires_at`,
      [i.teamId, channel, thread, i.userId, provider, credentialId, ttlMs],
    );
  }

  /** Whether a non-expired grant exists for this exact thread context. */
  async isGranted(
    i: SlackIdentity,
    channel: string,
    thread: string,
    provider: string,
    credentialId: string,
  ): Promise<boolean> {
    if (!isInteractionId(credentialId)) return false;
    const row = (await this.db.get(
      `SELECT 1 AS x FROM session_grant
       WHERE team_id=? AND channel=? AND thread=? AND user_id=? AND provider=?
         AND credential_id=? AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [i.teamId, channel, thread, i.userId, provider, credentialId],
    )) as { x: number } | undefined;
    return !!row;
  }

  /** Exact credential generation authorized by a live thread grant. Empty legacy/trusted-test rows
   * return null to production callers, forcing a fresh approval against a real connection id. */
  async grantedCredentialId(
    i: SlackIdentity,
    channel: string,
    thread: string,
    provider: string,
  ): Promise<string | null> {
    const row = await this.db.get<{ credential_id: string }>(
      `SELECT credential_id FROM session_grant
       WHERE team_id=? AND channel=? AND thread=? AND user_id=? AND provider=?
         AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [i.teamId, channel, thread, i.userId, provider],
    );
    return row?.credential_id || null;
  }

  /** Revoke every grant and pending request for a user (offboarding). */
  async revokeForUser(i: SlackIdentity): Promise<void> {
    if (!this.db.transaction) throw new Error('session revocation requires database transaction support');
    await this.db.transaction(async (tx) => {
      await tx.run(`DELETE FROM session_request WHERE team_id=? AND user_id=?`, [i.teamId, i.userId]);
      await tx.run(`DELETE FROM session_grant WHERE team_id=? AND user_id=?`, [i.teamId, i.userId]);
    });
  }

  /** Revoke a user's grants and pending requests for one provider (break-glass invalidation). */
  async clearForProvider(teamId: string, userId: string, provider: string): Promise<void> {
    if (!this.db.transaction) throw new Error('session revocation requires database transaction support');
    await this.db.transaction(async (tx) => {
      await tx.run(
        `DELETE FROM session_request WHERE team_id=? AND user_id=? AND provider=?`,
        [teamId, userId, provider],
      );
      await tx.run(
        `DELETE FROM session_grant WHERE team_id=? AND user_id=? AND provider=?`,
        [teamId, userId, provider],
      );
    });
  }

  /** Delete expired grants and unanswered requests. The combined count preserves the original
   *  numeric return while making the standard sweep reclaim both state families. */
  async sweepExpired(): Promise<number> {
    if (!this.db.transaction) throw new Error('session sweep requires database transaction support');
    return this.db.transaction(async (tx) => {
      const requests = (await tx.run(`DELETE FROM session_request WHERE expires_at<${POSTGRES_NOW_MS_SQL}`)).changes;
      const grants = (await tx.run(`DELETE FROM session_grant WHERE expires_at<${POSTGRES_NOW_MS_SQL}`)).changes;
      return requests + grants;
    });
  }
}

/** Session grants and their pending controls are satellites of a user-owned credential. Every
 *  Vault write/delete calls this inside its own transaction, so disconnect, reconnect, reference
 *  replacement, expiry, and break-glass invalidation cannot leave old thread authority live.
 *  Channel owners never have session-mode grants. */
export async function purgeSessionsForOwner(db: Db, owner: Owner, provider: string): Promise<void> {
  if (owner.kind !== 'user') return;
  await db.run(
    `DELETE FROM session_request WHERE team_id=? AND user_id=? AND provider=?`,
    [owner.teamId, owner.id, provider],
  );
  await db.run(
    `DELETE FROM session_grant WHERE team_id=? AND user_id=? AND provider=?`,
    [owner.teamId, owner.id, provider],
  );
}
