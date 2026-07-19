import { createHmac, randomUUID } from 'node:crypto';
import type { Db } from './db';

/** One lifetime for unanswered, human-facing interaction requests. Pending rows are authority-free
 *  lookup handles, but keeping them short-lived bounds stale controls and retained metadata. */
export const PENDING_INTERACTION_TTL_MS = 10 * 60 * 1000;

/** A prompt delivery claim is deliberately much shorter than the pending interaction TTL. It
 * prevents duplicate Slack posts across replicas without holding a database transaction over
 * Slack I/O; after a crashed claimant's lease expires, another turn can take over. */
export const PROMPT_DELIVERY_LEASE_MS = 30_000;

/**
 * Re-delivery debounce (#194 UX). A private prompt (Connect / key-setup / session / approval) is a
 * Slack ephemeral that vanishes on reload/device-switch, which used to dead-end a user for the full
 * PENDING_INTERACTION_TTL_MS (10 min) because a delivered prompt was never re-posted. This debounce
 * lets a genuine re-ask RE-POST the SAME generation once its last delivery is older than the window,
 * while rapid/concurrent identical asks (Slack event retries, agent retry loops, two replicas) still
 * dedup to one prompt. The atomic delivery lease is the RACE guard; this is only the UX cooldown.
 * Same value as the lease (they are conceptually distinct; keep the constants separate so either can
 * change independently).
 */
export const PROMPT_REDELIVERY_DEBOUNCE_MS = 30_000;

/** PostgreSQL is the one clock for cross-replica delivery leases. Application clocks may differ by
 * more than the lease itself; using Date.now() here would let a fast pod steal a live claim. */
export const POSTGRES_NOW_MS_SQL = `(extract(epoch from clock_timestamp()) * 1000)::bigint`;

export type PromptDeliveryClaim =
  | { status: 'claimed'; token: string }
  | { status: 'delivered' | 'in-flight' | 'stale' };

export const INTERACTION_KINDS = Object.freeze(['connection', 'session', 'approval'] as const);
export type InteractionKind = (typeof INTERACTION_KINDS)[number];

export const INTERACTION_STATE_REASONS = Object.freeze([
  'credential',
  'authorization',
  'grant',
] as const);
export type InteractionStateReason = (typeof INTERACTION_STATE_REASONS)[number];

export function isInteractionKind(value: unknown): value is InteractionKind {
  return typeof value === 'string' && (INTERACTION_KINDS as readonly string[]).includes(value);
}

export function isInteractionStateReason(value: unknown): value is InteractionStateReason {
  return typeof value === 'string'
    && (INTERACTION_STATE_REASONS as readonly string[]).includes(value);
}

/** A local connection/authorization fact changed after a handle was resolved but before pending
 * authority could be recorded or used. Fixed messages are safe for Slack/HTTP; `reason` lets the
 * broker distinguish a reconnect conflict (409) from current access denial (403) without parsing. */
export class InteractionStateChangedError extends Error {
  readonly code = 'interaction_state_changed' as const;

  constructor(
    public readonly interaction: InteractionKind,
    public readonly reason: InteractionStateReason,
  ) {
    super(
      reason === 'credential'
        ? 'The connection changed while Vouchr was handling this request. Resolve it again and retry.'
        : 'Access changed while Vouchr was handling this request. Resolve current access and retry.',
    );
    if (!isInteractionKind(interaction) || !isInteractionStateReason(reason)) {
      throw new Error('invalid interaction state change');
    }
    this.name = 'InteractionStateChangedError';
  }
}

/** Opaque identifier carried by Slack controls and headless approval responses. It contains no
 *  provider, identity, channel, thread, endpoint, query, or credential material. */
export function newInteractionId(): string {
  return randomUUID();
}

/** Reject missing, oversized, and non-UUID control values before a database lookup. UUIDs are an
 *  implementation detail, not authority: every mutation still re-resolves the stored row and the
 *  verified caller context. */
export function isInteractionId(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

/** Independent exact-action fields covered by the bounded approval deduplication selector. Provider
 * is deliberately absent: the globally unique credential generation already binds it, and every
 * authoritative query separately compares the raw provider field. Kept transport-free so migration
 * can backfill old rows with the identical encoder production inserts use. */
export interface ApprovalActionFields {
  teamId: string;
  userId: string;
  ownerKind: string;
  ownerId: string;
  credentialId: string;
  method: string;
  origin: string;
  host: string;
  path: string;
  queryHash: string;
  channel: string | null;
  thread: string | null;
}

/**
 * Bounded, collision-resistant, per-credential-keyed selector for one exact approval action.
 * PostgreSQL btree index entries have a finite size while an allowlisted URL path may be several
 * kilobytes, so the unique index cannot safely contain every raw column. Length framing makes the
 * encoding unambiguous. `credentialId` is the globally unique connection-row generation and thus
 * already binds its provider; omitting the redundant provider id also keeps OAuth configuration
 * objects out of a cryptographic sink. Every SQL path still compares ALL raw fields, including
 * provider, after selecting by this digest, so the hash is never authority (a hypothetical collision
 * fails closed instead of reusing or consuming another action).
 */
export function approvalActionKey(k: ApprovalActionFields): string {
  const fields = [
    k.teamId,
    k.userId,
    k.ownerKind,
    k.ownerId,
    k.credentialId,
    k.method,
    k.origin,
    k.host,
    k.path,
    k.queryHash,
    k.channel ?? '',
    k.thread ?? '',
  ];
  // The random, non-public credential generation is the HMAC key. This is not password hashing:
  // it is a deterministic, domain-specific lookup/fingerprint that prevents low-entropy action
  // fields from being dictionary-reversible if the rendered digest is observed.
  const hash = createHmac('sha256', k.credentialId);
  for (const value of fields) {
    hash.update(String(Buffer.byteLength(value, 'utf8')));
    hash.update(':');
    hash.update(value);
  }
  return hash.digest('hex');
}

/** Newest committed channel/provider mutation. Setup requests compare this PostgreSQL-clock marker
 * with the verified handler receipt so work that began before a credential or governance change
 * cannot mint or consume authority afterward, even when Slack I/O delayed ticket persistence. */
export async function latestChannelInteractionTombstone(
  db: Db,
  teamId: string,
  channel: string,
  provider: string,
): Promise<number | null> {
  const row = await db.get<{ created_at: number }>(
    `SELECT created_at FROM channel_interaction_tombstone
     WHERE team_id=? AND channel=? AND provider=?`,
    [teamId, channel, provider],
  );
  return Number.isSafeInteger(row?.created_at) ? row!.created_at : null;
}

/**
 * Invalidate every pending control and live grant whose authority depends on one channel/provider
 * governance tuple. Mode and tool changes call this inside their already-locked mutation
 * transaction, so an enabled→disabled→enabled or session→per-user→session ABA cannot resurrect an
 * old decision. This is intentionally broader than credential-owner satellite cleanup: it covers
 * both user- and channel-owned approvals, every user's thread session, and every outstanding
 * channel-credential setup request for the tuple.
 */
export async function purgeChannelInteractionState(
  db: Db,
  teamId: string,
  channel: string,
  provider: string,
): Promise<void> {
  const clock = await db.get<{ created_at: number }>(
    `SELECT ${POSTGRES_NOW_MS_SQL} AS created_at`,
  );
  if (!Number.isSafeInteger(clock?.created_at)) {
    throw new Error('could not establish channel interaction fence');
  }
  await db.run(
    `INSERT INTO channel_interaction_tombstone
       (team_id, channel, provider, created_at) VALUES (?,?,?,?)
     ON CONFLICT(team_id, channel, provider) DO UPDATE SET created_at=GREATEST(
       channel_interaction_tombstone.created_at,
       excluded.created_at
     )`,
    [teamId, channel, provider, clock!.created_at],
  );
  await db.run(
    `DELETE FROM session_request WHERE team_id=? AND channel=? AND provider=?`,
    [teamId, channel, provider],
  );
  await db.run(
    `DELETE FROM session_grant WHERE team_id=? AND channel=? AND provider=?`,
    [teamId, channel, provider],
  );
  await db.run(
    `DELETE FROM approval_request WHERE team_id=? AND channel=? AND provider=?`,
    [teamId, channel, provider],
  );
  await db.run(
    `DELETE FROM channel_provisioning_request WHERE team_id=? AND channel=? AND provider=?`,
    [teamId, channel, provider],
  );
}
