import { createHash, randomUUID } from 'node:crypto';
import type { Db } from './db';
import type { Owner } from './owner';

/**
 * Canonical digest of a request's query string, bound into the approval key (GHSA-pg84): a grant
 * for `POST /transfer?to=alice&amount=10` must never be spendable on
 * `POST /transfer?to=attacker&amount=1000000`. A DIGEST, never the raw values — query values can
 * carry PII or secrets, so they are never persisted or audited (SEC-1); the human-facing prompt
 * renders the live query from the in-memory error instead. Canonical = URLSearchParams entries
 * sorted by key then value and re-serialized, so parameter order and encoding variants of the SAME
 * parameters match while any changed key or value re-prompts. '' (no parameters) stays '', which
 * also makes pre-migration rows (DEFAULT '') behave correctly: an old grant still matches a
 * query-less request and fails closed (re-prompts) for any query-carrying one.
 */
export function queryDigest(search: string): string {
  const entries = [...new URLSearchParams(search)];
  if (!entries.length) return '';
  entries.sort(([ak, av], [bk, bv]) => (ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0));
  return createHash('sha256').update(new URLSearchParams(entries).toString()).digest('hex');
}

/** Default validity of an approval once granted (#113): 5 minutes, unless the provider sets ttlMs. */
export const DEFAULT_APPROVAL_TTL_MS = 5 * 60 * 1000;

/** How long an unanswered approval prompt stays decidable — same lifetime as a consent state. */
const PENDING_TTL_MS = 10 * 60 * 1000;

/**
 * Thrown by the injector when a request matches a provider's `approval` predicate and no live,
 * matching, unconsumed grant exists (#113). Control flow, exactly like ConsentRequiredError: the
 * Bolt adapter posts Approve/Deny buttons and the caller stops the turn; the headless broker maps
 * it to 403 `{ error: 'approval_required', approvalId }`. The message is Vouchr-authored and
 * secret-free (method/host/path only — never the body, a token, or a query string).
 */
export class ApprovalRequiredError extends Error {
  constructor(
    public provider: string,
    /** Who may decide: 'self' = the acting user; 'admin' = an eligible channel admin. */
    public approver: 'self' | 'admin',
    public method: string,
    public host: string,
    public path: string,
    /** The pending approval-request id the Approve/Deny surface decides on. */
    public approvalId: string,
    /**
     * The raw query string (`url.search`, '' when none) — DISPLAY ONLY, so the Approve/Deny prompt
     * can show the human exactly what they are approving (GHSA-pg84). Carried in memory on the
     * typed error, never in the message (host apps log messages), never persisted, never audited:
     * the store binds the canonical digest instead (see queryDigest).
     */
    public query: string = '',
  ) {
    super(
      `Approval required: ${method} ${host}${path} on provider "${provider}" needs ` +
        `${approver === 'admin' ? "an admin's" : 'your'} approval before it can run.`,
    );
    this.name = 'ApprovalRequiredError';
  }
}

/**
 * The exact action a grant covers. Matching is EXACT on every field — not a prefix, not a pattern:
 * the human approved one action, not a class of actions. `queryHash` binds the exact (canonical)
 * query parameters (GHSA-pg84, see queryDigest) — as a digest, never raw values. The request BODY
 * remains outside the key; see the threat model — for body-parameterized APIs approval covers the
 * endpoint + method + query, NOT the payload bytes. `channel`/`thread` bind the grant to the
 * conversation context it was requested from (null = none, stored as '').
 *
 * Two identities are carried SEPARATELY (never conflated):
 *  - `userId`: the REQUESTER (the human driving the agent — the caller, not the borrowed union
 *    member). Who is prompted, and who self-approval matches.
 *  - `ownerKind`/`ownerId`: the CREDENTIAL OWNER the grant is bound to. consume() matches it too, so
 *    if resolution later picks a different owner (a union member switch A→B, or a per-user→shared
 *    mode change), the grant no longer matches and re-prompts — the write can never run against a
 *    different credential than the human approved. It is also the purge key (purgeApprovalsForOwner).
 */
export interface ApprovalKey {
  teamId: string;
  userId: string;
  ownerKind: Owner['kind'];
  ownerId: string;
  provider: string;
  method: string;
  host: string;
  path: string;
  /** queryDigest(url.search): canonical query digest, '' when the request has no parameters. */
  queryHash: string;
  channel: string | null;
  thread: string | null;
}

/** One pending request / unspent grant, as the approve/deny surface and the sweep read it. */
export interface ApprovalRow extends ApprovalKey {
  id: string;
  status: 'pending' | 'granted';
  approvedBy: string | null;
  createdAt: number;
  expiresAt: number;
}

function toRow(r: any): ApprovalRow {
  return {
    id: r.id,
    teamId: r.team_id,
    userId: r.user_id,
    ownerKind: r.owner_kind,
    ownerId: r.owner_id,
    provider: r.provider,
    method: r.method,
    host: r.host,
    path: r.path,
    queryHash: r.query_hash ?? '',
    channel: r.channel || null,
    thread: r.thread || null,
    status: r.status,
    approvedBy: r.approved_by ?? null,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
  };
}

/**
 * Human-in-the-loop approval requests/grants for sensitive writes (#113). Lifecycle: the injector
 * `request()`s a pending row and throws ApprovalRequiredError; a human decision `approve()`s it into
 * a TTL-bound grant (or `deny()`s it); the retried fetch `consume()`s the grant — SINGLE-USE, via
 * the same atomic `DELETE ... RETURNING` pattern as the OAuth consent state, so two concurrent
 * retries can never both spend one approval. Expired rows (unanswered prompts and unspent grants)
 * are reclaimed by `sweepExpired()`.
 */
export class Approvals {
  constructor(private db: Db) {}

  /** Record a pending approval request for one exact action; returns its id (the button/403 handle). */
  async request(k: ApprovalKey): Promise<string> {
    const id = randomUUID();
    const now = Date.now();
    await this.db.run(
      `INSERT INTO approval_request
         (id, team_id, user_id, owner_kind, owner_id, provider, method, host, path, query_hash, channel, thread, status, approved_by, created_at, expires_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'pending',NULL,?,?)`,
      [id, k.teamId, k.userId, k.ownerKind, k.ownerId, k.provider, k.method, k.host, k.path, k.queryHash, k.channel ?? '', k.thread ?? '', now, now + PENDING_TTL_MS],
    );
    return id;
  }

  /** A live PENDING request by id, for the approve/deny surface. Null if absent, expired, or decided. */
  async get(id: string): Promise<ApprovalRow | null> {
    const row = await this.db.get<any>(
      `SELECT * FROM approval_request WHERE id=? AND status='pending' AND expires_at>?`,
      [id, Date.now()],
    );
    return row ? toRow(row) : null;
  }

  /**
   * Flip a pending request into a single-use grant valid `ttlMs` from now, recording who approved.
   * Atomic on status='pending': two concurrent decisions can't both win. False = already decided,
   * expired, or absent (the caller treats it as "nothing to do", never a second grant).
   */
  async approve(id: string, approvedBy: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    const { changes } = await this.db.run(
      `UPDATE approval_request SET status='granted', approved_by=?, expires_at=?
       WHERE id=? AND status='pending' AND expires_at>?`,
      [approvedBy, now + ttlMs, id, now],
    );
    return changes === 1;
  }

  /** Deny (delete) a pending request. Returns the row for the audit/notify pair, or null if gone. */
  async deny(id: string): Promise<ApprovalRow | null> {
    const row = await this.db.get<any>(
      `DELETE FROM approval_request WHERE id=? AND status='pending' RETURNING *`,
      [id],
    );
    return row ? toRow(row) : null;
  }

  /**
   * Consume (single-use) one live grant matching the EXACT action key. The atomic
   * `DELETE ... RETURNING` (see Consent.consume) is what makes a grant spend-once even for two
   * concurrent identical fetches — a get-then-delete would let both pass on multi-instance Postgres.
   * Returns the approver for audit attribution, or null when no live grant matches.
   */
  async consume(k: ApprovalKey): Promise<{ approvedBy: string | null } | null> {
    const row = await this.db.get<any>(
      `DELETE FROM approval_request WHERE id = (
         SELECT id FROM approval_request
          WHERE team_id=? AND user_id=? AND owner_kind=? AND owner_id=? AND provider=? AND method=? AND host=? AND path=? AND query_hash=?
            AND channel=? AND thread=? AND status='granted' AND expires_at>?
          LIMIT 1
       ) RETURNING approved_by`,
      [k.teamId, k.userId, k.ownerKind, k.ownerId, k.provider, k.method, k.host, k.path, k.queryHash, k.channel ?? '', k.thread ?? '', Date.now()],
    );
    return row ? { approvedBy: row.approved_by ?? null } : null;
  }

  /** Delete expired rows (unanswered prompts AND unspent grants), returning them so the sweep can
   *  audit each expiry. Run on the same timer as the connection TTL sweep. */
  async sweepExpired(): Promise<ApprovalRow[]> {
    const rows = await this.db.all<any>(
      `DELETE FROM approval_request WHERE expires_at<? RETURNING *`,
      [Date.now()],
    );
    return rows.map(toRow);
  }
}

/**
 * Delete every approval row (pending AND granted) bound to this credential owner + provider. The ONE
 * purge the vault runs inside its mutation transaction on EVERY connection write/delete (upsert,
 * reference, delete — which is the single surface disconnect / offboard / bulk-revoke / reconnect /
 * TTL-expiry all route through, STR-3): a grant must never outlive the credential it authorizes, nor
 * be spent after a reconnect/reconfiguration. Runs on the passed Db so it joins the caller's
 * transaction. A plain function (not an Approvals method) so the vault calls it without constructing
 * the store; the DELETE SQL lives HERE, once (STR-2).
 */
export async function purgeApprovalsForOwner(db: Db, owner: Owner, provider: string): Promise<void> {
  await db.run(
    `DELETE FROM approval_request WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
    [owner.teamId, owner.kind, owner.id, provider],
  );
}
