import { createHash } from 'node:crypto';
import type { Audit, AuditMeta } from './audit';
import { authorizeProvider, resolveCredentialOwner } from './authz';
import { ChannelConfig } from './channelConfig';
import {
  userInteractionIsCurrent,
  withUserInteractionFence,
  withUserInteractionFences,
} from './consent';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import {
  approvalActionKey,
  InteractionStateChangedError,
  isInteractionId,
  newInteractionId,
  PENDING_INTERACTION_TTL_MS,
  POSTGRES_NOW_MS_SQL,
  PROMPT_DELIVERY_LEASE_MS,
  PROMPT_REDELIVERY_DEBOUNCE_MS,
  type PromptDeliveryClaim,
  type PromptDeliveryOptions,
} from './interaction';
import { channelOwner, userOwner, type Owner } from './owner';
import type { Policy } from './policy';
import { isBrokeredProvider, type ProviderRegistry } from './providers';
import { SessionGrants } from './session';
import { ChannelTools } from './tools';
import type { Vault } from './vault';

/**
 * Digest of the EXACT query string sent upstream, bound into the approval key (GHSA-pg84): a grant
 * for `POST /transfer?to=alice&amount=10` must never be spendable on
 * `POST /transfer?to=attacker&amount=1000000`. A DIGEST, never the raw values — query values can
 * carry PII or secrets, so they are never persisted or audited (SEC-1).
 *
 * Byte-exact on purpose — no parsing, no sorting, no normalization: upstream parsers legitimately
 * treat reordered or duplicated parameters differently (`?amount=10&amount=1000000` vs its
 * reverse picks a different amount on first-wins vs last-wins servers), so ANY textual change is a
 * different action and must re-prompt. Fail-closed beats convenient: a semantically-identical
 * reordered retry re-prompts. Mint and consume both read `url.search` off the same WHATWG-parsed
 * URL the injector sends, so the hashed representation is exactly what goes upstream.
 *
 * '' (no query) stays '' — and pre-v5 rows are stamped with a `'pre-v5'` sentinel (see db.ts)
 * that no live digest can equal, so a legacy query-bearing grant can never authorize a queryless
 * request.
 */
export function queryDigest(search: string): string {
  if (!search || search === '?') return '';
  return createHash('sha256').update(search).digest('hex');
}

/** Finite low-layer path bound for in-process handles (HTTP has an independent request cap). The
 * exact raw path is short-lived authority and must never grow persistence/hash work without limit. */
export const MAX_APPROVAL_PATH_BYTES = 16 * 1024;

export class ApprovalPathTooLongError extends Error {
  readonly code = 'approval_path_too_large' as const;

  constructor() {
    super('The approval action path is too large. Narrow the endpoint and retry.');
    this.name = 'ApprovalPathTooLongError';
  }
}

function assertApprovalPathBounded(path: string): void {
  if (Buffer.byteLength(path, 'utf8') > MAX_APPROVAL_PATH_BYTES) {
    throw new ApprovalPathTooLongError();
  }
}

/** Bounded, per-credential-keyed representation for human surfaces, public errors, and audit.
 * `action_key` covers the random, non-output credential generation plus every independent action
 * discriminator (the generation already binds its provider), so unlike a bare path hash it is not
 * dictionary-reversible for low-entropy PII. Authority still compares every raw field. */
export function approvalActionFingerprint(key: ApprovalKey): string {
  return `hmac-sha256:${approvalActionKey(key)}`;
}

/** Opaque, row-specific digest of the exact recipient class/set whose current prompt delivery may
 * be reused. Slack membership/admin reads stay in Bolt, but only this bounded digest is persisted;
 * a self→admin rule change or admin-roster change therefore cannot inherit another audience's
 * delivered marker. */
export function approvalDeliveryAudienceKey(
  approvalId: string,
  approver: 'self' | 'admin',
  recipients: readonly string[],
): string {
  if (!isInteractionId(approvalId) || (approver !== 'self' && approver !== 'admin')) {
    throw new Error('invalid approval delivery audience');
  }
  const normalized = [...new Set(recipients)].sort();
  if (
    (approver === 'self' && normalized.length !== 1)
    || normalized.some((recipient) => (
      typeof recipient !== 'string' || recipient.length === 0 || recipient.length > 255
    ))
  ) {
    throw new Error('invalid approval delivery audience');
  }
  const hash = createHash('sha256');
  for (const value of ['vouchr-approval-audience-v1', approvalId, approver, ...normalized]) {
    hash.update(String(Buffer.byteLength(value, 'utf8')));
    hash.update(':');
    hash.update(value);
  }
  return hash.digest('hex');
}

/** Default validity of an approval once granted (#113): 5 minutes, unless the provider sets ttlMs. */
export const DEFAULT_APPROVAL_TTL_MS = 5 * 60 * 1000;

/**
 * Thrown by the injector when a request matches a provider's `approval` predicate and no live,
 * matching, unconsumed grant exists (#113). Control flow, exactly like ConsentRequiredError: the
 * Bolt adapter posts Approve/Deny buttons and the caller stops the turn; the headless broker maps
 * it to 403 `{ error: 'approval_required', approvalId }`. The message is Vouchr-authored and
 * secret-free (method/host/salted action fingerprint only — never the raw path, body, token, or query string).
 */
export class ApprovalRequiredError extends Error {
  readonly code = 'approval_required' as const;

  constructor(
    public provider: string,
    /** Who may decide: 'self' = the acting user; 'admin' = an eligible channel admin. */
    public approver: 'self' | 'admin',
    public method: string,
    public host: string,
    /** Bounded keyed digest only. Raw caller-controlled action fields never reach errors/Slack. */
    public actionFingerprint: string,
    /** The pending approval-request id the Approve/Deny surface decides on. */
    public approvalId: string,
    /**
     * How many query parameters the request carries — the ONLY query-derived thing the error (and
     * thus the Slack prompt and any error serializer) exposes. Parameter names are as
     * caller-controlled as values (`?ghp_token…=`, `?john@example.com=`), so neither may reach
     * Slack, logs, storage, or audit (SEC-1); the store binds the byte-exact digest instead (see
     * queryDigest). A provider-declared safe action renderer is the future shape if humans must
     * inspect action-defining fields.
     */
    public queryParamCount: number = 0,
    /** True only when this fetch created the deduplicated pending row. Bolt posts one prompt for
     *  that creator; repeated turns reuse the opaque id without posting or auditing duplicates. */
    public newRequest: boolean = true,
  ) {
    // Structured fields feed the bounded Block Kit renderer. The public message stays fixed-size:
    // safeUserMessage returns it verbatim, so embedding a valid multi-block path here would recreate
    // Slack's 40k overflow outside the renderer.
    super(`Approval required for provider "${provider}". Use the approval prompt before retrying.`);
    this.name = 'ApprovalRequiredError';
  }
}

/**
 * The exact action a grant covers. Matching is EXACT on every field — not a prefix, not a pattern:
 * the human approved one action, not a class of actions. `origin` binds scheme + host + effective
 * port, while `host` remains the hostname-only observability field. `queryHash` binds the exact
 * (canonical) query parameters (GHSA-pg84, see queryDigest) — as a digest, never raw values. The
 * request BODY remains outside the key; see the threat model — for body-parameterized APIs approval
 * covers the origin + endpoint + method + query, NOT the payload bytes. `channel`/`thread` bind the grant to the
 * conversation context it was requested from (null = none, stored as '').
 *
 * Two identities are carried SEPARATELY (never conflated):
 *  - `userId`: the REQUESTER (the human driving the agent — the caller). Who is prompted, and who
 *    self-approval matches.
 *  - `ownerKind`/`ownerId`: the CREDENTIAL OWNER the grant is bound to. consume() matches it too, so
 *    if resolution later picks a different owner (a per-user→shared mode change), the grant no longer
 *    matches and re-prompts — the write can never run against a different credential than the human
 *    approved. It is also the purge key (purgeApprovalsForOwner).
 */
export interface ApprovalKey {
  teamId: string;
  userId: string;
  ownerKind: Owner['kind'];
  ownerId: string;
  /** Exact connection row generation this action would use. Reconnect mints a new id. */
  credentialId: string;
  provider: string;
  method: string;
  /** WHATWG URL.origin: canonical scheme + host + effective port. Never rendered or audited raw. */
  origin: string;
  /** Hostname-only observability/render field; authority also requires the exact `origin`. */
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

/** Result of one persisted approval-button decision. `invalidated` means the stored action no
 * longer matches current provider/governance/owner state and was removed without creating either
 * a grant or a denial; `ineligible` leaves it pending for a legitimate approver. */
export type ApprovalDecisionResult =
  | { status: 'decided'; row: ApprovalRow }
  | { status: 'stale' | 'invalidated' | 'ineligible' | 'actor-stale' };

/**
 * Re-resolve every database-backed fact that determines which credential a pending action would
 * use. This runs inside the same locked transaction as the decision: a mode/tool writer cannot
 * change the answer between this check and the grant. Provider definitions and Policy are immutable
 * for one process; the caller separately rechecks the current provider approval rule and Slack-side
 * approver eligibility in the decision callback.
 */
export interface CredentialUseValidationInput {
  binding: Pick<
    ApprovalKey,
    'teamId' | 'userId' | 'ownerKind' | 'ownerId' | 'credentialId' | 'provider' | 'channel' | 'thread'
  >;
  db: Db;
  registry: ProviderRegistry;
  policy?: Policy;
  vault: Pick<Vault, 'liveId'>;
  enterpriseId?: string | null;
  /** Trusted Bolt receipt / headless assertion issuance in PostgreSQL's clock domain. */
  actorIssuedAt: number;
  /** `undefined` = core/Bolt default store; `null` = this adapter deliberately did not opt in. */
  channelTools?: ChannelTools | null;
  /** `undefined` = core/Bolt default store; `null` = historical per-user/no-mode semantics. */
  channelConfig?: ChannelConfig | null;
}

async function credentialUseStateForCurrentActor(
  input: CredentialUseValidationInput,
  principal: SlackIdentity,
): Promise<'current' | 'authorization' | 'credential'> {
  const { binding: row, db } = input;
  if (!input.registry.has(row.provider) || !isBrokeredProvider(input.registry.get(row.provider))) {
    return 'authorization';
  }

  const channelTools = input.channelTools === undefined ? new ChannelTools(db) : input.channelTools ?? undefined;
  if ((await authorizeProvider(input.policy, channelTools, principal, row.channel, row.provider, db)) !== null) {
    return 'authorization';
  }

  const channelConfig = input.channelConfig === undefined ? new ChannelConfig(db) : input.channelConfig;
  const mode = row.channel && channelConfig
    ? await channelConfig.getMode(row.teamId, row.channel, row.provider, db)
    : null;
  let resolved: ReturnType<typeof resolveCredentialOwner>;
  if (mode === 'shared') {
    resolved = resolveCredentialOwner({
      path: 'channel', mode, principal, channel: row.channel, eligible: row.channel !== null,
    });
  } else {
    const sessionCredentialId = mode === 'session' && row.channel && row.thread
      ? await new SessionGrants(db).grantedCredentialId(principal, row.channel, row.thread, row.provider)
      : null;
    resolved = resolveCredentialOwner({
      path: 'user', mode, principal, channel: row.channel, thread: row.thread,
      hasSessionGrant: sessionCredentialId === row.credentialId,
    });
  }
  if (
    resolved.status !== 'resolved' ||
    resolved.owner.kind !== row.ownerKind ||
    resolved.owner.id !== row.ownerId
  ) return 'authorization';
  return (await input.vault.liveId(resolved.owner, row.provider)) === row.credentialId
    ? 'current'
    : 'credential';
}

/** Classify a retained handle's binding under its lifecycle locks. Governance is checked before the
 * exact live credential generation so a mode/tool/session change remains an authorization failure
 * even when that writer also removed the formerly selected credential. */
export async function credentialUseState(
  input: CredentialUseValidationInput,
): Promise<'current' | 'authorization' | 'credential'> {
  const { binding: row, db } = input;
  const principal: SlackIdentity = {
    enterpriseId: input.enterpriseId ?? null,
    teamId: row.teamId,
    userId: row.userId,
  };
  if (!(await userInteractionIsCurrent(db, principal, input.actorIssuedAt))) {
    return 'authorization';
  }
  return credentialUseStateForCurrentActor(input, principal);
}

/** Retained-use/request form: keep the actor's offboard lock through the caller's surrounding
 * credential transaction so a pre-offboard assertion cannot validate and then persist authority. */
export async function credentialUseStateFenced(
  input: CredentialUseValidationInput,
): Promise<'current' | 'authorization' | 'credential'> {
  const principal: SlackIdentity = {
    enterpriseId: input.enterpriseId ?? null,
    teamId: input.binding.teamId,
    userId: input.binding.userId,
  };
  const fenced = await withUserInteractionFence(
    input.db,
    principal,
    input.actorIssuedAt,
    (tx) => credentialUseStateForCurrentActor({ ...input, db: tx }, principal),
  );
  return fenced.status === 'current' ? fenced.value : 'authorization';
}

export async function credentialUseStillCurrent(
  input: CredentialUseValidationInput,
): Promise<boolean> {
  return (await credentialUseState(input)) === 'current';
}

export async function credentialUseStillCurrentFenced(
  input: CredentialUseValidationInput,
): Promise<boolean> {
  return (await credentialUseStateFenced(input)) === 'current';
}

/** Approval-specific wrapper retained as the single validation call for request/decision paths. */
export async function approvalOwnerStillCurrent(input: {
  row: ApprovalKey;
  db: Db;
  registry: ProviderRegistry;
  policy?: Policy;
  vault: Pick<Vault, 'liveId'>;
  enterpriseId?: string | null;
  actorIssuedAt: number;
  channelTools?: ChannelTools | null;
  channelConfig?: ChannelConfig | null;
}): Promise<boolean> {
  return credentialUseStillCurrent({
    binding: input.row,
    db: input.db,
    registry: input.registry,
    policy: input.policy,
    vault: input.vault,
    enterpriseId: input.enterpriseId,
    actorIssuedAt: input.actorIssuedAt,
    channelTools: input.channelTools,
    channelConfig: input.channelConfig,
  });
}

/** Owners whose lifecycle locks fence an approval decision. The channel owner is always included
 * for channel-bound actions because mode/tool governance writers use that lock; the stored owner
 * fences reconnect/disconnect, and the projected current owner covers the pre-lock mode snapshot.
 * Vault canonicalizes and de-duplicates the returned keys. */
export function approvalDecisionLockOwners(
  row: ApprovalRow,
  currentMode: 'per-user' | 'shared' | 'session' | null,
): Owner[] {
  const stored: Owner = { teamId: row.teamId, kind: row.ownerKind, id: row.ownerId };
  if (!row.channel) return [stored];
  const governance = channelOwner(row.teamId, row.channel);
  const projected = currentMode === 'shared'
    ? governance
    : userOwner({ enterpriseId: null, teamId: row.teamId, userId: row.userId });
  return [governance, stored, projected];
}

function toRow(r: any): ApprovalRow {
  return {
    id: r.id,
    teamId: r.team_id,
    userId: r.user_id,
    ownerKind: r.owner_kind,
    ownerId: r.owner_id,
    credentialId: r.credential_id,
    provider: r.provider,
    method: r.method,
    origin: r.origin,
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
 * atomic `DELETE ... RETURNING`, so two concurrent retries can never both spend one approval.
 * Expired rows (unanswered prompts and unspent grants) are reclaimed by `sweepExpired()`.
 */
export class Approvals {
  constructor(private db: Db) {}

  /** Re-resolve the database-backed authority for a row through the canonical approval validator.
   * The recovery bridge has an Approvals instance but deliberately has no raw Db handle; keeping
   * this adapter on the store prevents it from copying the mode/session/offboard/credential checks.
   * This is a delivery-time fail-closed snapshot only. The decision mutation still repeats the
   * validation while holding its lifecycle locks. */
  async ownerStillCurrent(
    row: ApprovalKey,
    input: Omit<CredentialUseValidationInput, 'binding' | 'db'>,
  ): Promise<boolean> {
    return approvalOwnerStillCurrent({ row, db: this.db, ...input });
  }

  private keyParams(k: ApprovalKey): unknown[] {
    return [
      k.teamId,
      k.userId,
      k.ownerKind,
      k.ownerId,
      k.credentialId,
      k.provider,
      k.method,
      k.origin,
      k.host,
      k.path,
      k.queryHash,
      k.channel ?? '',
      k.thread ?? '',
    ];
  }

  private auditMeta(k: ApprovalKey, extra: AuditMeta = {}): AuditMeta {
    return {
      host: k.host,
      method: k.method,
      actionFingerprint: approvalActionFingerprint(k),
      ...(k.channel ? { channel: k.channel } : {}),
      ...extra,
    };
  }

  /** Insert or reuse the one live row for an exact action. The unique action index linearizes two
   *  replicas; an expired row is atomically replaced. A live granted row may win the consume→request
   *  race, in which case its id is returned without a duplicate prompt and the caller retries. */
  private async requestOn(db: Db, k: ApprovalKey): Promise<{ id: string; created: boolean }> {
    if (!isInteractionId(k.credentialId)) {
      throw new Error('approval request requires a valid credential generation id');
    }
    assertApprovalPathBounded(k.path);
    const params = this.keyParams(k);
    const actionKey = approvalActionKey(k);
    for (let attempt = 0; attempt < 3; attempt++) {
      const id = newInteractionId();
      const row = await db.get<{ id: string }>(
        `INSERT INTO approval_request
           (id, action_key, team_id, user_id, owner_kind, owner_id, credential_id, provider, method, origin, host, path, query_hash,
            channel, thread, status, approved_by, created_at, expires_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',NULL,${POSTGRES_NOW_MS_SQL},${POSTGRES_NOW_MS_SQL}+?)
         ON CONFLICT(action_key) DO UPDATE SET
           id=excluded.id, status='pending', approved_by=NULL,
           created_at=excluded.created_at, expires_at=excluded.expires_at,
           delivery_token=NULL, delivery_lease_expires_at=0, delivered_at=NULL,
           delivery_audience=NULL
         WHERE approval_request.team_id=excluded.team_id
           AND approval_request.user_id=excluded.user_id
           AND approval_request.owner_kind=excluded.owner_kind
           AND approval_request.owner_id=excluded.owner_id
           AND approval_request.credential_id=excluded.credential_id
           AND approval_request.provider=excluded.provider
           AND approval_request.method=excluded.method
           AND approval_request.origin=excluded.origin
           AND approval_request.host=excluded.host
           AND approval_request.path=excluded.path
           AND approval_request.query_hash=excluded.query_hash
           AND approval_request.channel=excluded.channel
           AND approval_request.thread=excluded.thread
           AND approval_request.expires_at<=${POSTGRES_NOW_MS_SQL}
         RETURNING id`,
        [id, actionKey, ...params, PENDING_INTERACTION_TTL_MS],
      );
      if (row) return { id: row.id, created: true };
      const live = await db.get<{ id: string }>(
        `SELECT id FROM approval_request
         WHERE action_key=?
           AND team_id=? AND user_id=? AND owner_kind=? AND owner_id=? AND credential_id=? AND provider=?
           AND method=? AND origin=? AND host=? AND path=? AND query_hash=? AND channel=? AND thread=?
           AND expires_at>${POSTGRES_NOW_MS_SQL}`,
        [actionKey, ...params],
      );
      if (live) return { id: live.id, created: false };
    }
    throw new Error('approval request could not be recorded; retry');
  }

  /** Low-level internal request primitive. Production injector paths use
   *  requestAudited() so the mutation and canonical audit row commit together. */
  async request(k: ApprovalKey): Promise<string> {
    return (await this.requestOn(this.db, k)).id;
  }

  /** Deduplicated request plus `approval_requested` audit in one transaction. Reuse writes no
   *  duplicate audit row and tells Bolt not to post another prompt. */
  async requestAudited(
    k: ApprovalKey,
    audit: Audit,
    acting: SlackIdentity,
    vault?: Pick<Vault, 'withCredentialLocks'>,
    validate?: (key: ApprovalKey, tx: Db, locked: Pick<Vault, 'liveId'>) => Promise<boolean>,
  ): Promise<{ id: string; created: boolean }> {
    const write = async (tx: Db) => {
      const result = await this.requestOn(tx, k);
      if (result.created) {
        await audit.record('approval_requested', acting, k.provider, this.auditMeta(k), undefined, tx);
      }
      return result;
    };
    if (vault) {
      const owner: Owner = { teamId: k.teamId, kind: k.ownerKind, id: k.ownerId };
      const scopes = [
        { owner, provider: k.provider },
        ...(k.channel ? [{ owner: channelOwner(k.teamId, k.channel), provider: k.provider }] : []),
      ];
      return vault.withCredentialLocks(scopes, async (locked, tx) => {
        if ((await locked.liveId(owner, k.provider)) !== k.credentialId) {
          throw new InteractionStateChangedError('approval', 'credential');
        }
        if ((!validate && k.channel) || (validate && !(await validate(k, tx, locked)))) {
          throw new InteractionStateChangedError('approval', 'authorization');
        }
        return write(tx);
      });
    }
    if (!this.db.transaction) throw new Error('approval requests require database transaction support');
    return this.db.transaction(write);
  }

  /** Cross-replica Slack-delivery lease, bound to the current exact recipient class/set. Headless
   * callers do not claim it; Bolt derives the audience from current Slack facts immediately before
   * posting. No transaction/advisory lock is held over Slack I/O. */
  async claimDelivery(
    id: string,
    audience: string,
    options: PromptDeliveryOptions = {},
  ): Promise<PromptDeliveryClaim> {
    if (!isInteractionId(id) || !/^[0-9a-f]{64}$/.test(audience)) return { status: 'stale' };
    for (let attempt = 0; attempt < 3; attempt++) {
      const token = newInteractionId();
      // A changed audience always needs a fresh decision surface. Re-delivery to the same audience
      // remains an explicit adapter decision because some private surfaces are durable messages.
      const claimed = await this.db.get<{ id: string }>(
        `UPDATE approval_request
         SET delivery_token=?, delivery_lease_expires_at=${POSTGRES_NOW_MS_SQL}+?,
             delivered_at=NULL, delivery_audience=?
         WHERE id=? AND status='pending' AND expires_at>${POSTGRES_NOW_MS_SQL}
           AND (
             delivery_token IS NULL OR delivery_lease_expires_at<=${POSTGRES_NOW_MS_SQL}
           )
           AND (
             delivery_audience IS DISTINCT FROM ? OR delivered_at IS NULL
             OR (?::boolean AND delivered_at <= ${POSTGRES_NOW_MS_SQL}-?)
           )
         RETURNING id`,
        [
          token,
          PROMPT_DELIVERY_LEASE_MS,
          audience,
          id,
          audience,
          options.redeliverDelivered === true,
          PROMPT_REDELIVERY_DEBOUNCE_MS,
        ],
      );
      if (claimed) return { status: 'claimed', token };
      const row = await this.db.get<{
        delivered_at: number | null;
        delivery_token: string | null;
        delivery_lease_expires_at: number;
        delivery_audience: string | null;
        now_ms: number;
      }>(
        `SELECT delivered_at, delivery_token, delivery_lease_expires_at, delivery_audience,
                ${POSTGRES_NOW_MS_SQL} AS now_ms
         FROM approval_request
         WHERE id=? AND status='pending' AND expires_at>${POSTGRES_NOW_MS_SQL}`,
        [id],
      );
      if (!row) return { status: 'stale' };
      if (row.delivery_audience !== audience) {
        if (row.delivery_token !== null && row.delivery_lease_expires_at > row.now_ms) {
          return { status: 'in-flight' };
        }
        continue;
      }
      if (row.delivered_at != null) return { status: 'delivered' };
      if (row.delivery_lease_expires_at > row.now_ms) return { status: 'in-flight' };
    }
    return { status: 'in-flight' };
  }

  async confirmDelivery(id: string, token: string, audience: string): Promise<boolean> {
    if (!isInteractionId(id) || !isInteractionId(token) || !/^[0-9a-f]{64}$/.test(audience)) {
      return false;
    }
    return (await this.db.run(
      `UPDATE approval_request SET delivered_at=${POSTGRES_NOW_MS_SQL}, delivery_token=NULL, delivery_lease_expires_at=0
       WHERE id=? AND delivery_token=? AND delivery_audience=?
         AND status='pending' AND delivered_at IS NULL
         AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [id, token, audience],
    )).changes === 1;
  }

  async abandonDelivery(
    id: string,
    token: string,
    audience: string,
    remove: boolean,
  ): Promise<boolean> {
    if (!isInteractionId(id) || !isInteractionId(token) || !/^[0-9a-f]{64}$/.test(audience)) {
      return false;
    }
    const result = remove
      ? await this.db.run(
        `DELETE FROM approval_request
         WHERE id=? AND delivery_token=? AND delivery_audience=?
           AND status='pending' AND delivered_at IS NULL`,
        [id, token, audience],
      )
      : await this.db.run(
        `UPDATE approval_request SET delivery_token=NULL, delivery_lease_expires_at=0
         WHERE id=? AND delivery_token=? AND delivery_audience=?
           AND status='pending' AND delivered_at IS NULL`,
        [id, token, audience],
      );
    return result.changes === 1;
  }

  /** A live PENDING request by id, for the approve/deny surface. Null if absent, expired, or decided. */
  async get(id: string): Promise<ApprovalRow | null> {
    if (!isInteractionId(id)) return null;
    const row = await this.db.get<any>(
      `SELECT * FROM approval_request WHERE id=? AND status='pending'
       AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [id],
    );
    return row ? toRow(row) : null;
  }

  /** Remove only this still-pending opaque id (prompt failure/provider invalidation cleanup). */
  async discardPending(id: string): Promise<boolean> {
    if (!isInteractionId(id)) return false;
    return (await this.db.run(
      `DELETE FROM approval_request WHERE id=? AND status='pending'`,
      [id],
    )).changes === 1;
  }

  /**
   * Flip a pending request into a single-use grant valid `ttlMs` from now, recording who approved.
   * Atomic on status='pending': two concurrent decisions can't both win. False = already decided,
   * expired, or absent (the caller treats it as "nothing to do", never a second grant).
   */
  async approve(id: string, approvedBy: string, ttlMs: number): Promise<boolean> {
    if (!isInteractionId(id)) return false;
    const { changes } = await this.db.run(
      `UPDATE approval_request SET status='granted', approved_by=?, expires_at=${POSTGRES_NOW_MS_SQL}+?
       WHERE id=? AND status='pending' AND expires_at>${POSTGRES_NOW_MS_SQL}`,
      [approvedBy, ttlMs, id],
    );
    return changes === 1;
  }

  /** Deny (delete) a pending request. Returns the row for the audit/notify pair, or null if gone. */
  async deny(id: string): Promise<ApprovalRow | null> {
    if (!isInteractionId(id)) return null;
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
    return this.consumeOn(this.db, k);
  }

  private async liveGrantOn(
    db: Db,
    k: ApprovalKey,
  ): Promise<{ id: string; createdAt: number } | null> {
    if (!isInteractionId(k.credentialId)) return null;
    assertApprovalPathBounded(k.path);
    // Deliberately unlocked: audited consumption takes the actor offboard lock before the DELETE,
    // matching decision/offboard lock order. Locking this row first could deadlock with a decision
    // that already holds the actor lock and is waiting to update the same approval row.
    const row = await db.get<{ id: string; created_at: number }>(
      `SELECT id, created_at FROM approval_request
        WHERE action_key=?
          AND team_id=? AND user_id=? AND owner_kind=? AND owner_id=? AND credential_id=? AND provider=? AND method=? AND origin=? AND host=? AND path=? AND query_hash=?
          AND channel=? AND thread=? AND status='granted' AND expires_at>${POSTGRES_NOW_MS_SQL}
        LIMIT 1`,
      [approvalActionKey(k), ...this.keyParams(k)],
    );
    return row ? { id: row.id, createdAt: row.created_at } : null;
  }

  private async consumeIdOn(
    db: Db,
    id: string,
  ): Promise<{ approvedBy: string | null } | null> {
    const row = await db.get<{ approved_by: string | null }>(
      `DELETE FROM approval_request
        WHERE id=? AND status='granted' AND expires_at>${POSTGRES_NOW_MS_SQL}
        RETURNING approved_by`,
      [id],
    );
    return row ? { approvedBy: row.approved_by ?? null } : null;
  }

  private async consumeOn(db: Db, k: ApprovalKey): Promise<{ approvedBy: string | null } | null> {
    const candidate = await this.liveGrantOn(db, k);
    return candidate ? this.consumeIdOn(db, candidate.id) : null;
  }

  /** Spend one exact grant and write `approval_consumed` atomically. If audit insertion fails the
   *  DELETE rolls back, so no provider action can execute without its committed audit claim. A
   *  supplied validator carries the requesting actor's trusted receipt into this transaction; its
   *  actor fence and the grant-created fence therefore remain held together through DELETE + audit. */
  async consumeAudited(
    k: ApprovalKey,
    audit: Audit,
    acting: SlackIdentity,
    vault?: Pick<Vault, 'withCredentialLocks'>,
    validate?: (key: ApprovalKey, tx: Db, locked: Pick<Vault, 'liveId'>) => Promise<boolean>,
  ): Promise<{ approvedBy: string | null } | null> {
    if (!this.db.transaction) throw new Error('approval consumption requires database transaction support');
    if (acting.teamId !== k.teamId || acting.userId !== k.userId) {
      throw new Error('approval consumer does not match the requesting actor');
    }
    const consume = async (tx: Db, locked?: Pick<Vault, 'liveId'>) => {
      const candidate = await this.liveGrantOn(tx, k);
      if (!candidate) return null;
      const fenced = await withUserInteractionFence(
        tx,
        acting,
        candidate.createdAt,
        async (fencedTx) => {
          if (locked && ((!validate && k.channel) || (validate && !(await validate(k, fencedTx, locked))))) {
            throw new InteractionStateChangedError('approval', 'authorization');
          }
          const grant = await this.consumeIdOn(fencedTx, candidate.id);
          if (grant) {
            await audit.record(
              'approval_consumed',
              acting,
              k.provider,
              this.auditMeta(k),
              grant.approvedBy ?? undefined,
              fencedTx,
            );
          }
          return grant;
        },
      );
      if (fenced.status === 'offboarded') {
        // Permanent tombstones make this pre-offboard grant unusable even after re-onboarding.
        // Delete it now so the next legitimate request can mint a fresh approval immediately.
        await tx.run(`DELETE FROM approval_request WHERE id=?`, [candidate.id]);
        return null;
      }
      return fenced.value;
    };
    if (vault) {
      const owner: Owner = { teamId: k.teamId, kind: k.ownerKind, id: k.ownerId };
      const scopes = [
        { owner, provider: k.provider },
        ...(k.channel ? [{ owner: channelOwner(k.teamId, k.channel), provider: k.provider }] : []),
      ];
      return vault.withCredentialLocks(scopes, async (locked, tx) => {
        if ((await locked.liveId(owner, k.provider)) !== k.credentialId) {
          throw new InteractionStateChangedError('approval', 'credential');
        }
        return consume(tx, locked);
      });
    }
    return this.db.transaction(consume);
  }

  /** Approve or deny one locked pending row and append its canonical audit companion in the same
   *  transaction. `null` is the losing double-click/retry/expiry race; callers always render a
   *  fixed already-decided receipt. Eligibility and current provider rules are checked before this
   *  helper, while the immutable request key is reloaded under `FOR UPDATE` here. */
  async decideAudited(input: {
    id: string;
    decision: 'approve' | 'deny';
    approvedBy: string;
    actor: SlackIdentity;
    issuance: number;
    ttlMs: number;
    audit: Audit;
    enterpriseId?: string | null;
    validate: (row: ApprovalRow, tx: Db) => Promise<'valid' | 'invalidated' | 'ineligible'>;
  }): Promise<ApprovalDecisionResult> {
    if (!isInteractionId(input.id)) return { status: 'stale' };
    if (input.decision !== 'approve' && input.decision !== 'deny') {
      throw new Error('approval decision must be approve or deny');
    }
    if (typeof input.validate !== 'function') {
      throw new Error('approval decision requires a validator');
    }
    if (input.actor.userId !== input.approvedBy) {
      throw new Error('approval actor does not match the decision actor');
    }
    const pending = await this.get(input.id);
    if (!pending) return { status: 'stale' };
    const requester: SlackIdentity = {
      enterpriseId: input.enterpriseId ?? null,
      teamId: pending.teamId,
      userId: pending.userId,
    };
    if (!this.db.transaction) throw new Error('approval decisions require database transaction support');
    return this.db.transaction(async (decisionTx) => {
      // Keep the canonical actor/requester advisory locks until this outer transaction commits. If
      // the requester receipt is stale, deleting that exact pending generation in the same
      // transaction prevents a failed best-effort offboard cleanup from parking action-key dedupe.
      const fenced = await withUserInteractionFences(
        decisionTx,
        [
          { identity: input.actor, issuedAt: input.issuance },
          { identity: requester, issuedAt: pending.createdAt },
        ],
        async (tx) => {
          const raw = await tx.get<any>(
            `SELECT * FROM approval_request WHERE id=? AND status='pending'
             AND expires_at>${POSTGRES_NOW_MS_SQL} FOR UPDATE`,
            [input.id],
          );
          if (!raw) return { status: 'stale' } as const;
          const row = toRow(raw);
          const validity = await input.validate(row, tx);
          if (validity !== 'valid' && validity !== 'invalidated' && validity !== 'ineligible') {
            throw new Error('approval validator returned an invalid result');
          }
          if (validity === 'invalidated') {
            await tx.run(`DELETE FROM approval_request WHERE id=?`, [row.id]);
            return { status: 'invalidated' } as const;
          }
          if (validity === 'ineligible') return { status: 'ineligible' } as const;
          const lockedRequester: SlackIdentity = {
            enterpriseId: input.enterpriseId ?? null,
            teamId: row.teamId,
            userId: row.userId,
          };
          if (input.decision === 'approve') {
            const updated = await tx.get<{ expires_at: number }>(
              `UPDATE approval_request SET status='granted', approved_by=?,
                 expires_at=${POSTGRES_NOW_MS_SQL}+? WHERE id=? RETURNING expires_at`,
              [input.approvedBy, input.ttlMs, row.id],
            );
            if (!updated) return { status: 'stale' } as const;
            const expiresAt = updated.expires_at;
            await input.audit.record(
              'approved',
              lockedRequester,
              row.provider,
              this.auditMeta(row),
              input.approvedBy,
              tx,
            );
            return {
              status: 'decided',
              row: { ...row, status: 'granted', approvedBy: input.approvedBy, expiresAt },
            } as const;
          }
          await tx.run(`DELETE FROM approval_request WHERE id=?`, [row.id]);
          await input.audit.record(
            'denied',
            lockedRequester,
            row.provider,
            this.auditMeta(row, { reason: 'approval-denied' }),
            input.approvedBy,
            tx,
          );
          return { status: 'decided', row } as const;
        },
      );
      if (fenced.status === 'current') return fenced.value;
      if (fenced.index === 0) return { status: 'actor-stale' };
      await decisionTx.run(
        `DELETE FROM approval_request
          WHERE id=? AND status='pending' AND team_id=? AND user_id=? AND created_at=?`,
        [pending.id, pending.teamId, pending.userId, pending.createdAt],
      );
      return { status: 'invalidated' };
    });
  }

  /** Best-effort offboarding cleanup for every pending/granted action requested by this user,
   * including channel-owned credentials that intentionally survive the user's departure. */
  async revokeForUser(identity: SlackIdentity): Promise<void> {
    await this.db.run(
      `DELETE FROM approval_request WHERE team_id=? AND user_id=?`,
      [identity.teamId, identity.userId],
    );
  }

  /** Delete expired rows (unanswered prompts AND unspent grants), returning them so the sweep can
   *  audit each expiry. Run on the same timer as the connection TTL sweep. */
  async sweepExpired(): Promise<ApprovalRow[]> {
    const rows = await this.db.all<any>(
      `DELETE FROM approval_request WHERE expires_at<${POSTGRES_NOW_MS_SQL} RETURNING *`,
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
