import { createHash } from 'node:crypto';
import type { Audit, AuditMeta } from './audit';
import {
  authorizeProvider,
  governanceChannelOf,
  isGovernanceChannelScope,
  resolveCredentialOwner,
} from './authz';
import { ChannelConfig, type ChannelIdentity } from './channelConfig';
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
  PENDING_INTERACTION_TTL_US,
  POSTGRES_NOW_US_SQL,
  PROMPT_DELIVERY_LEASE_US,
  PROMPT_REDELIVERY_DEBOUNCE_US,
  usFromMs,
  type PromptDeliveryClaim,
  type PromptDeliveryOptions,
} from './interaction';
import { channelOwner, userOwner, type Owner } from './owner';
import type { Policy } from './policy';
import {
  APPROVERS,
  APPROVAL_GRANTS,
  isBrokeredProvider,
  type ApprovalGrant,
  type Approver,
  type ProviderRegistry,
} from './providers';
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

/** Opaque, row-specific digest of the exact recipient class/surface whose current prompt delivery
 * may be reused: the requester for `self`, the owning channel for `member`. Only this bounded digest
 * is persisted; a self→member rule change therefore cannot inherit the other surface's delivered
 * marker. */
export function approvalDeliveryAudienceKey(
  approvalId: string,
  approver: Approver,
  recipients: readonly string[],
): string {
  if (!isInteractionId(approvalId) || !APPROVERS.includes(approver)) {
    throw new Error('invalid approval delivery audience');
  }
  const normalized = [...new Set(recipients)].sort();
  if (
    normalized.length !== 1
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

/** The approver rule that actually applies to ONE request (#322): `member` means "another member of
 * the channel that governs this action", so where no channel governs it (a DM or group DM, whose
 * governance scope is null) it degrades to `self`. One helper for the injector, both Bolt delivery
 * paths, and the click, so no site can disagree about who may decide. */
export function effectiveApprover(approver: Approver, governableChannel: string | null): Approver {
  return approver === 'member' && governableChannel === null ? 'self' : approver;
}

/** Finite bound for the agent's `reason` (#350). It is rendered verbatim (escaped) on the decision
 * surface, so it stays far under Slack's section-text limit and never becomes a payload. */
export const MAX_REASON_BYTES = 500;
/** Finite bound for the optional `link` rendered beside the reason. */
export const MAX_LINK_BYTES = 2048;

/** Validate the agent's reason at the lowest reusable layer (IMP-3): a non-empty, non-whitespace
 * string within the bound. Returns the RAW value, never trimmed or normalized, so what the human
 * reads is byte-exact what the agent stated. Throws a plain fixed-text Error; the broker maps it
 * to 400. */
export function assertReason(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error('reason must be a non-empty string');
  }
  if (Buffer.byteLength(value, 'utf8') > MAX_REASON_BYTES) {
    throw new Error(`reason must be at most ${MAX_REASON_BYTES} bytes`);
  }
  // C0 controls (except newline/tab) and DEL: PostgreSQL TEXT refuses NUL outright (an internal
  // error after the assertion is spent), and the rest have no place in a statement a human reads.
  for (const ch of value) {
    const code = ch.codePointAt(0)!;
    if ((code < 0x20 && code !== 0x0a && code !== 0x09) || code === 0x7f) {
      throw new Error('reason must not contain control characters');
    }
  }
  return value;
}

/** Validate the optional link (#350): one bounded https URL with no credentials, returned in its
 * WHATWG-canonical spelling so the prompt renders exactly what a click would open. */
export function assertLink(value: unknown): string {
  if (typeof value !== 'string' || value.trim() !== value || value === '') {
    throw new Error('link must be an https URL');
  }
  if (Buffer.byteLength(value, 'utf8') > MAX_LINK_BYTES) {
    throw new Error(`link must be at most ${MAX_LINK_BYTES} bytes`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('link must be an https URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new Error('link must be an https URL');
  }
  return url.href;
}

/** The agent's own account of an action, rendered on every prompt it produces (#350). Free text is
 * plain (never mrkdwn); the link is a validated https URL. Both optional, neither is authority. */
export interface ApprovalStatement {
  reason: string | null;
  link: string | null;
}

/** Validate a caller-supplied statement once, at the door that received it. Absent fields stay
 * null; present ones must pass their validator. */
export function approvalStatement(input: { reason?: unknown; link?: unknown }): ApprovalStatement {
  return {
    reason: input.reason === undefined ? null : assertReason(input.reason),
    link: input.link === undefined ? null : assertLink(input.link),
  };
}

/** Wire status of one backchannel authorization request (#296): the row's lifecycle as the polling
 * agent sees it. A consumed grant (the approved action ran) or a swept row is absent, not a status. */
export type AuthorizationStatus = 'pending' | 'approved' | 'denied' | 'expired';

/**
 * Thrown by the injector when a request matches the provider's approval rule and no live matching
 * grant exists (#113). Control flow, exactly like ConsentRequiredError: the Bolt adapter posts the
 * Approve/Deny prompt and the caller stops the turn; the headless broker maps it to 403
 * `{ error: 'approval_required', approvalId }`. The message is Vouchr-authored and secret-free.
 */
export class ApprovalRequiredError extends Error {
  readonly code = 'approval_required' as const;

  constructor(
    public provider: string,
    /** Who may decide, already resolved for this request's conversation (effectiveApprover):
     * 'self' = the acting user; 'member' = any other current member of the owning channel. */
    public approver: Approver,
    public method: string,
    public host: string,
    /** The exact request path, rendered plain on the prompt (#350). Never the query string. */
    public path: string,
    /** The pending approval-request id the Approve/Deny surface decides on. */
    public approvalId: string,
    /** What the decision would cover: this one call, or every matching call in the thread. */
    public grant: ApprovalGrant,
    /** True only when this fetch created the deduplicated pending row. Bolt posts one prompt for
     *  that creator; repeated turns reuse the opaque id without posting or auditing duplicates. */
    public newRequest: boolean = true,
    /** The agent's stated reason and link, as stored on the pending row. */
    public reason: string | null = null,
    public link: string | null = null,
  ) {
    // The public message stays fixed-size: safeUserMessage returns it verbatim.
    super(`Approval required for provider "${provider}". Use the approval prompt before retrying.`);
    this.name = 'ApprovalRequiredError';
  }
}

/**
 * The exact action a grant covers. Matching is EXACT on every field — not a prefix, not a pattern:
 * the human approved one action, not a class of actions. `origin` binds scheme + host + effective
 * port, while `host` remains the hostname-only observability field. `queryHash` binds the exact
 * (canonical) query parameters (GHSA-pg84, see queryDigest) — as a digest, never raw values. The
 * request BODY remains outside the key; see the threat model: for body-parameterized APIs approval
 * covers the origin + endpoint + method + query, NOT the payload bytes. `channel`/`thread` bind the
 * grant to the conversation context it was requested from (null = none, stored as ''). A `thread`
 * grant (#350) binds only that conversation: its method/origin/host/path/query record the call that
 * asked, and every later matching call in the thread selects the same row.
 *
 * Two identities are carried SEPARATELY (never conflated):
 *  - `userId`: the REQUESTER (the human driving the agent — the caller). Who is prompted, and who
 *    self-approval matches.
 *  - `ownerKind`/`ownerId`: the CREDENTIAL OWNER the grant is bound to. consume() matches it too, so
 *    if resolution later picks a different owner (a person -> channel identity change), the grant no longer
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
  /** `once` (exact action, single use) or `thread` (every matching call in `thread` until expiry). */
  grant: ApprovalGrant;
  channel: string | null;
  thread: string | null;
  /**
   * The mutable-GOVERNANCE scope of `channel` at request time (null in a personal conversation),
   * captured when the classification (Slack `channel_type`) is known so the DECISION revalidation can
   * classify a group DM (MPIM) whose id alone cannot be distinguished from a private channel. Stored
   * on the row and compared as part of every authoritative request/grant lookup. It deliberately
   * stays out of the rendered fingerprint: the raw channel is already bound there, while this scope
   * is an authorization classification for that channel. Required at every call site so an adapter
   * cannot silently lose the Slack `channel_type` fact before persistence.
   */
  governableChannel: string | null;
}

/** One pending request / unspent grant / persisted denial, as the approve/deny surface and the
 * sweep read it. `denied` rows (#296) exist only so a backchannel poller can observe the outcome;
 * no read path treats them as pending or spendable, and the sweep reclaims them unaudited. */
export interface ApprovalRow extends ApprovalKey {
  id: string;
  status: 'pending' | 'granted' | 'denied';
  /** The deciding human for granted AND denied rows (the column name predates persisted denials). */
  approvedBy: string | null;
  createdAt: number;
  expiresAt: number;
  /** The agent's reason and link (#350), rendered on the prompt and kept on the audit row. */
  reason: string | null;
  link: string | null;
  /** #296: true for an agent-initiated backchannel request, which the Bolt control plane delivers on
   * its own timer because no Slack turn can relay it. */
  backchannel: boolean;
}

/** Result of one persisted approval-button decision. `invalidated` means the stored action no
 * longer matches current provider/governance/owner state and was removed without creating either
 * a grant or a denial; `ineligible` leaves it pending for a legitimate approver. */
export type ApprovalDecisionResult =
  | { status: 'decided'; row: ApprovalRow }
  | { status: 'stale' | 'invalidated' | 'ineligible' | 'actor-stale' };

/**
 * Re-resolve every database-backed fact that determines which credential a pending action would
 * use. This runs inside the same locked transaction as the decision: an identity/tool writer cannot
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
  /** `undefined` = core/Bolt default store; `null` = every channel identity is 'person'. */
  channelConfig?: ChannelConfig | null;
  /**
   * The mutable-governance scope for the tool-allowlist + identity re-check; null in a personal
   * conversation so a retained handle / approval in a DM is not invalidated by deny-by-default.
   * Static Policy still evaluates against `binding.channel` (the real delivery channel). Omitted →
   * derived from `binding.channel` (governanceChannelOf), so a 1:1 DM is exempt even for a caller
   * that carries no channel_type; the channel_type-aware adapters pass the exact value.
   */
  governableChannel?: string | null;
}

async function credentialUseStateForCurrentActor(
  input: CredentialUseValidationInput,
  principal: SlackIdentity,
): Promise<'current' | 'authorization' | 'credential'> {
  const { binding: row, db } = input;
  if (!input.registry.has(row.provider) || !isBrokeredProvider(input.registry.get(row.provider))) {
    return 'authorization';
  }

  // Governance (tool allowlist + identity + owner resolution) is scoped to the mutable-governance
  // channel, null in a DM so a personal retained handle survives; static Policy keeps the real
  // delivery channel (row.channel) so a policy-deny of a DM still denies. Where non-null it equals row.channel.
  const governableChannel = input.governableChannel !== undefined
    ? input.governableChannel
    : governanceChannelOf(row.channel);
  const channelTools = input.channelTools === undefined ? new ChannelTools(db) : input.channelTools ?? undefined;
  if ((await authorizeProvider(input.policy, channelTools, principal, row.channel, governableChannel, row.provider, db)) !== null) {
    return 'authorization';
  }

  const channelConfig = input.channelConfig === undefined ? new ChannelConfig(db) : input.channelConfig;
  const identity: ChannelIdentity = governableChannel && channelConfig
    ? await channelConfig.getIdentity(row.teamId, governableChannel, row.provider, db)
    : 'person';
  const resolved = identity === 'channel'
    ? resolveCredentialOwner({
        path: 'channel', identity, principal, channel: governableChannel, eligible: governableChannel !== null,
      })
    : resolveCredentialOwner({ path: 'user', identity, principal, channel: governableChannel });
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
 * exact live credential generation so an identity/tool change remains an authorization failure
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
  return (await credentialUseState({
    binding: input.row,
    db: input.db,
    registry: input.registry,
    policy: input.policy,
    vault: input.vault,
    enterpriseId: input.enterpriseId,
    actorIssuedAt: input.actorIssuedAt,
    channelTools: input.channelTools,
    channelConfig: input.channelConfig,
    // Use the governance scope PERSISTED with the row, so the decision revalidation classifies a
    // group DM (MPIM) that its id alone cannot — instead of re-deriving it (and wrongly governing it).
    governableChannel: input.row.governableChannel,
  })) === 'current';
}

/** Owners whose lifecycle locks fence an approval decision. The channel owner is always included
 * for channel-bound actions because identity/tool governance writers use that lock; the stored
 * owner fences reconnect/disconnect, and the projected current owner covers the pre-lock identity
 * snapshot. Vault canonicalizes and de-duplicates the returned keys. */
export function approvalDecisionLockOwners(
  row: ApprovalRow,
  currentIdentity: ChannelIdentity,
): Owner[] {
  const stored: Owner = { teamId: row.teamId, kind: row.ownerKind, id: row.ownerId };
  if (!row.channel) return [stored];
  const governance = channelOwner(row.teamId, row.channel);
  const projected = currentIdentity === 'channel'
    ? governance
    : userOwner({ enterpriseId: null, teamId: row.teamId, userId: row.userId });
  return [governance, stored, projected];
}

function toRow(r: any): ApprovalRow {
  const channel = r.channel || null;
  if (typeof r.governable_channel !== 'string') {
    throw new Error('approval row has no governance scope');
  }
  const governableChannel = r.governable_channel === '' ? null : r.governable_channel;
  if (!isGovernanceChannelScope(channel, governableChannel)) {
    throw new Error('approval row has an invalid governance scope');
  }
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
    grant: r.grant_scope,
    channel,
    thread: r.thread || null,
    governableChannel,
    status: r.status,
    approvedBy: r.approved_by ?? null,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    reason: r.reason ?? null,
    link: r.link ?? null,
    backchannel: r.backchannel === 1 || r.backchannel === true,
  };
}

/**
 * Human-in-the-loop approval requests/grants for sensitive writes (#113). Lifecycle: the injector
 * `request()`s a pending row and throws ApprovalRequiredError; a human decision `approve()`s it into
 * a TTL-bound grant (or `deny()`s it); the retried fetch `consume()`s the grant. A `once` grant is
 * SINGLE-USE, via atomic `DELETE ... RETURNING`, so two concurrent retries can never both spend one
 * approval; a `thread` grant (#350) stays until its TTL and every matching call in the thread
 * spends it without deleting it. Expired rows (unanswered prompts and unspent grants) are reclaimed
 * by `sweepExpired()`.
 */
export class Approvals {
  constructor(private db: Db) {}

  /** Normalize and validate the authorization-affecting scope at the persistence boundary. Empty
   * string is the explicit personal-conversation encoding; the schema is NOT NULL so it can never
   * be confused with an older/unclassified row. A non-null scope must be the delivery channel. */
  private governanceParam(k: ApprovalKey): string {
    const scope = k.governableChannel;
    if (scope === undefined) {
      throw new Error('approval request has no governance scope');
    }
    if (!isGovernanceChannelScope(k.channel, scope)) {
      throw new Error('approval request has an invalid governance scope');
    }
    return scope ?? '';
  }

  /** Re-resolve the database-backed authority for a row through the canonical approval validator.
   * The recovery bridge has an Approvals instance but deliberately has no raw Db handle; keeping
   * this adapter on the store prevents it from copying the identity/offboard/credential checks.
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
      k.grant,
      k.channel ?? '',
      k.thread ?? '',
      this.governanceParam(k),
    ];
  }

  private auditMeta(k: ApprovalKey, extra: AuditMeta = {}): AuditMeta {
    return {
      host: k.host,
      method: k.method,
      actionFingerprint: approvalActionFingerprint(k),
      grant: k.grant,
      ...(k.channel ? { channel: k.channel } : {}),
      ...extra,
    };
  }

  /** The raw-field match for one key after the `action_key` selector: every scope field always, and
   *  the exact action fields only for a `once` grant (a `thread` row records the call that asked,
   *  which a later matching call in the thread need not repeat). One fragment for insert-conflict,
   *  live lookup, and consume, so the three cannot drift. */
  private static readonly MATCH_SQL = `team_id=? AND user_id=? AND owner_kind=? AND owner_id=? AND credential_id=? AND provider=?
           AND (grant_scope='thread' OR (method=? AND origin=? AND host=? AND path=? AND query_hash=?))
           AND grant_scope=? AND channel=? AND thread=? AND governable_channel=?`;

  /** Insert or reuse the one live row for an action. The unique action index linearizes two
   *  replicas; an expired or denied row is atomically replaced (a denial is a terminal outcome the
   *  poller may still be reading, but a new request IS a new decision, #296). A live granted row
   *  may win the consume -> request race, in which case its id is returned without a duplicate prompt
   *  and the caller retries. A reused pending row adopts the reason/link only if it had none, so the
   *  human never reads a statement that changed under an already-delivered prompt. */
  private async requestOn(
    db: Db,
    k: ApprovalKey,
    statement: ApprovalStatement = { reason: null, link: null },
    backchannel = false,
  ): Promise<{ id: string; created: boolean }> {
    if (!isInteractionId(k.credentialId)) {
      throw new Error('approval request requires a valid credential generation id');
    }
    if (!(APPROVAL_GRANTS as readonly string[]).includes(k.grant)) throw new Error('invalid approval grant');
    assertApprovalPathBounded(k.path);
    const reason = statement.reason === null ? null : assertReason(statement.reason);
    const link = statement.link === null ? null : assertLink(statement.link);
    const params = this.keyParams(k);
    const actionKey = approvalActionKey(k);
    for (let attempt = 0; attempt < 3; attempt++) {
      const id = newInteractionId();
      const row = await db.get<{ id: string }>(
        `INSERT INTO approval_request
           (id, action_key, team_id, user_id, owner_kind, owner_id, credential_id, provider, method, origin, host, path, query_hash,
            grant_scope, channel, thread, governable_channel, status, approved_by, created_at, expires_at, reason, link, backchannel)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',NULL,${POSTGRES_NOW_US_SQL},${POSTGRES_NOW_US_SQL}+?,?,?,?)
         ON CONFLICT(action_key) DO UPDATE SET
           id=excluded.id, status='pending', approved_by=NULL,
           created_at=excluded.created_at, expires_at=excluded.expires_at,
           method=excluded.method, origin=excluded.origin, host=excluded.host, path=excluded.path,
           query_hash=excluded.query_hash, governable_channel=excluded.governable_channel,
           delivery_token=NULL, delivery_lease_expires_at=0, delivered_at=NULL,
           delivery_audience=NULL, reason=excluded.reason, link=excluded.link, backchannel=excluded.backchannel
         WHERE approval_request.team_id=excluded.team_id
           AND approval_request.user_id=excluded.user_id
           AND approval_request.owner_kind=excluded.owner_kind
           AND approval_request.owner_id=excluded.owner_id
           AND approval_request.credential_id=excluded.credential_id
           AND approval_request.provider=excluded.provider
           AND approval_request.grant_scope=excluded.grant_scope
           AND (approval_request.grant_scope='thread' OR (
             approval_request.method=excluded.method
             AND approval_request.origin=excluded.origin
             AND approval_request.host=excluded.host
             AND approval_request.path=excluded.path
             AND approval_request.query_hash=excluded.query_hash))
           AND approval_request.channel=excluded.channel
           AND approval_request.thread=excluded.thread
           AND (approval_request.expires_at<=${POSTGRES_NOW_US_SQL} OR approval_request.status='denied')
         RETURNING id`,
        [id, actionKey, ...params, PENDING_INTERACTION_TTL_US, reason, link, backchannel ? 1 : 0],
      );
      if (row) return { id: row.id, created: true };
      const live = await db.get<{ id: string }>(
        `SELECT id FROM approval_request
         WHERE action_key=? AND ${Approvals.MATCH_SQL}
           AND status<>'denied' AND expires_at>${POSTGRES_NOW_US_SQL}`,
        [actionKey, ...params],
      );
      if (live) {
        if (reason !== null || link !== null) {
          await db.run(
            `UPDATE approval_request SET reason=COALESCE(reason, ?), link=COALESCE(link, ?)
             WHERE id=? AND status='pending'`,
            [reason, link, live.id],
          );
        }
        return { id: live.id, created: false };
      }
    }
    throw new Error('approval request could not be recorded; retry');
  }

  /** Low-level internal request primitive. Production injector paths use
   *  requestAudited() so the mutation and canonical audit row commit together. */
  async request(k: ApprovalKey): Promise<string> {
    return (await this.requestOn(this.db, k)).id;
  }

  /** Deduplicated request plus `approval_requested` audit in one transaction. Reuse writes no
   *  duplicate audit row and tells Bolt not to post another prompt. The agent's reason rides on the
   *  audit row under the fixed `reason` key (#350); `backchannel` marks an agent-initiated request
   *  the control plane delivers on its own timer (#296). */
  async requestAudited(
    k: ApprovalKey,
    audit: Audit,
    acting: SlackIdentity,
    vault?: Pick<Vault, 'withCredentialLocks'>,
    validate?: (key: ApprovalKey, tx: Db, locked: Pick<Vault, 'liveId'>) => Promise<boolean>,
    statement: ApprovalStatement = { reason: null, link: null },
    backchannel = false,
  ): Promise<{ id: string; created: boolean }> {
    const write = async (tx: Db) => {
      const result = await this.requestOn(tx, k, statement, backchannel);
      if (result.created) {
        await audit.record(
          'approval_requested',
          acting,
          k.provider,
          this.auditMeta(k, statement.reason === null ? {} : { reason: statement.reason }),
          undefined,
          tx,
        );
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
         SET delivery_token=?, delivery_lease_expires_at=${POSTGRES_NOW_US_SQL}+?,
             delivered_at=NULL, delivery_audience=?
         WHERE id=? AND status='pending' AND expires_at>${POSTGRES_NOW_US_SQL}
           AND (
             delivery_token IS NULL OR delivery_lease_expires_at<=${POSTGRES_NOW_US_SQL}
           )
           AND (
             delivery_audience IS DISTINCT FROM ? OR delivered_at IS NULL
             OR (?::boolean AND delivered_at <= ${POSTGRES_NOW_US_SQL}-?)
           )
         RETURNING id`,
        [
          token,
          PROMPT_DELIVERY_LEASE_US,
          audience,
          id,
          audience,
          options.redeliverDelivered === true,
          PROMPT_REDELIVERY_DEBOUNCE_US,
        ],
      );
      if (claimed) return { status: 'claimed', token };
      const row = await this.db.get<{
        delivered_at: number | null;
        delivery_token: string | null;
        delivery_lease_expires_at: number;
        delivery_audience: string | null;
        now_us: number;
      }>(
        `SELECT delivered_at, delivery_token, delivery_lease_expires_at, delivery_audience,
                ${POSTGRES_NOW_US_SQL} AS now_us
         FROM approval_request
         WHERE id=? AND status='pending' AND expires_at>${POSTGRES_NOW_US_SQL}`,
        [id],
      );
      if (!row) return { status: 'stale' };
      if (row.delivery_audience !== audience) {
        if (row.delivery_token !== null && row.delivery_lease_expires_at > row.now_us) {
          return { status: 'in-flight' };
        }
        continue;
      }
      if (row.delivered_at != null) return { status: 'delivered' };
      if (row.delivery_lease_expires_at > row.now_us) return { status: 'in-flight' };
    }
    return { status: 'in-flight' };
  }

  async confirmDelivery(id: string, token: string, audience: string): Promise<boolean> {
    if (!isInteractionId(id) || !isInteractionId(token) || !/^[0-9a-f]{64}$/.test(audience)) {
      return false;
    }
    return (await this.db.run(
      `UPDATE approval_request SET delivered_at=${POSTGRES_NOW_US_SQL}, delivery_token=NULL, delivery_lease_expires_at=0
       WHERE id=? AND delivery_token=? AND delivery_audience=?
         AND status='pending' AND delivered_at IS NULL
         AND expires_at>${POSTGRES_NOW_US_SQL}`,
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
       AND expires_at>${POSTGRES_NOW_US_SQL}`,
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
      `UPDATE approval_request SET status='granted', approved_by=?, expires_at=${POSTGRES_NOW_US_SQL}+?
       WHERE id=? AND status='pending' AND expires_at>${POSTGRES_NOW_US_SQL}`,
      [approvedBy, usFromMs(ttlMs), id],
    );
    return changes === 1;
  }

  /** Deny a pending request. The row is PERSISTED as `denied` (#296) for one more pending-TTL
   *  window so a backchannel poller observes the outcome instead of an indistinguishable absence;
   *  every pending/grant read path already excludes it, a re-request replaces it, and the sweep
   *  reclaims it without a second denial audit. Atomic on status='pending'. */
  private async denyOn(db: Db, id: string, decidedBy: string | null): Promise<ApprovalRow | null> {
    const row = await db.get<any>(
      `UPDATE approval_request SET status='denied', approved_by=?, expires_at=${POSTGRES_NOW_US_SQL}+?
       WHERE id=? AND status='pending' RETURNING *`,
      [decidedBy, PENDING_INTERACTION_TTL_US, id],
    );
    return row ? toRow(row) : null;
  }

  /** Low-level deny primitive. Returns the row for the audit/notify pair, or null if gone. */
  async deny(id: string): Promise<ApprovalRow | null> {
    if (!isInteractionId(id)) return null;
    return this.denyOn(this.db, id, null);
  }

  /** #296: the lifecycle of one authorization request as its REQUESTER may read it. Bound to the
   *  requesting team + user, so an opaque id copied across tenants reads as unknown. Null when the
   *  row is absent — swept, consumed by the approved action, or never this caller's. */
  async authorizationStatus(
    id: string,
    requester: Pick<SlackIdentity, 'teamId' | 'userId'>,
  ): Promise<{ id: string; status: AuthorizationStatus; expiresAt: number } | null> {
    if (!isInteractionId(id)) return null;
    const row = await this.db.get<{ status: string; expires_at: number; live: boolean }>(
      `SELECT status, expires_at, expires_at>${POSTGRES_NOW_US_SQL} AS live
       FROM approval_request WHERE id=? AND team_id=? AND user_id=?`,
      [id, requester.teamId, requester.userId],
    );
    if (!row) return null;
    const status: AuthorizationStatus = row.status === 'denied'
      ? 'denied'
      : !row.live ? 'expired' : row.status === 'granted' ? 'approved' : 'pending';
    return { id, status, expiresAt: row.expires_at };
  }

  /** #296: live backchannel requests whose decision surface has not been delivered and is not
   *  currently being delivered — the rows the Bolt control plane delivers on its timer. A row under
   *  a live delivery lease (a post in flight, or one whose outcome was ambiguous and kept its
   *  lease) is skipped until the lease lapses, so a degraded Slack cannot yield a second post per
   *  pass. Oldest first, bounded per pass; a row whose delivery keeps failing is retried once per
   *  lease window until its pending TTL reclaims it (bounded by design). */
  async listUndeliveredBackchannel(limit: number): Promise<ApprovalRow[]> {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('listUndeliveredBackchannel requires a positive limit');
    const rows = await this.db.all<any>(
      `SELECT * FROM approval_request
       WHERE status='pending' AND backchannel=1 AND delivered_at IS NULL
         AND (delivery_token IS NULL OR delivery_lease_expires_at<=${POSTGRES_NOW_US_SQL})
         AND expires_at>${POSTGRES_NOW_US_SQL}
       ORDER BY created_at LIMIT ?`,
      [limit],
    );
    return rows.map(toRow);
  }

  /**
   * Consume one live grant matching the action key: a `once` grant is spent by the atomic
   * `DELETE ... RETURNING` (see Consent.consume), which makes it spend-once even for two concurrent
   * identical fetches (a get-then-delete would let both pass on multi-instance Postgres); a
   * `thread` grant is matched and left in place until its TTL. Returns the approver for audit
   * attribution, or null when no live grant matches.
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
        WHERE action_key=? AND ${Approvals.MATCH_SQL}
          AND status='granted' AND expires_at>${POSTGRES_NOW_US_SQL}
        LIMIT 1`,
      [approvalActionKey(k), ...this.keyParams(k)],
    );
    return row ? { id: row.id, createdAt: row.created_at } : null;
  }

  /** Spend one live grant by id: a `once` row is deleted atomically; a `thread` row is read and
   *  kept. Both re-check liveness in the same statement. */
  private async consumeIdOn(
    db: Db,
    id: string,
    grant: ApprovalGrant,
  ): Promise<{ approvedBy: string | null } | null> {
    const live = `id=? AND status='granted' AND grant_scope=? AND expires_at>${POSTGRES_NOW_US_SQL}`;
    const row = grant === 'once'
      ? await db.get<{ approved_by: string | null }>(
        `DELETE FROM approval_request WHERE ${live} RETURNING approved_by`,
        [id, grant],
      )
      : await db.get<{ approved_by: string | null }>(
        `SELECT approved_by FROM approval_request WHERE ${live}`,
        [id, grant],
      );
    return row ? { approvedBy: row.approved_by ?? null } : null;
  }

  private async consumeOn(db: Db, k: ApprovalKey): Promise<{ approvedBy: string | null } | null> {
    const candidate = await this.liveGrantOn(db, k);
    return candidate ? this.consumeIdOn(db, candidate.id, k.grant) : null;
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
          const grant = await this.consumeIdOn(fencedTx, candidate.id, k.grant);
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
             AND expires_at>${POSTGRES_NOW_US_SQL} FOR UPDATE`,
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
                 expires_at=${POSTGRES_NOW_US_SQL}+? WHERE id=? RETURNING expires_at`,
              [input.approvedBy, usFromMs(input.ttlMs), row.id],
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
          const denied = await this.denyOn(tx, row.id, input.approvedBy);
          if (!denied) return { status: 'stale' } as const;
          await input.audit.record(
            'denied',
            lockedRequester,
            row.provider,
            this.auditMeta(row, { reason: 'approval-denied' }),
            input.approvedBy,
            tx,
          );
          return { status: 'decided', row: denied } as const;
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

  /** Delete expired rows (unanswered prompts, unspent grants, AND retained denials), returning them
   *  so the sweep can audit each expiry — a denial was already audited at decision time, so the
   *  sweep skips `denied` rows. Run on the same timer as the connection TTL sweep. */
  async sweepExpired(): Promise<ApprovalRow[]> {
    const rows = await this.db.all<any>(
      `DELETE FROM approval_request WHERE expires_at<${POSTGRES_NOW_US_SQL} RETURNING *`,
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
