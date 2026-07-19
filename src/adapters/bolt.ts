import { ErrorCode as SlackErrorCode, WebClient, type WebClientOptions } from '@slack/web-api';
import type { InstallationStore } from '@slack/bolt';
import {
  DB_CONNECTION_TIMEOUT_MS,
  DB_RUNTIME_QUERY_TIMEOUT_MS,
  openDb,
  type Db,
} from '../core/db';
import { loadKeyring, type EnvelopeProvider } from '../core/crypto';
import { ProviderRegistry, isBrokeredProvider, isValidProviderId, buildCallbackUrl, type Provider } from '../core/providers';
import { CredentialLockdownError, Vault, type TtlPolicy } from '../core/vault';
import { Audit, type AuditSink } from '../core/audit';
import { Consent } from '../core/consent';
import { Policy } from '../core/policy';
import type { SlackIdentity } from '../core/identity';
import { resolveIdentity, isSlackAdmin, isChannelAdmin, isChannelMember, listChannelMembers } from './slack-identity';
import { userOwner, channelOwner, type Owner } from '../core/owner';
import {
  authorizeProvider,
  PolicyDeniedError,
  resolveCredentialOwner,
  buildToolManifest,
  buildToolManifestSnapshot,
  ToolDisabledError,
} from '../core/authz';
import { ConnectionHandle, NoConnectionError, approvalNeeded, type Resolvers, type EventSink, type VouchrEvent } from '../core/injector';
import { MemoryRateLimitStore, RateLimitedError, type RateLimitStore } from '../core/rateLimit';
import { safeEmit } from '../core/safe-emit';
import { ChannelConfig, channelIneligibleReason, isChannelMode, type ChannelInfo, type ChannelMode } from '../core/channelConfig';
import {
  configureChannelCredential,
  setChannelCredentialMode,
  type ChannelProvisioningIssuance,
} from '../core/channelCredential';
import { ChannelTools, configureChannelTools, type ToolManifestEntry } from '../core/tools';
import { handleOAuthCallback, type CallbackResult } from '../core/oauthCallback';
import {
  offboardUser,
  disconnectProvider,
  disconnectProviderAtReceipt,
  disconnectConnectionGeneration,
} from '../core/offboard';
import { assertDryRunFlag, assertDryRunLocalKey, assertDryRunVault, dryRunAudit, DRY_RUN_CODE } from '../core/dryRun';
import { booleanEnv } from '../core/options';
import { sweepLifecycle } from '../core/sweep';
import { SessionGrants, type SessionGrantResult } from '../core/session';
import { InteractionStateChangedError, isInteractionId, PROMPT_DELIVERY_LEASE_MS } from '../core/interaction';
import {
  abandonUserProvisioningDelivery,
  ChannelProvisioningRequests,
  claimUserProvisioningDelivery,
  confirmUserProvisioningDelivery,
  configureUserCredential,
  issueUserProvisioningRequest,
  UserProvisioningRequests,
} from '../core/provisioning';
import {
  Approvals,
  ApprovalRequiredError,
  DEFAULT_APPROVAL_TTL_MS,
  approvalActionFingerprint,
  approvalDeliveryAudienceKey,
  approvalDecisionLockOwners,
  approvalOwnerStillCurrent,
  credentialUseStateFenced,
  credentialUseStillCurrentFenced,
  type ApprovalDecisionResult,
  type ApprovalKey,
} from '../core/approval';
import { NotificationState, type CredentialHealthEvent, type CredentialHealthHook } from '../core/health';
import {
  normalizeSecretReference,
  referenceChannelCredential,
  referenceUserCredential,
  SECRET_REFERENCE_SOURCES,
  type SecretReference,
} from '../core/reference';
import {
  ConsentRequiredError,
  SessionApprovalRequiredError,
  UserFacingError,
  isVouchrErrorCode,
  safeUserMessage,
  type ConsentPromptState,
} from '../core/errors';
export {
  ConsentRequiredError,
  SessionApprovalRequiredError,
  UserFacingError,
  safeUserMessage,
} from '../core/errors';
import { connectedHtml } from './landing';
import {
  connectBlocks, configureModal, CONFIGURE_CALLBACK,
  userKeyModal, keySetupBlocks, USER_KEY_CALLBACK, SETUP_KEY_ACTION, RECONNECT_ACTION,
  privateStatusModal,
  sessionApprovalBlocks, APPROVE_SESSION_ACTION, auditBlocks, statsBlocks, statusBlocks,
  approvalBlocks, APPROVAL_APPROVE_ACTION, APPROVAL_DENY_ACTION,
  configModal, CONFIG_CALLBACK, DISCONNECT_ACTION,
  homeView, connectionLine, HOME_CALLBACK, HOME_CHANNEL_ACTION, HOME_MODE_ACTION, HOME_TOOL_ACTION, HOME_CONFIGURE_ACTION,
  escapeMrkdwn, blocksFallbackText, connectedDmText, oauthRecoveryBlocks,
  type Connection, type ConfigAdminRow,
} from './blocks';

/** Default session-grant safety ceiling: 8h. The thread binding is the real scope; this just caps
 *  how long a single approval can live before the user must re-approve in the thread. */
const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

// One-release tombstones for preview controls issued by a drained v7 replica. These handlers retain
// no provider response, perform no share, and are deliberately not exported as a supported surface.
const RETIRED_PREVIEW_ACTIONS = ['vouchr_preview_share', 'vouchr_preview_dismiss'] as const;
const RETIRED_PREVIEW_MESSAGE =
  'This preview expired because private previews were removed. Ask the agent again.';

/** Aggressive default per-user connection lifetime: idle 7d, hard cap 30d. */
const DEFAULT_TTL: TtlPolicy = { idleMs: 7 * 24 * 60 * 60 * 1000, maxAgeMs: 30 * 24 * 60 * 60 * 1000 };

/** Denial message for the config gate, accurate to whether the channel-creator path is enabled. */
const adminOnly = (allowCreator: boolean, action: string): string =>
  `Only a workspace admin${allowCreator ? ' or the channel creator' : ''} can ${action}.`;

interface ConfigOpenState {
  p: string;
  m: ChannelMode | null;
  e: boolean;
}

/** Parse forgeable config-modal metadata into one bounded, canonical shape before iteration. */
function parseConfigMetadata(value: unknown): { channel: string; open: ConfigOpenState[] } | null {
  let parsed: any;
  try { parsed = JSON.parse(String(value)); } catch { return null; }
  if (
    !parsed || typeof parsed !== 'object' ||
    typeof parsed.channel !== 'string' ||
    !/^[A-Za-z0-9_-]{1,255}$/.test(parsed.channel) ||
    !Array.isArray(parsed.open) || parsed.open.length > 100
  ) return null;

  const seen = new Set<string>();
  for (const entry of parsed.open) {
    if (
      !entry || typeof entry !== 'object' ||
      typeof entry.p !== 'string' || !isValidProviderId(entry.p) || seen.has(entry.p) ||
      !(entry.m === null || isChannelMode(entry.m)) ||
      typeof entry.e !== 'boolean' ||
      // A pre-removal modal carries `v`. Reject it as stale so rolling-version overlap cannot
      // silently confirm mode/tool changes from a form that also contained a removed preview toggle.
      Object.hasOwn(entry, 'v')
    ) return null;
    seen.add(entry.p);
  }
  return { channel: parsed.channel, open: parsed.open };
}

/**
 * THE admin-eligibility predicate (STR-2: one rule, every caller): a custom `isAdmin` override
 * fully decides (a throw fails closed); else workspace admin OR — only when opted in — the channel
 * creator. ConnectContext.requireAdmin, the command-path gate, and the #113 approval-approver
 * resolution all route through this one function so the rule cannot drift between surfaces.
 */
async function adminEligible(
  client: WebClient,
  userId: string,
  teamId: string,
  channel: string,
  adminCheck: VouchrOptions['isAdmin'],
  allowCreator: boolean,
): Promise<boolean> {
  return adminCheck
    ? await adminCheck(client, userId, teamId).catch(() => false)
    : (await isSlackAdmin(client, userId) || (allowCreator && await isChannelAdmin(client, channel, userId)));
}

/** Slack may synthesize accessible top-level text from blocks when complete visible copy exceeds its
 *  40k fallback ceiling. Valid maximum-scope OAuth prompts can reach that case while every individual
 *  section and the 50-block message remain valid; omit `text` rather than failing after consent state
 *  was minted. Used only with renderers that always contain visible supported blocks. */
function optionalBlockFallback(blocks: unknown[]): { text: string } | Record<string, never> {
  try {
    return { text: blocksFallbackText(blocks) };
  } catch {
    return {};
  }
}

export const SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS = 3_000;
export const APPROVAL_FANOUT_CONCURRENCY = 16;
/** One complete, current approval-recipient snapshot must resolve promptly before delivery is
 * claimed. This bounds pagination plus admin checks even for direct test/custom clients that do not
 * inherit WebClient's request timeout. */
export const APPROVAL_AUDIENCE_RESOLUTION_DEADLINE_MS = SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS;
/** Fail closed instead of retaining unbounded member/admin work for an exceptionally large or
 * hostile paginated response. */
export const MAX_APPROVAL_AUDIENCE_MEMBERS = 5_000;
/** Bound empty/tiny pages with ever-changing cursors independently of the member-entry cap. */
export const MAX_CHANNEL_MEMBER_PAGES = 100;
const SLACK_NOTIFICATION_CLIENT_OPTIONS = Object.freeze({
  retryConfig: { retries: 0 },
  timeout: SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS,
  rejectRateLimitedCalls: true,
  // The SDK's request timeout starts only AFTER its internal p-queue. A lower operator-supplied
  // concurrency could therefore serialize one 16-wide wave beyond the delivery lease.
  maxRequestConcurrency: APPROVAL_FANOUT_CONCURRENCY,
});
/** A custom installation store has no cancellation contract. Cap distinct unresolved workspace
 * lookups so a broken shared store cannot turn callback traffic into unbounded retained work. */
export const MAX_PENDING_NOTIFICATION_CLIENT_LOOKUPS = 32;

/** A bounded client for lease-guarded prompt posts and best-effort DMs. Preserves the operator's
 * transport (`base`: custom slackApiUrl, agent/proxy, tls, headers) so a deployment using a
 * non-default Slack endpoint is not bypassed; Vouchr's finite timeout, zero retries, and rate-limit
 * rejection are applied ON TOP and always win (spread last), so a slow post can never outlive its
 * delivery lease. */
function slackNotificationClient(token: string, base?: WebClientOptions): WebClient {
  return new WebClient(token, { ...base, ...SLACK_NOTIFICATION_CLIENT_OPTIONS });
}

/** Skipped because the fan-out's start deadline elapsed before this item was started. */
export class PromptFanoutDeadlineError extends Error {}

type SettledWithLimitResult = PromiseSettledResult<void> | {
  status: 'skipped';
  reason: PromptFanoutDeadlineError;
};

function monotonicElapsedMs(startNs: bigint): number {
  return Number(process.hrtime.bigint() - startNs) / 1e6;
}

class ApprovalAudienceResolutionError extends Error {}

/** Await one audience-resolution stage only through the shared monotonic overall deadline. The
 * underlying bounded WebClient call may finish later, but Promise.race owns its rejection and no
 * later result can mutate delivery state. */
async function withinApprovalAudienceDeadline<T>(
  work: Promise<T>,
  startedAtNs: bigint,
): Promise<T> {
  const remaining = APPROVAL_AUDIENCE_RESOLUTION_DEADLINE_MS - monotonicElapsedMs(startedAtNs);
  if (remaining <= 0) throw new ApprovalAudienceResolutionError('approval audience deadline elapsed');
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new ApprovalAudienceResolutionError('approval audience deadline elapsed')),
      remaining,
    );
    timer.unref?.();
  });
  try {
    return await Promise.race([work, deadline]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Fail-closed channel-membership proof under the same finite cursor/member/deadline contract used
 * for approval audiences. This covers every shared-credential use and interaction revalidation,
 * including custom clients whose pagination is malformed or whose request never settles. */
async function boundedChannelMembership(
  client: WebClient,
  channel: string,
  userId: string,
  clientOptions?: WebClientOptions,
): Promise<boolean> {
  const startedAtNs = process.hrtime.bigint();
  const withinDeadline = (): boolean => (
    monotonicElapsedMs(startedAtNs) < APPROVAL_AUDIENCE_RESOLUTION_DEADLINE_MS
  );
  try {
    const token = (client as { token?: unknown }).token;
    const memberClient = typeof token === 'string' && token.length > 0
      ? slackNotificationClient(token, clientOptions)
      : client;
    return await withinApprovalAudienceDeadline(
      isChannelMember(memberClient, channel, userId, {
        maxMembers: MAX_APPROVAL_AUDIENCE_MEMBERS,
        maxPages: MAX_CHANNEL_MEMBER_PAGES,
        continue: withinDeadline,
      }),
      startedAtNs,
    );
  } catch {
    return false;
  }
}

/** Fan `task` out over `items` with at most `limit` in flight, returning settled outcomes in order.
 * `deadlineMs` (optional) caps the start window: once elapsed, remaining items are recorded as a
 * `PromptFanoutDeadlineError` skip WITHOUT being started. Already-started work remains bounded by
 * the caller's per-operation timeout. */
export async function settledWithLimit<T>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<void>,
  deadlineMs?: number,
): Promise<SettledWithLimitResult[]> {
  const results = new Array<SettledWithLimitResult>(items.length);
  // Monotonic clock: this bounds a lease-relevant duration, and Date.now() can jump (NTP/clock set),
  // which could either blow the budget or never expire it. hrtime never runs backward.
  const startNs = process.hrtime.bigint();
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      if (deadlineMs !== undefined && monotonicElapsedMs(startNs) >= deadlineMs) {
        results[i] = { status: 'skipped', reason: new PromptFanoutDeadlineError('fan-out deadline elapsed') };
        continue;
      }
      try {
        await task(items[i]);
        results[i] = { status: 'fulfilled', value: undefined };
      } catch (reason) {
        results[i] = { status: 'rejected', reason };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
/** Reserve one bounded Slack post, the runtime pool wait + query timeout, and event-loop margin
 * before the 30s lease. The timer begins BEFORE claimDelivery, conservatively including its round
 * trip, so even a late-wave first success starts confirmation with the supported database budget. */
export const APPROVAL_DELIVERY_SAFETY_MARGIN_MS = 1_000;
export const APPROVAL_FANOUT_DEADLINE_MS = PROMPT_DELIVERY_LEASE_MS
  - SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS
  - DB_CONNECTION_TIMEOUT_MS
  - DB_RUNTIME_QUERY_TIMEOUT_MS
  - APPROVAL_DELIVERY_SAFETY_MARGIN_MS;

function boundedNotificationResolution<T>(work: Promise<T>): Promise<T | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: T | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS);
    timer.unref();
    void work.then((value) => finish(value), () => finish(null));
  });
}

/** No actionable Slack recipient exists, so delivery is known not to have happened. Network/API
 * rejection is deliberately NOT this type: Slack may have accepted before the caller saw failure. */
class NoApprovalDecisionSurfaceError extends Error {}
/** The local start budget expired before any corresponding Slack request began. Unlike a transport
 * failure this is known-undelivered, so the token-fenced lease can be released safely. */
class ApprovalPromptNotStartedError extends Error {}

type SlackPromptDeliveryFailure = 'platform-rejected' | 'rate-limited' | 'ambiguous';
type ApprovalPromptConfirmation = 'confirmed' | 'changed' | 'unknown';

async function promptConfirmationOutcome(confirm: () => Promise<boolean>): Promise<ApprovalPromptConfirmation> {
  try {
    return (await confirm()) ? 'confirmed' : 'changed';
  } catch {
    return 'unknown';
  }
}

function requirePromptConfirmation(
  confirmation: ApprovalPromptConfirmation,
  surface: 'approval' | 'session' | 'private connection',
): void {
  if (confirmation === 'changed') {
    throw new UserFacingError(
      `The ${surface} prompt was delivered, but its state was already handled or changed before confirmation. Ask the agent to resolve the current state before continuing.`,
      'resolve_again',
    );
  }
  if (confirmation === 'unknown') {
    throw new UserFacingError(
      `The ${surface} prompt was delivered, but Vouchr could not confirm its delivery state. If it appears, use it; otherwise ask the agent to retry shortly.`,
      'retry_later',
    );
  }
}

/** Preserve one classified outcome after an admin fan-out without retaining/rendering any foreign
 * Slack error content. A single ambiguous send dominates definite rejections because Slack may have
 * accepted that request before the transport failed locally. */
class SlackPromptDeliveryError extends Error {
  constructor(readonly outcome: Exclude<SlackPromptDeliveryFailure, 'ambiguous'>) {
    super('Slack prompt delivery was rejected');
  }
}

/** Slack Web API errors are structural interfaces, not reliable instanceof classes. Only the two
 * SDK codes that prove Slack did not accept the post release its delivery lease. HTTP, request,
 * generic, and even hostile accessor failures remain ambiguous (fail safe: the button may exist). */
function classifySlackPromptDeliveryFailure(error: unknown): SlackPromptDeliveryFailure {
  try {
    if (error instanceof SlackPromptDeliveryError) return error.outcome;
    const code = error && (typeof error === 'object' || typeof error === 'function')
      ? (error as { code?: unknown }).code
      : undefined;
    if (code === SlackErrorCode.PlatformError) return 'platform-rejected';
    if (code === SlackErrorCode.RateLimitedError) return 'rate-limited';
  } catch {
    return 'ambiguous';
  }
  return 'ambiguous';
}

function isNoApprovalDecisionSurface(error: unknown): boolean {
  try {
    return error instanceof NoApprovalDecisionSurfaceError;
  } catch {
    return false;
  }
}

function isApprovalPromptNotStarted(error: unknown): boolean {
  try {
    return error instanceof ApprovalPromptNotStartedError;
  } catch {
    return false;
  }
}

function slackPromptDeliveryRecovery(
  outcome: SlackPromptDeliveryFailure,
  surface: 'approval' | 'connection' | 'session' | 'configuration',
): UserFacingError {
  if (outcome === 'platform-rejected') {
    return new UserFacingError(
      `Slack rejected the ${surface} prompt before delivery. Ask an admin to check Vouchr’s Slack access, then ask the agent again.`,
      'fix_configuration',
    );
  }
  if (outcome === 'rate-limited') {
    return new UserFacingError(
      `Slack rate-limited the ${surface} prompt before delivery. Wait, then ask the agent again.`,
      'retry_later',
    );
  }
  return new UserFacingError(
    `Vouchr could not confirm ${surface}-prompt delivery. If a prompt appears, use it; otherwise ask the agent to retry shortly.`,
    'retry_later',
  );
}

async function abandonKnownUndeliveredPrompt(
  abandon: () => Promise<boolean>,
  surface: 'approval' | 'connection' | 'session',
  cause: 'slack-rejected' | 'no-decision-surface' | 'deadline' = 'slack-rejected',
): Promise<void> {
  const description = cause === 'slack-rejected'
    ? `Slack rejected the ${surface} prompt`
    : cause === 'no-decision-surface'
      ? `Vouchr found no ${surface} decision surface`
      : `Vouchr's ${surface} delivery window elapsed before posting`;
  let released: boolean;
  try {
    released = await abandon();
  } catch {
    throw new UserFacingError(
      `${description}, but could not reset its request state. Ask the agent to retry shortly.`,
      'retry_later',
    );
  }
  if (!released) {
    throw new UserFacingError(
      `The ${surface} request changed before its undelivered state could be cleared. Ask the agent again.`,
      'resolve_again',
    );
  }
}

/** Channel/thread carried by a Slack-signed block_action. These are context facts only, never
 * authority on their own: core compares them with the persisted request before mutation. */
function interactionLocation(body: any): { channel: string; thread: string | null } | null {
  const channel = body?.channel?.id ?? body?.container?.channel_id;
  const thread = body?.container?.thread_ts ?? body?.message?.thread_ts ?? null;
  if (typeof channel !== 'string' || channel.length < 1 || channel.length > 255) return null;
  if (thread !== null && (typeof thread !== 'string' || thread.length < 1 || thread.length > 255)) return null;
  return { channel, thread };
}

/**
 * The adapter half of invariant 6, ONE implementation for every mutation path: fetch the channel
 * class (null on any error → fails closed) and apply the core rule (channelIneligibleReason), so a
 * packaged broker + thin clients enforce the same rule rather than re-implementing it. Throws a
 * UserFacingError naming the reason — no audit row, exactly like ConnectContext.setChannelMode's
 * eligibility refusal (the audit-on-denial convention is for authz denials, reason 'not-admin').
 */
async function assertChannelEligible(client: WebClient, channel: string): Promise<void> {
  let info: ChannelInfo | null = null;
  try {
    info = ((await client.conversations.info({ channel })) as any)?.channel ?? null;
  } catch {
    info = null;
  }
  const reason = channelIneligibleReason(info);
  if (reason) throw new UserFacingError(reason);
}

export interface VouchrOptions {
  providers: Provider[];
  /** Public origin where the callback is reachable, e.g. https://abc.ngrok.io */
  baseUrl: string;
  /** Canonical absolute OAuth callback pathname. Default `/vouchr/oauth/callback`. */
  callbackPath?: string;
  /** PostgreSQL connection string. Falls back to VOUCHR_DATABASE_URL. Vouchr is PostgreSQL-only
   *  (#204) — no embedded/SQLite mode, no generic DATABASE_URL fallback. Ignored when `db` is given. */
  databaseUrl?: string;
  /** A pre-opened, caller-managed store (see `openDb`). Inject one to share a single pool across a
   *  multi-workspace host (or a test), instead of Vouchr opening its own from `databaseUrl`. When
   *  injected, the caller owns its lifecycle — `install().stop()` will NOT close it. */
  db?: Db;
  policy?: Policy;
  /** Bot token used only for post-callback success and recovery DMs. */
  botToken?: string;
  /** Transport options for the bounded clients Vouchr builds to post prompts and best-effort DMs
   *  (custom `slackApiUrl`, `agent`/proxy, `tls`, `headers`). Vouchr always enforces finite timeout,
   *  zero retries, rate-limit rejection, and lease-safe queue concurrency on top — those cannot be
   *  overridden. Set this to match your Bolt `App`'s `clientOptions` when it uses a non-default
   *  transport, or those prompts/DMs would bypass it. */
  slackClientOptions?: WebClientOptions;
  /**
   * Multi-workspace token source. When set, post-OAuth success and recovery DMs are sent with the
   * bot token of the CONNECTING user's own workspace (resolved per (enterpriseId, teamId)),
   * so an app installed to many workspaces / org-wide works. When omitted, Vouchr uses the single
   * `botToken`. Wire the SAME store into Bolt's OAuth `installationStore`.
   */
  installationStore?: InstallationStore;
  /** Connection lifetime. Defaults to idle 7d / max-age 30d. Pass `{}` to disable expiry. */
  ttl?: TtlPolicy;
  /** External secret-manager resolvers, keyed by source id (e.g. { 'aws-sm': resolveArn }). */
  resolvers?: Resolvers;
  /**
   * Optional KMS-style envelope encryption for at-rest secrets. When supplied, new writes wrap a
   * fresh per-secret data key with your KMS key (KEK); when omitted, at-rest crypto behaves exactly
   * as before (direct master-key encryption). Either way, existing rows still decrypt.
   */
  envelope?: EnvelopeProvider;
  /**
   * Optional structured, NO-SECRET event hook for metrics/logs. Called fire-and-forget at key
   * points (inject, refresh, egress deny, connect, revoke, sweep). A throwing sink never affects
   * behavior. Events carry only non-secret fields (provider id, host, status, counts, booleans),
   * never tokens, references, or user/team ids.
   */
  onEvent?: EventSink;
  /**
   * Optional audit STREAM sink for host-side ingestion (e.g. a Redis stream the host consumes into
   * its own store). Fires IN ADDITION to the authoritative `audit` table at fetch / refresh /
   * consent. Unlike `onEvent` (deliberately actor-free), this carries the RAW acting user id so a
   * host can answer "who used this token, when, against which host". The streamed copy is LOSSY by
   * design (a capped stream may drop events) — the table remains the source of truth. Each event
   * carries a `jti` for idempotent host-side ingest. No-op when unset. Never carries token material.
   */
  auditSink?: AuditSink;
  /**
   * Custom admin check for channel-credential config (governance). When set, `requireAdmin` uses
   * it INSTEAD of the built-in gate, e.g. to defer to your own RBAC or an allow-list. When omitted,
   * the default gate is workspace admin/owner only. Use `allowChannelCreatorConfig: true` when a
   * channel's creator should self-serve without waiting for IT. The
   * default-deny + audit-on-denial behavior is identical regardless of which check runs. Fail closed
   * yourself: a thrown override is treated as "not admin".
   */
  isAdmin?: (client: WebClient, userId: string, teamId: string) => Promise<boolean>;
  /**
   * Opt in to letting a channel's CREATOR (not only a workspace admin) run the channel-credential
   * config commands (`mode`, `configure`, `enable`, `disable`). Default false: the gate is exactly
   * workspace-admin-only, unchanged from before this option existed. Off by default on purpose — in
   * Slack any member can create a public channel, so `creator` is not inherently a privileged role;
   * turn this on only where a channel owner should self-serve their own channel's config. Ignored
   * when a custom `isAdmin` is set (the override fully decides). See `isChannelAdmin` for the private-
   * channel / deactivated-creator caveats.
   */
  allowChannelCreatorConfig?: boolean;
  /**
   * When true, using a SHARED channel credential (`connectChannel`) requires the ACTING user to be
   * a member of the channel; a non-member (or a membership check we can't verify) is refused
   * fail-closed and audited 'denied' with reason 'not-member'. Default false: membership is not
   * checked, behaving exactly as before.
   */
  requireChannelMembership?: boolean;
  /**
   * Safety-ceiling lifetime for a thread session grant, in ms (default 8h). A grant always expires
   * after this, regardless of thread activity. Which providers use sessions is a per-channel setting
   * (`/vouchr mode <provider> session`), not a global list; this only tunes the ceiling.
   */
  sessionTtlMs?: number;
  /**
   * Pluggable store for the per-(owner, provider) token buckets behind `provider.rateLimit`. The
   * default is in-memory per-process — a multi-instance deployment multiplies the effective limit by
   * replica count unless a shared store is supplied. Providers without `rateLimit` are never limited,
   * store or not.
   */
  rateLimitStore?: RateLimitStore;
  /**
   * #117 credential-health hook: fired when a connection needs (or is about to need) human
   * attention — a DEFINITIVELY dead refresh token (`refresh_dead`, never on transient failures),
   * a connection within 72h of its TTL ceiling (`expiring_soon`, per sweep pass), or a swept
   * connection (`expired`). Events carry the owning principal + provider, never token material.
   * When omitted, the DEFAULT wiring DMs the credential owner (the configuring admin for a
   * channel-owned credential), with ask-the-agent-again guidance on `refresh_dead`, debounced to one DM per
   * (owner, provider, type) per 24h via the persistent `notification_state` table. Setting this
   * REPLACES the default DMs (same override contract as `isAdmin`) — debounce with the exported
   * `NotificationState` if your notifier needs it. Note the hook is wired while createVouchr is
   * still constructing (no `db` in hand yet), so an override must LATE-BIND its debounce store:
   * construct `new NotificationState(vouchr.db)` after createVouchr returns (or from your own
   * openDb handle) and reference it from inside the hook. Fire-and-forget; a throwing hook never
   * affects a request or the sweep.
   */
  onCredentialHealth?: CredentialHealthHook;
  /**
   * #116 dry-run: run the REAL consent state machine, channel modes, policy, tool allowlists,
   * egress gates, vault, and audit — under the invariant that NO real network call leaves the
   * process. The OAuth exchange yields a synthetic credential (marked `external_account:
   * 'dry-run'`; the Connect button's authorize URL becomes a local, instantly-succeeding redirect
   * into the real callback); `handle.fetch()` returns a `200 { dryRun, method, url, wouldInjectAs }`
   * echo instead of calling the provider — AFTER every request gate has run and the (synthetic)
   * credential was read from the vault; token refresh and upstream revoke are likewise skipped for
   * dry-run rows. The credential never appears in the echo. Request-side denials throw exactly as
   * in production. Safety rails: startup hard-fails if the database already holds non-dry-run
   * credential rows, a request refuses (and the dry-run callback never overwrites) a real row
   * written later, and every audit row written in dry-run carries `meta.dry_run: true`. Complete a
   * prompted consent programmatically in tests via `vouchr.dryRun.completeConsent(user, provider)`.
   * Default false: zero behavior change.
   */
  dryRun?: boolean;
}

/**
 * Deps/options for {@link ConnectContext}. A single named-field object instead of a ~20-arg
 * positional list: adjacent same-typed args (e.g. two `string | null`s, several optional stores)
 * can no longer be silently mis-ordered past the type-checker. Optional fields keep their old
 * defaults (see the constructor).
 */
export interface ConnectContextDeps {
  identity: SlackIdentity;
  channel: string | null;
  client: WebClient;
  registry: ProviderRegistry;
  vault: Vault;
  audit: Audit;
  consent: Consent;
  policy: Policy;
  redirectUri: string;
  resolvers?: Resolvers;
  channelConfig?: ChannelConfig;
  /** Per-channel tool manifest (which providers an agent may use here). Threaded like channelConfig. */
  channelTools?: ChannelTools;
  /** Shared single-flight refresh map (see ConnectionHandle). One per createVouchr instance. */
  inflight?: Map<string, Promise<string | null>>;
  /** Shared per-(owner, provider) rate-limit buckets (see ConnectionHandle). One per createVouchr
   *  instance — a per-request store would never accumulate budget across requests. */
  rateLimits?: RateLimitStore;
  /** No-secret observability hook. Default no-op (zero behavior change when unset). */
  sink?: EventSink;
  /** The registered provider ids, for toolManifest(). Mirrors the registry; empty = none listed. */
  providerIds?: string[];
  /** Governance: custom admin check (overrides the default). Undefined = built-in gate. */
  adminCheck?: (client: WebClient, userId: string, teamId: string) => Promise<boolean>;
  /** Governance: opt in to the channel-creator config path. Default false = workspace-admin-only. */
  allowChannelCreatorConfig?: boolean;
  /** Governance: when true, connectChannel requires the acting user to be a channel member. */
  requireMembership?: boolean;
  /** The Slack thread (thread_ts) this request is in, for thread-scoped sessions. Null off-thread. */
  thread?: string | null;
  /** Thread session-grant store. The 'session' channel mode drives whether the gate runs. */
  sessions?: SessionGrants;
  /** #113 human-in-the-loop approval store (provider.approval). Absent + a provider that declares
   *  the knob = the injector fails closed (a declared approval is never silently skipped). */
  approvals?: Approvals;
  /** Optional audit stream sink (raw actor id). Default no-op; the audit table stays authoritative. */
  auditSink?: AuditSink;
  /** #117 credential-health hook threaded to every ConnectionHandle (see VouchrOptions). Default no-op. */
  health?: CredentialHealthHook;
  /** Cross-replica notification debounce (shared with the #117 health DMs). The recovery bridge's
   *  admin channel-configuration direction claims it so repeated broker denials cannot spam the
   *  responsible admin. Absent = the bridge skips the admin DM (actor guidance still posts). */
  notifications?: NotificationState;
  /** #116 dry-run: threaded to every ConnectionHandle so the final outbound call is stubbed (see
   *  VouchrOptions.dryRun). Default false: unchanged behavior. */
  dryRun?: boolean;
  /** Transport options for bounded prompt/DM clients (see VouchrOptions.slackClientOptions). */
  slackClientOptions?: WebClientOptions;
}

/** Everything the Approve/Deny delivery needs, whether hydrated from an in-process
 * ApprovalRequiredError (the fetch wrapper) or from a broker-minted pending row plus the current
 * registry rule (the recovery bridge). `thread` is the conversation the pending action is bound
 * to: the wrapper passes the event thread; the bridge passes the stored row's thread so the click
 * lands in — and binds to — the same context the broker enforces at consume time. */
type ApprovalPromptSpec = {
  provider: string;
  approver: 'self' | 'admin';
  method: string;
  host: string;
  actionFingerprint: string;
  approvalId: string;
  /** `null` = query present, exact count not retained (see approvalBlocks). */
  queryParamCount: number | null;
  /** True only for the creator of the deduplicated pending row: an abandoned known-undelivered
   * prompt then removes the row. False (a reused id, or a broker-minted row the bridge delivers)
   * only releases the delivery lease so a later attempt can post. */
  newRequest: boolean;
  thread: string | null;
};

/**
 * Typed outcome of {@link ConnectContext.recoverBrokerDenial}: which private Slack recovery action
 * the trusted control plane took for a relayed broker denial. Hosts branch on `status`; the worker
 * retries a brokered call only after the human acts, and always with a freshly minted single-use
 * identity assertion.
 *
 * - `resolved` — current verified state no longer produces that denial (stale relay, mode change,
 *   or the approval rule no longer applies). This is not replay authority: stop this turn and let a
 *   new user-triggered turn repeat preflight and mint a fresh single-use assertion.
 * - `connect_prompted` — the private connect/key-setup flow posted (or reused) its prompt; stop
 *   this turn (`promptState` mirrors ConsentRequiredError).
 * - `session_prompted` — the thread-scoped session approval prompt is live in the thread.
 * - `approval_prompted` — the Approve/Deny decision surface is live (`approver` says whose).
 * - `configuration_required` — shared-owner credential is missing; an eligible admin was directed
 *   to channel configuration (never a personal connect prompt).
 * - `stale` — no live pending approval matches the relayed reference: it was decided, expired, or
 *   never existed. This is not replay authority: a new user-triggered turn must repeat preflight and
 *   mint a fresh assertion, re-evaluating and re-minting the request if still needed.
 * - `not_bridgeable` — the relayed code is not a broker denial this bridge recovers (or the input
 *   was not a valid BrokerError shape). Handle it with mapSafeError guidance instead.
 */
export type BrokerDenialRecovery =
  | { status: 'resolved'; provider: string }
  | { status: 'connect_prompted'; provider: string; promptState: ConsentPromptState }
  | { status: 'session_prompted'; provider: string }
  | { status: 'approval_prompted'; provider: string; approver: 'self' | 'admin' }
  | { status: 'configuration_required'; provider: string }
  | { status: 'stale'; provider: string }
  | { status: 'not_bridgeable' };

// Bolt owns the trusted event-receipt instant. Keep the override module-private so neither a
// caller nor any forgeable Slack field can choose a newer provisioning issuance. Normal direct
// construction falls back to the constructor's own monotonic instant.
const INTERNAL_PROVISIONING_RECEIVED_AT = Symbol('vouchr.provisioning-received-at');
const INTERNAL_CHANNEL_PROVISIONING_ISSUANCE = Symbol('vouchr.channel-provisioning-issuance');
type InternalConnectContextDeps = ConnectContextDeps & {
  [INTERNAL_PROVISIONING_RECEIVED_AT]?: bigint;
  [INTERNAL_CHANNEL_PROVISIONING_ISSUANCE]?: ChannelProvisioningIssuance;
};

/** Map a verified handler's monotonic receipt instant into PostgreSQL's clock domain. Query latency
 * is included in the subtraction and fractional milliseconds round up, so uncertainty can only
 * make the issuance older (fail closed), never newer than the received interaction. */
async function provisioningIssuedAtFromReceipt(vault: Vault, receivedAt: bigint): Promise<number> {
  const pgNow = await vault.userProvisioningIssuedAt();
  const elapsedNs = process.hrtime.bigint() - receivedAt;
  if (elapsedNs < 0n) throw new Error('invalid provisioning receipt clock');
  const elapsedMs = Number((elapsedNs + 999_999n) / 1_000_000n);
  const issuedAt = pgNow - elapsedMs;
  if (!Number.isSafeInteger(issuedAt)) throw new Error('could not issue provisioning fence');
  return issuedAt;
}

class ChannelProvisioningStaleError extends UserFacingError {
  constructor() {
    super(
      'Channel credential setup changed while Vouchr was preparing it. Reopen setup and review the current state.',
      'resolve_again',
    );
    this.name = 'ChannelProvisioningStaleError';
  }
}

/** Per-request handle attached to Bolt's `context.vouchr`. */
export class ConnectContext {
  private identity: SlackIdentity;
  private channel: string | null;
  private client: WebClient;
  private registry: ProviderRegistry;
  private vault: Vault;
  private audit: Audit;
  private consent: Consent;
  private policy: Policy;
  private redirectUri: string;
  private resolvers: Resolvers;
  private channelConfig?: ChannelConfig;
  private channelTools?: ChannelTools;
  private inflight: Map<string, Promise<string | null>>;
  private rateLimits: RateLimitStore;
  private sink: EventSink;
  private providerIds: string[];
  private adminCheck?: (client: WebClient, userId: string, teamId: string) => Promise<boolean>;
  private allowChannelCreatorConfig: boolean;
  private requireMembership: boolean;
  private thread: string | null;
  private sessions?: SessionGrants;
  private approvals: Approvals | null;
  private auditSink: AuditSink;
  private health: CredentialHealthHook;
  private notifications: NotificationState | null;
  private dryRun: boolean;
  private slackClientOptions?: WebClientOptions;
  private provisioningReceivedAt: bigint;
  private channelProvisioningIssuance?: ChannelProvisioningIssuance;

  constructor(deps: ConnectContextDeps) {
    this.identity = deps.identity;
    this.channel = deps.channel;
    this.client = deps.client;
    this.registry = deps.registry;
    this.vault = deps.vault;
    this.audit = deps.audit;
    this.consent = deps.consent;
    this.policy = deps.policy;
    this.redirectUri = deps.redirectUri;
    this.resolvers = deps.resolvers ?? {};
    this.channelConfig = deps.channelConfig;
    this.channelTools = deps.channelTools;
    this.inflight = deps.inflight ?? new Map();
    this.rateLimits = deps.rateLimits ?? new MemoryRateLimitStore();
    this.sink = deps.sink ?? (() => {});
    this.providerIds = deps.providerIds ?? [];
    this.adminCheck = deps.adminCheck;
    this.allowChannelCreatorConfig = deps.allowChannelCreatorConfig ?? false;
    this.requireMembership = deps.requireMembership ?? false;
    this.thread = deps.thread ?? null;
    this.sessions = deps.sessions;
    this.approvals = deps.approvals ?? null;
    this.auditSink = deps.auditSink ?? (() => {});
    this.health = deps.health ?? (() => {});
    this.notifications = deps.notifications ?? null;
    this.dryRun = deps.dryRun ?? false;
    this.slackClientOptions = deps.slackClientOptions;
    this.provisioningReceivedAt =
      (deps as InternalConnectContextDeps)[INTERNAL_PROVISIONING_RECEIVED_AT]
      ?? process.hrtime.bigint();
    this.channelProvisioningIssuance =
      (deps as InternalConnectContextDeps)[INTERNAL_CHANNEL_PROVISIONING_ISSUANCE];
  }

  /** Map this verified request's monotonic receipt instant into PostgreSQL's clock domain. Query
   * latency is included in the elapsed subtraction and fractional milliseconds round up, so clock
   * uncertainty can only make the issuance older (fail closed), never newer than the request. */
  private async provisioningIssuedAt(): Promise<number> {
    return provisioningIssuedAtFromReceipt(this.vault, this.provisioningReceivedAt);
  }

  /** Refuse every prompt/recovery/setup entry before it can ask a human for a new credential. The
   * Vault repeats the check at read/write boundaries; this earlier adapter gate keeps lockdown from
   * collecting OAuth grants, static keys, or external references that it will only discard. */
  private assertCredentialAccessAvailable(): void {
    if (this.vault.lockdownEnabled) throw new CredentialLockdownError();
  }

  /** Fire the sink, swallowing any error. A bad sink must never break a request. */
  private emit(e: VouchrEvent): void {
    safeEmit(this.sink, e);
  }

  /**
   * Slack surface for a rate-limited fetch (mirrors how connect() owns the consent prompts): tell
   * the acting user ephemerally, then rethrow — the typed RateLimitedError still reaches the caller,
   * so the ephemeral is extra feedback, not the only path. The post is best-effort: a Slack hiccup
   * must never replace the typed error the agent branches on. Fields come from the error (registry
   * provider id + numbers), and the provider id is escaped at render per SEC-5.
   */
  private notifyRateLimited(handle: ConnectionHandle): ConnectionHandle {
    const fetch = handle.fetch.bind(handle);
    handle.fetch = async (input: string, init: RequestInit = {}) => {
      try {
        return await fetch(input, init);
      } catch (e) {
        if (e instanceof RateLimitedError && this.channel) {
          await this.client.chat.postEphemeral({
            channel: this.channel,
            user: this.identity.userId,
            text: `Slow down: ${escapeMrkdwn(e.provider)} is limited to ${e.perMinute} requests/min, try again in ${Math.ceil(e.retryAfterMs / 1000)}s.`,
          }).catch(() => undefined);
        }
        throw e;
      }
    };
    return handle;
  }

  /**
   * Slack surface for the #113 approval gate (mirrors notifyRateLimited's wrapper shape): when a
   * fetch throws ApprovalRequiredError, post the Approve/Deny prompt — ephemerally to the acting
   * user for approver 'self', ephemerally to each eligible admin for 'admin' — then rethrow, so
   * the typed error still reaches the caller (catch-and-stop-turn, exactly like
   * ConsentRequiredError). If no actionable decision surface is delivered, remove only the id this
   * fetch minted and throw fixed retry guidance instead of falsely claiming a prompt was posted.
   * The blocks show provider/method/host plus a salted action fingerprint; raw path/query/body never
   * reach Slack (SEC-1). Buttons carry only the pending id (SEC-3 — authority is re-decided at click).
   */
  private notifyApprovalRequired(handle: ConnectionHandle): ConnectionHandle {
    const fetch = handle.fetch.bind(handle);
    handle.fetch = async (input: string, init: RequestInit = {}) => {
      try {
        return await fetch(input, init);
      } catch (e) {
        if (e instanceof ApprovalRequiredError) {
          await this.deliverApprovalPrompt({
            provider: e.provider,
            approver: e.approver,
            method: e.method,
            host: e.host,
            actionFingerprint: e.actionFingerprint,
            approvalId: e.approvalId,
            queryParamCount: e.queryParamCount,
            newRequest: e.newRequest,
            thread: this.thread,
          });
        }
        throw e;
      }
    };
    return handle;
  }

  /** Render, lease, post, and confirm the Approve/Deny prompt for ONE pending approval. The single
   * delivery path for both doors (STR-3): the in-process fetch wrapper builds the spec from its
   * ApprovalRequiredError; the broker-to-Slack recovery bridge hydrates it from the stored pending
   * row plus the current registry rule. Throws typed UserFacingError recovery on every failure;
   * returns normally when the prompt is delivered (or a live delivery already was). */
  private async deliverApprovalPrompt(spec: ApprovalPromptSpec): Promise<void> {
    let prompt: { blocks: any; fallback: { text: string } | Record<string, never> };
    try {
      const blocks = approvalBlocks({
        provider: spec.provider,
        method: spec.method,
        host: spec.host,
        actionFingerprint: spec.actionFingerprint,
        queryParamCount: spec.queryParamCount,
        requester: this.identity.userId,
        id: spec.approvalId,
        approver: spec.approver,
      }) as any;
      prompt = { blocks, fallback: optionalBlockFallback(blocks) };
    } catch {
      // Rendering happens before a delivery claim or Slack call, so this is a KNOWN no-post
      // failure. Remove the impossible request rather than parking it behind an unknown lease.
      await this.approvals?.discardPending(spec.approvalId).catch(() => undefined);
      throw new UserFacingError(
        'Vouchr could not render a complete approval prompt for this action. Ask an admin to narrow the endpoint.',
      );
    }
    // Resolve the complete current admin recipient set BEFORE claiming the delivery lease. The
    // bounded client plus one overall deadline/cap prevents pagination or member-by-member admin
    // checks from hanging recovery. The exact set also binds the persisted delivered marker: a
    // self→admin rule or admin-roster change must produce a fresh usable surface.
    const approvers = spec.approver === 'admin' && this.channel ? await this.eligibleApprovers() : [];
    const audience = approvalDeliveryAudienceKey(
      spec.approvalId,
      spec.approver,
      spec.approver === 'self' ? [this.identity.userId] : approvers,
    );
    // Start the conservative local budget BEFORE the claim round-trip. PostgreSQL creates the
    // lease during that call, so including the whole round-trip can only shorten our posting
    // window; it can never make us believe more lease remains than actually does.
    const deliveryLeaseStartedAtNs = process.hrtime.bigint();
    const delivery = await this.approvals?.claimDelivery(spec.approvalId, audience);
    if (!delivery || delivery.status === 'stale') {
      throw new UserFacingError(
        'The approval request changed before delivery. Ask the agent to retry the action.',
        'resolve_again',
      );
    }
    if (delivery.status === 'in-flight') {
      throw new UserFacingError(
        'An approval prompt is still being delivered. Ask the agent to retry shortly.',
        'retry_later',
      );
    }
    if (delivery.status === 'claimed') {
      let confirmation: ApprovalPromptConfirmation;
      try {
        // postApprovalPrompt owns confirmation: it confirms the FIRST successful delivery
        // immediately (single-flight). Its posting budget reserves the full bounded database
        // confirmation window even when every earlier wave failed.
        confirmation = await this.postApprovalPrompt(
          spec, prompt, approvers,
          () => this.approvals!.confirmDelivery(spec.approvalId, delivery.token, audience),
          deliveryLeaseStartedAtNs,
        );
      } catch (deliveryError) {
        const notStarted = isApprovalPromptNotStarted(deliveryError);
        if (notStarted) {
          if (this.approvals) {
            await abandonKnownUndeliveredPrompt(
              () => this.approvals!.abandonDelivery(
                spec.approvalId,
                delivery.token,
                audience,
                spec.newRequest,
              ),
              'approval',
              'deadline',
            );
          }
          throw new UserFacingError(
            'Vouchr’s approval delivery window elapsed before a prompt could be sent. Ask the agent to retry shortly.',
            'retry_later',
          );
        }
        const noSurface = isNoApprovalDecisionSurface(deliveryError);
        if (noSurface) {
          if (this.approvals) {
            await abandonKnownUndeliveredPrompt(
              () => this.approvals!.abandonDelivery(
                spec.approvalId,
                delivery.token,
                audience,
                spec.newRequest,
              ),
              'approval',
              'no-decision-surface',
            );
          }
          throw new UserFacingError(
            'Vouchr could not find an approval decision surface. Ask the agent to retry in an eligible channel.',
            'fix_configuration',
          );
        }
        const outcome = classifySlackPromptDeliveryFailure(deliveryError);
        if (outcome !== 'ambiguous' && this.approvals) {
          await abandonKnownUndeliveredPrompt(
            () => this.approvals!.abandonDelivery(
              spec.approvalId,
              delivery.token,
              audience,
              spec.newRequest,
            ),
            'approval',
          );
        }
        throw slackPromptDeliveryRecovery(outcome, 'approval');
      }
      // Confirmation outcomes are typed return values, outside the Slack-delivery catch: a
      // database failure can never be mistaken for either Slack rejection or request drift.
      requirePromptConfirmation(confirmation, 'approval');
    }
  }

  /** Recheck channel-governance facts while Approvals holds both the channel and credential locks. */
  private async approvalRequestStillCurrent(
    actorIssuedAt: number,
    key: ApprovalKey,
    tx: Db,
    locked: Pick<Vault, 'liveId'>,
  ): Promise<boolean> {
    if (!this.registry.has(key.provider) || !isBrokeredProvider(this.registry.get(key.provider))) return false;
    const approval = this.registry.get(key.provider).approval;
    if (!approval || !approvalNeeded(approval, key.method, key.path)) return false;
    return credentialUseStillCurrentFenced({
      binding: key,
      db: tx,
      registry: this.registry,
      policy: this.policy,
      vault: locked,
      enterpriseId: this.identity.enterpriseId,
      actorIssuedAt,
      channelTools: this.channelTools ?? null,
      channelConfig: this.channelConfig ?? null,
    });
  }

  /** Build the use-time validator for every Bolt handle. Handles are public and may be retained, so
   * every use rechecks the actor's offboard receipt, current owner/mode/policy/tool/session state,
   * and exact credential generation. Shared credentials also recheck live Slack channel safety and
   * the acting user's membership before entering the database-locked validation. */
  private useValidator(
    owner: Owner,
    provider: string,
    credentialId: string,
    channel: string | null,
    thread: string | null,
    actorIssuedAt: number,
  ): () => Promise<boolean> {
    return async () => {
      if (owner.kind === 'channel') {
        if (!channel) return false;
        try {
          await assertChannelEligible(this.client, channel);
        } catch {
          return false;
        }
        if (!(await boundedChannelMembership(
          this.client,
          channel,
          this.identity.userId,
          this.slackClientOptions,
        ))) return false;
      }
      return this.vault.withCredentialLocks(
        [
          ...(channel ? [{ owner: channelOwner(this.identity.teamId, channel), provider }] : []),
          { owner: userOwner(this.identity), provider },
          { owner, provider },
        ],
        async (locked, tx) => {
          const state = await credentialUseStateFenced({
            binding: {
              teamId: this.identity.teamId,
              userId: this.identity.userId,
              ownerKind: owner.kind,
              ownerId: owner.id,
              credentialId,
              provider,
              channel,
              thread,
            },
            db: tx,
            registry: this.registry,
            policy: this.policy,
            vault: locked,
            enterpriseId: this.identity.enterpriseId,
            actorIssuedAt,
            channelTools: this.channelTools ?? null,
            channelConfig: this.channelConfig ?? null,
          });
          if (state !== 'current') throw new InteractionStateChangedError('connection', state);
          return true;
        },
      );
    };
  }

  /** Client for lease-guarded prompt posts. A leased post must terminate well inside its
   * PROMPT_DELIVERY_LEASE_MS: the default WebClient has no request timeout and silently queues
   * rate-limited retries for up to ~30 minutes, so a slow post outlives its lease and a takeover
   * replica double-delivers the prompt (the caller then also mis-reports its own landed post).
   * Real Bolt clients carry their resolved token — post through a bounded twin (no retries, short
   * timeout, 429 rejected). A test double without a token string is already immediate; use as-is. */
  private promptClient(): WebClient {
    const token = (this.client as { token?: unknown }).token;
    return typeof token === 'string' && token.length > 0
      ? slackNotificationClient(token, this.slackClientOptions)
      : this.client;
  }

  /** Post the Approve/Deny prompt for one pending approval to whoever may decide it. `approvers` is
   * resolved by the caller BEFORE the delivery lease is claimed because even bounded Slack reads
   * consume a separate pre-delivery budget; it is empty for 'self'/off-channel approvals. */
  private async postApprovalPrompt(
    spec: ApprovalPromptSpec,
    prompt: { blocks: any; fallback: { text: string } | Record<string, never> },
    approvers: string[],
    /** Marks the prompt delivered and consumes the lease; returns false if the request changed
     * first. Owned here so the FIRST successful delivery confirms immediately, before a large
     * best-effort fan-out finishes. */
    confirm: () => Promise<boolean>,
    /** Monotonic instant captured before claimDelivery; the posting deadline includes that round trip. */
    deliveryLeaseStartedAtNs: bigint,
  ): Promise<ApprovalPromptConfirmation> {
    const client = this.promptClient();
    const { blocks, fallback } = prompt;
    const threadArg = spec.thread ? { thread_ts: spec.thread } : {};
    // Convert rejection immediately so a background confirmation can never become an unhandled
    // rejection while the remaining fan-out settles. Preserve false (state drift) separately from
    // rejection (database outcome unknown) so recovery copy stays truthful.
    let confirmPromise: Promise<ApprovalPromptConfirmation> | undefined;
    const confirmOnce = (): Promise<ApprovalPromptConfirmation> => (
      confirmPromise ??= promptConfirmationOutcome(confirm)
    );
    const remainingPostingBudget = (): number => Math.max(
      0,
      APPROVAL_FANOUT_DEADLINE_MS - monotonicElapsedMs(deliveryLeaseStartedAtNs),
    );
    if (spec.approver === 'self') {
      if (remainingPostingBudget() <= 0) {
        throw new ApprovalPromptNotStartedError('approval delivery budget elapsed before posting');
      }
      if (this.channel) {
        await client.chat.postEphemeral({ channel: this.channel, user: this.identity.userId, ...threadArg, blocks, ...fallback });
      } else {
        await client.chat.postMessage({ channel: this.identity.userId, blocks, ...fallback });
      }
      return confirmOnce();
    }
    // 'admin': the channel is the approval surface. Off-channel (a DM) there are no channel admins
    // to prompt — tell the requester why nothing can proceed instead of failing silently (STR-5).
    if (!this.channel) {
      await client.chat.postMessage({
        channel: this.identity.userId,
        text: `This ${escapeMrkdwn(spec.provider)} action needs an admin's approval — run it in a channel so an admin can approve it.`,
      }).catch(() => undefined);
      throw new NoApprovalDecisionSurfaceError('admin approval requires a channel decision surface');
    }
    let delivered = false;
    let sawAmbiguousFailure = false;
    let ambiguousFailure: unknown;
    let definiteFailure: Exclude<SlackPromptDeliveryFailure, 'ambiguous'> | undefined;
    let skippedForDeadline = false;
    // Post to every eligible admin CONCURRENTLY (bounded in-flight + start deadline). The FIRST
    // successful post triggers confirmation once in the background. The start deadline reserves the
    // supported post + database budgets, so planned fan-out cannot exhaust the lease first.
    const channel = this.channel;
    const results = await settledWithLimit(
      approvers,
      APPROVAL_FANOUT_CONCURRENCY,
      async (admin) => {
        await client.chat.postEphemeral({ channel, user: admin, ...threadArg, blocks, ...fallback });
        void confirmOnce();
      },
      remainingPostingBudget(),
    );
    for (const result of results) {
      if (result.status === 'fulfilled') {
        delivered = true;
        continue;
      }
      if (result.status === 'skipped') {
        skippedForDeadline = true;
        continue;
      }
      // If any send has an ambiguous transport outcome, the aggregate must remain ambiguous even when
      // every sibling was definitely rejected: at least one actionable prompt may still have reached Slack.
      const outcome = classifySlackPromptDeliveryFailure(result.reason);
      if (outcome === 'ambiguous') {
        sawAmbiguousFailure = true;
        ambiguousFailure ??= result.reason;
      }
      else if (outcome === 'rate-limited' || definiteFailure === undefined) definiteFailure = outcome;
    }
    if (!approvers.length) {
      // No eligible admin visible from here (fail-closed member/admin reads): the requester should
      // know the request is parked, not silently dropped.
      await client.chat.postEphemeral({
        channel: this.channel, user: this.identity.userId, ...threadArg,
        text: `This ${escapeMrkdwn(spec.provider)} action needs an admin's approval, but no eligible admin was found in this channel.`,
      }).catch(() => undefined);
    }
    // A requester-only explanation is not an approval surface. Reject when zero eligible admins or
    // every approver delivery failed so notifyApprovalRequired removes only this minted id; a later
    // turn can create and deliver a fresh prompt instead of being parked behind dedup for 10m.
    if (!delivered) {
      if (!approvers.length) throw new NoApprovalDecisionSurfaceError('no eligible approval recipient');
      if (sawAmbiguousFailure) {
        throw ambiguousFailure ?? new Error('approval prompt delivery outcome is unknown');
      }
      if (definiteFailure !== undefined) throw new SlackPromptDeliveryError(definiteFailure);
      if (skippedForDeadline) {
        throw new ApprovalPromptNotStartedError('approval delivery budget elapsed before posting');
      }
      throw new Error('approval prompt delivery outcome is unknown');
    }
    // At least one admin was delivered, so confirmation was triggered on the first success.
    return confirmPromise ?? 'unknown';
  }

  /**
   * Channel members who may decide an 'admin' approval: the SAME eligibility rule as every channel
   * config mutation (adminEligible — custom override, else workspace admin OR the channel creator
   * when opted in). Incomplete/over-budget reads fail with fixed retry guidance before delivery is
   * claimed; an empty complete snapshot means there is currently no usable decision surface.
   */
  private async eligibleApprovers(): Promise<string[]> {
    const startedAtNs = process.hrtime.bigint();
    const withinDeadline = (): boolean => (
      monotonicElapsedMs(startedAtNs) < APPROVAL_AUDIENCE_RESOLUTION_DEADLINE_MS
    );
    const client = this.promptClient();
    try {
      const members = await withinApprovalAudienceDeadline(
        listChannelMembers(client, this.channel!, {
          maxMembers: MAX_APPROVAL_AUDIENCE_MEMBERS,
          maxPages: MAX_CHANNEL_MEMBER_PAGES,
          continue: withinDeadline,
        }),
        startedAtNs,
      );
      if (!members) throw new ApprovalAudienceResolutionError('incomplete channel member set');
      const out: string[] = [];
      const results = await withinApprovalAudienceDeadline(
        settledWithLimit(
          members,
          APPROVAL_FANOUT_CONCURRENCY,
          async (userId) => {
            if (!withinDeadline()) {
              throw new ApprovalAudienceResolutionError('approval audience deadline elapsed');
            }
            if (await adminEligible(
              client,
              userId,
              this.identity.teamId,
              this.channel!,
              this.adminCheck,
              this.allowChannelCreatorConfig,
            )) out.push(userId);
          },
          Math.max(0, APPROVAL_AUDIENCE_RESOLUTION_DEADLINE_MS - monotonicElapsedMs(startedAtNs)),
        ),
        startedAtNs,
      );
      if (results.some((result) => result.status !== 'fulfilled')) {
        throw new ApprovalAudienceResolutionError('incomplete approval audience');
      }
      return out.sort();
    } catch {
      throw new UserFacingError(
        'Vouchr could not verify the current approval recipients in time. Ask the agent to retry shortly.',
        'retry_later',
      );
    }
  }

  /**
   * Return a leak-safe handle for the user's connection to `providerId`.
   * If they haven't connected, post an ephemeral Block Kit Connect prompt and
   * throw ConsentRequiredError (the caller should stop this turn).
   */
  /**
   * Fetch a provider AND refuse service-to-service tools. `identity: 'service'` tools have no human
   * credential to broker — the host runs them with its own service auth (see ToolManifestEntry.identity
   * / Provider.identity) — so EVERY Vouchr credential entry point (connect, user/channel key storage,
   * channel mode) routes through here, not just connect(). Also validates the provider exists.
   */
  private brokerable(providerId: string): Provider {
    const provider = this.registry.get(providerId);
    if (!isBrokeredProvider(provider)) {
      throw new UserFacingError(
        `"${providerId}" is a service-to-service tool; Vouchr does not broker it. Call it with your host's service auth.`,
      );
    }
    return provider;
  }

  /** The Bolt-side deny mapping of the shared authorizeProvider check. connectChannel keeps its own
   * variant because its audit metadata carries `owner: 'channel'`. */
  private async requireProviderAuthorized(providerId: string): Promise<void> {
    const denial = await authorizeProvider(this.policy, this.channelTools, this.identity, this.channel, providerId);
    if (denial === 'policy') {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel });
      this.emit({ type: 'policy_denied', provider: providerId });
      throw new PolicyDeniedError();
    }
    if (denial === 'tool-disabled') {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel, reason: 'tool-disabled' });
      throw new ToolDisabledError();
    }
  }

  async connect(providerId: string): Promise<ConnectionHandle> {
    this.assertCredentialAccessAvailable();
    // Refuse service-to-service tools BEFORE any consent flow — no Connect prompt, no vault lookup.
    const provider = this.brokerable(providerId);
    // Capture the intent in PostgreSQL's clock domain before ANY asynchronous read. Policy, mode,
    // credential, or session reads may pause behind offboarding; they must not let an older connect
    // mint a newer key request or OAuth state after the tombstone has committed.
    const connectIssuedAt = await this.provisioningIssuedAt();

    // The channel's configured auth mode for this provider decides the credential model:
    //   'shared'  → the channel's shared credential (delegate to connectChannel)
    //   'session' → the user's own credential, gated by a per-thread approval
    //   'per-user' / unset → the user's own credential, no gate
    const mode = this.channel && this.channelConfig
      ? await this.channelConfig.getMode(this.identity.teamId, this.channel, providerId)
      : null;
    if (mode === 'shared') return this.connectChannel(providerId);

    // Authorization (Policy + per-channel tool allowlist) — the CHECK is the shared core decision; the
    // Bolt path keeps its own audit/error mapping (and, unlike the broker, does NOT emit policy_denied on
    // a tool-disabled deny — preserved deliberately).
    await this.requireProviderAuthorized(providerId);

    // Resolve existence without decrypting. A first-time session user connects before approving a
    // thread; reconnect then purges old grants as a Vault satellite, so no approval can silently
    // carry across credential generations.
    const owner = userOwner(this.identity);
    const credentialId = await this.vault.liveId(owner, providerId);

    // Thread-scoped session: when the channel sets this provider to 'session', the user's token is usable
    // only inside the Slack thread they approved it in. The fail-closed rule lives in resolveCredentialOwner
    // (shared with the broker so the two can't drift); this branch maps the signal to Slack's surface — an
    // in-thread approval button, or the off-thread refusal. Checked before the stored-connection shortcut,
    // so being connected once still needs per-thread approval.
    if (mode === 'session' && credentialId) {
      const grantedCredentialId = this.channel && this.thread && this.sessions
        ? await this.sessions.grantedCredentialId(this.identity, this.channel, this.thread, providerId)
        : null;
      const hasSessionGrant = grantedCredentialId === credentialId;
      const r = resolveCredentialOwner({
        path: 'user', mode, principal: this.identity, channel: this.channel, thread: this.thread, hasSessionGrant,
      });
      if (r.status === 'needs_session') {
        if (r.reason === 'no-thread') {
          await this.audit.record('denied', this.identity, providerId, { channel: this.channel, reason: 'no-thread' });
          throw new Error(`"${providerId}" needs a thread-scoped session; ask me inside a thread.`);
        }
        if (!this.sessions || !this.channel) {
          throw new Error('Session approval state is not available. Ask an admin to check Vouchr.');
        }
        const pending = await this.sessions.requestAudited({
          identity: this.identity,
          channel: this.channel,
          thread: this.thread!,
          provider: providerId,
          credentialId,
          actorIssuedAt: connectIssuedAt,
          audit: this.audit,
          vault: this.vault,
          validate: async (tx) => {
            const currentMode = await new ChannelConfig(tx).getMode(
              this.identity.teamId,
              this.channel!,
              providerId,
              tx,
            );
            return currentMode === 'session' && (await authorizeProvider(
              this.policy,
              new ChannelTools(tx),
              this.identity,
              this.channel,
              providerId,
            )) === null;
          },
        });
        if (pending.status === 'requested') {
          const delivery = await this.sessions.claimDelivery(pending.id);
          if (delivery.status === 'claimed') {
            try {
              await this.postSessionApprovalPrompt(providerId, pending.id, this.thread!);
            } catch (deliveryError) {
              const outcome = classifySlackPromptDeliveryFailure(deliveryError);
              if (outcome !== 'ambiguous') {
                await abandonKnownUndeliveredPrompt(
                  () => this.sessions!.abandonDelivery(
                    pending.id,
                    delivery.token,
                    pending.created,
                  ),
                  'session',
                );
              }
              throw slackPromptDeliveryRecovery(outcome, 'session');
            }
            requirePromptConfirmation(
              await promptConfirmationOutcome(
                () => this.sessions!.confirmDelivery(pending.id, delivery.token),
              ),
              'session',
            );
          } else if (delivery.status === 'in-flight') {
            throw new UserFacingError(
              'A session approval prompt is still being delivered. Ask the agent to retry shortly.',
              'retry_later',
            );
          } else if (delivery.status === 'stale') {
            throw new UserFacingError(
              'The session request changed before delivery. Ask the agent again.',
              'resolve_again',
            );
          }
          throw new SessionApprovalRequiredError(providerId);
        }
        // The click committed while this connect() was waiting for the lifecycle locks. Continue
        // with the newly-live exact grant; do not mint, audit, or deliver a redundant request.
      }
      // resolved → fall through to the stored-credential / consent tail below (as before).
    }

    if (credentialId && await this.vault.get(owner, providerId, undefined, credentialId)) {
      return this.notifyApprovalRequired(this.notifyRateLimited(new ConnectionHandle(
        provider, owner, this.identity, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
        this.channel, // origin channel: attribute this user's usage to the channel it happened in (stats)
        this.rateLimits,
        this.health,
        this.approvals,
        this.thread,
        this.dryRun,
        undefined,
        undefined,
        credentialId,
        this.approvalRequestStillCurrent.bind(this, connectIssuedAt),
        this.useValidator(
          owner,
          providerId,
          credentialId,
          this.channel,
          this.thread,
          connectIssuedAt,
        ),
      )));
    }

    // Key providers have no OAuth: post a self-service "set up your key" prompt instead.
    if (provider.credential === 'key') {
      const promptState = await this.postKeySetupPrompt(providerId, connectIssuedAt);
      this.emit({ type: 'connect_prompted', provider: providerId });
      throw new ConsentRequiredError(providerId, promptState);
    }

    const pendingConsent = await this.consent.beginFenced(
      this.identity,
      provider,
      this.redirectUri,
      this.channel,
      connectIssuedAt,
    );
    if (!pendingConsent) {
      throw new UserFacingError(
        'Connection setup changed while Vouchr was preparing it. Ask the agent again.',
        'resolve_again',
      );
    }
    // Render before claiming delivery. A local registry/render failure is a known no-send and must
    // not park this reusable consent generation behind an ambiguous Slack lease.
    const prompt = this.connectPrompt(providerId, pendingConsent.authorizeUrl);
    const delivery = await this.consent.claimDelivery(pendingConsent.state);
    if (delivery.status !== 'claimed') {
      // 'delivered' reuses the live prompt instead of re-posting — but an in-channel prompt is an
      // ephemeral, which vanishes on reload/device switch. The typed 'reused' state drives fixed
      // copy (here and in the safe mapper) instead of claiming a fresh post.
      if (delivery.status === 'delivered') throw new ConsentRequiredError(providerId, 'reused');
      if (delivery.status === 'in-flight') {
        throw new UserFacingError(
          'A private connection prompt is already being delivered. If it appears, use it; otherwise ask the agent to retry shortly.',
          'retry_later',
        );
      }
      throw new UserFacingError(
        'The connection request changed before its prompt could be delivered. Ask the agent again.',
        'resolve_again',
      );
    }
    try {
      await this.postConnectPrompt(prompt);
    } catch (deliveryError) {
      const outcome = classifySlackPromptDeliveryFailure(deliveryError);
      if (outcome !== 'ambiguous') {
        await abandonKnownUndeliveredPrompt(
          () => this.consent.abandonDelivery(pendingConsent.state, delivery.token),
          'connection',
        );
      }
      throw slackPromptDeliveryRecovery(outcome, 'connection');
    }
    requirePromptConfirmation(
      await promptConfirmationOutcome(
        () => this.consent.confirmDelivery(pendingConsent.state, delivery.token),
      ),
      'private connection',
    );
    this.emit({ type: 'connect_prompted', provider: providerId });
    throw new ConsentRequiredError(providerId, 'posted');
  }

  /**
   * Store the acting user's OWN static key for `providerId` (key providers). Self-service,
   * NOT admin-gated (it's the user's own credential), keyed to `userOwner`. Leak-safe: the
   * secret never enters audit meta, the return value, or any error string.
   */
  async setUserSecret(providerId: string, secret: string): Promise<void> {
    this.assertCredentialAccessAvailable();
    this.brokerable(providerId);
    const issuance = await this.provisioningIssuedAt();
    const result = await configureUserCredential({
      vault: this.vault,
      audit: this.audit,
      identity: this.identity,
      providerId,
      credential: {
        kind: 'secret',
        token: {
          accessToken: secret, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
        },
      },
      issuance,
    });
    if (result !== 'stored') {
      throw new UserFacingError('This credential setup is no longer valid. Reopen it and try again.', 'resolve_again');
    }
  }

  /** Point the acting user's OWN credential at an external secret manager (self-service). */
  async referenceUserSecret(
    providerId: string,
    r: { source?: string; secretRef: string; scopes?: string },
  ): Promise<void> {
    this.assertCredentialAccessAvailable();
    const provider = this.brokerable(providerId);
    const reference = normalizeSecretReference(r, this.resolvers, provider.scopesDefault);
    const issuance = await this.provisioningIssuedAt();
    const result = await referenceUserCredential({
      vault: this.vault, audit: this.audit, identity: this.identity, providerId, reference, issuance,
    });
    if (result !== 'stored') {
      throw new UserFacingError('This credential setup is no longer valid. Reopen it and try again.', 'resolve_again');
    }
  }

  /** Whether the user already has a stored connection (no prompt side-effect). A service-to-service
   *  tool is never a Vouchr-brokered connection, so it always reports false (never "connected"). */
  async isConnected(providerId: string): Promise<boolean> {
    if (!isBrokeredProvider(this.registry.get(providerId))) return false;
    return (await this.vault.get(userOwner(this.identity), providerId)) != null;
  }

  // ── Channel-owned credentials (Phase 1: embedded, safe-by-construction). ──────────
  // `this.channel` comes from the VERIFIED Slack event, so the channel binding cannot be
  // forged (invariant 1). teamId is always the authenticated user's (invariant 2).

  /** Default-deny admin gate for config mutations (invariant 7). Audits the denial. Default is
   *  workspace-admin-only; when `allowChannelCreatorConfig` is opted in, the channel creator is also
   *  allowed. A custom `adminCheck` fully replaces the built-in gate (and ignores the flag). */
  private async requireAdmin(providerId: string): Promise<void> {
    // The ONE eligibility predicate (adminEligible); a thrown override fails closed (not admin).
    const ok = await adminEligible(this.client, this.identity.userId, this.identity.teamId, this.channel ?? '', this.adminCheck, this.allowChannelCreatorConfig);
    if (!ok) {
      await this.audit.record('denied', this.identity, providerId, {
        reason: 'not-admin',
        owner: 'channel',
        channel: this.channel,
      });
      throw new UserFacingError(adminOnly(this.allowChannelCreatorConfig, 'configure channel credentials'));
    }
  }

  private channelTarget() {
    if (!this.channelConfig) throw new UserFacingError('Channel config store not available.');
    if (!this.channel) throw new UserFacingError('No channel in context. Run this inside a channel.');
    return { cfg: this.channelConfig, owner: channelOwner(this.identity.teamId, this.channel), channel: this.channel };
  }

  /**
   * Refuse channel-owned (shared) credentials on channel classes where membership doesn't mean
   * "this workspace's own members" (invariant 6). Fails CLOSED: if we can't read the class, deny.
   * Externally-shared/Slack-Connect is the security-critical case: a shared cred there would leak
   * cross-org. Error messages name the reason and never carry tokens.
   */
  private assertChannelEligible(): Promise<void> {
    return assertChannelEligible(this.client, this.channel!);
  }

  /**
   * Store a raw static key as the channel's shared credential for `providerId`. Admin-only,
   * audited, refused on a `'per-user'`-locked channel (invariant 7). The secret never enters
   * the audit meta, the return value, or any error string (invariant 8 / T7). Prefer
   * `referenceChannelSecret` so rotation stays in your secret manager.
   */
  async setChannelSecret(providerId: string, secret: string): Promise<void> {
    this.assertCredentialAccessAvailable();
    this.brokerable(providerId); // validate provider exists + refuse service tools
    const { cfg, channel } = this.channelTarget();
    const issuance = this.channelProvisioningIssuance ?? await this.provisioningIssuedAt();
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    const stored = await configureChannelCredential({
      vault: this.vault,
      audit: this.audit,
      channelConfig: cfg,
      identity: this.identity,
      channel,
      providerId,
      issuance,
      credential: {
        kind: 'secret',
        token: { accessToken: secret, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null },
      },
      modeConflict: (mode) => {
        throw new UserFacingError(`Channel is set to ${escapeMrkdwn(mode)} for "${escapeMrkdwn(providerId)}"; static keys are not allowed.`);
      },
    });
    if (!stored) throw new ChannelProvisioningStaleError();
  }

  /**
   * Point the channel's shared credential at an external secret manager (e.g. an AWS Secrets
   * Manager ARN). Vouchr stores only the non-secret ref; the injector resolves it JIT and
   * rotation stays external. Admin-only, audited, refused on a `'per-user'` channel.
   */
  async referenceChannelSecret(
    providerId: string,
    r: { source?: string; secretRef: string; scopes?: string },
  ): Promise<void> {
    this.assertCredentialAccessAvailable();
    const provider = this.brokerable(providerId);
    const { cfg, channel } = this.channelTarget();
    const issuance = this.channelProvisioningIssuance ?? await this.provisioningIssuedAt();
    const reference = normalizeSecretReference(r, this.resolvers, provider.scopesDefault);
    const stored = await referenceChannelCredential({
      vault: this.vault, audit: this.audit, channelConfig: cfg, identity: this.identity,
      channel, providerId, reference, issuance,
      authorize: () => this.requireAdmin(providerId),
      assertEligible: () => this.assertChannelEligible(),
      modeConflict: (mode) => {
        throw new UserFacingError(
          `Channel is set to ${escapeMrkdwn(mode)} for "${escapeMrkdwn(providerId)}"; shared references are not allowed.`,
        );
      },
    });
    if (!stored) throw new ChannelProvisioningStaleError();
  }

  /**
   * Set the channel's auth mode for a provider. Admin-only, audited. Flipping to a user-owned mode
   * (`'per-user'` or `'session'`) removes any live shared cred (a re-own that must be re-authorized;
   * the admin gate is that authorization). Members then use their own creds via `connect()`.
   */
  async setChannelMode(providerId: string, mode: ChannelMode): Promise<void> {
    this.brokerable(providerId);
    const { cfg, channel } = this.channelTarget();
    const issuance = await this.provisioningIssuedAt();
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    const configured = await setChannelCredentialMode({
      vault: this.vault,
      audit: this.audit,
      channelConfig: cfg,
      identity: this.identity,
      channel,
      providerId,
      mode,
      issuance,
    });
    if (!configured) throw new InteractionStateChangedError('connection', 'authorization');
  }

  /**
   * Return a leak-safe handle for the CHANNEL's shared credential for `providerId`. The handle
   * keys the vault on the channel but audits as the acting human (invariant 9). Throws if the
   * channel is per-user-locked or has no shared cred configured.
   */
  async connectChannel(providerId: string): Promise<ConnectionHandle> {
    this.assertCredentialAccessAvailable();
    const provider = this.brokerable(providerId);
    const connectIssuedAt = await this.provisioningIssuedAt();
    const { cfg, owner, channel } = this.channelTarget();
    // Same authorization gate as connect() (the shared core CHECK): a deny applies to shared channel
    // creds too. Audit meta carries owner:'channel' here; like connect(), no policy_denied on tool-disabled.
    const denial = await authorizeProvider(this.policy, this.channelTools, this.identity, this.channel, providerId);
    if (denial === 'policy') {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel, owner: 'channel' });
      this.emit({ type: 'policy_denied', provider: providerId });
      throw new PolicyDeniedError();
    }
    if (denial === 'tool-disabled') {
      await this.audit.record('denied', this.identity, providerId, { channel, owner: 'channel', reason: 'tool-disabled' });
      throw new ToolDisabledError();
    }
    const m = await cfg.getMode(owner.teamId, channel, providerId);
    if (m != null && m !== 'shared') {
      throw new Error(`Channel "${channel}" uses ${m} credentials for "${providerId}"; use connect() instead.`);
    }
    const credentialId = await this.vault.liveId(owner, providerId);
    if (!credentialId || !(await this.vault.get(owner, providerId, undefined, credentialId))) {
      // Typed (code 'not_connected', owner 'channel' → recovery 'fix_configuration'): the same fact
      // the broker's shared-owner 409 reports, so the recovery bridge and in-process hosts branch on
      // one class instead of prose. Message text unchanged.
      throw new NoConnectionError(`No channel credential configured for "${providerId}" in this channel.`, 'channel');
    }
    // Governance (opt-in): a shared cred is only usable by an actual channel member. Fail-closed.
    // isChannelMember returns false on any error, so an unverifiable membership refuses the cred.
    if (this.requireMembership && !(await boundedChannelMembership(
      this.client,
      channel,
      this.identity.userId,
      this.slackClientOptions,
    ))) {
      await this.audit.record('denied', this.identity, providerId, { channel, owner: 'channel', reason: 'not-member' });
      throw new Error(`You must be a member of this channel to use its shared "${providerId}" credential.`);
    }
    // Defense in depth: re-verify class at use time (a channel can change class after config).
    // This is one conversations.info per use; cache the class with a short TTL if a hot channel
    // throttles. Correctness first: a channel turned Slack Connect must stop now.
    await this.assertChannelEligible();
    // Shared-owner mapping through the same core decision, so this direct shared-cred path can't drift
    // from the broker's. Eligibility is verified live above and mode is asserted 'shared', so eligible:true
    // and the helper always resolves (to channelOwner(teamId, channel) + this.identity — today's values).
    const r = resolveCredentialOwner({ path: 'channel', mode: 'shared', principal: this.identity, channel, eligible: true });
    if (r.status !== 'resolved') {
      throw new NoConnectionError(`No channel credential configured for "${providerId}" in this channel.`, 'channel');
    }
    // originChannel keeps its default (null): the channel-owned cred is attributed to its owning channel.
    return this.notifyApprovalRequired(this.notifyRateLimited(new ConnectionHandle(
      provider, r.owner, r.acting, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
      null, this.rateLimits, this.health, this.approvals, this.thread, this.dryRun,
      undefined, undefined, credentialId,
      this.approvalRequestStillCurrent.bind(this, connectIssuedAt),
      this.useValidator(r.owner, providerId, credentialId, owner.id, this.thread, connectIssuedAt),
    )));
  }

  /**
   * The channel-filtered tool manifest an agent / MCP gateway asks for before planning: every
   * registered provider with whether it's usable in THIS channel and the channel's credential mode.
   * `enabled` intersects the channel tool allowlist (backward-compat rule applies) with Policy, so
   * it matches what connect() would actually allow. With no channel (a DM-less context) there is no
   * tool-allowlist restriction and mode is null, but Policy still applies: a default-deny or
   * allow-channel-only policy can still report a provider disabled.
   */
  async toolManifest(): Promise<ToolManifestEntry[]> {
    // ONE shared core builder (with the broker's POST /v1/manifest), so `enabled` here is exactly
    // "authorizeProvider would allow it" and the two transports can't drift.
    return buildToolManifest({
      providerIds: this.providerIds, registry: this.registry, policy: this.policy,
      channelTools: this.channelTools, channelConfig: this.channelConfig,
      principal: this.identity, channel: this.channel,
    });
  }

  /**
   * The trusted broker-to-Slack recovery bridge (#194). A hybrid host's untrusted worker calls the
   * packaged HTTP broker; when the broker denies with a stable machine code, the host relays the
   * denial body here — from the SAME verified Slack event context that produced the worker's
   * identity assertion — and Vouchr takes the correct private recovery action:
   *
   *  - `not_connected` / `session_approval_required` → the full connect flow re-runs from current
   *    verified state: the private connect or key-setup prompt (deduplicated), the thread-scoped
   *    session approval prompt (single pending request per thread, click revalidated at the
   *    mutation), or — shared owner with no channel credential — an eligible admin is directed to
   *    channel configuration (never a personal connect prompt).
   *  - `approval_required` → the pending approval row named by `approvalId` is re-read from
   *    storage, bound to this verified team/user/channel and the relayed provider, the approver
   *    rule is re-derived from the registry (never the row or the wire), and the Approve/Deny
   *    decision surface is delivered through the same leased path as in-process approvals.
   *
   * The denial body is UNTRUSTED routing guidance, never authority (SEC-3/SEC-4): the code is
   * validated against VOUCHR_ERROR_CODES, `approvalId` is only a lookup handle, and every identity,
   * owner, mode, policy, and eligibility fact is re-resolved server-side here and again at the
   * click. Repeated relays of the same denial converge on one prompt (delivery leases / dedup
   * rows), and the worker's retry after a human acts must mint a fresh single-use assertion.
   * Typed denials that surface during recovery (policy, tool, rate limit…) throw as usual —
   * render them with safeUserMessage/mapSafeError.
   */
  async recoverBrokerDenial(providerId: string, denial: unknown): Promise<BrokerDenialRecovery> {
    this.assertCredentialAccessAvailable();
    // SEC-4: validate the provider against the registry (and refuse service tools) before any
    // read, write, audit, or Slack post. Throws on an unknown id.
    const provider = this.brokerable(providerId);
    const rawCode = typeof denial === 'object' && denial !== null
      ? (denial as { code?: unknown }).code
      : undefined;
    const code = isVouchrErrorCode(rawCode) ? rawCode : null;

    if (code === 'not_connected' || code === 'session_approval_required') {
      try {
        // connect() IS the recovery flow: it re-resolves mode/policy/credential/session from
        // current verified state, dedups prompts, and throws typed control-flow errors.
        await this.connect(providerId);
        return { status: 'resolved', provider: providerId };
      } catch (e) {
        if (e instanceof ConsentRequiredError) {
          return { status: 'connect_prompted', provider: providerId, promptState: e.promptState };
        }
        if (e instanceof SessionApprovalRequiredError) {
          return { status: 'session_prompted', provider: providerId };
        }
        if (e instanceof NoConnectionError && e.owner === 'channel') {
          await this.directChannelConfiguration(providerId);
          return { status: 'configuration_required', provider: providerId };
        }
        throw e;
      }
    }

    if (code === 'approval_required') {
      if (!this.approvals) {
        throw new UserFacingError('Approval state is not available. Ask an admin to check Vouchr.');
      }
      // Same audited gate as connect(): a decision surface is never delivered for a provider the
      // channel's current policy/tool state forbids.
      await this.requireProviderAuthorized(providerId);
      const rawApprovalId = (denial as { approvalId?: unknown }).approvalId;
      const row = typeof rawApprovalId === 'string' ? await this.approvals.get(rawApprovalId) : null;
      // Bind the stored row to THIS verified context: the requester, workspace, channel, and the
      // provider the host says it called. Any mismatch is treated as "no live pending approval" —
      // the id is a lookup handle, never authority.
      if (
        !row
        || row.provider !== providerId
        || row.teamId !== this.identity.teamId
        || row.userId !== this.identity.userId
        || row.channel !== this.channel
        || row.thread !== this.thread
      ) {
        return { status: 'stale', provider: providerId };
      }
      // Re-derive the approver rule from the current registry — never the stored row or the wire.
      // If the provider no longer requires approval for this action, the pending row is moot: the
      // retry re-evaluates against current state (and the sweep reclaims the row).
      const approval = provider.approval;
      if (!approval || !approvalNeeded(approval, row.method, row.path)) {
        return { status: 'resolved', provider: providerId };
      }
      // A broker denial can sit in transit while a session expires, the user is offboarded, the
      // credential is replaced, or channel governance changes. Re-run the ONE core authority check
      // before showing a decision surface. This is only a delivery-time snapshot; the click repeats
      // it under lifecycle locks before creating any grant.
      const current = await this.approvals.ownerStillCurrent(row, {
        registry: this.registry,
        policy: this.policy,
        vault: this.vault,
        enterpriseId: this.identity.enterpriseId,
        actorIssuedAt: row.createdAt,
        channelTools: this.channelTools ?? null,
        channelConfig: this.channelConfig ?? null,
      });
      if (!current) {
        await this.approvals.discardPending(row.id).catch(() => undefined);
        return { status: 'stale', provider: providerId };
      }
      // Core cannot query Slack. A shared-credential action additionally requires the same live
      // channel-class and requester-membership facts the decision mutation checks. Never post a
      // doomed/confidential prompt after Slack Connect conversion or requester removal.
      if (row.ownerKind === 'channel') {
        if (!row.channel) {
          await this.approvals.discardPending(row.id).catch(() => undefined);
          return { status: 'stale', provider: providerId };
        }
        const client = this.promptClient();
        try {
          await assertChannelEligible(client, row.channel);
        } catch (error) {
          await this.approvals.discardPending(row.id).catch(() => undefined);
          throw error;
        }
        if (!(await boundedChannelMembership(
          client,
          row.channel,
          row.userId,
          this.slackClientOptions,
        ))) {
          await this.approvals.discardPending(row.id).catch(() => undefined);
          return { status: 'stale', provider: providerId };
        }
      }
      await this.deliverApprovalPrompt({
        provider: providerId,
        approver: approval.approver,
        method: row.method,
        host: row.host,
        actionFingerprint: approvalActionFingerprint(row),
        approvalId: row.id,
        // The row binds the exact query byte-for-byte as a digest; the parameter COUNT is not
        // retained, and the renderer says "parameters present" instead of fabricating a number.
        queryParamCount: row.queryHash === '' ? 0 : null,
        newRequest: false,
        thread: row.thread,
      });
      return { status: 'approval_prompted', provider: providerId, approver: approval.approver };
    }

    return { status: 'not_bridgeable' };
  }

  /** Shared-owner recovery for a missing channel credential: direct an eligible admin to channel
   * configuration, privately and without spam. An admin-eligible actor is directed in place;
   * otherwise the last configuring admin (audit-derived — the mode change itself writes 'config',
   * so a shared-mode channel always has one) gets one DM per 24h window via the shared
   * NotificationState debounce, and the actor gets truthful private guidance either way. */
  private async directChannelConfiguration(providerId: string): Promise<void> {
    const channel = this.channel;
    const p = escapeMrkdwn(providerId);
    if (!channel) {
      // Shared mode only resolves inside a channel; without one there is no configuration surface.
      throw new UserFacingError(
        `"${providerId}" uses a shared channel credential. Ask in the channel where the agent should use it.`,
      );
    }
    // A channel can become externally shared or archived after shared mode was configured. Recheck
    // the same fail-closed class rule as the actual configuration mutation before directing anyone
    // to an operation Vouchr must refuse.
    const client = this.promptClient();
    await assertChannelEligible(client, channel);
    const actorIsAdmin = await adminEligible(
      client, this.identity.userId, this.identity.teamId, channel,
      this.adminCheck, this.allowChannelCreatorConfig,
    );
    let text: string;
    if (actorIsAdmin) {
      text = `No shared ${p} credential is configured in this channel. Run \`/vouchr configure ${p}\` here to set one up.`;
    } else {
      let adminDirection: 'confirmed' | 'possible' | 'none' = 'none';
      const admin = await this.audit.lastChannelConfigActor(this.identity.teamId, channel, providerId);
      // Audit identifies who configured it last, not who is authorized now. Recheck BOTH current
      // membership and the canonical admin predicate before disclosing private channel context.
      const adminIsCurrent = !!admin
        && await boundedChannelMembership(client, channel, admin, this.slackClientOptions)
        && await adminEligible(
          client, admin, this.identity.teamId, channel,
          this.adminCheck, this.allowChannelCreatorConfig,
        );
      if (admin && adminIsCurrent && this.notifications) {
        const owner = channelOwner(this.identity.teamId, channel, this.identity.enterpriseId ?? undefined);
        const claimedAt = Date.now();
        if (await this.notifications.claim(owner, providerId, 'not_configured', claimedAt)) {
          try {
            await client.chat.postMessage({
              channel: admin,
              text: `The shared ${p} credential in <#${escapeMrkdwn(channel)}> is missing. Run \`/vouchr configure ${p}\` there to set it up.`,
            });
            adminDirection = 'confirmed';
          } catch (deliveryError) {
            // Request/network failures are ambiguous: Slack may have accepted the DM, so retain the
            // debounce claim and report only that an admin MAY have been notified. Only definite
            // rejection releases the claim for a later relay to retry.
            const outcome = classifySlackPromptDeliveryFailure(deliveryError);
            if (outcome === 'ambiguous') adminDirection = 'possible';
            else {
              await this.notifications.release(owner, providerId, 'not_configured', claimedAt).catch(() => undefined);
            }
          }
        } else {
          // Another replica may have delivered, may still be delivering, or may have crashed after
          // claiming. The persisted claim proves only that duplicate delivery must stop, not that a
          // human definitely received the DM.
          adminDirection = 'possible';
        }
      }
      text = adminDirection === 'confirmed'
        ? `No shared ${p} credential is configured in this channel. A channel admin has been asked to configure it.`
        : adminDirection === 'possible'
          ? `No shared ${p} credential is configured in this channel. A channel admin may already have been notified; ask one directly if setup is still blocked.`
          : `No shared ${p} credential is configured in this channel. Ask a channel admin to run \`/vouchr configure ${p}\` here.`;
    }
    try {
      await client.chat.postEphemeral({ channel, user: this.identity.userId, text });
    } catch (deliveryError) {
      throw slackPromptDeliveryRecovery(classifySlackPromptDeliveryFailure(deliveryError), 'configuration');
    }
  }

  /** Ephemeral in-thread prompt to approve a thread-scoped session. Only the acting user sees it.
   *  Caller guarantees we're in a channel + thread. */
  private async postSessionApprovalPrompt(providerId: string, requestId: string, thread: string): Promise<void> {
    const blocks = sessionApprovalBlocks(providerId, requestId);
    await this.promptClient().chat.postEphemeral({
      channel: this.channel!,
      user: this.identity.userId,
      thread_ts: thread,
      blocks: blocks as any,
      text: blocksFallbackText(blocks),
    });
  }

  /** Durable private JIT prompt for a key provider: a button that opens the per-user key modal.
   * The existing core provisioning row owns the cross-replica delivery lease, exactly as consent
   * owns OAuth prompt delivery. */
  private async postKeySetupPrompt(
    providerId: string,
    issuedAt: number,
  ): Promise<ConsentPromptState> {
    // Mint when the prompt is produced, not when it is clicked. The PostgreSQL timestamp is the
    // authority's true start, so a prompt already delivered before offboarding can never mint a
    // post-offboard credential merely because its button was clicked later.
    const requestId = await issueUserProvisioningRequest(
      this.vault,
      this.identity,
      providerId,
      issuedAt,
    );
    if (!requestId) {
      throw new UserFacingError(
        'Credential setup changed while Vouchr was preparing it. Ask the agent again.',
        'resolve_again',
      );
    }
    const blocks = keySetupBlocks(providerId, requestId);
    const text = blocksFallbackText(blocks);
    const delivery = await claimUserProvisioningDelivery(
      this.vault,
      this.identity,
      providerId,
      requestId,
    );
    if (delivery.status === 'delivered') return 'reused';
    if (delivery.status === 'in-flight') {
      throw new UserFacingError(
        'A private key-setup prompt is already being delivered. If it appears, use it; otherwise ask the agent to retry shortly.',
        'retry_later',
      );
    }
    if (delivery.status === 'stale') {
      throw new UserFacingError(
        'The key-setup request changed before its prompt could be delivered. Ask the agent again.',
        'resolve_again',
      );
    }
    if (delivery.status !== 'claimed') {
      throw new UserFacingError(
        'Vouchr could not establish key-setup prompt delivery. Ask the agent to retry shortly.',
        'retry_later',
      );
    }
    try {
      const client = this.promptClient();
      if (this.channel) {
        await client.chat.postEphemeral({
          channel: this.channel,
          user: this.identity.userId,
          blocks: blocks as any,
          text,
        });
      } else {
        await client.chat.postMessage({
          channel: this.identity.userId,
          blocks: blocks as any,
          text,
        });
      }
    } catch (deliveryError) {
      const outcome = classifySlackPromptDeliveryFailure(deliveryError);
      if (outcome !== 'ambiguous') {
        await abandonKnownUndeliveredPrompt(
          () => abandonUserProvisioningDelivery(
            this.vault,
            this.identity,
            providerId,
            requestId,
            delivery.token,
          ),
          'connection',
        );
      }
      throw slackPromptDeliveryRecovery(outcome, 'connection');
    }
    requirePromptConfirmation(
      await promptConfirmationOutcome(
        () => confirmUserProvisioningDelivery(
          this.vault,
          this.identity,
          providerId,
          requestId,
          delivery.token,
        ),
      ),
      'private connection',
    );
    return 'posted';
  }

  private connectPrompt(providerId: string, url: string): {
    blocks: unknown[];
    fallback: { text: string } | Record<string, never>;
  } {
    const provider = this.registry.get(providerId);
    const blocks = connectBlocks(providerId, url, {
      list: provider.scopesDefault,
      describe: provider.scopeDescriptions,
    });
    return { blocks, fallback: optionalBlockFallback(blocks) };
  }

  private async postConnectPrompt(prompt: {
    blocks: unknown[];
    fallback: { text: string } | Record<string, never>;
  }): Promise<void> {
    const client = this.promptClient();
    const { blocks, fallback } = prompt;
    if (this.channel) {
      await client.chat.postEphemeral({
        channel: this.channel,
        user: this.identity.userId,
        blocks: blocks as any,
        ...fallback,
      });
    } else {
      await client.chat.postMessage({
        channel: this.identity.userId,
        blocks: blocks as any,
        ...fallback,
      });
    }
  }
}

/**
 * #117 default credential-health notifier: turn a {@link CredentialHealthEvent} into one owner DM.
 * Recipient: the owner for a user-owned credential; the last configuring admin (audit-derived) for
 * a channel-owned one — unknown admin ⇒ skip, never spam the channel. 'expired' events get no DM
 * (the connection is gone; the next use re-prompts Connect). Debounced to one DM per (owner,
 * provider, type) per 24h via the persistent NotificationState: the window is CLAIMED atomically
 * right before the send (exactly one claimer wins, even across pods on a shared Postgres) and
 * released on a send failure so the next event retries. Honest trade: a process that claims and
 * then crashes before the send loses that window's DM (the next window retries) — accepted over
 * the alternative, where two pods can double-DM. The provider is registry-validated before
 * anything is rendered or
 * persisted (SEC-4), and every interpolated value is escaped at render (SEC-5). No token material
 * anywhere. A refresh-dead DM contains no reconnect control: it may live past offboarding, so a
 * later click cannot safely mint fresh consent. The user asks the agent again, which produces a
 * current, offboard-fenced prompt. Exported for tests; createVouchr wires it with the same client
 * resolution the post-OAuth success and recovery DMs use.
 */
export function healthNotifier(deps: {
  registry: ProviderRegistry;
  audit: Audit;
  state: NotificationState;
  clientFor: (identity: SlackIdentity) => Promise<WebClient | null>;
}): (e: CredentialHealthEvent) => Promise<void> {
  return async (e) => {
    if (e.type === 'expired') return; // deleted: nothing actionable to reconnect yet
    if (!deps.registry.has(e.provider)) return; // stale row for an unregistered provider (SEC-4 gate)
    const recipient = e.owner.kind === 'user'
      ? e.owner.id
      : await deps.audit.lastChannelConfigActor(e.owner.teamId, e.owner.id, e.provider);
    if (!recipient) return; // channel cred with no known configuring admin: skip
    const identity: SlackIdentity = { enterpriseId: e.owner.enterpriseId ?? null, teamId: e.owner.teamId, userId: recipient };
    const client = await deps.clientFor(identity);
    if (!client) return;
    const p = escapeMrkdwn(e.provider); // SEC-5, even for a registry-validated id
    const where = e.owner.kind === 'channel' ? ` in <#${escapeMrkdwn(e.owner.id)}>` : '';
    let text: string;
    let blocks: unknown[] | undefined;
    if (e.type === 'refresh_dead') {
      if (e.owner.kind === 'user') {
        text = `Your ${p} connection stopped working. Ask the agent to reconnect it.`;
        const intro = { type: 'section', text: { type: 'mrkdwn', text: `:warning: Your *${p}* connection stopped working and needs to be reconnected.` } };
        blocks = [intro, {
          type: 'section',
          text: { type: 'mrkdwn', text: 'Ask the agent to reconnect; it will create a current private prompt.' },
        }];
      } else {
        text = `The shared ${p} connection${where} stopped working and needs to be reconfigured. Use \`/vouchr configure ${p}\` there.`;
      }
    } else {
      const hours = Math.max(1, Math.round(((e.expiresAt ?? Date.now()) - Date.now()) / 3_600_000));
      text = e.owner.kind === 'user'
        ? `Your ${p} connection expires in ~${hours}h. Reconnect to keep using it.`
        : `The shared ${p} connection${where} expires in ~${hours}h. Reconfigure it (\`/vouchr configure ${p}\`) to keep it working.`;
    }
    // Claim the 24h window LAST, right before the send (all skip-paths above claim nothing), so
    // exactly one claimer — across pods too — proceeds. On a failed send, release OUR claim so the
    // next event retries. Crash between claim and send = that window's DM is lost (next window
    // retries): the deliberate trade against cross-pod duplicate DMs.
    const claimedAt = Date.now();
    if (!(await deps.state.claim(e.owner, e.provider, e.type, claimedAt))) return; // someone already notified this window
    try {
      await client.chat.postMessage({ channel: recipient, text, ...(blocks ? { blocks: blocks as any } : {}) });
    } catch (err) {
      await deps.state.release(e.owner, e.provider, e.type, claimedAt).catch(() => undefined);
      throw err;
    }
  };
}

export async function createVouchr(opts: VouchrOptions) {
  const dryRun = assertDryRunFlag(opts.dryRun, 'createVouchr'); // SEC-4: fail closed before any wiring
  // Parse containment before key/provider validation or opening an owned pool. A typo fails boot
  // closed without leaking a Postgres pool acquired earlier in startup (#239).
  const lockdown = booleanEnv(process.env.VOUCHR_LOCKDOWN, 'VOUCHR_LOCKDOWN');
  // #116: external KMS makes real wrap/unwrap network calls — refuse fail-closed before opening the
  // db, so the "no real network on any edge" guarantee holds. Local master key only in dry-run.
  if (dryRun) assertDryRunLocalKey(!!opts.envelope);
  // Validate everything that DOESN'T need the db BEFORE opening the pool, so a bad master key or
  // provider config can't leak an owned pool (there's no handle to close it before createVouchr
  // returns). Only assertDryRunVault (which reads the vault) is post-open, and it's guarded below.
  const key = loadKeyring(); // VOUCHR_MASTER_KEY alone behaves exactly as before; VOUCHR_MASTER_KEYS adds rotation (#115)
  const registry = new ProviderRegistry(opts.providers);
  // Validate the origin + mounted pathname and build their redirect URL in ONE core helper, BEFORE
  // the pool opens. Keeping callbackPath as a canonical absolute pathname prevents the Express route
  // and the OAuth redirect URI from interpreting relative/URL/query/fragment forms differently.
  const callbackPath = opts.callbackPath === undefined ? '/vouchr/oauth/callback' : opts.callbackPath;
  const redirectUri = buildCallbackUrl(opts.baseUrl, callbackPath);
  // Inject a pre-opened store to share one pool across workspaces/tests; else open (and own) our own.
  const ownsDb = !opts.db;
  const db = opts.db ?? (await openDb({ databaseUrl: opts.databaseUrl }));
  // #116 safety rail: dry-run hard-fails at startup against a vault holding real credential rows.
  // Close the pool WE opened if this refuses — don't strand it (an injected db is the caller's).
  if (dryRun) {
    try {
      await assertDryRunVault(db);
    } catch (e) {
      if (ownsDb) await db.close().catch(() => undefined);
      throw e;
    }
  }
  // #239 containment comes from deployment configuration outside the credential database.
  const vault = new Vault(db, key, opts.ttl ?? DEFAULT_TTL, opts.envelope, lockdown);
  // #116: in dry-run EVERY audit row (connect, inject, denied, config, …) carries meta.dry_run.
  const audit = dryRun ? dryRunAudit(new Audit(db)) : new Audit(db);
  const consent = new Consent(db, dryRun);
  const channelConfig = new ChannelConfig(db);
  const channelTools = new ChannelTools(db);
  const sessions = new SessionGrants(db);
  const approvals = new Approvals(db); // #113 per-action approval requests/grants (provider.approval)
  const provisioning = new UserProvisioningRequests(db, vault);
  const channelProvisioning = new ChannelProvisioningRequests(db, vault);
  // The 'session' channel mode drives whether a thread grant is required; this is just the TTL ceiling.
  const sessionTtlMs = opts.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  const providerIds = opts.providers.map((p) => p.id); // for toolManifest(); mirrors the registry
  const policy = opts.policy ?? new Policy();
  const resolvers = opts.resolvers ?? {};
  const referenceSources = SECRET_REFERENCE_SOURCES.filter(
    (source) => Object.hasOwn(resolvers, source) && typeof resolvers[source] === 'function',
  );
  const botToken = opts.botToken ?? process.env.SLACK_BOT_TOKEN;
  const confirmClient = botToken ? slackNotificationClient(botToken, opts.slackClientOptions) : null;
  const inflight = new Map<string, Promise<string | null>>(); // shared single-flight refresh map
  // Shared per-(owner, provider) rate-limit buckets (provider.rateLimit); per-process by default.
  const rateLimits: RateLimitStore = opts.rateLimitStore ?? new MemoryRateLimitStore();
  const sink: EventSink = opts.onEvent ?? (() => {});
  // Optional audit stream sink (raw actor id). Separate from `sink`, which is deliberately actor-free.
  const auditSink: AuditSink = opts.auditSink ?? (() => {});
  // Safe emit for the createVouchr-level paths (OAuth callback, disconnect) that aren't inside a
  // ConnectContext/ConnectionHandle. A throwing sink must never break a request.
  const emit = (e: VouchrEvent): void => safeEmit(sink, e);
  const allowChannelCreatorConfig = opts.allowChannelCreatorConfig ?? false;
  // Same gate as ConnectContext.requireAdmin, for the command paths that don't route through it
  // (enable/disable tool allowlist, the configure pre-modal gate). Default workspace-admin-only; the
  // channel creator is OR-ed in only when opted in. A custom isAdmin override fully replaces it.
  const commandAdmin = async (client: WebClient, identity: SlackIdentity, channel: string): Promise<boolean> => {
    return adminEligible(client, identity.userId, identity.teamId, channel, opts.isAdmin, allowChannelCreatorConfig);
  };

  /** The acting user's brokered connections, for the status / config-modal / App-Home surfaces (one
   *  filter for all three). A service-to-service tool is never a Vouchr-brokered connection, so it
   *  never lists as a "connected account" (defensive — storage is blocked); an unknown/stale row
   *  still shows so nothing stored is ever hidden. */
  const listBrokeredConnections = async (identity: SlackIdentity): Promise<Connection[]> =>
    (await vault.listForUser(identity, true))
      .filter((c) => { try { return isBrokeredProvider(registry.get(c.provider)); } catch { return true; } })
      .map((c) => ({
        provider: c.provider,
        channel: null,
        account: c.externalAccount,
        credentialId: c.credentialId,
      }))
      .sort((a, b) => a.provider < b.provider ? -1 : a.provider > b.provider ? 1 : 0);

  /** Best-effort DM to the acting user — the App Home has no ephemeral/inline-error surface, so
   *  click feedback goes here (the same channel the modal-submit confirmations use). */
  const dmActor = async (client: WebClient, identity: SlackIdentity, text: string): Promise<void> => {
    await client.chat.postMessage({ channel: identity.userId, text }).catch(() => undefined);
  };

  /** Replace the private pending modal with its committed outcome. If the view is gone, fall back
   *  to a DM; if both Slack deliveries fail, the already-acknowledged pending view still contains
   *  truthful unknown-state recovery guidance. */
  const deliverModalOutcome = async (
    client: WebClient,
    identity: SlackIdentity,
    view: any,
    title: string,
    text: string,
  ): Promise<void> => {
    let updated = false;
    if (typeof view?.id === 'string' && typeof (client as any).views?.update === 'function') {
      try {
        await (client as any).views.update({ view_id: view.id, view: privateStatusModal(title, text) });
        updated = true;
      } catch { /* the pending view remains; fall back to a private DM */ }
    }
    if (!updated) await dmActor(client, identity, text);
  };

  /**
   * STR-3: the mutation+audit pair for flipping a provider's tool-allowlist bit in a channel, shared
   * by `/vouchr enable|disable` and the App Home Enable/Disable button so the admin gate, the write,
   * and the audit row are identical by construction. The write itself — including the first-write
   * allowlist materialization AND the configured-ness decision — is ONE atomic core mutation
   * (ChannelTools.applyEnabled, STR-1), so concurrent admins can't interleave a partial allowlist
   * and a failure can't leave one. Only the provider the admin actually targeted is audited.
   * Caller contract (SEC-4): `provider` is already registry-validated and `channel` is a verified
   * channel id (slash: Slack-supplied channel_id; App Home: verifiedHomeChannel) BEFORE this
   * records anything.
   */
  const setChannelToolEnabled = async (
    client: WebClient,
    identity: SlackIdentity,
    channel: string,
    provider: string,
    on: boolean,
    provisioningReceivedAt: bigint,
  ): Promise<'ok' | 'denied'> => {
    const configured = await configureChannelTools({
      channelTools,
      vault,
      audit,
      identity,
      channel,
      changes: [[provider, on]],
      allProviders: providerIds,
      issuance: await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt),
      authorize: async () => {
        if (await commandAdmin(client, identity, channel)) return true;
        await audit.record('denied', identity, provider, { reason: 'not-admin', owner: 'channel', channel });
        return false;
      },
      // Channel-class eligibility at the MUTATION, not just at render (SEC-3: the render hiding
      // controls for an archived/ext-shared channel is UI, not authorization; a forged payload — or
      // a slash command — must hit the same wall). Ordered after the admin gate and throwing a
      // UserFacingError with no audit row, exactly mirroring setChannelMode.
      assertEligible: () => assertChannelEligible(client, channel),
    });
    if (configured === 'stale') {
      throw new InteractionStateChangedError('connection', 'authorization');
    }
    return configured === 'configured' ? 'ok' : 'denied';
  };

  const CHANNEL_CREDENTIAL_UNAVAILABLE =
    'This tool uses service-managed credentials and cannot be configured here.';
  const CREDENTIAL_SETUP_LOCKED =
    'Credential setup is temporarily unavailable. Contact an administrator.';

  /** Consume Slack's short-lived trigger before any network/database gate, reserve opaque setup
   * authority immediately after Slack confirms the loading view, then hydrate it only after the
   * channel, admin, eligibility, and lifecycle fences pass. Reserving before the slow Slack gates
   * lets any concurrent credential mutation invalidate this request instead of being overwritten
   * by an older handler. Slash and App Home share this exact sequence (STR-3). */
  const openConfigureModal = async (
    client: WebClient,
    identity: SlackIdentity,
    candidateChannel: string | null,
    provider: string,
    triggerId: string,
    provisioningReceivedAt: bigint,
    verifyChannel?: () => Promise<string | null>,
  ): Promise<'ok' | 'denied' | 'locked' | 'unavailable' | 'unconfirmed' | 'unsupported'> => {
    // Refuse before opening even a loading modal: lockdown must not invite a human to submit a
    // credential or create setup authority that the Vault will reject later.
    if (vault.lockdownEnabled) return 'locked';
    // A forged App Home action and the slash command share this eligibility boundary. Reject
    // service-only tools before consuming the trigger, reading Slack/DB state, or minting setup
    // authority: Vouchr must never ask an admin to enter a credential it cannot use.
    if (!registry.has(provider) || !isBrokeredProvider(registry.get(provider))) {
      return 'unsupported';
    }
    let opened: any;
    try {
      opened = await client.views.open({
        trigger_id: triggerId,
        view: privateStatusModal(
          'Preparing setup',
          'Vouchr is checking this channel credential setup. If no result appears, close this window and try again.',
        ) as any,
      });
    } catch {
      // Slack may have accepted the modal before the response failed. Do no authorization reads or
      // ticket writes, and never claim that the window definitely did not open.
      await dmActor(
        client,
        identity,
        'Vouchr could not confirm whether channel credential setup opened. If a setup window appeared, follow it or close it; otherwise try again.',
      );
      return 'unconfirmed';
    }
    const viewId = opened?.view?.id;
    if (typeof viewId !== 'string' || !viewId) {
      await dmActor(
        client,
        identity,
        'Vouchr could not confirm whether channel credential setup opened. If a setup window appeared, follow it or close it; otherwise try again.',
      );
      return 'unconfirmed';
    }

    if (!candidateChannel) {
      await deliverModalOutcome(
        client,
        identity,
        { id: viewId },
        'Setup unavailable',
        'This channel selection is no longer current. Close this window, select the channel again, and retry.',
      );
      return 'unavailable';
    }

    let requestId: string | null;
    try {
      const issuedAt = await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt);
      requestId = await channelProvisioning.issue(identity, candidateChannel, provider, issuedAt);
    } catch {
      await deliverModalOutcome(
        client,
        identity,
        { id: viewId },
        'Setup not confirmed',
        'Vouchr could not confirm this setup request. Close this window and review the current channel state before trying again.',
      );
      return 'unconfirmed';
    }
    if (!requestId) {
      await deliverModalOutcome(
        client,
        identity,
        { id: viewId },
        'Review current status',
        'This channel credential setup is no longer active. Review the current channel state before requesting setup again.',
      );
      return 'unavailable';
    }
    const channel = verifyChannel ? await verifyChannel() : candidateChannel;
    if (!channel || channel !== candidateChannel) {
      await deliverModalOutcome(
        client,
        identity,
        { id: viewId },
        'Setup unavailable',
        'This channel selection is no longer current. Close this window, select the channel again, and retry.',
      );
      return 'unavailable';
    }
    const authorized = await commandAdmin(client, identity, channel);
    if (!authorized) {
      await audit.record('denied', identity, provider, {
        reason: 'not-admin',
        owner: 'channel',
        channel,
      });
      await deliverModalOutcome(
        client,
        identity,
        { id: viewId },
        'Setup unavailable',
        adminOnly(allowChannelCreatorConfig, 'configure channel credentials'),
      );
      return 'denied';
    }
    try {
      await assertChannelEligible(client, channel);
    } catch (error) {
      await deliverModalOutcome(
        client,
        identity,
        { id: viewId },
        'Setup unavailable',
        safeUserMessage(error),
      );
      return 'unavailable';
    }

    // A sibling credential/mode mutation may have committed while Slack authorization was in
    // flight. Re-read before rendering a secret-entry surface so the user is not invited to submit
    // a request that the mutation already invalidated. The final transaction still consumes and
    // rechecks the row, covering a mutation after this UX-only read.
    try {
      const pending = await channelProvisioning.resolveForModal(requestId, identity);
      if (!pending || pending.channel !== channel || pending.provider !== provider) {
        await deliverModalOutcome(
          client,
          identity,
          { id: viewId },
          'Review current status',
          'This channel credential setup is no longer active. Review the current channel state before requesting setup again.',
        );
        return 'unavailable';
      }
    } catch {
      await deliverModalOutcome(
        client,
        identity,
        { id: viewId },
        'Setup not confirmed',
        'Vouchr could not confirm this setup request. Close this window and review the current channel state before trying again.',
      );
      return 'unconfirmed';
    }

    try {
      await client.views.update({
        view_id: viewId,
        view: configureModal(provider, channel, referenceSources, requestId) as any,
      });
    } catch {
      // Acceptance of views.update is unknown. Leave the TTL-bound request alone and do not issue a
      // second update that could overwrite the form Slack actually accepted.
      await dmActor(
        client,
        identity,
        'Vouchr could not confirm whether channel credential setup finished opening. If the credential form appeared, use it or close it; otherwise try again.',
      );
      return 'unconfirmed';
    }
    return 'ok';
  };

  /**
   * The WebClient used to post post-OAuth success and recovery DMs. With an installationStore,
   * resolve the connecting user's own workspace bot token via fetchInstallation; without one,
   * fall back to the single env/opts token (unchanged behavior). The DM is best-effort, so a
   * missing install just means no nudge. Never throw, and never log the token.
   */
  type NotificationClientLookup = {
    raw: Promise<WebClient | null>;
    bounded: Promise<WebClient | null>;
  };
  const notificationClientLookups = new Map<string, NotificationClientLookup>();
  async function confirmClientFor(identity: SlackIdentity): Promise<WebClient | null> {
    if (!opts.installationStore) return confirmClient;
    const key = JSON.stringify([identity.enterpriseId, identity.teamId]);
    let entry = notificationClientLookups.get(key);
    if (!entry) {
      if (notificationClientLookups.size >= MAX_PENDING_NOTIFICATION_CLIENT_LOOKUPS) {
        // Bounded, non-fatal: skip this best-effort DM rather than start unbounded work behind a
        // hung installation store. Logged so a persistently full cap (a wedged store) is diagnosable
        // instead of silent. A custom store has no cancellation contract, so the slot must count
        // *unresolved* work — releasing it on a mere timeout would let a new lookup start every
        // window and defeat the cap. A store that never settles holds its slot until restart; that
        // bounded degradation is the deliberate trade for never exceeding the concurrency cap.
        console.error('[vouchr] notification-client lookup cap reached; skipping this best-effort DM');
        return null;
      }
      const raw = Promise.resolve().then(async () => {
        const inst = await opts.installationStore!.fetchInstallation({
          teamId: identity.teamId,
          enterpriseId: identity.enterpriseId ?? undefined,
          isEnterpriseInstall: false,
        });
        return inst.bot?.token ? slackNotificationClient(inst.bot.token, opts.slackClientOptions) : null;
      }).catch(() => null);
      const exactEntry: NotificationClientLookup = { raw, bounded: boundedNotificationResolution(raw) };
      entry = exactEntry;
      notificationClientLookups.set(key, entry);
      // Release the slot ONLY when the underlying store operation actually settles, so the cap
      // bounds unresolved concurrency, not just map size.
      void raw.then(
        () => { if (notificationClientLookups.get(key) === exactEntry) notificationClientLookups.delete(key); },
        () => { if (notificationClientLookups.get(key) === exactEntry) notificationClientLookups.delete(key); },
      );
    }
    // A custom installation store has no cancellation contract. Bound each caller (so a callback
    // never waits on a hung store), but keep the raw lookup deduplicated until it actually settles.
    return entry.bounded;
  }

  /** Attributable callback failures get one fixed private Slack next step. Unknown/replayed states
   * carry no identity and deliberately stay browser-only. Delivery is informational and best-effort:
   * it never changes the already-decided callback result. */
  async function notifyOAuthRecovery(
    result: Extract<CallbackResult, { ok: false; context: unknown }>,
  ): Promise<void> {
    const client = await confirmClientFor(result.context.identity);
    if (!client) return;
    const blocks = oauthRecoveryBlocks(
      result.context.provider,
      result.outcome,
      result.recovery,
    );
    await client.chat.postMessage({
      channel: result.context.identity.userId,
      blocks: blocks as any,
      text: blocksFallbackText(blocks),
    }).catch(() => undefined);
  }

  async function notifyOAuthConnected(
    result: Extract<CallbackResult, { ok: true }>,
  ): Promise<void> {
    const client = await confirmClientFor(result.identity);
    if (!client) return;
    await client.chat.postMessage({
      channel: result.identity.userId,
      // SEC-5: connectedDmText escapes the provider-reported account label.
      text: connectedDmText(result.provider, result.account),
    }).catch(() => undefined);
  }

  // #117 credential-health wiring. Default: DM the owner (healthNotifier), via the same per-workspace
  // client resolution as post-OAuth success and recovery DMs, debounced by the persistent notification_state
  // table. An operator-supplied onCredentialHealth REPLACES the default DMs (like `isAdmin`). Either
  // way the hook is fire-and-forget: a throwing/failing notifier never affects what fired it.
  const notifyState = new NotificationState(db);
  const notifyHealth = healthNotifier({ registry, audit, state: notifyState, clientFor: confirmClientFor });
  // Serialize deliveries through one in-process queue: shouldNotify→send→markNotified is
  // check-then-act, so two definitive failures milliseconds apart (sequential tool calls; the
  // single-flight map only dedupes CONCURRENT refreshes) would otherwise both pass the check and
  // double-DM. Cross-pod remains at-least-once (the state table narrows, not eliminates, the race).
  let healthQueue: Promise<void> = Promise.resolve();
  const health: CredentialHealthHook = opts.onCredentialHealth
    ?? ((e) => { healthQueue = healthQueue.then(() => notifyHealth(e)).catch(() => undefined); });

  /** Bolt global middleware: attach `context.vouchr` for each request with a user. */
  const middleware = async (args: any): Promise<void> => {
    const identity = resolveIdentity(args);
    if (identity) {
      const channel: string | null =
        args.event?.channel ?? args.body?.channel_id ?? args.body?.channel?.id ?? null;
      // The thread this request is in: thread_ts when in a thread, else the message's own ts (which
      // is the thread root). Null when there's no event (slash command / action).
      const thread: string | null = args.event?.thread_ts ?? args.event?.ts ?? null;
      args.context.vouchr = new ConnectContext({
        identity,
        channel,
        client: args.client,
        registry,
        vault,
        audit,
        consent,
        policy,
        redirectUri,
        resolvers,
        channelConfig,
        channelTools,
        inflight,
        rateLimits,
        sink,
        providerIds,
        adminCheck: opts.isAdmin,
        allowChannelCreatorConfig,
        requireMembership: opts.requireChannelMembership ?? false,
        thread,
        sessions,
        approvals,
        auditSink,
        health,
        notifications: notifyState,
        dryRun,
        slackClientOptions: opts.slackClientOptions,
      });
    }
    await args.next();
  };

  const callbackDeps = { registry, vault, audit, consent, redirectUri, auditSink, dryRun };

  /**
   * #116 dry-run test helper: complete the NEWEST pending consent for (user, provider) through the
   * REAL callback path — single-use state consumption, synthetic token exchange, vault write, audit
   * row — exactly as if the user had clicked Connect. Accepts a bare userId or a
   * `{ teamId, userId }` identity (to disambiguate multi-workspace tests). Throws when nothing is
   * pending (call `connect()` first — it posts the prompt and records the consent state) or when
   * the callback reports a failure.
   */
  const completeConsent = async (user: string | Pick<SlackIdentity, 'teamId' | 'userId'>, providerId: string) => {
    registry.get(providerId); // SEC-4: validate before any lookup; throws on an unknown id
    const userId = typeof user === 'string' ? user : user.userId;
    const state = await consent.latestStateFor(userId, providerId, typeof user === 'string' ? undefined : user.teamId);
    if (!state) {
      throw new Error(`No pending consent for "${providerId}" — call connect() first so the prompt records one.`);
    }
    const result = await handleOAuthCallback(callbackDeps, DRY_RUN_CODE, state);
    if (!result.ok) throw new Error(result.error);
    return result;
  };

  /** Mount the OAuth callback on the receiver's Express router. */
  function mountRoutes(router: any): void {
    router.get(callbackPath, async (req: any, res: any) => {
      try {
        const { code, state, error } = req.query;
        const result = await handleOAuthCallback(
          callbackDeps,
          code == null ? undefined : String(code),
          state == null ? undefined : String(state),
          error == null ? undefined : String(error),
        );
        // SEC-1/SEC-5 (#177): core returns a static error and never reflects the provider-controlled
        // query value. Keep text/plain + nosniff as defense in depth; the success path below opts
        // into text/html explicitly for the rendered landing page.
        if (!result.ok) {
          const response = res
            .status(result.status)
            .set({ 'content-type': 'text/plain; charset=utf-8', 'x-content-type-options': 'nosniff' })
            .send(result.error);
          // Slack is a best-effort side effect, never part of the browser callback's latency or
          // truthfulness. State was already consumed, so a replay cannot trigger a second DM attempt.
          if ('context' in result) void notifyOAuthRecovery(result).catch(() => undefined);
          return response;
        }
        emit({ type: 'connected', provider: result.provider });
        const response = res
          .set('content-type', 'text/html')
          .send(connectedHtml(result.provider, result.account, result.scopes, result.identity));
        void notifyOAuthConnected(result).catch(() => undefined);
        return response;
      } catch {
        // Express doesn't catch async rejections; an unhandled one here hangs the browser.
        res
          .status(500)
          .set({ 'content-type': 'text/plain; charset=utf-8', 'x-content-type-options': 'nosniff' })
          .send('Connection failed. Please try again.');
      }
    });
  }

  /** Build a per-request ConnectContext bound to a specific channel (for the modal submit). */
  function contextFor(
    identity: SlackIdentity,
    channel: string | null,
    client: WebClient,
    provisioningReceivedAt?: bigint,
    channelIssuance?: ChannelProvisioningIssuance,
  ): ConnectContext {
    const deps: InternalConnectContextDeps = {
      identity, channel, client, registry, vault, audit, consent, policy, redirectUri, resolvers,
      channelConfig, channelTools, inflight, rateLimits, sink, providerIds,
      adminCheck: opts.isAdmin, allowChannelCreatorConfig,
      requireMembership: opts.requireChannelMembership ?? false,
      thread: null, sessions, approvals, auditSink, health, notifications: notifyState, dryRun,
      slackClientOptions: opts.slackClientOptions,
    };
    if (provisioningReceivedAt != null) {
      deps[INTERNAL_PROVISIONING_RECEIVED_AT] = provisioningReceivedAt;
    }
    if (channelIssuance != null) {
      deps[INTERNAL_CHANNEL_PROVISIONING_ISSUANCE] = channelIssuance;
    }
    return new ConnectContext(deps);
  }

  /** The manifest plus its raw allowlist snapshot for admin renderers. Keeping the raw predicate lets
   *  them show policy-denied-but-allowlisted tools correctly without reading channel_tool twice. */
  const manifestSnapshotFor = (identity: SlackIdentity, channel: string) => buildToolManifestSnapshot({
    providerIds,
    registry,
    policy,
    channelTools,
    channelConfig,
    principal: identity,
    channel,
  });

  /**
   * Register the `/vouchr` slash command (`status`, `disconnect <provider>`,
   * `configure <provider>`), the channel-credential modal submit, and — when the app exposes
   * `event` (Bolt does; older custom fakes may not) — the App Home console (#111) on
   * `app_home_opened`. `configure` opens a private modal so the admin's secret is never typed
   * into the channel (invariant 7 / T7).
   */
  function registerCommands(app: {
    command: (name: string, handler: (args: any) => Promise<void>) => void;
    view: (id: string, handler: (args: any) => Promise<void>) => void;
    action: (id: string, handler: (args: any) => Promise<void>) => void;
    event?: (name: string, handler: (args: any) => Promise<void>) => void;
  }): void {
    // The command reference. ONLY subcommands that actually exist appear here (#194: never advertise a
    // command that doesn't exist). Plain text + code spans — legible without colour or emoji, so it
    // reads the same for keyboard and screen-reader users.
    const HELP_TEXT = [
      '*Vouchr commands*',
      '• `/vouchr` — open the settings panel for this channel',
      '• `/vouchr help` — show this command reference',
      '• `/vouchr status` — your connected accounts',
      '• `/vouchr tools` — the providers an agent may use in this channel',
      '• `/vouchr disconnect <provider>` — remove your connection to a provider',
      '• `/vouchr audit` — where your credentials have been used',
      '',
      '*Admin (this channel)*',
      '• `/vouchr enable <provider>` — allow a provider here',
      '• `/vouchr disable <provider>` — block a provider here',
      '• `/vouchr mode <provider> <shared|per-user|session>` — set the credential model',
      '• `/vouchr configure <provider>` — set a channel-shared credential (opens a private modal)',
      '• `/vouchr stats` — 30-day usage for this channel',
      '• `/vouchr audit channel` — this channel’s shared-credential usage',
    ].join('\n');
    // Raw command arguments can be credential-shaped (for example, a token pasted in the provider
    // position). SEC-1 therefore forbids reflecting an unknown value even after mrkdwn escaping:
    // escaping prevents injection, not disclosure. Keep one static, actionable response for every
    // provider-taking command.
    const UNKNOWN_PROVIDER_TEXT = 'Unknown provider. Run `/vouchr tools` to see the registered providers.';
    const UNKNOWN_DISCONNECT_PROVIDER_TEXT = 'Unknown provider. Run `/vouchr status` to see your connected accounts.';
    const COMMAND_READ_FAILURE = {
      status: 'Could not load your connected accounts. Try `/vouchr status` again in a moment.',
      tools: 'Could not load this channel\'s tools. Try `/vouchr tools` again in a moment.',
      stats: 'Could not load this channel\'s usage stats. Try `/vouchr stats` again in a moment.',
      audit: 'Could not load your credential usage. Try `/vouchr audit` again in a moment.',
      auditChannel: 'Could not load this channel\'s credential usage. Try `/vouchr audit channel` again in a moment.',
    } as const;
    // Keep dependency preparation separate from Slack delivery. If respond() itself rejects after
    // Slack accepted the response, catching it here and responding again could duplicate the reply.
    // Static fallback copy also ensures a DB/KMS/Slack error can never be reflected to the user.
    const prepareCommandResponse = async <T>(prepare: () => Promise<T>): Promise<
      { ok: true; value: T } | { ok: false }
    > => {
      try {
        return { ok: true, value: await prepare() };
      } catch {
        return { ok: false };
      }
    };

    app.command('/vouchr', async ({ command, ack, respond, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      const identity = resolveIdentity({ body: command });
      if (!identity) return respond('Could not resolve your Slack identity.');

      const text = String(command.text ?? '').trim();
      const words = text ? text.split(/\s+/) : [];
      const [sub, arg, arg2] = words;

      // No subcommand → open the interactive config modal (#109). `/vouchr status` (and any other
      // subcommand) keeps its text output below, so scripts and muscle memory are unaffected. A modal
      // needs a trigger_id; without one (shouldn't happen for a slash command) fall back to the text.
      // Building the modal makes several DB/Slack round-trips within Slack's ~3s trigger window. A
      // build/open failure gets fixed command guidance rather than silently substituting status for
      // the settings surface the user requested; raw Slack/DB errors are never reflected.
      if (!sub && command.trigger_id) {
        try {
          await client.views.open({ trigger_id: command.trigger_id, view: await buildConfigModal(identity, command.channel_id ?? null, client) });
          return;
        } catch {
          return respond('Could not open Vouchr settings. Run `/vouchr help` to use the text commands instead.');
        }
      }

      // List the channel's tool manifest (which providers an agent may use here + their mode).
      if (sub === 'tools') {
        if (words.length !== 1) return respond('Usage: `/vouchr tools`');
        if (!command.channel_id) return respond('Run `/vouchr tools` from inside a channel.');
        const prepared = await prepareCommandResponse(async () => {
          const manifest = await contextFor(identity, command.channel_id, client).toolManifest();
          if (!manifest.length) return 'No providers are registered.';
          const lines = manifest
            .map((m) => `• *${escapeMrkdwn(m.provider)}*: ${m.enabled ? 'enabled' : 'disabled'}${m.mode ? ` (${escapeMrkdwn(m.mode)})` : ''}`)
            .join('\n');
          return `Tools for <#${escapeMrkdwn(command.channel_id)}>:\n${lines}\n\nAdmins: \`/vouchr enable|disable <provider>\`.`;
        });
        return respond(prepared.ok ? prepared.value : COMMAND_READ_FAILURE.tools);
      }

      // Admin usage analytics for THIS channel over the last 30 days: which enabled tools are actually
      // used, by how many distinct humans, and which are idle dead-weight to prune. Admin-gated (same
      // gate as enable/mode) + audited on refusal. Service tools aren't brokered, so they're excluded.
      if (sub === 'stats') {
        if (words.length !== 1) return respond('Usage: `/vouchr stats`');
        if (!command.channel_id) return respond('Run `/vouchr stats` from inside a channel.');
        const prepared = await prepareCommandResponse(async () => {
          if (!(await commandAdmin(client, identity, command.channel_id))) {
            await audit.record('denied', identity, 'stats', { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
            return adminOnly(allowChannelCreatorConfig, 'view channel usage stats');
          }
          const manifest = await contextFor(identity, command.channel_id, client).toolManifest();
          const enabled = manifest.filter((m) => m.enabled && isBrokeredProvider(m)).map((m) => m.provider);
          const since = Date.now() - 30 * 24 * 60 * 60 * 1000;
          const stats = await audit.statsByChannel(identity.teamId, command.channel_id, since);
          const blocks = statsBlocks(enabled, stats, 30);
          return { text: blocksFallbackText(blocks), blocks: blocks as any };
        });
        return respond(prepared.ok ? prepared.value : COMMAND_READ_FAILURE.stats);
      }

      // Enable/disable a provider in this channel. Admin-gated (default-deny) + audited as 'config'
      // inside setChannelToolEnabled — the same helper the App Home button routes through (STR-3).
      // An ineligible channel class (archived / ext-shared / DM) throws a UserFacingError inside the
      // helper, surfaced like the `mode` branch does.
      if (sub === 'enable' || sub === 'disable') {
        if (words.length !== 2) return respond(`Usage: \`/vouchr ${sub} <provider>\``);
        if (!command.channel_id) return respond(`Run \`/vouchr ${sub}\` from inside the channel you want to configure.`);
        if (!registry.has(arg)) return respond(UNKNOWN_PROVIDER_TEXT);
        const on = sub === 'enable';
        try {
          if ((await setChannelToolEnabled(
            client,
            identity,
            command.channel_id,
            arg,
            on,
            provisioningReceivedAt,
          )) === 'denied') {
            return respond(adminOnly(allowChannelCreatorConfig, 'change channel tools'));
          }
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        return respond(`${on ? 'Enabled' : 'Disabled'} *${escapeMrkdwn(arg)}* in <#${escapeMrkdwn(command.channel_id)}>.`);
      }

      // Per-channel auth mode: shared (channel cred) | per-user | session (per-user + thread grant).
      // Admin-gated + audited in setChannelMode.
      if (sub === 'mode') {
        if (words.length !== 3 || !arg || !isChannelMode(arg2)) {
          return respond('Usage: `/vouchr mode <provider> <shared|per-user|session>`');
        }
        if (!registry.has(arg)) return respond(UNKNOWN_PROVIDER_TEXT);
        if (!command.channel_id) return respond('Run `/vouchr mode` from inside the channel you want to configure.');
        try {
          await contextFor(
            identity,
            command.channel_id,
            client,
            provisioningReceivedAt,
          ).setChannelMode(arg, arg2);
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        return respond(`Set *${escapeMrkdwn(arg)}* to *${escapeMrkdwn(arg2)}* in <#${escapeMrkdwn(command.channel_id)}>.`);
      }

      if (sub === 'configure') {
        if (words.length !== 2) return respond('Usage: `/vouchr configure <provider>`');
        if (!command.channel_id) return respond('Run `/vouchr configure` from inside the channel you want to configure.');
        // Validate the provider BEFORE recording a denial or opening the modal (parity with enable/disable):
        // otherwise an unvalidated arg — potentially a credential-shaped typo — lands raw in the audit
        // `provider` column and could be reflected back into a `/vouchr audit` view. The gate + denial
        // audit + modal open is openConfigureModal, shared with the App Home Configure button (STR-3).
        if (!registry.has(arg)) return respond(UNKNOWN_PROVIDER_TEXT);
        try {
          const result = await openConfigureModal(
            client,
            identity,
            command.channel_id,
            arg,
            command.trigger_id,
            provisioningReceivedAt,
          );
          if (result === 'denied') {
            return respond(adminOnly(allowChannelCreatorConfig, 'configure channel credentials'));
          }
          if (result === 'locked') return respond(CREDENTIAL_SETUP_LOCKED);
          if (result === 'unsupported') return respond(CHANNEL_CREDENTIAL_UNAVAILABLE);
        } catch (e) {
          return respond(safeUserMessage(e)); // ineligible channel class → the core reason, nothing else
        }
        return;
      }
      if (sub === 'disconnect') {
        if (words.length !== 2) return respond('Usage: `/vouchr disconnect <provider>`');
        // Shared with the headless broker's /v1/disconnect (core disconnectProvider): local delete
        // FIRST, then best-effort upstream revoke. Core recognizes either a current registry entry or
        // this user's exact stored stale row; arbitrary input reaches no mutation/audit/event (SEC-4).
        let outcome: Awaited<ReturnType<typeof disconnectProvider>>;
        try {
          outcome = await disconnectProviderAtReceipt(
            vault,
            audit,
            registry,
            identity,
            arg,
            await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt),
          );
        } catch (error) {
          if (error instanceof InteractionStateChangedError) {
            return respond(safeUserMessage(error));
          }
          // A thrown failure means the local delete itself is uncertain. Never echo DB/KMS/provider
          // text; give one state-agnostic way to discover the committed outcome (#194 UX-1/5).
          return respond('Could not confirm whether the account was disconnected. Run `/vouchr status` to check; if it is still listed, try again.');
        }
        if (!outcome.recognized) return respond(UNKNOWN_DISCONNECT_PROVIDER_TEXT);
        const p = escapeMrkdwn(arg); // recognized current/stored id; still escape at render (SEC-5)
        if (!outcome.removed && !outcome.ok) {
          return respond(`Could not confirm that older *${p}* setup requests were invalidated. Retry \`/vouchr disconnect ${p}\` before reconnecting.`);
        }
        if (!outcome.removed) return respond(`You have no connected *${p}* account, so there was nothing to disconnect.`);
        emit({ type: 'revoked', provider: arg, ok: outcome.ok });
        if (!outcome.audited && outcome.ok) {
          return respond(`Disconnected *${p}* locally, but Vouchr could not confirm the audit record. Ask an admin to check the Vouchr logs.`);
        }
        return respond(outcome.ok
          ? `Disconnected *${p}*. The agent can no longer act as you on ${p}.`
          : `Disconnected *${p}* locally, but complete revocation could not be confirmed. Retry \`/vouchr disconnect ${p}\` to invalidate older setup requests, and revoke or rotate Vouchr’s access in ${p} directly if needed.`);
      }

      // Self-service transparency: where your credential was used. `audit channel` (admin-gated) shows
      // this channel's channel-owned usage. Strictly scoped by the SELECT — a non-admin only ever sees
      // rows attributed to their own user id, never another user's or another channel's.
      if (sub === 'audit') {
        if (words.length > 2 || (arg && arg !== 'channel')) return respond('Usage: `/vouchr audit [channel]`');
        if (arg === 'channel') {
          if (!command.channel_id) return respond('Run `/vouchr audit channel` from inside the channel.');
          const prepared = await prepareCommandResponse(async () => {
            if (!(await commandAdmin(client, identity, command.channel_id))) {
              await audit.record('denied', identity, 'audit', { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
              return adminOnly(allowChannelCreatorConfig, 'view channel credential usage');
            }
            const rows = await audit.listByChannel(identity.teamId, command.channel_id, 20);
            const blocks = auditBlocks(rows, 'Credential usage in this channel');
            return { text: blocksFallbackText(blocks), blocks: blocks as any };
          });
          return respond(prepared.ok ? prepared.value : COMMAND_READ_FAILURE.auditChannel);
        }
        const prepared = await prepareCommandResponse(async () => {
          const rows = await audit.listByOwnerUser(identity, 20);
          const blocks = auditBlocks(rows, 'Your credential usage');
          return { text: blocksFallbackText(blocks), blocks: blocks as any };
        });
        return respond(prepared.ok ? prepared.value : COMMAND_READ_FAILURE.audit);
      }

      // Explicit `help` — the command reference. Lists only commands that actually exist (#194).
      if (sub === 'help') {
        if (words.length !== 1) return respond('Usage: `/vouchr help`');
        return respond(HELP_TEXT);
      }

      let statusPage = 1;
      if (sub === 'status') {
        const parsed = arg === undefined ? 1 : Number(arg);
        if (
          words.length > 2 ||
          (arg !== undefined && (!/^[1-9]\d*$/.test(arg) || !Number.isSafeInteger(parsed)))
        ) return respond('Usage: `/vouchr status [page]`');
        statusPage = parsed;
      }

      // `status` (plus the defensive bare-command path when Slack supplies no trigger id) → the
      // connected-accounts view below.
      // Any OTHER leftover token is an unrecognized subcommand (a typo): guide to `help` without
      // reflecting the raw token. It may be a credential pasted in the wrong position (SEC-1).
      if (sub && sub !== 'status') {
        return respond('Unknown subcommand. Run `/vouchr help` to see what you can do.');
      }

      // Never list a service-to-service tool as a "connected account": Vouchr doesn't broker those,
      // so they don't belong in the user's Vouchr connection status (defensive — storage is blocked).
      // Rendered through statusBlocks → connectionLine, the ONE escaped row renderer shared with
      // the modal and App Home (SEC-5: provider-reported account labels never hit mrkdwn raw).
      const prepared = await prepareCommandResponse(async () => {
        const conns = await listBrokeredConnections(identity);
        if (!conns.length) return statusPage === 1
          ? 'No connected accounts. They are created on demand when an agent needs one.'
          : 'No such status page. Run `/vouchr status` to start at page 1.';
        const legacyText = `Your connected accounts:\n${conns.map(connectionLine).join('\n')}\n\nDisconnect with \`/vouchr disconnect <provider>\`.`;
        if (arg === undefined) {
          try {
            // Preserve the stable text-command interface whenever the complete result fits. Paging
            // is a boundary fallback, not a behavior change for an otherwise valid text response.
            blocksFallbackText([{ type: 'section', text: { type: 'mrkdwn', text: legacyText } }]);
            return legacyText;
          } catch { /* the complete text exceeds Slack's top-level limit; page it below */ }
        }
        // Fourteen worst-case rows (63-char provider + a 512-byte account label whose `&` escaping
        // expands fivefold) keep both sections and the complete accessibility fallback under Slack's
        // limits without shortening any identity.
        const pageSize = 14;
        const totalPages = Math.ceil(conns.length / pageSize);
        if (statusPage > totalPages) return 'No such status page. Run `/vouchr status` to start at page 1.';
        const page = conns.slice((statusPage - 1) * pageSize, statusPage * pageSize);
        const blocks = statusBlocks(page, { page: statusPage, totalPages });
        return { text: blocksFallbackText(blocks), blocks: blocks as any };
      });
      return respond(prepared.ok ? prepared.value : COMMAND_READ_FAILURE.status);
    });

    // Modal submit (channel-shared OR per-user). One handler keeps validation, acknowledgement,
    // mutation, and receipts identical across both paths. Pure validation can still render inline;
    // Slack is acknowledged BEFORE any DB, KMS, resolver, or Slack API work (vision.md). A private
    // pending view remains as unknown-state recovery if both result update and DM delivery fail.
    // The typed value is never echoed, posted, logged, or put in audit meta (invariant 8 / T7).
    const handleSecretSubmit = async ({ ack, body, view, client }: any, kind: 'channel' | 'user') => {
      // Check before reading view.state: a modal opened before containment must not reach normal
      // credential parsing or mutation once lockdown is active.
      if (vault.lockdownEnabled) {
        return ack({
          response_action: 'update',
          view: privateStatusModal('Setup unavailable', CREDENTIAL_SETUP_LOCKED),
        });
      }
      const identity = resolveIdentity({ body });
      let provider: unknown;
      let requestId: unknown;
      try {
        ({ provider, requestId } = JSON.parse(view.private_metadata));
      } catch {
        return ack({ response_action: 'errors', errors: { raw: 'Malformed request. Please reopen the modal.' } });
      }
      const refValue = view.state?.values?.ref?.v?.value ?? '';
      const rawValue = view.state?.values?.raw?.v?.value ?? '';
      if (!identity) return ack({ response_action: 'errors', errors: { raw: 'Could not resolve your Slack identity.' } });
      if (typeof refValue !== 'string' || typeof rawValue !== 'string') {
        return ack({ response_action: 'errors', errors: { raw: 'Malformed request. Please reopen the modal.' } });
      }
      const ref = refValue;
      const raw = rawValue;
      if ((ref && raw) || (!ref && !raw)) {
        return ack({ response_action: 'errors', errors: { raw: 'Provide exactly one: a reference or a key.' } });
      }
      let normalizedReference: SecretReference | undefined;
      if (kind === 'user' && (
        typeof provider !== 'string' ||
        !registry.has(provider) ||
        !isBrokeredProvider(registry.get(provider))
      )) {
        return ack({ response_action: 'errors', errors: { [ref ? 'ref' : 'raw']: 'Credential setup is unavailable. Reopen the modal.' } });
      }
      if (kind === 'user' && ref) {
        try {
          const definition = registry.get(provider as string);
          normalizedReference = normalizeSecretReference({ secretRef: ref }, resolvers, definition.scopesDefault);
        } catch (e) {
          return ack({ response_action: 'errors', errors: { ref: safeUserMessage(e) } });
        }
      }
      if (!isInteractionId(requestId)) {
        return ack({ response_action: 'errors', errors: { [ref ? 'ref' : 'raw']: 'Credential setup expired. Reopen the modal.' } });
      }
      await ack({
        response_action: 'update',
        view: privateStatusModal(
          'Saving credential',
          'Vouchr is saving this credential. If no result appears here, reopen credential setup to review the current state before retrying.',
        ),
      });

      let channel = '';
      if (kind === 'channel') {
        let pending: { channel: string; provider: string } | null;
        try {
          pending = await channelProvisioning.resolveForModal(requestId, identity);
        } catch {
          await deliverModalOutcome(
            client,
            identity,
            view,
            'Save not confirmed',
            'Vouchr could not confirm whether the channel credential was saved. Review the current channel state before requesting setup again.',
          );
          return;
        }
        if (!pending) {
          await deliverModalOutcome(
            client,
            identity,
            view,
            'Review current status',
            'This channel credential setup request is no longer active. Review the current channel state before requesting setup again.',
          );
          return;
        }
        ({ channel, provider } = pending);
        if (!registry.has(pending.provider) || !isBrokeredProvider(registry.get(pending.provider))) {
          await deliverModalOutcome(
            client,
            identity,
            view,
            'Review current status',
            'This provider is no longer available for channel credential setup. Review the current channel state before requesting setup again.',
          );
          return;
        }
        if (ref) {
          try {
            const definition = registry.get(pending.provider);
            normalizeSecretReference({ secretRef: ref }, resolvers, definition.scopesDefault);
          } catch (error) {
            await deliverModalOutcome(
              client,
              identity,
              view,
              'Credential not saved',
              safeUserMessage(error),
            );
            return;
          }
        }
      }

      const authoritativeProvider = provider as string;
      try {
        if (kind === 'channel') {
          const channelContext = contextFor(
            identity,
            channel,
            client,
            undefined,
            channelProvisioning.issuance(requestId, identity, channel, authoritativeProvider),
          );
          if (ref) {
            await channelContext.referenceChannelSecret(authoritativeProvider, { secretRef: ref });
          } else {
            await channelContext.setChannelSecret(authoritativeProvider, raw);
          }
        } else {
          const result = await configureUserCredential({
            vault,
            audit,
            identity,
            providerId: authoritativeProvider,
            credential: normalizedReference
              ? { kind: 'ref', reference: normalizedReference }
              : {
                  kind: 'secret',
                  token: {
                    accessToken: raw,
                    refreshToken: null,
                    scopes: '',
                    expiresAt: null,
                    externalAccount: null,
                  },
                },
            issuance: provisioning.issuance(requestId, identity, authoritativeProvider),
          });
          if (result !== 'stored') {
            // A consumed request can be a Slack retry after the first submit already committed.
            // Never overwrite that success receipt with a definitive failure: the exact current
            // state may have changed again, so direct the user to review it before retrying.
            await deliverModalOutcome(
              client,
              identity,
              view,
              'Review current status',
              `This setup request is no longer active. Your *${escapeMrkdwn(authoritativeProvider)}* credential may already be saved. Ask the agent to check current connection status before requesting setup again.`,
            );
            return;
          }
        }
      } catch (error) {
        const p = escapeMrkdwn(authoritativeProvider);
        const target = kind === 'channel' ? `the *${p}* channel credential` : `your *${p}* credential`;
        if (error instanceof ChannelProvisioningStaleError) {
          await deliverModalOutcome(
            client,
            identity,
            view,
            'Review current status',
            'This channel credential setup request is no longer active. Review the current channel state before requesting setup again.',
          );
          return;
        }
        if (error instanceof UserFacingError) {
          await deliverModalOutcome(
            client,
            identity,
            view,
            'Credential not saved',
            safeUserMessage(error),
          );
          return;
        }
        await deliverModalOutcome(
          client,
          identity,
          view,
          'Save not confirmed',
          `Vouchr could not confirm whether ${target} was saved. Ask the agent to check current connection status before requesting setup again.`,
        );
        return;
      }
      // Private confirmation DM (no secret), just the fact it was set.
      const p = escapeMrkdwn(authoritativeProvider);
      const text = kind === 'channel'
        ? `Saved the *${p}* credential for <#${escapeMrkdwn(channel)}>.`
        : `Your *${p}* credential is set. Ask me again and I'll use it.`;
      await deliverModalOutcome(client, identity, view, 'Credential saved', text);
    };
    app.view(CONFIGURE_CALLBACK, (a: any) => handleSecretSubmit(a, 'channel'));
    app.view(USER_KEY_CALLBACK, (a: any) => handleSecretSubmit(a, 'user'));

    // ── #109 no-arg config modal ────────────────────────────────────────────────────────────
    // Build the modal for `identity` in `channelId`: everyone gets their connections + the read-only
    // channel manifest; ADMINS additionally get per-provider mode/enable controls (admin decided
    // server-side here, NOT trusted on submit). Shared by the initial open and the views.update after a
    // disconnect. Service tools are shown read-only but excluded from the admin controls: Vouchr doesn't
    // broker them, so channel-credential mode is meaningless and setChannelMode would refuse them.
    async function buildConfigModal(identity: SlackIdentity, channelId: string | null, client: WebClient): Promise<unknown> {
      // These are independent and all sit before Slack's short-lived trigger_id is consumed by
      // views.open. Dispatch them together rather than spending one DB/network window per fact.
      const [connections, manifest, isAdmin] = await Promise.all([
        listBrokeredConnections(identity),
        channelId
          ? manifestSnapshotFor(identity, channelId)
          : Promise.resolve({ tools: [], toolAllowed: (_provider: string) => true }),
        channelId ? commandAdmin(client, identity, channelId) : Promise.resolve(false),
      ]);
      // The modal keeps its pre-#111 contract: service tools are read-only there (its row shape is
      // mode+enabled controls, meaningless for them). The App Home instead renders every
      // row and per-row picks which controls a service tool gets (Enable/Disable only).
      const admin = isAdmin && channelId
        ? adminToolRows(manifest.tools, manifest.toolAllowed).filter((r) => isBrokeredProvider(r))
        : undefined;
      return configModal({ channel: channelId, connections, tools: manifest.tools, admin });
    }

    /**
     * The per-provider ADMIN control rows for a channel — ONE ROW PER REGISTERED PROVIDER (#111),
     * service tools included (their allowlist Enable/Disable is a valid channel control; renderers
     * use `identity` to omit the mode/credential controls core refuses for them). Shared by the App
     * Home governance section and (brokered-filtered) the config modal, so both consoles render the
     * same facts. The Enabled bit is channelTools.isEnabled — the raw tool-allowlist bit, NOT the
     * manifest's policy-intersected `enabled`: rendering the intersected value would show a
     * policy-denied provider as disabled and let an untouched save/click look like an intentional
     * disable (config-modal findings 3/1); the manifest keeps the intersected value for the
     * read-only displays.
     */
    function adminToolRows(
      tools: ToolManifestEntry[],
      toolAllowed: (provider: string) => boolean,
    ): ConfigAdminRow[] {
      // Raw tool-allowlist bit (NOT the manifest's policy-intersected `enabled`) reuses the manifest's
      // channel snapshot, so admin rendering adds no query and cannot drift to a second DB window.
      return tools.map((t) => ({
        provider: t.provider,
        mode: t.mode,
        enabled: toolAllowed(t.provider),
        identity: t.identity,
      }));
    }

    // Config modal submit: parse the view, acknowledge Slack, then re-check authorization and apply
    // changed controls. The modal only SHOWED controls to admins, but the payload is forgeable; each
    // mutation still routes through the same server-side helper as its slash/action counterpart.
    // Receipts are private and distinguish confirmed changes from unconfirmed failures, so a partial
    // batch is never presented as one all-or-nothing success or failure. An untouched field never
    // mutates or reverts a concurrent admin's change because every value is diffed against OPEN-TIME
    // metadata, not a later store read.
    app.view(CONFIG_CALLBACK, async ({ ack, body, view, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      const identity = resolveIdentity({ body });
      if (!identity) {
        return ack({
          response_action: 'update',
          view: privateStatusModal(
            'Settings not applied',
            'Could not verify your Slack identity. Reopen Vouchr settings and try again.',
          ),
        });
      }
      const metadata = parseConfigMetadata(view.private_metadata);
      if (!metadata) {
        return ack({
          response_action: 'update',
          view: privateStatusModal(
            'Settings not applied',
            'This settings view is stale or malformed. Reopen Vouchr settings and try again.',
          ),
        });
      }
      const { channel, open } = metadata;
      const openMode = new Map(open.map((o) => [o.p, o.m]));
      const openEnabled = new Map(open.map((o) => [o.p, o.e]));

      // Collect the submitted state per provider up front, so mode + enabled are each diffed against
      // their OPEN-TIME value rather than the current store.
      const values = view.state?.values ?? {};
      const submittedMode = new Map<string, unknown>();
      const submittedEnabled = new Map<string, boolean>();
      for (const [blockId, v] of Object.entries<any>(values)) {
        if (blockId.startsWith('mode:')) submittedMode.set(blockId.slice(5), v?.mode?.selected_option?.value);
        else if (blockId.startsWith('tool:')) {
          const options = v?.enabled?.selected_options;
          submittedEnabled.set(blockId.slice(5), Array.isArray(options) && options.some((o: any) => o?.value === 'enabled'));
        }
      }
      await ack({
        response_action: 'update',
        view: privateStatusModal(
          'Updating settings',
          'Vouchr is applying these settings. If no result appears here, reopen Vouchr settings to review the current state before retrying.',
        ),
      });

      if (!(await commandAdmin(client, identity, channel))) {
        await audit.record('denied', identity, 'config', { reason: 'not-admin', owner: 'channel', channel }).catch(() => undefined);
        await deliverModalOutcome(
          client,
          identity,
          view,
          'Settings not applied',
          `${adminOnly(allowChannelCreatorConfig, 'change channel settings')} Reopen Vouchr settings after an administrator grants access.`,
        );
        return;
      }

      const ctx = contextFor(identity, channel, client, provisioningReceivedAt);
      let confirmed = 0;
      let unconfirmed = 0;

      // ── mode: apply only where the admin actually changed the select (submitted !== open-time) ──
      for (const [provider, mode] of submittedMode) {
        if (!registry.has(provider) || !isChannelMode(mode)) continue; // forged/invalid → ignore
        if (mode === (openMode.get(provider) ?? null)) continue; // untouched (or reset to the same) → skip
        try { await ctx.setChannelMode(provider, mode); confirmed++; } catch { unconfirmed++; }
      }

      // ── enabled: the tool allowlist. Only the controls the admin actually changed (submitted !==
      // open-time) are applied; the write — including the first-write allowlist materialization that
      // keeps untouched providers from vanishing, and the configured-ness decision itself — is ONE
      // atomic core mutation (ChannelTools.applyEnabled), so a concurrent admin or a mid-write
      // failure can never leave a partial allowlist. Audit only the providers that actually changed. ──
      const enabledChanged = [...submittedEnabled].filter(([p]) => registry.has(p) && submittedEnabled.get(p) !== (openEnabled.get(p) ?? true));
      if (enabledChanged.length) {
        try {
          const configured = await configureChannelTools({
            channelTools,
            vault,
            audit,
            identity,
            channel,
            changes: enabledChanged,
            allProviders: providerIds,
            issuance: await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt),
            // The modal's common gate above already proved current admin authority once for every
            // submitted setting; the shared helper still owns the mutation/audit sequence.
            authorize: async () => true,
            assertEligible: () => assertChannelEligible(client, channel),
          });
          if (configured === 'configured') confirmed += enabledChanged.length;
          else unconfirmed += enabledChanged.length;
        } catch {
          unconfirmed += enabledChanged.length;
        }
      }

      const destination = `<#${escapeMrkdwn(channel)}>`;
      if (unconfirmed) {
        const prefix = confirmed ? `Updated ${confirmed} channel setting${confirmed === 1 ? '' : 's'} for ${destination}. ` : '';
        await deliverModalOutcome(
          client,
          identity,
          view,
          'Review settings',
          `${prefix}${unconfirmed} setting${unconfirmed === 1 ? '' : 's'} could not be confirmed. Reopen Vouchr settings to review the current state.`,
        );
      } else if (confirmed) {
        await deliverModalOutcome(
          client,
          identity,
          view,
          'Settings updated',
          `Updated ${confirmed} channel setting${confirmed === 1 ? '' : 's'} for ${destination}.`,
        );
      } else {
        await deliverModalOutcome(
          client,
          identity,
          view,
          'No changes',
          `No channel settings changed for ${destination}.`,
        );
      }
    });

    // ── #111 App Home console ───────────────────────────────────────────────────────────────
    // Everyone gets "Your connections" (same Disconnect flow as the modal); viewers who pass the
    // server-side gate additionally get "Channel governance" (a channel picker + per-provider mode /
    // enable / configure controls). RENDERING is the only thing decided here — every block action
    // re-validates its inputs (SEC-4) and re-checks admin at the mutation (SEC-3), because a
    // block_actions payload (private_metadata, block ids, button values) is fully forgeable.

    /** The selected channel carried in the published home view (or the app_home_opened event's echo
     *  of it). Untrusted: it only scopes rendering / is re-verified before any mutation. */
    function homeSelectedChannel(view: any): string | null {
      let channel: unknown = null;
      try { ({ channel = null } = JSON.parse(view?.private_metadata || '{}')); } catch { return null; }
      return typeof channel === 'string' && channel ? channel : null;
    }

    /**
     * The channel a home MUTATION targets. SEC-4: unlike a slash command's Slack-verified channel_id,
     * this comes from forgeable view metadata — so before it can reach any persist or audit write it
     * must name a real channel (conversations.info, fail-closed on any error/mismatch). Authorization
     * against that channel is then re-checked inside each mutation helper (SEC-3).
     */
    async function verifiedHomeChannel(client: WebClient, body: any): Promise<string | null> {
      const channel = homeSelectedChannel(body?.view);
      if (!channel) return null;
      try {
        const info = (await client.conversations.info({ channel })) as any;
        return info?.channel?.id === channel ? channel : null;
      } catch {
        return null;
      }
    }

    /**
     * Build the App Home view for `identity` — cheap (one vault list + the admin gate; per-provider
     * config reads only once a channel is selected) and idempotent, since app_home_opened fires often.
     * Governance shows for a workspace admin (or custom-isAdmin pass) and, when the creator path is
     * opted in, for everyone — a creator is unknowable until a channel is picked, so the PER-CHANNEL
     * gate (commandAdmin, the same eligibility function as the slash commands) decides once one is.
     * A selected channel that is ineligible (archived / externally shared / DM — the core
     * channelIneligibleReason rule) or was deleted since last render degrades to a note, never an error.
     */
    async function buildHomeView(identity: SlackIdentity, client: WebClient, selected: string | null): Promise<unknown> {
      const [connections, workspaceAdmin] = await Promise.all([
        listBrokeredConnections(identity),
        commandAdmin(client, identity, ''), // '' → the creator path can't match here
      ]);
      // "Available providers" advertises connect-on-demand, so it lists only providers Vouchr
      // actually brokers a user credential for — a service tool must not be advertised as
      // connectable. Governance rows are separate (adminToolRows, same brokered filter as the modal).
      const connectable = providerIds.filter((p) => isBrokeredProvider(registry.get(p)));
      const showGovernance = workspaceAdmin || (!opts.isAdmin && allowChannelCreatorConfig);

      let governance: { channel: string | null; note?: string; tools?: ConfigAdminRow[] } | undefined;
      if (showGovernance) {
        governance = { channel: selected };
        if (selected) {
          let info: ChannelInfo | null = null;
          try { info = ((await client.conversations.info({ channel: selected })) as any)?.channel ?? null; } catch { info = null; }
          const reason = channelIneligibleReason(info); // fail-closed: null info (deleted channel) → a reason
          if (reason) {
            governance = { channel: selected, note: reason };
          } else if (!(workspaceAdmin || (await commandAdmin(client, identity, selected)))) {
            governance = { channel: selected, note: adminOnly(allowChannelCreatorConfig, 'configure this channel') };
          } else {
            const manifest = await manifestSnapshotFor(identity, selected);
            governance = { channel: selected, tools: adminToolRows(manifest.tools, manifest.toolAllowed) };
          }
        }
      }
      // Ownership stamp: ONLY this internal publisher marks the view as Vouchr's and carries the
      // selection state — the exported homeView stays unstamped so a host reusing it for its OWN
      // Home tab is never mistaken for ours (the event/disconnect handlers key ownership off
      // HOME_CALLBACK). The metadata channel is forgeable like any view field; handlers re-verify
      // it (verifiedHomeChannel) and re-check admin before any write.
      return {
        ...(homeView({ connections, providers: connectable, governance }) as object),
        callback_id: HOME_CALLBACK,
        private_metadata: JSON.stringify({ channel: governance?.channel ?? null }),
      };
    }

    /** views.publish for `identity`, best-effort: re-publishing is feedback, so a Slack/API hiccup
     *  must never break the mutation (or event) that triggered it. */
    async function publishHome(identity: SlackIdentity, client: WebClient, selected: string | null): Promise<void> {
      try {
        const view = await buildHomeView(identity, client, selected);
        await client.views.publish({ user_id: identity.userId, view: view as any });
      } catch { /* best-effort */ }
    }

    /** Feedback for a click whose metadata channel no longer verifies (deleted since render, or a
     *  forged id): tell the actor why nothing happened and reset the view to a selection-less state
     *  — a legitimate user in that race must not get a silent no-op. */
    async function staleChannelFeedback(client: WebClient, identity: SlackIdentity): Promise<void> {
      await dmActor(client, identity, 'That channel is no longer available (deleted or inaccessible). Pick another channel in the Vouchr Home tab.');
      await publishHome(identity, client, null);
    }

    // Publish on open (and re-render with the previously selected channel, which the event echoes
    // back in its `view`). Only the Home tab — a messages-tab open has nothing to publish.
    app.event?.('app_home_opened', async ({ event, body, client }: any) => {
      if (event?.tab && event.tab !== 'home') return;
      // A host may publish its OWN Home tab (homeView is exported and hosts can run their own
      // app_home_opened handler): when the event echoes a foreign current view, defer to the host
      // instead of clobbering it — the same deference as DISCONNECT_ACTION. No current view (the
      // user's very first open) is ours to publish; if the host also publishes then, last write wins
      // once — from the next open the callback_id decides.
      if (event?.view && event.view.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body, event });
      if (!identity) return;
      await publishHome(identity, client, homeSelectedChannel(event?.view));
    });

    // Channel picked → re-render the governance section for it. Selection is not a mutation: the
    // render path itself re-checks eligibility + admin for the picked channel.
    app.action(HOME_CHANNEL_ACTION, async ({ ack, body, client }: any) => {
      await ack();
      if (body.view?.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const selected = body.actions?.[0]?.selected_conversation;
      await publishHome(identity, client, typeof selected === 'string' && selected ? selected : null);
    });

    // Mode select → the SAME helper as `/vouchr mode` (ConnectContext.setChannelMode owns the admin
    // gate, the eligibility check, the write, and the audit row — STR-3), then re-publish. Validation
    // order matches the slash command: registry + modes list BEFORE the mutation (SEC-4) — an invalid
    // forged mode must not even reach setChannelMode (whose shared-cred cleanup precedes its sink check).
    app.action(HOME_MODE_ACTION, async ({ ack, body, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      if (body.view?.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const a = body.actions?.[0] ?? {};
      const provider = typeof a.block_id === 'string' && a.block_id.startsWith('home_mode:') ? a.block_id.slice('home_mode:'.length) : '';
      const mode = a.selected_option?.value;
      if (!registry.has(provider) || !isChannelMode(mode)) return;
      const channel = await verifiedHomeChannel(client, body);
      if (!channel) return staleChannelFeedback(client, identity);
      try {
        await contextFor(
          identity,
          channel,
          client,
          provisioningReceivedAt,
        ).setChannelMode(provider, mode);
      } catch (e) {
        // The home view has no inline-error surface; the re-publish below shows the real (unchanged)
        // state, and the reason goes to the actor as a DM. Denials were already audited inside.
        await dmActor(client, identity, safeUserMessage(e));
      }
      await publishHome(identity, client, channel);
    });

    // Enable/Disable → the SAME helper as `/vouchr enable|disable` (STR-3; a denial is audited
    // inside), then re-publish. The button value carries the TARGET state, never trusted for authz.
    app.action(HOME_TOOL_ACTION, async ({ ack, body, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      if (body.view?.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const m = /^(enable|disable):(.+)$/.exec(String(body.actions?.[0]?.value ?? ''));
      if (!m || !registry.has(m[2])) return; // SEC-4: registry-validate before anything is written
      const channel = await verifiedHomeChannel(client, body);
      if (!channel) return staleChannelFeedback(client, identity);
      try {
        if ((await setChannelToolEnabled(
          client,
          identity,
          channel,
          m[2],
          m[1] === 'enable',
          provisioningReceivedAt,
        )) === 'denied') {
          await dmActor(client, identity, adminOnly(allowChannelCreatorConfig, 'change channel tools'));
        }
      } catch (e) {
        // Ineligible channel class (SEC-3: forged payloads reach the same wall as slash) → the
        // core reason, as a DM; the re-publish shows the real (unchanged) state.
        await dmActor(client, identity, safeUserMessage(e));
      }
      await publishHome(identity, client, channel);
    });

    // Configure → the SAME gate + modal as `/vouchr configure` (STR-3). The modal's submit is the
    // existing CONFIGURE_CALLBACK flow, so the credential write path is untouched.
    app.action(HOME_CONFIGURE_ACTION, async ({ ack, body, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      if (body.view?.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const provider = body.actions?.[0]?.value;
      if (typeof provider !== 'string' || !registry.has(provider) || !body.trigger_id) return;
      const candidateChannel = homeSelectedChannel(body.view);
      try {
        const result = await openConfigureModal(
          client,
          identity,
          candidateChannel,
          provider,
          body.trigger_id,
          provisioningReceivedAt,
          () => verifiedHomeChannel(client, body),
        );
        if (result === 'denied') {
          await dmActor(client, identity, adminOnly(allowChannelCreatorConfig, 'configure channel credentials')); // denial audited inside
        }
        if (result === 'locked') await dmActor(client, identity, CREDENTIAL_SETUP_LOCKED);
        if (result === 'unsupported') await dmActor(client, identity, CHANNEL_CREDENTIAL_UNAVAILABLE);
      } catch (e) {
        await dmActor(client, identity, safeUserMessage(e)); // ineligible channel class → the core reason
      }
    });

    // Disconnect the acting user's own EXACT rendered connection generation from Vouchr-owned
    // config/Home views. The button carries only its opaque UUID; core resolves provider + ownership
    // server-side and repeats the generation check under the mutation locks. The exported
    // DISCONNECT_ACTION / disconnectConfirmBlocks provider-valued contract remains host-owned: Bolt
    // runs every matching listener, so acting on a foreign view/message here would double-fire a host
    // disconnect and clobber its view. When the callback stamp isn't ours we ack and defer.
    app.action(DISCONNECT_ACTION, async ({ ack, body, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      const surface = body.view?.callback_id === CONFIG_CALLBACK ? 'modal'
        : body.view?.callback_id === HOME_CALLBACK ? 'home' : null;
      if (!surface) return; // not our view → the host owns this action
      const identity = resolveIdentity({ body });
      const credentialId = body.actions?.[0]?.value;
      // Exported/custom configModal users retain the historical provider-valued action contract and
      // own its handler. Only an opaque Vouchr generation proves this listener owns the action; ack
      // and defer every other value so parallel Bolt listeners neither double-disconnect nor emit a
      // spurious stale receipt for a host control.
      if (!identity || !isInteractionId(credentialId)) return;
      let provider: string | undefined;
      let outcome: Awaited<ReturnType<typeof disconnectProvider>> | undefined;
      try {
        const resolved = await disconnectConnectionGeneration(
          vault,
          audit,
          registry,
          identity,
          credentialId,
          await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt),
        );
        if (resolved.status === 'stale') {
          await dmActor(
            client,
            identity,
            'That Disconnect button is no longer current. Review your current connections before trying again.',
          );
        } else {
          ({ provider, outcome } = resolved);
        }
      } catch (error) {
        await dmActor(
          client,
          identity,
          error instanceof InteractionStateChangedError
            ? safeUserMessage(error)
            : 'Could not confirm whether the account was disconnected. Run `/vouchr status` to check; if it is still listed, try again.',
        );
      }
      if (outcome && provider) {
        const p = escapeMrkdwn(provider);
        if (outcome.removed) emit({ type: 'revoked', provider, ok: outcome.ok });
        if (outcome.removed && !outcome.ok) {
          await dmActor(client, identity, `Disconnected *${p}* locally, but complete revocation could not be confirmed. Retry \`/vouchr disconnect ${p}\` to invalidate older setup requests, and revoke or rotate Vouchr’s access in ${p} directly if needed.`);
        } else if (outcome.removed && !outcome.audited) {
          await dmActor(client, identity, `Disconnected *${p}* locally, but Vouchr could not confirm the audit record. Ask an admin to check the Vouchr logs.`);
        } else if (outcome.removed) {
          // A modal/Home refresh is best effort and may fail after the destructive mutation has
          // committed. Always send one explicit receipt so a failed refresh never leaves the click
          // looking ignored (#194 UX-1/5).
          await dmActor(client, identity, `Disconnected *${p}*. The agent can no longer act as you on ${p}.`);
        } else if (!outcome.ok) {
          await dmActor(client, identity, `Could not confirm that older *${p}* setup requests were invalidated. Retry \`/vouchr disconnect ${p}\` before reconnecting.`);
        } else {
          // A duplicate click is still a valid interaction. It owns no mutation/event/audit, but it
          // must receive one idempotent receipt even if the subsequent view refresh also fails.
          await dmActor(client, identity, `No *${p}* account was connected, so there was nothing to disconnect.`);
        }
      }
      const channel = homeSelectedChannel(body.view);
      if (surface === 'home') return publishHome(identity, client, channel);
      await client.views.update({ view_id: body.view.id, view: await buildConfigModal(identity, channel, client) }).catch(() => undefined);
    });

    // Per-user key setup: an already-issued opaque prompt id → private modal (self-service, not
    // admin-gated). The click does not mint or extend authority; provider is reloaded from the exact
    // Slack-actor-bound row, and the same id is consumed only with the final credential write.
    app.action(SETUP_KEY_ACTION, async ({ ack, body, client }: any) => {
      await ack();
      const identity = resolveIdentity({ body });
      if (vault.lockdownEnabled) {
        if (identity) await dmActor(client, identity, CREDENTIAL_SETUP_LOCKED);
        return;
      }
      const requestId = body.actions?.[0]?.value;
      const staleText = 'This credential setup button is no longer valid. Ask the agent to request setup again.';
      const unconfirmedText = 'Vouchr could not confirm whether credential setup is available. Close this window and use the setup button again; if it keeps failing, ask the agent to request setup again.';
      const staleRecover = () => identity
        ? dmActor(client, identity, staleText)
        : Promise.resolve();
      if (!identity || !body.trigger_id || !isInteractionId(requestId)) return staleRecover();
      // Slack trigger_ids expire in roughly three seconds. Consume it before any database read with
      // a fixed, authority-free loading view; provider/request bindings are resolved server-side
      // afterward, then the same private view is hydrated. The loading view has no callback or
      // metadata, so a forged click gains no submit surface while validation is pending.
      let opened: any;
      try {
        opened = await client.views.open({
          trigger_id: body.trigger_id,
          view: privateStatusModal(
            'Credential setup',
            'Checking current access… If this does not finish, close this window and ask the agent to request setup again.',
          ),
        });
      } catch {
        return identity
          ? dmActor(
              client,
              identity,
              'Vouchr could not confirm whether credential setup opened. If a setup window appeared, follow it or close it; otherwise use the button again or ask the agent to request setup again.',
            )
          : undefined;
      }
      const loadingView = opened?.view;
      try {
        const provider = await provisioning.resolveForModal(requestId, identity);
        if (!provider || !registry.has(provider)) {
          return deliverModalOutcome(client, identity, loadingView, 'Setup unavailable', staleText);
        }
        const definition = registry.get(provider);
        if (!isBrokeredProvider(definition) || definition.credential !== 'key') {
          return deliverModalOutcome(client, identity, loadingView, 'Setup unavailable', staleText);
        }
        if (typeof loadingView?.id !== 'string') {
          return dmActor(client, identity, 'Vouchr could not finish opening credential setup. Use the setup button again.');
        }
        await client.views.update({
          view_id: loadingView.id,
          view: userKeyModal(provider, referenceSources, requestId),
        });
      } catch {
        await deliverModalOutcome(client, identity, loadingView, 'Setup not confirmed', unconfirmedText);
      }
    });

    // Compatibility for already-delivered #117 reconnect buttons. A health DM can outlive
    // offboarding, so its click must never mint fresh consent. Acknowledge it and replace/DM fixed
    // recovery; a current agent turn owns creation of the next offboard-fenced prompt.
    app.action(RECONNECT_ACTION, async ({ ack, body, respond, client }: any) => {
      await ack();
      const identity = resolveIdentity({ body });
      const text = 'This reconnect button is no longer valid. Ask the agent to reconnect.';
      if (respond) {
        try {
          await respond({ replace_original: true, text });
          return;
        } catch { /* fall through to the private DM receipt */ }
      }
      if (identity) await dmActor(client, identity, text);
    });

    // Thread-scoped session approval. The control contains one opaque request id; provider and every
    // binding come from PostgreSQL, while identity/channel/thread come from the Slack-signed click.
    // The provider lock is shared with mode and tool writers, so revalidation + consume + grant +
    // audit linearize before or after a concurrent governance change across replicas.
    app.action(APPROVE_SESSION_ACTION, async ({ ack, body, respond, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      const identity = resolveIdentity({ body });
      const location = interactionLocation(body);
      const id = body.actions?.[0]?.value;
      const reply = async (text: string, replaceOriginal = true) => {
        if (respond) {
          try {
            await respond({ replace_original: replaceOriginal, response_type: 'ephemeral', text });
            return;
          } catch { /* fall back to a private DM */ }
        }
        if (identity) await dmActor(client, identity, text);
      };
      const stale = 'This session request expired or was already completed. Ask the agent again in this thread.';
      if (!identity || !location?.thread || typeof id !== 'string') return reply(stale);

      const pending = await sessions.getRequest(id, identity, location.channel, location.thread);
      if (!pending) return reply(stale);
      let result: SessionGrantResult;
      try {
        const actorIssuedAt = await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt);
        result = await vault.withCredentialLocks(
          [
            { owner: channelOwner(identity.teamId, location.channel), provider: pending.provider },
            { owner: userOwner(identity), provider: pending.provider },
          ],
          async (locked, tx) => new SessionGrants(tx).grantRequested({
            id,
            identity,
            channel: location.channel,
            thread: location.thread!,
            ttlMs: sessionTtlMs,
            actorIssuedAt,
            audit,
            validate: async (row, decisionTx) => {
              if (!registry.has(row.provider) || !isBrokeredProvider(registry.get(row.provider))) return false;
              if ((await locked.liveId(userOwner(identity), row.provider)) !== row.credentialId) return false;
              const currentMode = await new ChannelConfig(decisionTx).getMode(
                row.teamId,
                row.channel,
                row.provider,
                decisionTx,
              );
              if (currentMode !== 'session') return false;
              return (await authorizeProvider(
                policy,
                new ChannelTools(decisionTx),
                identity,
                row.channel,
                row.provider,
              )) === null;
            },
          }),
        );
      } catch {
        return reply('Vouchr could not confirm the session. Try this button again.', false);
      }
      if (result.status === 'stale') return reply(stale);
      if (result.status === 'actor-stale') {
        return reply('Your authority changed while Vouchr was checking this session. Ask the agent again in this thread.', false);
      }
      if (result.status === 'invalidated') {
        return reply('This session request is no longer valid because provider or channel access changed. Ask the agent again in this thread.');
      }
      return reply(`Approved *${escapeMrkdwn(result.provider)}* for this thread. Ask the agent again.`);
    });

    // #113 Approve/Deny for a pending sensitive-write approval. The button value is ONLY the
    // pending-approval id — every field of an interaction payload is forgeable (SEC-3), so
    // authority is decided here, server-side, at the mutation: the provider is re-validated
    // against the registry (SEC-4), the approver RULE comes from the registry (never the payload
    // or the stored row), and the clicker's eligibility is re-checked — 'self' means exactly the
    // requester, 'admin' means the same adminEligible gate as every channel-config mutation. An
    // ineligible click is rejected AND audited 'denied'. Approve mints the single-use TTL grant;
    // Deny records the denial (approver in the actor column) and notifies the requester.
    const handleApprovalDecision = async ({ ack, body, respond, client }: any, decision: 'approve' | 'deny') => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      const identity = resolveIdentity({ body });
      const location = interactionLocation(body);
      const id = body.actions?.[0]?.value;
      const reply = async (text: string, replaceOriginal = true) => {
        if (respond) {
          try {
            await respond({ replace_original: replaceOriginal, response_type: 'ephemeral', text });
            return;
          } catch { /* fall back to a private DM */ }
        }
        if (identity) await dmActor(client, identity, text);
      };
      const stale = 'This approval expired or was already decided. Ask the agent again.';
      if (!identity || typeof id !== 'string') return reply(stale);
      const pending = await approvals.get(id);
      // Team + conversation binding: a control copied from another workspace/channel/thread cannot
      // decide the real row. Off-channel requests are delivered in the requester's DM and have no
      // stored channel/thread binding.
      if (
        !pending ||
        pending.teamId !== identity.teamId ||
        (pending.channel !== null && (
          !location ||
          location.channel !== pending.channel ||
          location.thread !== pending.thread
        ))
      ) {
        return reply(stale);
      }
      if (
        !registry.has(pending.provider) ||
        !isBrokeredProvider(registry.get(pending.provider)) ||
        !registry.get(pending.provider).approval ||
        !approvalNeeded(registry.get(pending.provider).approval!, pending.method, pending.path)
      ) {
        await approvals.discardPending(id).catch(() => undefined);
        return reply('This approval is no longer valid because provider access changed. Ask the agent again.');
      }
      const approval = registry.get(pending.provider).approval!;
      const p = escapeMrkdwn(pending.provider); // SEC-5, even for a registry-validated id
      // Raw query values are never stored or shown (GHSA-pg84: only their digest is); the receipt
      // marks that parameters are cryptographically bound with '?…'.
      // Requester notification: ephemeral in the request's channel, or a DM when there was none.
      const tellRequester = async (text: string) => {
        if (pending.channel) {
          await client.chat.postEphemeral({ channel: pending.channel, user: pending.userId, ...(pending.thread ? { thread_ts: pending.thread } : {}), text }).catch(() => undefined);
        } else {
          await client.chat.postMessage({ channel: pending.userId, text }).catch(() => undefined);
        }
      };
      const ttlMs = approval.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
      let decided: ApprovalDecisionResult;
      try {
        // Slack facts cannot be queried through PostgreSQL. Resolve them before taking lifecycle
        // locks, fail closed on any read error, then carry only the verdict into the row-locked
        // validation. A channel-owned approval is invalid if the channel class is no longer safe or
        // the original requester is no longer a member.
        let sharedOwnerFactsValid = true;
        if (pending.ownerKind === 'channel') {
          if (!pending.channel) sharedOwnerFactsValid = false;
          else {
            try {
              await assertChannelEligible(client, pending.channel);
            } catch {
              sharedOwnerFactsValid = false;
            }
            if (
              sharedOwnerFactsValid &&
              !(await boundedChannelMembership(
                client,
                pending.channel,
                pending.userId,
                opts.slackClientOptions,
              ))
            ) sharedOwnerFactsValid = false;
          }
        }
        const approverRule = approval.approver;
        const approverEligible = approverRule === 'admin'
          ? !!pending.channel && await commandAdmin(client, identity, pending.channel)
          : identity.userId === pending.userId;
        // Snapshot mode only to choose every possibly-relevant lock. The authoritative mode/owner/
        // policy/tool decision is reloaded after those canonical locks are held below.
        const mode = pending.channel
          ? await channelConfig.getMode(pending.teamId, pending.channel, pending.provider)
          : null;
        const owners = approvalDecisionLockOwners(pending, mode);
        const issuance = await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt);
        decided = await vault.withCredentialLocks(
          owners.map((owner) => ({ owner, provider: pending.provider })),
          async (locked, tx) => {
            const outcome = await new Approvals(tx).decideAudited({
              id,
              decision,
              approvedBy: identity.userId,
              actor: identity,
              issuance,
              ttlMs,
              audit,
              enterpriseId: identity.enterpriseId,
              validate: async (row, decisionTx) => {
                // Exact signed conversation binding is checked again while the pending row is
                // locked. It is immutable, but keeping it beside every other mutation-time fact
                // prevents a future row-shape change from weakening the boundary.
                if (
                  row.teamId !== identity.teamId ||
                  row.channel !== pending.channel ||
                  row.thread !== pending.thread ||
                  (row.channel !== null && (
                    !location || location.channel !== row.channel || location.thread !== row.thread
                  ))
                ) return 'ineligible';
                if (!registry.has(row.provider) || !isBrokeredProvider(registry.get(row.provider))) {
                  return 'invalidated';
                }
                const currentApproval = registry.get(row.provider).approval;
                if (!currentApproval || !approvalNeeded(currentApproval, row.method, row.path)) {
                  return 'invalidated';
                }
                if (currentApproval.approver !== approverRule) return 'invalidated';
                if (row.ownerKind === 'channel' && !sharedOwnerFactsValid) return 'invalidated';
                if (!(await approvalOwnerStillCurrent({
                  row,
                  db: decisionTx,
                  registry,
                  policy,
                  vault: locked,
                  enterpriseId: identity.enterpriseId,
                  actorIssuedAt: row.createdAt,
                }))) return 'invalidated';
                return approverEligible ? 'valid' : 'ineligible';
              },
            });
            if (outcome.status === 'ineligible') {
              await audit.record(
                'denied',
                identity,
                pending.provider,
                { reason: 'not-approver', ...(pending.channel ? { channel: pending.channel } : {}) },
                undefined,
                tx,
              );
            }
            return outcome;
          },
        );
      } catch {
        const verb = decision === 'approve' ? 'approval' : 'denial';
        return reply(`Vouchr could not confirm this ${verb}. Try this button again.`, false);
      }
      if (decided.status === 'stale') return reply(stale);
      if (decided.status === 'invalidated') {
        return reply('This approval is no longer valid because provider or channel access changed. Ask the agent again.');
      }
      if (decided.status === 'actor-stale') {
        return reply('Your authority changed while Vouchr was checking this approval. Reopen the current request before deciding it.', false);
      }
      if (decided.status === 'ineligible') {
        return reply('You are not eligible to decide this approval.', false);
      }
      if (decision === 'approve') {
        emit({ type: 'approval_approved', provider: pending.provider, host: pending.host });
        await reply(`✅ Approved the *${p}* action. The approval is single-use and expires in ${Math.round(ttlMs / 1000)}s — have the agent retry now.`);
        if (identity.userId !== pending.userId) {
          await tellRequester(`✅ <@${escapeMrkdwn(identity.userId)}> approved your *${p}* action — ask the agent to retry.`);
        }
      } else {
        emit({ type: 'approval_denied', provider: pending.provider, host: pending.host });
        await reply(`🚫 Denied the *${p}* action. Nothing was sent.`);
        if (identity.userId !== pending.userId) {
          await tellRequester(`🚫 <@${escapeMrkdwn(identity.userId)}> denied your *${p}* action. Nothing was sent.`);
        }
      }
    };
    app.action(APPROVAL_APPROVE_ACTION, (a: any) => handleApprovalDecision(a, 'approve'));
    app.action(APPROVAL_DENY_ACTION, (a: any) => handleApprovalDecision(a, 'deny'));

    // A pre-cutover ephemeral message can outlive the v7 process that created it. Ack its old
    // controls before doing anything else, then replace the private message with fixed guidance.
    // Never inspect/repost the old message body: v8 owns no preview data or share capability.
    const expireRetiredPreview = async ({ ack, respond }: any) => {
      await ack();
      if (respond) await respond({ replace_original: true, text: RETIRED_PREVIEW_MESSAGE });
    };
    for (const action of RETIRED_PREVIEW_ACTIONS) app.action(action, expireRetiredPreview);

  }

  /** Remove all of a user's own connections + pending consent + thread sessions (offboarding).
   *  offboardUser clears the session grants (passed through), so the Grid/SCIM path gets it too. */
  function offboard(identity: SlackIdentity): Promise<string[]> {
    return offboardUser(
      vault,
      audit,
      consent,
      identity,
      registry,
      'offboarded',
      sessions,
      provisioning,
      channelProvisioning,
      approvals,
    );
  }

  /**
   * Auto-offboard: subscribe to Slack's `user_change` event and, when an account is
   * deactivated (`deleted: true`), delete that user's connections. Requires the
   * `users:read` scope + the `user_change` event subscription on the Slack app.
   *
   * Scoping note: this offboards the `(team_id, user_id)` the event carries. On
   * Enterprise Grid a user may hold connections under several workspace team_ids;
   * org-wide deprovisioning should be wired through SCIM (which carries the proper
   * org/user context) to offboard per workspace. We intentionally do NOT delete by
   * user_id alone: Slack user ids are unique only within a workspace, so a bare
   * user_id delete could remove a different person's connection in another workspace.
   */
  function registerOffboarding(app: {
    event: (name: string, handler: (args: any) => Promise<void>) => void;
  }): void {
    app.event('user_change', async ({ event }: any) => {
      const u = event?.user;
      if (!u?.deleted || !u.team_id || !u.id) return; // only act on deactivation
      await offboard({
        enterpriseId: u.enterprise_user?.enterprise_id ?? null,
        teamId: u.team_id,
        userId: u.id,
      });
    });
  }

  /** Delete every connection past its TTL plus every stale interaction family through the one core
   *  lifecycle coordinator. Expired approvals are audited there (#113). Run on a timer. */
  async function sweep(): Promise<number> {
    return sweepLifecycle({ db, vault, audit, sink, health, dryRun });
  }

  /**
   * One-call wiring for the common case. Does everything a Bolt app needs in the right order:
   * the credential-injection middleware, the OAuth callback route, the `/vouchr` slash command, the
   * deactivation → offboard hook, and the hourly TTL sweep (once at startup, then on a timer). The
   * granular methods above remain for apps that need finer control. Returns `{ stop }` to clear the
   * sweep timer on shutdown. `sweepIntervalMs: 0` disables the timer (drive `sweepExpired()` yourself).
   */
  function install(
    app: {
      use: (m: typeof middleware) => void;
      command: (name: string, handler: (args: any) => Promise<void>) => void;
      view: (id: string, handler: (args: any) => Promise<void>) => void;
      action: (id: string, handler: (args: any) => Promise<void>) => void;
      event: (name: string, handler: (args: any) => Promise<void>) => void;
    },
    receiver: { router: any },
    opts: { sweepIntervalMs?: number } = {},
  ): { stop: () => Promise<void> } {
    app.use(middleware);
    mountRoutes(receiver.router);
    registerCommands(app);
    registerOffboarding(app);
    const intervalMs = opts.sweepIntervalMs ?? 60 * 60 * 1000;
    let timer: ReturnType<typeof setInterval> | undefined;
    if (intervalMs > 0) {
      void sweep().catch(() => undefined); // reclaim expired rows at startup; errors are non-fatal
      timer = setInterval(() => void sweep().catch(() => undefined), intervalMs);
      timer.unref(); // never keep the process alive for the sweep alone
    }
    // stop() tears down what install() started: the sweep timer, and (only if Vouchr opened it) the
    // db pool. An injected db is the caller's to close.
    return { stop: async () => { if (timer) clearInterval(timer); if (ownsDb) await db.close(); } };
  }

  /** Close the store pool if Vouchr opened it (a no-op for an injected db, which the caller owns).
   *  For hosts that wire the granular methods instead of install(); install().stop() calls this too. */
  async function close(): Promise<void> {
    if (ownsDb) await db.close();
  }

  return {
    install,
    close,
    middleware,
    mountRoutes,
    registerCommands,
    registerOffboarding,
    offboard,
    sweepExpired: sweep,
    vault,
    audit,
    db,
    /** #116 dry-run helpers (see VouchrOptions.dryRun); undefined unless `dryRun: true`. */
    dryRun: dryRun ? { completeConsent } : undefined,
  };
}

// Type `context.vouchr` for consumers so handlers can call it without `as any`.
declare module '@slack/bolt' {
  interface Context {
    vouchr: ConnectContext;
  }
}
