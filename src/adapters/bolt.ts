import { ErrorCode as SlackErrorCode, WebClient, type WebClientOptions } from '@slack/web-api';
import type { InstallationStore } from '@slack/bolt';
import {
  DB_CONNECTION_TIMEOUT_MS,
  DB_RUNTIME_QUERY_TIMEOUT_MS,
  openDb,
  type Db,
} from '../core/db';
import { loadKeyring, type EnvelopeProvider } from '../core/crypto';
import { ProviderRegistry, isBrokeredProvider, isValidProviderId, buildCallbackUrl, readOnlyEgress, DEFAULT_APPROVAL_TTL_MS, type ApprovalGrant, type Approver, type Provider } from '../core/providers';
import { CredentialLockdownError, Vault, type TtlPolicy } from '../core/vault';
import { Audit, type AuditSink } from '../core/audit';
import { Consent, browserHopUrls } from '../core/consent';
import { Policy } from '../core/policy';
import type { SlackIdentity } from '../core/identity';
import { resolveIdentity, isChannelMember } from './slack-identity';
import { BrowserIdentityVerifier, assertSlackOidcOptions, type SlackOidcOptions } from './slackVerify';
import { userOwner, channelOwner, type Owner } from '../core/owner';
import {
  authorizeProvider,
  governanceChannelOf,
  isGovernanceChannelScope,
  isSlackConversationType,
  PolicyDeniedError,
  resolveCredentialOwner,
  buildToolManifest,
  buildToolManifestSnapshot,
  ToolDisabledError,
} from '../core/authz';
import { ConnectionHandle, NoConnectionError, approvalNeeded, type Resolvers, type EventSink, type VouchrEvent } from '../core/injector';
import { MemoryRateLimitStore, RateLimitedError, type RateLimitStore } from '../core/rateLimit';
import { safeEmit } from '../core/safe-emit';
import { defineHidden, hideInternals } from '../core/redact';
import { ChannelConfig, channelIneligibleReason, isChannelIdentity, type ChannelInfo, type ChannelIdentity } from '../core/channelConfig';
import {
  configureChannelCredential,
  setChannelCredentialIdentity,
  disconnectChannelShared,
  type ChannelProvisioningIssuance,
} from '../core/channelCredential';
import { ChannelTools, configureChannelTools, type ToolManifestEntry } from '../core/tools';
import { handleOAuthCallback, OAUTH_CONNECTION_FAILED, type CallbackResult } from '../core/oauthCallback';
import {
  offboardUser,
  disconnectProvider,
  disconnectProviderAtReceipt,
  disconnectConnectionGeneration,
} from '../core/offboard';
import { assertDryRunFlag, assertDryRunLocalKey, assertDryRunVault, dryRunAudit, DRY_RUN_CODE } from '../core/dryRun';
import { booleanEnv, MAX_TIMER_MS } from '../core/options';
import { sweepLifecycle } from '../core/sweep';
import {
  InteractionStateChangedError,
  isInteractionId,
  PENDING_INTERACTION_TTL_US,
  PROMPT_DELIVERY_LEASE_US,
  WORKER_SESSION_IDLE_TTL_US,
} from '../core/interaction';
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
  approvalDeliveryAudienceKey,
  approvalDecisionLockOwners,
  approvalOwnerStillCurrent,
  credentialUseStateFenced,
  credentialUseStillCurrentFenced,
  type ApprovalDecisionResult,
  type ApprovalKey,
  approvalDecider,
  delegationOf,
  type Delegation,
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
  UserFacingError,
  isVouchrErrorCode,
  safeUserMessage,
  type ConsentPromptState,
  type VouchrErrorCode,
} from '../core/errors';
export {
  ConsentRequiredError,
  UserFacingError,
  safeUserMessage,
} from '../core/errors';
import { connectedHtml } from './landing';
import {
  connectBlocks, configureModal, CONFIGURE_CALLBACK,
  userKeyModal, keySetupBlocks, USER_KEY_CALLBACK, SETUP_KEY_ACTION, OAUTH_CONNECT_ACTION, RECONNECT_ACTION,
  OAUTH_RENEW_ACTION, connectExpiredBlocks, CONNECT_PROMPT_OPENING_TEXT, CONNECT_PROMPT_STALE_TEXT,
  privateStatusModal,
  auditBlocks, statsBlocks, statusBlocks,
  approvalBlocks, grantCovers, APPROVAL_APPROVE_ACTION, APPROVAL_DENY_ACTION,
  configModal, CONFIG_CALLBACK, DISCONNECT_ACTION,
  homeView, connectionLine, HOME_CALLBACK, HOME_CHANNEL_ACTION, HOME_IDENTITY_ACTION, HOME_TOOL_ACTION, HOME_CONFIGURE_ACTION,
  escapeMrkdwn, blocksFallbackText, connectedDmText, oauthRecoveryBlocks,
  type Connection, type ConfigMemberRow,
} from './blocks';

/** #296: how often `install()` delivers pending backchannel authorization prompts. Well inside the
 * 10-minute pending TTL; each pass is bounded and lease-deduplicated across replicas. */
const DEFAULT_AUTHORIZATION_DELIVERY_INTERVAL_MS = 15_000;
/** #296: rows one delivery pass may post. Bounds Slack work per interval; the rest wait a pass. */
const MAX_AUTHORIZATION_DELIVERIES_PER_PASS = 50;

/** Aggressive default per-user connection lifetime: idle 7d, hard cap 30d. */
const DEFAULT_TTL: TtlPolicy = { idleMs: 7 * 24 * 60 * 60 * 1000, maxAgeMs: 30 * 24 * 60 * 60 * 1000 };

/** Denial message for the channel-member gate (#322). Membership is read from Slack and fails
 * closed, so the next step covers the one honest false negative: Vouchr not being in the channel. */
const memberOnly = (action: string): string =>
  `Only a current member of this channel can ${action}. If you are one, make sure Vouchr is in the channel and try again.`;

interface ConfigOpenState {
  p: string;
  i: ChannelIdentity | 'service';
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
      !(entry.i === 'service' || isChannelIdentity(entry.i)) ||
      typeof entry.e !== 'boolean'
    ) return null;
    seen.add(entry.p);
  }
  return { channel: parsed.channel, open: parsed.open };
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
/** Leave most of Slack's short-lived trigger window for modal construction/open after classifying
 * an ambiguous G… conversation. Timeout/error stays governed (fail closed). */
export const SLACK_CONVERSATION_CLASSIFICATION_TIMEOUT_MS = 1_000;
export const SLACK_NOTIFICATION_CLIENT_CONCURRENCY = 16;
/** One complete, current channel-membership proof must resolve promptly before a governance write,
 * shared-credential use, or approval decision proceeds. This bounds roster pagination even for direct
 * test/custom clients that do not inherit WebClient's request timeout. */
export const CHANNEL_MEMBERSHIP_DEADLINE_MS = SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS;
/** Fail closed instead of retaining unbounded roster work for an exceptionally large or hostile
 * paginated response: a member beyond this scanned prefix is refused as a non-member. */
export const MAX_APPROVAL_AUDIENCE_MEMBERS = 5_000;
/** Bound empty/tiny pages with ever-changing cursors independently of the member-entry cap. */
export const MAX_CHANNEL_MEMBER_PAGES = 100;
const SLACK_NOTIFICATION_CLIENT_OPTIONS = Object.freeze({
  retryConfig: { retries: 0 },
  timeout: SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS,
  rejectRateLimitedCalls: true,
  // The SDK's request timeout starts only AFTER its internal p-queue. A lower operator-supplied
  // concurrency could therefore serialize one 16-wide wave beyond the delivery lease.
  maxRequestConcurrency: SLACK_NOTIFICATION_CLIENT_CONCURRENCY,
});
/** A custom installation store has no cancellation contract. Cap distinct unresolved workspace
 * lookups so a broken shared store cannot turn callback traffic into unbounded retained work. */
export const MAX_PENDING_NOTIFICATION_CLIENT_LOOKUPS = 32;

/** A bounded client for lease-guarded prompt posts and best-effort DMs. Preserves the operator's
 * transport (`base`: custom slackApiUrl, agent/proxy, tls, headers) so a deployment using a
 * non-default Slack endpoint is not bypassed; Vouchr's finite timeout, zero retries, and rate-limit
 * rejection are applied ON TOP and always win (spread last), so a slow post can never outlive its
 * delivery lease. */
function slackNotificationClient(
  token: string,
  base?: WebClientOptions,
  timeout = SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS,
): WebClient {
  return new WebClient(token, { ...base, ...SLACK_NOTIFICATION_CLIENT_OPTIONS, timeout });
}

function monotonicElapsedMs(startNs: bigint): number {
  return Number(process.hrtime.bigint() - startNs) / 1e6;
}

class MembershipResolutionError extends Error {}

/** Await one membership-resolution stage only through the shared monotonic overall deadline. The
 * underlying bounded WebClient call may finish later, but Promise.race owns its rejection and no
 * later result can mutate delivery state. */
async function withinMembershipDeadline<T>(
  work: Promise<T>,
  startedAtNs: bigint,
): Promise<T> {
  const remaining = CHANNEL_MEMBERSHIP_DEADLINE_MS - monotonicElapsedMs(startedAtNs);
  if (remaining <= 0) throw new MembershipResolutionError('channel membership deadline elapsed');
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new MembershipResolutionError('channel membership deadline elapsed')),
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

/** Fail-closed channel-membership proof under one finite cursor/member/deadline contract. This
 * covers every governance write, shared-credential use, and interaction revalidation,
 * including custom clients whose pagination is malformed or whose request never settles. */
async function boundedChannelMembership(
  client: WebClient,
  channel: string,
  userId: string,
  clientOptions?: WebClientOptions,
): Promise<boolean> {
  const startedAtNs = process.hrtime.bigint();
  const withinDeadline = (): boolean => (
    monotonicElapsedMs(startedAtNs) < CHANNEL_MEMBERSHIP_DEADLINE_MS
  );
  try {
    const token = (client as { token?: unknown }).token;
    const memberClient = typeof token === 'string' && token.length > 0
      ? slackNotificationClient(token, clientOptions)
      : client;
    return await withinMembershipDeadline(
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

/** Reserve one bounded Slack post, the runtime pool wait + query timeout, and event-loop margin
 * before the 30s lease. The timer begins BEFORE claimDelivery, conservatively including its round
 * trip, so even a late-wave first success starts confirmation with the supported database budget. */
export const APPROVAL_DELIVERY_SAFETY_MARGIN_MS = 1_000;
export const APPROVAL_PROMPT_POST_DEADLINE_MS = PROMPT_DELIVERY_LEASE_US / 1_000
  - SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS
  - DB_CONNECTION_TIMEOUT_MS
  - DB_RUNTIME_QUERY_TIMEOUT_MS
  - APPROVAL_DELIVERY_SAFETY_MARGIN_MS;

function boundedNotificationResolution<T>(
  work: Promise<T>,
  timeoutMs = SLACK_NOTIFICATION_RESOLUTION_TIMEOUT_MS,
): Promise<T | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: T | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    timer.unref();
    void work.then((value) => finish(value), () => finish(null));
  });
}

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
  surface: 'approval' | 'private connection',
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

/** Preserve one classified outcome of a Slack prompt post without retaining/rendering any foreign
 * Slack error content. An ambiguous send is never treated as a definite rejection because Slack may
 * have accepted that request before the transport failed locally. */
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

function isApprovalPromptNotStarted(error: unknown): boolean {
  try {
    return error instanceof ApprovalPromptNotStartedError;
  } catch {
    return false;
  }
}

function slackPromptDeliveryRecovery(
  outcome: SlackPromptDeliveryFailure,
  surface: 'approval' | 'connection' | 'configuration',
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
  surface: 'approval' | 'connection',
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
 * authority on their own: core compares them with the persisted request before mutation. Do not
 * fall back to the decision prompt's message_ts here: that timestamp is the prompt Slack rendered,
 * not necessarily the originating thread stored on the approval row. */
function interactionLocation(body: any): { channel: string; thread: string | null } | null {
  const channel = body?.channel?.id ?? body?.container?.channel_id;
  const thread = body?.container?.thread_ts ?? body?.message?.thread_ts ?? null;
  if (typeof channel !== 'string' || channel.length < 1 || channel.length > 255) return null;
  if (thread !== null && (typeof thread !== 'string' || thread.length < 1 || thread.length > 255)) return null;
  return { channel, thread };
}

/** The `/vouchr disconnect` and Disconnect-button receipt (UX-3): what committed, what could not be
 *  confirmed, and what to do next. `p` is the already-escaped provider id (SEC-5); `nothingText` is
 *  each surface's own no-op copy (UX-2). */
function disconnectReceipt(
  p: string,
  o: Awaited<ReturnType<typeof disconnectProvider>>,
  nothingText: string,
): string {
  if (o.removed && !o.ok) return `Disconnected *${p}* locally, but complete revocation could not be confirmed. Retry \`/vouchr disconnect ${p}\` to invalidate older setup requests, and revoke or rotate Vouchr’s access in ${p} directly if needed.`;
  if (o.removed && !o.audited) return `Disconnected *${p}* locally, but Vouchr could not confirm the audit record. Ask an admin to check the Vouchr logs.`;
  if (o.removed) return `Disconnected *${p}*. The agent can no longer act as you on ${p}.`;
  if (!o.ok) return `Could not confirm that older *${p}* setup requests were invalidated. Retry \`/vouchr disconnect ${p}\` before reconnecting.`;
  return nothingText;
}

/**
 * The adapter half of invariant 6, ONE implementation for every mutation path: fetch the channel
 * class (null on any error → fails closed) and apply the core rule (channelIneligibleReason), so a
 * packaged broker + thin clients enforce the same rule rather than re-implementing it. Throws a
 * UserFacingError naming the reason, no audit row, exactly like ConnectContext.setChannelIdentity's
 * eligibility refusal (the audit-on-denial convention is for authz denials, reason 'not-member').
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

/** Resolve the one ambiguous Slack id class (G… can be a private channel or MPIM) from Slack's
 * authenticated API. This is the trusted mutable-governance classifier for command/action contexts;
 * every error fails closed as governed. Shared mutations still run the stricter
 * channelIneligibleReason check at their core mutation boundary. */
async function governanceChannelForCommand(
  client: WebClient,
  channel: string,
  clientOptions?: WebClientOptions,
): Promise<string | null> {
  const inferred = governanceChannelOf(channel);
  if (inferred === null || !channel.startsWith('G')) return inferred;
  try {
    const token = (client as { token?: unknown }).token;
    const lookupClient = typeof token === 'string' && token.length > 0
      ? slackNotificationClient(token, clientOptions, SLACK_CONVERSATION_CLASSIFICATION_TIMEOUT_MS)
      : client;
    const result = await boundedNotificationResolution(
      Promise.resolve(lookupClient.conversations.info({ channel })),
      SLACK_CONVERSATION_CLASSIFICATION_TIMEOUT_MS,
    );
    const info = (result as any)?.channel;
    return governanceChannelOf(channel, info?.is_mpim === true ? 'mpim' : undefined);
  } catch {
    return channel;
  }
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
   * `botToken`. Wire the SAME store into Bolt's OAuth `installationStore`. The built-in
   * `DbInstallationStore` honors `VOUCHR_LOCKDOWN` itself; a custom store wired into Bolt's receiver
   * must enforce the same external gate. Vouchr never queries this store while its own lockdown is
   * active.
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
   * When true, using a SHARED channel credential (`connectChannel`) requires the ACTING user to be
   * a member of the channel; a non-member (or a membership check we can't verify) is refused
   * fail-closed and audited 'denied' with reason 'not-member'. Default false: membership is not
   * checked, behaving exactly as before.
   */
  requireChannelMembership?: boolean;
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
   * When omitted, the DEFAULT wiring DMs the credential owner (the last configuring member for a
   * channel-owned credential), with ask-the-agent-again guidance on `refresh_dead`, debounced to one DM per
   * (owner, provider, type) per 24h via the persistent `notification_state` table. Setting this
   * REPLACES the default DMs — debounce with the exported
   * `NotificationState` if your notifier needs it. Note the hook is wired while createVouchr is
   * still constructing (no `db` in hand yet), so an override must LATE-BIND its debounce store:
   * construct `new NotificationState(vouchr.db)` after createVouchr returns (or from your own
   * openDb handle) and reference it from inside the hook. Fire-and-forget; a throwing hook never
   * affects a request or the sweep.
   */
  onCredentialHealth?: CredentialHealthHook;
  /**
   * #116 dry-run: run the REAL consent state machine, channel identities, policy, tool allowlists,
   * egress gates, vault, and audit — under the invariant that NO real network call leaves the
   * process. The OAuth exchange yields a synthetic credential (marked `external_account:
   * 'dry-run'`; the Connect button's authorize URL becomes a local, instantly-succeeding redirect
   * into the real callback); `handle.fetch()` returns a `200 { dryRun, method, url, wouldInjectAs }`
   * echo instead of calling the provider — AFTER every request gate has run and the (synthetic)
   * credential was read from the vault; token refresh and upstream revoke are likewise skipped for
   * dry-run rows. The credential never appears in the echo. Request-side denials throw exactly as
   * in production. Safety rails: startup hard-fails if the database already holds non-dry-run
   * credential rows, a request refuses (and the dry-run callback never overwrites) a real row
   * written later, and every audit row written in dry-run carries `meta.dry_run: true`. The
   * returned `vouchr.dryRun` object exposes two test helpers: `enableTool(member, channel,
   * providerId)` opts a provider into a channel's allowlist (channels are DENY-BY-DEFAULT, so you
   * MUST call this before `connect()` will resolve that provider in a channel — it reproduces an
   * member's `/vouchr enable`; DMs are ungoverned and need no enable), and `completeConsent(user,
   * provider)` finishes a prompted consent programmatically. Default false: zero behavior change.
   */
  dryRun?: boolean;
  /**
   * Allow non-GET/HEAD provider requests through `handle.fetch()`. Default **true**, which is this
   * path's long-standing behaviour: acting as the asking user — opening the PR, filing the ticket —
   * is the point of the Bolt surface, and `provider.approval` (on by default) is how a write is gated.
   *
   * Set it to **false** to force every provider read-only: each one's methods are INTERSECTED with
   * GET/HEAD, so even a provider that declares writes of its own — `databricks()` declares
   * `['GET','POST']` — loses them, and a prompt-injected `handle.fetch(url, { method: 'DELETE' })`
   * is refused before the credential is read. Recommended for read-only agents.
   *
   * NOTE the asymmetry with `createBroker`, which defaults writes OFF: the broker serves remote
   * workers over HTTP and rejects non-GET/HEAD at the route before identity or vault access, whereas
   * this path runs the host's own in-process handler. The same prompt injection therefore reaches
   * further here than through the broker unless you set this false or declare `egressMethods` on the
   * provider. See guides/THREAT-MODEL.md, "Write blast radius differs by transport".
   */
  allowWrites?: boolean;
  /**
   * #302: Slack app OIDC credentials (the same Slack app that owns the bot). Required: every Connect
   * prompt points at a Vouchr verify route (mounted beside `callbackPath`) that routes the browser
   * through Slack sign-in before revealing the provider authorize URL, and the callback refuses any
   * consent the hop never stamped — the "Forwarded consent link" hand-off in guides/THREAT-MODEL.md.
   * Falls back to `VOUCHR_SLACK_CLIENT_ID` / `VOUCHR_SLACK_CLIENT_SECRET`; startup fails closed
   * without them. The Slack app must list the `…/slack` route beside `callbackPath` as an OAuth
   * redirect URL (see guides/DEPLOYMENT.md).
   */
  slackOidc?: SlackOidcOptions;
}

/**
 * Deps/options for {@link ConnectContext}. A single named-field object instead of a ~20-arg
 * positional list: adjacent same-typed args (e.g. two `string | null`s, several optional stores)
 * can no longer be silently mis-ordered past the type-checker. Optional fields keep their old
 * defaults (see the constructor).
 */
export interface ConnectContextDeps {
  identity: SlackIdentity;
  /** The conversation this request is delivered in — where prompts/DMs are posted. */
  channel: string | null;
  /** The channel scope that channel GOVERNANCE (tool allowlist + identity) applies to. Null for a
   *  personal conversation (DM/group-DM) that no channel governs, so credential use there is
   *  never gated by the channel allowlist — exactly like a channel-less context. When OMITTED it is
   *  derived from `channel` via `governanceChannelOf` (a 1:1 DM id `D…` maps to null); a caller that
   *  can classify a group DM (it has the Slack `channel_type`) passes the exact value. Delivery still
   *  uses `channel`, and static Policy still evaluates against `channel`. */
  governableChannel?: string | null;
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
  /** Governance: when true, connectChannel requires the acting user to be a channel member. */
  requireMembership?: boolean;
  /** The Slack thread (thread_ts) this request is in; a `thread` grant binds to it. Null off-thread. */
  thread?: string | null;
  /** Where this request's PRIVATE prompts (ephemerals) are placed: the thread the request was asked
   *  from, or null for a top-level message. An ephemeral is not a reply, so one posted under a root
   *  with no replies shows no indicator and is never seen; the middleware therefore sets this only
   *  when the triggering message itself sits inside an existing thread. Defaults to `thread`. */
  replyThread?: string | null;
  /** #113 human-in-the-loop approval store (provider.approval). Absent + a provider whose approval
   *  is not `false` = the injector fails closed (an approval rule is never silently skipped). */
  approvals?: Approvals;
  /** Optional audit stream sink (raw actor id). Default no-op; the audit table stays authoritative. */
  auditSink?: AuditSink;
  /** #117 credential-health hook threaded to every ConnectionHandle (see VouchrOptions). Default no-op. */
  health?: CredentialHealthHook;
  /** Cross-replica notification debounce for the #117 health DMs. */
  notifications?: NotificationState;
  /** #116 dry-run: threaded to every ConnectionHandle so the final outbound call is stubbed (see
   *  VouchrOptions.dryRun). Default false: unchanged behavior. */
  dryRun?: boolean;
  /** Permit non-GET/HEAD provider requests (see VouchrOptions.allowWrites). Default TRUE: this
   *  path's existing behaviour. False pins providers that declare no egressMethods to GET/HEAD. */
  allowWrites?: boolean;
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
  approver: Approver;
  method: string;
  host: string;
  path: string;
  approvalId: string;
  grant: ApprovalGrant;
  /** True only for the creator of the deduplicated pending row: an abandoned known-undelivered
   * prompt then removes the row. False (a reused id, or a broker-minted row the bridge delivers)
   * only releases the delivery lease so a later attempt can post. */
  newRequest: boolean;
  thread: string | null;
  /** The agent's reason and link as stored on the row (#350); null when it gave none. */
  reason: string | null;
  link: string | null;
  /** Who receives a private ('self') prompt: the requester, or the bound member for a worker's
   * request in their thread session (#360). */
  decider: string;
  /** #360 how the request is delegated (see delegationOf); 'none' for an ordinary request. */
  delegated: Delegation;
};

/**
 * Typed outcome of {@link ConnectContext.recoverBrokerDenial}: which private Slack recovery action
 * the trusted control plane took for a relayed broker denial. Hosts branch on `status`; the worker
 * retries a brokered call only after the human acts, and always with a freshly minted single-use
 * identity assertion.
 *
 * - `resolved` — current verified state no longer produces that denial (stale relay, identity
 *   change, or the approval rule no longer applies). This is not replay authority: stop this turn
 *   and let a new user-triggered turn repeat preflight and mint a fresh single-use assertion.
 * - `connect_prompted` — the private connect/key-setup flow posted (or reused) its prompt; stop
 *   this turn (`promptState` mirrors ConsentRequiredError).
 * - `approval_prompted` — the Approve/Deny decision surface is live (`approver` says whose).
 * - `configuration_required` — shared-owner credential is missing; the asking member was directed
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
  | { status: 'approval_prompted'; provider: string; approver: Approver }
  | { status: 'configuration_required'; provider: string }
  | { status: 'stale'; provider: string }
  /** A denial with no button: the user was told privately that a human must act. */
  | { status: 'notified'; provider: string; code: VouchrErrorCode }
  | { status: 'not_bridgeable' };

/**
 * Relayed denial codes that carry user-actionable copy but no decision surface. Mapping to the TYPED
 * error (rather than reusing the relayed message) means the hybrid path and the Bolt path render the
 * identical sentence from `mapSafeError`, and no broker-supplied text is ever echoed into Slack.
 *
 * Deliberately excluded: egress/response blocks and resolver/token failures (operator configuration,
 * not something the asking human can act on) and rate limiting (already surfaced by the Bolt path's
 * own ephemeral, and its retry hint would have to come from the wire).
 */
export const BRIDGEABLE_NOTICES: Partial<Record<VouchrErrorCode, () => Error>> = Object.assign(
  Object.create(null) as Partial<Record<VouchrErrorCode, () => Error>>,
  {
    tool_disabled: () => new ToolDisabledError(),
    policy_denied: () => new PolicyDeniedError(),
  },
);

/**
 * Every remaining code, and why it is NOT bridged. Exported so a test can assert the two sets
 * partition VOUCHR_ERROR_CODES exactly (REV-2): adding a code to core then fails the suite until
 * someone decides which side it belongs on, instead of silently not being bridged — which is the
 * very silence this bridge exists to remove.
 */
export const DELIBERATELY_UNBRIDGED: readonly VouchrErrorCode[] = Object.freeze([
  // Consent-shaped: handled earlier in recoverBrokerDenial with a real decision surface.
  'consent_required', 'not_connected', 'approval_required',
  // Operator configuration, not something the asking human can act on.
  'egress_blocked', 'response_blocked', 'invalid_reference', 'invalid_scopes',
  'resolver_configuration_error', 'resolver_failed', 'approval_path_too_large',
  'resolver_unavailable',
  // Transient/infrastructural: the host's safeText path already reports these.
  'token_endpoint_failed', 'upstream_timeout', 'overloaded', 'rate_limited',
  'internal_error', 'interaction_state_changed',
  // Identity/assertion problems on the broker door: the worker's, not the human's, to fix (#348
  // added the perimeter codes; the worker mints a fresh assertion or fixes its request).
  'source_mismatch', 'unauthorized', 'invalid_identity', 'identity_replayed', 'request_too_large',
  'not_found',
  // Containment (#239): the control plane shares the deployment flag and refuses to post prompts.
  'locked_down',
  // Host-authored copy; Vouchr has no fixed sentence to show.
  'user_facing',
] as VouchrErrorCode[]);

// Bolt owns the trusted event-receipt instant. Keep the override module-private so neither a
// caller nor any forgeable Slack field can choose a newer provisioning issuance. Normal direct
// construction falls back to the constructor's own monotonic instant.
const INTERNAL_PROVISIONING_RECEIVED_AT = Symbol('vouchr.provisioning-received-at');
const INTERNAL_CHANNEL_PROVISIONING_ISSUANCE = Symbol('vouchr.channel-provisioning-issuance');
const INTERNAL_GOVERNANCE_CHANNEL_RESOLVER = Symbol('vouchr.governance-channel-resolver');
const INTERNAL_POSTED_APPROVAL_PROMPTS = Symbol('vouchr.posted-approval-prompts');

/** Fixed reply for a click on a prompt whose pending row is gone; also what the sweep writes over an
 *  unclicked prompt's buttons (#348). One constant, both surfaces. */
const APPROVAL_STALE_TEXT = 'This approval expired or was already decided. Ask the agent again.';
/** Whole minutes of the pending-request and worker-session lifetimes, for click receipts (#360). */
const PENDING_APPROVAL_MINUTES = Math.round(PENDING_INTERACTION_TTL_US / 60_000_000);
const WORKER_SESSION_IDLE_MINUTES = Math.round(WORKER_SESSION_IDLE_TTL_US / 60_000_000);

/** Approve/Deny messages this process posted and can still edit: `chat.update` needs the channel and
 *  ts, and no approval_request column stores them (#348). Best-effort by design: a restart or another
 *  replica's sweep loses the entry, and the untouched buttons then answer APPROVAL_STALE_TEXT on
 *  click. Bounded; an in-channel 'self' prompt is an ephemeral and cannot be updated, so it is never
 *  remembered. */
const MAX_POSTED_APPROVAL_PROMPTS = 256;
class PostedApprovalPrompts {
  private readonly entries = new Map<string, { client: WebClient; channel: string; ts: string }>();

  remember(id: string, client: WebClient, posted: { channel?: unknown; ts?: unknown }): void {
    if (typeof posted.channel !== 'string' || typeof posted.ts !== 'string') return;
    if (this.entries.size >= MAX_POSTED_APPROVAL_PROMPTS) {
      this.entries.delete(this.entries.keys().next().value as string);
    }
    this.entries.set(id, { client, channel: posted.channel, ts: posted.ts });
  }

  /** A decision replaced the message through its response_url; the sweep must not overwrite it. */
  forget(id: string): void {
    this.entries.delete(id);
  }

  /** Strip the buttons from every prompt whose pending row is gone (expired, decided on another
   *  replica, or removed by offboarding). Slack failures are swallowed: the row is already gone. */
  async expire(stillPending: (id: string) => Promise<boolean>): Promise<void> {
    for (const [id, p] of this.entries) {
      if (await stillPending(id)) continue;
      this.entries.delete(id);
      await p.client.chat.update({ channel: p.channel, ts: p.ts, text: APPROVAL_STALE_TEXT, blocks: [] })
        .catch(() => undefined);
    }
  }
}

type InternalConnectContextDeps = ConnectContextDeps & {
  /** REQUIRED here, though optional on the public `ConnectContextDeps`. `allowWrites` is a security
   *  gate whose default is permissive, so a construction site that omits it fails OPEN silently —
   *  which is exactly what happened once: it was wired into `contextFor()` but not into the
   *  middleware's `contextDeps`, making `createVouchr({ allowWrites: false })` a no-op on the only
   *  path that calls `handle.fetch`. Requiring it here makes a missed site a compile error (REV-2). */
  allowWrites: boolean;
  [INTERNAL_PROVISIONING_RECEIVED_AT]?: bigint;
  [INTERNAL_CHANNEL_PROVISIONING_ISSUANCE]?: ChannelProvisioningIssuance;
  [INTERNAL_GOVERNANCE_CHANNEL_RESOLVER]?: () => Promise<string | null>;
  [INTERNAL_POSTED_APPROVAL_PROMPTS]?: PostedApprovalPrompts;
};

/** Map a verified handler's monotonic receipt instant into PostgreSQL's clock domain. Query latency
 * is included in the subtraction and fractional microseconds round up (the nanosecond monotonic
 * receipt keeps sub-millisecond precision), so uncertainty can only make the issuance older (fail
 * closed) — by at least 1µs — never newer than the received interaction. */
async function provisioningIssuedAtFromReceipt(vault: Vault, receivedAt: bigint): Promise<number> {
  const pgNow = await vault.userProvisioningIssuedAt();
  const elapsedNs = process.hrtime.bigint() - receivedAt;
  if (elapsedNs < 0n) throw new Error('invalid provisioning receipt clock');
  const elapsedUs = Number((elapsedNs + 999n) / 1_000n);
  const issuedAt = pgNow - elapsedUs;
  if (!Number.isSafeInteger(issuedAt)) throw new Error('could not issue provisioning fence');
  return issuedAt;
}

type ConnectPrompt = { blocks: unknown[]; fallback: { text: string } | Record<string, never> };

/**
 * Mint (or reuse) the acting user's consent generation for one OAuth provider and deliver its
 * private Connect prompt under the cross-replica delivery lease. Resolves only after a confirmed
 * post; every other outcome throws the fixed user-facing recovery (a still-delivered generation
 * throws `ConsentRequiredError('reused')`). ONE sequence for the agent turn and the "Send a new
 * link" button (#347), so the two surfaces cannot drift on lease handling.
 */
async function deliverConnectPrompt(o: {
  consent: Consent;
  identity: SlackIdentity;
  provider: Provider;
  redirectUri: string;
  channel: string | null;
  issuedAt: number;
  post: (prompt: ConnectPrompt) => Promise<void>;
}): Promise<void> {
  const pendingConsent = await o.consent.beginFenced(
    o.identity,
    o.provider,
    o.redirectUri,
    o.channel,
    o.issuedAt,
  );
  if (!pendingConsent) {
    throw new UserFacingError(
      'Connection setup changed while Vouchr was preparing it. Ask the agent again.',
      'resolve_again',
    );
  }
  // Render before claiming delivery. A local registry/render failure is a known no-send and must
  // not park this reusable consent generation behind an ambiguous Slack lease.
  const blocks = connectBlocks(
    o.provider.id,
    pendingConsent.authorizeUrl,
    { list: o.provider.scopesDefault, describe: o.provider.scopeDescriptions },
    pendingConsent.state,
  );
  const prompt: ConnectPrompt = { blocks, fallback: optionalBlockFallback(blocks) };
  const delivery = await o.consent.claimDelivery(pendingConsent.state, {
    redeliverDelivered: !!o.channel,
  });
  if (delivery.status !== 'claimed') {
    // 'delivered' reuses the live prompt instead of re-posting — but an in-channel prompt is an
    // ephemeral, which vanishes on reload/device switch. The typed 'reused' state drives fixed
    // copy (here and in the safe mapper) instead of claiming a fresh post.
    if (delivery.status === 'delivered') throw new ConsentRequiredError(o.provider.id, 'reused');
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
    await o.post(prompt);
  } catch (deliveryError) {
    const outcome = classifySlackPromptDeliveryFailure(deliveryError);
    if (outcome !== 'ambiguous') {
      await abandonKnownUndeliveredPrompt(
        () => o.consent.abandonDelivery(pendingConsent.state, delivery.token),
        'connection',
      );
    }
    throw slackPromptDeliveryRecovery(outcome, 'connection');
  }
  requirePromptConfirmation(
    await promptConfirmationOutcome(
      () => o.consent.confirmDelivery(pendingConsent.state, delivery.token),
    ),
    'private connection',
  );
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
  /** Channel scope for governance (allowlist + identity); null in a DM/group-DM. See ConnectContextDeps. */
  private governableChannel: string | null;
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
  private requireMembership: boolean;
  private thread: string | null;
  private replyThread: string | null;
  private approvals: Approvals | null;
  private auditSink: AuditSink;
  private health: CredentialHealthHook;
  private notifications: NotificationState | null;
  private dryRun: boolean;
  private allowWrites: boolean;
  private slackClientOptions?: WebClientOptions;
  private provisioningReceivedAt: bigint;
  private channelProvisioningIssuance?: ChannelProvisioningIssuance;
  /** Bolt commands/actions omit `channel_type`; classify an ambiguous G… id only when the host
   * first uses Vouchr, so global middleware never delays the host's acknowledgement path. */
  private governanceChannelResolver?: () => Promise<string | null>;
  private governanceChannelResolution?: Promise<string | null>;
  private postedApprovalPrompts?: PostedApprovalPrompts;

  constructor(deps: ConnectContextDeps) {
    this.identity = deps.identity;
    this.channel = deps.channel;
    // Omitted → derive from the delivery channel (a 1:1 DM `D…` maps to null/ungoverned via the same
    // id heuristic the middleware and broker use); explicit value (incl. null) is honored as given.
    // Fixes a directly-constructed context for a DM channel being treated as governed (so `/vouchr
    // tools` in a DM reported providers disabled). A group DM still needs an explicit null.
    this.governableChannel = deps.governableChannel === undefined
      ? governanceChannelOf(deps.channel)
      : deps.governableChannel;
    if (!isGovernanceChannelScope(deps.channel, this.governableChannel)) {
      throw new Error('ConnectContext governance scope does not match its delivery channel');
    }
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
    this.requireMembership = deps.requireMembership ?? false;
    this.thread = deps.thread ?? null;
    this.replyThread = deps.replyThread === undefined ? this.thread : deps.replyThread;
    this.approvals = deps.approvals ?? null;
    this.auditSink = deps.auditSink ?? (() => {});
    this.health = deps.health ?? (() => {});
    this.notifications = deps.notifications ?? null;
    this.dryRun = deps.dryRun ?? false;
    this.allowWrites = deps.allowWrites ?? true;
    this.slackClientOptions = deps.slackClientOptions;
    this.provisioningReceivedAt =
      (deps as InternalConnectContextDeps)[INTERNAL_PROVISIONING_RECEIVED_AT]
      ?? process.hrtime.bigint();
    this.channelProvisioningIssuance =
      (deps as InternalConnectContextDeps)[INTERNAL_CHANNEL_PROVISIONING_ISSUANCE];
    this.governanceChannelResolver =
      (deps as InternalConnectContextDeps)[INTERNAL_GOVERNANCE_CHANNEL_RESOLVER];
    this.postedApprovalPrompts = (deps as InternalConnectContextDeps)[INTERNAL_POSTED_APPROVAL_PROMPTS];
    // Declared-but-unassigned would be created enumerable on first write, escaping hideInternals.
    this.governanceChannelResolution = undefined;
    // SEC-1: this object is attached to Bolt's per-request `context.vouchr` — the thing a handler
    // is most likely to dump on error. The `private` modifiers above are erased at runtime; without
    // this, JSON.stringify/spread/a structured logger walks client → Slack bot token, vault →
    // master key, registry → OAuth client secrets, and db → connection password.
    // Regression: test/no-secret-serialization.test.ts.
    hideInternals(this);
  }

  /** Resolve Slack's ambiguous G… id class once. A transport/API failure retains the initial
   * governed scope (fail closed); an invalid resolver result can never widen authority. */
  private currentGovernanceChannel(): Promise<string | null> {
    if (!this.governanceChannelResolver) return Promise.resolve(this.governableChannel);
    this.governanceChannelResolution ??= (async () => {
      let resolved = this.governableChannel;
      try {
        const candidate = await this.governanceChannelResolver!();
        if (isGovernanceChannelScope(this.channel, candidate)) resolved = candidate;
      } catch {
        // Keep the constructor's governed G… classification when Slack cannot classify it.
      }
      this.governableChannel = resolved;
      this.governanceChannelResolver = undefined;
      return resolved;
    })();
    return this.governanceChannelResolution;
  }

  /** Map this verified request's monotonic receipt instant into PostgreSQL's clock domain. Query
   * latency is included in the elapsed subtraction and fractional microseconds round up, so clock
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
    // defineHidden, not assignment: a plain `handle.fetch = …` shadows the prototype method with an
    // own ENUMERABLE property, undoing hideInternals for this key (SEC-1).
    defineHidden(handle, 'fetch', async (input: string, init: RequestInit = {}) => {
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
    });
    return handle;
  }

  /**
   * Slack surface for the #113 approval gate (mirrors notifyRateLimited's wrapper shape): when a
   * fetch throws ApprovalRequiredError, post the Approve/Deny prompt — ephemerally to the acting
   * user for approver 'self', as one channel message for 'member' (#322) — then rethrow, so
   * the typed error still reaches the caller (catch-and-stop-turn, exactly like
   * ConsentRequiredError). If no actionable decision surface is delivered, remove only the id this
   * fetch minted and throw fixed retry guidance instead of falsely claiming a prompt was posted.
   * The blocks show requester, provider, method, path, reason, and link; the query string and body
   * never reach Slack (SEC-1). Buttons carry only the pending id (SEC-3: authority is re-decided at
   * click).
   */
  private notifyApprovalRequired(handle: ConnectionHandle): ConnectionHandle {
    const fetch = handle.fetch.bind(handle);
    // See notifyRateLimited: assignment would re-expose this key to enumeration.
    defineHidden(handle, 'fetch', async (input: string, init: RequestInit = {}) => {
      try {
        return await fetch(input, init);
      } catch (e) {
        if (e instanceof ApprovalRequiredError) {
          await this.deliverApprovalPrompt({
            provider: e.provider,
            approver: e.approver,
            method: e.method,
            host: e.host,
            path: e.path,
            approvalId: e.approvalId,
            grant: e.grant,
            newRequest: e.newRequest,
            thread: this.thread,
            reason: e.reason,
            link: e.link,
            decider: this.identity.userId,
            delegated: 'none',
          });
        }
        throw e;
      }
    });
    return handle;
  }

  /** The current approval rule for a provider whose request needed one. The rule is read from the
   * registry at render time (never the row or the wire) so the prompt states the lifetime the click
   * will actually grant. */
  private approvalTtlMs(provider: string): number {
    const rule = this.registry.get(provider).approval;
    return rule ? rule.ttlMs : DEFAULT_APPROVAL_TTL_MS;
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
        path: spec.path,
        requester: this.identity.userId,
        id: spec.approvalId,
        approver: spec.approver,
        grant: spec.grant,
        ttlMs: this.approvalTtlMs(spec.provider),
        reason: spec.reason,
        link: spec.link,
        ...(spec.delegated === 'none' ? {} : { delegated: spec.delegated }),
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
    // A 'member' prompt is a regular message the whole channel reads and its decision surface is
    // channel membership, so an ineligible channel (Slack Connect / externally shared / DM-classed /
    // unverifiable) must never receive it: conversations.members there includes foreign-org users.
    // Checked before any delivery claim, so like a render failure this is a KNOWN no-post and the
    // impossible request is removed instead of parked behind a lease.
    if (spec.approver === 'member') {
      try {
        await assertChannelEligible(this.promptClient(), this.channel!);
      } catch (error) {
        await this.approvals?.discardPending(spec.approvalId).catch(() => undefined);
        throw error;
      }
    }
    // The surface binds the persisted delivered marker: the requester for 'self', the owning channel
    // for 'member', so a self→member rule change produces a fresh usable surface. 'member' always
    // has a channel here: effectiveApprover degraded it to 'self' wherever no channel governs.
    const audience = approvalDeliveryAudienceKey(
      spec.approvalId,
      spec.approver,
      [spec.approver === 'self' ? spec.decider : this.channel!],
    );
    // Start the conservative local budget BEFORE the claim round-trip. PostgreSQL creates the
    // lease during that call, so including the whole round-trip can only shorten our posting
    // window; it can never make us believe more lease remains than actually does.
    const deliveryLeaseStartedAtNs = process.hrtime.bigint();
    // Ephemerals vanish, so an in-channel 'self' prompt is re-posted after the debounce; a DM or a
    // 'member' channel message is durable and must not be posted twice.
    const delivery = await this.approvals?.claimDelivery(spec.approvalId, audience, {
      redeliverDelivered: spec.approver === 'self' && !!this.channel,
    });
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
    // Re-asking while the prompt is still up gets one private line (#350): the durable member
    // message stays where it is, so the requester learns why nothing new appeared.
    if (delivery.status === 'delivered') {
      await this.postPrivateNotice(
        spec.delegated === 'unbound'
          ? `Still waiting for a member of this channel to authorize the ${escapeMrkdwn(spec.provider)} action.`
          : spec.approver === 'member'
            ? `Still waiting for another member of this channel to approve the ${escapeMrkdwn(spec.provider)} action.`
            : `Still waiting for you to decide the ${escapeMrkdwn(spec.provider)} action above.`,
      );
    }
    if (delivery.status === 'claimed') {
      let confirmation: ApprovalPromptConfirmation;
      try {
        // postApprovalPrompt owns confirmation: it confirms the FIRST successful delivery
        // immediately (single-flight). Its posting budget reserves the full bounded database
        // confirmation window even when every earlier wave failed.
        confirmation = await this.postApprovalPrompt(
          spec, prompt,
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
    if (!approvalNeeded(this.registry.get(key.provider).approval, key.method, key.path)) return false;
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
      // Classify the action's channel by the governance scope carried on the key (null in a DM/group
      // DM), so a retained approval in a personal conversation is not re-denied by deny-by-default (#2).
      governableChannel: key.governableChannel,
    });
  }

  /** Build the use-time validator for every Bolt handle. Handles are public and may be retained, so
   * every use rechecks the actor's offboard receipt, current owner/identity/policy/tool state, and
   * exact credential generation. Shared credentials also recheck live Slack channel safety and
   * the acting user's membership before entering the database-locked validation. */
  private useValidator(
    owner: Owner,
    provider: string,
    credentialId: string,
    channel: string | null,
    thread: string | null,
    actorIssuedAt: number,
    governableChannel: string | null,
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
              delegated: false,
            },
            db: tx,
            registry: this.registry,
            policy: this.policy,
            vault: locked,
            enterpriseId: this.identity.enterpriseId,
            actorIssuedAt,
            channelTools: this.channelTools ?? null,
            channelConfig: this.channelConfig ?? null,
            // A channel-owned (shared) credential only lives in a governed channel, so its channel IS
            // the governance scope; a user-owned credential uses the DM-aware governance channel, so a
            // retained handle in a DM is not re-invalidated by deny-by-default (policy still applies).
            governableChannel: owner.kind === 'channel' ? channel : governableChannel,
          });
          if (state !== 'current') throw new InteractionStateChangedError('connection', state);
          return true;
        },
      );
    };
  }

  /** Client for lease-guarded prompt posts. A leased post must terminate well inside its
   * PROMPT_DELIVERY_LEASE_US: the default WebClient has no request timeout and silently queues
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

  /** Post the Approve/Deny prompt for one pending approval to its decision surface: the requester
   * (ephemeral in the channel, else a DM) for 'self'; one regular message in the owning channel, in
   * the originating thread when there is one, for 'member' (#322). The agent's `link` is untrusted, so
   * chat.postMessage never unfurls it into a picture or card beside the Approve button
   * (chat.postEphemeral has no unfurl knobs and never unfurls). */
  private async postApprovalPrompt(
    spec: ApprovalPromptSpec,
    prompt: { blocks: any; fallback: { text: string } | Record<string, never> },
    /** Marks the prompt delivered and consumes the lease; returns false if the request changed
     * first. */
    confirm: () => Promise<boolean>,
    /** Monotonic instant captured before claimDelivery; the posting deadline includes that round trip. */
    deliveryLeaseStartedAtNs: bigint,
  ): Promise<ApprovalPromptConfirmation> {
    const client = this.promptClient();
    const { blocks, fallback } = prompt;
    const threadArg = spec.thread ? { thread_ts: spec.thread } : {};
    if (APPROVAL_PROMPT_POST_DEADLINE_MS - monotonicElapsedMs(deliveryLeaseStartedAtNs) <= 0) {
      throw new ApprovalPromptNotStartedError('approval delivery budget elapsed before posting');
    }
    if (spec.approver === 'member') {
      const posted = await client.chat.postMessage({ channel: this.channel!, ...threadArg, blocks, ...fallback, unfurl_links: false, unfurl_media: false });
      this.postedApprovalPrompts?.remember(spec.approvalId, client, posted);
    } else if (this.channel) {
      // An ephemeral is placed where the asker is looking (replyThread), not necessarily where the
      // grant binds (spec.thread): under a top-level message it goes to the channel view.
      const replyArg = this.replyThread ? { thread_ts: this.replyThread } : {};
      await client.chat.postEphemeral({ channel: this.channel, user: spec.decider, ...replyArg, blocks, ...fallback });
    } else {
      const posted = await client.chat.postMessage({ channel: spec.decider, blocks, ...fallback, unfurl_links: false, unfurl_media: false });
      this.postedApprovalPrompts?.remember(spec.approvalId, client, posted);
    }
    // Preserve false (state drift) separately from rejection (database outcome unknown) so
    // recovery copy stays truthful.
    return promptConfirmationOutcome(confirm);
  }

  /**
   * Return a leak-safe handle for the user's connection to `providerId`.
   * If they haven't connected, post an ephemeral Block Kit Connect prompt and
   * throw ConsentRequiredError (the caller should stop this turn).
   */
  /**
   * Fetch a provider AND refuse service-to-service tools. `identity: 'service'` tools have no human
   * credential to broker (the host runs them with its own service auth, see ToolManifestEntry.identity
   * / Provider.identity), so EVERY Vouchr credential entry point (connect, user/channel key storage,
   * channel identity) routes through here, not just connect(). Also validates the provider exists.
   */
  private brokerable(providerId: string): Provider {
    const provider = this.registry.get(providerId);
    if (!isBrokeredProvider(provider)) {
      throw new UserFacingError(
        `"${providerId}" is a service-to-service tool; Vouchr does not broker it. Call it with your host's service auth.`,
      );
    }
    // Apply the write gate at the one chokepoint every Bolt credential entry point already routes
    // through, so both ConnectionHandle construction sites inherit it and a future third cannot miss
    // it. `allowWrites: false` must INTERSECT (readOnlyEgress), not merely default: a provider that
    // declares its own methods — databricks() declares ['GET','POST'] — would otherwise keep POST on
    // a deployment that explicitly asked to be read-only. The broker gets the same guarantee from its
    // route-level 405, which runs before the provider is consulted.
    return this.allowWrites ? provider : readOnlyEgress(provider);
  }

  /** The Bolt-side deny mapping of the shared authorizeProvider check. `meta` is spread into the
   * denial audit row (connectChannel adds `owner: 'channel'`). */
  private async requireProviderAuthorized(
    providerId: string,
    resolvedGovernanceChannel?: string | null,
    meta: Record<string, unknown> = {},
  ): Promise<void> {
    // Static Policy evaluates against the real delivery channel (this.channel — a DM included), while
    // the mutable tool allowlist is scoped to governableChannel (null in a DM, so deny-by-default
    // never locks a DM out). Audit/delivery stay on the actual delivery channel.
    const governanceChannel = resolvedGovernanceChannel === undefined
      ? await this.currentGovernanceChannel()
      : resolvedGovernanceChannel;
    const denial = await authorizeProvider(
      this.policy,
      this.channelTools,
      this.identity,
      this.channel,
      governanceChannel,
      providerId,
    );
    if (denial === 'policy') {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel, ...meta });
      this.emit({ type: 'policy_denied', provider: providerId });
      throw new PolicyDeniedError();
    }
    if (denial === 'tool-disabled') {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel, ...meta, reason: 'tool-disabled' });
      throw new ToolDisabledError();
    }
  }

  async connect(providerId: string): Promise<ConnectionHandle> {
    this.assertCredentialAccessAvailable();
    // Refuse service-to-service tools BEFORE any consent flow — no Connect prompt, no vault lookup.
    const provider = this.brokerable(providerId);
    // Capture the intent in PostgreSQL's clock domain before ANY asynchronous read. Policy,
    // identity, or credential reads may pause behind offboarding; they must not let an older connect
    // mint a newer key request or OAuth state after the tombstone has committed.
    const connectIssuedAt = await this.provisioningIssuedAt();
    const governableChannel = await this.currentGovernanceChannel();

    // Who the agent acts as for this provider here decides the credential (#350):
    //   'channel' -> the channel's one connected credential (delegate to connectChannel)
    //   'person'  -> the asking human's own credential
    // Identity is channel governance too, so it reads from governableChannel: a DM has none and
    // resolves to the person's own credential, never a channel credential.
    const identity = governableChannel && this.channelConfig
      ? await this.channelConfig.getIdentity(this.identity.teamId, governableChannel, providerId)
      : 'person';
    if (identity === 'channel') return this.connectChannel(providerId);

    // Authorization (Policy + per-channel tool allowlist): the CHECK is the shared core decision; the
    // Bolt path keeps its own audit/error mapping (and, unlike the broker, does NOT emit policy_denied on
    // a tool-disabled deny, preserved deliberately).
    await this.requireProviderAuthorized(providerId, governableChannel);

    // Resolve existence without decrypting. Reconnect purges old grants as a Vault satellite, so no
    // approval can silently carry across credential generations.
    const owner = userOwner(this.identity);
    const credentialId = await this.vault.liveId(owner, providerId);

    // Metadata-only, TTL-aware read of the EXACT generation bound above: the same linearization point
    // the decrypting read gave (a cross-pool reconnect landing after the read still falls through to
    // consent), without a KMS unwrap the handle's fetch() is about to repeat.
    if (credentialId && await this.vault.getAccount(owner, providerId, credentialId)) {
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
          governableChannel,
        ),
        // Persist the channel_type-aware governance scope on any approval so its DECISION
        // revalidation can classify a group DM the id alone cannot (#2).
        governableChannel,
      )));
    }

    // Key providers have no OAuth: post a self-service "set up your key" prompt instead.
    if (provider.credential === 'key') {
      const promptState = await this.postKeySetupPrompt(providerId, connectIssuedAt);
      this.emit({ type: 'connect_prompted', provider: providerId });
      throw new ConsentRequiredError(providerId, promptState);
    }

    await deliverConnectPrompt({
      consent: this.consent,
      identity: this.identity,
      provider,
      redirectUri: this.redirectUri,
      channel: this.channel,
      issuedAt: connectIssuedAt,
      post: (prompt) => this.postConnectPrompt(prompt),
    });
    this.emit({ type: 'connect_prompted', provider: providerId });
    throw new ConsentRequiredError(providerId, 'posted');
  }

  /**
   * Store the acting user's OWN static key for `providerId` (key providers). Self-service,
   * NOT member-gated (it's the user's own credential), keyed to `userOwner`. Leak-safe: the
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

  /** Default-deny member gate for config mutations (invariant 7, #322): the channel is the team, so
   *  any CURRENT member of it may configure it. Read from Slack, fails closed on any error, and
   *  audits the denial. The same bounded predicate gates every command, modal, and Home path. */
  private async requireMember(providerId: string): Promise<void> {
    const ok = !!this.channel && await boundedChannelMembership(
      this.client, this.channel, this.identity.userId, this.slackClientOptions,
    );
    if (!ok) {
      await this.audit.record('denied', this.identity, providerId, {
        reason: 'not-member',
        owner: 'channel',
        channel: this.channel,
      });
      throw new UserFacingError(memberOnly('configure channel credentials'));
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
   * Store a raw static key as the channel's credential for `providerId` and make the agent act as
   * the channel there. Member-gated and audited. The secret never enters the audit meta, the return
   * value, or any error string (invariant 8 / T7). Prefer `referenceChannelSecret` so rotation stays
   * in your secret manager.
   */
  async setChannelSecret(providerId: string, secret: string): Promise<void> {
    this.assertCredentialAccessAvailable();
    this.brokerable(providerId); // validate provider exists + refuse service tools
    const { cfg, channel } = this.channelTarget();
    const issuance = this.channelProvisioningIssuance ?? await this.provisioningIssuedAt();
    await this.requireMember(providerId);
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
    });
    if (!stored) throw new ChannelProvisioningStaleError();
  }

  /**
   * Point the channel's credential at an external secret manager (e.g. an AWS Secrets Manager
   * ARN) and make the agent act as the channel there. Vouchr stores only the non-secret ref; the
   * injector resolves it JIT and rotation stays external. Member-gated, audited.
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
      authorize: () => this.requireMember(providerId),
      assertEligible: () => this.assertChannelEligible(),
    });
    if (!stored) throw new ChannelProvisioningStaleError();
  }

  /**
   * Set who the agent acts as for a provider in this channel (#350). Member-gated, audited. Flipping
   * to `person` removes any live channel credential (a re-own that must be re-authorized; the member
   * gate is that authorization). Members then use their own accounts via `connect()`.
   */
  async setChannelIdentity(providerId: string, identity: ChannelIdentity): Promise<void> {
    this.brokerable(providerId);
    const { cfg, channel } = this.channelTarget();
    const issuance = await this.provisioningIssuedAt();
    await this.requireMember(providerId);
    await this.assertChannelEligible();
    const configured = await setChannelCredentialIdentity({
      vault: this.vault,
      audit: this.audit,
      channelConfig: cfg,
      identity: this.identity,
      channel,
      providerId,
      actAs: identity,
      issuance,
    });
    if (!configured) throw new InteractionStateChangedError('connection', 'authorization');
  }

  /**
   * Return a leak-safe handle for the CHANNEL's credential for `providerId`. The handle keys the
   * vault on the channel but audits as the acting human (invariant 9). Throws if the agent acts as
   * each person here or no channel credential is connected yet.
   */
  async connectChannel(providerId: string): Promise<ConnectionHandle> {
    this.assertCredentialAccessAvailable();
    const provider = this.brokerable(providerId);
    const connectIssuedAt = await this.provisioningIssuedAt();
    const governableChannel = await this.currentGovernanceChannel();
    if (governableChannel === null) {
      throw new UserFacingError('Shared channel credentials are not available in a personal conversation.');
    }
    const { cfg, owner, channel } = this.channelTarget();
    // Same authorization gate as connect() (the shared core CHECK): a deny applies to shared channel
    // creds too. A shared credential only exists in a governed channel, so governableChannel == the
    // real channel here. Audit meta carries owner:'channel'; like connect(), no policy_denied on tool-disabled.
    await this.requireProviderAuthorized(providerId, governableChannel, { owner: 'channel' });
    if ((await cfg.getIdentity(owner.teamId, channel, providerId)) !== 'channel') {
      throw new UserFacingError(
        `This channel does not share a "${providerId}" credential. Ask the agent again to use your own connection.`,
        'resolve_again',
      );
    }
    const credentialId = await this.vault.liveId(owner, providerId);
    if (!credentialId || !(await this.vault.getAccount(owner, providerId, credentialId))) { // exact row, no decrypt
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
      throw new UserFacingError(
        `You must be a member of this channel to use its shared "${providerId}" credential. Join the channel, then ask the agent again.`,
        'resolve_again',
      );
    }
    // Defense in depth: re-verify class at use time (a channel can change class after config).
    // This is one conversations.info per use; cache the class with a short TTL if a hot channel
    // throttles. Correctness first: a channel turned Slack Connect must stop now.
    await this.assertChannelEligible();
    // Channel-owner mapping through the same core decision, so this direct path can't drift from the
    // broker's. Eligibility is verified live above and identity is asserted 'channel', so eligible:true
    // and the helper always resolves (to channelOwner(teamId, channel) + this.identity).
    const r = resolveCredentialOwner({ path: 'channel', identity: 'channel', principal: this.identity, channel, eligible: true });
    if (r.status !== 'resolved') {
      throw new NoConnectionError(`No channel credential configured for "${providerId}" in this channel.`, 'channel');
    }
    // originChannel keeps its default (null): the channel-owned cred is attributed to its owning channel.
    return this.notifyApprovalRequired(this.notifyRateLimited(new ConnectionHandle(
      provider, r.owner, r.acting, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
      null, this.rateLimits, this.health, this.approvals, this.thread, this.dryRun,
      undefined, undefined, credentialId,
      this.approvalRequestStillCurrent.bind(this, connectIssuedAt),
      this.useValidator(
        r.owner,
        providerId,
        credentialId,
        owner.id,
        this.thread,
        connectIssuedAt,
        governableChannel,
      ),
      // A shared credential only lives in a governed channel, so its governance scope is that channel.
      governableChannel,
    )));
  }

  /**
   * The channel-filtered tool manifest an agent / MCP gateway asks for before planning: every
   * registered provider with whether it's usable in THIS channel and who the agent acts as there.
   * `enabled` intersects the channel's explicit deny-by-default allowlist with Policy, so it matches
   * what connect() would actually allow. With no channel (a DM-less context) there is no
   * tool-allowlist restriction and everyone acts as themselves, but Policy still applies: a
   * default-deny or allow-channel-only policy can still report a provider disabled.
   */
  async toolManifest(): Promise<ToolManifestEntry[]> {
    const governanceChannel = await this.currentGovernanceChannel();
    // ONE shared core builder (with the broker's POST /v1/manifest), so `enabled` here is exactly
    // "authorizeProvider would allow it" and the two transports can't drift.
    return buildToolManifest({
      providerIds: this.providerIds, registry: this.registry, policy: this.policy,
      channelTools: this.channelTools, channelConfig: this.channelConfig,
      // Policy on the real delivery channel; tool-allowlist + identity on the governance scope (null in a
      // DM, so personal providers report enabled there instead of deny-by-default disabled).
      principal: this.identity, channel: this.channel, governanceChannel,
    });
  }

  /**
   * The trusted broker-to-Slack recovery bridge (#194). A hybrid host's untrusted worker calls the
   * packaged HTTP broker; when the broker denies with a stable machine code, the host relays the
   * denial body here — from the SAME verified Slack event context that produced the worker's
   * identity assertion — and Vouchr takes the correct private recovery action:
   *
   *  - `not_connected` → the full connect flow re-runs from current verified state: the private
   *    connect or key-setup prompt (deduplicated), or, for a channel identity with no channel
   *    credential, the asking member is directed to channel configuration (never a personal
   *    connect prompt).
   *  - `approval_required` → the pending approval row named by `approvalId` is re-read from
   *    storage, bound to this verified team/user/channel and the relayed provider, the approver
   *    rule is re-derived from the registry (never the row or the wire), and the Approve/Deny
   *    decision surface is delivered through the same leased path as in-process approvals.
   *
   * The denial body is UNTRUSTED routing guidance, never authority (SEC-3/SEC-4): the code is
   * validated against VOUCHR_ERROR_CODES, `approvalId` is only a lookup handle, and every identity,
   * owner, policy, and eligibility fact is re-resolved server-side here and again at the
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

    if (code === 'not_connected') {
      try {
        // connect() IS the recovery flow: it re-resolves identity/policy/credential from current
        // verified state, dedups prompts, and throws typed control-flow errors.
        await this.connect(providerId);
        return { status: 'resolved', provider: providerId };
      } catch (e) {
        if (e instanceof ConsentRequiredError) {
          return { status: 'connect_prompted', provider: providerId, promptState: e.promptState };
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
      // A broker denial can sit in transit while the user is offboarded, the credential is
      // replaced, or channel governance changes. Re-run the ONE core authority check
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
      const { approver, decider } = approvalDecider(approval.approver, row);
      await this.deliverApprovalPrompt({
        provider: providerId,
        approver,
        method: row.method,
        host: row.host,
        path: row.path,
        approvalId: row.id,
        grant: row.grant,
        newRequest: false,
        thread: row.thread,
        reason: row.reason,
        link: row.link,
        decider,
        delegated: delegationOf(row),
      });
      return { status: 'approval_prompted', provider: providerId, approver };
    }

    // Denials that need a HUMAN, not a consent surface. On the Bolt path these already reach the
    // user (connect() throws them and the host renders safeUserMessage); relayed from the broker
    // they reached nobody — so a hybrid deployment's most common first-run failure, a channel that
    // is deny-by-default with the provider never enabled, was silence. Same failure, same words,
    // whichever transport produced it.
    //
    // SEC-3/SEC-1: the copy is derived LOCALLY from the typed code, never from the relayed payload.
    // A broker response is transport input; its `message` is neither trusted nor echoed — exactly as
    // the consent branches above rebuild their surfaces from verified state rather than sent text.
    if (code) {
      const notice = BRIDGEABLE_NOTICES[code];
      if (notice) {
        const delivery = await this.postPrivateNotice(safeUserMessage(notice()));
        // Never claim a delivery that did not happen — the same rule the rest of this file applies
        // to prompts, and the whole point of this PR. `no-channel` (nothing was posted) and
        // `platform-rejected` (Slack proved it was refused) fall through to `not_bridgeable`, so the
        // host's existing safeText path still tells the user something. `ambiguous`/`rate-limited`
        // may well have landed; reporting them as failure would produce a duplicate notice.
        if (delivery !== 'no-channel' && delivery !== 'platform-rejected') {
          return { status: 'notified', provider: providerId, code };
        }
      }
    }

    return { status: 'not_bridgeable' };
  }

  /**
   * Send one private, ephemeral, text-only notice to the acting user and REPORT what happened.
   *
   * The single place that owns channel presence, thread placement, and delivery classification for
   * a buttonless notice (STR-3) — `recoverBrokerDenial` and `directChannelConfiguration` both use
   * it, and previously disagreed about all three. It never throws: each caller decides what a
   * failure means, which is the only difference between them.
   *
   * `platform-rejected` is the one outcome that PROVES the user did not see it (channel_not_found,
   * bot removed). `ambiguous` and `rate-limited` may still have landed, so they are reported as
   * such rather than as failure — the same fail-safe reading the approval prompts use.
   */
  private async postPrivateNotice(text: string): Promise<'delivered' | 'no-channel' | SlackPromptDeliveryFailure> {
    const channel = this.channel;
    if (!channel) return 'no-channel'; // a relayed call outside any conversation
    // Thread placement matches every other private surface in this file: a question asked in a
    // thread is answered in that thread, not in the channel view where the user is not looking.
    const threadArg = this.replyThread ? { thread_ts: this.replyThread } : {};
    try {
      await this.promptClient().chat.postEphemeral({
        channel, user: this.identity.userId, ...threadArg, text,
      });
      return 'delivered';
    } catch (deliveryError) {
      return classifySlackPromptDeliveryFailure(deliveryError);
    }
  }

  /** Shared-owner recovery for a missing channel credential: tell the actor, privately, that the
   * channel needs one and how to set it up. Any current member may configure it (#322), so the
   * asking human is the one to direct; the command itself re-checks membership and channel class. */
  private async directChannelConfiguration(providerId: string): Promise<void> {
    const channel = this.channel;
    const p = escapeMrkdwn(providerId);
    if (!channel) {
      // A channel identity only resolves inside a channel; without one there is no configuration surface.
      throw new UserFacingError(
        `"${providerId}" uses a shared channel credential. Ask in the channel where the agent should use it.`,
      );
    }
    // A channel can become externally shared or archived after the identity was set. Recheck
    // the same fail-closed class rule as the actual configuration mutation before directing anyone
    // to an operation Vouchr must refuse.
    await assertChannelEligible(this.promptClient(), channel);
    const text = `No shared ${p} credential is configured in this channel. Run \`/vouchr connect-shared ${p}\` here to set one up.`;
    const delivery = await this.postPrivateNotice(text);
    // Same sender, different contract: this path is a configuration DIRECTION the caller must know
    // failed, so a non-delivery still throws exactly as before.
    if (delivery !== 'delivered') {
      throw slackPromptDeliveryRecovery(delivery === 'no-channel' ? 'ambiguous' : delivery, 'configuration');
    }
  }

  /** Private JIT prompt for a key provider: ephemeral in-channel, or a durable DM off-channel. The
   * button opens the per-user key modal. The existing core provisioning row owns the cross-replica
   * delivery lease, exactly as consent owns OAuth prompt delivery. */
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
      { redeliverDelivered: !!this.channel },
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

  private async postConnectPrompt(prompt: ConnectPrompt): Promise<void> {
    const client = this.promptClient();
    const { blocks, fallback } = prompt;
    if (this.channel) {
      // Same placement rule as every private prompt: in the thread the person asked from, at channel
      // level for a top-level message (an ephemeral under an unreplied root is never seen).
      await client.chat.postEphemeral({
        channel: this.channel,
        user: this.identity.userId,
        ...(this.replyThread ? { thread_ts: this.replyThread } : {}),
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
 * Recipient: the owner for a user-owned credential; the last configuring member (audit-derived) for
 * a channel-owned one — nobody on record ⇒ skip, never spam the channel. 'expired' events get no DM
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
    if (!recipient) return; // channel cred with no known configuring member: skip
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
        text = `The shared ${p} connection${where} stopped working and needs to be reconnected. Use \`/vouchr connect-shared ${p}\` there.`;
      }
    } else {
      const hours = Math.max(1, Math.round(((e.expiresAt ?? Date.now()) - Date.now()) / 3_600_000));
      text = e.owner.kind === 'user'
        ? `Your ${p} connection expires in ~${hours}h. Reconnect to keep using it.`
        : `The shared ${p} connection${where} expires in ~${hours}h. Reconnect it (\`/vouchr connect-shared ${p}\`) to keep it working.`;
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
  // #302: validate the browser Slack-identity hop config BEFORE the pool opens, like every other
  // no-db check above. The verify/slack routes mount beside callbackPath (same directory).
  const slackOidc = assertSlackOidcOptions(
    opts.slackOidc ?? {
      clientId: process.env.VOUCHR_SLACK_CLIENT_ID ?? '',
      clientSecret: process.env.VOUCHR_SLACK_CLIENT_SECRET ?? '',
    },
    'createVouchr',
  );
  const hops = browserHopUrls(redirectUri);
  const browserVerifyPath = hops.verify.pathname;
  const slackRedirectPath = hops.slack.pathname;
  if (browserVerifyPath === callbackPath || slackRedirectPath === callbackPath) {
    throw new Error('createVouchr: callbackPath must not end in /verify or /slack (the Slack verify routes mount there)');
  }
  const oidcRedirectUri = hops.slack.toString();
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
  const approvals = new Approvals(db); // #113 per-action approval requests/grants (provider.approval)
  const postedApprovalPrompts = new PostedApprovalPrompts(); // #348 editable Approve/Deny messages
  const provisioning = new UserProvisioningRequests(db, vault);
  const channelProvisioning = new ChannelProvisioningRequests(db, vault);
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
  // Same gate as ConnectContext.requireMember, for the command paths that don't route through it
  // (enable/disable tool allowlist, the configure pre-modal gate, stats/audit reads, App Home): any
  // CURRENT member of the channel (#322). Read from Slack through the bounded client; fails closed.
  const channelMember = (client: WebClient, identity: SlackIdentity, channel: string): Promise<boolean> =>
    boundedChannelMembership(client, channel, identity.userId, opts.slackClientOptions);

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

  /** A stored consent row belongs to the Slack-signed clicker. */
  const sameActor = (row: SlackIdentity, actor: SlackIdentity): boolean =>
    row.teamId === actor.teamId && row.userId === actor.userId;

  /** Button feedback: an ephemeral through the interaction's `respond`, falling back to a DM. */
  const replyToActor = (respond: any, client: WebClient, identity: SlackIdentity | null) =>
    async (text: string, replaceOriginal = true) => {
      if (respond) {
        try {
          await respond({ replace_original: replaceOriginal, response_type: 'ephemeral', text });
          return;
        } catch { /* fall back to a private DM */ }
      }
      if (identity) await dmActor(client, identity, text);
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
   * by `/vouchr enable|disable` and the App Home Enable/Disable button so the member gate, the write,
   * and the audit row are identical by construction. The write itself — including the first-write
   * allowlist materialization AND the configured-ness decision — is ONE atomic core mutation
   * (ChannelTools.applyEnabled, STR-1), so concurrent members can't interleave a partial allowlist
   * and a failure can't leave one. Only the provider the member actually targeted is audited.
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
  ): Promise<'ok' | 'unchanged' | 'denied'> => {
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
        if (await channelMember(client, identity, channel)) return true;
        await audit.record('denied', identity, provider, { reason: 'not-member', owner: 'channel', channel });
        return false;
      },
      // Channel-class eligibility at the MUTATION, not just at render (SEC-3: the render hiding
      // controls for an archived/ext-shared channel is UI, not authorization; a forged payload or
      // a slash command must hit the same wall). Ordered after the member gate and throwing a
      // UserFacingError with no audit row, exactly mirroring setChannelIdentity.
      assertEligible: () => assertChannelEligible(client, channel),
    });
    if (configured === 'stale') {
      throw new InteractionStateChangedError('connection', 'authorization');
    }
    if (configured === 'denied') return 'denied';
    return configured === 'unchanged' ? 'unchanged' : 'ok';
  };

  const CHANNEL_CREDENTIAL_UNAVAILABLE =
    'This tool uses service-managed credentials and cannot be configured here.';
  const CREDENTIAL_SETUP_LOCKED =
    'Credential setup is temporarily unavailable. Contact an administrator.';

  /** Consume Slack's short-lived trigger before any network/database gate, reserve opaque setup
   * authority immediately after Slack confirms the loading view, then hydrate it only after the
   * channel, membership, eligibility, and lifecycle fences pass. Reserving before the slow Slack gates
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
    // authority: Vouchr must never ask a member to enter a credential it cannot use.
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
    const authorized = await channelMember(client, identity, channel);
    if (!authorized) {
      await audit.record('denied', identity, provider, {
        reason: 'not-member',
        owner: 'channel',
        channel,
      });
      await deliverModalOutcome(
        client,
        identity,
        { id: viewId },
        'Setup unavailable',
        memberOnly('configure channel credentials'),
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

    // A sibling credential/identity mutation may have committed while Slack authorization was in
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

    // Warn if the provider is disabled in this channel: a credential set here is inert until enabled
    // (disable wins at use time). Read-only; a stale read is harmless — the write path is unchanged.
    const providerDisabled = !(await channelTools.isEnabled(identity.teamId, channel, provider).catch(() => true));
    try {
      await client.views.update({
        view_id: viewId,
        view: configureModal(provider, channel, referenceSources, requestId, providerDisabled) as any,
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
    // A custom InstallationStore is outside Vault and may not implement Vouchr's deployment gate.
    // Never ask it for a Slack credential while this control plane is contained.
    if (lockdown) return null;
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
    // SEC-5: connectedDmText escapes the provider-reported account label.
    const text = connectedDmText(result.provider, result.account);
    // Durable private receipt in the user's DM (survives; the record of what happened).
    await client.chat.postMessage({ channel: result.identity.userId, text }).catch(() => undefined);
    // Plus an in-context confirmation where the connect prompt was posted, so the user sees a green
    // signal in the channel they were working in — not only a DM they may not be watching. Ephemeral
    // (private to the connector, never broadcast) and best-effort. The disconnected browser callback
    // can't update the original url-button prompt in place, so this is a fresh private confirmation.
    if (result.channel && result.channel !== result.identity.userId) {
      await client.chat.postEphemeral({
        channel: result.channel,
        user: result.identity.userId,
        text,
      }).catch(() => undefined);
    }
  }

  // #117 credential-health wiring. Default: DM the owner (healthNotifier), via the same per-workspace
  // client resolution as post-OAuth success and recovery DMs, debounced by the persistent notification_state
  // table. An operator-supplied onCredentialHealth REPLACES the default DMs. Either
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
        args.event?.channel
        ?? args.body?.channel_id
        ?? args.body?.channel?.id
        ?? args.body?.container?.channel_id
        ?? null;
      // The thread this request is in: thread_ts for a reply, else the message's own ts (the root).
      // Unlike interactionLocation() for Vouchr's decision buttons, a CUSTOM action listener uses
      // the clicked message as its originating context, so standard message_ts/message.ts are valid
      // root fallbacks here. Slash commands have none and remain null.
      const thread: string | null =
        args.event?.thread_ts
        ?? args.event?.ts
        ?? args.body?.container?.thread_ts
        ?? args.body?.message?.thread_ts
        ?? args.body?.container?.message_ts
        ?? args.body?.message?.ts
        ?? null;
      // Where PRIVATE prompts go: only an existing thread (a message whose thread_ts differs from its
      // own ts, or an action inside a thread). A top-level message is its own root, and an ephemeral
      // posted under an unreplied root shows no reply indicator, so it goes to the channel view.
      const eventThread = args.event?.thread_ts;
      const replyThread: string | null =
        (typeof eventThread === 'string' && eventThread !== args.event?.ts ? eventThread : undefined)
        ?? args.body?.container?.thread_ts
        ?? args.body?.message?.thread_ts
        ?? null;
      // A DM / group-DM is a personal conversation that no channel governs, so channel governance (the tool
      // allowlist + identity) does not apply; the request must NOT be denied by the deny-by-default
      // allowlist there. The connect prompt is still delivered to `channel` (and static Policy still
      // evaluates against it), but the governable scope is null (like a channel-less context). ONE
      // source of truth for the mapping (governanceChannelOf, STR-2), shared with the headless broker.
      const channelType = isSlackConversationType(args.event?.channel_type)
        ? args.event.channel_type
        : undefined;
      const governableChannel: string | null = governanceChannelOf(channel, channelType);
      const contextDeps: InternalConnectContextDeps = {
        identity,
        channel,
        governableChannel,
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
        requireMembership: opts.requireChannelMembership ?? false,
        thread,
        replyThread,
        approvals,
        auditSink,
        health,
        notifications: notifyState,
        dryRun,
        allowWrites: opts.allowWrites ?? true,
        slackClientOptions: opts.slackClientOptions,
        [INTERNAL_POSTED_APPROVAL_PROMPTS]: postedApprovalPrompts,
      };
      // Slash commands and block actions have no event.channel_type. A G… id can mean either a
      // private channel (governed) or an MPIM (personal), so attach a LAZY authenticated lookup.
      // It does not start in middleware: the host can acknowledge first, and the first Vouchr call
      // resolves and memoizes the classification. Errors retain the governed scope (fail closed).
      if (channel?.startsWith('G') && channelType === undefined) {
        contextDeps[INTERNAL_GOVERNANCE_CHANNEL_RESOLVER] = () => (
          governanceChannelForCommand(args.client, channel, opts.slackClientOptions)
        );
      }
      args.context.vouchr = new ConnectContext(contextDeps);
    }
    await args.next();
  };

  const callbackDeps = { registry, vault, audit, consent, redirectUri, auditSink, dryRun };

  // #302: one shared verifier owns the OIDC exchange + compare + stamp/spend sequence.
  const browserVerifier = new BrowserIdentityVerifier({ consent, registry, redirectUri, oidcRedirectUri, audit, auditSink, oidc: slackOidc });

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

  /**
   * #116 dry-run test helper: opt a provider into a channel's tool allowlist, exactly as a member
   * running `/vouchr enable <provider>` (or toggling App Home) would. Channels are deny-by-default,
   * so a first `connect()` for a provider that was never enabled here throws `ToolDisabledError`
   * before any consent — call this once in setup to reproduce a governed channel offline.
   */
  const enableTool = async (
    member: SlackIdentity,
    channel: string,
    providerId: string,
  ): Promise<void> => {
    registry.get(providerId); // SEC-4: validate before any write; throws on an unknown id
    const outcome = await configureChannelTools({
      channelTools,
      vault,
      audit,
      identity: member,
      channel,
      changes: [[providerId, true]],
      allProviders: providerIds,
      issuance: await vault.userProvisioningIssuedAt(),
      authorize: async () => true, // the caller vouches for membership in a test
      assertEligible: async () => undefined,
    });
    if (outcome === 'stale') throw new Error('channel tool enable was superseded');
  };

  /** One fixed text/plain error response for the browser routes (SEC-1/SEC-5: static text only). */
  function sendPlain(res: any, status: number, text: string): any {
    return res
      .status(status)
      .set({ 'content-type': 'text/plain; charset=utf-8', 'x-content-type-options': 'nosniff' })
      .send(text);
  }

  /** Mount the Slack verify hop (#302) and the OAuth callback on the receiver's router. */
  function mountRoutes(router: any): void {
    // #116 dry-run: the hop routes are not mounted (404). Hop 2 is the one place the client secret
    // would leave the process for slack.com; the dry-run prompt points at the callback, never here.
    if (!dryRun) {
      // #302 hop 1: the Connect prompt's URL. Redirects the browser to Slack's OIDC authorize.
      router.get(browserVerifyPath, async (req: any, res: any) => {
        try {
          const r = await browserVerifier.begin(req.query?.state);
          if (r.ok) return res.status(302).set({ location: r.redirectUrl }).send();
          return sendPlain(res, r.status, r.error);
        } catch {
          sendPlain(res, 500, OAUTH_CONNECTION_FAILED);
        }
      });
      // #302 hop 2: Slack's redirect back. A verified match continues to the provider authorize URL.
      router.get(slackRedirectPath, async (req: any, res: any) => {
        try {
          const r = await browserVerifier.complete({
            code: req.query?.code,
            state: req.query?.state,
            error: req.query?.error,
          });
          if (r.ok) return res.status(302).set({ location: r.redirectUrl }).send();
          return sendPlain(res, r.status, r.error);
        } catch {
          sendPlain(res, 500, OAUTH_CONNECTION_FAILED);
        }
      });
    }
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
          .send(OAUTH_CONNECTION_FAILED);
      }
    });
  }

  /** Build a per-request ConnectContext bound to a specific channel (for the modal submit, and —
   *  with `thread` — for a stored backchannel row's exact conversation, #296). */
  function contextFor(
    identity: SlackIdentity,
    channel: string | null,
    client: WebClient,
    provisioningReceivedAt?: bigint,
    channelIssuance?: ChannelProvisioningIssuance,
    governableChannel?: string | null,
    thread: string | null = null,
  ): ConnectContext {
    // A stored row carries the binding thread only; whether its root has replies is unknown here, so
    // private prompts for it keep the historical thread placement.
    const deps: InternalConnectContextDeps = {
      identity, channel, client, registry, vault, audit, consent, policy, redirectUri, resolvers,
      channelConfig, channelTools, inflight, rateLimits, sink, providerIds,
      requireMembership: opts.requireChannelMembership ?? false,
      thread, replyThread: thread, approvals, auditSink, health, notifications: notifyState, dryRun,
      allowWrites: opts.allowWrites ?? true,
      slackClientOptions: opts.slackClientOptions,
      [INTERNAL_POSTED_APPROVAL_PROMPTS]: postedApprovalPrompts,
    };
    if (governableChannel !== undefined) deps.governableChannel = governableChannel;
    if (provisioningReceivedAt != null) {
      deps[INTERNAL_PROVISIONING_RECEIVED_AT] = provisioningReceivedAt;
    }
    if (channelIssuance != null) {
      deps[INTERNAL_CHANNEL_PROVISIONING_ISSUANCE] = channelIssuance;
    }
    return new ConnectContext(deps);
  }

  /** The manifest plus its raw allowlist snapshot for governance renderers. Keeping the raw predicate lets
   *  them show policy-denied-but-allowlisted tools correctly without reading channel_tool twice. */
  const manifestSnapshotFor = (
    identity: SlackIdentity,
    channel: string,
    governanceChannel: string | null,
  ) => buildToolManifestSnapshot({
    providerIds,
    registry,
    policy,
    channelTools,
    channelConfig,
    principal: identity,
    channel,
    governanceChannel,
  });

  /**
   * Register the `/vouchr` slash command (`status`, `disconnect <provider>`,
   * `connect-shared <provider>`), the channel-credential modal submit, and — when the app exposes
   * `event` (Bolt does; older custom fakes may not) — the App Home console (#111) on
   * `app_home_opened`. `connect-shared` opens a private modal so the member's secret is never typed
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
      '*This channel (any member)*',
      '• `/vouchr enable <provider>` — allow a provider here',
      '• `/vouchr disable <provider>` — block a provider here',
      '• `/vouchr identity <provider> <person|channel>` — who the agent acts as here: each person, or the channel',
      '• `/vouchr connect-shared <provider>` — connect one shared account for the whole channel (opens a private modal)',
      '• `/vouchr disconnect-shared <provider>` — remove the channel-shared account (the agent acts as each person again)',
      '• `/vouchr stats` — 30-day usage for this channel',
      '• `/vouchr audit channel` — this channel’s shared-credential usage',
    ].join('\n');
    // Raw command arguments can be credential-shaped (for example, a token pasted in the provider
    // position). SEC-1 therefore forbids reflecting an unknown value even after mrkdwn escaping:
    // escaping prevents injection, not disclosure. Keep one static, actionable response for every
    // provider-taking command.
    const UNKNOWN_PROVIDER_TEXT = 'Unknown provider. Run `/vouchr tools` to see the registered providers.';
    // A trusted audit subject for non-member attempts against an unregistered provider-shaped value.
    // The submitted value is not yet recognized and therefore must never reach any audit column.
    const DISCONNECT_SHARED_DENIAL_SUBJECT = 'disconnect-shared';
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
      // PLAT-2: the trigger is consumed by a cheap loading view FIRST; building the real modal reads
      // the DB and pages the channel roster (up to the membership deadline), which can outlive Slack's
      // ~3s trigger window, so the built modal hydrates that view through views.update (the pattern
      // openConfigureModal uses). An open failure gets fixed command guidance rather than silently
      // substituting status for the settings surface the user requested; a build/update failure
      // replaces the loading view (or DMs) with the same guidance. Raw Slack/DB errors are never reflected.
      if (!sub && command.trigger_id) {
        const recovery = 'Could not open Vouchr settings. Run `/vouchr help` to use the text commands instead.';
        let viewId: unknown;
        try {
          const opened: any = await client.views.open({
            trigger_id: command.trigger_id,
            view: privateStatusModal('Vouchr settings', 'Loading…'),
          });
          viewId = opened?.view?.id;
          if (typeof viewId !== 'string' || !viewId) throw new Error('unconfirmed view');
        } catch {
          return respond(recovery);
        }
        try {
          await client.views.update({ view_id: viewId, view: await buildConfigModal(identity, command.channel_id ?? null, client) });
        } catch {
          await deliverModalOutcome(client, identity, { id: viewId }, 'Vouchr settings', recovery);
        }
        return;
      }

      // List the channel's tool manifest (which providers an agent may use here + who it acts as).
      if (sub === 'tools') {
        if (words.length !== 1) return respond('Usage: `/vouchr tools`');
        if (!command.channel_id) return respond('Run `/vouchr tools` from inside a channel.');
        const prepared = await prepareCommandResponse(async () => {
          const governance = await governanceChannelForCommand(
            client,
            command.channel_id,
            opts.slackClientOptions,
          );
          const manifest = await contextFor(
            identity,
            command.channel_id,
            client,
            undefined,
            undefined,
            governance,
          ).toolManifest();
          if (!manifest.length) return 'No providers are registered.';
          const lines = manifest
            // Service tools have no human credential to broker, so they say so instead of an identity.
            .map((m) => {
              const actor = isBrokeredProvider(m) ? `acts as ${escapeMrkdwn(m.identity)}` : 'service tool';
              return `• *${escapeMrkdwn(m.provider)}*: ${m.enabled ? 'enabled' : 'disabled'} (${actor})`;
            })
            .join('\n');
          return `Tools for <#${escapeMrkdwn(command.channel_id)}>:\n${lines}\n\nAny member: \`/vouchr enable|disable <provider>\`.`;
        });
        return respond(prepared.ok ? prepared.value : COMMAND_READ_FAILURE.tools);
      }

      // Usage analytics for THIS channel over the last 30 days: which enabled tools are actually
      // used, by how many distinct humans, and which are idle dead-weight to prune. Member-gated (same
      // gate as enable/identity) + audited on refusal. Service tools aren't brokered, so they're excluded.
      if (sub === 'stats') {
        if (words.length !== 1) return respond('Usage: `/vouchr stats`');
        if (!command.channel_id) return respond('Run `/vouchr stats` from inside a channel.');
        const prepared = await prepareCommandResponse(async () => {
          if (!(await channelMember(client, identity, command.channel_id))) {
            await audit.record('denied', identity, 'stats', { reason: 'not-member', owner: 'channel', channel: command.channel_id });
            return memberOnly('view channel usage stats');
          }
          const governance = await governanceChannelForCommand(
            client,
            command.channel_id,
            opts.slackClientOptions,
          );
          const manifest = await contextFor(
            identity,
            command.channel_id,
            client,
            undefined,
            undefined,
            governance,
          ).toolManifest();
          const enabled = manifest.filter((m) => m.enabled && isBrokeredProvider(m)).map((m) => m.provider);
          const since = Date.now() - 30 * 24 * 60 * 60 * 1000;
          const stats = await audit.statsByChannel(identity.teamId, command.channel_id, since);
          const blocks = statsBlocks(enabled, stats, 30);
          return { text: blocksFallbackText(blocks), blocks: blocks as any };
        });
        return respond(prepared.ok ? prepared.value : COMMAND_READ_FAILURE.stats);
      }

      // Enable/disable a provider in this channel. Member-gated (default-deny) + audited as 'config'
      // inside setChannelToolEnabled — the same helper the App Home button routes through (STR-3).
      // An ineligible channel class (archived / ext-shared / DM) throws a UserFacingError inside the
      // helper, surfaced like the `identity` branch does.
      if (sub === 'enable' || sub === 'disable') {
        if (words.length !== 2) return respond(`Usage: \`/vouchr ${sub} <provider>\``);
        if (!command.channel_id) return respond(`Run \`/vouchr ${sub}\` from inside the channel you want to configure.`);
        if (!registry.has(arg)) return respond(UNKNOWN_PROVIDER_TEXT);
        const on = sub === 'enable';
        let outcome: 'ok' | 'unchanged' | 'denied';
        try {
          outcome = await setChannelToolEnabled(
            client,
            identity,
            command.channel_id,
            arg,
            on,
            provisioningReceivedAt,
          );
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        if (outcome === 'denied') return respond(memberOnly('change channel tools'));
        if (outcome === 'unchanged') {
          return respond(`*${escapeMrkdwn(arg)}* is already ${on ? 'enabled' : 'disabled'} in <#${escapeMrkdwn(command.channel_id)}> — nothing changed.`);
        }
        return respond(`${on ? 'Enabled' : 'Disabled'} *${escapeMrkdwn(arg)}* in <#${escapeMrkdwn(command.channel_id)}>.`);
      }

      // Who the agent acts as here (#350): each person, or the channel. Member-gated + audited in
      // setChannelIdentity.
      if (sub === 'identity') {
        if (words.length !== 3 || !arg || !isChannelIdentity(arg2)) {
          return respond('Usage: `/vouchr identity <provider> <person|channel>`');
        }
        if (!command.channel_id) return respond('Run `/vouchr identity` from inside the channel you want to configure.');
        if (!registry.has(arg)) return respond(UNKNOWN_PROVIDER_TEXT);
        try {
          await contextFor(
            identity,
            command.channel_id,
            client,
            provisioningReceivedAt,
          ).setChannelIdentity(arg, arg2);
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        return respond(arg2 === 'channel'
          ? `In <#${escapeMrkdwn(command.channel_id)}> the agent now acts as the channel for *${escapeMrkdwn(arg)}*. Connect its account with \`/vouchr connect-shared ${escapeMrkdwn(arg)}\`.`
          : `In <#${escapeMrkdwn(command.channel_id)}> the agent now acts as each person for *${escapeMrkdwn(arg)}*.`);
      }

      if (sub === 'connect-shared') {
        if (words.length !== 2) return respond('Usage: `/vouchr connect-shared <provider>`');
        if (!command.channel_id) return respond('Run `/vouchr connect-shared` from inside the channel you want to configure.');
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
            return respond(memberOnly('configure channel credentials'));
          }
          if (result === 'locked') return respond(CREDENTIAL_SETUP_LOCKED);
          if (result === 'unsupported') return respond(CHANNEL_CREDENTIAL_UNAVAILABLE);
        } catch (e) {
          return respond(safeUserMessage(e)); // ineligible channel class → the core reason, nothing else
        }
        return;
      }
      // The counterpart to connect-shared. Member-gated; the dedicated core op only acts when the
      // agent acts as the channel (a `person` channel is a truthful no-op), deletes the channel
      // credential AND attempts upstream revocation, and reports its real outcome.
      if (sub === 'disconnect-shared') {
        if (words.length !== 2) return respond('Usage: `/vouchr disconnect-shared <provider>`');
        if (!command.channel_id) return respond('Run `/vouchr disconnect-shared` from inside the channel you want to configure.');
        // Validate id syntax before any lookup or audit (SEC-4). Registry membership is safe to use
        // in the denial audit; an unregistered submitted value is replaced by a fixed trusted subject.
        if (!isValidProviderId(arg)) return respond(UNKNOWN_PROVIDER_TEXT);
        const chan = command.channel_id;
        let outcome: Awaited<ReturnType<typeof disconnectChannelShared>>;
        try {
          if (!(await channelMember(client, identity, chan))) {
            await audit.record(
              'denied',
              identity,
              registry.has(arg) ? arg : DISCONNECT_SHARED_DENIAL_SUBJECT,
              { reason: 'not-member', owner: 'channel', channel: chan },
            );
            return respond(memberOnly('change channel credentials'));
          }
          // Recognize a current registry entry, this channel's exact stored credential, OR its exact
          // persisted channel-identity row. The last case is the documented `missing` recovery path: a
          // break-glass delete may remove the credential while leaving the identity behind, and provider
          // retirement must not make that stuck governance row impossible to clear.
          const recognized = registry.has(arg)
            || await vault.has(channelOwner(identity.teamId, chan), arg)
            || await channelConfig.getIdentity(identity.teamId, chan, arg) === 'channel';
          if (!recognized) {
            return respond(UNKNOWN_PROVIDER_TEXT);
          }
          outcome = await disconnectChannelShared({
            vault, audit, channelConfig, registry, identity,
            channel: chan, providerId: arg,
            issuance: await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt),
          });
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        const p = escapeMrkdwn(arg);
        if (outcome.status === 'not-shared') {
          return respond(`No shared *${p}* account is set in <#${escapeMrkdwn(chan)}>, so there was nothing to disconnect.`);
        }
        if (outcome.status === 'missing') {
          return respond(`There was no shared *${p}* credential stored in <#${escapeMrkdwn(chan)}> (it may already have been revoked). The agent now acts as each person there.`);
        }
        if (outcome.status === 'stale') {
          return respond(`The *${p}* setup changed before the change completed. Run \`/vouchr disconnect-shared ${p}\` again.`);
        }
        if (!outcome.ok) {
          return respond(`Removed the shared *${p}* account in <#${escapeMrkdwn(chan)}>; the agent now acts as each person there. Upstream revocation could not be confirmed, so revoke or rotate Vouchr’s access in ${p} directly if needed.`);
        }
        if (!outcome.audited) {
          // The delete + identity flip + revoke committed, but the durable revoke audit could not be
          // written: surface it separately instead of discarding the committed outcome (mirrors disconnect).
          return respond(`Removed the shared *${p}* account in <#${escapeMrkdwn(chan)}>, but Vouchr could not confirm the audit record. Ask an admin to check the Vouchr logs.`);
        }
        return respond(`Removed the shared *${p}* account in <#${escapeMrkdwn(chan)}>. The agent now acts as each person there.`);
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
        if (outcome.removed) emit({ type: 'revoked', provider: arg, ok: outcome.ok });
        return respond(disconnectReceipt(p, outcome, `You have no connected *${p}* account, so there was nothing to disconnect.`));
      }

      // Self-service transparency: where your credential was used. `audit channel` (member-gated) shows
      // this channel's channel-owned usage. Strictly scoped by the SELECT — a non-member only ever sees
      // rows attributed to their own user id, never another user's or another channel's.
      if (sub === 'audit') {
        if (words.length > 2 || (arg && arg !== 'channel')) return respond('Usage: `/vouchr audit [channel]`');
        if (arg === 'channel') {
          if (!command.channel_id) return respond('Run `/vouchr audit channel` from inside the channel.');
          const prepared = await prepareCommandResponse(async () => {
            if (!(await channelMember(client, identity, command.channel_id))) {
              await audit.record('denied', identity, 'audit', { reason: 'not-member', owner: 'channel', channel: command.channel_id });
              return memberOnly('view channel credential usage');
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
    // channel manifest; MEMBERS additionally get per-provider identity/enable controls (membership
    // decided server-side here, NOT trusted on submit). Shared by the initial open and the views.update
    // after a disconnect. Service tools are shown read-only but excluded from the governance controls:
    // Vouchr doesn't broker them, so a channel identity is meaningless and setChannelIdentity would
    // refuse them.
    async function buildConfigModal(identity: SlackIdentity, channelId: string | null, client: WebClient): Promise<unknown> {
      // Connection rows do not depend on channel classification; start that database read now so an
      // ambiguous G… Slack lookup and the independent vault read overlap inside the trigger window.
      const connectionsPromise = listBrokeredConnections(identity);
      // Slash commands and modal actions do not carry Slack's channel_type. Resolve the only
      // ambiguous id class (G… private channel vs MPIM) after acknowledgement, then use that exact
      // classification for both the read-only manifest and whether channel-governance controls exist.
      // A DM/group-DM is a personal conversation: tools remain available without a mutable channel
      // allowlist, and there are no channel-governance controls to render.
      const governanceChannel = channelId
        ? await governanceChannelForCommand(client, channelId, opts.slackClientOptions)
        : null;
      // These are independent and all sit before Slack's short-lived trigger_id is consumed by
      // views.open. Dispatch them together rather than spending one DB/network window per fact.
      const [connections, manifest, member] = await Promise.all([
        connectionsPromise,
        channelId
          ? manifestSnapshotFor(identity, channelId, governanceChannel)
          : Promise.resolve({ tools: [], toolAllowed: (_provider: string) => true }),
        channelId && governanceChannel
          ? channelMember(client, identity, channelId)
          : Promise.resolve(false),
      ]);
      // The modal keeps its pre-#111 contract: service tools are read-only there (its row shape is
      // identity+enabled controls, meaningless for them). The App Home instead renders every
      // row and per-row picks which controls a service tool gets (Enable/Disable only).
      const admin = member && channelId
        ? memberToolRows(manifest.tools, manifest.toolAllowed).filter((r) => isBrokeredProvider(r))
        : undefined;
      return configModal({ channel: channelId, connections, tools: manifest.tools, admin });
    }

    /**
     * The per-provider governance control rows for a channel — ONE ROW PER REGISTERED PROVIDER (#111),
     * service tools included (their allowlist Enable/Disable is a valid channel control; renderers
     * use `identity` to omit the identity/credential controls core refuses for them). Shared by the App
     * Home governance section and (brokered-filtered) the config modal, so both consoles render the
     * same facts. The Enabled bit is channelTools.isEnabled — the raw tool-allowlist bit, NOT the
     * manifest's policy-intersected `enabled`: rendering the intersected value would show a
     * policy-denied provider as disabled and let an untouched save/click look like an intentional
     * disable (config-modal findings 3/1); the manifest keeps the intersected value for the
     * read-only displays.
     */
    function memberToolRows(
      tools: ToolManifestEntry[],
      toolAllowed: (provider: string) => boolean,
    ): ConfigMemberRow[] {
      // Raw tool-allowlist bit (NOT the manifest's policy-intersected `enabled`) reuses the manifest's
      // channel snapshot, so governance rendering adds no query and cannot drift to a second DB window.
      return tools.map((t) => ({
        provider: t.provider,
        identity: t.identity,
        enabled: toolAllowed(t.provider),
      }));
    }

    // Config modal submit: parse the view, acknowledge Slack, then re-check authorization and apply
    // changed controls. The modal only SHOWED controls to members, but the payload is forgeable; each
    // mutation still routes through the same server-side helper as its slash/action counterpart.
    // Receipts are private and distinguish confirmed changes from unconfirmed failures, so a partial
    // batch is never presented as one all-or-nothing success or failure. An untouched field never
    // mutates or reverts a concurrent member's change because every value is diffed against OPEN-TIME
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
      const openIdentity = new Map(open.map((o) => [o.p, o.i]));
      const openEnabled = new Map(open.map((o) => [o.p, o.e]));

      // Collect the submitted state per provider up front, so identity + enabled are each diffed
      // against their OPEN-TIME value rather than the current store.
      const values = view.state?.values ?? {};
      const submittedIdentity = new Map<string, unknown>();
      const submittedEnabled = new Map<string, boolean>();
      for (const [blockId, v] of Object.entries<any>(values)) {
        if (blockId.startsWith('identity:')) submittedIdentity.set(blockId.slice(9), v?.identity?.selected_option?.value);
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

      if (!(await channelMember(client, identity, channel))) {
        await audit.record('denied', identity, 'config', { reason: 'not-member', owner: 'channel', channel }).catch(() => undefined);
        await deliverModalOutcome(
          client,
          identity,
          view,
          'Settings not applied',
          memberOnly('change channel settings'),
        );
        return;
      }

      const ctx = contextFor(identity, channel, client, provisioningReceivedAt);
      let confirmed = 0;
      let unconfirmed = 0;

      // ── identity: apply only where the member actually changed the select (submitted !== open-time) ──
      for (const [provider, actAs] of submittedIdentity) {
        if (!registry.has(provider) || !isChannelIdentity(actAs)) continue; // forged/invalid → ignore
        if (actAs === openIdentity.get(provider)) continue; // untouched (or reset to the same) → skip
        try { await ctx.setChannelIdentity(provider, actAs); confirmed++; } catch { unconfirmed++; }
      }

      // ── enabled: the tool allowlist. Only the controls the member actually changed (submitted !==
      // open-time) are applied; the write — including the first-write allowlist materialization that
      // keeps untouched providers from vanishing, and the configured-ness decision itself — is ONE
      // atomic core mutation (ChannelTools.applyEnabled), so a concurrent member or a mid-write
      // failure can never leave a partial allowlist. Audit only the providers that actually changed. ──
      const enabledChanged = [...submittedEnabled].filter(([p]) => registry.has(p) && submittedEnabled.get(p) !== (openEnabled.get(p) ?? false));
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
            // The modal's common gate above already proved current membership once for every
            // submitted setting; the shared helper still owns the mutation/audit sequence.
            authorize: async () => true,
            assertEligible: () => assertChannelEligible(client, channel),
          });
          // 'unchanged' (the desired state already held, e.g. a concurrent write landed it) is still a
          // confirmed outcome for the member — the channel matches what they submitted.
          if (configured === 'configured' || configured === 'unchanged') confirmed += enabledChanged.length;
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
    // server-side gate additionally get "Channel governance" (a channel picker + per-provider identity /
    // enable / configure controls). RENDERING is the only thing decided here; every block action
    // re-validates its inputs (SEC-4) and re-checks membership at the mutation (SEC-3), because a
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
     * Build the App Home view for `identity` — cheap (one vault list; per-provider config reads only
     * once a channel is selected) and idempotent, since app_home_opened fires often. Governance shows
     * for everyone: membership is unknowable until a channel is picked, so the PER-CHANNEL gate
     * (channelMember, the same predicate as the slash commands) decides once one is (#322).
     * A selected channel that is ineligible (archived / externally shared / DM — the core
     * channelIneligibleReason rule) or was deleted since last render degrades to a note, never an error.
     */
    async function buildHomeView(identity: SlackIdentity, client: WebClient, selected: string | null): Promise<unknown> {
      const connections = await listBrokeredConnections(identity);
      // "Available providers" advertises connect-on-demand, so it lists only providers Vouchr
      // actually brokers a user credential for — a service tool must not be advertised as
      // connectable. Governance rows are separate (memberToolRows, same brokered filter as the modal).
      const connectable = providerIds.filter((p) => isBrokeredProvider(registry.get(p)));

      let governance: { channel: string | null; note?: string; tools?: ConfigMemberRow[] } = { channel: selected };
      if (selected) {
        let info: ChannelInfo | null = null;
        try { info = ((await client.conversations.info({ channel: selected })) as any)?.channel ?? null; } catch { info = null; }
        const reason = channelIneligibleReason(info); // fail-closed: null info (deleted channel) → a reason
        if (reason) {
          governance = { channel: selected, note: reason };
        } else if (!(await channelMember(client, identity, selected))) {
          governance = { channel: selected, note: memberOnly('configure this channel') };
        } else {
          const manifest = await manifestSnapshotFor(identity, selected, selected);
          governance = { channel: selected, tools: memberToolRows(manifest.tools, manifest.toolAllowed) };
        }
      }
      // Ownership stamp: ONLY this internal publisher marks the view as Vouchr's and carries the
      // selection state — the exported homeView stays unstamped so a host reusing it for its OWN
      // Home tab is never mistaken for ours (the event/disconnect handlers key ownership off
      // HOME_CALLBACK). The metadata channel is forgeable like any view field; handlers re-verify
      // it (verifiedHomeChannel) and re-check membership before any write.
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
    // render path itself re-checks eligibility + membership for the picked channel.
    app.action(HOME_CHANNEL_ACTION, async ({ ack, body, client }: any) => {
      await ack();
      if (body.view?.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const selected = body.actions?.[0]?.selected_conversation;
      await publishHome(identity, client, typeof selected === 'string' && selected ? selected : null);
    });

    // Identity select → the SAME helper as `/vouchr identity` (ConnectContext.setChannelIdentity owns
    // the member gate, the eligibility check, the write, and the audit row, STR-3), then re-publish.
    // Validation order matches the slash command: registry + identity list BEFORE the mutation (SEC-4);
    // an invalid forged value must not even reach setChannelIdentity (whose credential cleanup precedes
    // its sink check).
    app.action(HOME_IDENTITY_ACTION, async ({ ack, body, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      if (body.view?.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const a = body.actions?.[0] ?? {};
      const provider = typeof a.block_id === 'string' && a.block_id.startsWith('home_identity:') ? a.block_id.slice('home_identity:'.length) : '';
      const actAs = a.selected_option?.value;
      if (!registry.has(provider) || !isChannelIdentity(actAs)) return;
      const channel = await verifiedHomeChannel(client, body);
      if (!channel) return staleChannelFeedback(client, identity);
      try {
        await contextFor(
          identity,
          channel,
          client,
          provisioningReceivedAt,
        ).setChannelIdentity(provider, actAs);
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
          await dmActor(client, identity, memberOnly('change channel tools'));
        }
      } catch (e) {
        // Ineligible channel class (SEC-3: forged payloads reach the same wall as slash) → the
        // core reason, as a DM; the re-publish shows the real (unchanged) state.
        await dmActor(client, identity, safeUserMessage(e));
      }
      await publishHome(identity, client, channel);
    });

    // Configure → the SAME gate + modal as `/vouchr connect-shared` (STR-3). The modal's submit is the
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
          await dmActor(client, identity, memberOnly('configure channel credentials')); // denial audited inside
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
        // One explicit receipt per click, duplicate clicks included: the modal/Home refresh below is
        // best effort and may fail after the destructive mutation has committed (#194 UX-1/5).
        await dmActor(client, identity, disconnectReceipt(p, outcome, `No *${p}* account was connected, so there was nothing to disconnect.`));
      }
      const channel = homeSelectedChannel(body.view);
      if (surface === 'home') return publishHome(identity, client, channel);
      await client.views.update({ view_id: body.view.id, view: await buildConfigModal(identity, channel, client) }).catch(() => undefined);
    });

    // Per-user key setup: an already-issued opaque prompt id → private modal (self-service, not
    // member-gated). The click does not mint or extend authority; provider is reloaded from the exact
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

    // The OAuth "Connect <provider>" button carries a `url`, so Slack opens the sign-in page in the
    // browser on click AND delivers a block_actions interaction whose response_url addresses the
    // prompt itself (#347). The value is the prompt's own opaque state: it is read, never spent, and
    // only the Slack-signed clicker matching the row's owner gets anything but the fixed stale copy
    // (a missing or tampered value included: every Vouchr-rendered button carries one).
    app.action(OAUTH_CONNECT_ACTION, async ({ ack, body, respond, client }: any) => {
      await ack();
      const state = body.actions?.[0]?.value;
      const identity = resolveIdentity({ body });
      const reply = replyToActor(respond, client, identity);
      const found = identity ? await consent.inspect(state) : null;
      if (!found || !identity || !sameActor(found.row.identity, identity)) {
        return reply(CONNECT_PROMPT_STALE_TEXT);
      }
      if (found.live) {
        // A DM prompt is a durable message and the only retry surface after a cancelled Slack
        // sign-in (DM generations are never redelivered), so it stays; the channel ephemeral is
        // replaced with the one line the browser hop's copy points back at.
        if (found.row.channel === null) return;
        return reply(CONNECT_PROMPT_OPENING_TEXT);
      }
      const blocks = connectExpiredBlocks(found.row.provider, found.row.state);
      try {
        await respond({ replace_original: true, response_type: 'ephemeral', blocks, ...optionalBlockFallback(blocks) });
      } catch {
        // Slack may have accepted the replacement before the failure surfaced. A second
        // replace_original write through the same response_url could overwrite the installed
        // "Send a new link" prompt with stale text, so the fallback is a DM, never the response_url.
        await dmActor(client, identity, CONNECT_PROMPT_STALE_TEXT);
      }
    });

    // "Send a new link" on a replaced stale prompt (#347): the same mint + lease + confirm sequence
    // as the agent turn, posted through the click's response_url so the fresh prompt takes the old
    // one's place. Owner, provider, and channel come from the stored row; identity from the signed
    // click. With two replicas racing, beginFenced yields one generation and the lease lets exactly
    // one replace the message; the loser stays quiet because the winner's replacement is the
    // feedback and a second response_url write would clobber it.
    app.action(OAUTH_RENEW_ACTION, async ({ ack, body, respond, client }: any) => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      const identity = resolveIdentity({ body });
      const reply = replyToActor(respond, client, identity);
      const found = identity ? await consent.inspect(body.actions?.[0]?.value) : null;
      if (!found || !identity || !sameActor(found.row.identity, identity)) {
        return reply(CONNECT_PROMPT_STALE_TEXT);
      }
      if (vault.lockdownEnabled) return reply(CREDENTIAL_SETUP_LOCKED, false);
      const providerId = found.row.provider;
      if (!registry.has(providerId) || !isBrokeredProvider(registry.get(providerId))
        || registry.get(providerId).credential === 'key') {
        return reply(CONNECT_PROMPT_STALE_TEXT);
      }
      // Once the response_url has been written, a failure is ambiguous: a second write could
      // overwrite a replacement Slack already installed. Report through a DM instead; before any
      // write, the private ephemeral reply is still safe.
      let wroteResponse = false;
      try {
        await deliverConnectPrompt({
          consent,
          identity,
          provider: registry.get(providerId),
          redirectUri,
          channel: found.row.channel,
          issuedAt: await provisioningIssuedAtFromReceipt(vault, provisioningReceivedAt),
          post: async ({ blocks, fallback }) => {
            wroteResponse = true;
            await respond({ replace_original: true, response_type: 'ephemeral', blocks, ...fallback });
          },
        });
      } catch (error) {
        if (error instanceof ConsentRequiredError) return; // the other replica's click replaced it
        if (wroteResponse) await dmActor(client, identity, safeUserMessage(error));
        else await reply(safeUserMessage(error), false);
      }
    });

    // #113 Approve/Deny for a pending sensitive-write approval. The button value is ONLY the
    // pending-approval id — every field of an interaction payload is forgeable (SEC-3), so
    // authority is decided here, server-side, at the mutation: the provider is re-validated
    // against the registry (SEC-4), the approver RULE comes from the registry (never the payload
    // or the stored row), and the clicker's eligibility is re-checked — 'self' means exactly the
    // requester; 'member' (#322) means anyone ELSE who is a current member of the request's channel,
    // clicking from that channel (the payload channel is compared with the persisted row, never
    // trusted on its own). An ineligible click is rejected AND audited 'denied'. Approve mints the
    // single-use TTL grant; Deny records the denial (approver in the actor column) and notifies the
    // requester.
    const handleApprovalDecision = async ({ ack, body, respond, client }: any, decision: 'approve' | 'deny') => {
      const provisioningReceivedAt = process.hrtime.bigint();
      await ack();
      const identity = resolveIdentity({ body });
      const location = interactionLocation(body);
      const id = body.actions?.[0]?.value;
      const reply = replyToActor(respond, client, identity);
      const stale = APPROVAL_STALE_TEXT;
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
      const approval = registry.has(pending.provider) && isBrokeredProvider(registry.get(pending.provider))
        ? registry.get(pending.provider).approval
        : false;
      if (!approval || !approvalNeeded(approval, pending.method, pending.path)) {
        await approvals.discardPending(id).catch(() => undefined);
        return reply('This approval is no longer valid because provider access changed. Ask the agent again.');
      }
      const p = escapeMrkdwn(pending.provider); // SEC-5, even for a registry-validated id
      // Requester notification: ephemeral in the request's channel, or a DM when there was none.
      const tellRequester = async (text: string) => {
        if (pending.channel) {
          await client.chat.postEphemeral({ channel: pending.channel, user: pending.userId, ...(pending.thread ? { thread_ts: pending.thread } : {}), text }).catch(() => undefined);
        } else {
          await client.chat.postMessage({ channel: pending.userId, text }).catch(() => undefined);
        }
      };
      const ttlMs = approval.ttlMs;
      // Resolved for the request's own identity and conversation (unset follows the persisted owner
      // kind, a DM degrades 'member' to 'self'; a worker's request asks any member, then the bound
      // member), from the persisted row — never from the payload.
      const delegation = delegationOf(pending);
      const { approver: approverRule, decider } = approvalDecider(approval.approver, pending);
      // #360 a worker's request is authorized by a member AS themselves: the grant binds to the
      // clicking member's own credential. A member without one is sent the private Connect prompt in
      // this conversation and the request stays pending for them (or anyone) to authorize later.
      let delegate: { ownerId: string; credentialId: string } | undefined;
      if (delegation === 'unbound' && decision === 'approve') {
        if (!pending.channel || identity.userId === pending.userId) {
          return reply('You are not eligible to authorize this request; a member of this channel other than the worker must.', false);
        }
        const credentialId = await vault.liveId(userOwner(identity), pending.provider);
        if (!credentialId) {
          if (!(await boundedChannelMembership(client, pending.channel, identity.userId, opts.slackClientOptions))) {
            return reply('You are not eligible to authorize this request; a current member of this channel must.', false);
          }
          try {
            await contextFor(
              identity, pending.channel, client, provisioningReceivedAt, undefined, pending.governableChannel, pending.thread,
            ).connect(pending.provider);
          } catch (error) {
            if (!(error instanceof ConsentRequiredError)) return reply(safeUserMessage(error), false);
          }
          return reply(
            `Connect your *${p}* account first. Vouchr sent you a private Connect prompt${pending.thread ? ' in this thread' : ' in this channel'}; `
            + 'once connected, click *Authorize with your account* again. The request stays open for '
            + `${PENDING_APPROVAL_MINUTES} minutes if nobody authorizes it.`,
            false,
          );
        }
        delegate = { ownerId: identity.userId, credentialId };
      }
      let decided: ApprovalDecisionResult;
      try {
        // Slack facts cannot be queried through PostgreSQL. Resolve them before taking lifecycle
        // locks, fail closed on any read error, then carry only the verdict into the row-locked
        // validation. The channel is the trust boundary for a channel-owned approval AND for a
        // 'member' decision surface: both are invalid once the channel class is no longer safe (a
        // Slack Connect conversion puts foreign-org users in conversations.members), and a
        // channel-owned approval also needs its original requester to still be a member.
        const channelBound = pending.ownerKind === 'channel' || approverRule === 'member' || delegation !== 'none';
        let channelFactsValid = true;
        if (channelBound) {
          if (!pending.channel) channelFactsValid = false;
          else {
            try {
              await assertChannelEligible(client, pending.channel);
            } catch {
              channelFactsValid = false;
            }
            if (
              channelFactsValid &&
              pending.ownerKind === 'channel' &&
              !(await boundedChannelMembership(
                client,
                pending.channel,
                pending.userId,
                opts.slackClientOptions,
              ))
            ) channelFactsValid = false;
          }
        }
        const approverEligible = approverRule === 'member'
          ? channelFactsValid
            && identity.userId !== pending.userId
            && await boundedChannelMembership(client, pending.channel!, identity.userId, opts.slackClientOptions)
          : delegation === 'bound'
            ? channelFactsValid
              && identity.userId === decider
              && await boundedChannelMembership(client, pending.channel!, identity.userId, opts.slackClientOptions)
            : identity.userId === pending.userId;
        // Snapshot the identity only to choose every possibly-relevant lock. The authoritative
        // identity/owner/policy/tool decision is reloaded after those canonical locks are held below.
        const actAs = pending.channel
          ? await channelConfig.getIdentity(pending.teamId, pending.channel, pending.provider)
          : 'person';
        // The authorizing member's own credential scope is locked too, so their disconnect cannot
        // race the bind (#360).
        const owners = [...approvalDecisionLockOwners(pending, actAs), ...(delegate ? [userOwner(identity)] : [])];
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
              delegate,
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
                if (delegationOf(row) !== delegation || approvalDecider(currentApproval.approver, row).approver !== approverRule) return 'invalidated';
                if (channelBound && !channelFactsValid) return 'invalidated';
                if (!(await approvalOwnerStillCurrent({
                  row,
                  db: decisionTx,
                  registry,
                  policy,
                  vault: locked,
                  enterpriseId: identity.enterpriseId,
                  actorIssuedAt: row.createdAt,
                }))) return 'invalidated';
                // The member's credential must still be the generation read above: a disconnect that
                // landed in between leaves the request pending for a member who holds one.
                if (delegate && (await locked.liveId(userOwner(identity), row.provider)) !== delegate.credentialId) return 'ineligible';
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
        return reply(
          delegation === 'unbound'
            ? 'You are not eligible to authorize this request right now. A current member of this channel with a connected account must; if that is you, click again.'
            : delegation === 'bound'
              ? 'You are not eligible to decide this approval; only the member who authorized this worker in this thread can.'
              : approverRule === 'member'
                ? 'You are not eligible to decide this approval; another channel member must.'
                : 'You are not eligible to decide this approval; only the requester can.',
          false,
        );
      }
      // The decision replaces the prompt through its response_url below; the sweep must not
      // overwrite that outcome with the expired copy.
      postedApprovalPrompts.forget(id);
      if (decision === 'approve') {
        emit({ type: 'approval_approved', provider: pending.provider, host: pending.host });
        if (delegation === 'unbound') {
          await reply(
            `✅ Authorized the *${p}* action with your account. It runs as you, once. Further *${p}* actions this worker takes `
            + `${pending.thread ? 'in this thread' : 'in this channel'} will ask you privately, each time, until `
            + `${WORKER_SESSION_IDLE_MINUTES} minutes pass without one. The worker can retry now.`,
          );
        } else if (delegation === 'bound') {
          await reply(`✅ Approved the *${p}* action. It runs as you, once. The worker can retry now.`);
        } else {
          await reply(`✅ Approved the *${p}* action. ${grantCovers(pending.provider, pending.grant, ttlMs)} Have the agent retry now.`);
        }
        // A worker requester is a bot user: nobody reads its ephemeral.
        if (identity.userId !== pending.userId && delegation === 'none') {
          await tellRequester(`✅ <@${escapeMrkdwn(identity.userId)}> approved your *${p}* action. Ask the agent to retry.`);
        }
      } else {
        emit({ type: 'approval_denied', provider: pending.provider, host: pending.host });
        await reply(`🚫 Denied the *${p}* action. Nothing was sent.`);
        if (identity.userId !== pending.userId && delegation === 'none') {
          await tellRequester(`🚫 <@${escapeMrkdwn(identity.userId)}> denied your *${p}* action. Nothing was sent.`);
        }
      }
    };
    app.action(APPROVAL_APPROVE_ACTION, (a: any) => handleApprovalDecision(a, 'approve'));
    app.action(APPROVAL_DENY_ACTION, (a: any) => handleApprovalDecision(a, 'deny'));
  }

  /** Remove all of a user's own connections + pending consent + approvals (offboarding). */
  function offboard(identity: SlackIdentity): Promise<string[]> {
    return offboardUser(
      vault,
      audit,
      consent,
      identity,
      registry,
      'offboarded',
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

  /**
   * #296: deliver the Approve/Deny surface for every live backchannel authorization request that
   * has none yet. A background agent's request arrives with no Slack turn to relay a denial from,
   * so this pass plays that turn: for each undelivered row it rebuilds the requester's context
   * (identity, channel, thread — from the stored row, never the wire) and runs the SAME trusted
   * recovery bridge an in-turn relay would (`recoverBrokerDenial`): registry-derived approver rule,
   * current-authority revalidation, leased cross-replica delivery. Bounded per pass; a row whose
   * delivery keeps failing is retried until its pending TTL reclaims it. A provider the channel now
   * forbids is discarded so the pass does not re-audit that denial every interval. Per-row failures
   * never stop the pass or the caller's timer. Returns how many prompts this pass delivered.
   */
  async function deliverPendingAuthorizations(): Promise<number> {
    let delivered = 0;
    for (const row of await approvals.listUndeliveredBackchannel(MAX_AUTHORIZATION_DELIVERIES_PER_PASS)) {
      const identity: SlackIdentity = { enterpriseId: null, teamId: row.teamId, userId: row.userId };
      const client = await confirmClientFor(identity);
      if (!client) continue; // no bot token for this workspace (or lockdown): nothing can be posted
      try {
        const outcome = await contextFor(
          identity, row.channel, client, undefined, undefined, row.governableChannel, row.thread,
        ).recoverBrokerDenial(row.provider, { code: 'approval_required', approvalId: row.id });
        if (outcome.status === 'approval_prompted') delivered++;
      } catch (e) {
        if (e instanceof PolicyDeniedError || e instanceof ToolDisabledError) {
          await approvals.discardPending(row.id).catch(() => undefined);
        }
        // Slack/DB/lease failures: the row stays undelivered and the next pass retries (bounded by TTL).
      }
    }
    return delivered;
  }

  /** Delete every connection past its TTL plus every stale interaction family through the one core
   *  lifecycle coordinator. Expired approvals are audited there (#113). Then deliver any pending
   *  backchannel decision surfaces (#296). Run on a timer. */
  async function sweep(): Promise<number> {
    const count = await sweepLifecycle({ db, vault, audit, sink, health, dryRun });
    // #348: an unclicked prompt whose row the sweep (or offboarding) removed must not keep
    // live-looking buttons. Database first, Slack second; only rows that are gone are edited.
    await postedApprovalPrompts.expire(async (id) => (await approvals.get(id)) !== null);
    await deliverPendingAuthorizations();
    return count;
  }

  /**
   * One-call wiring for the common case. Does everything a Bolt app needs in the right order:
   * the credential-injection middleware, the OAuth callback route, the `/vouchr` slash command, the
   * deactivation → offboard hook, and the hourly TTL sweep (once at startup, then on a timer). The
   * granular methods above remain for apps that need finer control. Returns `{ stop }` to clear the
   * timers on shutdown. `sweepIntervalMs: 0` disables the sweep timer (drive `sweepExpired()`
   * yourself — it also delivers pending backchannel prompts). `authorizationDeliveryIntervalMs`
   * (#296, default 15s, `0` disables) is the separate, much shorter cadence at which pending
   * backchannel authorization prompts reach Slack: a background agent's request has a 10-minute
   * pending TTL, so the hourly sweep alone would let most of them expire undelivered.
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
    opts: { sweepIntervalMs?: number; authorizationDeliveryIntervalMs?: number } = {},
  ): { stop: () => Promise<void> } {
    const deliveryMs = opts.authorizationDeliveryIntervalMs ?? DEFAULT_AUTHORIZATION_DELIVERY_INTERVAL_MS;
    // A non-integer/NaN/oversized interval would fire immediately and continuously (Node clamps
    // out-of-range timers to 1ms) — fail closed at wiring time instead. Bounded to MAX_TIMER_MS.
    if (!Number.isSafeInteger(deliveryMs) || deliveryMs < 0 || deliveryMs > MAX_TIMER_MS) {
      throw new Error(`install: authorizationDeliveryIntervalMs must be an integer between 0 and ${MAX_TIMER_MS}`);
    }
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
    // #296 delivery timer: single-flight per process (a slow Slack pass never stacks a second one),
    // per-row failures are swallowed inside the pass, and the lease dedupes across replicas.
    let deliveryTimer: ReturnType<typeof setInterval> | undefined;
    let deliveryPass: Promise<void> | undefined;
    if (deliveryMs > 0) {
      deliveryTimer = setInterval(() => {
        deliveryPass ??= deliverPendingAuthorizations()
          .then(() => undefined, () => undefined)
          .finally(() => { deliveryPass = undefined; });
      }, deliveryMs);
      deliveryTimer.unref();
    }
    // stop() tears down what install() started: the timers (waiting for a delivery pass already in
    // flight, so its Slack posts and lease confirmations settle before the pool goes away), and
    // (only if Vouchr opened it) the db pool. An injected db is the caller's to close.
    return {
      stop: async () => {
        if (timer) clearInterval(timer);
        if (deliveryTimer) clearInterval(deliveryTimer);
        await deliveryPass;
        if (ownsDb) await db.close();
      },
    };
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
    dryRun: dryRun ? { completeConsent, enableTool } : undefined,
  };
}

// Type `context.vouchr` for consumers so handlers can call it without `as any`.
declare module '@slack/bolt' {
  interface Context {
    vouchr: ConnectContext;
  }
}
