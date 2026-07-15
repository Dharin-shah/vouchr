import { WebClient } from '@slack/web-api';
import type { InstallationStore } from '@slack/bolt';
import { openDb, type Db } from '../core/db';
import { loadKeyring, type EnvelopeProvider } from '../core/crypto';
import { ProviderRegistry, isBrokeredProvider, isValidProviderId, buildCallbackUrl, type Provider } from '../core/providers';
import { Vault, type TtlPolicy } from '../core/vault';
import { Audit, type AuditSink } from '../core/audit';
import { Consent } from '../core/consent';
import { Policy } from '../core/policy';
import type { SlackIdentity } from '../core/identity';
import { resolveIdentity, isSlackAdmin, isChannelAdmin, isChannelMember, listChannelMembers } from './slack-identity';
import { userOwner, channelOwner } from '../core/owner';
import {
  authorizeProvider,
  resolveCredentialOwner,
  buildToolManifest,
  buildToolManifestSnapshot,
} from '../core/authz';
import { ConnectionHandle, EgressBlockedError, NoConnectionError, ResolverFailedError, ResponseBlockedError, type Resolvers, type EventSink, type VouchrEvent } from '../core/injector';
import { MemoryRateLimitStore, RateLimitedError, type RateLimitStore } from '../core/rateLimit';
import { safeEmit } from '../core/safe-emit';
import { ChannelConfig, channelIneligibleReason, isChannelMode, isPreviewVisibility, type ChannelInfo, type ChannelMode, type PreviewVisibility } from '../core/channelConfig';
import { configureChannelCredential, setChannelCredentialMode } from '../core/channelCredential';
import { ChannelTools, type ToolManifestEntry } from '../core/tools';
import { PendingPreviews } from '../core/preview';
import { handleOAuthCallback } from '../core/oauthCallback';
import { offboardUser, disconnectProvider } from '../core/offboard';
import { assertDryRunFlag, assertDryRunLocalKey, assertDryRunVault, dryRunAudit, DRY_RUN_CODE } from '../core/dryRun';
import { sweepExpired } from '../core/sweep';
import { SessionGrants } from '../core/session';
import { Approvals, ApprovalRequiredError, DEFAULT_APPROVAL_TTL_MS } from '../core/approval';
import { NotificationState, type CredentialHealthEvent, type CredentialHealthHook } from '../core/health';
import {
  normalizeSecretReference,
  referenceChannelCredential,
  referenceUserCredential,
  SECRET_REFERENCE_SOURCES,
  SecretReferenceError,
} from '../core/reference';
import {
  connectBlocks, connectedHtml, configureModal, CONFIGURE_CALLBACK,
  userKeyModal, keySetupBlocks, USER_KEY_CALLBACK, SETUP_KEY_ACTION, RECONNECT_ACTION,
  privateStatusModal,
  sessionApprovalBlocks, APPROVE_SESSION_ACTION, auditBlocks, statsBlocks, statusBlocks,
  approvalBlocks, APPROVAL_APPROVE_ACTION, APPROVAL_DENY_ACTION,
  configModal, CONFIG_CALLBACK, DISCONNECT_ACTION,
  homeView, connectionLine, HOME_CALLBACK, HOME_CHANNEL_ACTION, HOME_MODE_ACTION, HOME_TOOL_ACTION, HOME_CONFIGURE_ACTION,
  previewBlocks, previewPostBlocks, normalizePreviewContent, PREVIEW_SHARE_ACTION, PREVIEW_DISMISS_ACTION,
  escapeMrkdwn, blocksFallbackText, connectedDmText,
  type Connection, type ConfigAdminRow,
} from './blocks';

/** How long a private preview's Share button stays claimable. Short on purpose: the human is
 *  looking at the ephemeral message right now; a stale share re-posts stale data. */
const PREVIEW_TTL_MS = 10 * 60_000;

/** Default session-grant safety ceiling: 8h. The thread binding is the real scope; this just caps
 *  how long a single approval can live before the user must re-approve in the thread. */
const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

/** Aggressive default per-user connection lifetime: idle 7d, hard cap 30d. */
const DEFAULT_TTL: TtlPolicy = { idleMs: 7 * 24 * 60 * 60 * 1000, maxAgeMs: 30 * 24 * 60 * 60 * 1000 };

/** Denial message for the config gate, accurate to whether the channel-creator path is enabled. */
const adminOnly = (allowCreator: boolean, action: string): string =>
  `Only a workspace admin${allowCreator ? ' or the channel creator' : ''} can ${action}.`;

interface ConfigOpenState {
  p: string;
  m: ChannelMode | null;
  e: boolean;
  v?: PreviewVisibility;
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
      !(entry.v === undefined || isPreviewVisibility(entry.v))
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

/** Thrown by `connect()` after a Connect prompt is posted: stop this turn. */
export class ConsentRequiredError extends Error {
  constructor(public provider: string) {
    super(`Consent required for "${provider}". A Connect prompt was posted to the user.`);
    this.name = 'ConsentRequiredError';
  }
}

/** Thrown by `connect()` when a thread-scoped session is required and not yet approved: an in-thread
 *  "Allow … here" button was posted. Stop this turn; the user approves and re-invokes. */
export class SessionApprovalRequiredError extends Error {
  constructor(public provider: string) {
    super(`Session approval required for "${provider}": an approval button was posted in the thread.`);
    this.name = 'SessionApprovalRequiredError';
  }
}

/**
 * Marker for a deliberate, Vouchr-authored, secret-free denial/validation message that IS safe to
 * echo to the Slack user (an admin gate, a channel-eligibility or mode-lock refusal, a bad-input
 * message). These read identically to a foreign `new Error(...)` — which could carry a provider /
 * KMS / DB secret — so the throw site opts a message into the whitelist by using THIS class; a bare
 * Error stays masked to its class name. See safeUserMessage.
 */
export class UserFacingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UserFacingError';
  }
}

/**
 * The only text safe to echo to a Slack user from a caught error. Mirrors the headless broker's
 * top-level catch (broker.ts), which returns the error CLASS NAME only: an extension point (a custom
 * `provider.inject`, KMS `wrapDataKey`, a DB driver) can throw AFTER touching a secret, so a raw
 * `e.message` could carry a token. We therefore show `e.message` ONLY for Vouchr's OWN error classes
 * — those are the messages Vouchr deliberately authored to be user-facing and secret-free. Any other
 * (unexpected) error is reduced to its class name; the type still triages in the logs.
 */
export function safeUserMessage(e: unknown): string {
  if (
    e instanceof ConsentRequiredError ||
    e instanceof SessionApprovalRequiredError ||
    e instanceof ApprovalRequiredError ||
    e instanceof EgressBlockedError ||
    e instanceof ResponseBlockedError ||
    e instanceof NoConnectionError ||
    e instanceof ResolverFailedError ||
    e instanceof RateLimitedError ||
    e instanceof SecretReferenceError ||
    e instanceof UserFacingError
  ) {
    return e.message;
  }
  const name = (e as Error)?.constructor?.name ?? 'Error';
  return `Something went wrong (${name}). Ask an admin to check the Vouchr logs.`;
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
  /** Bot token used only to post the "connected" confirmation back to Slack. */
  botToken?: string;
  /**
   * Multi-workspace token source. When set, the post-OAuth confirmation DM is sent with the
   * bot token of the CONNECTING user's own workspace (resolved per (enterpriseId, teamId)),
   * so an app installed to many workspaces / org-wide works. When omitted, behaves exactly as
   * before, a single `botToken`. Wire the SAME store into Bolt's OAuth `installationStore`.
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
   * channel-owned credential), with a reconnect button on `refresh_dead`, debounced to one DM per
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
  /** Pending private previews awaiting Share/Dismiss. Must be the createVouchr-scoped instance so a
   *  share click (a later request) finds the entry; a direct-constructed context gets its own (the
   *  ephemeral still posts; the share button then reports expired unless the host wires the actions). */
  previews?: PendingPreviews;
  /** #116 dry-run: threaded to every ConnectionHandle so the final outbound call is stubbed (see
   *  VouchrOptions.dryRun). Default false: unchanged behavior. */
  dryRun?: boolean;
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
  private previews: PendingPreviews;
  private dryRun: boolean;

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
    this.previews = deps.previews ?? new PendingPreviews(PREVIEW_TTL_MS);
    this.dryRun = deps.dryRun ?? false;
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
   * ConsentRequiredError). Best-effort: a Slack hiccup never replaces the typed error. The blocks
   * show provider/method/host+path and NEVER the request body (SEC-1); the buttons carry only the
   * pending-approval id (SEC-3 — authority is re-decided server-side at the click).
   */
  private notifyApprovalRequired(handle: ConnectionHandle): ConnectionHandle {
    const fetch = handle.fetch.bind(handle);
    handle.fetch = async (input: string, init: RequestInit = {}) => {
      try {
        return await fetch(input, init);
      } catch (e) {
        if (e instanceof ApprovalRequiredError) await this.postApprovalPrompt(e).catch(() => undefined);
        throw e;
      }
    };
    return handle;
  }

  /** Post the Approve/Deny prompt for one pending approval to whoever may decide it. */
  private async postApprovalPrompt(e: ApprovalRequiredError): Promise<void> {
    const blocks = approvalBlocks({
      provider: e.provider, method: e.method, host: e.host, path: e.path, queryParamCount: e.queryParamCount,
      requester: this.identity.userId, id: e.approvalId, approver: e.approver,
    }) as any;
    const text = blocksFallbackText(blocks);
    const threadArg = this.thread ? { thread_ts: this.thread } : {};
    if (e.approver === 'self') {
      if (this.channel) {
        await this.client.chat.postEphemeral({ channel: this.channel, user: this.identity.userId, ...threadArg, blocks, text });
      } else {
        await this.client.chat.postMessage({ channel: this.identity.userId, blocks, text });
      }
      return;
    }
    // 'admin': the channel is the approval surface. Off-channel (a DM) there are no channel admins
    // to prompt — tell the requester why nothing can proceed instead of failing silently (STR-5).
    if (!this.channel) {
      await this.client.chat.postMessage({
        channel: this.identity.userId,
        text: `This ${escapeMrkdwn(e.provider)} action needs an admin's approval — run it in a channel so an admin can approve it.`,
      });
      return;
    }
    const approvers = await this.eligibleApprovers();
    for (const admin of approvers) {
      await this.client.chat.postEphemeral({ channel: this.channel, user: admin, ...threadArg, blocks, text }).catch(() => undefined);
    }
    if (!approvers.length) {
      // No eligible admin visible from here (fail-closed member/admin reads): the requester should
      // know the request is parked, not silently dropped.
      await this.client.chat.postEphemeral({
        channel: this.channel, user: this.identity.userId, ...threadArg,
        text: `This ${escapeMrkdwn(e.provider)} action needs an admin's approval, but no eligible admin was found in this channel.`,
      }).catch(() => undefined);
    }
  }

  /**
   * Channel members who may decide an 'admin' approval: the SAME eligibility rule as every channel
   * config mutation (adminEligible — custom override, else workspace admin OR the channel creator
   * when opted in). Fail-closed reads: an unreadable member list yields nobody.
   */
  // ponytail: linear scan of members × one users.info each; fine for normal channels. Cache admin
  // flags with a short TTL if a huge channel makes this hot.
  private async eligibleApprovers(): Promise<string[]> {
    const out: string[] = [];
    for (const userId of await listChannelMembers(this.client, this.channel!)) {
      if (await adminEligible(this.client, userId, this.identity.teamId, this.channel!, this.adminCheck, this.allowChannelCreatorConfig)) {
        out.push(userId);
      }
    }
    return out;
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

  /**
   * The Bolt-side deny mapping of the shared authorizeProvider CHECK (audit row + policy_denied emit
   * + user-safe error) — ONE mapping for connect() and preview(), so the credential path and the
   * output path enforce and report the same decision. connectChannel keeps its own variant of this
   * mapping because its audit meta carries owner:'channel'.
   */
  private async requireProviderAuthorized(providerId: string): Promise<void> {
    const denial = await authorizeProvider(this.policy, this.channelTools, this.identity, this.channel, providerId);
    if (denial === 'policy') {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel });
      this.emit({ type: 'policy_denied', provider: providerId });
      throw new Error(`Policy denies "${providerId}" in this channel.`);
    }
    if (denial === 'tool-disabled') {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel, reason: 'tool-disabled' });
      throw new Error(`"${providerId}" is not enabled in this channel.`);
    }
  }

  async connect(providerId: string): Promise<ConnectionHandle> {
    // Refuse service-to-service tools BEFORE any consent flow — no Connect prompt, no vault lookup.
    const provider = this.brokerable(providerId);

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

    // Thread-scoped session: when the channel sets this provider to 'session', the user's token is usable
    // only inside the Slack thread they approved it in. The fail-closed rule lives in resolveCredentialOwner
    // (shared with the broker so the two can't drift); this branch maps the signal to Slack's surface — an
    // in-thread approval button, or the off-thread refusal. Checked before the stored-connection shortcut,
    // so being connected once still needs per-thread approval.
    if (mode === 'session') {
      const hasSessionGrant = !!(this.channel && this.thread && this.sessions &&
        (await this.sessions.isGranted(this.identity, this.channel, this.thread, providerId)));
      const r = resolveCredentialOwner({
        path: 'user', mode, principal: this.identity, channel: this.channel, thread: this.thread, hasSessionGrant,
      });
      if (r.status === 'needs_session') {
        if (r.reason === 'no-thread') {
          await this.audit.record('denied', this.identity, providerId, { channel: this.channel, reason: 'no-thread' });
          throw new Error(`"${providerId}" needs a thread-scoped session; ask me inside a thread.`);
        }
        await this.postSessionApprovalPrompt(providerId, this.thread!);
        await this.audit.record('session', this.identity, providerId, { channel: this.channel, thread: this.thread, event: 'prompt' });
        throw new SessionApprovalRequiredError(providerId);
      }
      // resolved → fall through to the stored-credential / consent tail below (as before).
    }

    if (await this.vault.get(userOwner(this.identity), providerId)) {
      return this.notifyApprovalRequired(this.notifyRateLimited(new ConnectionHandle(
        provider, userOwner(this.identity), this.identity, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
        this.channel, // origin channel: attribute this user's usage to the channel it happened in (stats)
        this.rateLimits,
        this.health,
        this.approvals,
        this.thread,
        this.dryRun,
      )));
    }

    // Key providers have no OAuth: post a self-service "set up your key" prompt instead.
    if (provider.credential === 'key') {
      await this.postKeySetupPrompt(providerId);
      this.emit({ type: 'connect_prompted', provider: providerId });
      throw new ConsentRequiredError(providerId);
    }

    const { authorizeUrl } = await this.consent.begin(
      this.identity,
      provider,
      this.redirectUri,
      this.channel,
    );
    await this.postConnectPrompt(providerId, authorizeUrl);
    this.emit({ type: 'connect_prompted', provider: providerId });
    throw new ConsentRequiredError(providerId);
  }

  /**
   * Store the acting user's OWN static key for `providerId` (key providers). Self-service,
   * NOT admin-gated (it's the user's own credential), keyed to `userOwner`. Leak-safe: the
   * secret never enters audit meta, the return value, or any error string.
   */
  async setUserSecret(providerId: string, secret: string): Promise<void> {
    this.brokerable(providerId);
    await this.vault.upsert(userOwner(this.identity), providerId, {
      accessToken: secret, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    }, undefined, (tx) => this.audit.record(
      'config',
      this.identity,
      providerId,
      { owner: 'user', kind: 'secret' },
      undefined,
      tx,
    ));
  }

  /** Point the acting user's OWN credential at an external secret manager (self-service). */
  async referenceUserSecret(
    providerId: string,
    r: { source?: string; secretRef: string; scopes?: string },
  ): Promise<void> {
    const provider = this.brokerable(providerId);
    const reference = normalizeSecretReference(r, this.resolvers, provider.scopesDefault);
    await referenceUserCredential({
      vault: this.vault, audit: this.audit, identity: this.identity, providerId, reference,
    });
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
    this.brokerable(providerId); // validate provider exists + refuse service tools
    const { cfg, channel } = this.channelTarget();
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    await configureChannelCredential({
      vault: this.vault,
      audit: this.audit,
      channelConfig: cfg,
      identity: this.identity,
      channel,
      providerId,
      credential: {
        kind: 'secret',
        token: { accessToken: secret, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null },
      },
      modeConflict: (mode) => {
        throw new UserFacingError(`Channel is set to ${escapeMrkdwn(mode)} for "${escapeMrkdwn(providerId)}"; static keys are not allowed.`);
      },
    });
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
    const provider = this.brokerable(providerId);
    const { cfg, channel } = this.channelTarget();
    const reference = normalizeSecretReference(r, this.resolvers, provider.scopesDefault);
    await referenceChannelCredential({
      vault: this.vault, audit: this.audit, channelConfig: cfg, identity: this.identity,
      channel, providerId, reference,
      authorize: () => this.requireAdmin(providerId),
      assertEligible: () => this.assertChannelEligible(),
      modeConflict: (mode) => {
        throw new UserFacingError(
          `Channel is set to ${escapeMrkdwn(mode)} for "${escapeMrkdwn(providerId)}"; shared references are not allowed.`,
        );
      },
    });
  }

  /**
   * Set the channel's auth mode for a provider. Admin-only, audited. Flipping to a user-owned mode
   * (`'per-user'` or `'session'`) removes any live shared cred (a re-own that must be re-authorized;
   * the admin gate is that authorization). Members then use their own creds via `connect()`.
   */
  async setChannelMode(providerId: string, mode: ChannelMode): Promise<void> {
    this.brokerable(providerId);
    const { cfg, channel } = this.channelTarget();
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    await setChannelCredentialMode({
      vault: this.vault,
      audit: this.audit,
      channelConfig: cfg,
      identity: this.identity,
      channel,
      providerId,
      mode,
    });
  }

  /**
   * Set the channel's preview visibility for a provider ('private' = agent output goes only to the
   * requester, with a Share action). Admin-only, audited — the same gate as setChannelMode. A
   * rendering policy, not a credential one, so no channel-eligibility check and no `brokerable`
   * refusal: a service tool's output can leak in a thread exactly like a brokered one's.
   */
  async setChannelVisibility(providerId: string, visibility: PreviewVisibility): Promise<void> {
    this.registry.get(providerId); // validate BEFORE persist/audit (SEC-4): throws on an unknown id
    const { cfg, owner, channel } = this.channelTarget();
    await this.requireAdmin(providerId);
    await cfg.setVisibility(owner.teamId, channel, providerId, visibility);
    await this.audit.record('config', this.identity, providerId, { owner: 'channel', channel, visibility });
  }

  /**
   * Post provider-derived agent output ('title' + 'lines') honoring the channel's preview
   * visibility for `providerId`:
   *  - 'public' (default) → a normal message in the channel (threaded when in a thread).
   *  - 'private'          → ephemeral to the requester with Share/Dismiss buttons; the rendered
   *    content is held in memory (see PendingPreviews) so a Share click reposts exactly what the
   *    human reviewed, publicly attributed to them.
   * Outside a channel (a DM with the agent) there is no one to leak to: always a direct post.
   * Returns which path ran so the host can stop its turn ('private') vs continue ('posted').
   */
  async preview(providerId: string, content: { title: string; lines: string[] }): Promise<'posted' | 'private'> {
    this.registry.get(providerId); // unknown provider ids never reach a message or the preview store
    const p = escapeMrkdwn(providerId); // top-level Slack text is parsed mrkdwn too (SEC-5)
    // Output rides the SAME authorization as credential use (the shared CHECK, same audit/deny mapping
    // as connect()): a policy-denied or tool-disabled provider must not get its output posted through
    // Vouchr's preview surface either — otherwise the manifest's `enabled` would be a lie here.
    await this.requireProviderAuthorized(providerId);
    // Normalize ONCE to exactly what rendering shows (blank lines dropped, caps applied), so the
    // pending store never retains provider text the recipient couldn't actually have reviewed.
    const c = normalizePreviewContent(providerId, content);
    const visibility = this.channel && this.channelConfig
      ? await this.channelConfig.getVisibility(this.identity.teamId, this.channel, providerId)
      : 'public';
    if (visibility === 'private' && this.channel) {
      const id = this.previews.put({
        teamId: this.identity.teamId, userId: this.identity.userId, channel: this.channel,
        thread: this.thread, provider: providerId, title: c.title, lines: c.lines,
      });
      await this.client.chat.postEphemeral({
        channel: this.channel,
        user: this.identity.userId,
        ...(this.thread ? { thread_ts: this.thread } : {}),
        blocks: previewBlocks({
          provider: providerId, title: c.title, lines: c.lines, id,
          where: this.thread ? 'thread' : 'channel', ttlMinutes: Math.round(PREVIEW_TTL_MS / 60_000),
        }) as any,
        text: `Private ${p} preview (only visible to you)`,
      });
      return 'private';
    }
    await this.client.chat.postMessage({
      channel: this.channel ?? this.identity.userId,
      ...(this.thread ? { thread_ts: this.thread } : {}),
      blocks: previewPostBlocks({ provider: providerId, title: c.title, lines: c.lines }) as any,
      // Fallback/notification text is PARSED mrkdwn, not blocks: a provider-derived title there could
      // fire a <!channel> or forge a mention (SEC-5). Neutral constant + the registry-validated id only.
      text: `${p} preview`,
    });
    return 'posted';
  }

  /**
   * Return a leak-safe handle for the CHANNEL's shared credential for `providerId`. The handle
   * keys the vault on the channel but audits as the acting human (invariant 9). Throws if the
   * channel is per-user-locked or has no shared cred configured.
   */
  async connectChannel(providerId: string): Promise<ConnectionHandle> {
    const provider = this.brokerable(providerId);
    const { cfg, owner, channel } = this.channelTarget();
    // Same authorization gate as connect() (the shared core CHECK): a deny applies to shared channel
    // creds too. Audit meta carries owner:'channel' here; like connect(), no policy_denied on tool-disabled.
    const denial = await authorizeProvider(this.policy, this.channelTools, this.identity, this.channel, providerId);
    if (denial === 'policy') {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel, owner: 'channel' });
      this.emit({ type: 'policy_denied', provider: providerId });
      throw new Error(`Policy denies "${providerId}" in this channel.`);
    }
    if (denial === 'tool-disabled') {
      await this.audit.record('denied', this.identity, providerId, { channel, owner: 'channel', reason: 'tool-disabled' });
      throw new Error(`"${providerId}" is not enabled in this channel.`);
    }
    const m = await cfg.getMode(owner.teamId, channel, providerId);
    if (m != null && m !== 'shared') {
      throw new Error(`Channel "${channel}" uses ${m} credentials for "${providerId}"; use connect() instead.`);
    }
    if (!(await this.vault.get(owner, providerId))) {
      throw new Error(`No channel credential configured for "${providerId}" in this channel.`);
    }
    // Governance (opt-in): a shared cred is only usable by an actual channel member. Fail-closed.
    // isChannelMember returns false on any error, so an unverifiable membership refuses the cred.
    if (this.requireMembership && !(await isChannelMember(this.client, channel, this.identity.userId))) {
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
    if (r.status !== 'resolved') throw new Error(`No channel credential configured for "${providerId}" in this channel.`);
    // originChannel keeps its default (null): the channel-owned cred is attributed to its owning channel.
    return this.notifyApprovalRequired(this.notifyRateLimited(new ConnectionHandle(
      provider, r.owner, r.acting, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
      null, this.rateLimits, this.health, this.approvals, this.thread, this.dryRun,
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

  /** Ephemeral in-thread prompt to approve a thread-scoped session. Only the acting user sees it.
   *  Caller guarantees we're in a channel + thread. */
  private async postSessionApprovalPrompt(providerId: string, thread: string): Promise<void> {
    const blocks = sessionApprovalBlocks(providerId, thread);
    await this.client.chat.postEphemeral({
      channel: this.channel!,
      user: this.identity.userId,
      thread_ts: thread,
      blocks: blocks as any,
      text: blocksFallbackText(blocks),
    });
  }

  /** Ephemeral JIT prompt for a key provider: a button that opens the per-user key modal. */
  private async postKeySetupPrompt(providerId: string): Promise<void> {
    const blocks = keySetupBlocks(providerId);
    const text = blocksFallbackText(blocks);
    if (this.channel) {
      await this.client.chat.postEphemeral({ channel: this.channel, user: this.identity.userId, blocks: blocks as any, text });
    } else {
      await this.client.chat.postMessage({ channel: this.identity.userId, blocks: blocks as any, text });
    }
  }

  private async postConnectPrompt(providerId: string, url: string): Promise<void> {
    const provider = this.registry.get(providerId);
    const blocks = connectBlocks(providerId, url, {
      list: provider.scopesDefault,
      describe: provider.scopeDescriptions,
    });
    const fallback = optionalBlockFallback(blocks);
    if (this.channel) {
      await this.client.chat.postEphemeral({
        channel: this.channel,
        user: this.identity.userId,
        blocks: blocks as any,
        ...fallback,
      });
    } else {
      await this.client.chat.postMessage({
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
 * anywhere. The refresh_dead reconnect button is an ACTION (RECONNECT_ACTION), not a baked-in
 * authorize URL: a consent state lives 10 minutes and this DM may be read hours later, so the
 * state is minted fresh on click (see the handler in registerCommands) — otherwise the 24h
 * debounce would leave a dead link with no recovery path. Exported for tests; createVouchr wires
 * it with the same client resolution the post-OAuth confirmation DM uses.
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
    const provider = deps.registry.get(e.provider);
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
        text = `Your ${p} connection stopped working and needs to be reconnected.`;
        const intro = { type: 'section', text: { type: 'mrkdwn', text: `:warning: Your *${p}* connection stopped working and needs to be reconnected.` } };
        // Key providers have no OAuth authorize URL: reuse the key-setup prompt instead. (Today only
        // OAuth creds can refresh at all, so this branch is defensive symmetry, not a live path.)
        blocks = provider.credential === 'key'
          ? [intro, ...keySetupBlocks(e.provider)]
          : [intro, {
              type: 'actions',
              elements: [{
                type: 'button',
                text: { type: 'plain_text', text: `Connect ${e.provider}`, emoji: true },
                action_id: RECONNECT_ACTION,
                value: e.provider, // forgeable — the click handler re-validates against the registry
                style: 'primary',
              }],
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
  const vault = new Vault(db, key, opts.ttl ?? DEFAULT_TTL, opts.envelope);
  // #116: in dry-run EVERY audit row (connect, inject, denied, config, …) carries meta.dry_run.
  const audit = dryRun ? dryRunAudit(new Audit(db)) : new Audit(db);
  const consent = new Consent(db, dryRun);
  const channelConfig = new ChannelConfig(db);
  const channelTools = new ChannelTools(db);
  const sessions = new SessionGrants(db);
  const approvals = new Approvals(db); // #113 per-action approval requests/grants (provider.approval)
  // The 'session' channel mode drives whether a thread grant is required; this is just the TTL ceiling.
  const sessionTtlMs = opts.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  const providerIds = opts.providers.map((p) => p.id); // for toolManifest(); mirrors the registry
  const policy = opts.policy ?? new Policy();
  const resolvers = opts.resolvers ?? {};
  const referenceSources = SECRET_REFERENCE_SOURCES.filter(
    (source) => Object.hasOwn(resolvers, source) && typeof resolvers[source] === 'function',
  );
  const botToken = opts.botToken ?? process.env.SLACK_BOT_TOKEN;
  const confirmClient = botToken ? new WebClient(botToken) : null;
  const inflight = new Map<string, Promise<string | null>>(); // shared single-flight refresh map
  // Shared per-(owner, provider) rate-limit buckets (provider.rateLimit); per-process by default.
  const rateLimits: RateLimitStore = opts.rateLimitStore ?? new MemoryRateLimitStore();
  const previews = new PendingPreviews(PREVIEW_TTL_MS); // pending private previews (share/dismiss)
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
    (await vault.listForUser(identity))
      .filter((c) => { try { return isBrokeredProvider(registry.get(c.provider)); } catch { return true; } })
      .map((c) => ({ provider: c.provider, channel: null, account: c.externalAccount }))
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
    client: WebClient, identity: SlackIdentity, channel: string, provider: string, on: boolean,
  ): Promise<'ok' | 'denied'> => {
    if (!(await commandAdmin(client, identity, channel))) {
      await audit.record('denied', identity, provider, { reason: 'not-admin', owner: 'channel', channel });
      return 'denied';
    }
    // Channel-class eligibility at the MUTATION, not just at render (SEC-3: the render hiding
    // controls for an archived/ext-shared channel is UI, not authorization; a forged payload — or a
    // slash command — must hit the same wall). Ordered after the admin gate and throwing a
    // UserFacingError with no audit row, exactly mirroring setChannelMode.
    await assertChannelEligible(client, channel);
    await channelTools.applyEnabled(identity.teamId, channel, [[provider, on]], providerIds);
    await audit.record('config', identity, provider, { owner: 'channel', channel, tool: on ? 'enabled' : 'disabled' });
    return 'ok';
  };

  /** STR-3: the admin gate + denial audit in front of the channel-credential modal, shared by
   *  `/vouchr configure` and the App Home Configure button. Same caller contract as
   *  setChannelToolEnabled: provider registry-validated, channel verified, BEFORE any audit write.
   *  Also refuses ineligible channel classes up front (same rule the submit re-asserts at the
   *  write), so a forged click can't even open the modal for an archived/ext-shared channel. */
  const openConfigureModal = async (
    client: WebClient, identity: SlackIdentity, channel: string, provider: string, triggerId: string,
  ): Promise<'ok' | 'denied'> => {
    if (!(await commandAdmin(client, identity, channel))) {
      await audit.record('denied', identity, provider, { reason: 'not-admin', owner: 'channel', channel });
      return 'denied';
    }
    await assertChannelEligible(client, channel); // throws UserFacingError, mirrors setChannelMode
    try {
      await client.views.open({
        trigger_id: triggerId,
        view: configureModal(provider, channel, referenceSources) as any,
      });
    } catch {
      // Expired trigger_id / transient Slack error: tell the actor instead of dying silently.
      await dmActor(client, identity, `Couldn't open the ${escapeMrkdwn(provider)} credential modal (the button may have expired). Try again.`);
    }
    return 'ok';
  };

  /**
   * The WebClient used to post the post-OAuth confirmation DM. With an installationStore,
   * resolve the connecting user's own workspace bot token via fetchInstallation; without one,
   * fall back to the single env/opts token (unchanged behavior). The DM is best-effort, so a
   * missing install just means no nudge. Never throw, and never log the token.
   */
  async function confirmClientFor(identity: SlackIdentity): Promise<WebClient | null> {
    if (!opts.installationStore) return confirmClient;
    try {
      const inst = await opts.installationStore.fetchInstallation({
        teamId: identity.teamId,
        enterpriseId: identity.enterpriseId ?? undefined,
        isEnterpriseInstall: false,
      });
      return inst.bot?.token ? new WebClient(inst.bot.token) : null;
    } catch {
      return null;
    }
  }

  // #117 credential-health wiring. Default: DM the owner (healthNotifier), via the same per-workspace
  // client resolution as the post-OAuth confirmation DM, debounced by the persistent notification_state
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
        previews,
        dryRun,
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
          return res
            .status(result.status)
            .set({ 'content-type': 'text/plain; charset=utf-8', 'x-content-type-options': 'nosniff' })
            .send(result.error);
        }
        emit({ type: 'connected', provider: result.provider });

        // Best-effort nudge back into Slack, from the connecting user's own workspace.
        const client = await confirmClientFor(result.identity);
        if (client) {
          await client.chat
            .postMessage({
              channel: result.identity.userId,
              // SEC-5: connectedDmText escapes the provider-reported account label.
              text: connectedDmText(result.provider, result.account),
            })
            .catch(() => undefined);
        }
        res.set('content-type', 'text/html').send(connectedHtml(result.provider, result.account, result.scopes));
      } catch {
        // Express doesn't catch async rejections; an unhandled one here hangs the browser.
        res.status(500).send('Connection failed. Please try again.');
      }
    });
  }

  /** Build a per-request ConnectContext bound to a specific channel (for the modal submit). */
  function contextFor(identity: SlackIdentity, channel: string | null, client: WebClient): ConnectContext {
    return new ConnectContext({
      identity, channel, client, registry, vault, audit, consent, policy, redirectUri, resolvers,
      channelConfig, channelTools, inflight, rateLimits, sink, providerIds,
      adminCheck: opts.isAdmin, allowChannelCreatorConfig,
      requireMembership: opts.requireChannelMembership ?? false,
      thread: null, sessions, approvals, auditSink, health, previews, dryRun,
    });
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
            .map((m) => `• *${escapeMrkdwn(m.provider)}*: ${m.enabled ? 'enabled' : 'disabled'}${m.mode ? ` (${escapeMrkdwn(m.mode)})` : ''}${m.visibility === 'private' ? ' · private previews (:lock:)' : ''}`)
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
          if ((await setChannelToolEnabled(client, identity, command.channel_id, arg, on)) === 'denied') {
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
          await contextFor(identity, command.channel_id, client).setChannelMode(arg, arg2);
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        return respond(`Set *${escapeMrkdwn(arg)}* to *${escapeMrkdwn(arg2)}* in <#${escapeMrkdwn(command.channel_id)}>.`);
      }

      // Per-channel preview visibility: private = agent output goes only to the requester, with an
      // explicit Share button. Admin-gated + audited in setChannelVisibility (same gate as `mode`).
      if (sub === 'preview') {
        if (words.length !== 3 || !arg || !isPreviewVisibility(arg2)) {
          return respond('Usage: `/vouchr preview <provider> <public|private>`');
        }
        if (!registry.has(arg)) return respond(UNKNOWN_PROVIDER_TEXT);
        if (!command.channel_id) return respond('Run `/vouchr preview` from inside the channel you want to configure.');
        try {
          await contextFor(identity, command.channel_id, client).setChannelVisibility(arg, arg2);
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        return respond(arg2 === 'private'
          ? `Set *${escapeMrkdwn(arg)}* previews to *private* in <#${escapeMrkdwn(command.channel_id)}>: results go only to whoever asked, with a Share button.`
          : `Set *${escapeMrkdwn(arg)}* previews to *public* in <#${escapeMrkdwn(command.channel_id)}>.`);
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
          if ((await openConfigureModal(client, identity, command.channel_id, arg, command.trigger_id)) === 'denied') {
            return respond(adminOnly(allowChannelCreatorConfig, 'configure channel credentials'));
          }
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
          outcome = await disconnectProvider(vault, audit, registry, identity, arg);
        } catch {
          // A thrown failure means the local delete itself is uncertain. Never echo DB/KMS/provider
          // text; give one state-agnostic way to discover the committed outcome (#194 UX-1/5).
          return respond('Could not confirm whether the account was disconnected. Run `/vouchr status` to check; if it is still listed, try again.');
        }
        if (!outcome.recognized) return respond(UNKNOWN_DISCONNECT_PROVIDER_TEXT);
        const p = escapeMrkdwn(arg); // recognized current/stored id; still escape at render (SEC-5)
        if (!outcome.removed) return respond(`You have no connected *${p}* account, so there was nothing to disconnect.`);
        emit({ type: 'revoked', provider: arg, ok: outcome.ok });
        if (!outcome.audited && outcome.ok) {
          return respond(`Disconnected *${p}* locally, but Vouchr could not confirm the audit record. Ask an admin to check the Vouchr logs.`);
        }
        return respond(outcome.ok
          ? `Disconnected *${p}*. The agent can no longer act as you on ${p}.`
          : `Disconnected *${p}* locally, but the upstream token revoke could not be confirmed. Revoke or rotate Vouchr’s access in ${p} directly.`);
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
      const identity = resolveIdentity({ body });
      let channel = '';
      let provider = '';
      try {
        ({ channel = '', provider } = JSON.parse(view.private_metadata));
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
      if (kind === 'channel' && (typeof channel !== 'string' || !channel)) {
        return ack({ response_action: 'errors', errors: { [ref ? 'ref' : 'raw']: 'No channel was selected. Reopen the modal.' } });
      }
      if (typeof provider !== 'string' || !registry.has(provider) || !isBrokeredProvider(registry.get(provider))) {
        return ack({ response_action: 'errors', errors: { [ref ? 'ref' : 'raw']: 'Credential setup is unavailable. Reopen the modal.' } });
      }
      if (ref) {
        try {
          const definition = registry.get(provider);
          normalizeSecretReference({ secretRef: ref }, resolvers, definition.scopesDefault);
        } catch (e) {
          return ack({ response_action: 'errors', errors: { ref: safeUserMessage(e) } });
        }
      }
      await ack({
        response_action: 'update',
        view: privateStatusModal(
          'Saving credential',
          'Vouchr is saving this credential. If no result appears here, reopen credential setup to review the current state before retrying.',
        ),
      });

      const ctx = contextFor(identity, kind === 'channel' ? channel : null, client);
      try {
        if (kind === 'channel') {
          if (ref) await ctx.referenceChannelSecret(provider, { secretRef: ref });
          else await ctx.setChannelSecret(provider, raw);
        } else {
          if (ref) await ctx.referenceUserSecret(provider, { secretRef: ref });
          else await ctx.setUserSecret(provider, raw);
        }
      } catch (e) {
        const p = escapeMrkdwn(provider);
        const target = kind === 'channel' ? `the *${p}* channel credential` : `your *${p}* credential`;
        await deliverModalOutcome(
          client,
          identity,
          view,
          'Save not confirmed',
          `Could not save ${target}. ${safeUserMessage(e)} Reopen credential setup and try again.`,
        );
        return;
      }
      // Private confirmation DM (no secret), just the fact it was set.
      const p = escapeMrkdwn(provider);
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
      // mode+enabled+preview checkboxes, meaningless for them). The App Home instead renders every
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
        visibility: t.visibility,
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
      const openVisibility = new Map(open.map((o) => [o.p, o.v ?? 'public']));

      // Collect the submitted state per provider up front, so mode + enabled are each diffed against
      // their OPEN-TIME value rather than the current store.
      const values = view.state?.values ?? {};
      const submittedMode = new Map<string, unknown>();
      const submittedEnabled = new Map<string, boolean>();
      const submittedVisibility = new Map<string, PreviewVisibility>();
      for (const [blockId, v] of Object.entries<any>(values)) {
        if (blockId.startsWith('mode:')) submittedMode.set(blockId.slice(5), v?.mode?.selected_option?.value);
        else if (blockId.startsWith('tool:')) {
          const options = v?.enabled?.selected_options;
          submittedEnabled.set(blockId.slice(5), Array.isArray(options) && options.some((o: any) => o?.value === 'enabled'));
        } else if (blockId.startsWith('preview:')) {
          const options = v?.visibility?.selected_options;
          submittedVisibility.set(blockId.slice(8), Array.isArray(options) && options.some((o: any) => o?.value === 'private') ? 'private' : 'public');
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

      const ctx = contextFor(identity, channel, client);
      let confirmed = 0;
      let unconfirmed = 0;

      // ── mode: apply only where the admin actually changed the select (submitted !== open-time) ──
      for (const [provider, mode] of submittedMode) {
        if (!registry.has(provider) || !isChannelMode(mode)) continue; // forged/invalid → ignore
        if (mode === (openMode.get(provider) ?? null)) continue; // untouched (or reset to the same) → skip
        try { await ctx.setChannelMode(provider, mode); confirmed++; } catch { unconfirmed++; }
      }

      // ── preview visibility: same open-time-diff contract as mode ──
      for (const [provider, visibility] of submittedVisibility) {
        if (!registry.has(provider)) continue; // forged/invalid → ignore
        if (visibility === (openVisibility.get(provider) ?? 'public')) continue; // untouched → skip
        try { await ctx.setChannelVisibility(provider, visibility); confirmed++; } catch { unconfirmed++; }
      }

      // ── enabled: the tool allowlist. Only the controls the admin actually changed (submitted !==
      // open-time) are applied; the write — including the first-write allowlist materialization that
      // keeps untouched providers from vanishing, and the configured-ness decision itself — is ONE
      // atomic core mutation (ChannelTools.applyEnabled), so a concurrent admin or a mid-write
      // failure can never leave a partial allowlist. Audit only the providers that actually changed. ──
      const enabledChanged = [...submittedEnabled].filter(([p]) => registry.has(p) && submittedEnabled.get(p) !== (openEnabled.get(p) ?? true));
      if (enabledChanged.length) {
        try {
          await channelTools.applyEnabled(identity.teamId, channel, enabledChanged, providerIds);
          for (const [p, e] of enabledChanged) {
            await audit.record('config', identity, p, { owner: 'channel', channel, tool: e ? 'enabled' : 'disabled' });
          }
          confirmed += enabledChanged.length;
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
        await contextFor(identity, channel, client).setChannelMode(provider, mode);
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
      await ack();
      if (body.view?.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const m = /^(enable|disable):(.+)$/.exec(String(body.actions?.[0]?.value ?? ''));
      if (!m || !registry.has(m[2])) return; // SEC-4: registry-validate before anything is written
      const channel = await verifiedHomeChannel(client, body);
      if (!channel) return staleChannelFeedback(client, identity);
      try {
        if ((await setChannelToolEnabled(client, identity, channel, m[2], m[1] === 'enable')) === 'denied') {
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
      await ack();
      if (body.view?.callback_id !== HOME_CALLBACK) return;
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const provider = body.actions?.[0]?.value;
      if (typeof provider !== 'string' || !registry.has(provider) || !body.trigger_id) return;
      const channel = await verifiedHomeChannel(client, body);
      if (!channel) return staleChannelFeedback(client, identity);
      try {
        if ((await openConfigureModal(client, identity, channel, provider, body.trigger_id)) === 'denied') {
          await dmActor(client, identity, adminOnly(allowChannelCreatorConfig, 'configure channel credentials')); // denial audited inside
        }
      } catch (e) {
        await dmActor(client, identity, safeUserMessage(e)); // ineligible channel class → the core reason
      }
    });

    // Disconnect the acting user's own connection from a Disconnect button IN VOUCHR'S OWN surfaces —
    // the config modal (refresh via views.update) or the App Home (#111, refresh via views.publish).
    // Scoped to OUR callback_ids: the DISCONNECT_ACTION id is also EXPORTED for hosts who embed
    // disconnectConfirmBlocks in their OWN surfaces and register their own listener — Bolt runs every
    // matching listener, so acting on a foreign view/message here would double-fire disconnectProvider
    // (duplicate audit/revoke) and clobber the host's view. When it isn't ours we ack and defer.
    app.action(DISCONNECT_ACTION, async ({ ack, body, client }: any) => {
      await ack();
      const surface = body.view?.callback_id === CONFIG_CALLBACK ? 'modal'
        : body.view?.callback_id === HOME_CALLBACK ? 'home' : null;
      if (!surface) return; // not our view → the host owns this action
      const identity = resolveIdentity({ body });
      const provider = body.actions?.[0]?.value;
      if (!identity || typeof provider !== 'string') return;
      // Core accepts a current registry id or this user's exact stored stale row, and rejects every
      // forged/unknown value before mutation/audit. That keeps retired credentials removable from
      // status/config surfaces without trusting the button payload (SEC-3/SEC-4).
      let outcome: Awaited<ReturnType<typeof disconnectProvider>> | undefined;
      try {
        outcome = await disconnectProvider(vault, audit, registry, identity, provider);
      } catch {
        await dmActor(client, identity, 'Could not confirm whether the account was disconnected. Run `/vouchr status` to check; if it is still listed, try again.');
      }
      if (outcome?.recognized) {
        const p = escapeMrkdwn(provider);
        if (outcome.removed) emit({ type: 'revoked', provider, ok: outcome.ok });
        if (outcome.removed && !outcome.ok) {
          await dmActor(client, identity, `Disconnected *${p}* locally, but the upstream token revoke could not be confirmed. Revoke or rotate Vouchr’s access in ${p} directly.`);
        } else if (outcome.removed && !outcome.audited) {
          await dmActor(client, identity, `Disconnected *${p}* locally, but Vouchr could not confirm the audit record. Ask an admin to check the Vouchr logs.`);
        } else if (outcome.removed) {
          // A modal/Home refresh is best effort and may fail after the destructive mutation has
          // committed. Always send one explicit receipt so a failed refresh never leaves the click
          // looking ignored (#194 UX-1/5).
          await dmActor(client, identity, `Disconnected *${p}*. The agent can no longer act as you on ${p}.`);
        } else {
          // A duplicate click is still a valid interaction. It owns no mutation/event/audit, but it
          // must receive one idempotent receipt even if the subsequent view refresh also fails.
          await dmActor(client, identity, `No *${p}* account was connected, so there was nothing to disconnect.`);
        }
      } else if (outcome) {
        // This is either a forged value or the losing half of a concurrent click on a retired row.
        // Do not reflect the unvalidated value; one fixed receipt keeps the valid race non-silent.
        await dmActor(client, identity, 'That connection no longer exists. Run `/vouchr status` to see your current connections.');
      }
      const channel = homeSelectedChannel(body.view);
      if (surface === 'home') return publishHome(identity, client, channel);
      await client.views.update({ view_id: body.view.id, view: await buildConfigModal(identity, channel, client) }).catch(() => undefined);
    });

    // Per-user key setup: ephemeral button → private modal (self-service, not admin-gated).
    app.action(SETUP_KEY_ACTION, async ({ ack, body, client }: any) => {
      await ack();
      const identity = resolveIdentity({ body });
      const provider = body.actions?.[0]?.value;
      const recover = () => identity
        ? dmActor(client, identity, 'This credential setup button is no longer valid. Ask the agent to request setup again.')
        : Promise.resolve();
      if (typeof provider !== 'string' || !body.trigger_id || !registry.has(provider)) return recover();
      if (!isBrokeredProvider(registry.get(provider))) return recover();
      try {
        await client.views.open({
          trigger_id: body.trigger_id,
          view: userKeyModal(provider, referenceSources),
        });
      } catch {
        await recover();
      }
    });

    // #117 refresh_dead DM's Connect button: mint a FRESH single-use consent state on click and
    // swap the DM for the normal connect prompt. Late-minting is the point — a state lives 10
    // minutes (STATE_TTL_MS) and the DM may sit unread for hours, and the 24h DM debounce means a
    // dead baked-in link would have no recovery path. The button value is forgeable (SEC-3/SEC-4):
    // validate it against the registry before anything, and mint for the ACTING user from the
    // Slack-verified payload — exactly what that user could do themselves via connect().
    app.action(RECONNECT_ACTION, async ({ ack, body, respond }: any) => {
      await ack();
      const identity = resolveIdentity({ body });
      const providerId = body.actions?.[0]?.value;
      if (!identity || typeof providerId !== 'string' || !registry.has(providerId)) return;
      const provider = registry.get(providerId);
      // No OAuth to mint for service/key tools (the DM never offers this button for them; forged-safe).
      if (provider.identity === 'service' || provider.credential === 'key') return;
      const { authorizeUrl } = await consent.begin(identity, provider, redirectUri, null);
      emit({ type: 'connect_prompted', provider: providerId });
      if (respond) {
        const blocks = connectBlocks(providerId, authorizeUrl, { list: provider.scopesDefault, describe: provider.scopeDescriptions });
        await respond({
          replace_original: true,
          ...optionalBlockFallback(blocks),
          blocks: blocks as any,
        });
      }
    });

    // Thread-scoped session approval: the user clicks "Allow … here" → grant for THIS thread only.
    // provider + thread come from the (verified) button value; channel/user/team from the payload.
    app.action(APPROVE_SESSION_ACTION, async ({ ack, body, respond }: any) => {
      await ack();
      const identity = resolveIdentity({ body });
      if (!identity) return;
      let provider = '', thread = '';
      try { ({ provider, thread } = JSON.parse(body.actions?.[0]?.value ?? '{}')); } catch { return; }
      const channel: string | undefined = body.channel?.id ?? body.container?.channel_id;
      if (!provider || !thread || !channel || !registry.has(provider)) return;
      await sessions.grant(identity, channel, thread, provider, sessionTtlMs);
      await audit.record('session', identity, provider, { channel, thread, event: 'grant' });
      if (respond) await respond({ replace_original: true, text: `✅ Approved *${escapeMrkdwn(provider)}* for this thread. Ask me again.` });
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
      await ack();
      const identity = resolveIdentity({ body });
      const id = body.actions?.[0]?.value;
      if (!identity || typeof id !== 'string' || !id) return;
      const pending = await approvals.get(id);
      // Team binding: a forged id from another workspace must never be decidable here.
      if (!pending || pending.teamId !== identity.teamId) {
        if (respond) await respond({ replace_original: true, text: 'This approval expired or was already decided. Ask the agent again.' });
        return;
      }
      if (!registry.has(pending.provider)) return; // stale row for an unregistered provider (SEC-4)
      const approval = registry.get(pending.provider).approval;
      const eligible = approval?.approver === 'admin'
        ? await commandAdmin(client, identity, pending.channel ?? '')
        : identity.userId === pending.userId; // 'self': exactly the requester, nobody else
      if (!eligible) {
        await audit.record('denied', identity, pending.provider,
          { reason: 'not-approver', ...(pending.channel ? { channel: pending.channel } : {}) });
        if (respond) await respond({ replace_original: false, response_type: 'ephemeral', text: 'You are not eligible to decide this approval.' });
        return;
      }
      const requester: SlackIdentity = { enterpriseId: identity.enterpriseId, teamId: pending.teamId, userId: pending.userId };
      // Same meta shape as the injector's approval rows (STR-4): method + host + pathname, never a
      // body or query value. Row values were egress-validated before they were ever stored (SEC-4).
      const meta = { host: pending.host, method: pending.method, path: pending.path, ...(pending.channel ? { channel: pending.channel } : {}) };
      const p = escapeMrkdwn(pending.provider); // SEC-5, even for a registry-validated id
      // Raw query values are never stored (GHSA-pg84: only their digest is) — the receipt marks
      // that parameters are bound with '?…'; the prompt the decision was made on showed them fully.
      const what = `\`${escapeMrkdwn(pending.method)} ${escapeMrkdwn(pending.host)}${escapeMrkdwn(pending.path)}${pending.queryHash ? '?…' : ''}\``;
      // Requester notification: ephemeral in the request's channel, or a DM when there was none.
      const tellRequester = async (text: string) => {
        if (pending.channel) {
          await client.chat.postEphemeral({ channel: pending.channel, user: pending.userId, ...(pending.thread ? { thread_ts: pending.thread } : {}), text }).catch(() => undefined);
        } else {
          await client.chat.postMessage({ channel: pending.userId, text }).catch(() => undefined);
        }
      };
      if (decision === 'approve') {
        const ttlMs = approval?.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
        if (!(await approvals.approve(id, identity.userId, ttlMs))) return; // concurrently decided: exactly one wins
        await audit.record('approved', requester, pending.provider, meta, identity.userId);
        emit({ type: 'approval_approved', provider: pending.provider, host: pending.host });
        if (respond) await respond({ replace_original: true, text: `✅ Approved ${what} on *${p}*. The approval is single-use and expires in ${Math.round(ttlMs / 1000)}s — have the agent retry now.` });
        if (identity.userId !== pending.userId) {
          await tellRequester(`✅ <@${escapeMrkdwn(identity.userId)}> approved your *${p}* request (${what}) — ask the agent to retry.`);
        }
      } else {
        if (!(await approvals.deny(id))) return; // concurrently decided: exactly one wins
        await audit.record('denied', requester, pending.provider, { ...meta, reason: 'approval-denied' }, identity.userId);
        emit({ type: 'approval_denied', provider: pending.provider, host: pending.host });
        if (respond) await respond({ replace_original: true, text: `🚫 Denied ${what} on *${p}*. Nothing was sent.` });
        if (identity.userId !== pending.userId) {
          await tellRequester(`🚫 <@${escapeMrkdwn(identity.userId)}> denied your *${p}* request (${what}). Nothing was sent.`);
        }
      }
    };
    app.action(APPROVAL_APPROVE_ACTION, (a: any) => handleApprovalDecision(a, 'approve'));
    app.action(APPROVAL_DENY_ACTION, (a: any) => handleApprovalDecision(a, 'deny'));

    // Share a private preview to the channel/thread. The button value is ONLY the claim id; the
    // authorization is the server-side claim in PendingPreviews.take (recipient + team + channel must
    // match what was stored at issue time — SEC-3: every field of the interaction payload is forgeable,
    // so nothing in it is trusted as content or authority). Single-use, like an OAuth `state`.
    app.action(PREVIEW_SHARE_ACTION, async ({ ack, body, respond, client }: any) => {
      await ack();
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const id = typeof body.actions?.[0]?.value === 'string' ? body.actions[0].value : '';
      const channel: string | undefined = body.channel?.id ?? body.container?.channel_id;
      if (!id || !channel) return;
      const p = previews.take(id, { userId: identity.userId, teamId: identity.teamId, channel });
      if (!p) {
        if (respond) await respond({ replace_original: true, text: 'This preview expired. Ask the agent again.' });
        return;
      }
      await client.chat.postMessage({
        channel: p.channel,
        ...(p.thread ? { thread_ts: p.thread } : {}),
        blocks: previewPostBlocks({ provider: p.provider, title: p.title, lines: p.lines, sharedBy: identity.userId }) as any,
        // Neutral fallback: the stored title is provider-derived and fallback text is parsed mrkdwn
        // (SEC-5). p.provider was registry-validated at preview() time; the user id is authenticated.
        text: `${escapeMrkdwn(p.provider)} preview shared by <@${escapeMrkdwn(identity.userId)}>`,
      });
      // The moment private data became public, by whose decision. p.provider is registry-validated
      // (preview() refuses unknown ids), so nothing unvalidated reaches the audit provider column.
      await audit.record('preview', identity, p.provider, { channel: p.channel, thread: p.thread, event: 'shared' });
      if (respond) await respond({ delete_original: true });
    });

    app.action(PREVIEW_DISMISS_ACTION, async ({ ack, body, respond }: any) => {
      await ack();
      const identity = resolveIdentity({ body });
      if (!identity) return;
      const id = typeof body.actions?.[0]?.value === 'string' ? body.actions[0].value : '';
      const channel: string | undefined = body.channel?.id ?? body.container?.channel_id;
      if (id && channel) previews.dismiss(id, { userId: identity.userId, teamId: identity.teamId, channel });
      if (respond) await respond({ delete_original: true });
    });
  }

  /** Remove all of a user's own connections + pending consent + thread sessions (offboarding).
   *  offboardUser clears the session grants (passed through), so the Grid/SCIM path gets it too. */
  function offboard(identity: SlackIdentity): Promise<string[]> {
    return offboardUser(vault, audit, consent, identity, registry, 'offboarded', sessions);
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

  /** Delete every connection past its TTL + clear stale consent + expired thread sessions +
   *  expired approval prompts/grants (#113, audited inside core sweepExpired). Run on a timer. */
  async function sweep(): Promise<number> {
    const n = await sweepExpired(vault, audit, consent, sink, health, approvals);
    await sessions.sweepExpired();
    return n;
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
