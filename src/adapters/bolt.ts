import { WebClient } from '@slack/web-api';
import type { InstallationStore } from '@slack/bolt';
import { openDb } from '../core/db';
import { loadKeyring, type EnvelopeProvider } from '../core/crypto';
import { ProviderRegistry, type Provider } from '../core/providers';
import { Vault, type TtlPolicy } from '../core/vault';
import { Audit, type AuditSink } from '../core/audit';
import { Consent } from '../core/consent';
import { Policy } from '../core/policy';
import type { SlackIdentity } from '../core/identity';
import { resolveIdentity, isSlackAdmin, isChannelAdmin, isChannelMember, listChannelMembers } from './slack-identity';
import { userOwner, channelOwner } from '../core/owner';
import { authorizeProvider, resolveCredentialOwner, buildToolManifest } from '../core/authz';
import { ConnectionHandle, EgressBlockedError, NoConnectionError, ResponseBlockedError, type Resolvers, type EventSink, type VouchrEvent } from '../core/injector';
import { MemoryRateLimitStore, RateLimitedError, type RateLimitStore } from '../core/rateLimit';
import { safeEmit } from '../core/safe-emit';
import { ChannelConfig, channelIneligibleReason, isChannelMode, isPreviewVisibility, type ChannelInfo, type ChannelMode, type PreviewVisibility } from '../core/channelConfig';
import { ChannelTools, type ToolManifestEntry } from '../core/tools';
import { PendingPreviews } from '../core/preview';
import { handleOAuthCallback } from '../core/oauthCallback';
import { UnionOptin, eligibleUnionMembers, joinUnion, leaveUnion } from '../core/unionOptin';
import { offboardUser, disconnectProvider } from '../core/offboard';
import { sweepExpired } from '../core/sweep';
import { SessionGrants } from '../core/session';
import { NotificationState, type CredentialHealthEvent, type CredentialHealthHook } from '../core/health';
import {
  connectBlocks, connectedHtml, configureModal, CONFIGURE_CALLBACK,
  userKeyModal, keySetupBlocks, USER_KEY_CALLBACK, SETUP_KEY_ACTION, RECONNECT_ACTION,
  sessionApprovalBlocks, APPROVE_SESSION_ACTION, auditBlocks, statsBlocks,
  configModal, CONFIG_CALLBACK, DISCONNECT_ACTION,
  previewBlocks, previewPostBlocks, normalizePreviewContent, PREVIEW_SHARE_ACTION, PREVIEW_DISMISS_ACTION,
  escapeMrkdwn,
} from './blocks';

/** How long a private preview's Share button stays claimable. Short on purpose: the human is
 *  looking at the ephemeral message right now; a stale share re-posts stale data. */
const PREVIEW_TTL_MS = 10 * 60_000;

/** Default session-grant safety ceiling: 8h. The thread binding is the real scope; this just caps
 *  how long a single approval can live before the user must re-approve in the thread. */
const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

/** #112 part 2: at most one owner-notification DM per (owner, provider, channel) per hour. */
// ponytail: per-process debounce, duplicate DMs possible multi-instance, harmless. The map's keys
// are never pruned, but real cardinality is bounded by owner×provider×channel; prune-on-size if a
// long-lived pod ever cares.
const UNION_NOTIFY_DEBOUNCE_MS = 60 * 60 * 1000;

/** Map an external ref to its resolver source id. Add resolvers → extend this. */
export function refSource(ref: string): string {
  if (/^arn:aws:secretsmanager:/.test(ref)) return 'aws-sm';
  if (/^gcp-sm:\/\//.test(ref)) return 'gcp-sm';
  if (/^azure-kv:\/\//.test(ref)) return 'azure-kv';
  if (/^vault:\/\//.test(ref)) return 'vault';
  throw new UserFacingError(
    'Unsupported secret reference. Expected one of: an AWS Secrets Manager ARN (arn:aws:secretsmanager:…), ' +
      'gcp-sm://…, azure-kv://…, or vault://….',
  );
}

/** Aggressive default per-user connection lifetime: idle 7d, hard cap 30d. */
const DEFAULT_TTL: TtlPolicy = { idleMs: 7 * 24 * 60 * 60 * 1000, maxAgeMs: 30 * 24 * 60 * 60 * 1000 };

/** Denial message for the config gate, accurate to whether the channel-creator path is enabled. */
const adminOnly = (allowCreator: boolean, action: string): string =>
  `Only a workspace admin${allowCreator ? ' or the channel creator' : ''} can ${action}.`;

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
    e instanceof EgressBlockedError ||
    e instanceof ResponseBlockedError ||
    e instanceof NoConnectionError ||
    e instanceof RateLimitedError ||
    e instanceof UserFacingError
  ) {
    return e.message;
  }
  const name = (e as Error)?.constructor?.name ?? 'Error';
  return `Something went wrong (${name}). Ask an admin to check the Vouchr logs.`;
}

export interface VouchrOptions {
  providers: Provider[];
  /** Public origin where the callback is reachable, e.g. https://abc.ngrok.io */
  baseUrl: string;
  callbackPath?: string;
  /** SQLite file path (the zero-config default). */
  dbPath?: string;
  /** Postgres connection string, for stateless / multi-instance infra. Overrides dbPath. */
  databaseUrl?: string;
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
   * the default gate is "workspace admin OR channel creator" (a channel owner can self-serve without
   * waiting for IT); set `isAdmin: (c,u)=>isSlackAdmin(c,u)` for strict workspace-only. The
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
   * #112 union-mode explicit opt-in. When true, `union` resolution only ever borrows a member who
   * explicitly opted in for that (channel, provider): by completing a Connect prompted from the
   * union channel, or `/vouchr union join <provider>`. `/vouchr union leave`, disconnect, and
   * offboarding remove eligibility immediately. With nobody opted in, the caller gets the normal
   * Connect prompt. When false (the default), ANY connected channel member is borrowable — exactly
   * today's behavior.
   *
   * DEPRECATED DEFAULT: `false` is a temporary compatibility default and will flip to `true` at the
   * next breaking release. Set it explicitly.
   */
  unionRequiresOptIn?: boolean;
  /**
   * Pluggable store for the per-(owner, provider) token buckets behind `provider.rateLimit`. The
   * default is in-memory per-process — a multi-instance deployment multiplies the effective limit by
   * replica count unless a shared store is supplied (same upgrade shape as the broker's replayStore).
   * Providers without `rateLimit` are never limited, store or not.
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
  /** #112 union opt-in store. Consulted by union resolution when `unionRequiresOptIn` is true
   *  (absent + flag on = fail closed: no candidates). */
  unionOptin?: UnionOptin;
  /** #112: whether union resolution requires an explicit opt-in row. Default false (today's behavior). */
  unionRequiresOptIn?: boolean;
  /** #112 owner-DM debounce timestamps, shared per createVouchr instance (like `inflight`) so the
   *  once-per-hour rule spans requests. A direct-constructed context gets its own map. */
  unionNotified?: Map<string, number>;
  /** Optional audit stream sink (raw actor id). Default no-op; the audit table stays authoritative. */
  auditSink?: AuditSink;
  /** #117 credential-health hook threaded to every ConnectionHandle (see VouchrOptions). Default no-op. */
  health?: CredentialHealthHook;
  /** Pending private previews awaiting Share/Dismiss. Must be the createVouchr-scoped instance so a
   *  share click (a later request) finds the entry; a direct-constructed context gets its own (the
   *  ephemeral still posts; the share button then reports expired unless the host wires the actions). */
  previews?: PendingPreviews;
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
  private unionOptin?: UnionOptin;
  private unionRequiresOptIn: boolean;
  private unionNotified: Map<string, number>;
  private auditSink: AuditSink;
  private health: CredentialHealthHook;
  private previews: PendingPreviews;

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
    this.unionOptin = deps.unionOptin;
    this.unionRequiresOptIn = deps.unionRequiresOptIn ?? false;
    this.unionNotified = deps.unionNotified ?? new Map();
    this.auditSink = deps.auditSink ?? (() => {});
    this.health = deps.health ?? (() => {});
    this.previews = deps.previews ?? new PendingPreviews(PREVIEW_TTL_MS);
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
    if (provider.identity === 'service') {
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
    //   'union'   → any connected member's own credential, acting as that member
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

    // 'union' (any connected member): resolve to WHICHEVER channel member has connected this provider
    // and act AS that member — their user-owned cred is the vault key AND they are the audited actor.
    // No owner/actor conflation: we never key on the channel and we attribute the real member, not the
    // caller. If no member is connected yet, fall through so the caller is prompted to connect (and so
    // becomes the connected member next time).
    if (mode === 'union') {
      // Union borrows another member's user-owned cred THROUGH the channel, so it inherits the SAME
      // channel-eligibility rule as a shared cred (invariant 6): never resolve on an externally-shared /
      // Slack Connect channel, or a member's third-party credential would leak cross-org. Re-checked at
      // USE time (not just at config) because a channel can turn Slack Connect after union was set —
      // mirrors connectChannel's use-time guard. Fails CLOSED (null info → refuse).
      await this.assertChannelEligible();
      // Governance parity with shared creds: when membership is required, only an actual channel member
      // may borrow. Fail-closed (isChannelMember is false on any error / unverifiable membership).
      if (this.requireMembership && !(await isChannelMember(this.client, this.channel!, this.identity.userId))) {
        await this.audit.record('denied', this.identity, providerId, { channel: this.channel, reason: 'not-member' });
        throw new Error(`You must be a member of this channel to use a shared "${providerId}" connection.`);
      }
      // The mode→owner mapping (union → the member's user-owned cred, audited as that member) is the shared
      // core decision. Eligibility already re-checked above; a resolved member yields its owner + actor.
      const member = await this.resolveUnionMember(providerId);
      if (member) {
        const r = resolveCredentialOwner({ path: 'channel', mode, principal: this.identity, channel: this.channel, eligible: true, actingMember: member });
        if (r.status === 'resolved') {
          // #112 part 2: the owner DM fires on ACTUAL use — the wrapped fetch returning a provider
          // Response — not here at resolution: connect() alone injects nothing, and a resolution-time
          // DM would also burn the hourly debounce before the first real use (PR #171 P2).
          return this.notifyOwnerOnUse(this.notifyRateLimited(new ConnectionHandle(
            provider, r.owner, r.acting, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
            // Union non-repudiation: `r.acting` is the borrowed member (audited as them); the REAL
            // requester is the caller. Pass it as triggeredBy so the inject audit records WHO borrowed
            // the credential — this is what surfaces in the owner's `/vouchr audit` view.
            this.identity.userId,
            this.channel, // origin channel: attribute union usage to the channel it happened in (stats)
            this.rateLimits,
            this.health,
          )), member, providerId);
        }
      }
    }

    if (await this.vault.get(userOwner(this.identity), providerId)) {
      return this.notifyRateLimited(new ConnectionHandle(
        provider, userOwner(this.identity), this.identity, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
        null, // no union borrow on the direct per-user path
        this.channel, // origin channel: attribute this user's usage to the channel it happened in (stats)
        this.rateLimits,
        this.health,
      ));
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
    // #112 informed consent: in a union-mode channel, completing this connect ALSO opts the user
    // into serving other members' requests (the callback records it) — the prompt must say so.
    await this.postConnectPrompt(providerId, authorizeUrl, mode === 'union');
    this.emit({ type: 'connect_prompted', provider: providerId });
    throw new ConsentRequiredError(providerId);
  }

  /**
   * 'union' mode resolver: the first channel member who has a live connection to `provider`, built as
   * a SlackIdentity (their userId, the caller's team — invariant 2: never the channel's). Returns null
   * when no member is connected (fail-closed list → no resolution). The member becomes BOTH the vault
   * owner and the audited actor, so the credential's owner and the acting human stay the same real
   * person; the channel is never the owner and the caller is never credited with another's action.
   */
  private async resolveUnionMember(provider: string): Promise<SlackIdentity | null> {
    if (!this.channel) return null;
    // ponytail: linear scan of members × one vault.get each; fine for normal channels. If a huge
    // channel makes this hot, add a "connected members for (team, channel, provider)" index query.
    // Sort by userId so selection is DETERMINISTIC: Slack's conversations.members ordering is
    // arbitrary, and with 2+ connected members a non-deterministic pick would make the borrowed (and
    // audited) credential change between calls. Sorted → the same member always wins.
    const members = [...(await listChannelMembers(this.client, this.channel))].sort();
    // #112 explicit opt-in: the candidate rule is the core eligibleUnionMembers (flag off → all
    // members, unchanged). Flag on with no store wired = fail closed: no candidates, so the caller
    // falls through to the Connect prompt rather than borrowing without consent.
    const candidates = this.unionOptin
      ? await eligibleUnionMembers(this.unionOptin, this.unionRequiresOptIn, this.identity.teamId, this.channel, provider, members)
      : (this.unionRequiresOptIn ? [] : members);
    for (const userId of candidates) {
      const member: SlackIdentity = { enterpriseId: this.identity.enterpriseId, teamId: this.identity.teamId, userId };
      if (await this.vault.get(userOwner(member), provider)) return member;
    }
    return null;
  }

  /**
   * #112 part 2 — wrap a resolved union handle so the owner DM fires on ACTUAL use: after the
   * underlying fetch resolves with a provider Response (credential injected, provider answered —
   * ANY status counts as use), or rejects with ResponseBlockedError (#110's post-injection response
   * guard — the request WAS served). Any other thrown fetch (egress/policy deny, rate limit,
   * network failure) never notifies. ALL rejections re-throw unchanged. Mirrors notifyRateLimited's
   * wrapper shape; applied outermost so an inner throw skips the DM. Not applied on self-use —
   * nothing to disclose.
   */
  private notifyOwnerOnUse(handle: ConnectionHandle, owner: SlackIdentity, provider: string): ConnectionHandle {
    if (owner.userId === this.identity.userId) return handle; // serving yourself: no wrap, no DM
    const fetch = handle.fetch.bind(handle);
    handle.fetch = async (input: string, init: RequestInit = {}) => {
      let res: Response;
      try {
        res = await fetch(input, init);
      } catch (err) {
        // #110's response guard throws ResponseBlockedError POST-injection — after the provider call
        // happened and its inject audit row was written — so a response-blocked use still notifies:
        // the credential DID serve the request, only the response was withheld, and the DM stays in
        // lockstep with the audit record. Pre-injection denials (egress/policy/rate-limit/
        // no-connection) are different classes and stay silent. Every rejection re-throws unchanged.
        if (err instanceof ResponseBlockedError) this.notifyUnionOwner(owner, provider);
        throw err;
      }
      this.notifyUnionOwner(owner, provider); // debounced + fire-and-forget; never affects `res`
      return res;
    };
    return handle;
  }

  /**
   * #112 part 2 — DM the credential owner that their union connection just served ANOTHER member's
   * request (invoked by notifyOwnerOnUse after a real provider round-trip): who used it, where, and
   * how to review (`/vouchr audit`) or withdraw (`/vouchr union leave`). A courtesy signal only —
   * the audit table is the record (the inject row carries the borrower as `actor`). Never fires on
   * self-use. Fire-and-forget with a swallowed failure, so a Slack hiccup can never break the
   * request path. Debounced per (owner, provider, channel), consumed by real use only.
   */
  private notifyUnionOwner(owner: SlackIdentity, provider: string): void {
    if (!this.channel || owner.userId === this.identity.userId) return; // serving yourself → no DM
    const key = `${owner.userId}|${provider}|${this.channel}`;
    const now = Date.now();
    if (now - (this.unionNotified.get(key) ?? 0) < UNION_NOTIFY_DEBOUNCE_MS) return;
    this.unionNotified.set(key, now);
    const p = escapeMrkdwn(provider); // SEC-5, even for a registry-validated id
    try {
      void this.client.chat.postMessage({
        channel: owner.userId,
        text:
          `Your ${p} connection was used by <@${this.identity.userId}> in <#${this.channel}> just now. ` +
          `\`/vouchr audit\` to review · \`/vouchr union leave ${p}\` to stop. ` +
          `(This DM is a courtesy heads-up; the full history is in \`/vouchr audit\`.)`,
      }).catch(() => undefined);
    } catch { /* .catch() only guards the async path; a sync-throwing client must not break the request either */ }
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
    });
    await this.audit.record('config', this.identity, providerId, { owner: 'user', kind: 'secret' });
  }

  /** Point the acting user's OWN credential at an external secret manager (self-service). */
  async referenceUserSecret(providerId: string, r: { source: string; secretRef: string; scopes?: string }): Promise<void> {
    this.brokerable(providerId);
    await this.vault.reference(userOwner(this.identity), providerId, { source: r.source, secretRef: r.secretRef, scopes: r.scopes });
    await this.audit.record('config', this.identity, providerId, { owner: 'user', kind: 'ref', source: r.source });
  }

  /** Whether the user already has a stored connection (no prompt side-effect). A service-to-service
   *  tool is never a Vouchr-brokered connection, so it always reports false (never "connected"). */
  async isConnected(providerId: string): Promise<boolean> {
    if (this.registry.get(providerId).identity === 'service') return false;
    return (await this.vault.get(userOwner(this.identity), providerId)) != null;
  }

  // ── Channel-owned credentials (Phase 1: embedded, safe-by-construction). ──────────
  // `this.channel` comes from the VERIFIED Slack event, so the channel binding cannot be
  // forged (invariant 1). teamId is always the authenticated user's (invariant 2).

  /** Default-deny admin gate for config mutations (invariant 7). Audits the denial. Default is
   *  workspace-admin-only; when `allowChannelCreatorConfig` is opted in, the channel creator is also
   *  allowed. A custom `adminCheck` fully replaces the built-in gate (and ignores the flag). */
  private async requireAdmin(providerId: string): Promise<void> {
    // A custom check overrides the built-in gate; a thrown override fails closed (not admin).
    const ok = this.adminCheck
      ? await this.adminCheck(this.client, this.identity.userId, this.identity.teamId).catch(() => false)
      : (await isSlackAdmin(this.client, this.identity.userId)
        || (this.allowChannelCreatorConfig && await isChannelAdmin(this.client, this.channel ?? '', this.identity.userId)));
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
  private async assertChannelEligible(): Promise<void> {
    // Adapter fetches the channel info; the eligibility RULE lives in core (channelIneligibleReason)
    // so a future sidecar + thin clients enforce the same rule rather than re-implementing it.
    // null info => fails closed.
    let info: ChannelInfo | null = null;
    try {
      info = ((await this.client.conversations.info({ channel: this.channel! })) as any)?.channel ?? null;
    } catch {
      info = null;
    }
    const reason = channelIneligibleReason(info);
    if (reason) throw new UserFacingError(reason);
  }

  /**
   * Store a raw static key as the channel's shared credential for `providerId`. Admin-only,
   * audited, refused on a `'per-user'`-locked channel (invariant 7). The secret never enters
   * the audit meta, the return value, or any error string (invariant 8 / T7). Prefer
   * `referenceChannelSecret` so rotation stays in your secret manager.
   */
  async setChannelSecret(providerId: string, secret: string): Promise<void> {
    this.brokerable(providerId); // validate provider exists + refuse service tools
    const { cfg, owner, channel } = this.channelTarget();
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    const cm = await cfg.getMode(owner.teamId, channel, providerId);
    if (cm != null && cm !== 'shared') {
      throw new UserFacingError(`Channel is set to ${cm} for "${providerId}"; static keys are not allowed.`);
    }
    await this.vault.upsert(owner, providerId, {
      accessToken: secret, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
    await cfg.setMode(owner.teamId, channel, providerId, 'shared');
    await this.audit.record('config', this.identity, providerId, { owner: 'channel', channel, mode: 'shared', kind: 'secret' });
  }

  /**
   * Point the channel's shared credential at an external secret manager (e.g. an AWS Secrets
   * Manager ARN). Vouchr stores only the non-secret ref; the injector resolves it JIT and
   * rotation stays external. Admin-only, audited, refused on a `'per-user'` channel.
   */
  async referenceChannelSecret(
    providerId: string,
    r: { source: string; secretRef: string; scopes?: string },
  ): Promise<void> {
    this.brokerable(providerId);
    const { cfg, owner, channel } = this.channelTarget();
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    const cm = await cfg.getMode(owner.teamId, channel, providerId);
    if (cm != null && cm !== 'shared') {
      throw new UserFacingError(`Channel is set to ${cm} for "${providerId}"; shared references are not allowed.`);
    }
    await this.vault.reference(owner, providerId, { source: r.source, secretRef: r.secretRef, scopes: r.scopes });
    await cfg.setMode(owner.teamId, channel, providerId, 'shared');
    await this.audit.record('config', this.identity, providerId, { owner: 'channel', channel, mode: 'shared', kind: 'ref', source: r.source });
  }

  /**
   * Set the channel's auth mode for a provider. Admin-only, audited. Flipping to a user-owned mode
   * (`'per-user'` or `'session'`) removes any live shared cred (a re-own that must be re-authorized;
   * the admin gate is that authorization). Members then use their own creds via `connect()`.
   */
  async setChannelMode(providerId: string, mode: ChannelMode): Promise<void> {
    this.brokerable(providerId);
    const { cfg, owner, channel } = this.channelTarget();
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    if (mode !== 'shared') await this.vault.delete(owner, providerId); // user-owned: drop any shared cred
    await cfg.setMode(owner.teamId, channel, providerId, mode);
    await this.audit.record('config', this.identity, providerId, { owner: 'channel', channel, mode });
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
        text: `Private ${providerId} preview (only visible to you)`,
      });
      return 'private';
    }
    await this.client.chat.postMessage({
      channel: this.channel ?? this.identity.userId,
      ...(this.thread ? { thread_ts: this.thread } : {}),
      blocks: previewPostBlocks({ provider: providerId, title: c.title, lines: c.lines }) as any,
      // Fallback/notification text is PARSED mrkdwn, not blocks: a provider-derived title there could
      // fire a <!channel> or forge a mention (SEC-5). Neutral constant + the registry-validated id only.
      text: `${providerId} preview`,
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
    // triggeredBy/originChannel keep their defaults (null): unchanged behavior on this path.
    return this.notifyRateLimited(new ConnectionHandle(
      provider, r.owner, r.acting, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
      null, null, this.rateLimits, this.health,
    ));
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
      text: `Approve ${providerId} for this thread`,
    });
  }

  /** Ephemeral JIT prompt for a key provider: a button that opens the per-user key modal. */
  private async postKeySetupPrompt(providerId: string): Promise<void> {
    const blocks = keySetupBlocks(providerId);
    const text = `Set up your ${providerId} access`;
    if (this.channel) {
      await this.client.chat.postEphemeral({ channel: this.channel, user: this.identity.userId, blocks: blocks as any, text });
    } else {
      await this.client.chat.postMessage({ channel: this.identity.userId, blocks: blocks as any, text });
    }
  }

  private async postConnectPrompt(providerId: string, url: string, unionNote = false): Promise<void> {
    const provider = this.registry.get(providerId);
    const blocks = connectBlocks(providerId, url, {
      list: provider.scopesDefault,
      describe: provider.scopeDescriptions,
    });
    if (unionNote) {
      // #112: disclose the opt-in side effect of a union-channel connect (SEC-5-escaped id).
      const p = escapeMrkdwn(providerId);
      blocks.push({
        type: 'context',
        elements: [{
          type: 'mrkdwn',
          text: `This channel is in *union* mode: completing this connect also makes your ${p} account usable for other members' requests here. \`/vouchr union leave ${p}\` to undo.`,
        }],
      });
    }
    const text = `Connect your ${providerId} account`;
    if (this.channel) {
      await this.client.chat.postEphemeral({
        channel: this.channel,
        user: this.identity.userId,
        blocks: blocks as any,
        text,
      });
    } else {
      await this.client.chat.postMessage({
        channel: this.identity.userId,
        blocks: blocks as any,
        text,
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
  const db = await openDb({ dbPath: opts.dbPath, databaseUrl: opts.databaseUrl });
  const key = loadKeyring(); // VOUCHR_MASTER_KEY alone behaves exactly as before; VOUCHR_MASTER_KEYS adds rotation (#115)
  const registry = new ProviderRegistry(opts.providers);
  const vault = new Vault(db, key, opts.ttl ?? DEFAULT_TTL, opts.envelope);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const channelConfig = new ChannelConfig(db);
  const channelTools = new ChannelTools(db);
  const sessions = new SessionGrants(db);
  const unionOptin = new UnionOptin(db); // #112 union opt-in store (rows recorded regardless of the flag)
  const unionRequiresOptIn = opts.unionRequiresOptIn ?? false;
  const unionNotified = new Map<string, number>(); // #112 owner-DM debounce (see UNION_NOTIFY_DEBOUNCE_MS)
  // The 'session' channel mode drives whether a thread grant is required; this is just the TTL ceiling.
  const sessionTtlMs = opts.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  const providerIds = opts.providers.map((p) => p.id); // for toolManifest(); mirrors the registry
  const policy = opts.policy ?? new Policy();
  const resolvers = opts.resolvers ?? {};
  const callbackPath = opts.callbackPath ?? '/vouchr/oauth/callback';
  const redirectUri = new URL(callbackPath, opts.baseUrl).toString();
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
    return opts.isAdmin
      ? await opts.isAdmin(client, identity.userId, identity.teamId).catch(() => false)
      : (await isSlackAdmin(client, identity.userId)
        || (allowChannelCreatorConfig && await isChannelAdmin(client, channel, identity.userId)));
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
        unionOptin,
        unionRequiresOptIn,
        unionNotified,
        auditSink,
        health,
        previews,
      });
    }
    await args.next();
  };

  // channelConfig + unionOptin let the callback record the union opt-in for a connect prompted
  // from a union-mode channel (the consent row carries that channel). See handleOAuthCallback.
  const callbackDeps = { registry, vault, audit, consent, redirectUri, auditSink, channelConfig, unionOptin };

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
        if (!result.ok) return res.status(result.status).send(result.error);
        emit({ type: 'connected', provider: result.provider });

        // Best-effort nudge back into Slack, from the connecting user's own workspace.
        const client = await confirmClientFor(result.identity);
        if (client) {
          await client.chat
            .postMessage({
              channel: result.identity.userId,
              text: `✅ ${result.provider} connected${result.account ? ` as ${result.account}` : ''}.`,
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
      thread: null, sessions, unionOptin, unionRequiresOptIn, unionNotified, auditSink, health, previews,
    });
  }

  /**
   * Register the `/vouchr` slash command (`status`, `disconnect <provider>`,
   * `configure <provider>`) and the channel-credential modal submit. `configure` opens a
   * private modal so the admin's secret is never typed into the channel (invariant 7 / T7).
   */
  function registerCommands(app: {
    command: (name: string, handler: (args: any) => Promise<void>) => void;
    view: (id: string, handler: (args: any) => Promise<void>) => void;
    action: (id: string, handler: (args: any) => Promise<void>) => void;
  }): void {
    app.command('/vouchr', async ({ command, ack, respond, client }: any) => {
      await ack();
      const identity = resolveIdentity({ body: command });
      if (!identity) return respond('Could not resolve your Slack identity.');

      const [sub, arg, arg2] = String(command.text ?? '').trim().split(/\s+/);

      // No subcommand → open the interactive config modal (#109). `/vouchr status` (and any other
      // subcommand) keeps its text output below, so scripts and muscle memory are unaffected. A modal
      // needs a trigger_id; without one (shouldn't happen for a slash command) fall back to the text.
      // Building the modal makes several DB/Slack round-trips within Slack's ~3s trigger window; if the
      // open fails (expired_trigger_id, a transient API error, a build error) DON'T return — fall through
      // to the status text so a no-arg `/vouchr` is never silent (matches main's pre-modal behavior).
      if (!sub && command.trigger_id) {
        try {
          await client.views.open({ trigger_id: command.trigger_id, view: await buildConfigModal(identity, command.channel_id ?? null, client) });
          return;
        } catch { /* fall through to the status text below */ }
      }

      // List the channel's tool manifest (which providers an agent may use here + their mode).
      if (sub === 'tools') {
        if (!command.channel_id) return respond('Run `/vouchr tools` from inside a channel.');
        const manifest = await contextFor(identity, command.channel_id, client).toolManifest();
        if (!manifest.length) return respond('No providers are registered.');
        const lines = manifest
          .map((m) => `• *${m.provider}*: ${m.enabled ? 'enabled' : 'disabled'}${m.mode ? ` (${m.mode})` : ''}${m.visibility === 'private' ? ' · :lock: private previews' : ''}`)
          .join('\n');
        return respond(`Tools for <#${command.channel_id}>:\n${lines}\n\nAdmins: \`/vouchr enable|disable <provider>\`.`);
      }

      // Admin usage analytics for THIS channel over the last 30 days: which enabled tools are actually
      // used, by how many distinct humans, and which are idle dead-weight to prune. Admin-gated (same
      // gate as enable/mode) + audited on refusal. Service tools aren't brokered, so they're excluded.
      if (sub === 'stats') {
        if (!command.channel_id) return respond('Run `/vouchr stats` from inside a channel.');
        if (!(await commandAdmin(client, identity, command.channel_id))) {
          await audit.record('denied', identity, 'stats', { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
          return respond(adminOnly(allowChannelCreatorConfig, 'view channel usage stats'));
        }
        const manifest = await contextFor(identity, command.channel_id, client).toolManifest();
        const enabled = manifest.filter((m) => m.enabled && m.identity !== 'service').map((m) => m.provider);
        const since = Date.now() - 30 * 24 * 60 * 60 * 1000;
        const stats = await audit.statsByChannel(identity.teamId, command.channel_id, since);
        return respond({ text: 'Channel tool usage', blocks: statsBlocks(enabled, stats, 30) as any });
      }

      // Enable/disable a provider in this channel. Admin-gated (default-deny) + audited as 'config'.
      if (sub === 'enable' || sub === 'disable') {
        if (!arg) return respond(`Usage: \`/vouchr ${sub} <provider>\``);
        if (!command.channel_id) return respond(`Run \`/vouchr ${sub}\` from inside the channel you want to configure.`);
        if (!registry.has(arg)) return respond(`Unknown provider "${arg}".`);
        if (!(await commandAdmin(client, identity, command.channel_id))) {
          await audit.record('denied', identity, arg, { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
          return respond(adminOnly(allowChannelCreatorConfig, 'change channel tools'));
        }
        const on = sub === 'enable';
        await channelTools.setEnabled(identity.teamId, command.channel_id, arg, on);
        await audit.record('config', identity, arg, { owner: 'channel', channel: command.channel_id, tool: on ? 'enabled' : 'disabled' });
        return respond(`${on ? 'Enabled' : 'Disabled'} *${arg}* in <#${command.channel_id}>.`);
      }

      // Per-channel auth mode: shared (channel cred) | per-user | session (per-user + thread grant)
      // | union (any connected member, acting as that member). Admin-gated + audited in setChannelMode.
      if (sub === 'mode') {
        if (!arg || !isChannelMode(arg2)) {
          return respond('Usage: `/vouchr mode <provider> <shared|per-user|session|union>`');
        }
        if (!registry.has(arg)) return respond(`Unknown provider "${arg}". See \`/vouchr tools\` for the registered ones.`);
        if (!command.channel_id) return respond('Run `/vouchr mode` from inside the channel you want to configure.');
        try {
          await contextFor(identity, command.channel_id, client).setChannelMode(arg, arg2);
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        return respond(`Set *${arg}* to *${arg2}* in <#${command.channel_id}>.`);
      }

      // Per-channel preview visibility: private = agent output goes only to the requester, with an
      // explicit Share button. Admin-gated + audited in setChannelVisibility (same gate as `mode`).
      if (sub === 'preview') {
        if (!arg || !isPreviewVisibility(arg2)) {
          return respond('Usage: `/vouchr preview <provider> <public|private>`');
        }
        if (!registry.has(arg)) return respond(`Unknown provider "${arg}". See \`/vouchr tools\` for the registered ones.`);
        if (!command.channel_id) return respond('Run `/vouchr preview` from inside the channel you want to configure.');
        try {
          await contextFor(identity, command.channel_id, client).setChannelVisibility(arg, arg2);
        } catch (e) {
          return respond(safeUserMessage(e)); // raw message never reaches the user (may carry a secret)
        }
        return respond(arg2 === 'private'
          ? `Set *${arg}* previews to *private* in <#${command.channel_id}>: results go only to whoever asked, with a Share button.`
          : `Set *${arg}* previews to *public* in <#${command.channel_id}>.`);
      }

      // #112 union opt-in: join/leave the union pool for THIS channel — self-service, acting user
      // only (it's their own delegation decision, so no admin gate). `leave` is effective on the
      // very next resolution. Rows are recorded even while `unionRequiresOptIn` is off, so flipping
      // the flag later doesn't strand members who already opted in.
      if (sub === 'union') {
        if ((arg !== 'join' && arg !== 'leave') || !arg2) return respond('Usage: `/vouchr union join|leave <provider>`');
        if (!command.channel_id) return respond('Run `/vouchr union` from inside a channel.');
        // SEC-4: validate the provider against the registry BEFORE any persist or audit write.
        // SEC-5: the refused id is raw user input, so it's escaped at render.
        if (!registry.has(arg2)) return respond(`Unknown provider "${escapeMrkdwn(arg2)}". See \`/vouchr tools\` for the registered ones.`);
        const provider = registry.get(arg2);
        const p = escapeMrkdwn(arg2);
        if (provider.identity === 'service') {
          return respond(`"${p}" is a service-to-service tool; Vouchr does not broker it, so there is no union pool for it.`);
        }
        if (arg === 'leave') {
          const left = await leaveUnion(unionOptin, audit, identity, command.channel_id, arg2);
          return respond(left
            ? `Left the *${p}* union pool in <#${command.channel_id}>. Your credential no longer serves other members' requests here.`
            : `You weren't in the *${p}* union pool in <#${command.channel_id}>.`);
        }
        // join requires a connected credential; otherwise post the normal setup/Connect prompt.
        // Completing a Connect from this channel auto-joins when the channel is in union mode for
        // the provider (the consent row carries the channel — see handleOAuthCallback).
        if (!(await vault.get(userOwner(identity), arg2))) {
          if (provider.credential === 'key') {
            return respond({ text: `Set up your ${arg2} access first`, blocks: keySetupBlocks(arg2) as any });
          }
          const { authorizeUrl } = await consent.begin(identity, provider, redirectUri, command.channel_id);
          return respond({
            text: `Connect your ${arg2} account first`,
            blocks: connectBlocks(arg2, authorizeUrl, { list: provider.scopesDefault, describe: provider.scopeDescriptions }) as any,
          });
        }
        await joinUnion(unionOptin, audit, identity, command.channel_id, arg2);
        return respond(
          `Joined the *${p}* union pool in <#${command.channel_id}>: your connected account may now serve ` +
          `other members' requests here (each use is audited with the requester as the actor). ` +
          `\`/vouchr union leave ${p}\` to stop.`,
        );
      }

      if (sub === 'configure') {
        if (!arg) return respond('Usage: `/vouchr configure <provider>`');
        if (!command.channel_id) return respond('Run `/vouchr configure` from inside the channel you want to configure.');
        // Validate the provider BEFORE recording a denial or opening the modal (parity with enable/disable):
        // otherwise an unvalidated arg — potentially a credential-shaped typo — lands raw in the audit
        // `provider` column and could be reflected back into a `/vouchr audit` view.
        if (!registry.has(arg)) return respond(`Unknown provider "${arg}".`);
        if (!(await commandAdmin(client, identity, command.channel_id))) {
          await audit.record('denied', identity, arg, { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
          return respond(adminOnly(allowChannelCreatorConfig, 'configure channel credentials'));
        }
        await client.views.open({ trigger_id: command.trigger_id, view: configureModal(arg, command.channel_id) });
        return;
      }
      if (sub === 'disconnect') {
        if (!arg) return respond('Usage: `/vouchr disconnect <provider>`');
        // Shared with the headless broker's /v1/disconnect (core disconnectProvider): local delete
        // FIRST, then best-effort upstream revoke — a revoke failure is non-fatal. Union opt-ins
        // for the provider go with the credential (#112).
        const { ok } = await disconnectProvider(vault, audit, registry, identity, arg, unionOptin);
        emit({ type: 'revoked', provider: arg, ok });
        return respond(`Disconnected *${arg}*. The agent can no longer act as you on ${arg}.`);
      }

      // Self-service transparency: where your credential was used. `audit channel` (admin-gated) shows
      // this channel's channel-owned usage. Strictly scoped by the SELECT — a non-admin only ever sees
      // rows attributed to their own user id, never another user's or another channel's.
      if (sub === 'audit') {
        if (arg === 'channel') {
          if (!command.channel_id) return respond('Run `/vouchr audit channel` from inside the channel.');
          if (!(await commandAdmin(client, identity, command.channel_id))) {
            await audit.record('denied', identity, 'audit', { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
            return respond(adminOnly(allowChannelCreatorConfig, 'view channel credential usage'));
          }
          const rows = await audit.listByChannel(identity.teamId, command.channel_id, 20);
          return respond({ text: 'Channel credential usage', blocks: auditBlocks(rows, 'Credential usage in this channel') as any });
        }
        const rows = await audit.listByOwnerUser(identity, 20);
        return respond({ text: 'Your credential usage', blocks: auditBlocks(rows, 'Your credential usage') as any });
      }

      // Never list a service-to-service tool as a "connected account": Vouchr doesn't broker those,
      // so they don't belong in the user's Vouchr connection status (defensive — storage is blocked).
      const conns = (await vault.listForUser(identity)).filter((c) => {
        try { return registry.get(c.provider).identity !== 'service'; } catch { return true; }
      });
      if (!conns.length) return respond('No connected accounts. They are created on demand when an agent needs one.');
      const lines = conns
        .map((c) => `• *${c.provider}*${c.externalAccount ? ` (${c.externalAccount})` : ''}`)
        .join('\n');
      return respond(`Your connected accounts:\n${lines}\n\nDisconnect with \`/vouchr disconnect <provider>\`.`);
    });

    // Modal submit (channel-shared OR per-user). One handler so both paths stay leak-safe and both
    // await the write. The typed value lives only in this view's state, never echoed, posted, logged,
    // or put in audit meta (invariant 8 / T7).
    const handleSecretSubmit = async ({ ack, body, view, client }: any, kind: 'channel' | 'user') => {
      const identity = resolveIdentity({ body });
      let channel = '';
      let provider = '';
      try {
        ({ channel = '', provider } = JSON.parse(view.private_metadata));
      } catch {
        return ack({ response_action: 'errors', errors: { ref: 'Malformed request. Please reopen the modal.' } });
      }
      const ref = view.state?.values?.ref?.v?.value?.trim() || '';
      const raw = view.state?.values?.raw?.v?.value || '';
      if (!identity) return ack({ response_action: 'errors', errors: { ref: 'Could not resolve your Slack identity.' } });
      if ((ref && raw) || (!ref && !raw)) {
        return ack({ response_action: 'errors', errors: { raw: 'Provide exactly one: a reference or a key.' } });
      }
      const ctx = contextFor(identity, kind === 'channel' ? channel : null, client);
      try {
        if (kind === 'channel') {
          if (ref) await ctx.referenceChannelSecret(provider, { source: refSource(ref), secretRef: ref });
          else await ctx.setChannelSecret(provider, raw);
        } else {
          if (ref) await ctx.referenceUserSecret(provider, { source: refSource(ref), secretRef: ref });
          else await ctx.setUserSecret(provider, raw);
        }
      } catch (e) {
        // Show only Vouchr's own user-facing messages inline; any unexpected throw (KMS/DB/inject)
        // could carry the secret, so it's reduced to its class name — never the raw message.
        return ack({ response_action: 'errors', errors: { [ref ? 'ref' : 'raw']: safeUserMessage(e) } });
      }
      await ack();
      // Private confirmation DM (no secret), just the fact it was set.
      const text = kind === 'channel'
        ? `✅ Saved the *${provider}* credential for <#${channel}>.`
        : `✅ Your *${provider}* credential is set. Ask me again and I'll use it.`;
      await client.chat.postMessage({ channel: identity.userId, text }).catch(() => undefined);
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
      const connections = (await vault.listForUser(identity))
        .filter((c) => { try { return registry.get(c.provider).identity !== 'service'; } catch { return true; } })
        .map((c) => ({ provider: c.provider, channel: null as string | null }));
      const tools = channelId ? await contextFor(identity, channelId, client).toolManifest() : [];
      const isAdmin = channelId ? await commandAdmin(client, identity, channelId) : false;
      // The admin Enabled checkbox controls ONLY the tool allowlist bit, so it must render from
      // channelTools.isEnabled — NOT the read-only manifest's `enabled`, which is (allowlist AND policy).
      // Rendering the policy-intersected value would show a policy-denied provider unchecked and then let
      // an untouched save look like an intentional disable (findings 3/1). The manifest keeps the
      // policy-intersected value for its read-only "Tools in this channel" display.
      const admin = isAdmin && channelId
        ? await Promise.all(
            // Preview visibility applies to ALL tools (service included — their output can leak in a
            // thread just the same), so unlike mode/enabled it is NOT filtered to brokered providers…
            // but the admin rows are; the service tools' knob ships when someone needs it.
            tools.filter((t) => t.identity !== 'service').map(async (t) => ({
              provider: t.provider,
              mode: t.mode,
              enabled: await channelTools.isEnabled(identity.teamId, channelId, t.provider),
              visibility: t.visibility,
            })),
          )
        : undefined;
      return configModal({ channel: channelId, connections, tools, admin });
    }

    // Config modal submit: apply the admin mode/enable changes. Authorization is RE-CHECKED here
    // server-side (commandAdmin) — the modal only SHOWED these controls to admins, but a client can
    // forge a view_submission, so presence of the fields is never the authority. Each mutation routes to
    // the SAME helper the slash command uses (setChannelMode re-checks admin + eligibility itself), so
    // audit + eligibility stay identical. A control is acted on ONLY when its submitted value differs
    // from the OPEN-TIME value carried in private_metadata — so an untouched field never mutates, never
    // reverts a concurrent admin's change (a stale re-submit of the open value is a no-op), and never
    // depends on a re-read whose basis drifted from what was rendered.
    app.view(CONFIG_CALLBACK, async ({ ack, body, view, client }: any) => {
      const identity = resolveIdentity({ body });
      // A view_submission always carries user/team, so identity failure is near-impossible; ack (closing
      // the modal, no mutation) beats keying an error to a block id that may not exist.
      if (!identity) return ack();
      let channel = '';
      let open: { p: string; m: string | null; e: boolean; v?: string }[] = [];
      try { ({ channel = '', open = [] } = JSON.parse(view.private_metadata)); } catch { channel = ''; }
      if (!channel || !(await commandAdmin(client, identity, channel))) {
        await audit.record('denied', identity, 'config', { reason: 'not-admin', owner: 'channel', channel });
        const firstBlock = Object.keys(view.state?.values ?? {}).find((b) => b.startsWith('mode:') || b.startsWith('tool:') || b.startsWith('preview:'));
        // Only attach the error to a REAL block id (Slack silently drops unknown keys); if there are no
        // admin blocks (a forged submit), a bare ack still rejects the mutation — nothing was written.
        return firstBlock
          ? ack({ response_action: 'errors', errors: { [firstBlock]: adminOnly(allowChannelCreatorConfig, 'change channel settings') } })
          : ack();
      }
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
        else if (blockId.startsWith('tool:')) submittedEnabled.set(blockId.slice(5), (v?.enabled?.selected_options ?? []).some((o: any) => o.value === 'enabled'));
        else if (blockId.startsWith('preview:')) submittedVisibility.set(blockId.slice(8), (v?.visibility?.selected_options ?? []).some((o: any) => o.value === 'private') ? 'private' : 'public');
      }

      const ctx = contextFor(identity, channel, client);
      const errors: Record<string, string> = {};

      // ── mode: apply only where the admin actually changed the select (submitted !== open-time) ──
      for (const [provider, mode] of submittedMode) {
        if (!registry.has(provider) || !isChannelMode(mode)) continue; // forged/invalid → ignore
        if (mode === (openMode.get(provider) ?? null)) continue; // untouched (or reset to the same) → skip
        try { await ctx.setChannelMode(provider, mode); } catch (e) { errors[`mode:${provider}`] = safeUserMessage(e); }
      }

      // ── preview visibility: same open-time-diff contract as mode ──
      for (const [provider, visibility] of submittedVisibility) {
        if (!registry.has(provider)) continue; // forged/invalid → ignore
        if (visibility === (openVisibility.get(provider) ?? 'public')) continue; // untouched → skip
        try { await ctx.setChannelVisibility(provider, visibility); } catch (e) { errors[`preview:${provider}`] = safeUserMessage(e); }
      }

      // ── enabled: the tool allowlist. Writing the FIRST row flips the channel from "all enabled"
      // (backward-compat) into allowlist mode, where every still-row-less provider silently becomes
      // disabled. So when a change would create that allowlist on an as-yet-unconfigured channel,
      // MATERIALIZE the full allowlist (every registered provider's desired state) rather than a single
      // row — else the untouched providers vanish. Once the channel is already an allowlist, a per-
      // provider write is local and safe. Audit only the providers whose state actually changed. ──
      const enabledChanged = [...submittedEnabled].filter(([p]) => registry.has(p) && submittedEnabled.get(p) !== (openEnabled.get(p) ?? true));
      if (enabledChanged.length) {
        const alreadyAllowlist = await channelTools.isConfigured(identity.teamId, channel);
        const willDisableSome = [...submittedEnabled].some(([p, e]) => registry.has(p) && !e);
        if (!alreadyAllowlist && willDisableSome) {
          for (const p of providerIds) {
            const on = submittedEnabled.has(p) ? submittedEnabled.get(p)! : true; // unshown providers stay enabled
            await channelTools.setEnabled(identity.teamId, channel, p, on);
          }
        } else {
          for (const [p] of enabledChanged) await channelTools.setEnabled(identity.teamId, channel, p, submittedEnabled.get(p)!);
        }
        for (const [p, e] of enabledChanged) {
          await audit.record('config', identity, p, { owner: 'channel', channel, tool: e ? 'enabled' : 'disabled' });
        }
      }

      if (Object.keys(errors).length) return ack({ response_action: 'errors', errors });
      await ack();
      await client.chat.postMessage({ channel: identity.userId, text: `✅ Updated channel settings for <#${channel}>.` }).catch(() => undefined);
    });

    // Disconnect the acting user's own connection from a Disconnect button IN VOUCHR'S OWN config modal,
    // then refresh the view so the row disappears. Scoped to `callback_id === CONFIG_CALLBACK`: the
    // DISCONNECT_ACTION id is also EXPORTED for hosts who embed disconnectConfirmBlocks in their OWN
    // surfaces and register their own listener — Bolt runs every matching listener, so acting on a
    // foreign view/message here would double-fire disconnectProvider (duplicate audit/revoke) and clobber
    // the host's view. When it isn't our modal we ack and defer to the host's listener.
    app.action(DISCONNECT_ACTION, async ({ ack, body, client }: any) => {
      await ack();
      if (body.view?.callback_id !== CONFIG_CALLBACK) return; // not our modal → the host owns this action
      const identity = resolveIdentity({ body });
      const provider = body.actions?.[0]?.value;
      // Validate against the registry before writing anything: disconnectProvider records the provider
      // into the audit `provider` column unconditionally, so a forged/unknown value would pollute audit.
      if (!identity || typeof provider !== 'string' || !registry.has(provider)) return;
      const { ok } = await disconnectProvider(vault, audit, registry, identity, provider, unionOptin);
      emit({ type: 'revoked', provider, ok });
      let channel: string | null = null;
      try { ({ channel = null } = JSON.parse(body.view.private_metadata ?? '{}')); } catch { channel = null; }
      await client.views.update({ view_id: body.view.id, view: await buildConfigModal(identity, channel, client) }).catch(() => undefined);
    });

    // Per-user key setup: ephemeral button → private modal (self-service, not admin-gated).
    app.action(SETUP_KEY_ACTION, async ({ ack, body, client }: any) => {
      await ack();
      const provider = body.actions?.[0]?.value;
      if (!provider || !body.trigger_id) return;
      await client.views.open({ trigger_id: body.trigger_id, view: userKeyModal(provider) });
    });

    // #117 refresh_dead DM's Connect button: mint a FRESH single-use consent state on click and
    // swap the DM for the normal connect prompt. Late-minting is the point — a state lives 10
    // minutes (STATE_TTL_MS) and the DM may sit unread for hours, and the 24h DM debounce means a
    // dead baked-in link would have no recovery path. The button value is forgeable (SEC-3/SEC-4):
    // validate it against the registry before anything, and mint for the ACTING user from the
    // Slack-verified payload — exactly what that user could do themselves via connect(). DM
    // context ⇒ channel=null, so the callback records no union opt-in.
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
        await respond({
          replace_original: true,
          text: `Connect your ${providerId} account`,
          blocks: connectBlocks(providerId, authorizeUrl, { list: provider.scopesDefault, describe: provider.scopeDescriptions }) as any,
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
      if (respond) await respond({ replace_original: true, text: `✅ Approved *${provider}* for this thread. Ask me again.` });
    });

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
        text: `${p.provider} preview shared by <@${identity.userId}>`,
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
    return offboardUser(vault, audit, consent, identity, registry, 'offboarded', sessions, unionOptin);
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

  /** Delete every connection past its TTL + clear stale consent + expired thread sessions. Run on a timer. */
  async function sweep(): Promise<number> {
    const n = await sweepExpired(vault, audit, consent, sink, unionOptin, health);
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
  ): { stop: () => void } {
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
    return { stop: () => { if (timer) clearInterval(timer); } };
  }

  return {
    install,
    middleware,
    mountRoutes,
    registerCommands,
    registerOffboarding,
    offboard,
    sweepExpired: sweep,
    vault,
    audit,
    db,
  };
}

// Type `context.vouchr` for consumers so handlers can call it without `as any`.
declare module '@slack/bolt' {
  interface Context {
    vouchr: ConnectContext;
  }
}
