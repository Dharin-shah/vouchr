import { WebClient } from '@slack/web-api';
import type { InstallationStore } from '@slack/bolt';
import { openDb } from '../core/db';
import { loadMasterKey, type EnvelopeProvider } from '../core/crypto';
import { ProviderRegistry, type Provider } from '../core/providers';
import { Vault, type TtlPolicy } from '../core/vault';
import { Audit, type AuditSink } from '../core/audit';
import { Consent } from '../core/consent';
import { Policy } from '../core/policy';
import type { SlackIdentity } from '../core/identity';
import { resolveIdentity, isSlackAdmin, isChannelAdmin, isChannelMember, listChannelMembers } from './slack-identity';
import { userOwner, channelOwner } from '../core/owner';
import { authorizeProvider, resolveCredentialOwner } from '../core/authz';
import { ConnectionHandle, EgressBlockedError, NoConnectionError, type Resolvers, type EventSink, type VouchrEvent } from '../core/injector';
import { safeEmit } from '../core/safe-emit';
import { ChannelConfig, channelIneligibleReason, type ChannelInfo, type ChannelMode } from '../core/channelConfig';
import { ChannelTools, type ToolManifestEntry } from '../core/tools';
import { handleOAuthCallback } from '../core/oauthCallback';
import { offboardUser, disconnectProvider } from '../core/offboard';
import { sweepExpired } from '../core/sweep';
import { SessionGrants } from '../core/session';
import {
  connectBlocks, connectedHtml, configureModal, CONFIGURE_CALLBACK,
  userKeyModal, keySetupBlocks, USER_KEY_CALLBACK, SETUP_KEY_ACTION,
  sessionApprovalBlocks, APPROVE_SESSION_ACTION, auditBlocks, statsBlocks,
  configModal, CONFIG_CALLBACK, DISCONNECT_ACTION,
} from './blocks';

/** The four valid per-channel auth modes, plus a RUNTIME guard. The slash command validates its text
 *  arg against these; the modal `view_submission` needs the same server-side check because a client can
 *  forge a `selected_option.value` that the compile-time `ChannelMode` type never sees. */
const CHANNEL_MODES = ['shared', 'per-user', 'session', 'union'] as const;
const isChannelMode = (m: unknown): m is ChannelMode => typeof m === 'string' && (CHANNEL_MODES as readonly string[]).includes(m);

/** Default session-grant safety ceiling: 8h. The thread binding is the real scope; this just caps
 *  how long a single approval can live before the user must re-approve in the thread. */
const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

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
    e instanceof NoConnectionError ||
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
  /** Optional audit stream sink (raw actor id). Default no-op; the audit table stays authoritative. */
  auditSink?: AuditSink;
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
  private sink: EventSink;
  private providerIds: string[];
  private adminCheck?: (client: WebClient, userId: string, teamId: string) => Promise<boolean>;
  private allowChannelCreatorConfig: boolean;
  private requireMembership: boolean;
  private thread: string | null;
  private sessions?: SessionGrants;
  private auditSink: AuditSink;

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
    this.sink = deps.sink ?? (() => {});
    this.providerIds = deps.providerIds ?? [];
    this.adminCheck = deps.adminCheck;
    this.allowChannelCreatorConfig = deps.allowChannelCreatorConfig ?? false;
    this.requireMembership = deps.requireMembership ?? false;
    this.thread = deps.thread ?? null;
    this.sessions = deps.sessions;
    this.auditSink = deps.auditSink ?? (() => {});
  }

  /** Fire the sink, swallowing any error. A bad sink must never break a request. */
  private emit(e: VouchrEvent): void {
    safeEmit(this.sink, e);
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
          return new ConnectionHandle(
            provider, r.owner, r.acting, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
            // Union non-repudiation: `r.acting` is the borrowed member (audited as them); the REAL
            // requester is the caller. Pass it as triggeredBy so the inject audit records WHO borrowed
            // the credential — this is what surfaces in the owner's `/vouchr audit` view.
            this.identity.userId,
            this.channel, // origin channel: attribute union usage to the channel it happened in (stats)
          );
        }
      }
    }

    if (await this.vault.get(userOwner(this.identity), providerId)) {
      return new ConnectionHandle(
        provider, userOwner(this.identity), this.identity, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink,
        null, // no union borrow on the direct per-user path
        this.channel, // origin channel: attribute this user's usage to the channel it happened in (stats)
      );
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
    for (const userId of [...(await listChannelMembers(this.client, this.channel))].sort()) {
      const member: SlackIdentity = { enterpriseId: this.identity.enterpriseId, teamId: this.identity.teamId, userId };
      if (await this.vault.get(userOwner(member), provider)) return member;
    }
    return null;
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
    return new ConnectionHandle(provider, r.owner, r.acting, this.vault, this.audit, this.resolvers, this.inflight, this.sink, this.auditSink);
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
    const out: ToolManifestEntry[] = [];
    for (const provider of this.providerIds) {
      const toolEnabled = this.channel && this.channelTools
        ? await this.channelTools.isEnabled(this.identity.teamId, this.channel, provider)
        : true;
      // Intersect with Policy so the manifest matches what connect() would actually allow: a
      // provider the channel tool allowlist enables but Policy denies is not usable here.
      const enabled = toolEnabled && this.policy.check(provider, this.channel);
      const mode = this.channel && this.channelConfig
        ? await this.channelConfig.getMode(this.identity.teamId, this.channel, provider)
        : null;
      // 'acting_human' (default) → Vouchr brokers it via connect(); 'service' → host's own service auth.
      const identity = this.registry.get(provider).identity ?? 'acting_human';
      out.push({ provider, mode, enabled, identity });
    }
    return out;
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

  private async postConnectPrompt(providerId: string, url: string): Promise<void> {
    const provider = this.registry.get(providerId);
    const blocks = connectBlocks(providerId, url, {
      list: provider.scopesDefault,
      describe: provider.scopeDescriptions,
    });
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

export async function createVouchr(opts: VouchrOptions) {
  const db = await openDb({ dbPath: opts.dbPath, databaseUrl: opts.databaseUrl });
  const key = loadMasterKey();
  const registry = new ProviderRegistry(opts.providers);
  const vault = new Vault(db, key, opts.ttl ?? DEFAULT_TTL, opts.envelope);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const channelConfig = new ChannelConfig(db);
  const channelTools = new ChannelTools(db);
  const sessions = new SessionGrants(db);
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
        sink,
        providerIds,
        adminCheck: opts.isAdmin,
        allowChannelCreatorConfig,
        requireMembership: opts.requireChannelMembership ?? false,
        thread,
        sessions,
        auditSink,
      });
    }
    await args.next();
  };

  const callbackDeps = { registry, vault, audit, consent, redirectUri, auditSink };

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
      channelConfig, channelTools, inflight, sink, providerIds,
      adminCheck: opts.isAdmin, allowChannelCreatorConfig,
      requireMembership: opts.requireChannelMembership ?? false,
      thread: null, sessions, auditSink,
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
      if (!sub && command.trigger_id) {
        await client.views.open({ trigger_id: command.trigger_id, view: await buildConfigModal(identity, command.channel_id ?? null, client) });
        return;
      }

      // List the channel's tool manifest (which providers an agent may use here + their mode).
      if (sub === 'tools') {
        if (!command.channel_id) return respond('Run `/vouchr tools` from inside a channel.');
        const manifest = await contextFor(identity, command.channel_id, client).toolManifest();
        if (!manifest.length) return respond('No providers are registered.');
        const lines = manifest
          .map((m) => `• *${m.provider}*: ${m.enabled ? 'enabled' : 'disabled'}${m.mode ? ` (${m.mode})` : ''}`)
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
        // FIRST, then best-effort upstream revoke — a revoke failure is non-fatal.
        const { ok } = await disconnectProvider(vault, audit, registry, identity, arg);
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
      const admin = isAdmin
        ? tools.filter((t) => t.identity !== 'service').map((t) => ({ provider: t.provider, mode: t.mode, enabled: t.enabled }))
        : undefined;
      return configModal({ channel: channelId, connections, tools, admin });
    }

    // Config modal submit: apply the admin mode/enable changes. Authorization is RE-CHECKED here
    // server-side (commandAdmin) — the modal only SHOWED these controls to admins, but a client can
    // forge a view_submission, so presence of the fields is never the authority. Each mutation routes
    // to the SAME helper the slash command uses (setChannelMode re-checks admin + eligibility itself;
    // enable/disable mirrors the `/vouchr enable|disable` path), so audit + eligibility are identical.
    // Only CHANGED fields mutate (diffed against the store), so an unchanged submit writes nothing.
    app.view(CONFIG_CALLBACK, async ({ ack, body, view, client }: any) => {
      const identity = resolveIdentity({ body });
      if (!identity) return ack({ response_action: 'errors', errors: { [`mode:`]: 'Could not resolve your Slack identity.' } });
      let channel = '';
      try { ({ channel = '' } = JSON.parse(view.private_metadata)); } catch { channel = ''; }
      if (!channel || !(await commandAdmin(client, identity, channel))) {
        await audit.record('denied', identity, 'config', { reason: 'not-admin', channel });
        // Attach the error to the first admin block if present, else reject generically.
        const firstBlock = Object.keys(view.state?.values ?? {})[0] ?? 'mode:';
        return ack({ response_action: 'errors', errors: { [firstBlock]: adminOnly(allowChannelCreatorConfig, 'change channel settings') } });
      }
      const ctx = contextFor(identity, channel, client);
      const values = view.state?.values ?? {};
      const errors: Record<string, string> = {};
      for (const [blockId, v] of Object.entries<any>(values)) {
        if (blockId.startsWith('mode:')) {
          const provider = blockId.slice(5);
          const mode = v?.mode?.selected_option?.value;
          // Validate the submitted mode server-side: a forged view_submission can carry any string, and
          // ChannelConfig.setMode does not runtime-check it. An invalid value is ignored, never persisted.
          if (!isChannelMode(mode) || !registry.has(provider)) continue;
          const current = await channelConfig.getMode(identity.teamId, channel, provider);
          if (mode === current) continue; // unchanged → no mutation, no audit
          try { await ctx.setChannelMode(provider, mode); } catch (e) { errors[blockId] = safeUserMessage(e); }
        } else if (blockId.startsWith('tool:')) {
          const provider = blockId.slice(5);
          if (!registry.has(provider)) continue;
          const enabled = (v?.enabled?.selected_options ?? []).some((o: any) => o.value === 'enabled');
          const current = await channelTools.isEnabled(identity.teamId, channel, provider);
          if (enabled === current) continue; // unchanged → no mutation, no audit
          await channelTools.setEnabled(identity.teamId, channel, provider, enabled);
          await audit.record('config', identity, provider, { owner: 'channel', channel, tool: enabled ? 'enabled' : 'disabled' });
        }
      }
      if (Object.keys(errors).length) return ack({ response_action: 'errors', errors });
      await ack();
      await client.chat.postMessage({ channel: identity.userId, text: `✅ Updated channel settings for <#${channel}>.` }).catch(() => undefined);
    });

    // Disconnect one of the acting user's own connections (from the modal row button, or any consumer
    // that reuses disconnectConfirmBlocks/DISCONNECT_ACTION). Same core path as `/vouchr disconnect`.
    // When fired from inside the modal, refresh the view so the row disappears; else confirm in-thread.
    app.action(DISCONNECT_ACTION, async ({ ack, body, client, respond }: any) => {
      await ack();
      const identity = resolveIdentity({ body });
      const provider = body.actions?.[0]?.value;
      if (!identity || typeof provider !== 'string' || !provider) return;
      const { ok } = await disconnectProvider(vault, audit, registry, identity, provider);
      emit({ type: 'revoked', provider, ok });
      if (body.view?.id) {
        let channel: string | null = null;
        try { ({ channel = null } = JSON.parse(body.view.private_metadata ?? '{}')); } catch { channel = null; }
        await client.views.update({ view_id: body.view.id, view: await buildConfigModal(identity, channel, client) }).catch(() => undefined);
      } else if (respond) {
        await respond({ replace_original: true, text: `✅ Disconnected *${provider}*. The agent can no longer act as you on ${provider}.` });
      }
    });

    // Per-user key setup: ephemeral button → private modal (self-service, not admin-gated).
    app.action(SETUP_KEY_ACTION, async ({ ack, body, client }: any) => {
      await ack();
      const provider = body.actions?.[0]?.value;
      if (!provider || !body.trigger_id) return;
      await client.views.open({ trigger_id: body.trigger_id, view: userKeyModal(provider) });
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

  /** Delete every connection past its TTL + clear stale consent + expired thread sessions. Run on a timer. */
  async function sweep(): Promise<number> {
    const n = await sweepExpired(vault, audit, consent, sink);
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
