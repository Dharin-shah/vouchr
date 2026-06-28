import { WebClient } from '@slack/web-api';
import type { InstallationStore } from '@slack/bolt';
import { openDb } from '../core/db';
import { loadMasterKey, type EnvelopeProvider } from '../core/crypto';
import { ProviderRegistry, type Provider } from '../core/providers';
import { Vault, type TtlPolicy } from '../core/vault';
import { Audit } from '../core/audit';
import { Consent } from '../core/consent';
import { Policy } from '../core/policy';
import { resolveIdentity, isSlackAdmin, isChannelMember, type SlackIdentity } from '../core/identity';
import { userOwner, channelOwner } from '../core/owner';
import { ConnectionHandle, type Resolvers, type EventSink, type VouchrEvent } from '../core/injector';
import { ChannelConfig, channelIneligibleReason, type ChannelInfo } from '../core/channelConfig';
import { ChannelTools, type ToolManifestEntry } from '../core/tools';
import { handleOAuthCallback } from '../core/oauthCallback';
import { offboardUser } from '../core/offboard';
import { revokeToken } from '../core/tokens';
import { sweepExpired } from '../core/sweep';
import { SessionGrants, type SessionEnforcement } from '../core/session';
import {
  connectBlocks, connectedHtml, configureModal, CONFIGURE_CALLBACK,
  userKeyModal, keySetupBlocks, USER_KEY_CALLBACK, SETUP_KEY_ACTION,
  sessionApprovalBlocks, APPROVE_SESSION_ACTION,
} from './blocks';

/** Default session-grant safety ceiling: 8h. The thread binding is the real scope; this just caps
 *  how long a single approval can live before the user must re-approve in the thread. */
const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

/** Map an external ref to its resolver source id. Add resolvers → extend this. */
function refSource(ref: string): string {
  if (/^arn:aws:secretsmanager:/.test(ref)) return 'aws-sm';
  throw new Error('Unsupported secret reference. Expected an AWS Secrets Manager ARN.');
}

/** Aggressive default per-user connection lifetime: idle 7d, hard cap 30d. */
const DEFAULT_TTL: TtlPolicy = { idleMs: 7 * 24 * 60 * 60 * 1000, maxAgeMs: 30 * 24 * 60 * 60 * 1000 };

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
   * Custom admin check for channel-credential config (governance). When set, `requireAdmin` uses
   * it INSTEAD of the built-in Slack is_admin/is_owner gate, e.g. to defer to your own RBAC or an
   * allow-list. When omitted, the gate is exactly as before (`isSlackAdmin`). The default-deny +
   * audit-on-denial behavior is identical regardless of which check runs. Fail closed yourself:
   * a thrown override is treated as "not admin".
   */
  isAdmin?: (client: WebClient, userId: string, teamId: string) => Promise<boolean>;
  /**
   * When true, using a SHARED channel credential (`connectChannel`) requires the ACTING user to be
   * a member of the channel; a non-member (or a membership check we can't verify) is refused
   * fail-closed and audited 'denied' with reason 'not-member'. Default false: membership is not
   * checked, behaving exactly as before.
   */
  requireChannelMembership?: boolean;
  /**
   * Opt-in thread-scoped sessions. When set, `connect()` for a covered provider returns a handle
   * only if the acting user has approved that provider IN THE CURRENT Slack thread; otherwise it
   * posts an in-thread "Allow … here" button and throws `SessionApprovalRequiredError`. A grant is
   * bound to (team, channel, thread, user, provider) and cannot be used in any other thread. It
   * always expires after `ttlMs` (safety ceiling, default 8h). `providers` limits which providers
   * require a session ('all' or an explicit list); omit for 'all'. Unset = no session gate (default).
   */
  session?: { ttlMs?: number; providers?: string[] | 'all' };
}

/** Per-request handle attached to Bolt's `context.vouchr`. */
export class ConnectContext {
  constructor(
    private identity: SlackIdentity,
    private channel: string | null,
    private client: WebClient,
    private registry: ProviderRegistry,
    private vault: Vault,
    private audit: Audit,
    private consent: Consent,
    private policy: Policy,
    private redirectUri: string,
    private resolvers: Resolvers = {},
    private channelConfig?: ChannelConfig,
    // Per-channel tool manifest (which providers an agent may use here). Threaded like channelConfig.
    private channelTools?: ChannelTools,
    // Shared single-flight refresh map (see ConnectionHandle). One per createVouchr instance.
    private inflight: Map<string, Promise<string | null>> = new Map(),
    // No-secret observability hook. Default no-op (zero behavior change when unset).
    private sink: EventSink = () => {},
    // The registered provider ids, for toolManifest(). Mirrors the registry; empty = none listed.
    private providerIds: string[] = [],
    // Governance: custom admin check (overrides isSlackAdmin). Undefined = built-in Slack gate.
    private adminCheck?: (client: WebClient, userId: string, teamId: string) => Promise<boolean>,
    // Governance: when true, connectChannel requires the acting user to be a channel member.
    private requireMembership: boolean = false,
    // The Slack thread (thread_ts) this request is in, for thread-scoped sessions. Null off-thread.
    private thread: string | null = null,
    // Thread-scoped session store + enforcement config. Undefined cfg = no session gate (default).
    private sessions?: SessionGrants,
    private sessionCfg?: SessionEnforcement,
  ) {}

  /** Fire the sink, swallowing any error. A bad sink must never break a request. */
  private emit(e: VouchrEvent): void {
    try {
      this.sink(e);
    } catch {
      // ignore: observability is best-effort, never fatal
    }
  }

  /**
   * Return a leak-safe handle for the user's connection to `providerId`.
   * If they haven't connected, post an ephemeral Block Kit Connect prompt and
   * throw ConsentRequiredError (the caller should stop this turn).
   */
  async connect(providerId: string): Promise<ConnectionHandle> {
    const provider = this.registry.get(providerId);

    if (!this.policy.check(providerId, this.channel)) {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel });
      this.emit({ type: 'policy_denied', provider: providerId });
      throw new Error(`Policy denies "${providerId}" in this channel.`);
    }

    // Channel tool manifest: refuse a provider not enabled for this channel (backward-compat rule
    // in ChannelTools, an unconfigured channel allows all). A null channel keeps current behavior.
    if (this.channel && this.channelTools &&
        !(await this.channelTools.isEnabled(this.identity.teamId, this.channel, providerId))) {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel, reason: 'tool-disabled' });
      throw new Error(`"${providerId}" is not enabled in this channel.`);
    }

    // Thread-scoped session (opt-in): a covered provider is usable only inside the Slack thread the
    // user approved it in. No grant → post an in-thread approval button and stop the turn. Checked
    // before the stored-connection shortcut, so "connected once" still needs per-thread approval.
    if (this.sessionCfg?.requires(providerId)) {
      if (!this.channel || !this.thread) {
        await this.audit.record('denied', this.identity, providerId, { channel: this.channel, reason: 'no-thread' });
        throw new Error(`"${providerId}" needs a thread-scoped session; ask me inside a thread.`);
      }
      if (!this.sessions || !(await this.sessions.isGranted(this.identity, this.channel, this.thread, providerId))) {
        await this.postSessionApprovalPrompt(providerId, this.thread);
        await this.audit.record('session', this.identity, providerId, { channel: this.channel, thread: this.thread, event: 'prompt' });
        throw new SessionApprovalRequiredError(providerId);
      }
    }

    if (await this.vault.get(userOwner(this.identity), providerId)) {
      return new ConnectionHandle(
        provider, userOwner(this.identity), this.identity, this.vault, this.audit, this.resolvers, this.inflight, this.sink,
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
   * Store the acting user's OWN static key for `providerId` (key providers). Self-service,
   * NOT admin-gated (it's the user's own credential), keyed to `userOwner`. Leak-safe: the
   * secret never enters audit meta, the return value, or any error string.
   */
  async setUserSecret(providerId: string, secret: string): Promise<void> {
    this.registry.get(providerId);
    await this.vault.upsert(userOwner(this.identity), providerId, {
      accessToken: secret, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
    await this.audit.record('config', this.identity, providerId, { owner: 'user', kind: 'secret' });
  }

  /** Point the acting user's OWN credential at an external secret manager (self-service). */
  async referenceUserSecret(providerId: string, r: { source: string; secretRef: string; scopes?: string }): Promise<void> {
    this.registry.get(providerId);
    await this.vault.reference(userOwner(this.identity), providerId, { source: r.source, secretRef: r.secretRef, scopes: r.scopes });
    await this.audit.record('config', this.identity, providerId, { owner: 'user', kind: 'ref', source: r.source });
  }

  /** Whether the user already has a stored connection (no prompt side-effect). */
  async isConnected(providerId: string): Promise<boolean> {
    return (await this.vault.get(userOwner(this.identity), providerId)) != null;
  }

  // ── Channel-owned credentials (Phase 1: embedded, safe-by-construction). ──────────
  // `this.channel` comes from the VERIFIED Slack event, so the channel binding cannot be
  // forged (invariant 1). teamId is always the authenticated user's (invariant 2).

  /** Default-deny admin gate for config mutations (invariant 7). Audits the denial. */
  private async requireAdmin(providerId: string): Promise<void> {
    // A custom check overrides the built-in Slack gate; a thrown override fails closed (not admin).
    const ok = this.adminCheck
      ? await this.adminCheck(this.client, this.identity.userId, this.identity.teamId).catch(() => false)
      : await isSlackAdmin(this.client, this.identity.userId);
    if (!ok) {
      await this.audit.record('denied', this.identity, providerId, {
        reason: 'not-admin',
        owner: 'channel',
        channel: this.channel,
      });
      throw new Error(`Only a workspace admin can configure channel credentials.`);
    }
  }

  private channelTarget(providerId: string) {
    if (!this.channelConfig) throw new Error('Channel config store not available.');
    if (!this.channel) throw new Error('No channel in context. Run this inside a channel.');
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
    if (reason) throw new Error(reason);
  }

  /**
   * Store a raw static key as the channel's shared credential for `providerId`. Admin-only,
   * audited, refused on a `'per-user'`-locked channel (invariant 7). The secret never enters
   * the audit meta, the return value, or any error string (invariant 8 / T7). Prefer
   * `referenceChannelSecret` so rotation stays in your secret manager.
   */
  async setChannelSecret(providerId: string, secret: string): Promise<void> {
    this.registry.get(providerId); // validate provider exists before anything else
    const { cfg, owner, channel } = this.channelTarget(providerId);
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    if ((await cfg.getMode(owner.teamId, channel, providerId)) === 'per-user') {
      throw new Error(`Channel is set to per-user for "${providerId}"; static keys are not allowed.`);
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
    this.registry.get(providerId);
    const { cfg, owner, channel } = this.channelTarget(providerId);
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    if ((await cfg.getMode(owner.teamId, channel, providerId)) === 'per-user') {
      throw new Error(`Channel is set to per-user for "${providerId}"; shared references are not allowed.`);
    }
    await this.vault.reference(owner, providerId, { source: r.source, secretRef: r.secretRef, scopes: r.scopes });
    await cfg.setMode(owner.teamId, channel, providerId, 'shared');
    await this.audit.record('config', this.identity, providerId, { owner: 'channel', channel, mode: 'shared', kind: 'ref', source: r.source });
  }

  /**
   * Lock/unlock the channel's mode for a provider. Admin-only, audited. Flipping to
   * `'per-user'` removes the live shared cred (a re-own that must be re-authorized, the admin
   * gate is that authorization). Members then use their own creds via `connect()`.
   */
  async setChannelMode(providerId: string, mode: 'shared' | 'per-user'): Promise<void> {
    this.registry.get(providerId);
    const { cfg, owner, channel } = this.channelTarget(providerId);
    await this.requireAdmin(providerId);
    await this.assertChannelEligible();
    if (mode === 'per-user') await this.vault.delete(owner, providerId);
    await cfg.setMode(owner.teamId, channel, providerId, mode);
    await this.audit.record('config', this.identity, providerId, { owner: 'channel', channel, mode });
  }

  /**
   * Return a leak-safe handle for the CHANNEL's shared credential for `providerId`. The handle
   * keys the vault on the channel but audits as the acting human (invariant 9). Throws if the
   * channel is per-user-locked or has no shared cred configured.
   */
  async connectChannel(providerId: string): Promise<ConnectionHandle> {
    const provider = this.registry.get(providerId);
    const { cfg, owner, channel } = this.channelTarget(providerId);
    // Same provider/channel policy gate as connect(): a deny applies to shared channel creds too.
    if (!this.policy.check(providerId, this.channel)) {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel, owner: 'channel' });
      this.emit({ type: 'policy_denied', provider: providerId });
      throw new Error(`Policy denies "${providerId}" in this channel.`);
    }
    // Same tool-manifest gate as connect(): a disabled provider is unusable here, shared cred or not.
    if (this.channelTools && !(await this.channelTools.isEnabled(owner.teamId, channel, providerId))) {
      await this.audit.record('denied', this.identity, providerId, { channel, owner: 'channel', reason: 'tool-disabled' });
      throw new Error(`"${providerId}" is not enabled in this channel.`);
    }
    if ((await cfg.getMode(owner.teamId, channel, providerId)) === 'per-user') {
      throw new Error(`Channel "${channel}" uses per-user credentials for "${providerId}"; use connect() instead.`);
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
    return new ConnectionHandle(provider, owner, this.identity, this.vault, this.audit, this.resolvers, this.inflight, this.sink);
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
      out.push({ provider, mode, enabled });
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
    const blocks = connectBlocks(providerId, url);
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
  // Thread-scoped session enforcement, resolved once from opts.session. Undefined = no gate.
  const sessionTtlMs = opts.session?.ttlMs ?? DEFAULT_SESSION_TTL_MS;
  const sessionCfg: SessionEnforcement | undefined = opts.session
    ? {
        ttlMs: sessionTtlMs,
        requires: (p) => {
          const list = opts.session!.providers;
          return !list || list === 'all' || list.includes(p);
        },
      }
    : undefined;
  const providerIds = opts.providers.map((p) => p.id); // for toolManifest(); mirrors the registry
  const policy = opts.policy ?? new Policy();
  const resolvers = opts.resolvers ?? {};
  const callbackPath = opts.callbackPath ?? '/vouchr/oauth/callback';
  const redirectUri = new URL(callbackPath, opts.baseUrl).toString();
  const botToken = opts.botToken ?? process.env.SLACK_BOT_TOKEN;
  const confirmClient = botToken ? new WebClient(botToken) : null;
  const inflight = new Map<string, Promise<string | null>>(); // shared single-flight refresh map
  const sink: EventSink = opts.onEvent ?? (() => {});
  // Safe emit for the createVouchr-level paths (OAuth callback, disconnect) that aren't inside a
  // ConnectContext/ConnectionHandle. A throwing sink must never break a request.
  const emit = (e: VouchrEvent): void => {
    try {
      sink(e);
    } catch {
      // ignore: observability is best-effort, never fatal
    }
  };
  const commandAdmin = async (client: WebClient, identity: SlackIdentity): Promise<boolean> => {
    return opts.isAdmin
      ? await opts.isAdmin(client, identity.userId, identity.teamId).catch(() => false)
      : await isSlackAdmin(client, identity.userId);
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
      args.context.vouchr = new ConnectContext(
        identity,
        channel,
        args.client,
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
        opts.isAdmin,
        opts.requireChannelMembership ?? false,
        thread,
        sessions,
        sessionCfg,
      );
    }
    await args.next();
  };

  const callbackDeps = { registry, vault, audit, consent, redirectUri };

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
        res.set('content-type', 'text/html').send(connectedHtml(result.provider, result.account));
      } catch {
        // Express doesn't catch async rejections; an unhandled one here hangs the browser.
        res.status(500).send('Connection failed. Please try again.');
      }
    });
  }

  /** Build a per-request ConnectContext bound to a specific channel (for the modal submit). */
  function contextFor(identity: SlackIdentity, channel: string | null, client: WebClient): ConnectContext {
    return new ConnectContext(
      identity, channel, client, registry, vault, audit, consent, policy, redirectUri, resolvers,
      channelConfig, channelTools, inflight, sink, providerIds,
      opts.isAdmin, opts.requireChannelMembership ?? false, null, sessions, sessionCfg,
    );
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

      // Enable/disable a provider in this channel. Admin-gated (default-deny) + audited as 'config'.
      if (sub === 'enable' || sub === 'disable') {
        if (!arg) return respond(`Usage: \`/vouchr ${sub} <provider>\``);
        if (!command.channel_id) return respond(`Run \`/vouchr ${sub}\` from inside the channel you want to configure.`);
        if (!registry.has(arg)) return respond(`Unknown provider "${arg}".`);
        if (!(await commandAdmin(client, identity))) {
          await audit.record('denied', identity, arg, { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
          return respond('Only a workspace admin can change channel tools.');
        }
        const on = sub === 'enable';
        await channelTools.setEnabled(identity.teamId, command.channel_id, arg, on);
        await audit.record('config', identity, arg, { owner: 'channel', channel: command.channel_id, tool: on ? 'enabled' : 'disabled' });
        return respond(`${on ? 'Enabled' : 'Disabled'} *${arg}* in <#${command.channel_id}>.`);
      }

      // Shortcut for the existing per-channel credential mode (admin-gated + audited in setChannelMode).
      if (sub === 'mode') {
        if (!arg || (arg2 !== 'shared' && arg2 !== 'per-user')) {
          return respond('Usage: `/vouchr mode <provider> <shared|per-user>`');
        }
        if (!command.channel_id) return respond('Run `/vouchr mode` from inside the channel you want to configure.');
        try {
          await contextFor(identity, command.channel_id, client).setChannelMode(arg, arg2);
        } catch (e) {
          return respond((e as Error).message); // never carries a secret
        }
        return respond(`Set *${arg}* to *${arg2}* in <#${command.channel_id}>.`);
      }

      if (sub === 'configure') {
        if (!arg) return respond('Usage: `/vouchr configure <provider>`');
        if (!command.channel_id) return respond('Run `/vouchr configure` from inside the channel you want to configure.');
        if (!(await commandAdmin(client, identity))) {
          await audit.record('denied', identity, arg, { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
          return respond('Only a workspace admin can configure channel credentials.');
        }
        await client.views.open({ trigger_id: command.trigger_id, view: configureModal(arg, command.channel_id) });
        return;
      }
      if (sub === 'disconnect') {
        if (!arg) return respond('Usage: `/vouchr disconnect <provider>`');
        // Read the token BEFORE deleting; local delete (the security-meaningful action) FIRST,
        // then best-effort upstream revoke. A revoke failure is non-fatal: the user still sees
        // a successful disconnect (local access is already gone).
        const cred = registry.has(arg) ? await vault.get(userOwner(identity), arg) : null;
        await vault.delete(userOwner(identity), arg);
        let ok = true;
        try {
          if (cred?.accessToken) await revokeToken(registry.get(arg), cred.accessToken);
        } catch {
          ok = false;
        }
        await audit.record('revoke', identity, arg, { ok }); // never the token
        emit({ type: 'revoked', provider: arg, ok });
        return respond(`Disconnected *${arg}*. The agent can no longer act as you on ${arg}.`);
      }

      const conns = await vault.listForUser(identity);
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
        // The error never contains the secret (we never interpolate it); surface it inline.
        return ack({ response_action: 'errors', errors: { [ref ? 'ref' : 'raw']: (e as Error).message } });
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

  /** Remove all of a user's own connections + pending consent + thread sessions (offboarding). */
  async function offboard(identity: SlackIdentity): Promise<string[]> {
    await sessions.revokeForUser(identity); // a deactivated user's thread grants must not survive
    return offboardUser(vault, audit, consent, identity, registry); // registry → best-effort upstream revoke
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

  return {
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
