import { WebClient } from '@slack/web-api';
import { openDb } from '../core/db';
import { loadMasterKey } from '../core/crypto';
import { ProviderRegistry, type Provider } from '../core/providers';
import { Vault, type TtlPolicy } from '../core/vault';
import { Audit } from '../core/audit';
import { Consent } from '../core/consent';
import { Policy } from '../core/policy';
import { resolveIdentity, isSlackAdmin, type SlackIdentity } from '../core/identity';
import { userOwner, channelOwner } from '../core/owner';
import { ConnectionHandle, type Resolvers } from '../core/injector';
import { ChannelConfig } from '../core/channelConfig';
import { handleOAuthCallback } from '../core/oauthCallback';
import { offboardUser } from '../core/offboard';
import { sweepExpired } from '../core/sweep';
import {
  connectBlocks, connectedHtml, configureModal, CONFIGURE_CALLBACK,
  userKeyModal, keySetupBlocks, USER_KEY_CALLBACK, SETUP_KEY_ACTION,
} from './blocks';

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
    super(`Consent required for "${provider}" — a Connect prompt was posted to the user.`);
    this.name = 'ConsentRequiredError';
  }
}

export interface VouchrOptions {
  providers: Provider[];
  /** Public origin where the callback is reachable, e.g. https://abc.ngrok.io */
  baseUrl: string;
  callbackPath?: string;
  /** SQLite file path (the zero-config default). */
  dbPath?: string;
  /** Postgres connection string — for stateless / multi-instance infra. Overrides dbPath. */
  databaseUrl?: string;
  policy?: Policy;
  /** Bot token used only to post the "connected" confirmation back to Slack. */
  botToken?: string;
  /** Connection lifetime. Defaults to idle 7d / max-age 30d. Pass `{}` to disable expiry. */
  ttl?: TtlPolicy;
  /** External secret-manager resolvers, keyed by source id (e.g. { 'aws-sm': resolveArn }). */
  resolvers?: Resolvers;
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
    // Shared single-flight refresh map (see ConnectionHandle). One per createVouchr instance.
    private inflight: Map<string, Promise<string | null>> = new Map(),
  ) {}

  /**
   * Return a leak-safe handle for the user's connection to `providerId`.
   * If they haven't connected, post an ephemeral Block Kit Connect prompt and
   * throw ConsentRequiredError (the caller should stop this turn).
   */
  async connect(providerId: string): Promise<ConnectionHandle> {
    const provider = this.registry.get(providerId);

    if (!this.policy.check(providerId, this.channel)) {
      await this.audit.record('denied', this.identity, providerId, { channel: this.channel });
      throw new Error(`Policy denies "${providerId}" in this channel.`);
    }

    if (await this.vault.get(userOwner(this.identity), providerId)) {
      return new ConnectionHandle(
        provider, userOwner(this.identity), this.identity, this.vault, this.audit, this.resolvers, this.inflight,
      );
    }

    // Key providers have no OAuth — post a self-service "set up your key" prompt instead.
    if (provider.credential === 'key') {
      await this.postKeySetupPrompt(providerId);
      throw new ConsentRequiredError(providerId);
    }

    const { authorizeUrl } = await this.consent.begin(
      this.identity,
      provider,
      this.redirectUri,
      this.channel,
    );
    await this.postConnectPrompt(providerId, authorizeUrl);
    throw new ConsentRequiredError(providerId);
  }

  /**
   * Store the acting user's OWN static key for `providerId` (key providers). Self-service —
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
    if (!(await isSlackAdmin(this.client, this.identity.userId))) {
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
    if (!this.channel) throw new Error('No channel in context — run this inside a channel.');
    return { cfg: this.channelConfig, owner: channelOwner(this.identity.teamId, this.channel), channel: this.channel };
  }

  /**
   * Refuse channel-owned (shared) credentials on channel classes where membership doesn't mean
   * "this workspace's own members" (invariant 6). Fails CLOSED: if we can't read the class, deny.
   * Externally-shared/Slack-Connect is the security-critical case — a shared cred there would leak
   * cross-org. Error messages name the reason and never carry tokens.
   */
  private async assertChannelEligible(): Promise<void> {
    let info: any;
    try {
      info = await this.client.conversations.info({ channel: this.channel! });
    } catch {
      throw new Error('Could not verify the channel type; channel credentials are refused.');
    }
    const ch = info?.channel;
    if (!ch) throw new Error('Could not verify the channel type; channel credentials are refused.');
    if (ch.is_ext_shared || ch.is_shared || ch.is_pending_ext_shared) {
      throw new Error('Channel credentials are not allowed in externally shared channels.');
    }
    if (ch.is_im || ch.is_mpim) {
      throw new Error('Channel credentials are not allowed in DMs or group DMs.');
    }
    if (ch.is_archived) {
      throw new Error('Channel credentials are not allowed in archived channels.');
    }
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
   * `'per-user'` removes the live shared cred (a re-own that must be re-authorized — the admin
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
    if ((await cfg.getMode(owner.teamId, channel, providerId)) === 'per-user') {
      throw new Error(`Channel "${channel}" uses per-user credentials for "${providerId}"; use connect() instead.`);
    }
    if (!(await this.vault.get(owner, providerId))) {
      throw new Error(`No channel credential configured for "${providerId}" in this channel.`);
    }
    // Defense in depth: re-verify class at use time (a channel can change class after config).
    // ponytail: one conversations.info per use (Slack Tier-3 ~50/min); cache the class with a short
    // TTL if a hot channel throttles. Correctness first — a channel turned Slack-Connect must stop now.
    await this.assertChannelEligible();
    return new ConnectionHandle(provider, owner, this.identity, this.vault, this.audit, this.resolvers, this.inflight);
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
  const vault = new Vault(db, key, opts.ttl ?? DEFAULT_TTL);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const channelConfig = new ChannelConfig(db);
  const policy = opts.policy ?? new Policy();
  const resolvers = opts.resolvers ?? {};
  const callbackPath = opts.callbackPath ?? '/vouchr/oauth/callback';
  const redirectUri = new URL(callbackPath, opts.baseUrl).toString();
  const botToken = opts.botToken ?? process.env.SLACK_BOT_TOKEN;
  const confirmClient = botToken ? new WebClient(botToken) : null;
  const inflight = new Map<string, Promise<string | null>>(); // shared single-flight refresh map

  /** Bolt global middleware: attach `context.vouchr` for each request with a user. */
  const middleware = async (args: any): Promise<void> => {
    const identity = resolveIdentity(args);
    if (identity) {
      const channel: string | null =
        args.event?.channel ?? args.body?.channel_id ?? args.body?.channel?.id ?? null;
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
        inflight,
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

        // Best-effort nudge back into Slack.
        if (confirmClient) {
          await confirmClient.chat
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
      identity, channel, client, registry, vault, audit, consent, policy, redirectUri, resolvers, channelConfig, inflight,
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

      const [sub, arg] = String(command.text ?? '').trim().split(/\s+/);
      if (sub === 'configure') {
        if (!arg) return respond('Usage: `/vouchr configure <provider>`');
        if (!command.channel_id) return respond('Run `/vouchr configure` from inside the channel you want to configure.');
        if (!(await isSlackAdmin(client, identity.userId))) {
          await audit.record('denied', identity, arg, { reason: 'not-admin', owner: 'channel', channel: command.channel_id });
          return respond('Only a workspace admin can configure channel credentials.');
        }
        await client.views.open({ trigger_id: command.trigger_id, view: configureModal(arg, command.channel_id) });
        return;
      }
      if (sub === 'disconnect') {
        if (!arg) return respond('Usage: `/vouchr disconnect <provider>`');
        // Note: local delete only — the agent immediately loses access, which is the
        // security-meaningful action. Upstream token revocation when a provider exposes a
        // revoke endpoint (add provider.revokeUrl then call it best-effort here).
        await vault.delete(userOwner(identity), arg);
        await audit.record('revoke', identity, arg, {});
        return respond(`Disconnected *${arg}*. The agent can no longer act as you on ${arg}.`);
      }

      const conns = await vault.listForUser(identity);
      if (!conns.length) return respond('No connected accounts. They are created on demand when an agent needs one.');
      const lines = conns
        .map((c) => `• *${c.provider}*${c.externalAccount ? ` — ${c.externalAccount}` : ''}`)
        .join('\n');
      return respond(`Your connected accounts:\n${lines}\n\nDisconnect with \`/vouchr disconnect <provider>\`.`);
    });

    // Modal submit (channel-shared OR per-user). One handler so both paths stay leak-safe and both
    // await the write — the typed value lives only in this view's state, never echoed, posted, logged,
    // or put in audit meta (invariant 8 / T7).
    const handleSecretSubmit = async ({ ack, body, view, client }: any, kind: 'channel' | 'user') => {
      const identity = resolveIdentity({ body });
      let channel = '';
      let provider = '';
      try {
        ({ channel = '', provider } = JSON.parse(view.private_metadata));
      } catch {
        return ack({ response_action: 'errors', errors: { ref: 'Malformed request — please reopen the modal.' } });
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
      // Private confirmation DM — no secret, just the fact it was set.
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
  }

  /** Remove all of a user's own connections + pending consent (offboarding). */
  function offboard(identity: SlackIdentity): Promise<string[]> {
    return offboardUser(vault, audit, consent, identity);
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
   * user_id alone — Slack user ids are unique only within a workspace, so a bare
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

  /** Delete every connection past its TTL + clear stale consent. Run on a timer. */
  function sweep(): Promise<number> {
    return sweepExpired(vault, audit, consent);
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
