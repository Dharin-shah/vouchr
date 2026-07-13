import { userOwner, channelOwner, type Owner } from './owner';
import type { SlackIdentity } from './identity';
import type { ChannelMode, ChannelConfig, PreviewVisibility } from './channelConfig';
import type { Policy } from './policy';
import type { ChannelTools, ToolManifestEntry } from './tools';
import type { ProviderRegistry } from './providers';

/**
 * The two SECURITY-CRITICAL decisions — credential-owner resolution and provider authorization —
 * as ONE transport-agnostic source of truth both adapters (Bolt + the headless HTTP broker) call.
 * They used to be duplicated across the two adapters and DRIFTED (that drift is how the session-mode
 * fail-closed rule went missing on the broker). Keeping the DECISION here means the Bolt path, the
 * Bolt adapter and packaged broker enforce the identical rule; each adapter keeps only its own
 * transport I/O (Slack client / HTTP status / audit meta / Block Kit prompts) and maps the result.
 *
 * No @slack/HTTP knowledge lives here (architecture.test.ts enforces it): callers pass in the already
 * VERIFIED facts (the Slack event / signed claim), never a request body. Fail-closed by construction.
 */

// ── Authorization (Policy + per-channel tool allowlist) ───────────────────────────────────────────

/** Why a provider is not authorized in a channel, or null if it is. The CHECK is shared; each adapter
 *  maps the reason to its own surface (audit meta, whether to emit policy_denied, error string/status). */
export type AuthzDenial = 'policy' | 'tool-disabled';

/**
 * The authorization VERDICT from the two already-resolved bits (pure, no I/O): Policy first, then the
 * channel tool allowlist. `policyAllows` = Policy permits this provider in this channel; `toolAllowed` =
 * the channel allowlist permits it (true where nothing restricts). `authorizeProvider` resolves the two
 * bits for ONE provider (a query); `buildToolManifest` resolves them for ALL providers in one batch —
 * both fold the ordering/mapping through HERE, so the manifest's `enabled` can never disagree with the
 * runtime gate or with which denial reason wins.
 */
export function authorizeVerdict(policyAllows: boolean, toolAllowed: boolean): AuthzDenial | null {
  if (!policyAllows) return 'policy';
  if (!toolAllowed) return 'tool-disabled';
  return null;
}

/**
 * The credential-use authorization gate, identical for both adapters: Policy first, then the per-channel
 * tool allowlist (backward-compat: an unconfigured channel allows all — see ChannelTools.isEnabled). The
 * channel/team are the VERIFIED ones (Slack event or signed claim), never a request body. Returns the
 * denial reason (or null); the caller decides audit/emit/error — deliberately, because the two adapters
 * differ there (e.g. the broker emits policy_denied on a tool-disabled deny and Bolt does not).
 */
export async function authorizeProvider(
  policy: Policy | undefined,
  channelTools: ChannelTools | undefined,
  principal: SlackIdentity,
  channel: string | null,
  provider: string,
): Promise<AuthzDenial | null> {
  const policyAllows = !policy || policy.check(provider, channel);
  // Resolve the tool-allowlist bit only when policy would allow AND there's a channel + store to
  // restrict against — so a policy-deny still never runs the allowlist query (unchanged short-circuit).
  const toolAllowed = policyAllows && channel && channelTools
    ? await channelTools.isEnabled(principal.teamId, channel, provider)
    : true;
  return authorizeVerdict(policyAllows, toolAllowed);
}

/**
 * The channel-scoped tool manifest an agent reads before planning: for every registered provider,
 * whether it's usable here (`enabled` = exactly "authorizeProvider would allow it", so the manifest
 * can never disagree with what connect()/fetch would do), the channel's credential mode, who the
 * agent acts as, and the preview visibility. ONE builder for both adapters — Bolt's
 * `toolManifest()` and the broker's `POST /v1/manifest` — so the two transports can't drift (the
 * broker shipped without ANY channel-scoped manifest at first, which is this file's failure mode).
 * With no channel (or no store opted in): mode null, visibility 'public', no allowlist restriction.
 */
export async function buildToolManifest(o: {
  providerIds: string[];
  registry: ProviderRegistry;
  policy?: Policy;
  channelTools?: ChannelTools;
  channelConfig?: ChannelConfig;
  principal: SlackIdentity;
  channel: string | null;
}): Promise<ToolManifestEntry[]> {
  // Three channel-scoped batch reads (tool allowlist, mode, visibility) — a fixed query count regardless
  // of provider count, replacing the per-provider isEnabled/getMode/getVisibility fan-out (#209). With no
  // channel (or no store) there is nothing channel-scoped to read: tools unrestricted, mode null, public.
  const toolAllowed: (provider: string) => boolean = o.channel && o.channelTools
    ? await o.channelTools.enabledSnapshot(o.principal.teamId, o.channel)
    : () => true;
  const modeOf: (provider: string) => ChannelMode | null = o.channel && o.channelConfig
    ? await o.channelConfig.modeSnapshot(o.principal.teamId, o.channel)
    : () => null;
  const visibilityOf: (provider: string) => PreviewVisibility = o.channel && o.channelConfig
    ? await o.channelConfig.visibilitySnapshot(o.principal.teamId, o.channel)
    : () => 'public';
  return o.providerIds.map((provider) => {
    const policyAllows = !o.policy || o.policy.check(provider, o.channel);
    return {
      provider,
      mode: modeOf(provider),
      // `enabled` = exactly authorizeProvider's verdict (via the shared authorizeVerdict), so the manifest
      // can never disagree with what connect()/fetch enforce in this channel.
      enabled: authorizeVerdict(policyAllows, toolAllowed(provider)) === null,
      // 'acting_human' (default) → Vouchr brokers it via connect(); 'service' → host's own service auth.
      identity: o.registry.get(provider).identity ?? 'acting_human',
      visibility: visibilityOf(provider),
    };
  });
}

// ── Owner resolution ──────────────────────────────────────────────────────────────────────────────

/** The owner-resolution decision: either a resolvable credential owner (+ the acting human to audit),
 *  or a typed "cannot serve" signal the adapter maps to its own surface. Fail-closed by construction. */
export type OwnerResolution =
  | { status: 'resolved'; owner: Owner; acting: SlackIdentity }
  /** No credential to serve: the caller is not connected. */
  | { status: 'needs_consent' }
  /** Session mode, fail-closed: no thread to scope a grant, or no live grant for it. */
  | { status: 'needs_session'; reason: 'no-thread' | 'no-session-grant' }
  /** Channel-borrow refused: an ineligible channel class, or a channel not configured for a channel cred. */
  | { status: 'refused'; code: 'ineligible' | 'not_configured' };

export interface OwnerInputs {
  /**
   * Which credential family the caller is on. The Bolt path derives this from the mode (`connect()` for
   * user-owned, `connectChannel()` for shared); the broker derives it from the SIGNED `ownerKind`.
   * 'user' → the caller's own credential (+ the session gate); 'channel' → the channel's shared credential.
   */
  path: 'user' | 'channel';
  /** The channel's configured mode for this provider; null = unconfigured (treated as per-user). */
  mode: ChannelMode | null;
  /** The acting human. Owner + audit derive from this + verified facts, NEVER a request body. */
  principal: SlackIdentity;
  /** The VERIFIED channel this request is in (Slack event / signed claim), or null off-channel. */
  channel: string | null;
  /**
   * Channel-borrow eligibility verdict, already computed by the adapter from the channel class via the
   * core `channelIneligibleReason` rule. Fail-closed: only an explicit `true` is eligible; undefined/false
   * refuses. (Only consulted on the channel path.)
   */
  eligible?: boolean;
  /** session: the thread to scope the grant to (null off-thread), and whether a live grant exists. */
  thread?: string | null;
  hasSessionGrant?: boolean;
  /**
   * user path: whether the caller already has a stored credential. Explicit `false` → needs_consent
   * (the Bolt path uses this to prompt). Undefined → resolve and let the injector 409 on a missing cred
   * (the broker relies on this — it never pre-reads the vault).
   */
  hasUserCredential?: boolean;
}

/**
 * Resolve which credential owner serves a request, or WHY it can't — the single source of truth both
 * adapters call. It folds in the session-mode fail-closed rule (a `session` channel is usable only inside
 * a thread with a live grant) and the channel-borrow eligibility + mode→owner mapping, so neither can
 * drift between the two transports. Pure: no I/O, no Slack/HTTP; the caller supplies verified facts.
 */
export function resolveCredentialOwner(i: OwnerInputs): OwnerResolution {
  if (i.path === 'user') {
    // 'session' is the one user-owned mode with a fail-closed gate: a live grant for THIS thread. Checked
    // before the stored-credential shortcut, so "connected once" still needs per-thread approval.
    if (i.mode === 'session') {
      if (!i.thread) return { status: 'needs_session', reason: 'no-thread' };
      if (!i.hasSessionGrant) return { status: 'needs_session', reason: 'no-session-grant' };
    }
    if (i.hasUserCredential === false) return { status: 'needs_consent' };
    return { status: 'resolved', owner: userOwner(i.principal), acting: i.principal };
  }

  // channel-borrow (shared). Eligibility is fail-closed for a channel-owned credential (invariant 6):
  // an externally-shared / Slack-Connect / DM / archived channel would leak cross-org.
  if (i.eligible !== true) return { status: 'refused', code: 'ineligible' };
  if (i.mode === 'shared' && i.channel) {
    // The channel OWNS the credential; the audited actor stays the acting human (invariant 9).
    return { status: 'resolved', owner: channelOwner(i.principal.teamId, i.channel), acting: i.principal };
  }
  // 'per-user' / 'session' / unconfigured are user-owned modes; a channel handle can't reach them.
  return { status: 'refused', code: 'not_configured' };
}
