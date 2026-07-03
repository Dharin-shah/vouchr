import { userOwner, channelOwner, type Owner } from './owner';
import type { SlackIdentity } from './identity';
import type { ChannelMode } from './channelConfig';
import type { Policy } from './policy';
import type { ChannelTools } from './tools';

/**
 * The two SECURITY-CRITICAL decisions — credential-owner resolution and provider authorization —
 * as ONE transport-agnostic source of truth both adapters (Bolt + the headless HTTP broker) call.
 * They used to be duplicated across the two adapters and DRIFTED (that drift is how the session-mode
 * fail-closed rule went missing on the broker). Keeping the DECISION here means the Bolt path, the
 * broker, and a future sidecar all enforce the identical rule; each adapter keeps only its own
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
  if (policy && !policy.check(provider, channel)) return 'policy';
  // Tool allowlist is channel-scoped; with no channel there is nothing to restrict (matches both adapters).
  if (channel && channelTools && !(await channelTools.isEnabled(principal.teamId, channel, provider))) {
    return 'tool-disabled';
  }
  return null;
}

// ── Owner resolution ──────────────────────────────────────────────────────────────────────────────

/** The owner-resolution decision: either a resolvable credential owner (+ the acting human to audit),
 *  or a typed "cannot serve" signal the adapter maps to its own surface. Fail-closed by construction. */
export type OwnerResolution =
  | { status: 'resolved'; owner: Owner; acting: SlackIdentity }
  /** No credential to serve (user path: caller not connected; union path: no member to act as). */
  | { status: 'needs_consent' }
  /** Session mode, fail-closed: no thread to scope a grant, or no live grant for it. */
  | { status: 'needs_session'; reason: 'no-thread' | 'no-session-grant' }
  /** Channel-borrow refused: an ineligible channel class, or a channel not configured for a channel cred. */
  | { status: 'refused'; code: 'ineligible' | 'not_configured' };

export interface OwnerInputs {
  /**
   * Which credential family the caller is on. The Bolt path derives this from the mode (`connect()` for
   * user-owned + union, `connectChannel()` for shared); the broker derives it from the SIGNED `ownerKind`.
   * 'user' → the caller's own credential (+ the session gate); 'channel' → a channel-borrowed credential
   * (shared cred or a union member's cred).
   */
  path: 'user' | 'channel';
  /** The channel's configured mode for this provider; null = unconfigured (treated as per-user). */
  mode: ChannelMode | null;
  /** The acting human. Owner + audit derive from this + verified facts, NEVER a request body. */
  principal: SlackIdentity;
  /** The VERIFIED channel this request is in (Slack event / signed claim), or null off-channel. */
  channel: string | null;
  /**
   * union: the connected member the caller resolved to act AS (their user-owned cred is borrowed and they
   * are the audited actor). null = no connected member. Only consulted on a union channel-path request.
   */
  actingMember?: SlackIdentity | null;
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

  // channel-borrow (shared / union). Eligibility is fail-closed for ANY channel-borrowed credential
  // (invariant 6): an externally-shared / Slack-Connect / DM / archived channel would leak cross-org.
  if (i.eligible !== true) return { status: 'refused', code: 'ineligible' };
  if (i.mode === 'shared' && i.channel) {
    // The channel OWNS the credential; the audited actor stays the acting human (invariant 9).
    return { status: 'resolved', owner: channelOwner(i.principal.teamId, i.channel), acting: i.principal };
  }
  if (i.mode === 'union') {
    // Borrow the connected member's OWN credential and act AS that member — never the channel, never the
    // caller. No member to borrow → needs_consent (Bolt falls through to prompt; the broker maps to 400).
    if (!i.actingMember) return { status: 'needs_consent' };
    return { status: 'resolved', owner: userOwner(i.actingMember), acting: i.actingMember };
  }
  // 'per-user' / 'session' / unconfigured are user-owned modes; a channel handle can't reach them.
  return { status: 'refused', code: 'not_configured' };
}
