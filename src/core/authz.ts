import { userOwner, channelOwner, type Owner } from './owner';
import type { SlackIdentity } from './identity';
import { ChannelConfig, type ChannelIdentity } from './channelConfig';
import type { Policy } from './policy';
import { ChannelTools, type ToolManifestEntry } from './tools';
import { isBrokeredProvider, type ProviderRegistry } from './providers';
import type { Db } from './db';

/**
 * The two SECURITY-CRITICAL decisions — credential-owner resolution and provider authorization —
 * as ONE transport-agnostic source of truth both adapters (Bolt + the headless HTTP broker) call.
 * They used to be duplicated across the two adapters and DRIFTED. Keeping the DECISION here means the
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

/** Static/provider policy refused this channel. The caller cannot repair governance by retrying. */
export class PolicyDeniedError extends Error {
  readonly code = 'policy_denied' as const;

  constructor() {
    super('Provider policy denies this request.');
    this.name = 'PolicyDeniedError';
  }
}

/** The channel's explicit tool allowlist disabled this provider. Retrying cannot change the bit. */
export class ToolDisabledError extends Error {
  readonly code = 'tool_disabled' as const;

  constructor() {
    super('Provider is disabled in this channel.');
    this.name = 'ToolDisabledError';
  }
}

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

/** Whether a store's batch method is safe to use without bypassing an existing customization in the
 * legacy single-provider call chain. Plain shipped stores keep every relevant prototype method. A
 * custom batch method is authoritative; otherwise any legacy override forces the compatibility path,
 * or the manifest can disagree with runtime authorization. */
function usableBatchMethod(batch: unknown, baseBatch: unknown, baseMethodsUnchanged: boolean): batch is (...args: any[]) => Promise<any> {
  return typeof batch === 'function' && (batch !== baseBatch || baseMethodsUnchanged);
}

/** Resolve the raw tool-allowlist bits for a channel. Shipped stores take one read; legacy/custom
 * stores that only implement or override `isEnabled` retain their existing behavior. */
export async function snapshotToolAllowlist(
  store: ChannelTools,
  teamId: string,
  channel: string,
  providerIds: readonly string[],
): Promise<(provider: string) => boolean> {
  if (providerIds.length === 0) return () => true;
  const batch = (store as Partial<ChannelTools>).enabledSnapshot;
  const single = (store as Partial<ChannelTools>).isEnabled;
  const configured = (store as Partial<ChannelTools>).isConfigured;
  if (usableBatchMethod(
    batch,
    ChannelTools.prototype.enabledSnapshot,
    single === ChannelTools.prototype.isEnabled && configured === ChannelTools.prototype.isConfigured,
  )) {
    return batch.call(store, teamId, channel);
  }
  if (typeof single !== 'function') throw new Error('channel tools store must implement isEnabled');
  const values = new Map<string, boolean>();
  for (const provider of new Set(providerIds)) values.set(provider, await single.call(store, teamId, channel, provider));
  return (provider) => values.get(provider) ?? false;
}

/** Batched identity resolver with the same compatibility rule as {@link snapshotToolAllowlist}. */
export async function snapshotChannelIdentities(
  store: ChannelConfig,
  teamId: string,
  channel: string,
  providerIds: readonly string[],
): Promise<(provider: string) => ChannelIdentity> {
  if (providerIds.length === 0) return () => 'person';
  const batch = (store as Partial<ChannelConfig>).identitySnapshot;
  const single = (store as Partial<ChannelConfig>).getIdentity;
  if (usableBatchMethod(batch, ChannelConfig.prototype.identitySnapshot, single === ChannelConfig.prototype.getIdentity)) {
    return batch.call(store, teamId, channel);
  }
  if (typeof single !== 'function') throw new Error('channel config store must implement getIdentity');
  const values = new Map<string, ChannelIdentity>();
  for (const provider of new Set(providerIds)) values.set(provider, await single.call(store, teamId, channel, provider));
  return (provider) => values.get(provider) ?? 'person';
}

/**
 * A DM or group-DM is a PERSONAL conversation that per-channel governance (the mutable tool
 * allowlist + channel identity) does not reach: there is no channel roster to enable a provider, so
 * deny-by-default must NOT lock it out. Map a VERIFIED delivery channel to its mutable-governance
 * scope — null for a personal conversation, else the channel itself. Static Policy is a DIFFERENT
 * axis (deployment config, not channel-mutable) and keeps evaluating against the real delivery channel,
 * so a deployment can still deny a provider in DMs / allow it only in named channels.
 *
 * `channelType` is Slack's event `channel_type`; it identifies a group DM whose id is
 * not `D…`. The id-prefix check alone catches a 1:1 DM when only the channel string is available (a
 * signed broker claim, or a retained-use re-check that carries no channel_type).
 * ponytail: a group-DM whose id is neither `D…` nor accompanied by channel_type stays governed —
 * reachable only on a re-check that lost the original channel_type, never on the connect path.
 */
export const SLACK_CONVERSATION_TYPES = Object.freeze([
  'channel',
  'group',
  'im',
  'mpim',
  'app_home',
] as const);
export type SlackConversationType = (typeof SLACK_CONVERSATION_TYPES)[number];

/** Runtime guard shared by every transport that accepts Slack's conversation type. Keep the closed
 * set beside the governance decision it controls: an unknown or malformed value must never become
 * a signed authorization fact or silently exempt a channel from deny-by-default. */
export function isSlackConversationType(value: unknown): value is SlackConversationType {
  return typeof value === 'string'
    && (SLACK_CONVERSATION_TYPES as readonly string[]).includes(value);
}

export function governanceChannelOf(
  channel: string | null,
  channelType?: SlackConversationType,
): string | null {
  if (channel === null) return null;
  if (channel.startsWith('D')) return null;
  // Slack's MPIM ids share the G… prefix with private channels. Require both facts before widening
  // the governance scope; a contradictory signed type/id pair fails closed as governed.
  if (channelType === 'mpim' && channel.startsWith('G')) return null;
  return channel;
}

/** Validate a persisted/forwarded governance classification for one delivery channel. A governed
 * scope is always the exact channel. Personal scope is valid only for Slack's DM id classes: D… is
 * unambiguous, while G… needs the separately verified MPIM fact at the adapter boundary. */
export function isGovernanceChannelScope(
  channel: string | null,
  scope: string | null,
): boolean {
  if (scope !== null) return scope === channel;
  return channel === null || channel.startsWith('D') || channel.startsWith('G');
}

/**
 * The credential-use authorization gate, identical for both adapters: Policy first, then the per-channel
 * tool allowlist (deny-by-default: an unconfigured channel allows nothing — see ChannelTools.isEnabled).
 * The channel/team are the VERIFIED ones (Slack event or signed claim), never a request body. Returns
 * the denial reason (or null); the caller decides audit/emit/error — deliberately, because the two
 * adapters differ there (e.g. the broker emits policy_denied on a tool-disabled deny and Bolt does not).
 *
 * TWO channel scopes, deliberately distinct (see governanceChannelOf): `channel` is the real delivery
 * channel that static Policy evaluates against (a DM included); `governanceChannel` is the mutable
 * tool-allowlist scope, null in a personal conversation so deny-by-default never locks a DM out.
 */
export async function authorizeProvider(
  policy: Policy | undefined,
  channelTools: ChannelTools | undefined,
  principal: SlackIdentity,
  channel: string | null,
  governanceChannel: string | null,
  provider: string,
  db?: Db,
): Promise<AuthzDenial | null> {
  const policyAllows = !policy || policy.check(provider, channel);
  // Resolve the tool-allowlist bit only when policy would allow AND there's a GOVERNANCE channel +
  // store to restrict against — so a policy-deny still never runs the allowlist query (unchanged
  // short-circuit), and a personal conversation (governanceChannel null) is never allowlist-gated.
  const toolAllowed = policyAllows && governanceChannel && channelTools
    ? await channelTools.isEnabled(principal.teamId, governanceChannel, provider, db)
    : true;
  return authorizeVerdict(policyAllows, toolAllowed);
}

/**
 * The channel-scoped tool manifest an agent reads before planning: for every registered provider,
 * whether it's usable here (`enabled` = exactly "authorizeProvider would allow it", so the manifest
 * can never disagree with what connect()/fetch would do) and who the agent acts as there. ONE
 * builder for both adapters — Bolt's
 * `toolManifest()` and the broker's `POST /v1/manifest` — so the two transports can't drift (the
 * broker shipped without ANY channel-scoped manifest at first, which is this file's failure mode).
 * With no channel (or no store opted in): identity 'person', no allowlist restriction.
 */
export interface ToolManifestBuildOptions {
  providerIds: string[];
  registry: ProviderRegistry;
  policy?: Policy;
  channelTools?: ChannelTools;
  channelConfig?: ChannelConfig;
  principal: SlackIdentity;
  /** The real delivery channel static Policy evaluates against (a DM included). */
  channel: string | null;
  /** The mutable-governance scope (tool allowlist + identity); null in a personal conversation so a
   *  DM reports personal providers enabled. Defaults to `channel` when omitted (a governed channel). */
  governanceChannel?: string | null;
}

/** Build the public manifest and retain the raw allowlist predicate used to produce it. Governance
 * renderers reuse that predicate instead of querying the same channel twice; the public manifest
 * wrapper below deliberately returns only the serializable rows. */
export async function buildToolManifestSnapshot(o: ToolManifestBuildOptions): Promise<{
  tools: ToolManifestEntry[];
  toolAllowed: (provider: string) => boolean;
}> {
  if (o.providerIds.length === 0) return { tools: [], toolAllowed: () => true };
  // Governance (tool allowlist + identity) is scoped to the mutable-governance channel: null in a DM,
  // so the manifest reports personal providers enabled there; static Policy still evaluates against
  // the real delivery channel below, so a policy-denied provider is still reported disabled in a DM.
  const governanceChannel = o.governanceChannel === undefined ? o.channel : o.governanceChannel;
  // Two channel-scoped batch reads (tool allowlist and identity), a fixed query count regardless of
  // provider count (#209). With no governance channel (or no store) there is nothing channel-scoped
  // to read: tools unrestricted and everyone acts as themselves. Dispatch the two reads together so
  // a slow database costs one round-trip window (important before Slack trigger_id expiry).
  const [toolAllowed, identityOf] = await Promise.all([
    governanceChannel && o.channelTools
      ? snapshotToolAllowlist(o.channelTools, o.principal.teamId, governanceChannel, o.providerIds)
      : Promise.resolve((_provider: string) => true),
    governanceChannel && o.channelConfig
      ? snapshotChannelIdentities(o.channelConfig, o.principal.teamId, governanceChannel, o.providerIds)
      : Promise.resolve((_provider: string): ChannelIdentity => 'person'),
  ]);
  const tools = o.providerIds.map((provider): ToolManifestEntry => {
    const policyAllows = !o.policy || o.policy.check(provider, o.channel);
    return {
      provider,
      // `enabled` = exactly authorizeProvider's verdict (via the shared authorizeVerdict), so the manifest
      // can never disagree with what connect()/fetch enforce in this channel.
      enabled: authorizeVerdict(policyAllows, toolAllowed(provider)) === null,
      // A service tool has no Vouchr-owned credential, so even a stale config row cannot advertise a
      // channel identity the runtime will never honor.
      identity: isBrokeredProvider(o.registry.get(provider)) ? identityOf(provider) : 'service',
    };
  });
  return { tools, toolAllowed };
}

export async function buildToolManifest(o: ToolManifestBuildOptions): Promise<ToolManifestEntry[]> {
  return (await buildToolManifestSnapshot(o)).tools;
}

// ── Owner resolution ──────────────────────────────────────────────────────────────────────────────

/** The owner-resolution decision: either a resolvable credential owner (+ the acting human to audit),
 *  or a typed "cannot serve" signal the adapter maps to its own surface. Fail-closed by construction. */
export type OwnerResolution =
  | { status: 'resolved'; owner: Owner; acting: SlackIdentity }
  /** No credential to serve: the caller is not connected. */
  | { status: 'needs_consent' }
  /** Channel credential refused: an ineligible channel class, or a channel whose identity is 'person'. */
  | { status: 'refused'; code: 'ineligible' | 'not_configured' };

export interface OwnerInputs {
  /**
   * Which credential family the caller is on. The Bolt path derives this from the channel identity
   * (`connect()` for the person's own credential, `connectChannel()` for the channel's); the broker
   * derives it from the SIGNED `ownerKind`.
   */
  path: 'user' | 'channel';
  /** Who the agent acts as for this provider in the channel ('person' where nothing is configured). */
  identity: ChannelIdentity;
  /** The acting human. Owner + audit derive from this + verified facts, NEVER a request body. */
  principal: SlackIdentity;
  /** The VERIFIED channel this request is in (Slack event / signed claim), or null off-channel. */
  channel: string | null;
  /**
   * Channel-credential eligibility verdict, already computed by the adapter from the channel class via
   * the core `channelIneligibleReason` rule. Fail-closed: only an explicit `true` is eligible;
   * undefined/false refuses. (Only consulted on the channel path.)
   */
  eligible?: boolean;
  /**
   * user path: whether the caller already has a stored credential. Explicit `false` -> needs_consent
   * (the Bolt path uses this to prompt). Undefined -> resolve and let the injector 409 on a missing cred
   * (the broker relies on this; it never pre-reads the vault).
   */
  hasUserCredential?: boolean;
}

/**
 * Resolve which credential owner serves a request, or WHY it can't: the single source of truth both
 * adapters call. It folds in the channel-credential eligibility + identity -> owner mapping, so
 * neither can drift between the two transports. Pure: no I/O, no Slack/HTTP; the caller supplies
 * verified facts.
 */
export function resolveCredentialOwner(i: OwnerInputs): OwnerResolution {
  if (i.path === 'user') {
    if (i.hasUserCredential === false) return { status: 'needs_consent' };
    return { status: 'resolved', owner: userOwner(i.principal), acting: i.principal };
  }

  // Channel credential. Eligibility is fail-closed (invariant 6): an externally-shared /
  // Slack-Connect / DM / archived channel would leak cross-org.
  if (i.eligible !== true) return { status: 'refused', code: 'ineligible' };
  if (i.identity === 'channel' && i.channel) {
    // The channel OWNS the credential; the audited actor stays the acting human (invariant 9).
    return { status: 'resolved', owner: channelOwner(i.principal.teamId, i.channel), acting: i.principal };
  }
  // 'person' is user-owned; a channel handle can't reach it.
  return { status: 'refused', code: 'not_configured' };
}
