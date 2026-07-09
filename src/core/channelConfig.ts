import type { Db } from './db';

/**
 * Per-channel auth mode for a provider. The single source of truth for which credential model
 * `connect()` uses in this channel:
 *  - 'shared':   the channel owns one credential every member's agent injects (a static key or an
 *                 external ref, admin-set). connect() routes to the shared credential.
 *  - 'per-user': each member uses their own credential; no shared cred may exist here (invariant 7).
 *  - 'session':  per-user, but usable only inside the Slack thread the user approved it in (a thread
 *                 session grant), with a TTL ceiling.
 *  - 'union':    "any connected member" — connect() resolves to WHICHEVER channel member has connected
 *                 the provider and acts as THAT member (their user-owned cred is the key; that member is
 *                 the audited actor). Still per-user creds (no shared channel cred), just resolved across
 *                 the channel's members instead of only the caller. No owner/actor conflation: the audited
 *                 actor is the real member whose credential is used, never the channel and never the caller.
 * No row → unconfigured, treated as 'per-user' (each member uses their own; an admin may set a mode).
 */
export const CHANNEL_MODES = ['shared', 'per-user', 'session', 'union'] as const;
export type ChannelMode = (typeof CHANNEL_MODES)[number];
/** Runtime guard — the SINGLE source of truth for "is this a valid channel mode". Every caller that
 *  takes a mode from an untrusted surface (a slash arg, a modal view_submission, a broker request body)
 *  routes through this, so the four modes are never re-listed and can never drift out of sync. */
export const isChannelMode = (m: unknown): m is ChannelMode =>
  typeof m === 'string' && (CHANNEL_MODES as readonly string[]).includes(m);

/**
 * Per-channel PREVIEW visibility for a provider: how an agent's provider-derived output should be
 * posted in this channel.
 *  - 'public'  (default, no row): posted to the channel/thread like any message.
 *  - 'private': posted ephemerally to the requesting user only, with an explicit "Share to thread"
 *               action — provider data never reaches other members unless a human shares it.
 * A rendering policy, not a credential one — it lives beside (not inside) `channel_config` because
 * "no mode row = unconfigured" is load-bearing for the shared-credential path.
 */
export const PREVIEW_VISIBILITIES = ['public', 'private'] as const;
export type PreviewVisibility = (typeof PREVIEW_VISIBILITIES)[number];
/** Runtime guard — the single source of truth for "is this a valid preview visibility" (see
 *  isChannelMode's note; same rule, same reason). */
export const isPreviewVisibility = (v: unknown): v is PreviewVisibility =>
  typeof v === 'string' && (PREVIEW_VISIBILITIES as readonly string[]).includes(v);

/** The subset of Slack's conversations.info shape that channel-credential eligibility depends on. */
export interface ChannelInfo {
  is_ext_shared?: boolean;
  is_shared?: boolean;
  is_pending_ext_shared?: boolean;
  is_im?: boolean;
  is_mpim?: boolean;
  is_archived?: boolean;
}

/**
 * Why a channel is INELIGIBLE for a shared (channel-owned) credential (invariant 6), or null if
 * it's eligible. The classification rule lives in core (transport-agnostic) so every adapter
 * (the Bolt middleware today, a sidecar + thin clients later) enforces the SAME security rule
 * instead of re-implementing it. The adapter only fetches the info; pass `null` if it couldn't
 * (fails closed). Externally shared / Slack Connect is the security-critical case (cross-org leak).
 */
export function channelIneligibleReason(info: ChannelInfo | null | undefined): string | null {
  if (!info) return 'Could not verify the channel type; channel credentials are refused.';
  if (info.is_ext_shared || info.is_shared || info.is_pending_ext_shared) {
    return 'Channel credentials are not allowed in externally shared channels.';
  }
  if (info.is_im || info.is_mpim) return 'Channel credentials are not allowed in DMs or group DMs.';
  if (info.is_archived) return 'Channel credentials are not allowed in archived channels.';
  return null;
}

/** Store for `(team_id, channel, provider) → mode`. Non-secret; just the policy bit. */
export class ChannelConfig {
  constructor(private db: Db) {}

  async getMode(teamId: string, channel: string, provider: string): Promise<ChannelMode | null> {
    const row = (await this.db.get(
      `SELECT mode FROM channel_config WHERE team_id=? AND channel=? AND provider=?`,
      [teamId, channel, provider],
    )) as { mode: ChannelMode } | undefined;
    return row?.mode ?? null;
  }

  async setMode(teamId: string, channel: string, provider: string, mode: ChannelMode): Promise<void> {
    // Defense-in-depth at the true sink: TypeScript's `ChannelMode` is compile-time only, so a value
    // arriving from an untrusted surface (modal/broker/slash) could still be a bogus string at runtime.
    if (!isChannelMode(mode)) throw new Error(`invalid channel mode: ${mode}`);
    await this.db.run(
      `INSERT INTO channel_config (team_id, channel, provider, mode) VALUES (?,?,?,?)
       ON CONFLICT(team_id, channel, provider) DO UPDATE SET mode=excluded.mode`,
      [teamId, channel, provider, mode],
    );
  }

  /** Preview visibility for `(team, channel, provider)`. No row → 'public' (today's behavior). */
  async getVisibility(teamId: string, channel: string, provider: string): Promise<PreviewVisibility> {
    const row = (await this.db.get(
      `SELECT visibility FROM channel_preview WHERE team_id=? AND channel=? AND provider=?`,
      [teamId, channel, provider],
    )) as { visibility: PreviewVisibility } | undefined;
    return row?.visibility ?? 'public';
  }

  async setVisibility(teamId: string, channel: string, provider: string, visibility: PreviewVisibility): Promise<void> {
    // Same defense-in-depth as setMode: the value may arrive from an untrusted surface at runtime.
    if (!isPreviewVisibility(visibility)) throw new Error(`invalid preview visibility: ${visibility}`);
    await this.db.run(
      `INSERT INTO channel_preview (team_id, channel, provider, visibility) VALUES (?,?,?,?)
       ON CONFLICT(team_id, channel, provider) DO UPDATE SET visibility=excluded.visibility`,
      [teamId, channel, provider, visibility],
    );
  }
}
