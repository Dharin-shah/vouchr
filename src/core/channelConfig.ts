import type { Db } from './db';

/**
 * Per-channel auth mode for a provider. The single source of truth for which credential model
 * `connect()` uses in this channel:
 *  - 'shared':   the channel owns one credential every member's agent injects (a static key or an
 *                 external ref, admin-set). connect() routes to the shared credential.
 *  - 'per-user': each member uses their own credential; no shared cred may exist here (invariant 7).
 *  - 'session':  per-user, but usable only inside the Slack thread the user approved it in (a thread
 *                 session grant), with a TTL ceiling.
 * No row → unconfigured, treated as 'per-user' (each member uses their own; an admin may set a mode).
 */
export type ChannelMode = 'shared' | 'per-user' | 'session';

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
    await this.db.run(
      `INSERT INTO channel_config (team_id, channel, provider, mode) VALUES (?,?,?,?)
       ON CONFLICT(team_id, channel, provider) DO UPDATE SET mode=excluded.mode`,
      [teamId, channel, provider, mode],
    );
  }
}
