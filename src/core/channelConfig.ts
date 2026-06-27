import type { Db } from './db';

/**
 * Per-channel credential mode for a provider:
 *  - 'shared'   — the channel owns one credential every member's agent injects (a static
 *                 key or an external ref). Set by an admin.
 *  - 'per-user' — the channel is LOCKED to per-user identity: no shared cred may exist here,
 *                 each member must use their own (invariant 7). setChannelSecret refuses.
 * No row → unconfigured: no shared cred, and an admin may set one (defaults to 'shared').
 */
export type ChannelMode = 'shared' | 'per-user';

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
