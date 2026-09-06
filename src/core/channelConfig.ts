import type { Db } from './db';

// Write capability kept module-private. `ChannelConfig` is exported to headless hosts as the
// broker's read store, but a naked row upsert would bypass lifecycle locks, dependent-state purge,
// authorization, and audit. Internal core mutations use `writeChannelIdentity`; package entry points
// do not export that helper, so supported writes go through the Bolt/headless governance facades.
const WRITE_CHANNEL_IDENTITY = Symbol('write-channel-identity');

/**
 * Who the agent acts as for a provider in a channel (#350). The single source of truth for which
 * credential `connect()` uses there:
 *  - 'person':  each member acts as themselves with their own connected account (the default).
 *  - 'channel': the channel owns one credential that a member connected (`/vouchr connect-shared`);
 *               every member's agent acts with it, audited as the asking human.
 * No row is 'person'.
 */
export const CHANNEL_IDENTITIES = ['person', 'channel'] as const;
export type ChannelIdentity = (typeof CHANNEL_IDENTITIES)[number];
/** Runtime guard, the ONE source of truth for "is this a valid channel identity". Every caller that
 *  takes the value from an untrusted surface (a slash arg, a modal view_submission, a broker request
 *  body) routes through this, so the two values are never re-listed. */
export const isChannelIdentity = (value: unknown): value is ChannelIdentity =>
  typeof value === 'string' && (CHANNEL_IDENTITIES as readonly string[]).includes(value);

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
 * Why a channel is INELIGIBLE for a channel-owned credential (invariant 6), or null if it is
 * eligible. The classification rule lives in core (transport-agnostic) so every adapter (the Bolt
 * middleware and packaged broker) enforces the SAME security rule instead of re-implementing it.
 * The adapter only fetches the info; pass `null` if it couldn't (fails closed). Externally shared /
 * Slack Connect is the security-critical case (cross-org leak).
 */
export function channelIneligibleReason(info: ChannelInfo | null | undefined): string | null {
  // Every refusal names the alternative (#348): the person's own connection here, or another channel.
  const alternative = 'Use your own connection here, or configure in an internal channel.';
  if (!info) return 'Could not verify the channel type; channel credentials are refused. Add Vouchr to the channel, then retry.';
  if (info.is_ext_shared || info.is_shared || info.is_pending_ext_shared) {
    return `Channel credentials are not allowed in externally shared channels. ${alternative}`;
  }
  if (info.is_im || info.is_mpim) return `Channel credentials are not allowed in DMs or group DMs. ${alternative}`;
  if (info.is_archived) return 'Channel credentials are not allowed in archived channels. Configure in an active channel.';
  return null;
}

/** Store for `(team_id, channel, provider) -> identity`. Non-secret; just the policy bit. */
export class ChannelConfig {
  constructor(
    private db: Db,
    /** Test/diagnostic hook inside the caller's lifecycle transaction. It can observe or fail a
     * write but cannot authorize one. */
    private beforeWrite?: (provider: string, identity: ChannelIdentity) => Promise<void>,
  ) {}

  /** The effective identity: 'person' unless a row says 'channel'. */
  async getIdentity(teamId: string, channel: string, provider: string, db: Db = this.db): Promise<ChannelIdentity> {
    const row = (await db.get(
      `SELECT identity FROM channel_config WHERE team_id=? AND channel=? AND provider=?`,
      [teamId, channel, provider],
    )) as { identity: ChannelIdentity } | undefined;
    return row?.identity ?? 'person';
  }

  /** Every provider's identity in this channel in ONE read, the batched form of {@link getIdentity}.
   *  Bounds the manifest's reads to one query (#209). */
  async identitySnapshot(teamId: string, channel: string): Promise<(provider: string) => ChannelIdentity> {
    const rows = (await this.db.all(
      `SELECT provider, identity FROM channel_config WHERE team_id=? AND channel=?`,
      [teamId, channel],
    )) as { provider: string; identity: ChannelIdentity }[];
    const m = new Map(rows.map((r) => [r.provider, r.identity]));
    return (provider) => m.get(provider) ?? 'person';
  }

  async [WRITE_CHANNEL_IDENTITY](
    teamId: string,
    channel: string,
    provider: string,
    identity: ChannelIdentity,
    db: Db = this.db,
  ): Promise<void> {
    // Defense-in-depth at the true sink: TypeScript's `ChannelIdentity` is compile-time only, so a
    // value arriving from an untrusted surface (modal/broker/slash) could still be a bogus string.
    if (!isChannelIdentity(identity)) throw new Error(`invalid channel identity: ${identity}`);
    await this.beforeWrite?.(provider, identity);
    await db.run(
      `INSERT INTO channel_config (team_id, channel, provider, identity) VALUES (?,?,?,?)
       ON CONFLICT(team_id, channel, provider) DO UPDATE SET identity=excluded.identity`,
      [teamId, channel, provider, identity],
    );
  }
}

/** @internal Raw row write for already-authorized, lifecycle-locked core mutations and fixtures.
 * This is deliberately not re-exported from the package entry points. */
export async function writeChannelIdentity(
  config: ChannelConfig,
  teamId: string,
  channel: string,
  provider: string,
  identity: ChannelIdentity,
  db?: Db,
): Promise<void> {
  return config[WRITE_CHANNEL_IDENTITY](teamId, channel, provider, identity, db);
}
