import type { Db } from './db';
import type { ChannelMode } from './channelConfig';

/** One row of a channel's tool manifest: a provider, its channel credential mode, and whether
 *  it's usable in this channel. This is the shape an agent / MCP gateway reads before planning. */
export interface ToolManifestEntry {
  provider: string;
  mode: ChannelMode | null;
  enabled: boolean;
  /**
   * Who the agent acts AS when it calls this tool, and therefore whether Vouchr is in the path:
   *  - 'acting_human' (default): the tool acts as the human in the channel against a third-party
   *     provider with that human's credential + consent. THIS is what Vouchr brokers — connect()
   *     resolves it through the vault and the consent flow.
   *  - 'service': a service-to-service tool the agent calls as ITSELF (its own service identity, an
   *     internal egress allowlist). There is no human credential to broker, so Vouchr is deliberately
   *     NOT in this path: connect() refuses it and the host wires its own service auth. It appears in
   *     the manifest only so the host can see the full tool set in one place.
   */
  identity: 'service' | 'acting_human';
}

/**
 * Per-channel "tool manifest": the set of providers an agent is allowed to use in a channel.
 * Non-secret policy bits only: same kind of store as ChannelConfig, over the async `Db`.
 *
 * BACKWARD-COMPAT RULE (important): a channel with NO rows here treats EVERY provider as
 * enabled, so existing channels keep working untouched. The moment ANY provider is explicitly
 * set for the channel (enabled OR disabled), the channel flips to an allowlist: only providers
 * with an `enabled` row are usable; anything not listed is implicitly disabled. Re-enable all by
 * setting every provider back on, or there's no "clear all". That's intentional (an empty
 * allowlist = nothing usable, never silently reverts to all-on once configured).
 */
export class ChannelTools {
  constructor(private db: Db) {}

  /** Enable or disable `provider` in this channel. Upsert keyed on (team, channel, provider). */
  async setEnabled(teamId: string, channel: string, provider: string, enabled: boolean): Promise<void> {
    await this.db.run(
      `INSERT INTO channel_tool (team_id, channel, provider, enabled) VALUES (?,?,?,?)
       ON CONFLICT(team_id, channel, provider) DO UPDATE SET enabled=excluded.enabled`,
      [teamId, channel, provider, enabled ? 1 : 0],
    );
  }

  /** Providers explicitly enabled in this channel. Empty array means either "unconfigured"
   *  (→ all enabled, see the rule above) or "configured but everything off", callers that need
   *  to tell them apart use `isEnabled`, which applies the backward-compat rule. */
  async listEnabled(teamId: string, channel: string): Promise<string[]> {
    const rows = (await this.db.all(
      `SELECT provider FROM channel_tool WHERE team_id=? AND channel=? AND enabled=1`,
      [teamId, channel],
    )) as { provider: string }[];
    return rows.map((r) => r.provider);
  }

  /** Whether `provider` may be used in this channel, applying the backward-compat rule:
   *  no rows at all → enabled; otherwise only an explicit enabled row counts. */
  /** Whether this channel has ANY tool row — i.e. it is an explicit allowlist rather than the
   *  backward-compat "all providers enabled" default. Callers about to write the FIRST row (which flips
   *  the channel into allowlist mode, silently disabling every still-row-less provider) use this to
   *  materialize the full desired allowlist instead of a single row. */
  async isConfigured(teamId: string, channel: string): Promise<boolean> {
    const row = (await this.db.get(
      `SELECT 1 AS x FROM channel_tool WHERE team_id=? AND channel=? LIMIT 1`,
      [teamId, channel],
    )) as { x: number } | undefined;
    return !!row;
  }

  async isEnabled(teamId: string, channel: string, provider: string): Promise<boolean> {
    const configured = await this.isConfigured(teamId, channel);
    if (!configured) return true; // no rows for this channel → all providers enabled (backward compat)
    const row = (await this.db.get(
      `SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?`,
      [teamId, channel, provider],
    )) as { enabled: number } | undefined;
    return row ? !!row.enabled : false; // configured channel = allowlist; unlisted provider → disabled
  }
}
