import type { Db } from './db';
import type { Audit } from './audit';
import type { ChannelMode } from './channelConfig';
import type { SlackIdentity } from './identity';

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

  /** One `SELECT provider, enabled UNION ALL …` table expression over `rows`, with the CASTs the
   *  first branch needs for Postgres parameter-type inference, plus the flattened parameter list.
   *  Shared by both applyEnabled statements. */
  private static rowsSql(rows: readonly (readonly [string, boolean])[]): { sql: string; params: (string | number)[] } {
    const sql = rows
      .map((_, i) => (i === 0
        ? 'SELECT CAST(? AS TEXT) AS provider, CAST(? AS INTEGER) AS enabled'
        : 'UNION ALL SELECT ?, ?'))
      .join(' ');
    return { sql, params: rows.flatMap(([p, e]) => [p, e ? 1 : 0]) };
  }

  /**
   * Atomically apply the desired enabled bits for `changes`, handling the first-write flip. Writing
   * the FIRST row turns the channel from "all enabled" (backward-compat) into an allowlist where
   * every row-less provider is implicitly disabled — so when the channel has no rows yet, the FULL
   * allowlist is materialized (every provider in `allProviders` at its desired state where given,
   * enabled otherwise) instead of a destructive partial one.
   *
   * Concurrency safety comes from the configured-ness decision being evaluated INSIDE the
   * materialization statement and every writer acquiring row locks in canonical provider order.
   *  - Statement 1 materializes if-and-only-if no rows exist, with `DO NOTHING` on conflicts so a
   *    concurrent materializer's explicit bits are never overwritten by our fillers.
   *  - Statement 2 upserts the caller's own changes, so they win regardless of who materialized.
   * Both statements and `afterWrite` run in one PostgreSQL transaction. `afterWrite` composes trusted
   * audit companions into that transaction, so a failed request cannot leave a live governance
   * change without its audit row. Any concurrent interleaving converges, while any failure rolls the
   * complete logical mutation back.
   */
  async applyEnabled(
    teamId: string,
    channel: string,
    changes: readonly (readonly [string, boolean])[],
    allProviders: readonly string[],
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<void> {
    if (!changes.length) return;
    const desired = new Map(changes);
    // Every replica acquires row locks in the same provider-id order. Front doors may declare the
    // same registry in a different order; preserving caller order lets concurrent first writes (or
    // bulk updates) deadlock while inserting/upserting the same rows in opposite directions.
    const orderedChanges = [...desired.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    const full = [...new Set([...allProviders, ...desired.keys()])]
      .sort()
      .map((p) => [p, desired.get(p) ?? true] as const);

    if (!this.db.transaction) {
      throw new Error('channel tool allowlist updates require database transaction support');
    }
    await this.db.transaction(async (tx) => {
      const materialize = ChannelTools.rowsSql(full);
      await tx.run(
        `INSERT INTO channel_tool (team_id, channel, provider, enabled)
         SELECT CAST(? AS TEXT), CAST(? AS TEXT), v.provider, v.enabled FROM (${materialize.sql}) AS v
         WHERE NOT EXISTS (SELECT 1 FROM channel_tool WHERE team_id = ? AND channel = ?)
         ON CONFLICT(team_id, channel, provider) DO NOTHING`,
        [teamId, channel, ...materialize.params, teamId, channel],
      );

      const upsert = ChannelTools.rowsSql(orderedChanges);
      await tx.run(
        `INSERT INTO channel_tool (team_id, channel, provider, enabled)
         SELECT CAST(? AS TEXT), CAST(? AS TEXT), v.provider, v.enabled FROM (${upsert.sql}) AS v
         WHERE TRUE
         ON CONFLICT(team_id, channel, provider) DO UPDATE SET enabled = excluded.enabled`,
        [teamId, channel, ...upsert.params],
      );
      await afterWrite?.(tx);
    });
  }

  /**
   * The tool-allowlist verdict for EVERY provider in one channel-scoped read — the batched form of
   * {@link isEnabled}, same backward-compat rule applied once, returning a predicate. A channel with no
   * rows is unconfigured → every provider enabled; the moment any row exists the channel is an allowlist
   * → only a provider with an explicit `enabled` row is on (an explicit-off or unlisted provider is off).
   * `buildToolManifest` and the App Home admin console fold through this so their query count is bounded
   * by the channel, not the configured-provider count (#209).
   */
  async enabledSnapshot(teamId: string, channel: string): Promise<(provider: string) => boolean> {
    const rows = (await this.db.all(
      `SELECT provider, enabled FROM channel_tool WHERE team_id=? AND channel=?`,
      [teamId, channel],
    )) as { provider: string; enabled: number }[];
    if (rows.length === 0) return () => true; // unconfigured → all enabled (backward compat), like isEnabled
    const on = new Set(rows.filter((r) => !!r.enabled).map((r) => r.provider));
    return (provider) => on.has(provider); // configured = allowlist; explicit-off / unlisted → disabled
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

/**
 * One channel-tool authorization, mutation, and audit sequence shared by Bolt and headless.
 * Transport adapters prove admin/channel eligibility through callbacks because only they can
 * validate Slack state or signed claims; after those checks, the first-write-safe allowlist update
 * and its canonical audit rows commit as one transaction and cannot drift between front doors.
 */
export async function configureChannelTools(input: {
  channelTools: ChannelTools;
  audit: Audit;
  identity: SlackIdentity;
  channel: string;
  changes: readonly (readonly [providerId: string, enabled: boolean])[];
  allProviders: readonly string[];
  authorize: () => Promise<boolean>;
  assertEligible: () => Promise<void>;
}): Promise<boolean> {
  if (!(await input.authorize())) return false;
  await input.assertEligible();
  await input.channelTools.applyEnabled(
    input.identity.teamId,
    input.channel,
    input.changes,
    input.allProviders,
    async (tx) => {
      for (const [providerId, enabled] of input.changes) {
        await input.audit.record('config', input.identity, providerId, {
          owner: 'channel',
          channel: input.channel,
          tool: enabled ? 'enabled' : 'disabled',
        }, undefined, tx);
      }
    },
  );
  return true;
}
