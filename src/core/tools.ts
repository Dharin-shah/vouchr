import type { Db } from './db';
import type { Audit } from './audit';
import type { ChannelMode } from './channelConfig';
import type { SlackIdentity } from './identity';
import { withUserInteractionFence } from './consent';
import { purgeChannelInteractionState } from './interaction';
import { channelOwner } from './owner';
import type { Vault } from './vault';

// Like ChannelConfig, the exported class is a read store. Raw writes are symbol-keyed so package
// consumers cannot bypass the supported governance facade's authorization, locks, purge, and audit.
const SET_CHANNEL_TOOL_ENABLED = Symbol('set-channel-tool-enabled');
const APPLY_CHANNEL_TOOLS_ENABLED = Symbol('apply-channel-tools-enabled');

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
  async [SET_CHANNEL_TOOL_ENABLED](teamId: string, channel: string, provider: string, enabled: boolean): Promise<void> {
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
   * Atomically apply the desired enabled bits for `changes`. Deny-by-default means a row-less channel
   * already disables every provider, so the first write no longer flips a default — but we still
   * materialize the full explicit allowlist on first write (every provider in `allProviders` at its
   * desired state where given, DISABLED otherwise) so the stored state is fully explicit rather than
   * relying on the implicit deny. ponytail: this materialization is now belt-and-suspenders (a bare
   * upsert of `changes` would give the same verdicts); keep it for explicit auditable state, drop it
   * if the allProviders plumbing ever becomes a burden.
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
  async [APPLY_CHANNEL_TOOLS_ENABLED](
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
      .map((p) => [p, desired.get(p) ?? false] as const); // deny-by-default: untouched providers stay OFF

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
   * {@link isEnabled}, same deny-by-default rule applied once, returning a predicate. A channel is a
   * strict allowlist: only a provider with an explicit `enabled` row is on. No rows → nothing enabled;
   * an explicit-off or unlisted provider is off. An admin opts each provider in per channel (SEC-3).
   * `buildToolManifest` and the App Home admin console fold through this so their query count is bounded
   * by the channel, not the configured-provider count (#209).
   */
  async enabledSnapshot(teamId: string, channel: string): Promise<(provider: string) => boolean> {
    const rows = (await this.db.all(
      `SELECT provider, enabled FROM channel_tool WHERE team_id=? AND channel=?`,
      [teamId, channel],
    )) as { provider: string; enabled: number }[];
    if (rows.length === 0) return () => false; // deny-by-default: unconfigured channel → nothing enabled
    const on = new Set(rows.filter((r) => !!r.enabled).map((r) => r.provider));
    return (provider) => on.has(provider); // allowlist; explicit-off / unlisted → disabled
  }

  /** Providers explicitly enabled in this channel. Empty array means nothing is enabled here —
   *  under deny-by-default that is the same whether the channel is unconfigured or configured-all-off
   *  (both → no provider usable). `isEnabled` gives the same verdict for any single provider. */
  async listEnabled(teamId: string, channel: string): Promise<string[]> {
    const rows = (await this.db.all(
      `SELECT provider FROM channel_tool WHERE team_id=? AND channel=? AND enabled=1`,
      [teamId, channel],
    )) as { provider: string }[];
    return rows.map((r) => r.provider);
  }

  /** Whether this channel has ANY tool row. Under deny-by-default this no longer changes the
   *  authorization verdict (row-less and all-off both deny) — it only tells a first-write caller that
   *  no rows exist yet, so it can still materialize the full explicit-state allowlist in one write. */
  async isConfigured(teamId: string, channel: string, db: Db = this.db): Promise<boolean> {
    const row = (await db.get(
      `SELECT 1 AS x FROM channel_tool WHERE team_id=? AND channel=? LIMIT 1`,
      [teamId, channel],
    )) as { x: number } | undefined;
    return !!row;
  }

  /** Whether `provider` may be used in this channel. Deny-by-default: only an explicit `enabled` row
   *  counts; no rows → disabled, an unlisted or explicit-off provider → disabled. */
  async isEnabled(teamId: string, channel: string, provider: string, db: Db = this.db): Promise<boolean> {
    const configured = await this.isConfigured(teamId, channel, db);
    if (!configured) return false; // deny-by-default: no rows for this channel → nothing enabled
    const row = (await db.get(
      `SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?`,
      [teamId, channel, provider],
    )) as { enabled: number } | undefined;
    return row ? !!row.enabled : false; // configured channel = allowlist; unlisted provider → disabled
  }
}

/** @internal Raw single-row fixture helper. Supported product writes use configureChannelTools. */
export async function setChannelToolEnabled(
  tools: ChannelTools,
  teamId: string,
  channel: string,
  provider: string,
  enabled: boolean,
): Promise<void> {
  return tools[SET_CHANNEL_TOOL_ENABLED](teamId, channel, provider, enabled);
}

/** @internal Atomic first-write primitive for configureChannelTools and store-level tests. */
export async function applyChannelToolsEnabled(
  tools: ChannelTools,
  teamId: string,
  channel: string,
  changes: readonly (readonly [string, boolean])[],
  allProviders: readonly string[],
  afterWrite?: (tx: Db) => Promise<void>,
): Promise<void> {
  return tools[APPLY_CHANNEL_TOOLS_ENABLED](teamId, channel, changes, allProviders, afterWrite);
}

/**
 * One channel-tool authorization, mutation, and audit sequence shared by Bolt and headless.
 * Transport adapters prove admin/channel eligibility through callbacks because only they can
 * validate Slack state or signed claims; after those checks, the first-write-safe allowlist update
 * and its canonical audit rows commit as one transaction and cannot drift between front doors.
 */
export async function configureChannelTools(input: {
  channelTools: ChannelTools;
  vault: Vault;
  audit: Audit;
  identity: SlackIdentity;
  channel: string;
  changes: readonly (readonly [providerId: string, enabled: boolean])[];
  allProviders: readonly string[];
  authorize: () => Promise<boolean>;
  assertEligible: () => Promise<void>;
  issuance: number;
}): Promise<'configured' | 'unchanged' | 'denied' | 'stale'> {
  if (!(await input.authorize())) return 'denied';
  await input.assertEligible();
  const owner = channelOwner(input.identity.teamId, input.channel);
  let noRealChange = false;
  const result = await input.vault.withCredentialLocks(
    input.changes.map(([provider]) => ({ owner, provider })),
    async (_locked, tx) => {
      return withUserInteractionFence(tx, input.identity, input.issuance, async (fencedTx) => {
        // Compare effective authorization before materializing/upserting, then apply ONLY the changes
        // that actually flip a provider's state. A repeated/stale Disable (or Enable) whose desired
        // state already matches the effective one writes nothing and is not audited — no fabricated
        // `config/tool` row, no materialization. Every applied change is by definition an authority
        // change, so it always purges + audits. Locks serialize same-provider writers; the snapshot,
        // write, purge, and audit all commit in this one transaction.
        const txTools = new ChannelTools(fencedTx);
        const effectiveBefore = new Map<string, boolean>();
        for (const [providerId] of input.changes) {
          effectiveBefore.set(
            providerId,
            await txTools.isEnabled(input.identity.teamId, input.channel, providerId, fencedTx),
          );
        }
        // Dedup to the last-write-wins desired state, then drop entries that don't change anything.
        const desired = new Map(input.changes);
        const realChanges = [...desired].filter(([p, enabled]) => effectiveBefore.get(p) !== enabled);
        if (realChanges.length === 0) {
          noRealChange = true;
          return;
        }
        await applyChannelToolsEnabled(
          txTools,
          input.identity.teamId,
          input.channel,
          realChanges,
          input.allProviders,
          async (writeTx) => {
            for (const [providerId, enabled] of realChanges) {
              await purgeChannelInteractionState(
                writeTx,
                input.identity.teamId,
                input.channel,
                providerId,
              );
              await input.audit.record('config', input.identity, providerId, {
                owner: 'channel',
                channel: input.channel,
                tool: enabled ? 'enabled' : 'disabled',
              }, undefined, writeTx);
            }
          }
        );
      });
    },
  );
  if (result.status !== 'current') return 'stale';
  return noRealChange ? 'unchanged' : 'configured';
}
