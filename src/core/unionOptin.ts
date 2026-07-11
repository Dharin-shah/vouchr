import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { Audit } from './audit';

/**
 * Explicit union-mode opt-in (#112). A row says: "I allow my connected `provider` credential to
 * serve OTHER members' requests in this channel". Rows are written when the user opts in — by
 * completing a Connect that was prompted from a union-mode channel (see oauthCallback), or by
 * `/vouchr union join <provider>` — and deleted on `union leave`, disconnect, and offboarding.
 * Union resolution consults it only when `unionRequiresOptIn` is enabled; the rows themselves are
 * inert without a live credential (resolution still requires a vault hit for the member).
 */
export class UnionOptin {
  constructor(private db: Db) {}

  /** Record the opt-in. Idempotent; returns whether a row was actually created. */
  async join(i: SlackIdentity, channel: string, provider: string): Promise<boolean> {
    const { changes } = await this.db.run(
      `INSERT INTO union_optin (team_id, channel_id, user_id, provider, created_at)
       VALUES (?,?,?,?,?)
       ON CONFLICT(team_id, channel_id, user_id, provider) DO NOTHING`,
      [i.teamId, channel, i.userId, provider, Date.now()],
    );
    return changes > 0;
  }

  /** Remove the opt-in — effective on the very next resolution. Returns whether a row existed. */
  async leave(i: SlackIdentity, channel: string, provider: string): Promise<boolean> {
    const { changes } = await this.db.run(
      `DELETE FROM union_optin WHERE team_id=? AND channel_id=? AND user_id=? AND provider=?`,
      [i.teamId, channel, i.userId, provider],
    );
    return changes > 0;
  }

  /** The user ids opted in for (channel, provider) — the union-resolution candidate set. */
  async optedIn(teamId: string, channel: string, provider: string): Promise<Set<string>> {
    const rows = await this.db.all<{ user_id: string }>(
      `SELECT user_id FROM union_optin WHERE team_id=? AND channel_id=? AND provider=?`,
      [teamId, channel, provider],
    );
    return new Set(rows.map((r) => r.user_id));
  }

  /** Delete every opt-in for a user across channels/providers (offboarding). */
  async deleteForUser(i: SlackIdentity): Promise<void> {
    await this.db.run(`DELETE FROM union_optin WHERE team_id=? AND user_id=?`, [i.teamId, i.userId]);
  }

  /** Delete a user's opt-ins for ONE provider (disconnect / break-glass revoke): once the
   *  credential is gone, a stale opt-in must not resurrect delegation on a later reconnect. */
  async deleteForUserProvider(teamId: string, userId: string, provider: string): Promise<void> {
    await this.db.run(
      `DELETE FROM union_optin WHERE team_id=? AND user_id=? AND provider=?`,
      [teamId, userId, provider],
    );
  }

  /**
   * The TTL-sweep variant of {@link deleteForUserProvider} (#192 review): delete the user's
   * opt-ins for the provider ONLY where no live connection backs them. The sweep's credential
   * delete and this cleanup are separate statements, so an OAuth reconnect (which re-creates the
   * credential AND the opt-in via joinUnion) can land between them — the NOT EXISTS guard makes
   * this delete a no-op in that case instead of silently destroying the fresh delegation state.
   * One atomic statement, so there is no window between the check and the delete.
   */
  async deleteForUserProviderIfDisconnected(teamId: string, userId: string, provider: string): Promise<void> {
    await this.db.run(
      `DELETE FROM union_optin WHERE team_id=? AND user_id=? AND provider=? AND NOT EXISTS (
         SELECT 1 FROM connection WHERE owner_kind='user' AND owner_id=union_optin.user_id
           AND team_id=union_optin.team_id AND provider=union_optin.provider)`,
      [teamId, userId, provider],
    );
  }
}

/**
 * The union-resolution candidate filter — the security rule lives HERE (STR-1), adapters only fetch
 * the member list. Opt-in not required → every member is a candidate (pre-#112 behavior, no DB
 * read). Required → only members with an opt-in row for (channel, provider); nobody opted in ⇒ []
 * ⇒ the caller falls through to the normal Connect prompt (which doubles as the opt-in moment).
 */
export async function eligibleUnionMembers(
  optin: UnionOptin,
  requiresOptIn: boolean,
  teamId: string,
  channel: string,
  provider: string,
  memberIds: string[],
): Promise<string[]> {
  if (!requiresOptIn) return memberIds;
  const opted = await optin.optedIn(teamId, channel, provider);
  return memberIds.filter((m) => opted.has(m));
}

/** ONE join-mutation+audit pair (STR-3) for both call sites: `/vouchr union join` and the OAuth
 *  callback's auto-join. Audits only when a row was actually created, so idempotent re-joins
 *  (e.g. reconnecting from the same union channel) don't spam the audit log. */
export async function joinUnion(
  optin: UnionOptin,
  audit: Audit,
  i: SlackIdentity,
  channel: string,
  provider: string,
): Promise<boolean> {
  const changed = await optin.join(i, channel, provider);
  if (changed) await audit.record('union', i, provider, { channel, event: 'join' });
  return changed;
}

/** leaveUnion is joinUnion's twin (same meta shape, `event: 'leave'`), kept beside it so the
 *  audit contract for the two lifecycle events can't drift. */
export async function leaveUnion(
  optin: UnionOptin,
  audit: Audit,
  i: SlackIdentity,
  channel: string,
  provider: string,
): Promise<boolean> {
  const changed = await optin.leave(i, channel, provider);
  if (changed) await audit.record('union', i, provider, { channel, event: 'leave' });
  return changed;
}
