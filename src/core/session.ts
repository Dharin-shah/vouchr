import type { Db } from './db';
import type { SlackIdentity } from './identity';

/**
 * Thread-scoped session grants. A grant says: the acting user may use `provider` only inside the
 * exact Slack thread (team, channel, thread) it was approved in, until `expires_at`. A different
 * thread has no grant, so the agent cannot act there. The TTL is an always-on safety ceiling, not
 * the primary control: the thread context is.
 */
export class SessionGrants {
  constructor(private db: Db) {}

  /** Approve `provider` for this user in exactly this (team, channel, thread) for `ttlMs`.
   *  Idempotent: re-approving the same thread refreshes the expiry. */
  async grant(i: SlackIdentity, channel: string, thread: string, provider: string, ttlMs: number): Promise<void> {
    const now = Date.now();
    await this.db.run(
      `INSERT INTO session_grant (team_id, channel, thread, user_id, provider, created_at, expires_at)
       VALUES (?,?,?,?,?,?,?)
       ON CONFLICT(team_id, channel, thread, user_id, provider) DO UPDATE SET expires_at=excluded.expires_at`,
      [i.teamId, channel, thread, i.userId, provider, now, now + ttlMs],
    );
  }

  /** Whether a non-expired grant exists for this exact thread context. */
  async isGranted(i: SlackIdentity, channel: string, thread: string, provider: string): Promise<boolean> {
    const row = (await this.db.get(
      `SELECT 1 AS x FROM session_grant
       WHERE team_id=? AND channel=? AND thread=? AND user_id=? AND provider=? AND expires_at>?`,
      [i.teamId, channel, thread, i.userId, provider, Date.now()],
    )) as { x: number } | undefined;
    return !!row;
  }

  /** Revoke every grant for a user (offboarding). */
  async revokeForUser(i: SlackIdentity): Promise<void> {
    await this.db.run(`DELETE FROM session_grant WHERE team_id=? AND user_id=?`, [i.teamId, i.userId]);
  }

  /** Revoke a user's grants for ONE provider (break-glass bulk revocation of that provider). */
  async clearForProvider(teamId: string, userId: string, provider: string): Promise<void> {
    await this.db.run(`DELETE FROM session_grant WHERE team_id=? AND user_id=? AND provider=?`, [teamId, userId, provider]);
  }

  /** Delete expired grants. Run on the same timer as the connection TTL sweep. */
  async sweepExpired(): Promise<number> {
    return (await this.db.run(`DELETE FROM session_grant WHERE expires_at<?`, [Date.now()])).changes;
  }
}
