import { randomUUID } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';

/** Append-only audit log. `meta` must NEVER contain token material. */
export class Audit {
  constructor(private db: Db) {}

  async record(
    action: 'connect' | 'refresh' | 'inject' | 'revoke' | 'denied' | 'config',
    i: SlackIdentity,
    provider: string,
    meta: Record<string, unknown> = {},
    actor?: string,
  ): Promise<void> {
    await this.db.run(
      `INSERT INTO audit (id, team_id, user_id, provider, action, actor, meta, at)
       VALUES (?,?,?,?,?,?,?,?)`,
      [randomUUID(), i.teamId, i.userId, provider, action, actor ?? null, JSON.stringify(meta), Date.now()],
    );
  }
}
