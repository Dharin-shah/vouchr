import { randomUUID } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';

/** Shape of `meta` accepted by the audit log: values must NEVER be token material. */
export type AuditMeta = Record<string, unknown>;

const REDACTED = '[redacted]';

// Clear "this is a credential" signals. Keys are kept; only matching string values are scrubbed.
const TOKEN_PREFIX = /^(xox[bpars]-|ghp_|gho_|ghu_|ghs_|github_pat_|sk-|sk_|AKIA|Bearer )/;
// Generic high-entropy secret: one whitespace-free base64/base64url/hex blob, long enough that a
// channel id (C0123ABC), hostname, or status code can't trip it.
const HIGH_ENTROPY = /^[A-Za-z0-9_\-+/=]{40,}$/;

function looksSecret(s: string): boolean {
  return TOKEN_PREFIX.test(s) || HIGH_ENTROPY.test(s);
}

/** Deep-copy `meta`, replacing any credential-shaped string with a sentinel. Never throws, never mutates input. */
function redact(value: unknown): unknown {
  if (typeof value === 'string') return looksSecret(value) ? REDACTED : value;
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redact(v); // keys intact, values scrubbed
    return out;
  }
  return value; // numbers, booleans, null, undefined pass through
}

/** Append-only audit log. `meta` must NEVER contain token material; defense-in-depth redaction enforces it anyway. */
export class Audit {
  constructor(private db: Db) {}

  async record(
    action: 'connect' | 'refresh' | 'inject' | 'revoke' | 'denied' | 'config' | 'session',
    i: SlackIdentity,
    provider: string,
    meta: AuditMeta = {},
    actor?: string,
  ): Promise<void> {
    // Promote a channel id from meta to its own column so audit is queryable by channel (it stays in
    // meta too). A channel id isn't secret and never trips redact(), so reading it raw here is safe.
    const channel = typeof meta.channel === 'string' ? meta.channel : null;
    await this.db.run(
      `INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [randomUUID(), i.teamId, i.userId, provider, action, actor ?? null, channel, JSON.stringify(redact(meta)), Date.now()],
    );
  }
}
