import { randomUUID } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';

/** Shape of `meta` accepted by the audit log: values must NEVER be token material. */
export type AuditMeta = Record<string, unknown>;

/**
 * A convenience copy of an audit event for host-side ingestion (e.g. a Redis stream the host
 * consumes into its own observability/storage). The `audit` TABLE is AUTHORITATIVE / the source of
 * truth; this stream is a LOSSY convenience copy — a capped stream (Redis `MAXLEN ~`) may drop
 * events. Unlike the no-secret `VouchrEvent` metrics sink, this carries the RAW actor id so a host
 * can answer "who used this connection's token, when, against which host". The sink is expected to
 * live inside the host's existing trust boundary (which already stores user ids); a one-way hash
 * would defeat that use case and is brute-forceable over one workspace anyway. NEVER carries token
 * or secret material. `jti` is the dedupe key for idempotent host-side ingest (ack on a consumer
 * group, dedupe redeliveries on `jti`).
 */
export interface VouchrAuditEvent {
  ts: string; // ISO-8601
  teamId: string;
  userId: string; // raw acting actor id, NOT a hash
  provider: string;
  ownerKind: 'user' | 'channel';
  ownerId: string; // user id or channel id that OWNS the credential
  action: 'fetch' | 'refresh' | 'consent_granted' | 'consent_denied';
  egressHost: string;
  /** HTTP method for fetch events. Omitted for refresh/consent events. */
  method?: string;
  // HTTP-ish status. Only 'fetch' carries a REAL upstream status; the others are synthetic: 'refresh'
  // is hardcoded 200 (it only emits after refresh already succeeded), 'consent_granted' is 200, and
  // 'consent_denied' is 400 for a real user denial or 500 for a post-consent connection failure.
  // Don't treat `status` as a uniform provider response code across actions; key on `action` first.
  status: number;
  jti: string;
}

/** Fire-and-forget audit stream sink. Sync; a throwing sink must never affect request behavior. */
export type AuditSink = (e: VouchrAuditEvent) => void;

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

/** One audit row for the in-Slack usage view. NOTE: `meta` is deliberately NOT selected — it could
 *  hold sensitive labels, and the Slack surface must render only these non-secret columns. */
export interface AuditRow {
  provider: string;
  action: string;
  actor: string | null; // who triggered it (union non-repudiation); null on most rows
  channel: string | null;
  at: number; // ms epoch
}

/** Append-only audit log. `meta` must NEVER contain token material; defense-in-depth redaction enforces it anyway. */
export class Audit {
  constructor(private db: Db) {}

  /** The caller's own audit trail: rows attributed to them as the acting/owning user, across channels.
   *  `user_id` is always the acted-as member (the credential owner in union mode), so this scopes strictly
   *  to the caller — never another user's rows. Excludes `meta`. */
  async listByOwnerUser(i: SlackIdentity, limit: number): Promise<AuditRow[]> {
    return this.db.all(
      `SELECT provider, action, actor, channel, at FROM audit
       WHERE team_id = ? AND user_id = ? ORDER BY at DESC LIMIT ?`,
      [i.teamId, i.userId, limit],
    );
  }

  /** Every audit row tagged with this channel — channel-owned credential usage AND per-user activity
   *  that happened in the channel (provider/action/actor/at). Admin-gated at the call site. Excludes `meta`. */
  async listByChannel(teamId: string, channelId: string, limit: number): Promise<AuditRow[]> {
    return this.db.all(
      `SELECT provider, action, actor, channel, at FROM audit
       WHERE team_id = ? AND channel = ? ORDER BY at DESC LIMIT ?`,
      [teamId, channelId, limit],
    );
  }

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
