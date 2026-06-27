import { randomUUID } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { Owner } from './owner';
import { seal, open, type EnvelopeProvider } from './crypto';

/** Input for a vaulted (Vouchr-encrypted) connection. */
export interface StoredToken {
  accessToken: string;
  refreshToken: string | null;
  scopes: string;
  expiresAt: number | null;
  externalAccount: string | null;
}

/**
 * What `get` returns. `source==='vault'` → `accessToken` is the decrypted secret.
 * Otherwise the secret lives in an external manager: `secretRef` is a non-secret
 * pointer (e.g. an AWS Secrets Manager ARN) the injector resolves just-in-time.
 */
export interface StoredCredential {
  source: string;
  accessToken: string | null;
  refreshToken: string | null;
  secretRef: string | null;
  scopes: string;
  expiresAt: number | null;
  externalAccount: string | null;
}

/**
 * Connection lifetime, independent of the provider's own access-token expiry.
 * - idleMs: delete a connection unused for this long (idle timeout)
 * - maxAgeMs: delete a connection this long after it was (re)connected
 * An empty policy ({}) disables expiry. Per-user deployments should set these
 * aggressively; shared/channel connections warrant gentler windows.
 */
export interface TtlPolicy {
  idleMs?: number;
  maxAgeMs?: number;
}

/** Encrypted credential store, keyed by the owning principal (user OR channel). */
export class Vault {
  constructor(
    private db: Db,
    private key: Buffer,
    private ttl: TtlPolicy = {},
    // Optional KMS envelope binding. When supplied, NEW writes use envelope encryption (scheme
    // 0x01); when absent, NEW writes use the legacy direct-to-master format (current behavior).
    // Reads dispatch on the stored format regardless, so either mode reads existing rows.
    private envelope?: EnvelopeProvider,
  ) {}

  private isExpired(createdAt: number, lastUsedAt: number, now = Date.now()): boolean {
    if (this.ttl.idleMs != null && now - lastUsedAt > this.ttl.idleMs) return true;
    if (this.ttl.maxAgeMs != null && now - createdAt > this.ttl.maxAgeMs) return true;
    return false;
  }

  /** Returns the credential, or null if absent OR expired per the TTL policy. */
  async get(owner: Owner, provider: string): Promise<StoredCredential | null> {
    const row = (await this.db.get(
      `SELECT * FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [owner.teamId, owner.kind, owner.id, provider],
    )) as any;
    if (!row) return null;
    if (this.isExpired(row.created_at, row.last_used_at ?? row.created_at)) return null;
    return {
      source: row.source,
      accessToken: row.access_token_enc ? await open(toBuffer(row.access_token_enc), this.key, this.envelope) : null,
      refreshToken: row.refresh_token_enc ? await open(toBuffer(row.refresh_token_enc), this.key, this.envelope) : null,
      secretRef: row.secret_ref,
      scopes: row.scopes,
      expiresAt: row.expires_at,
      externalAccount: row.external_account,
    };
  }

  /** Store a vaulted credential (Vouchr encrypts and owns refresh). */
  async upsert(owner: Owner, provider: string, t: StoredToken): Promise<void> {
    const now = Date.now();
    const accessEnc = await seal(t.accessToken, this.key, this.envelope);
    const refreshEnc = t.refreshToken ? await seal(t.refreshToken, this.key, this.envelope) : null;
    await this.db.run(
      `INSERT INTO connection
         (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
          access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
          external_account, created_at, updated_at, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, 'vault', ?, ?, NULL, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(team_id, owner_kind, owner_id, provider) DO UPDATE SET
         source='vault', access_token_enc=excluded.access_token_enc,
         refresh_token_enc=excluded.refresh_token_enc, secret_ref=NULL,
         scopes=excluded.scopes, expires_at=excluded.expires_at,
         external_account=excluded.external_account, updated_at=excluded.updated_at,
         created_at=excluded.created_at, last_used_at=excluded.last_used_at`,
      [
        randomUUID(), null, owner.teamId, owner.kind, owner.id, provider,
        accessEnc, refreshEnc,
        t.scopes, t.expiresAt, t.externalAccount, now, now, now,
      ],
    );
  }

  /**
   * Store a REFERENCED credential: the secret stays in an external manager (e.g. AWS
   * Secrets Manager). We persist only a non-secret `ref` + the resolver `source` id;
   * the injector resolves it just-in-time. Rotation stays external — Vouchr never holds it.
   */
  async reference(
    owner: Owner,
    provider: string,
    r: { source: string; secretRef: string; scopes?: string; externalAccount?: string | null },
  ): Promise<void> {
    const now = Date.now();
    await this.db.run(
      `INSERT INTO connection
         (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
          access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
          external_account, created_at, updated_at, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, ?, ?, ?)
       ON CONFLICT(team_id, owner_kind, owner_id, provider) DO UPDATE SET
         source=excluded.source, access_token_enc=NULL, refresh_token_enc=NULL,
         secret_ref=excluded.secret_ref, scopes=excluded.scopes, expires_at=NULL,
         external_account=excluded.external_account, updated_at=excluded.updated_at,
         created_at=excluded.created_at, last_used_at=excluded.last_used_at`,
      [
        randomUUID(), null, owner.teamId, owner.kind, owner.id, provider, r.source,
        r.secretRef, r.scopes ?? '', r.externalAccount ?? null, now, now, now,
      ],
    );
  }

  /**
   * Update only the token material on a vaulted connection, leaving created_at
   * intact. Used by the silent refresh path so a rotating-token provider can't
   * indefinitely defer the max-age TTL (reconnect goes through upsert, which
   * *does* reset created_at; a refresh must not).
   */
  async updateTokens(
    owner: Owner,
    provider: string,
    t: Pick<StoredToken, 'accessToken' | 'refreshToken' | 'scopes' | 'expiresAt'>,
  ): Promise<void> {
    const accessEnc = await seal(t.accessToken, this.key, this.envelope);
    const refreshEnc = t.refreshToken ? await seal(t.refreshToken, this.key, this.envelope) : null;
    await this.db.run(
      `UPDATE connection SET access_token_enc=?, refresh_token_enc=?, scopes=?, expires_at=?, updated_at=?
       WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=? AND source='vault'`,
      [
        accessEnc, refreshEnc,
        t.scopes, t.expiresAt, Date.now(),
        owner.teamId, owner.kind, owner.id, provider,
      ],
    );
  }

  /** Mark a connection as used now (resets the idle timer). Called after each injection. */
  async touch(owner: Owner, provider: string): Promise<void> {
    await this.db.run(
      `UPDATE connection SET last_used_at=? WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [Date.now(), owner.teamId, owner.kind, owner.id, provider],
    );
  }

  /** A user's OWN connections (for `/vouchr status`). Never lists channel-owned creds. */
  async listForUser(i: SlackIdentity): Promise<{ provider: string; externalAccount: string | null }[]> {
    const rows = (await this.db.all(
      `SELECT provider, external_account FROM connection WHERE team_id=? AND owner_kind='user' AND owner_id=?`,
      [i.teamId, i.userId],
    )) as any[];
    return rows.map((r) => ({ provider: r.provider, externalAccount: r.external_account }));
  }

  /**
   * Every connection currently past its TTL — for the periodic sweep. Filters in SQL
   * (only expired rows cross the wire) rather than scanning the whole table in memory.
   * The predicate MUST mirror isExpired(): idle uses last_used_at (falling back to
   * created_at), max-age uses created_at; an empty policy expires nothing.
   */
  async listExpired(): Promise<{ owner: Owner; provider: string }[]> {
    const now = Date.now();
    const clauses: string[] = [];
    const params: any[] = [];
    if (this.ttl.idleMs != null) {
      clauses.push('COALESCE(last_used_at, created_at) < ?');
      params.push(now - this.ttl.idleMs);
    }
    if (this.ttl.maxAgeMs != null) {
      clauses.push('created_at < ?');
      params.push(now - this.ttl.maxAgeMs);
    }
    if (!clauses.length) return []; // empty policy → nothing expires
    const rows = (await this.db.all(
      `SELECT team_id, owner_kind, owner_id, provider FROM connection WHERE ${clauses.join(' OR ')}`,
      params,
    )) as any[];
    return rows.map((r) => ({
      owner: { teamId: r.team_id, kind: r.owner_kind, id: r.owner_id } as Owner,
      provider: r.provider,
    }));
  }

  async delete(owner: Owner, provider: string): Promise<void> {
    await this.db.run(
      `DELETE FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [owner.teamId, owner.kind, owner.id, provider],
    );
  }
}

/** Postgres returns BYTEA as Buffer already; this is a no-op guard for both engines. */
function toBuffer(v: unknown): Buffer {
  return Buffer.isBuffer(v) ? v : Buffer.from(v as any);
}
