import { randomUUID } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { Owner } from './owner';
import { purgeApprovalsForOwner } from './approval';
import { seal, open, toBuffer, type EnvelopeProvider, type MasterKeys } from './crypto';

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
  /** #116 system-only provenance: true iff this row was written by a dry-run synthetic consent
   *  (never user- or provider-controlled — unlike externalAccount). The ONE trusted marker every
   *  dry-run safety/revoke decision keys off. */
  dryRun: boolean;
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
    // A bare Buffer is the single id-less master key (today's deploys); a Keyring (#115) adds
    // named decryption keys and, when its primary is named, keyed-scheme writes for rotation.
    private key: MasterKeys,
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

  /**
   * Returns the credential, or null if absent OR expired per the TTL policy.
   * `onDecrypt` (optional) fires once per real KMS/envelope DEK unwrap, so a caller can meter
   * decrypt volume without the vault holding an event sink. No-op on the legacy direct path.
   */
  async get(owner: Owner, provider: string, onDecrypt?: () => void): Promise<StoredCredential | null> {
    const row = await this.fetchRow(owner, provider);
    if (!row) return null;
    if (this.isExpired(row.created_at, row.last_used_at ?? row.created_at)) return null;
    return this.decode(row, onDecrypt);
  }

  /**
   * TTL-independent decrypting read, for best-effort upstream REVOCATION only (GHSA-25m2): a row
   * past its local TTL may still be live at the provider, so disconnect/offboard must still hand
   * its token to the revoke endpoint. Never use this for injection — `get` stays the only read
   * gated on the TTL policy.
   */
  async getForRevoke(owner: Owner, provider: string): Promise<StoredCredential | null> {
    const row = await this.fetchRow(owner, provider);
    return row ? this.decode(row) : null;
  }

  private async fetchRow(owner: Owner, provider: string): Promise<any> {
    return this.db.get(
      `SELECT * FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [owner.teamId, owner.kind, owner.id, provider],
    );
  }

  private async decode(row: any, onDecrypt?: () => void): Promise<StoredCredential> {
    return {
      source: row.source,
      accessToken: row.access_token_enc ? await open(toBuffer(row.access_token_enc), this.key, this.envelope, onDecrypt) : null,
      refreshToken: row.refresh_token_enc ? await open(toBuffer(row.refresh_token_enc), this.key, this.envelope, onDecrypt) : null,
      secretRef: row.secret_ref,
      scopes: row.scopes,
      expiresAt: row.expires_at,
      externalAccount: row.external_account,
      dryRun: row.dry_run === 1, // fail-closed: only an explicit 1 is trusted as synthetic
    };
  }

  /**
   * notification_state rows (#117 health-notification debounce) are satellites of a connection:
   * purge them whenever the connection is (re)written or deleted — so a RECONNECT resets the
   * debounce (fresh connection ⇒ fresh state) and a deleted connection can't leak state rows.
   * Owned HERE, inside the vault, because every entry point (Bolt, modal, broker, CLI, sweep)
   * routes its connection writes/deletes through these three methods — no per-call-site purges to
   * drift (STR-3). updateTokens (silent refresh) deliberately does NOT purge: a refresh is not a
   * reconnect, and the max-age warning must survive it.
   *
   * #113 approval grants (`approval_request`) are satellites of a connection the SAME way, and purged
   * on the SAME three methods for the SAME reason: a grant authorizes use of THIS owner's credential,
   * so it must not outlive a delete (disconnect / offboard / bulk-revoke / TTL-expiry all route
   * through delete()) nor be spent after a reconnect/reconfiguration (upsert/reference). updateTokens
   * again does NOT purge — a silent refresh keeps the same connection, so a live grant stays valid.
   */
  private async clearSatellites(db: Db, owner: Owner, provider: string): Promise<void> {
    await db.run(
      `DELETE FROM notification_state WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [owner.teamId, owner.kind, owner.id, provider],
    );
    await purgeApprovalsForOwner(db, owner, provider);
  }

  /** Connection WRITE + its satellite purge are ONE logical mutation: run them in one transaction
   *  so a purge failure can't half-commit a write (a "failed" upsert that actually landed). Used by
   *  the write paths only — delete() deliberately is NOT transactional over the purge, so a
   *  satellite failure can never roll back a credential delete (GHSA-25m2 review; see delete()).
   *  A backend without `transaction` (only minimal test stubs) falls back to sequential statements. */
  private mutation<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    return this.db.transaction ? this.db.transaction(fn) : fn(this.db);
  }

  /** Store a vaulted credential (Vouchr encrypts and owns refresh). A production write is always
   *  REAL: `dry_run=0` on insert AND on conflict, so overwriting a dry-run row re-marks it real
   *  (zero-behavior-change — production ignores dry-run provenance entirely). */
  async upsert(owner: Owner, provider: string, t: StoredToken): Promise<void> {
    const now = Date.now();
    const accessEnc = await seal(t.accessToken, this.key, this.envelope);
    const refreshEnc = t.refreshToken ? await seal(t.refreshToken, this.key, this.envelope) : null;
    await this.mutation(async (tx) => {
      await tx.run(
        `INSERT INTO connection
           (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
            access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
            external_account, dry_run, created_at, updated_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, 'vault', ?, ?, NULL, ?, ?, ?, 0, ?, ?, ?)
         ON CONFLICT(team_id, owner_kind, owner_id, provider) DO UPDATE SET
           source='vault', enterprise_id=excluded.enterprise_id,
           access_token_enc=excluded.access_token_enc,
           refresh_token_enc=excluded.refresh_token_enc, secret_ref=NULL,
           scopes=excluded.scopes, expires_at=excluded.expires_at,
           external_account=excluded.external_account, dry_run=0, updated_at=excluded.updated_at,
           created_at=excluded.created_at, last_used_at=excluded.last_used_at`,
        [
          randomUUID(), owner.enterpriseId ?? null, owner.teamId, owner.kind, owner.id, provider,
          accessEnc, refreshEnc,
          t.scopes, t.expiresAt, t.externalAccount, now, now, now,
        ],
      );
      await this.clearSatellites(tx, owner, provider); // reconnect ⇒ fresh notification state (#117) + drop stale approval grants (#113)
    });
  }

  /**
   * #116 SYNTHETIC (dry-run) write. Like {@link upsert} but sets the trusted `dry_run=1` provenance
   * column, and is ATOMIC with the no-clobber check: the conditional `ON CONFLICT … WHERE
   * connection.dry_run=1` only overwrites an existing row that is ITSELF synthetic, so a REAL row a
   * sibling production process wrote — even one that lands between an earlier read and this call —
   * survives untouched. Returns false (0 rows written) when a real row blocked it; the caller
   * refuses the consent. No separate get(): the check and write are one statement, so there is no
   * TOCTOU window.
   */
  async upsertDryRun(owner: Owner, provider: string, t: StoredToken): Promise<boolean> {
    const now = Date.now();
    const accessEnc = await seal(t.accessToken, this.key, this.envelope);
    const refreshEnc = t.refreshToken ? await seal(t.refreshToken, this.key, this.envelope) : null;
    return this.mutation(async (tx) => {
      const { changes } = await tx.run(
        `INSERT INTO connection
           (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
            access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
            external_account, dry_run, created_at, updated_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, 'vault', ?, ?, NULL, ?, ?, ?, 1, ?, ?, ?)
         ON CONFLICT(team_id, owner_kind, owner_id, provider) DO UPDATE SET
           source='vault', enterprise_id=excluded.enterprise_id,
           access_token_enc=excluded.access_token_enc,
           refresh_token_enc=excluded.refresh_token_enc, secret_ref=NULL,
           scopes=excluded.scopes, expires_at=excluded.expires_at,
           external_account=excluded.external_account, updated_at=excluded.updated_at,
           created_at=excluded.created_at, last_used_at=excluded.last_used_at
         WHERE connection.dry_run=1`,
        [
          randomUUID(), owner.enterpriseId ?? null, owner.teamId, owner.kind, owner.id, provider,
          accessEnc, refreshEnc,
          t.scopes, t.expiresAt, t.externalAccount, now, now, now,
        ],
      );
      if (changes === 0) return false; // a real row exists → refuse; nothing was written
      await this.clearSatellites(tx, owner, provider); // #113 renamed clearNotifyState → also purges approvals
      return true;
    });
  }

  /** #116: whether at-rest writes go through an external KMS envelope. Dry-run refuses one at
   *  startup (its wrap/unwrap are real network calls, breaking the offline guarantee). */
  get usesEnvelope(): boolean { return !!this.envelope; }

  /**
   * Store a REFERENCED credential: the secret stays in an external manager (e.g. AWS
   * Secrets Manager). We persist only a non-secret `ref` + the resolver `source` id;
   * the injector resolves it just-in-time. Rotation stays external: Vouchr never holds it.
   */
  async reference(
    owner: Owner,
    provider: string,
    r: { source: string; secretRef: string; scopes?: string; externalAccount?: string | null },
  ): Promise<void> {
    const now = Date.now();
    await this.mutation(async (tx) => {
      await tx.run(
        `INSERT INTO connection
           (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
            access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
            external_account, dry_run, created_at, updated_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, 0, ?, ?, ?)
         ON CONFLICT(team_id, owner_kind, owner_id, provider) DO UPDATE SET
           source=excluded.source, enterprise_id=excluded.enterprise_id,
           access_token_enc=NULL, refresh_token_enc=NULL,
           secret_ref=excluded.secret_ref, scopes=excluded.scopes, expires_at=NULL,
           external_account=excluded.external_account, dry_run=0, updated_at=excluded.updated_at,
           created_at=excluded.created_at, last_used_at=excluded.last_used_at`,
        [
          randomUUID(), owner.enterpriseId ?? null, owner.teamId, owner.kind, owner.id, provider, r.source,
          r.secretRef, r.scopes ?? '', r.externalAccount ?? null, now, now, now,
        ],
      );
      await this.clearSatellites(tx, owner, provider); // reconnect ⇒ fresh notification state (#117) + drop stale approval grants (#113)
    });
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

  /** True when the backend coordinates refresh across processes (Postgres advisory lock). */
  get crossProcessRefresh(): boolean { return !!this.db.withRefreshLock; }

  /**
   * Run `fn` while holding the cross-process refresh lock for (owner, provider), with the vault
   * rebound to the locked transaction so `fn`'s reads/writes (get/updateTokens) see the same tx.
   * On a backend without a lock (SQLite) this is a passthrough that runs `fn(this)` — the injector's
   * in-process single-flight map already serializes a single process. Key matches the injector's
   * inflight key so in-process and cross-process coordination agree on identity.
   */
  async withRefreshLock<T>(owner: Owner, provider: string, fn: (locked: Vault) => Promise<T>): Promise<T> {
    if (!this.db.withRefreshLock) return fn(this);
    const key = `${owner.teamId}:${owner.kind}:${owner.id}:${provider}`;
    return this.db.withRefreshLock(key, (txDb) => fn(new Vault(txDb, this.key, this.ttl, this.envelope)));
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
   * A user's OWN connections that are still LIVE per the TTL policy — the batched, zero-decryption
   * analogue of `get() != null` for a status view. Reuses the SAME `isExpired` computation `get`
   * applies (so a past-TTL row is dropped identically), just in memory over one query instead of
   * N decrypting `get` calls. `listForUser` stays unfiltered on purpose (offboarding must revoke
   * expired rows too); this variant is for "what can the user actually use right now".
   */
  async listLiveForUser(i: SlackIdentity): Promise<{ provider: string; externalAccount: string | null }[]> {
    const rows = (await this.db.all(
      `SELECT provider, external_account, created_at, last_used_at FROM connection WHERE team_id=? AND owner_kind='user' AND owner_id=?`,
      [i.teamId, i.userId],
    )) as any[];
    return rows
      .filter((r) => !this.isExpired(r.created_at, r.last_used_at ?? r.created_at))
      .map((r) => ({ provider: r.provider, externalAccount: r.external_account }));
  }

  /**
   * Every connection currently past its TTL (for the periodic sweep). Filters in SQL
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

  /**
   * Connections whose TTL ceiling falls within the next `withinMs` (#117 proactive expiry
   * warnings). The SQL predicate MUST mirror isExpired() — idle uses last_used_at (falling back to
   * created_at), max-age uses created_at, an empty policy expires nothing — just evaluated at
   * `now + withinMs` instead of `now`. Rows ALREADY past their ceiling are excluded (the sweep
   * deletes those instead of warning). `expiresAt` = the effective ceiling (the earliest applicable
   * expiry), so callers can say when.
   *
   * Window guard — SELECTION only: a TTL dimension ≤ `withinMs` never SELECTS rows. With, say,
   * idleMs = 48h against a 72h window, every live connection — used one second ago included —
   * sits permanently "inside the window", so selecting on that dimension is a daily reconnect nag
   * forever, not an early warning. The REPORTED `expiresAt` is different: it is the connection's
   * real earliest death, min over ALL configured dimensions, guard or no guard — a row selected
   * for its approaching max-age may still die of a short idle TTL first, and "expires in ~Nh"
   * must not overstate its lifetime.
   */
  async listExpiringSoon(withinMs: number): Promise<{ owner: Owner; provider: string; expiresAt: number }[]> {
    const now = Date.now();
    const horizon = now + withinMs;
    const warnIdle = this.ttl.idleMs != null && this.ttl.idleMs > withinMs;
    const warnMaxAge = this.ttl.maxAgeMs != null && this.ttl.maxAgeMs > withinMs;
    const clauses: string[] = [];
    const params: any[] = [];
    if (warnIdle) {
      clauses.push('COALESCE(last_used_at, created_at) < ?');
      params.push(horizon - this.ttl.idleMs!);
    }
    if (warnMaxAge) {
      clauses.push('created_at < ?');
      params.push(horizon - this.ttl.maxAgeMs!);
    }
    if (!clauses.length) return []; // no warnable dimension → nothing to warn about
    const rows = (await this.db.all(
      `SELECT enterprise_id, team_id, owner_kind, owner_id, provider, created_at, last_used_at
         FROM connection WHERE ${clauses.join(' OR ')}`,
      params,
    )) as any[];
    return rows.flatMap((r) => {
      const createdAt = Number(r.created_at);
      const lastUsedAt = r.last_used_at == null ? createdAt : Number(r.last_used_at);
      // Real earliest ceiling: ALL configured dimensions, not just the selecting ones (see above).
      const ceilings: number[] = [];
      if (this.ttl.idleMs != null) ceilings.push(lastUsedAt + this.ttl.idleMs);
      if (this.ttl.maxAgeMs != null) ceilings.push(createdAt + this.ttl.maxAgeMs);
      const expiresAt = Math.min(...ceilings);
      if (expiresAt <= now) return []; // already expired: swept, never warned
      return [{
        owner: { teamId: r.team_id, kind: r.owner_kind, id: r.owner_id, enterpriseId: r.enterprise_id ?? null } as Owner,
        provider: r.provider,
        expiresAt,
      }];
    });
  }

  /**
   * Returns whether a row actually existed, so callers derive a truthful `removed` from the
   * delete itself — not from whether the token happened to be readable/unexpired (GHSA-25m2).
   *
   * Unlike the WRITE paths (upsert/reference, where a satellite-purge failure correctly rolls the
   * whole write back — no new credential lands without its satellites cleared), the satellite
   * purge here runs AFTER the delete and BEST-EFFORT: a notification/approval cleanup failure must
   * never roll back or block the credential delete (GHSA-25m2 review). A missed purge is
   * fail-closed anyway: a grant without its connection cannot reach a secret (consume precedes the
   * vault read, which then throws NoConnectionError), a reconnect purges satellites inside
   * upsert/reference BEFORE the new credential is usable, and the TTL sweep reclaims expired rows.
   */
  async delete(owner: Owner, provider: string): Promise<boolean> {
    const { changes } = await this.db.run(
      `DELETE FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [owner.teamId, owner.kind, owner.id, provider],
    );
    try {
      await this.clearSatellites(this.db, owner, provider); // notification_state (#117) + approval grants (#113)
    } catch { /* best-effort; see above */ }
    return changes > 0;
  }
}
