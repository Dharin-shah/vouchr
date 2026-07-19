import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { Owner } from './owner';
import { purgeApprovalsForOwner } from './approval';
import { purgeSessionsForOwner } from './session';
import {
  InteractionStateChangedError,
  isInteractionId,
  POSTGRES_NOW_MS_SQL,
  purgeChannelInteractionState,
} from './interaction';
import {
  latestProvisioningRevocationTombstone,
  latestUserOffboardTombstone,
  markProvisioningRevoked,
  tombstoneBlocks,
  withProvisioningRevocationLock,
  withUserInteractionFence,
  withUserProvisioningLock,
} from './consent';
import { seal, open, toBuffer, toKeyring, type EnvelopeProvider, type MasterKeys } from './crypto';

/** Input for a vaulted (Vouchr-encrypted) connection. */
export interface StoredToken {
  accessToken: string;
  refreshToken: string | null;
  scopes: string;
  expiresAt: number | null;
  externalAccount: string | null;
}

/** A user-provisioning intent is either a trusted server timestamp or an atomic resolver that
 * consumes a persisted opaque request inside the credential transaction and yields its issuance
 * time (or null to abort). Every user write is fenced by generation ordering regardless of shape. */
export type UserProvisioningIssuance = number | ((tx: Db) => Promise<number | null>);
export type UserProvisioningResult = 'stored' | 'stale' | 'offboarded' | 'revoked' | 'conflict';

const PREPARE_VAULT_CREDENTIAL_WRITE = Symbol('prepare-vault-credential-write');
const BIND_VAULT_EXPIRY_TRANSACTION = Symbol('bind-vault-expiry-transaction');
export type PreparedVaultCredentialWrite = (
  tx: Db,
  owner: Owner,
  provider: string,
) => Promise<void>;

interface VaultExpiryTransaction {
  listExpired(): Promise<{ owner: Owner; provider: string }[]>;
  deleteExpired(owner: Owner, provider: string): Promise<boolean>;
  listExpiringSoon(withinMs: number): Promise<{ owner: Owner; provider: string; expiresAt: number }[]>;
}

/** Canonical PostgreSQL advisory-lock key for one credential lifecycle. Kept beside Vault so every
 * mutation, including break-glass pending-authority purge, orders on the exact same key. */
export function credentialLockKey(owner: Owner, provider: string): string {
  return `${owner.teamId}:${owner.kind}:${owner.id}:${provider}`;
}

/**
 * What `get` returns. A null `secretRef` marks a Vouchr-encrypted token; a non-null reference marks
 * an external-manager pointer the injector resolves just-in-time. Most external source ids differ
 * from `vault`; HashiCorp's advertised `vault://` source intentionally shares that historical name,
 * so callers must use reference presence rather than source alone to distinguish the two.
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

/**
 * Thrown by the Vault when the deployment is in operator-declared lockdown (`VOUCHR_LOCKDOWN`,
 * #239 containment): credential SERVING (`get`), MINTING (`upsert`/`reference`) and refresh WRITES
 * fail closed, so a compromised deployment cannot serve or resurrect a credential while an incident
 * is being contained. Break-glass DELETION (`deleteForRevoke`) and metadata-only reads stay open so
 * `vouchr revoke` still works during lockdown. Carries no secret; `mapSafeError` deliberately has no
 * branch for it, so it collapses to the generic internal-error copy and never advertises the incident
 * state to a caller. Its authority is deployment configuration outside the credential database — a DB
 * flag would not be trustworthy once the database itself is the compromised boundary. */
export class CredentialLockdownError extends Error {
  readonly code = 'credential_lockdown' as const;
  constructor() {
    super('credential access is locked down');
    this.name = 'CredentialLockdownError';
  }
}

/** Encrypted credential store, keyed by the owning principal (user OR channel). */
export class Vault {
  /** Set only on the transaction-bound facade created by withCredentialLocks. Deletion through
   * that facade already rolls satellite cleanup back with its outer mutation, so it must not try
   * to establish a provisioning marker while holding the credential lock. */
  private credentialLockHeld = false;

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
    // #239 containment: when true, serving/minting/refresh fail closed (deletion + metadata stay
    // open). Set from deployment config (VOUCHR_LOCKDOWN) by the boot paths, never from the DB.
    private lockdown = false,
  ) {}

  /** #239: fail closed on any credential serve/mint/refresh while the deployment is locked down.
   *  Deletion and metadata reads deliberately do NOT call this — break-glass must work in lockdown. */
  private assertNotLockedDown(): void {
    if (this.lockdown) throw new CredentialLockdownError();
  }

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
  async get(
    owner: Owner,
    provider: string,
    onDecrypt?: () => void,
    expectedId?: string,
  ): Promise<StoredCredential | null> {
    this.assertNotLockedDown(); // serving a credential is denied under lockdown (#239)
    if (expectedId !== undefined && !isInteractionId(expectedId)) return null;
    const row = await this.fetchRow(owner, provider, expectedId);
    if (!row) return null;
    if (this.isExpired(row.created_at, row.last_used_at ?? row.created_at)) return null;
    return this.decode(row, onDecrypt);
  }

  /**
   * TTL-independent decrypting read, for best-effort upstream REVOCATION only (GHSA-25m2): a row
   * past its local TTL may still be live at the provider, so disconnect/offboard must still hand
   * its token to the revoke endpoint. Never use this for injection — `get` stays the only read
   * gated on the TTL policy.
   *
   * Deliberately NOT `assertNotLockedDown`-gated (#239): like `deleteForRevoke`, this is a
   * revocation-scoped read that break-glass must keep working during a lockdown/incident. Serving a
   * credential to an agent goes through `get`, which IS gated — do not route injection through here.
   */
  async getForRevoke(owner: Owner, provider: string): Promise<StoredCredential | null> {
    const row = await this.fetchRow(owner, provider);
    return row ? this.decode(row) : null;
  }

  /**
   * TTL-independent, metadata-only existence check for one exact owned connection. Used when a
   * provider has been removed from the runtime registry: the stored row itself is the allowlist
   * entry that lets its owner delete it, without decrypting token material or listing other rows.
   */
  async has(owner: Owner, provider: string): Promise<boolean> {
    const row = await this.db.get(
      `SELECT 1 AS present FROM connection
       WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [owner.teamId, owner.kind, owner.id, provider],
    );
    return row != null;
  }

  /** Metadata-only live existence check for control-flow gates that must run before any credential
   *  decrypt (for example session approval). Uses the same TTL predicate as get(). */
  async hasLive(owner: Owner, provider: string): Promise<boolean> {
    return (await this.liveId(owner, provider)) !== null;
  }

  /** Metadata-only current credential generation. Reconnect/reconfiguration writes a fresh row id;
   * approvals, sessions, and handles bind to it so authority for generation A can never read B. */
  async liveId(owner: Owner, provider: string): Promise<string | null> {
    const row = await this.db.get<{ id: string; created_at: number; last_used_at: number | null }>(
      `SELECT id, created_at, last_used_at FROM connection
       WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [owner.teamId, owner.kind, owner.id, provider],
    );
    return row && !this.isExpired(row.created_at, row.last_used_at ?? row.created_at) ? row.id : null;
  }

  /** TTL-aware, metadata-only account label for one exact connection generation. Account display
   * must not decrypt token material (or invoke KMS) merely to render non-secret identity metadata. */
  async getAccount(
    owner: Owner,
    provider: string,
    expectedId?: string,
  ): Promise<{ externalAccount: string | null } | null> {
    if (expectedId !== undefined && !isInteractionId(expectedId)) return null;
    const exact = expectedId !== undefined;
    const row = await this.db.get<{
      external_account: string | null;
      created_at: number;
      last_used_at: number | null;
    }>(
      `SELECT external_account, created_at, last_used_at FROM connection
       WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?${exact ? ' AND id=?' : ''}`,
      exact
        ? [owner.teamId, owner.kind, owner.id, provider, expectedId]
        : [owner.teamId, owner.kind, owner.id, provider],
    );
    if (!row || this.isExpired(row.created_at, row.last_used_at ?? row.created_at)) return null;
    return { externalAccount: row.external_account };
  }

  private async fetchRow(owner: Owner, provider: string, expectedId?: string): Promise<any> {
    if (expectedId !== undefined && !isInteractionId(expectedId)) return undefined;
    const exact = expectedId !== undefined;
    return this.db.get(
      `SELECT * FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?${exact ? ' AND id=?' : ''}`,
      exact
        ? [owner.teamId, owner.kind, owner.id, provider, expectedId]
        : [owner.teamId, owner.kind, owner.id, provider],
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
   *
   * User- and channel-provisioning requests are credential satellites too. A successful write or
   * delete spends every sibling setup prompt for that owner/provider, so an older modal cannot
   * overwrite a newer credential or recreate one after disconnect.
   */
  private async clearSatellites(db: Db, owner: Owner, provider: string): Promise<void> {
    await db.run(
      `DELETE FROM notification_state WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      [owner.teamId, owner.kind, owner.id, provider],
    );
    await purgeApprovalsForOwner(db, owner, provider);
    await purgeSessionsForOwner(db, owner, provider);
    if (owner.kind === 'user') {
      await db.run(
        `DELETE FROM user_provisioning_request WHERE team_id=? AND user_id=? AND provider=?`,
        [owner.teamId, owner.id, provider],
      );
    } else {
      await purgeChannelInteractionState(db, owner.teamId, owner.id, provider);
    }
  }

  /** Connection write/delete + its satellite purge are ONE logical mutation: run them in one
   *  transaction so a purge failure can't half-commit a write, and a delete's purge can never
   *  touch a newer credential generation. delete() additionally retries WITHOUT the purge when
   *  the transaction fails — a satellite failure must never roll back a credential delete
   *  (GHSA-25m2 review; see delete()). A backend without `transaction` (only minimal test stubs)
   *  falls back to sequential statements. */
  private mutation<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    return this.db.transaction ? this.db.transaction(fn) : fn(this.db);
  }

  /**
   * Atomically claim one exact connection for deletion and return only the columns needed to inspect
   * its trusted provenance or decode it for best-effort upstream revocation. `DELETE ... RETURNING`
   * is the concurrency boundary: only the caller that actually removes the row receives token
   * material, so duplicate disconnects cannot both revoke upstream.
   *
   * The happy path keeps the credential delete and satellite purge in one transaction. If the DELETE
   * ran but satellite cleanup fails, retry the same credential-only claim outside the rolled-back
   * transaction, preserving delete()'s fail-closed fallback. A backend without transactions is only a
   * minimal test stub: its first DELETE already committed, so retain that claim when the retry sees no
   * row. A DELETE failure itself still propagates.
   */
  private async claimDelete(
    owner: Owner,
    provider: string,
    expectedId?: string,
  ): Promise<{
    id: string;
    access_token_enc: unknown;
    refresh_token_enc: unknown;
    secret_ref: string | null;
    dry_run: unknown;
  } | null> {
    if (expectedId !== undefined && !isInteractionId(expectedId)) {
      throw new Error('invalid expected credential generation');
    }
    const returning = 'RETURNING id, access_token_enc, refresh_token_enc, secret_ref, dry_run';
    const sql = `DELETE FROM connection
      WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?${expectedId !== undefined ? ' AND id=?' : ''}
      ${returning}`;
    const params = [
      owner.teamId,
      owner.kind,
      owner.id,
      provider,
      ...(expectedId !== undefined ? [expectedId] : []),
    ];
    let claimed: {
      id: string;
      access_token_enc: unknown;
      refresh_token_enc: unknown;
      secret_ref: string | null;
      dry_run: unknown;
    } | null | undefined;
    try {
      return await this.withCredentialLock(owner, provider, async (_locked, tx) => {
        claimed = (await tx.get(sql, params)) ?? null;
        if (claimed) await this.clearSatellites(tx, owner, provider);
        return claimed;
      });
    } catch (e) {
      // `undefined` means the DELETE statement itself never completed. Do not hide a genuinely
      // stranded credential behind the satellite-cleanup fallback.
      if (claimed === undefined) throw e;
      // Current reconnects write a fresh row-generation id; the ciphertext/reference fingerprint
      // also protects rolling overlap with an older writer that preserved id. Bind the fallback to
      // the exact row whose transaction rolled back, never a newer reconnect or refresh.
      const original = claimed;
      const retry = original
        ? await this.withCredentialLock(owner, provider, async (_locked, tx) => (
          await tx.get(
            `DELETE FROM connection
             WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=? AND id=?
               AND access_token_enc IS NOT DISTINCT FROM ?
               AND refresh_token_enc IS NOT DISTINCT FROM ?
               AND secret_ref IS NOT DISTINCT FROM ?
             ${returning}`,
            [...params, original.id, original.access_token_enc, original.refresh_token_enc, original.secret_ref],
          )
        ) ?? null)
        : null;
      // Without a real transaction, the first DELETE was already committed before cleanup failed.
      if (retry) return retry;
      if (!this.db.transaction) return claimed;
      throw new Error('credential deletion could not be confirmed after cleanup failure; retry');
    }
  }

  /** Establish a durable exact-owner provisioning fence before an ordinary delete. The marker's
   * short transaction releases its scope lock before claimDelete takes the credential lock: an old
   * writer either commits first and is then deleted, or observes this marker and refuses. If the
   * marker fails, still attempt the local delete but surface the outcome as unconfirmed afterward;
   * a credential must never be reported cleanly removed while an exposed setup request can recreate
   * it. Transaction-bound locked facades skip this step because their outer mutation makes delete +
   * satellite purge atomic and already serializes the same credential lifecycle. */
  private async claimDeleteFenced(
    owner: Owner,
    provider: string,
    expectedId?: string,
  ): Promise<{
    row: Awaited<ReturnType<Vault['claimDelete']>>;
    fenced: boolean;
    fenceError: unknown;
  }> {
    let fenced = this.credentialLockHeld;
    let fenceError: unknown;
    if (!this.credentialLockHeld) {
      try {
        await markProvisioningRevoked(
          this.db,
          owner.kind === 'user'
            ? { provider, teamId: owner.teamId, userId: owner.id }
            : { provider, teamId: owner.teamId, channel: owner.id },
        );
        fenced = true;
      } catch (error) {
        fenceError = error;
      }
    }
    // Preserve a marker failure as outcome data until the caller has finished every operation that
    // depends on the deleted row. In particular, deleteForRevoke must still decode the one claimed
    // token and make its best-effort upstream revoke before the lifecycle failure is surfaced.
    return {
      row: await this.claimDelete(owner, provider, expectedId),
      fenced,
      fenceError,
    };
  }

  /** Exact-generation delete used only after {@link prepareUserDisconnect}. The caller holds the
   * credential and actor-offboard locks. A savepoint keeps satellite cleanup atomic while retaining
   * the historical credential-only fallback without releasing either fence. */
  private async claimPreparedDisconnect(
    tx: Db,
    owner: Owner,
    provider: string,
    expectedId: string,
  ): Promise<Awaited<ReturnType<Vault['claimDelete']>>> {
    if (!isInteractionId(expectedId)) throw new Error('invalid expected credential generation');
    const returning = 'RETURNING id, access_token_enc, refresh_token_enc, secret_ref, dry_run';
    const params = [owner.teamId, owner.kind, owner.id, provider, expectedId];
    const sql = `DELETE FROM connection
      WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=? AND id=?
      ${returning}`;
    const savepoint = 'vouchr_disconnect_credential_delete';
    await tx.exec(`SAVEPOINT ${savepoint}`);
    let claimed: Awaited<ReturnType<Vault['claimDelete']>> | undefined;
    try {
      claimed = (await tx.get(sql, params)) ?? null;
      if (claimed) await this.clearSatellites(tx, owner, provider);
      await tx.exec(`RELEASE SAVEPOINT ${savepoint}`);
      return claimed;
    } catch (error) {
      try {
        await tx.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
        await tx.exec(`RELEASE SAVEPOINT ${savepoint}`);
      } catch {
        throw error;
      }
      if (claimed === undefined) throw error;
      if (!claimed) return null;
      const retry = await tx.get<NonNullable<Awaited<ReturnType<Vault['claimDelete']>>>>(
        `DELETE FROM connection
          WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=? AND id=?
            AND access_token_enc IS NOT DISTINCT FROM ?
            AND refresh_token_enc IS NOT DISTINCT FROM ?
            AND secret_ref IS NOT DISTINCT FROM ?
          ${returning}`,
        [
          ...params,
          claimed.access_token_enc,
          claimed.refresh_token_enc,
          claimed.secret_ref,
        ],
      );
      if (retry) return retry;
      throw new Error('credential deletion could not be confirmed after cleanup failure; retry');
    }
  }

  /**
   * Bind one user-initiated Disconnect to its trusted receipt and the exact stored credential
   * generation visible at that authorization point. Lock order is the suffix of every user writer:
   * provisioning-revocation scopes, then actor offboarding scopes. A reconnect writer holding the
   * credential lock therefore waits here at the revocation lock; this helper never takes that
   * credential lock, so the order cannot invert.
   *
   * The exact setup marker and generation snapshot share that short transaction. PostgreSQL-only
   * savepoint recovery preserves the historical disconnect guarantee: if the marker write itself
   * fails, the caller may still conditionally delete the snapshotted generation, but must report
   * `fenced:false`. Failure before the actor verdict or savepoint recovery propagates fail-closed.
   */
  async prepareUserDisconnect(
    identity: SlackIdentity,
    provider: string,
    issuedAt: number,
    expectedId?: string,
  ): Promise<
    | { status: 'current'; expectedId: string | null; fenced: boolean }
    | { status: 'offboarded' }
    | { status: 'stale' }
  > {
    if (!Number.isSafeInteger(issuedAt)) throw new Error('invalid disconnect issuance');
    if (expectedId !== undefined && !isInteractionId(expectedId)) return { status: 'stale' };
    const owner: Owner = {
      teamId: identity.teamId,
      kind: 'user',
      id: identity.userId,
      enterpriseId: identity.enterpriseId,
    };
    return withProvisioningRevocationLock(this.db, owner, provider, async (revocationTx) => {
      const current = await withUserInteractionFence(
        revocationTx,
        identity,
        issuedAt,
        async (actorTx) => {
          const row = await actorTx.get<{ id: string; generation_at: number }>(
            `SELECT id, generation_at FROM connection
              WHERE team_id=? AND owner_kind='user' AND owner_id=? AND provider=?`,
            [identity.teamId, identity.userId, provider],
          );
          // A Vouchr-owned Disconnect button carries only the opaque generation rendered with it.
          // Resolve provider/ownership before entering this helper, then repeat the exact-generation
          // check here under the credential + actor fences. A redelivered generation A action after
          // reconnect B must leave no provisioning marker or other durable side effect.
          if (expectedId !== undefined && row?.id !== expectedId) {
            return { status: 'stale' } as const;
          }
          // Provider-addressed slash/headless requests carry no opaque row id. This PostgreSQL-clock
          // boundary proves the current row already existed when the trusted request/assertion was
          // issued; a delayed request can never retarget a later reconnect.
          if (expectedId === undefined && row && row.generation_at > issuedAt) {
            return { status: 'stale' } as const;
          }
          const savepoint = 'vouchr_disconnect_provisioning_fence';
          await actorTx.exec(`SAVEPOINT ${savepoint}`);
          let fenced = true;
          try {
            await markProvisioningRevoked(actorTx, {
              provider,
              teamId: identity.teamId,
              userId: identity.userId,
            });
            await actorTx.exec(`RELEASE SAVEPOINT ${savepoint}`);
          } catch (error) {
            try {
              await actorTx.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
              await actorTx.exec(`RELEASE SAVEPOINT ${savepoint}`);
            } catch {
              throw error;
            }
            fenced = false;
          }
          return { status: 'current', expectedId: row?.id ?? null, fenced } as const;
        },
      );
      return current.status === 'current' ? current.value : { status: 'offboarded' };
    });
  }

  /**
   * Delete one connection for the revocation path and, only for the winning caller, optionally decode
   * its access token after the local delete committed. Unregistered/stale providers pass
   * `decrypt=false`: their trusted `dry_run` bit remains available without touching ciphertext.
   */
  async deleteForRevoke(
    owner: Owner,
    provider: string,
    decrypt: boolean,
    prepared?: {
      expectedId: string;
      fenced: boolean;
      identity: SlackIdentity;
      issuedAt: number;
    },
  ): Promise<{
    removed: boolean;
    accessToken: string | null;
    dryRun: boolean;
    readFailed: boolean;
    fenced: boolean;
  }> {
    let row: Awaited<ReturnType<Vault['claimDelete']>>;
    let fenced: boolean;
    if (prepared) {
      const current = await this.withCredentialLock(owner, provider, async (_locked, tx) =>
        withUserInteractionFence(tx, prepared.identity, prepared.issuedAt, (actorTx) =>
          this.claimPreparedDisconnect(actorTx, owner, provider, prepared.expectedId)));
      if (current.status === 'offboarded') {
        throw new InteractionStateChangedError('connection', 'authorization');
      }
      row = current.value;
      fenced = prepared.fenced;
    } else {
      ({ row, fenced } = await this.claimDeleteFenced(owner, provider));
    }
    if (!row) {
      return {
        removed: false,
        accessToken: null,
        dryRun: false,
        readFailed: false,
        fenced,
      };
    }
    const dryRun = row.dry_run === 1;
    if (!decrypt || dryRun) {
      return { removed: true, accessToken: null, dryRun, readFailed: false, fenced };
    }
    try {
      const accessToken = row.access_token_enc
        ? await open(toBuffer(row.access_token_enc), this.key, this.envelope)
        : null;
      return { removed: true, accessToken, dryRun, readFailed: false, fenced };
    } catch {
      return { removed: true, accessToken: null, dryRun, readFailed: true, fenced };
    }
  }

  /** PostgreSQL-clock timestamp for a direct trusted user-provisioning call. Capture this before
   * any work that may race offboarding, then pass it to {@link upsertUser} or
   * {@link referenceUser}. Persisted Slack requests and verified headless assertions carry their
   * own earlier issuance time instead. */
  async userProvisioningIssuedAt(): Promise<number> {
    const row = await this.db.get<{ issued_at: number }>(`SELECT ${POSTGRES_NOW_MS_SQL} AS issued_at`);
    if (!Number.isSafeInteger(row?.issued_at)) throw new Error('could not issue user provisioning fence');
    return row!.issued_at;
  }

  /** One load-bearing fence for every user-owned credential creation/replacement. Lock order stays
   * credential lifecycle -> user offboard fence: either this transaction commits first and a later
   * offboard sees/deletes the row, or the tombstone commits first and this write refuses. A request
   * resolver runs under the same transaction so opaque-request consumption, credential mutation,
   * satellite purge, and audit companions are one outcome. */
  private async withUserProvisioningFence(
    owner: Owner,
    provider: string,
    issuance: UserProvisioningIssuance,
    write: (tx: Db) => Promise<void>,
  ): Promise<Exclude<UserProvisioningResult, 'conflict'>> {
    if (owner.kind !== 'user') throw new Error('user provisioning requires a user owner');
    const identity: SlackIdentity = {
      enterpriseId: owner.enterpriseId ?? null,
      teamId: owner.teamId,
      userId: owner.id,
    };
    return this.withCredentialLock(owner, provider, async (_locked, tx) =>
      withUserProvisioningLock(tx, identity, provider, async (fencedTx) => {
        const issuedAt = typeof issuance === 'number' ? issuance : await issuance(fencedTx);
        if (issuedAt == null) return 'stale';
        if (!Number.isSafeInteger(issuedAt)) throw new Error('invalid user provisioning issuance');
        const offboardedAt = await latestUserOffboardTombstone(fencedTx, identity);
        const revokedAt = await latestProvisioningRevocationTombstone(
          fencedTx,
          owner,
          provider,
        );
        if (tombstoneBlocks(offboardedAt, issuedAt)) return 'offboarded';
        if (tombstoneBlocks(revokedAt, issuedAt)) return 'revoked';
        // Newest-generation fence for EVERY user write, whatever the issuance shape. A credential
        // whose generation (write time) is at or after this request's issuance must never be
        // overwritten — EQUALITY FAILS CLOSED (`>=`): both are integer PostgreSQL milliseconds, so a
        // credential that committed just after an older request can compare equal, and a strict `>`
        // would let the stale write win the tie. A stalled OAuth/key/reference request therefore
        // loses. Legitimate replacements are not ties: each real re-key/re-reference/re-auth arrives
        // on a fresh interaction receipt strictly later than the prior write's generation.
        const existing = await fencedTx.get<{
          created_at: number;
          last_used_at: number | null;
          generation_at: number;
        }>(
          `SELECT created_at, last_used_at, generation_at FROM connection
           WHERE team_id=? AND owner_kind='user' AND owner_id=? AND provider=?`,
          [owner.teamId, owner.id, provider],
        );
        if (
          existing
          && !this.isExpired(existing.created_at, existing.last_used_at ?? existing.created_at)
          && existing.generation_at >= issuedAt
        ) {
          return 'stale';
        }
        await write(fencedTx);
        // A committed user credential makes every consent at-or-before its issuance obsolete: the
        // generation fence would fail that consent's callback closed (`>=`), so its URL is dead.
        // Supersede those rows in the SAME transaction (under the provisioning lock) so a fresh
        // connect cannot reuse one. The threshold MUST match the fence: `<= issuedAt` fails the
        // equal-millisecond consent closed too — a strict `<` would leave a same-ms consent reusable
        // even though its callback can never complete. The consent that minted THIS write (OAuth) is
        // already consumed and deleted by finalizeProvisioning; a strictly-newer pending consent
        // (created_at > issuedAt) is deliberately left alone.
        await fencedTx.run(
          `UPDATE consent_request SET superseded_at=${POSTGRES_NOW_MS_SQL}
           WHERE team_id=? AND user_id=? AND provider=?
             AND superseded_at IS NULL AND consumed_at IS NULL AND created_at <= ?`,
          [owner.teamId, owner.id, provider, issuedAt],
        );
        return 'stored';
      }));
  }

  /** The matching break-glass fence for exported low-level channel-owner writes. Capture issuance
   * before KMS or caller-adjacent async work, then hold every applicable revoke-scope lock through
   * the credential mutation so a confirmed CLI sweep cannot return before an older write settles. */
  private async withChannelProvisioningFence<T>(
    owner: Owner,
    provider: string,
    issuedAt: number,
    write: (tx: Db) => Promise<T>,
  ): Promise<{ status: 'written'; value: T } | { status: 'revoked' }> {
    if (owner.kind !== 'channel') throw new Error('channel provisioning requires a channel owner');
    if (!Number.isSafeInteger(issuedAt)) throw new Error('invalid channel provisioning issuance');
    return this.withCredentialLock(owner, provider, async (_locked, tx) =>
      withProvisioningRevocationLock(tx, owner, provider, async (fencedTx) => {
        const revokedAt = await latestProvisioningRevocationTombstone(
          fencedTx,
          owner,
          provider,
        );
        if (tombstoneBlocks(revokedAt, issuedAt)) return { status: 'revoked' };
        return { status: 'written', value: await write(fencedTx) };
      }));
  }

  private async sealedToken(t: StoredToken): Promise<{
    accessEnc: Buffer;
    refreshEnc: Buffer | null;
    now: number;
  }> {
    return {
      accessEnc: await seal(t.accessToken, this.key, this.envelope),
      refreshEnc: t.refreshToken ? await seal(t.refreshToken, this.key, this.envelope) : null,
      now: Date.now(),
    };
  }

  /** Prepare envelope/KMS material before a caller acquires lifecycle locks, then expose only one
   * transaction-bound write. The symbol keeps this primitive off the public package API; channel
   * setup uses it so a slow external KMS cannot pin an actor's offboarding fence. */
  async [PREPARE_VAULT_CREDENTIAL_WRITE](
    t: StoredToken,
  ): Promise<PreparedVaultCredentialWrite> {
    const prepared = await this.sealedToken(t);
    let used = false;
    return async (tx, owner, provider) => {
      if (used) throw new Error('prepared credential write already used');
      used = true;
      await this.writeVaultCredential(tx, owner, provider, t, prepared);
    };
  }

  private async writeVaultCredential(
    tx: Db,
    owner: Owner,
    provider: string,
    t: StoredToken,
    prepared: Awaited<ReturnType<Vault['sealedToken']>>,
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<void> {
    this.assertNotLockedDown(); // minting a credential is denied under lockdown (#239)
    await tx.run(
      `INSERT INTO connection
         (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
          access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
          external_account, dry_run, created_at, updated_at, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, 'vault', ?, ?, NULL, ?, ?, ?, 0, ?, ?, ?)
       ON CONFLICT(team_id, owner_kind, owner_id, provider) DO UPDATE SET
         id=excluded.id, source='vault', enterprise_id=excluded.enterprise_id,
         generation_at=excluded.generation_at,
         access_token_enc=excluded.access_token_enc,
         refresh_token_enc=excluded.refresh_token_enc, secret_ref=NULL,
         scopes=excluded.scopes, expires_at=excluded.expires_at,
         external_account=excluded.external_account, dry_run=0, updated_at=excluded.updated_at,
         created_at=excluded.created_at, last_used_at=excluded.last_used_at`,
      [
        randomUUID(), owner.enterpriseId ?? null, owner.teamId, owner.kind, owner.id, provider,
        prepared.accessEnc, prepared.refreshEnc,
        t.scopes, t.expiresAt, t.externalAccount, prepared.now, prepared.now, prepared.now,
      ],
    );
    await this.clearSatellites(tx, owner, provider);
    await afterWrite?.(tx);
  }

  private async writeDryRunCredential(
    tx: Db,
    owner: Owner,
    provider: string,
    t: StoredToken,
    prepared: Awaited<ReturnType<Vault['sealedToken']>>,
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<boolean> {
    this.assertNotLockedDown(); // minting a (dry-run) credential is denied under lockdown (#239)
    const { changes } = await tx.run(
      `INSERT INTO connection
         (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
          access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
          external_account, dry_run, created_at, updated_at, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, 'vault', ?, ?, NULL, ?, ?, ?, 1, ?, ?, ?)
       ON CONFLICT(team_id, owner_kind, owner_id, provider) DO UPDATE SET
         id=excluded.id, source='vault', enterprise_id=excluded.enterprise_id,
         generation_at=excluded.generation_at,
         access_token_enc=excluded.access_token_enc,
         refresh_token_enc=excluded.refresh_token_enc, secret_ref=NULL,
         scopes=excluded.scopes, expires_at=excluded.expires_at,
         external_account=excluded.external_account, updated_at=excluded.updated_at,
         created_at=excluded.created_at, last_used_at=excluded.last_used_at
       WHERE connection.dry_run=1`,
      [
        randomUUID(), owner.enterpriseId ?? null, owner.teamId, owner.kind, owner.id, provider,
        prepared.accessEnc, prepared.refreshEnc,
        t.scopes, t.expiresAt, t.externalAccount, prepared.now, prepared.now, prepared.now,
      ],
    );
    if (changes === 0) return false;
    await this.clearSatellites(tx, owner, provider);
    await afterWrite?.(tx);
    return true;
  }

  private async writeReferenceCredential(
    tx: Db,
    owner: Owner,
    provider: string,
    r: { source: string; secretRef: string; scopes?: string; externalAccount?: string | null },
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<void> {
    this.assertNotLockedDown(); // minting a referenced credential is denied under lockdown (#239)
    const now = Date.now();
    await tx.run(
      `INSERT INTO connection
         (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
          access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
          external_account, dry_run, created_at, updated_at, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, 0, ?, ?, ?)
       ON CONFLICT(team_id, owner_kind, owner_id, provider) DO UPDATE SET
         id=excluded.id, source=excluded.source, enterprise_id=excluded.enterprise_id,
         generation_at=excluded.generation_at,
         access_token_enc=NULL, refresh_token_enc=NULL,
         secret_ref=excluded.secret_ref, scopes=excluded.scopes, expires_at=NULL,
         external_account=excluded.external_account, dry_run=0, updated_at=excluded.updated_at,
         created_at=excluded.created_at, last_used_at=excluded.last_used_at`,
      [
        randomUUID(), owner.enterpriseId ?? null, owner.teamId, owner.kind, owner.id, provider, r.source,
        r.secretRef, r.scopes ?? '', r.externalAccount ?? null, now, now, now,
      ],
    );
    await this.clearSatellites(tx, owner, provider);
    await afterWrite?.(tx);
  }

  /** Store one real user credential behind the unified offboard fence. */
  async upsertUser(
    owner: Owner,
    provider: string,
    t: StoredToken,
    issuance: UserProvisioningIssuance,
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<UserProvisioningResult> {
    const prepared = await this.sealedToken(t); // KMS/envelope work happens before either lock
    return this.withUserProvisioningFence(owner, provider, issuance, (tx) =>
      this.writeVaultCredential(tx, owner, provider, t, prepared, afterWrite));
  }

  /** Store one synthetic dry-run user credential behind the same offboard fence. */
  async upsertDryRunUser(
    owner: Owner,
    provider: string,
    t: StoredToken,
    issuance: UserProvisioningIssuance,
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<UserProvisioningResult> {
    const prepared = await this.sealedToken(t);
    let written = false;
    const fenced = await this.withUserProvisioningFence(owner, provider, issuance, async (tx) => {
      written = await this.writeDryRunCredential(tx, owner, provider, t, prepared, afterWrite);
    });
    return fenced === 'stored' && !written ? 'conflict' : fenced;
  }

  /** Store one referenced user credential behind the same offboard fence. */
  async referenceUser(
    owner: Owner,
    provider: string,
    r: { source: string; secretRef: string; scopes?: string; externalAccount?: string | null },
    issuance: UserProvisioningIssuance,
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<UserProvisioningResult> {
    return this.withUserProvisioningFence(owner, provider, issuance, (tx) =>
      this.writeReferenceCredential(tx, owner, provider, r, afterWrite));
  }

  /** Store a vaulted credential (Vouchr encrypts and owns refresh). A production write is always
   *  REAL: `dry_run=0` on insert AND on conflict, so overwriting a dry-run row re-marks it real
   *  (zero-behavior-change — production ignores dry-run provenance entirely).
   *
   *  `gate` (GHSA-25m2, callback path only): the OAuth callback already consumed its single-use
   *  state, then paused in token exchange; offboarding can write the tombstone and delete every
   *  credential during that pause. Gating the write ATOMICALLY against the tombstone — one
   *  conditional statement, under the user's offboard advisory fence acquired inside the existing
   *  credential transaction — makes the final credential write refuse to resurrect an offboarded
   *  user while also making an upsert-first offboard wait and delete the committed row. Same rule as
   *  {@link tombstoneBlocks}, expressed in SQL because it must be atomic with the INSERT. Returns
   *  true when the credential was written; false only when the gate refused it (offboarded).
   *  `afterWrite` composes trusted config/audit companions into the same transaction. */
  async upsert(
    owner: Owner,
    provider: string,
    t: StoredToken,
    gate?: { mintedAt: number },
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<boolean> {
    if (gate) return (await this.upsertUser(owner, provider, t, gate.mintedAt, afterWrite)) === 'stored';
    if (owner.kind === 'user') {
      const issuedAt = await this.userProvisioningIssuedAt();
      return (await this.upsertUser(owner, provider, t, issuedAt, afterWrite)) === 'stored';
    }
    const issuedAt = await this.userProvisioningIssuedAt();
    const prepared = await this.sealedToken(t);
    const result = await this.withChannelProvisioningFence(
      owner,
      provider,
      issuedAt,
      (tx) => this.writeVaultCredential(tx, owner, provider, t, prepared, afterWrite),
    );
    return result.status === 'written';
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
    if (owner.kind === 'user') {
      const issuedAt = await this.userProvisioningIssuedAt();
      return (await this.upsertDryRunUser(owner, provider, t, issuedAt)) === 'stored';
    }
    const issuedAt = await this.userProvisioningIssuedAt();
    const prepared = await this.sealedToken(t);
    const result = await this.withChannelProvisioningFence(
      owner,
      provider,
      issuedAt,
      (tx) => this.writeDryRunCredential(tx, owner, provider, t, prepared),
    );
    return result.status === 'written' && result.value;
  }

  /** #116: whether at-rest writes go through an external KMS envelope. Dry-run refuses one at
   *  startup (its wrap/unwrap are real network calls, breaking the offline guarantee). */
  get usesEnvelope(): boolean { return !!this.envelope; }

  /**
   * No-secret purpose-separation predicate for broker construction (#212). It exposes only equality,
   * never the master-key bytes, and checks every active/legacy key in a rotation ring.
   */
  usesMasterKeyMaterial(material: string | Buffer): boolean {
    const candidate = Buffer.isBuffer(material) ? material : Buffer.from(material, 'utf8');
    return toKeyring(this.key).legacy.some(({ key }) =>
      key.length === candidate.length && timingSafeEqual(key, candidate));
  }

  /**
   * Store a REFERENCED credential: the secret stays in an external manager (e.g. AWS
   * Secrets Manager). We persist only a non-secret `ref` + the resolver `source` id;
   * the injector resolves it just-in-time. Rotation stays external: Vouchr never holds it.
   */
  async reference(
    owner: Owner,
    provider: string,
    r: { source: string; secretRef: string; scopes?: string; externalAccount?: string | null },
    afterWrite?: (tx: Db) => Promise<void>,
  ): Promise<void> {
    if (owner.kind === 'user') {
      const issuedAt = await this.userProvisioningIssuedAt();
      const result = await this.referenceUser(owner, provider, r, issuedAt, afterWrite);
      if (result !== 'stored') throw new Error('user credential provisioning was refused');
      return;
    }
    const issuedAt = await this.userProvisioningIssuedAt();
    const result = await this.withChannelProvisioningFence(
      owner,
      provider,
      issuedAt,
      (tx) => this.writeReferenceCredential(tx, owner, provider, r, afterWrite),
    );
    if (result.status === 'revoked') throw new Error('channel credential provisioning was refused');
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
    expectedId?: string,
  ): Promise<boolean> {
    if (expectedId !== undefined && !isInteractionId(expectedId)) return false;
    this.assertNotLockedDown(); // a silent refresh write is denied under lockdown (#239)
    const accessEnc = await seal(t.accessToken, this.key, this.envelope);
    const refreshEnc = t.refreshToken ? await seal(t.refreshToken, this.key, this.envelope) : null;
    const result = await this.db.run(
      `UPDATE connection SET access_token_enc=?, refresh_token_enc=?, scopes=?, expires_at=?, updated_at=?
       WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=? AND source='vault'${expectedId !== undefined ? ' AND id=?' : ''}`,
      [
        accessEnc, refreshEnc,
        t.scopes, t.expiresAt, Date.now(),
        owner.teamId, owner.kind, owner.id, provider,
        ...(expectedId !== undefined ? [expectedId] : []),
      ],
    );
    return result.changes === 1;
  }

  /** True when the backend coordinates refresh across processes (Postgres advisory lock). */
  get crossProcessRefresh(): boolean { return !!this.db.withRefreshLock; }

  /**
   * Serialize one credential's lifecycle across replicas and run `fn` in the same transaction as
   * the advisory lock. Channel mode changes and credential setup use this boundary so neither can
   * commit against a stale view of the other; refresh delegates to the same owner/provider key.
   * A transaction-bound Vault has no lock method and simply reuses its current transaction.
   */
  async withCredentialLock<T>(
    owner: Owner,
    provider: string,
    fn: (locked: Vault, tx: Db) => Promise<T>,
  ): Promise<T> {
    return this.withCredentialLocks([{ owner, provider }], fn);
  }

  /** Serialize several credential/governance keys in canonical order inside one transaction. The
   *  owner/provider → advisory-key representation lives only here (STR-2); callers supply typed
   *  scopes and cannot accidentally choose a lock that disagrees with refresh/mode writers. */
  async withCredentialLocks<T>(
    scopes: readonly { owner: Owner; provider: string }[],
    fn: (locked: Vault, tx: Db) => Promise<T>,
  ): Promise<T> {
    const run = (tx: Db) => {
      const locked = new Vault(tx, this.key, this.ttl, this.envelope, this.lockdown);
      locked.credentialLockHeld = true;
      return fn(locked, tx);
    };
    const keys = scopes.map(({ owner, provider }) => credentialLockKey(owner, provider));
    if (this.db.withRefreshLocks) return this.db.withRefreshLocks(keys, run);
    if (keys.length === 1 && this.db.withRefreshLock) return this.db.withRefreshLock(keys[0], run);
    return this.mutation(run);
  }

  /**
   * Run `fn` while holding the cross-process refresh lock for (owner, provider), with the vault
   * rebound to the locked transaction so `fn`'s reads/writes (get/updateTokens) see the same tx.
   * A Db without `withRefreshLock` (a tx-bound client already inside a transaction) is a passthrough
   * that runs `fn(this)` — the injector's in-process single-flight map already serializes a single
   * process. Key matches the injector's inflight key so in-process and cross-process coordination
   * agree on identity.
   */
  async withRefreshLock<T>(owner: Owner, provider: string, fn: (locked: Vault) => Promise<T>): Promise<T> {
    return this.withCredentialLock(owner, provider, (locked) => fn(locked));
  }

  /** Mark a connection as used now (resets the idle timer). Called after each injection. */
  async touch(owner: Owner, provider: string, expectedId?: string): Promise<void> {
    if (expectedId !== undefined && !isInteractionId(expectedId)) return;
    await this.db.run(
      `UPDATE connection SET last_used_at=? WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?${expectedId !== undefined ? ' AND id=?' : ''}`,
      [Date.now(), owner.teamId, owner.kind, owner.id, provider, ...(expectedId !== undefined ? [expectedId] : [])],
    );
  }

  /** A user's OWN connections (for status and Vouchr-owned controls). Never lists channel-owned
   * credentials. Metadata-only and TTL-independent: expired-here rows remain disconnectable.
   * Built-in interactive renderers request the additive opaque generation; the default return
   * shape remains unchanged for existing callers. */
  async listForUser(
    i: SlackIdentity,
  ): Promise<{ provider: string; externalAccount: string | null }[]>;
  async listForUser(
    i: SlackIdentity,
    withGeneration: true,
  ): Promise<{ credentialId: string; provider: string; externalAccount: string | null }[]>;
  async listForUser(
    i: SlackIdentity,
    withGeneration = false,
  ): Promise<
    | { provider: string; externalAccount: string | null }[]
    | { credentialId: string; provider: string; externalAccount: string | null }[]
  > {
    const rows = (await this.db.all(
      `SELECT id, provider, external_account FROM connection
       WHERE team_id=? AND owner_kind='user' AND owner_id=?`,
      [i.teamId, i.userId],
    )) as any[];
    return rows.map((r) => ({
      ...(withGeneration ? { credentialId: r.id } : {}),
      provider: r.provider,
      externalAccount: r.external_account,
    })) as
      | { provider: string; externalAccount: string | null }[]
      | { credentialId: string; provider: string; externalAccount: string | null }[];
  }

  /** Resolve one opaque generation only when it belongs to the verified acting user. This is a
   * metadata read, not authority: the destructive mutation repeats owner + generation validation
   * under its lifecycle locks. */
  async providerForUserGeneration(i: SlackIdentity, credentialId: unknown): Promise<string | null> {
    if (!isInteractionId(credentialId)) return null;
    const row = await this.db.get<{ provider: string }>(
      `SELECT provider FROM connection
       WHERE id=? AND team_id=? AND owner_kind='user' AND owner_id=?`,
      [credentialId, i.teamId, i.userId],
    );
    return typeof row?.provider === 'string' ? row.provider : null;
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

  /** The ONE SQL form of isExpired() at time `now`, shared by listExpired and deleteExpired
   *  (STR-2 — list/delete semantics must not drift): idle uses last_used_at (falling back to
   *  created_at), max-age uses created_at; an empty policy yields no clauses (nothing expires). */
  private expiredPredicate(now: number): { clauses: string[]; params: any[] } {
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
    return { clauses, params };
  }

  /**
   * Every connection currently past its TTL (for the periodic sweep). Filters in SQL
   * (only expired rows cross the wire) rather than scanning the whole table in memory.
   */
  private async listExpiredOn(db: Db): Promise<{ owner: Owner; provider: string }[]> {
    const { clauses, params } = this.expiredPredicate(Date.now());
    if (!clauses.length) return []; // empty policy → nothing expires
    const rows = (await db.all(
      `SELECT team_id, owner_kind, owner_id, provider FROM connection WHERE ${clauses.join(' OR ')}`,
      params,
    )) as any[];
    return rows.map((r) => ({
      owner: { teamId: r.team_id, kind: r.owner_kind, id: r.owner_id } as Owner,
      provider: r.provider,
    }));
  }

  async listExpired(): Promise<{ owner: Owner; provider: string }[]> {
    return this.listExpiredOn(this.db);
  }

  /**
   * Atomic, self-guarding expiry delete (#192): removes the row ONLY if it is still past its TTL
   * at delete time, so a reconnect that lands between the sweep's listExpired() snapshot and this
   * call survives — the conditional DELETE re-evaluates the same predicate the snapshot used (one
   * source of truth, expiredPredicate). Returns whether a still-expired row was actually deleted;
   * satellites are purged (and the caller audits/notifies) only in that case, so a fresh
   * reconnect's notification state and grants are never clobbered by a stale sweep.
   */
  private async deleteExpiredOn(db: Db, owner: Owner, provider: string): Promise<boolean> {
    const { clauses, params } = this.expiredPredicate(Date.now());
    if (!clauses.length) return false; // empty policy → nothing expires
    const { changes } = await db.run(
      `DELETE FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=? AND (${clauses.join(' OR ')})`,
      [owner.teamId, owner.kind, owner.id, provider, ...params],
    );
    if (changes > 0) await this.clearSatellites(db, owner, provider);
    return changes > 0;
  }

  async deleteExpired(owner: Owner, provider: string): Promise<boolean> {
    return this.withCredentialLock(
      owner,
      provider,
      async (_locked, tx) => this.deleteExpiredOn(tx, owner, provider),
    );
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
  private async listExpiringSoonOn(
    withinMs: number,
    db: Db,
  ): Promise<{ owner: Owner; provider: string; expiresAt: number }[]> {
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
    const rows = (await db.all(
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

  async listExpiringSoon(withinMs: number): Promise<{ owner: Owner; provider: string; expiresAt: number }[]> {
    return this.listExpiringSoonOn(withinMs, this.db);
  }

  /** Bind expiry primitives to the lifecycle coordinator's already table-locked transaction. The
   * unexported symbol keeps the no-advisory-lock path off the public Vault instance API. */
  [BIND_VAULT_EXPIRY_TRANSACTION](transaction: Db): VaultExpiryTransaction {
    return {
      listExpired: () => this.listExpiredOn(transaction),
      deleteExpired: (owner, provider) => this.deleteExpiredOn(transaction, owner, provider),
      listExpiringSoon: (withinMs) => this.listExpiringSoonOn(withinMs, transaction),
    };
  }

  /**
   * Returns whether a row was atomically claimed, so callers derive a truthful `removed` from the
   * delete itself — not from whether the token happened to be readable/unexpired (GHSA-25m2).
   *
   * Satellite handling differs from the WRITE paths (upsert/reference, where a satellite-purge
   * failure correctly rolls the whole write back — no new credential lands without its satellites
   * cleared). Here the delete+purge run in ONE transaction on the happy path — atomic, so a purge
   * can never touch a NEWER credential generation written after the delete commits. On failure the
   * two modes are told apart (GHSA-25m2 review): if the DELETE statement itself never ran the
   * credential is genuinely stranded, so the error PROPAGATES (offboardUser reports the offboarding
   * incomplete, never as success); if only the satellite purge failed after a successful DELETE the
   * credential delete is re-run alone, guarded to the same row generation. A generation mismatch is
   * surfaced for retry instead of deleting a concurrent reconnect. A missed purge after a successful
   * fallback is fail-closed anyway: a grant without its connection cannot reach a secret (consume
   * precedes the vault read, which then throws NoConnectionError), a reconnect purges satellites
   * inside upsert/reference BEFORE the new credential is usable, and the TTL sweep reclaims expired
   * rows.
   */
  async delete(owner: Owner, provider: string): Promise<boolean> {
    const { row, fenced, fenceError } = await this.claimDeleteFenced(owner, provider);
    if (!fenced) {
      throw fenceError instanceof Error
        ? fenceError
        : new Error('credential provisioning fence could not be confirmed; retry');
    }
    return row != null;
  }
}

/** @internal Prepare a vaulted token without holding credential/revocation/offboard locks. This
 * module export is intentionally not re-exported by the package entry points. */
export function prepareVaultCredentialWrite(
  vault: Vault,
  token: StoredToken,
): Promise<PreparedVaultCredentialWrite> {
  return vault[PREPARE_VAULT_CREDENTIAL_WRITE](token);
}

/** @internal Bind expiry operations to the lifecycle coordinator's table-locked transaction. This
 * module export is intentionally not re-exported by the package entry points. */
export function bindVaultExpiryTransaction(vault: Vault, transaction: Db): VaultExpiryTransaction {
  return vault[BIND_VAULT_EXPIRY_TRANSACTION](transaction);
}
