import { bindVaultExpiryTransaction, type Vault } from './vault';
import type { Audit } from './audit';
import { Consent } from './consent';
import type { Db } from './db';
import type { EventSink, VouchrEvent } from './injector';
import type { CredentialHealthEvent, CredentialHealthHook } from './health';
import { approvalActionFingerprint, Approvals } from './approval';
import { SessionGrants } from './session';
import { ChannelProvisioningRequests, UserProvisioningRequests } from './provisioning';
import { assertDryRunVault } from './dryRun';
import { safeEmit } from './safe-emit';

/** #117: warn this far ahead of a connection's TTL ceiling (idle/max-age). */
const EXPIRING_SOON_WINDOW_MS = 72 * 60 * 60 * 1000;

/**
 * Proactively delete every connection past its TTL (auditing each), and clear
 * abandoned consent requests. Run on an interval (and once at startup). Lazy
 * get()-time expiry already prevents *use* of an expired connection; this reclaims
 * idle rows that would otherwise linger forever because nobody touches them again.
 * Returns the number of connections swept.
 */
async function sweepExpiredOn(vault: Vault, audit: Audit, consent: Consent, sink?: EventSink,
  // Optional (#117): credential-health hook. Fires 'expired' per deleted connection (after the
  // delete) and 'expiring_soon' for every connection within 72h of its TTL ceiling. NOT debounced
  // here — it re-fires each sweep pass; notifiers debounce (see NotificationState / the Bolt
  // default wiring). safeEmit: a throwing hook never breaks the sweep.
  health?: CredentialHealthHook,
  // Optional (#113): reclaim expired approval prompts/grants on the same timer. Each expiry is
  // audited (acceptance: deny AND expiry paths are audited) as a 'denied' row attributed to the
  // requesting user, with the non-human sweeper as the actor — the same actor pattern as the
  // channel-owned expiry above (STR-4).
  approvals?: Approvals,
  transaction?: Db,
): Promise<number> {
  let swept = 0;
  // The no-advisory-lock path is available only through this module-internal capability. Public
  // Vault callers retain the credential-locked methods and cannot pass an arbitrary Db handle.
  const expiry = transaction ? bindVaultExpiryTransaction(vault, transaction) : vault;
  for (const { owner, provider } of await expiry.listExpired()) {
    // Conditional delete (#192): a reconnect that landed after the snapshot above makes this row
    // live again — deleteExpired re-checks the TTL atomically, and a fresh credential must not be
    // deleted, audited, or notified as 'expired'.
    if (!(await expiry.deleteExpired(owner, provider))) continue;
    swept++;
    // Audit as the owner. A channel has no acting human → user_id=channel id, actor='system'.
    const id = { enterpriseId: null, teamId: owner.teamId, userId: owner.id };
    await audit.record('revoke', id, provider, { reason: 'expired', owner_kind: owner.kind },
      owner.kind === 'channel' ? 'system' : undefined, transaction);
    safeEmit(health, { type: 'expired', owner, provider }); // after the delete actually happened
  }
  // Warn AFTER the delete pass (the two sets are disjoint: listExpiringSoon excludes expired rows).
  for (const { owner, provider, expiresAt } of await expiry.listExpiringSoon(EXPIRING_SOON_WINDOW_MS)) {
    safeEmit(health, { type: 'expiring_soon', owner, provider, expiresAt });
  }
  await consent.sweepStale();
  // #113: expired approval prompts and unspent grants. Meta mirrors the injector's approval rows
  // (method + hostname + salted action fingerprint, never a raw path, body, or query value — SEC-1),
  // reason names the expiry.
  if (approvals) {
    for (const row of await approvals.sweepExpired()) {
      const id = { enterpriseId: null, teamId: row.teamId, userId: row.userId };
      const channelMeta = row.channel ? { channel: row.channel } : {};
      await audit.record('denied', id, row.provider,
        {
          host: row.host,
          method: row.method,
          actionFingerprint: approvalActionFingerprint(row),
          reason: 'approval-expired',
          ...channelMeta,
        }, 'system', transaction);
    }
  }
  // No-secret observability: just the count — of rows actually deleted, not merely snapshotted.
  safeEmit(sink, { type: 'expired', count: swept });
  return swept;
}

/** Backward-compatible low-level sweep. Broker/Bolt deployments use the complete internal
 * coordinator below; this export remains for callers that intentionally own their stores. */
export function sweepExpired(
  vault: Vault,
  audit: Audit,
  consent: Consent,
  sink?: EventSink,
  health?: CredentialHealthHook,
  approvals?: Approvals,
): Promise<number> {
  return sweepExpiredOn(vault, audit, consent, sink, health, approvals);
}

export interface LifecycleSweepOptions {
  db: Db;
  vault: Vault;
  audit: Audit;
  sink?: EventSink;
  health?: CredentialHealthHook;
  dryRun?: boolean;
}

/**
 * One internal owner for the complete lifecycle-store list. Bolt and headless adapters delegate
 * here so adding a new bounded interaction family cannot silently leave one deployment shape
 * without cleanup. Only adapters expose safe facade methods; authority-bearing stores stay private.
 *
 * Dry-run takes a stronger path: lock every swept table, revalidate the trusted connection
 * provenance inside that transaction, and commit all cleanup atomically. A writer that already
 * holds a conflicting table makes the sweep fail for retry; a writer arriving after the lock blocks
 * until the clean snapshot commits. The sweep can never delete or relabel unchecked real state.
 */
export async function sweepLifecycle({
  db,
  vault,
  audit,
  sink,
  health,
  dryRun = false,
}: LifecycleSweepOptions): Promise<number> {
  const run = async (
    storeDb: Db,
    transaction?: Db,
    eventSink: EventSink | undefined = sink,
    healthHook: CredentialHealthHook | undefined = health,
  ): Promise<number> => {
    const count = await sweepExpiredOn(
      vault,
      audit,
      new Consent(storeDb, dryRun),
      eventSink,
      healthHook,
      new Approvals(storeDb),
      transaction,
    );
    await new SessionGrants(storeDb).sweepExpired();
    await new UserProvisioningRequests(storeDb, vault).sweepExpired();
    await new ChannelProvisioningRequests(storeDb, vault).sweepExpired();
    return count;
  };

  if (!dryRun) {
    // Preserve the established production behavior: each hook follows the specific committed
    // credential mutation it describes, even if a later independent interaction-family sweep fails.
    return run(db);
  }

  if (!db.transaction) throw new Error('dry-run lifecycle sweep requires database transaction support');
  const events: VouchrEvent[] = [];
  const healthEvents: CredentialHealthEvent[] = [];
  const captureEvents: EventSink = (event) => { events.push(event); };
  const captureHealth: CredentialHealthHook = (event) => { healthEvents.push(event); };
  const count = await db.transaction(async (tx) => {
    // Acquire the write-capable mode up front: plain SHARE would let two sweepers enter together,
    // then deadlock when both upgrade for DELETE. NOWAIT is equally load-bearing because ordinary
    // interaction flows do not all acquire these tables in one canonical order; if a writer already
    // owns any later table, fail/retry without waiting while holding a partial lock prefix.
    // Once acquired, the locks exclude every writer until provenance validation and cleanup commit.
    await tx.exec(
      `LOCK TABLE connection, consent_request, approval_request, session_request, session_grant,
        user_provisioning_request, channel_provisioning_request, channel_interaction_tombstone
        IN SHARE ROW EXCLUSIVE MODE NOWAIT`,
    );
    await assertDryRunVault(tx);
    return run(tx, tx, captureEvents, captureHealth);
  });
  // Dry-run hooks fire only after the complete table-locked transaction commits. A later store
  // failure rolls every cleanup back without publishing a deletion that did not persist.
  for (const event of healthEvents) safeEmit(health, event);
  for (const event of events) safeEmit(sink, event);
  return count;
}
