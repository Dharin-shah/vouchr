import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { EventSink } from './injector';
import type { UnionOptin } from './unionOptin';
import type { CredentialHealthHook } from './health';
import type { Approvals } from './approval';
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
export async function sweepExpired(vault: Vault, audit: Audit, consent: Consent, sink?: EventSink,
  // Optional (#112): a swept user credential also drops that user's union opt-ins for the provider —
  // delegation must not outlive the credential (a later reconnect must re-opt-in).
  unionOptin?: UnionOptin,
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
): Promise<number> {
  const expired = await vault.listExpired();
  for (const { owner, provider } of expired) {
    await vault.delete(owner, provider);
    if (owner.kind === 'user') await unionOptin?.deleteForUserProvider(owner.teamId, owner.id, provider);
    // Audit as the owner. A channel has no acting human → user_id=channel id, actor='system'.
    const id = { enterpriseId: null, teamId: owner.teamId, userId: owner.id };
    await audit.record('revoke', id, provider, { reason: 'expired', owner_kind: owner.kind },
      owner.kind === 'channel' ? 'system' : undefined);
    safeEmit(health, { type: 'expired', owner, provider }); // after the delete actually happened
  }
  // Warn AFTER the delete pass (the two sets are disjoint: listExpiringSoon excludes expired rows).
  for (const { owner, provider, expiresAt } of await vault.listExpiringSoon(EXPIRING_SOON_WINDOW_MS)) {
    safeEmit(health, { type: 'expiring_soon', owner, provider, expiresAt });
  }
  await consent.sweepStale();
  // #113: expired approval prompts and unspent grants. Meta mirrors the injector's approval rows
  // (method + hostname + pathname, never a body or query value — SEC-1), reason names the expiry.
  if (approvals) {
    for (const row of await approvals.sweepExpired()) {
      const id = { enterpriseId: null, teamId: row.teamId, userId: row.userId };
      const channelMeta = row.channel ? { channel: row.channel } : {};
      await audit.record('denied', id, row.provider,
        { host: row.host, method: row.method, path: row.path, reason: 'approval-expired', ...channelMeta }, 'system');
    }
  }
  // No-secret observability: just the count. Best-effort, a bad sink must never break the sweep.
  safeEmit(sink, { type: 'expired', count: expired.length });
  return expired.length;
}
