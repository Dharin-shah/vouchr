import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { EventSink } from './injector';

/**
 * Proactively delete every connection past its TTL (auditing each), and clear
 * abandoned consent requests. Run on an interval (and once at startup). Lazy
 * get()-time expiry already prevents *use* of an expired connection; this reclaims
 * idle rows that would otherwise linger forever because nobody touches them again.
 * Returns the number of connections swept.
 */
export async function sweepExpired(vault: Vault, audit: Audit, consent: Consent, sink?: EventSink): Promise<number> {
  const expired = await vault.listExpired();
  for (const { owner, provider } of expired) {
    await vault.delete(owner, provider);
    // Audit as the owner. A channel has no acting human → user_id=channel id, actor='system'.
    const id = { enterpriseId: null, teamId: owner.teamId, userId: owner.id };
    await audit.record('revoke', id, provider, { reason: 'expired', owner_kind: owner.kind },
      owner.kind === 'channel' ? 'system' : undefined);
  }
  await consent.sweepStale();
  // No-secret observability: just the count. Best-effort, a bad sink must never break the sweep.
  if (sink) try { sink({ type: 'expired', count: expired.length }); } catch { /* ignore */ }
  return expired.length;
}
