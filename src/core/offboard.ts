import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { SlackIdentity } from './identity';
import { userOwner } from './owner';

/**
 * Remove ALL of a user's own connections — the offboarding cleanup. Triggered
 * automatically when Slack deactivates the account (see the Bolt adapter's
 * registerOffboarding), and callable from a SCIM deprovision hook or an admin.
 *
 * Also purges any in-flight consent for the user, so a pending "Connect" click
 * can't complete after offboarding and resurrect a live connection.
 *
 * Only the user's own connections are removed. Channel/shared connections belong
 * to the channel, not the person, so they are intentionally left in place and
 * reviewed separately by an admin. Idempotent. Returns the providers removed.
 */
export async function offboardUser(
  vault: Vault,
  audit: Audit,
  consent: Consent,
  identity: SlackIdentity,
  reason = 'offboarded',
): Promise<string[]> {
  await consent.deleteForUser(identity); // kill pending OAuth so it can't resurrect a connection
  const providers = (await vault.listForUser(identity)).map((c) => c.provider); // user-owned only
  for (const provider of providers) {
    await vault.delete(userOwner(identity), provider);
    await audit.record('revoke', identity, provider, { reason });
  }
  return providers;
  // Note: local delete stops the agent acting as this user immediately, which is the
  // security-meaningful action. Best-effort upstream revocation (provider.revokeUrl) is a
  // separate follow-up, not faked here.
}
