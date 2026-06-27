import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { SlackIdentity } from './identity';
import type { ProviderRegistry } from './providers';
import { revokeToken } from './tokens';
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
  // Optional: when supplied, also revoke each token upstream (best-effort). Omitted callers
  // keep the prior local-only behavior.
  registry?: ProviderRegistry,
  reason = 'offboarded',
): Promise<string[]> {
  await consent.deleteForUser(identity); // kill pending OAuth so it can't resurrect a connection
  const owner = userOwner(identity);
  const providers = (await vault.listForUser(identity)).map((c) => c.provider); // user-owned only
  for (const provider of providers) {
    // Read the token BEFORE deleting so we can hand it to the upstream revoke.
    const cred = registry?.has(provider) ? await vault.get(owner, provider) : null;
    await vault.delete(owner, provider); // local delete FIRST — the security-meaningful action
    // Best-effort upstream revocation: swallow per-connection errors so offboarding always completes.
    const meta: Record<string, unknown> = { reason };
    if (registry) {
      let ok = true;
      try {
        if (cred?.accessToken) await revokeToken(registry.get(provider), cred.accessToken);
      } catch {
        ok = false; // network/HTTP failure — local access is already gone; nothing is faked
      }
      meta.ok = ok; // never the token, just whether the upstream call succeeded
    }
    await audit.record('revoke', identity, provider, meta);
  }
  return providers;
}
