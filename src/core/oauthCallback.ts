import type { ProviderRegistry } from './providers';
import type { Vault } from './vault';
import type { Audit } from './audit';
import type { Consent } from './consent';
import type { SlackIdentity } from './identity';
import { userOwner } from './owner';
import { exchangeCode } from './tokens';

export interface CallbackDeps {
  registry: ProviderRegistry;
  vault: Vault;
  audit: Audit;
  consent: Consent;
  redirectUri: string;
}

export type CallbackResult =
  | { ok: true; provider: string; account: string | null; identity: SlackIdentity }
  | { ok: false; status: number; error: string };

/**
 * Shared OAuth callback handling: consume the single-use state, exchange the code,
 * probe the account label, and store the encrypted token. Used by every adapter so
 * the security-critical exchange path lives in exactly one place.
 */
export async function handleOAuthCallback(
  deps: CallbackDeps,
  code: string | undefined,
  state: string | undefined,
  error?: string,
): Promise<CallbackResult> {
  if (error) return { ok: false, status: 400, error: `OAuth error: ${error}` };
  if (!code || !state) return { ok: false, status: 400, error: 'Missing code/state.' };

  const row = await deps.consent.consume(state);
  if (!row) return { ok: false, status: 400, error: 'Invalid or expired state. Please retry.' };

  const provider = deps.registry.get(row.provider);
  try {
    const tok = await exchangeCode(provider, code, deps.redirectUri, row.pkceVerifier);
    const account = provider.accountProbe
      ? await provider.accountProbe(tok.accessToken).catch(() => null)
      : null;
    await deps.vault.upsert(userOwner(row.identity), provider.id, {
      accessToken: tok.accessToken,
      refreshToken: tok.refreshToken,
      scopes: tok.scopes ?? provider.scopesDefault.join(' '),
      expiresAt: tok.expiresAt,
      externalAccount: account,
    });
    await deps.audit.record('connect', row.identity, provider.id, { account });
    return { ok: true, provider: provider.id, account, identity: row.identity };
  } catch (e: any) {
    return { ok: false, status: 500, error: `Connection failed: ${e.message}` };
  }
}
