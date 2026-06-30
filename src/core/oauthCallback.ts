import { randomUUID } from 'node:crypto';
import type { ProviderRegistry } from './providers';
import type { Vault } from './vault';
import type { Audit, AuditSink, VouchrAuditEvent } from './audit';
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
  /** Optional audit STREAM sink (raw actor id). No-op when unset; the audit table is authoritative. */
  auditSink?: AuditSink;
}

/** Emit a consent_granted/denied audit-stream copy. Best-effort; a throwing sink never breaks the callback. */
function emitConsent(
  deps: CallbackDeps,
  identity: SlackIdentity,
  provider: string,
  egressHost: string,
  action: 'consent_granted' | 'consent_denied',
  status: number,
): void {
  const e: VouchrAuditEvent = {
    ts: new Date().toISOString(),
    teamId: identity.teamId,
    userId: identity.userId, // raw actor id, never a token
    provider,
    ownerKind: 'user', // consent always establishes a user-owned credential
    ownerId: identity.userId,
    action,
    egressHost,
    status,
    jti: randomUUID(),
  };
  try {
    deps.auditSink?.(e);
  } catch {
    // ignore: best-effort, never fatal
  }
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
    emitConsent(deps, row.identity, provider.id, new URL(provider.tokenUrl).hostname, 'consent_granted', 200);
    return { ok: true, provider: provider.id, account, identity: row.identity };
  } catch {
    emitConsent(deps, row.identity, provider.id, new URL(provider.tokenUrl).hostname, 'consent_denied', 500);
    return { ok: false, status: 500, error: 'Connection failed. Please try again.' };
  }
}
