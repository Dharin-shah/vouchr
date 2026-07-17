import { randomUUID } from 'node:crypto';
import { normalizeAccountLabel, type ProviderRegistry } from './providers';
import type { Vault } from './vault';
import type { Audit, AuditSink, VouchrAuditEvent } from './audit';
import type { Consent } from './consent';
import type { SlackIdentity } from './identity';
import { userOwner } from './owner';
import { exchangeCode, normalizeGrantedScopes, type TokenResponse } from './tokens';
import { DRY_RUN_ACCOUNT, DRY_RUN_CODE, DryRunVaultError, dryRunTokenResponse } from './dryRun';
import { safeEmit } from './safe-emit';
import type { Db } from './db';
import { mapSafeError, type VouchrRecovery } from './errors';

export interface CallbackDeps {
  registry: ProviderRegistry;
  vault: Vault;
  audit: Audit;
  consent: Consent;
  redirectUri: string;
  /** Optional audit STREAM sink (raw actor id). No-op when unset; the audit table is authoritative. */
  auditSink?: AuditSink;
  /** #116 dry-run: replace the token-exchange network edge with a synthetic credential (marked
   *  `external_account: 'dry-run'`). State consumption, vault write, and audit around it run for
   *  real. Default false: unchanged behavior. */
  dryRun?: boolean;
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
  safeEmit(deps.auditSink, e);
}

export type OAuthCallbackOutcome =
  | 'connected'
  | 'denied'
  | 'incomplete'
  | 'state_unavailable'
  | 'state_expired'
  | 'state_stale'
  | 'exchange_failed'
  | 'setup_changed';
export type AttributedOAuthCallbackOutcome = Exclude<
  OAuthCallbackOutcome,
  'connected' | 'state_unavailable'
>;

interface CallbackContext {
  identity: SlackIdentity;
  provider: string;
}

export type CallbackResult =
  | {
      ok: true;
      outcome: 'connected';
      status: 200;
      provider: string;
      account: string | null;
      scopes: string;
      identity: SlackIdentity;
    }
  | {
      ok: false;
      outcome: 'state_unavailable';
      status: 400;
      error: string;
      retryable: false;
      recovery: 'connect';
    }
  | {
      ok: false;
      outcome: AttributedOAuthCallbackOutcome;
      status: number;
      error: string;
      retryable: false;
      recovery: VouchrRecovery;
      context: CallbackContext;
    };

function unavailable(error: string): CallbackResult {
  return {
    ok: false,
    outcome: 'state_unavailable',
    status: 400,
    error,
    retryable: false,
    recovery: 'connect',
  };
}

function attributedFailure(
  outcome: AttributedOAuthCallbackOutcome,
  status: number,
  error: string,
  recovery: VouchrRecovery,
  context: CallbackContext,
): CallbackResult {
  return { ok: false, outcome, status, error, retryable: false, recovery, context };
}

async function recordDenied(
  deps: CallbackDeps,
  identity: SlackIdentity,
  provider: string,
  reason: 'consent_denied' | 'consent_incomplete' | 'offboarded' | 'revoked',
): Promise<boolean> {
  try {
    await deps.audit.record('denied', identity, provider, { reason });
    return true;
  } catch {
    return false;
  }
}

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
  signal?: AbortSignal,
): Promise<CallbackResult> {
  // State is required even on the error path: without it there's no identity to attribute the denial
  // to. Consuming it on a denial is correct — state is single-use, so this also prevents replay.
  if (!state) return unavailable('Missing code/state.');

  const claim = await deps.consent.consume(state);
  if (claim.status === 'unavailable') {
    return unavailable('Invalid or expired state. Please retry.');
  }
  const row = claim.row;
  const context = { identity: row.identity, provider: row.provider };
  if (claim.status === 'expired') {
    return attributedFailure(
      'state_expired',
      400,
      'This connection request expired. Ask the agent for a new connection prompt.',
      'connect',
      context,
    );
  }
  if (claim.status === 'superseded') {
    return attributedFailure(
      'state_stale',
      409,
      'This connection request is no longer current. Use the newest prompt or ask the agent again.',
      'connect',
      context,
    );
  }
  if (claim.status === 'invalidated') {
    return attributedFailure(
      'setup_changed',
      claim.reason === 'offboarded' ? 403 : 409,
      claim.reason === 'offboarded'
        ? 'This account is no longer active. Reconnect is unavailable.'
        : 'Connection setup changed while authorization was completing. Start a new connection request.',
      claim.reason === 'offboarded' ? 'contact_admin' : 'connect',
      context,
    );
  }
  if (!deps.registry.has(row.provider)) {
    return attributedFailure(
      'state_stale',
      409,
      'This connection request is no longer current. Ask the agent to resolve the provider again.',
      'resolve_again',
      context,
    );
  }

  const provider = deps.registry.get(row.provider);
  // A user denial is exactly `error=access_denied` (RFC 6749 §4.1.2.1). Every other redirect error
  // (`server_error`, `temporarily_unavailable`, `invalid_scope`, or anything unrecognized) is a
  // provider-side failure the user never decided — classifying it as a denial would DM a false
  // "you haven't allowed this" claim. Both branches treat the provider-controlled query value as a
  // branch signal only: never reflected into the browser, Slack, logs, or audit output (SEC-4).
  // Denial stays outside the exchange catch so audit trouble cannot rewrite it as `exchange_failed`.
  if (error === 'access_denied') {
    const recorded = await recordDenied(deps, row.identity, provider.id, 'consent_denied');
    emitConsent(
      deps,
      row.identity,
      provider.id,
      new URL(provider.tokenUrl).hostname,
      'consent_denied',
      recorded ? 400 : 500,
    );
    return attributedFailure(
      'denied',
      recorded ? 400 : 500,
      recorded
        ? 'OAuth authorization was denied. Please try again.'
        : 'OAuth authorization was denied, but Vouchr could not record the outcome. Contact an administrator.',
      recorded ? 'connect' : 'contact_admin',
      context,
    );
  }
  if (error !== undefined) {
    try {
      await deps.audit.record('denied', row.identity, provider.id, { reason: 'exchange_failed' });
    } catch { /* audit store unavailable; return the fixed failure below */ }
    emitConsent(deps, row.identity, provider.id, new URL(provider.tokenUrl).hostname, 'consent_denied', 502);
    return attributedFailure(
      'exchange_failed',
      502,
      'The provider could not complete authorization. Wait a moment, then ask the agent for a new connection prompt.',
      'retry_later',
      context,
    );
  }
  if (!code) {
    const recorded = await recordDenied(deps, row.identity, provider.id, 'consent_incomplete');
    emitConsent(
      deps,
      row.identity,
      provider.id,
      new URL(provider.tokenUrl).hostname,
      'consent_denied',
      recorded ? 400 : 500,
    );
    return attributedFailure(
      'incomplete',
      recorded ? 400 : 500,
      recorded
        ? 'Connection authorization did not complete. Ask the agent for a new connection prompt.'
        : 'Connection authorization did not complete, and Vouchr could not record the outcome. Contact an administrator.',
      recorded ? 'connect' : 'contact_admin',
      context,
    );
  }
  try {
    // #116 dry-run: the token-exchange edge. The single-use state was already consumed by the real
    // machinery above; only the provider round-trips (code exchange + account probe) are replaced —
    // with a random token and the canonical 'dry-run' account marker.
    let tok: TokenResponse;
    let account: string | null;
    if (deps.dryRun) {
      // Code-provenance rail: a code the local stub didn't mint is a REAL provider redirect — refuse
      // it loudly rather than silently swallowing a real authorization into a synthetic row. Throws
      // into the catch below: audited 'denied', nothing written.
      if (code !== DRY_RUN_CODE) throw new DryRunVaultError();
      tok = dryRunTokenResponse();
      account = DRY_RUN_ACCOUNT;
    } else {
      tok = await exchangeCode(provider, code, deps.redirectUri, row.pkceVerifier, signal);
      const probed = provider.accountProbe
        ? await provider.accountProbe(tok.accessToken, signal).catch((probeError) => {
            if (signal?.aborted) throw probeError;
            return null;
          })
        : null;
      // Provider hooks are JavaScript extension points: their TypeScript return type is not a runtime
      // boundary. Normalize before BOTH persistence and the connect audit row so objects, control text,
      // whitespace-only, and overlong labels cannot become stored/audited external values (SEC-4).
      const normalized = normalizeAccountLabel(probed);
      // A buggy/malicious hook sees the access token and could return it as the cosmetic account
      // label, which is persisted, audited, and rendered. Drop labels containing any credential or
      // one-time flow secret already known at this boundary; a missing label is always safer than a
      // secret copied into output (SEC-1).
      const sensitive = [
        tok.accessToken,
        tok.refreshToken,
        provider.clientSecret,
        code,
        state,
        row.pkceVerifier,
      ].filter((value): value is string => typeof value === 'string' && value.length > 0);
      account = normalized && sensitive.some((value) => normalized.includes(value)) ? null : normalized;
    }
    // A custom one-argument probe may ignore the optional signal. Recheck at the mutation boundary so
    // a callback cancelled during that hook cannot persist or audit a newly connected credential.
    signal?.throwIfAborted();
    // The scopes actually granted (token response), falling back to what we requested if the provider
    // doesn't echo a canonical, bounded, non-secret value — this is what the post-connect
    // confirmation shows the user. Re-normalize through the ONE helper with callback-only secrets
    // (`state` is never sent to the token endpoint).
    const scopes = normalizeGrantedScopes(tok.scopes, [
      tok.accessToken,
      tok.refreshToken,
      provider.clientSecret,
      code,
      state,
      row.pkceVerifier,
    ]) ?? provider.scopesDefault.join(' ');
    const token = { accessToken: tok.accessToken, refreshToken: tok.refreshToken, scopes, expiresAt: tok.expiresAt, externalAccount: account };
    const owner = userOwner(row.identity);
    const recordConnect = (tx: Db) =>
      deps.audit.record('connect', row.identity, provider.id, { account }, undefined, tx);
    const finalize = (tx: Db) => deps.consent.finalizeProvisioning(row, tx);
    const provisioned = deps.dryRun
      ? await deps.vault.upsertDryRunUser(owner, provider.id, token, finalize, recordConnect)
      : await deps.vault.upsertUser(owner, provider.id, token, finalize, recordConnect);
    if (deps.dryRun && provisioned === 'conflict') {
      // ATOMIC no-clobber: one conditional statement that only overwrites an existing SYNTHETIC row,
      // so a REAL credential a sibling process wrote — even between boot and now — survives untouched.
      // No get()-then-upsert, so there is no TOCTOU window. false → a real row blocked it: refuse.
      throw new DryRunVaultError();
    }
    if (provisioned === 'offboarded') {
      // GHSA-25m2: offboarding won the race between consume() and this write — it wrote the
      // tombstone and deleted every credential while we were in token exchange. The atomic gate
      // refused to resurrect the credential (nothing landed). Audit as denied; write nothing.
      const recorded = await recordDenied(deps, row.identity, provider.id, 'offboarded');
      emitConsent(
        deps,
        row.identity,
        provider.id,
        new URL(provider.tokenUrl).hostname,
        'consent_denied',
        recorded ? 403 : 500,
      );
      return attributedFailure(
        'setup_changed',
        recorded ? 403 : 500,
        recorded
          ? 'This account is no longer active. Reconnect is unavailable.'
          : 'This account is no longer active, but Vouchr could not record the outcome. Contact an administrator.',
        'contact_admin',
        context,
      );
    }
    if (provisioned === 'revoked') {
      // A confirmed break-glass revoke linearized while this already-consumed OAuth state was in
      // token exchange. This is not account deactivation and unchanged retries of the old state are
      // not useful: refuse the write and direct the user to start one genuinely new setup.
      const recorded = await recordDenied(deps, row.identity, provider.id, 'revoked');
      emitConsent(
        deps,
        row.identity,
        provider.id,
        new URL(provider.tokenUrl).hostname,
        'consent_denied',
        recorded ? 409 : 500,
      );
      return attributedFailure(
        'setup_changed',
        recorded ? 409 : 500,
        recorded
          ? 'Connection setup changed while authorization was completing. Start a new connection request.'
          : 'Connection setup changed, but Vouchr could not record the outcome. Contact an administrator.',
        recorded ? 'connect' : 'contact_admin',
        context,
      );
    }
    if (provisioned === 'stale' || provisioned === 'conflict') {
      return attributedFailure(
        'state_stale',
        409,
        'This connection request is no longer current. Use the newest prompt or ask the agent again.',
        'connect',
        context,
      );
    }
    emitConsent(deps, row.identity, provider.id, new URL(provider.tokenUrl).hostname, 'consent_granted', 200);
    return {
      ok: true,
      outcome: 'connected',
      status: 200,
      provider: provider.id,
      account,
      scopes,
      identity: row.identity,
    };
  } catch (error) {
    // Post-consent connection FAILURE (token exchange / account probe / vault write threw) — not a
    // user denial, but the closest action on the lossy stream. status 500 here is synthetic (the host
    // distinguishes the real user-denial above by its 400). See VouchrAuditEvent.status doc.
    // The credential + connect audit already rolled back together when either write failed. A
    // second audit-store failure must not escape this public boundary or turn a fixed 500 into an
    // unhandled rejection; there is no committed success to conceal here.
    try {
      await deps.audit.record('denied', row.identity, provider.id, { reason: 'exchange_failed' });
    } catch { /* audit store unavailable; return the fixed failure below */ }
    emitConsent(deps, row.identity, provider.id, new URL(provider.tokenUrl).hostname, 'consent_denied', 500);
    const safe = mapSafeError(error);
    return attributedFailure(
      'exchange_failed',
      500,
      'Connection failed. Please try again.',
      safe.recovery,
      context,
    );
  }
}
