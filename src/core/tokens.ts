import { isOAuthScopeToken, type Provider } from './providers';
import {
  cancelResponseBody,
  DEFAULT_OAUTH_TIMEOUT_MS,
  disposableDeadline,
  readResponseJsonCapped,
} from './httpBounds';
import { MAX_TIMER_MS } from './options';

// Bound the /token round-trip. A refresh runs while HOLDING the Postgres advisory lock and a
// refresh-pool connection (see injector.doRefresh / db.withRefreshLock); without this a hung token
// endpoint would pin the lock and a pool backend indefinitely (statement_timeout only bounds DB
// statements, not this outbound fetch). The provider's one OAuth timeout also bounds revocation and
// built-in account probes.

export interface TokenResponse {
  accessToken: string;
  refreshToken: string | null;
  scopes: string | null;
  expiresAt: number | null;
}

/**
 * Typed token-endpoint failure carrying the ONE definitive-vs-transient classification (#117).
 * `definitive` = the grant itself is dead — HTTP 400/401 (RFC 6749 §5.2: invalid_grant /
 * invalid_client come back as 400/401) or an explicit `invalid_grant` error body — so retrying is
 * pointless and only reconnecting fixes it. Everything else (5xx, 429, network throw, timeout) is
 * transient and must NEVER trigger owner-facing notifications. Message text is identical to the
 * previous bare Errors (callers string-match it) and never carries token material.
 */
export class TokenEndpointError extends Error {
  constructor(
    message: string,
    public definitive: boolean,
  ) {
    super(message);
    this.name = 'TokenEndpointError';
  }
}

const MAX_GRANTED_SCOPE_BYTES = 4 * 1024;
const MAX_GRANTED_SCOPES = 128;

/** Canonicalize one provider-returned OAuth scope string before it can be persisted or rendered.
 * Invalid/overlong/secret-bearing cosmetic scope text becomes null, so callers safely retain or
 * fall back to the configured requested scopes. */
export function normalizeGrantedScopes(value: unknown, sensitive: readonly unknown[] = []): string | null {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value, 'utf8') > MAX_GRANTED_SCOPE_BYTES) {
    return null;
  }
  const scopes = value.split(' ');
  if (scopes.length > MAX_GRANTED_SCOPES || scopes.some((scope) => !isOAuthScopeToken(scope))) return null;
  const secrets = sensitive.filter((item): item is string => typeof item === 'string' && item.length > 0);
  if (secrets.some((secret) => value.includes(secret))) return null;
  return value;
}

/** Validate the bounded but still untrusted OAuth JSON before any field reaches the vault. */
function parseTokenResponse(value: unknown, sensitive: readonly unknown[]): TokenResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Token endpoint returned an invalid response');
  }
  const json = value as Record<string, unknown>;
  if (typeof json.access_token !== 'string' || json.access_token.length === 0) {
    throw new Error('Token endpoint returned no valid access_token');
  }
  if (json.refresh_token !== undefined && json.refresh_token !== null
    && (typeof json.refresh_token !== 'string' || json.refresh_token.length === 0)) {
    throw new Error('Token endpoint returned an invalid refresh_token');
  }
  if (json.scope !== undefined && json.scope !== null && typeof json.scope !== 'string') {
    throw new Error('Token endpoint returned an invalid scope');
  }

  let expiresAt: number | null = null;
  if (json.expires_in !== undefined && json.expires_in !== null) {
    if (typeof json.expires_in !== 'number' || !Number.isFinite(json.expires_in) || json.expires_in < 0) {
      throw new Error('Token endpoint returned an invalid expires_in');
    }
    const candidate = Date.now() + json.expires_in * 1000;
    // ECMAScript Date's TimeClip range. Refuse an unusable/infinite persisted timestamp.
    if (!Number.isFinite(candidate) || candidate > 8_640_000_000_000_000) {
      throw new Error('Token endpoint returned an invalid expires_in');
    }
    expiresAt = candidate;
  }

  return {
    accessToken: json.access_token,
    refreshToken: (json.refresh_token as string | null | undefined) ?? null,
    scopes: normalizeGrantedScopes(json.scope, [json.access_token, json.refresh_token, ...sensitive]),
    expiresAt,
  };
}

async function tokenRequest(
  provider: Provider,
  params: Record<string, string>,
  callerSignal?: AbortSignal,
): Promise<TokenResponse> {
  const fields: Record<string, string> = { ...params };
  const headers: Record<string, string> = { Accept: 'application/json' };

  // clientId is guaranteed for oauth providers (defineProvider); token paths never run for key providers.
  // A PKCE public client (publicClient) has no secret — it authenticates with the code_verifier alone,
  // so only send client_secret when the provider actually has one (confidential client).
  if ((provider.tokenAuth ?? 'body') === 'basic') {
    const creds = Buffer.from(`${provider.clientId}:${provider.clientSecret ?? ''}`).toString('base64');
    headers.Authorization = `Basic ${creds}`;
  } else {
    fields.client_id = provider.clientId!;
    if (provider.clientSecret) fields.client_secret = provider.clientSecret;
  }

  let body: string;
  if ((provider.bodyFormat ?? 'form') === 'json') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(fields);
  } else {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(fields).toString();
  }

  // The provider's finite OAuth ceiling composes with the request/caller signal. Cancellation releases
  // the refresh lock/pool promptly, while a caller that forgets a signal cannot make this unbounded.
  const deadline = disposableDeadline(provider.oauthTimeoutMs ?? DEFAULT_OAUTH_TIMEOUT_MS, callerSignal);
  try {
    const res = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers,
      body,
      // OAuth codes, refresh tokens, and client credentials are all replayable secrets. Fetch's
      // default redirect mode would resend this POST body on a 307/308, potentially to a different
      // origin. Token endpoints must be final destinations: surface every redirect as a failure.
      redirect: 'manual',
      signal: deadline.signal,
    });
    if (!res.ok) {
      // 400/401 usually means the grant is dead (RFC 6749 §5.2) — but a parseable OAuth error code
      // that is NOT invalid_grant (e.g. invalid_client: the operator's client secret expired) is
      // operator-side breakage no amount of user reconnecting can fix, so telling every owner to
      // reconnect would be pure spam: classify those transient. A bare/unparseable 400/401 stays
      // definitive. The body is bounded and only parsed here, never logged or put in the error.
      let definitive = res.status === 400 || res.status === 401;
      if (definitive) {
        try {
          const json: any = await readResponseJsonCapped(res);
          if (typeof json?.error === 'string' && json.error !== 'invalid_grant') definitive = false;
        } catch {
          // Unparseable/over-cap body: keep status classification and ensure the socket is released.
          await cancelResponseBody(res);
        }
      } else {
        // Cancel the discarded body: undici pins the socket to an unread body until GC (#172), so
        // hourly-sweep refresh retries against a 429/5xx-ing endpoint would accumulate pinned sockets.
        await cancelResponseBody(res);
      }
      // The configured URL is external input and may contain credential-like query values. Identify
      // the field and status only; never reflect the endpoint itself into owner/operator error text.
      throw new TokenEndpointError(`Token endpoint returned HTTP ${res.status}`, definitive);
    }
    const json = await readResponseJsonCapped(res);
    if (json && typeof json === 'object' && !Array.isArray(json) && 'error' in json) {
      const error = (json as Record<string, unknown>).error;
      if (typeof error !== 'string' || error.length === 0) {
        throw new Error('Token endpoint returned an invalid response');
      }
      // Some providers return 200 with an error body; only invalid_grant is definitively dead.
      // Boundary: a provider that reports a dead grant as 200 + a bespoke code (e.g.
      // bad_refresh_token) never classifies definitive → no owner DM, i.e. the pre-#117 status quo.
      // Fail-safe on purpose: a missed notification beats a false "reconnect now"; no per-provider
      // error-code list (the built-ins all use invalid_grant).
      throw new TokenEndpointError('Token endpoint returned an OAuth error', error === 'invalid_grant');
    }
    return parseTokenResponse(json, [
      provider.clientSecret,
      params.code,
      params.code_verifier,
      params.refresh_token,
    ]);
  } finally {
    deadline.dispose();
  }
}

export async function exchangeCode(
  provider: Provider,
  code: string,
  redirectUri: string,
  pkceVerifier: string,
  signal?: AbortSignal,
): Promise<TokenResponse> {
  const params: Record<string, string> = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
  };
  if (provider.pkce) params.code_verifier = pkceVerifier;
  return tokenRequest(provider, params, signal);
}

export async function refreshToken(
  provider: Provider,
  refresh: string,
  signal?: AbortSignal,
): Promise<TokenResponse> {
  return tokenRequest(provider, { grant_type: 'refresh_token', refresh_token: refresh }, signal);
}

/**
 * Best-effort upstream token revocation. No-op when the provider declares no revoke
 * capability (no `revokeUrl`/`revoke`). Uses the provider's `revoke` function for
 * non-standard endpoints, otherwise POSTs `token=<token>` (form, RFC 7009) to `revokeUrl`,
 * adding client_id/client_secret when `revokeAuth === 'body'`. NEVER logs the token or puts
 * it in an error; MAY throw on network/HTTP failure (callers wrap it best-effort).
 *
 * EVERY implementation is time-bounded (GHSA-25m2): a hung revoke endpoint must not stall
 * disconnect/offboarding for minutes. The abort signal is handed to the custom `revoke` hook so a
 * well-behaved implementation cancels its own fetch, and the call is ALSO raced against the same
 * deadline so a hook that ignores the signal still cannot hang the caller (the abandoned promise
 * is fine: revocation is best-effort by contract, local deletion already happened or follows).
 * `timeoutMs` remains parameterizable for focused tests; production uses the provider's shared
 * `oauthTimeoutMs` (10 seconds by default).
 */
export async function revokeToken(
  provider: Provider,
  token: string,
  timeoutMs = provider.oauthTimeoutMs ?? DEFAULT_OAUTH_TIMEOUT_MS,
): Promise<void> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMER_MS) {
    throw new Error(`Revoke timeout must be a positive safe integer no greater than ${MAX_TIMER_MS}`);
  }
  if (!provider.revoke && !provider.revokeUrl) return; // no documented revoke (e.g. Notion): honest no-op
  const controller = new AbortController();
  const work = provider.revoke
    ? provider.revoke(provider, token, controller.signal)
    : standardRevoke(provider, token, controller.signal);
  // A real referenced timer, deliberately not AbortSignal.timeout: its unref'd timer could let a
  // one-shot process (e.g. a CLI offboard) exit before the deadline ever fires.
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(`Revoke for provider "${provider.id}" timed out after ${timeoutMs}ms`); // never includes the token
      // Settle the deadline before abort dispatches synchronously. A custom hook may resolve when it
      // observes cancellation; it must not win Promise.race and turn a real timeout into success.
      reject(error);
      controller.abort(error);
    }, timeoutMs);
  });
  try {
    await Promise.race([work, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** The default RFC 7009 revoke (form POST of `token=` to `revokeUrl`). */
async function standardRevoke(provider: Provider, token: string, signal: AbortSignal): Promise<void> {
  const fields: Record<string, string> = { token };
  if (provider.revokeAuth === 'body') {
    fields.client_id = provider.clientId!;
    fields.client_secret = provider.clientSecret!;
  }
  const res = await fetch(provider.revokeUrl!, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
    // A 307/308 would replay the live token (and, for revokeAuth=body, client credentials) to the
    // redirect destination. Revocation endpoints must be final destinations.
    redirect: 'manual',
    signal,
  });
  // Revoke responses are never read (only the status matters): cancel the body on BOTH paths, or
  // undici pins the socket to it until GC (#172).
  await cancelResponseBody(res);
  if (!res.ok) {
    throw new Error(`Revoke endpoint returned HTTP ${res.status}`); // never includes the token or configured URL
  }
}
