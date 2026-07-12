import type { Provider } from './providers';

// Bound the /token round-trip. A refresh runs while HOLDING the Postgres advisory lock and a
// refresh-pool connection (see injector.doRefresh / db.withRefreshLock); without this a hung token
// endpoint would pin the lock and a pool backend indefinitely (statement_timeout only bounds DB
// statements, not this outbound fetch). Slightly above the 8s in-lock statement_timeout.
const TOKEN_FETCH_TIMEOUT_MS = 10_000;

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

async function tokenRequest(
  provider: Provider,
  params: Record<string, string>,
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

  const res = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers,
    body,
    // OAuth codes, refresh tokens, and client credentials are all replayable secrets. Fetch's
    // default redirect mode would resend this POST body on a 307/308, potentially to a different
    // origin. Token endpoints must be final destinations: surface every redirect as a failure.
    redirect: 'manual',
    signal: AbortSignal.timeout(TOKEN_FETCH_TIMEOUT_MS), // release the lock/pool if the endpoint hangs
  });
  if (!res.ok) {
    // 400/401 usually means the grant is dead (RFC 6749 §5.2) — but a parseable OAuth error code
    // that is NOT invalid_grant (e.g. invalid_client: the operator's client secret expired) is
    // operator-side breakage no amount of user reconnecting can fix, so telling every owner to
    // reconnect would be pure spam: classify those transient. A bare/unparseable 400/401 stays
    // definitive. The body is only parsed here, never logged or put in the error (it's untrusted).
    let definitive = res.status === 400 || res.status === 401;
    if (definitive) {
      try {
        const err = JSON.parse(await res.text())?.error; // text() drains the body
        if (typeof err === 'string' && err !== 'invalid_grant') definitive = false;
      } catch {
        // Unparseable body: keep the status-based classification. If text() itself threw the
        // stream may be unconsumed — cancel it (harmless no-op when already drained).
        res.body?.cancel().catch(() => undefined);
      }
    } else {
      // Cancel the discarded body: undici pins the socket to an unread body until GC (#172), so
      // hourly-sweep refresh retries against a 429/5xx-ing endpoint would accumulate pinned sockets.
      res.body?.cancel().catch(() => undefined);
    }
    // The configured URL is external input and may contain credential-like query values. Identify
    // the field and status only; never reflect the endpoint itself into owner/operator error text.
    throw new TokenEndpointError(`Token endpoint returned HTTP ${res.status}`, definitive);
  }
  const json: any = await res.json();
  if (json.error) {
    // Some providers return 200 with an error body; only invalid_grant is definitively dead.
    // Boundary: a provider that reports a dead grant as 200 + a bespoke code (e.g.
    // bad_refresh_token) never classifies definitive → no owner DM, i.e. the pre-#117 status quo.
    // Fail-safe on purpose: a missed notification beats a false "reconnect now"; no per-provider
    // error-code list (the built-ins all use invalid_grant).
    throw new TokenEndpointError('Token endpoint returned an OAuth error', json.error === 'invalid_grant');
  }
  if (!json.access_token) {
    throw new Error('Token endpoint returned no access_token');
  }
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token ?? null,
    scopes: json.scope ?? null,
    expiresAt: json.expires_in ? Date.now() + Number(json.expires_in) * 1000 : null,
  };
}

export async function exchangeCode(
  provider: Provider,
  code: string,
  redirectUri: string,
  pkceVerifier: string,
): Promise<TokenResponse> {
  const params: Record<string, string> = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
  };
  if (provider.pkce) params.code_verifier = pkceVerifier;
  return tokenRequest(provider, params);
}

export async function refreshToken(
  provider: Provider,
  refresh: string,
): Promise<TokenResponse> {
  return tokenRequest(provider, { grant_type: 'refresh_token', refresh_token: refresh });
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
 * `timeoutMs` is parameterizable for tests only; production callers use the default.
 */
export async function revokeToken(provider: Provider, token: string, timeoutMs = TOKEN_FETCH_TIMEOUT_MS): Promise<void> {
  if (!provider.revoke && !provider.revokeUrl) return; // no documented revoke (e.g. Notion): honest no-op
  const controller = new AbortController();
  const work = provider.revoke
    ? provider.revoke(provider, token, controller.signal)
    : standardRevoke(provider, token, controller.signal);
  // A REAL (ref'd) timer, deliberately not AbortSignal.timeout: its unref'd timer lets a one-shot
  // process (e.g. a CLI offboard) drain the event loop and exit before the deadline ever fires.
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`Revoke for provider "${provider.id}" timed out after ${timeoutMs}ms`)); // never includes the token
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
  res.body?.cancel().catch(() => undefined);
  if (!res.ok) {
    throw new Error(`Revoke endpoint returned HTTP ${res.status}`); // never includes the token or configured URL
  }
}
