import type { Provider } from './providers';

export interface TokenResponse {
  accessToken: string;
  refreshToken: string | null;
  scopes: string | null;
  expiresAt: number | null;
}

async function tokenRequest(
  provider: Provider,
  params: Record<string, string>,
): Promise<TokenResponse> {
  const fields: Record<string, string> = { ...params };
  const headers: Record<string, string> = { Accept: 'application/json' };

  // clientId/clientSecret are guaranteed for oauth providers (defineProvider); token paths never run for key providers.
  if ((provider.tokenAuth ?? 'body') === 'basic') {
    const creds = Buffer.from(`${provider.clientId}:${provider.clientSecret}`).toString('base64');
    headers.Authorization = `Basic ${creds}`;
  } else {
    fields.client_id = provider.clientId!;
    fields.client_secret = provider.clientSecret!;
  }

  let body: string;
  if ((provider.bodyFormat ?? 'form') === 'json') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(fields);
  } else {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(fields).toString();
  }

  const res = await fetch(provider.tokenUrl, { method: 'POST', headers, body });
  if (!res.ok) {
    throw new Error(`Token endpoint ${provider.tokenUrl} returned HTTP ${res.status}`);
  }
  const json: any = await res.json();
  if (json.error) {
    throw new Error('Token endpoint returned an OAuth error');
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
 */
export async function revokeToken(provider: Provider, token: string): Promise<void> {
  if (provider.revoke) return provider.revoke(provider, token);
  if (!provider.revokeUrl) return; // no documented revoke (e.g. Notion): honest no-op

  const fields: Record<string, string> = { token };
  if (provider.revokeAuth === 'body') {
    fields.client_id = provider.clientId!;
    fields.client_secret = provider.clientSecret!;
  }
  const res = await fetch(provider.revokeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  });
  if (!res.ok) {
    throw new Error(`Revoke endpoint ${provider.revokeUrl} returned HTTP ${res.status}`); // never includes the token
  }
}
