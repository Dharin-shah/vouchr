import type { Owner } from '../../src/core/owner';

/**
 * Tiny TS thin client for the Vouchr sidecar. This is the shape OTHER languages replicate: three
 * POSTs over localhost HTTP with a shared bearer. A Python/Go client is the same contract. See
 * README.md. The token is NEVER returned by /proxy; you only ever get the provider's response.
 */

/** The provider request the sidecar will proxy. `url`/`method`/`headers`/`body` are passed through to ConnectionHandle.fetch. */
export interface ProxyRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

/** What /proxy returns: the provider's own reply. No credential anywhere in here. */
export interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export class SidecarClient {
  constructor(
    private baseUrl: string,
    private token: string,
  ) {}

  private async call<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${this.token}` },
      body: JSON.stringify(body),
    });
    const json: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error ?? `sidecar ${path} failed: HTTP ${res.status}`);
    return json as T;
  }

  /**
   * Proxy an outbound provider call. `acting` (the verified Slack user who triggered this) is
   * optional for a user owner (defaults to the owner), required for a channel owner.
   */
  proxy(
    owner: Owner,
    provider: string,
    request: ProxyRequest,
    acting?: { userId: string; enterpriseId?: string | null },
  ): Promise<ProxyResponse> {
    return this.call<ProxyResponse>('/proxy', { owner, provider, request, acting });
  }

  /** List the owner's connected providers (no secrets). User owners only (see README). */
  status(owner: Owner): Promise<{ providers: { provider: string; externalAccount: string | null }[] }> {
    return this.call('/status', { owner });
  }

  /** Delete the stored credential. Upstream OAuth revoke stays in the Slack app. */
  disconnect(owner: Owner, provider: string): Promise<{ ok: true }> {
    return this.call('/disconnect', { owner, provider });
  }
}

// Tiny usage sketch (not run): proxy a GitHub call as a user, never seeing the token.
async function example(): Promise<void> {
  const client = new SidecarClient('http://127.0.0.1:8787', process.env.VOUCHR_SIDECAR_TOKEN ?? '');
  const owner: Owner = { teamId: 'T123', kind: 'user', id: 'U123' };
  const res = await client.proxy(owner, 'github', { url: 'https://api.github.com/user' });
  console.log(res.status, res.body); // the provider's reply; no token in sight
}
void example; // referenced so the example typechecks without an unused warning
