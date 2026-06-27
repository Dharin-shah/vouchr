export type RefreshStrategy = 'rotating' | 'static' | 'none';

/** A provider is declarative OAuth2 + a refresh strategy + an egress allowlist. */
export interface Provider {
  id: string;
  /**
   * How a USER supplies their own credential when none exists yet:
   *  - 'oauth' (default) → JIT in-Slack Connect button → browser OAuth.
   *  - 'key' → the user pastes their own static key (or external reference) into a private
   *    self-service modal. No OAuth client; `clientId`/`clientSecret`/`authorizeUrl`/`tokenUrl`
   *    are unused.
   */
  credential?: 'oauth' | 'key';
  authorizeUrl: string;
  tokenUrl: string;
  scopesDefault: string[];
  /** Hostnames this provider's tokens may be sent to (injection boundary). */
  egressAllow: string[];
  /**
   * How the secret is attached to the outbound request. Mutate `headers` in place.
   * Default (unset): `Authorization: Bearer <secret>`. Use for non-Bearer APIs/MCPs,
   * e.g. `(h, s) => h.set('x-api-key', s)`.
   * Note: header-only — covers Bearer/x-api-key/Basic. Add a URL arg if a provider
   * ever needs the secret in a query param.
   */
  inject?: (headers: Headers, secret: string) => void;
  refresh: RefreshStrategy;
  /** Send PKCE in the authorize + token exchange. */
  pkce: boolean;
  /** Extra provider-specific query params on the authorize URL (e.g. Google's access_type=offline). */
  authorizeParams?: Record<string, string>;
  /** Client auth at the token endpoint. Default 'body' (client_secret in the body). 'basic' = HTTP Basic header. */
  tokenAuth?: 'body' | 'basic';
  /** Token request body encoding. Default 'form'. */
  bodyFormat?: 'form' | 'json';
  /**
   * OPTIONAL upstream token revocation (RFC 7009 style). When unset, revoke is a no-op
   * (e.g. Notion has no documented endpoint — not faked). The declarative path POSTs
   * `token=<token>` (form) to `revokeUrl`; `revokeAuth: 'body'` additionally sends
   * client_id/client_secret in the body (GitLab). `revokeAuth: 'none'` (default) sends no
   * client auth (Google). For genuinely non-standard endpoints (e.g. GitHub's DELETE with
   * Basic auth + JSON + client_id in the path) use the `revoke` function escape hatch.
   */
  revokeUrl?: string;
  /** Client auth at the revoke endpoint. Default 'none'. 'body' = client_id/client_secret in the body. */
  revokeAuth?: 'none' | 'body';
  /** Escape hatch for non-standard revoke endpoints; takes precedence over `revokeUrl`. */
  revoke?: (provider: Provider, token: string) => Promise<void>;
  /** Required for `credential: 'oauth'` (the default); unused for `credential: 'key'`. */
  clientId?: string;
  clientSecret?: string;
  /** Optional: fetch a human-readable account label after connecting. */
  accountProbe?: (accessToken: string) => Promise<string | null>;
}

export interface ProviderConfig {
  clientId?: string;
  clientSecret?: string;
  scopes?: string[];
}

export function defineProvider(spec: Provider): Provider {
  // Key providers carry no OAuth client; only OAuth providers need clientId/clientSecret.
  if (spec.credential !== 'key' && (!spec.clientId || !spec.clientSecret)) {
    throw new Error(
      `Provider "${spec.id}" is missing clientId/clientSecret. Set them in the provider config or via env.`,
    );
  }
  return spec;
}

/** Built-in GitHub provider. Classic OAuth tokens are long-lived (no refresh). */
export function github(cfg: ProviderConfig = {}): Provider {
  return defineProvider({
    id: 'github',
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scopesDefault: cfg.scopes ?? ['read:user', 'repo'],
    egressAllow: ['api.github.com'],
    refresh: 'none',
    pkce: false, // GitHub OAuth Apps use the client secret, not PKCE
    clientId: cfg.clientId ?? process.env.GITHUB_CLIENT_ID ?? '',
    clientSecret: cfg.clientSecret ?? process.env.GITHUB_CLIENT_SECRET ?? '',
    // Non-standard shape (DELETE + Basic + JSON + client_id in the path) → function escape hatch.
    revoke: async (p, token) => {
      const creds = Buffer.from(`${p.clientId}:${p.clientSecret}`).toString('base64');
      const r = await fetch(`https://api.github.com/applications/${p.clientId}/token`, {
        method: 'DELETE',
        headers: { Authorization: `Basic ${creds}`, Accept: 'application/vnd.github+json', 'User-Agent': 'vouchr' },
        body: JSON.stringify({ access_token: token }),
      });
      if (!r.ok && r.status !== 404) throw new Error(`GitHub token revoke returned HTTP ${r.status}`); // 404 = already gone
    },
    accountProbe: async (token) => {
      const r = await fetch('https://api.github.com/user', {
        headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'vouchr' },
      });
      if (!r.ok) return null;
      const j: any = await r.json();
      return j.login ?? null;
    },
  });
}

/** Built-in Google provider. Needs access_type=offline + prompt=consent for a refresh token. */
export function google(cfg: ProviderConfig = {}): Provider {
  return defineProvider({
    id: 'google',
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scopesDefault: cfg.scopes ?? [
      'openid',
      'email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
    egressAllow: ['www.googleapis.com', 'gmail.googleapis.com', 'people.googleapis.com'],
    refresh: 'rotating',
    pkce: true,
    authorizeParams: { access_type: 'offline', prompt: 'consent' },
    revokeUrl: 'https://oauth2.googleapis.com/revoke', // form token=<token>, no client auth
    clientId: cfg.clientId ?? process.env.GOOGLE_CLIENT_ID ?? '',
    clientSecret: cfg.clientSecret ?? process.env.GOOGLE_CLIENT_SECRET ?? '',
    accountProbe: async (token) => {
      const r = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) return null;
      const j: any = await r.json();
      return j.email ?? null;
    },
  });
}

/** Built-in GitLab.com provider (rotating refresh tokens, PKCE). */
export function gitlab(cfg: ProviderConfig = {}): Provider {
  return defineProvider({
    id: 'gitlab',
    authorizeUrl: 'https://gitlab.com/oauth/authorize',
    tokenUrl: 'https://gitlab.com/oauth/token',
    scopesDefault: cfg.scopes ?? ['read_user', 'api'],
    egressAllow: ['gitlab.com'],
    refresh: 'rotating',
    pkce: true,
    revokeUrl: 'https://gitlab.com/oauth/revoke', // form client_id+client_secret+token
    revokeAuth: 'body',
    clientId: cfg.clientId ?? process.env.GITLAB_CLIENT_ID ?? '',
    clientSecret: cfg.clientSecret ?? process.env.GITLAB_CLIENT_SECRET ?? '',
    accountProbe: async (token) => {
      const r = await fetch('https://gitlab.com/api/v4/user', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) return null;
      const j: any = await r.json();
      return j.username ?? null;
    },
  });
}

/**
 * Built-in Notion provider. Notion's token endpoint is non-standard: HTTP Basic
 * client auth + a JSON body, and scopes are configured on the integration (not
 * sent per-request). This is exactly what the tokenAuth/bodyFormat knobs are for.
 */
export function notion(cfg: ProviderConfig = {}): Provider {
  return defineProvider({
    id: 'notion',
    authorizeUrl: 'https://api.notion.com/v1/oauth/authorize',
    tokenUrl: 'https://api.notion.com/v1/oauth/token',
    scopesDefault: cfg.scopes ?? [],
    egressAllow: ['api.notion.com'],
    refresh: 'none',
    pkce: false,
    tokenAuth: 'basic',
    bodyFormat: 'json',
    authorizeParams: { owner: 'user' },
    clientId: cfg.clientId ?? process.env.NOTION_CLIENT_ID ?? '',
    clientSecret: cfg.clientSecret ?? process.env.NOTION_CLIENT_SECRET ?? '',
    accountProbe: async (token) => {
      const r = await fetch('https://api.notion.com/v1/users/me', {
        headers: { Authorization: `Bearer ${token}`, 'Notion-Version': '2022-06-28' },
      });
      if (!r.ok) return null;
      const j: any = await r.json();
      return j?.bot?.owner?.user?.name ?? j?.name ?? null;
    },
  });
}

export class ProviderRegistry {
  private map = new Map<string, Provider>();
  constructor(providers: Provider[]) {
    for (const p of providers) this.map.set(p.id, p);
  }
  get(id: string): Provider {
    const p = this.map.get(id);
    if (!p) {
      throw new Error(
        `Unknown provider "${id}". Registered: ${[...this.map.keys()].join(', ') || '(none)'}`,
      );
    }
    return p;
  }
  has(id: string): boolean {
    return this.map.has(id);
  }
}
