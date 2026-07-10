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
  /**
   * Whether the agent calls this provider AS the human (default) or AS a service. Drives the
   * tool-manifest `identity` and whether Vouchr brokers it:
   *  - 'acting_human' (default): Vouchr resolves the human's credential + consent via connect().
   *  - 'service': a service-to-service tool the host runs with its own service auth; connect()
   *     refuses it (no human credential to broker, no consent flow). See ToolManifestEntry.identity.
   */
  identity?: 'service' | 'acting_human';
  authorizeUrl: string;
  tokenUrl: string;
  scopesDefault: string[];
  /** Optional human-language description per scope id, shown in the connect prompt. Unknown scopes fall back to the raw string. */
  scopeDescriptions?: Record<string, string>;
  /** Hostnames this provider's tokens may be sent to (injection boundary). */
  egressAllow: string[];
  /**
   * OPTIONAL finer egress controls, layered on top of `egressAllow`. All additive: a provider
   * with only `egressAllow` behaves exactly as before. Each is checked AFTER the hostname + https
   * checks and BEFORE the secret is read; any failure denies the request.
   */
  /** Allowed URL path prefixes (e.g. ['/repos/', '/user']). If set, the request path must start with one. */
  egressPaths?: string[];
  /** Allowed HTTP methods (e.g. ['GET','POST']). If set, the request method (case-insensitive) must be in the set. */
  egressMethods?: string[];
  /** Per-provider escape-hatch validator. If set and it returns false, the request is denied. */
  egressValidate?: (url: URL, init: RequestInit) => boolean;
  /**
   * OPTIONAL structural constraints on the provider's RESPONSE, enforced in the injector AFTER the
   * fetch returns and BEFORE the Response reaches the caller — the Bolt handle and the HTTP broker
   * inherit them identically. Structural only, never content/PII inspection:
   *  - `maxBytes`: response body cap. Fast-fails on a declared Content-Length, then enforced with a
   *    byte counter while streaming (a Content-Length can lie low; chunked bodies carry none). A
   *    breach aborts the read — the caller never sees a partial body. Absent = unlimited.
   *  - `allowContentTypes`: allowed bare media types, matched exactly and case-insensitively with
   *    parameters ignored (['application/json'] admits 'application/json; charset=utf-8', never
   *    'application/jsonp-evil'; a missing header matches nothing). A mismatch denies the response
   *    with the body unread. Bodyless responses (204/205/304, HEAD) are exempt.
   *  - `stripHeaders`: response headers to remove, on top of `set-cookie` — which is ALWAYS
   *    stripped from every response, opt-in or not (a credential-adjacent artifact the agent has
   *    no business seeing).
   */
  egressResponse?: { maxBytes?: number; allowContentTypes?: string[]; stripHeaders?: string[] };
  /**
   * OPT-IN for the headless broker's `POST /v1/mcp` route (#65). Absent = the provider is refused
   * on /v1/mcp (403), even when POST-enabled for /v1/fetch: the raw streamed passthrough skips the
   * broker's per-request response envelope gates, so reaching it must be a deliberate declaration
   * with the endpoint locked down.
   *  - `paths`: REQUIRED — the MCP endpoint path prefixes, matched with the SAME semantics as
   *    `egressPaths` (one shared matcher; encoded path separators refused fail-closed).
   *  - `allowContentTypes`: allowed RESPONSE media types, matched on the bare type exactly like
   *    `egressResponse.allowContentTypes`. Default `['application/json', 'text/event-stream']`
   *    (the two MCP Streamable-HTTP transport types); a response outside it is withheld unread.
   * Session note: `Mcp-Session-Id` values relayed on this route are opaque and potentially
   * sensitive — Vouchr never stores, logs, or authenticates by them.
   */
  mcp?: { paths: string[]; allowContentTypes?: string[] };
  /**
   * Optional per-(owner, provider) request throttle at the injection boundary: `perMinute` sustained
   * requests per minute PER credential owner (user or channel), with up to `burst` (default =
   * `perMinute`) available at once. A limited request throws `RateLimitedError` BEFORE the vault is
   * read — the secret is never touched. Absent = unlimited (unchanged behavior).
   */
  rateLimit?: { perMinute: number; burst?: number };
  /**
   * How the secret is attached to the outbound request. Mutate `headers` in place.
   * Default (unset): `Authorization: Bearer <secret>`. Use for non-Bearer APIs/MCPs,
   * e.g. `(h, s) => h.set('x-api-key', s)`.
   * Note: header-only, covers Bearer/x-api-key/Basic. Add a URL arg if a provider
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
   * (e.g. Notion has no documented endpoint, not faked). The declarative path POSTs
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
  /**
   * OAuth PUBLIC client: PKCE-only, no client secret (e.g. Databricks U2M public apps). When true,
   * defineProvider requires only clientId (not clientSecret), and the token exchange authenticates
   * with the PKCE code_verifier alone. Requires `pkce: true` — a public client with no PKCE has no
   * client authentication at all. Confidential clients (with a secret) leave this unset.
   */
  publicClient?: boolean;
  /** Optional: fetch a human-readable account label after connecting. */
  accountProbe?: (accessToken: string) => Promise<string | null>;
}

export interface ProviderConfig {
  clientId?: string;
  clientSecret?: string;
  scopes?: string[];
  /** Optional finer egress controls (see Provider). */
  egressPaths?: string[];
  egressMethods?: string[];
  egressValidate?: (url: URL, init: RequestInit) => boolean;
  /** Optional structural response constraints at the injection boundary (see Provider). */
  egressResponse?: Provider['egressResponse'];
  /** Optional per-(owner, provider) throttle at the injection boundary (see Provider). */
  rateLimit?: { perMinute: number; burst?: number };
}

/** The per-config injection-boundary gates (egress + rate limit), passed through to a built-in. */
function egressOptions(cfg: ProviderConfig): Pick<Provider, 'egressPaths' | 'egressMethods' | 'egressValidate' | 'egressResponse' | 'rateLimit'> {
  return {
    egressPaths: cfg.egressPaths,
    egressMethods: cfg.egressMethods,
    egressValidate: cfg.egressValidate,
    egressResponse: cfg.egressResponse,
    rateLimit: cfg.rateLimit,
  };
}

export function defineProvider(spec: Provider): Provider {
  // A zero/negative/NaN rate limit would build a bucket that can never refill (or never denies) —
  // reject the misconfiguration at definition time rather than shipping a broken limiter.
  if (spec.rateLimit) {
    const { perMinute, burst } = spec.rateLimit;
    if (!(Number.isFinite(perMinute) && perMinute > 0) || (burst !== undefined && !(Number.isFinite(burst) && burst > 0))) {
      throw new Error(`Provider "${spec.id}" has an invalid rateLimit: perMinute (and burst, when set) must be a finite number > 0.`);
    }
    // The bucket's capacity is `burst ?? perMinute`, every request costs 1, and refill is capped at
    // capacity — so an effective capacity < 1 can never accumulate a whole token and would deny
    // every request forever. Sub-1/minute rates stay expressible via an explicit burst >= 1.
    if ((burst ?? perMinute) < 1) {
      throw new Error(
        `Provider "${spec.id}" has an invalid rateLimit: burst (or perMinute, when burst is unset) must be >= 1, or no request can ever be admitted. For rates below one per minute, set burst: 1.`,
      );
    }
  }
  // A NaN/zero/negative maxBytes would silently disable the cap (NaN comparisons are all false) or
  // deny every response; an invalid stripHeaders NAME would throw per-request at strip time — AFTER
  // the token was already spent. Reject both at definition time, like the rateLimit checks above.
  if (spec.egressResponse) {
    const { maxBytes, allowContentTypes, stripHeaders } = spec.egressResponse;
    if (maxBytes !== undefined && !(Number.isFinite(maxBytes) && maxBytes > 0)) {
      throw new Error(`Provider "${spec.id}" has an invalid egressResponse.maxBytes: must be a finite number > 0.`);
    }
    // An empty array is a silent deny-all, an empty entry a misconfigured (never-matching) type —
    // both read as protection while doing something else entirely. Reject at definition time.
    if (allowContentTypes !== undefined && (allowContentTypes.length === 0 || allowContentTypes.some((c) => typeof c !== 'string' || !c.trim()))) {
      throw new Error(`Provider "${spec.id}" has an invalid egressResponse.allowContentTypes: must be a non-empty array of non-empty media types.`);
    }
    for (const h of stripHeaders ?? []) {
      try {
        new Headers().delete(h);
      } catch {
        throw new Error(`Provider "${spec.id}" has an invalid egressResponse.stripHeaders entry: not a valid header name.`);
      }
    }
  }
  // #65 /v1/mcp opt-in: an empty/invalid `paths` lock and an empty content-type list are silent
  // misconfigurations (allow-nothing that reads as protection, or a never-matching type) — reject
  // at definition time, in the same style as the egressResponse checks above.
  if (spec.mcp) {
    const { paths, allowContentTypes } = spec.mcp;
    if (!Array.isArray(paths) || paths.length === 0 || paths.some((p) => typeof p !== 'string' || !p.trim())) {
      throw new Error(`Provider "${spec.id}" has an invalid mcp.paths: must be a non-empty array of non-empty path prefixes.`);
    }
    if (allowContentTypes !== undefined && (allowContentTypes.length === 0 || allowContentTypes.some((c) => typeof c !== 'string' || !c.trim()))) {
      throw new Error(`Provider "${spec.id}" has an invalid mcp.allowContentTypes: must be a non-empty array of non-empty media types.`);
    }
  }
  // Key providers carry no OAuth client. OAuth confidential clients need clientId + clientSecret;
  // a PKCE public client (publicClient:true) authenticates with the code_verifier alone → clientId only.
  if (spec.credential !== 'key') {
    if (spec.publicClient && !spec.pkce) {
      throw new Error(
        `Provider "${spec.id}" is a public client (publicClient:true) but PKCE is disabled — a public client must use PKCE.`,
      );
    }
    if (spec.publicClient && (spec.tokenAuth ?? 'body') === 'basic') {
      // Basic token auth IS a client-secret credential (Basic base64(id:secret)); a public client has
      // no secret, so it would send `Basic base64(id:)` — nonsensical. Reject rather than half-auth.
      throw new Error(
        `Provider "${spec.id}" is a public client but uses Basic token auth — Basic transmits a client secret a public client does not have.`,
      );
    }
    const needsSecret = !spec.publicClient;
    if (!spec.clientId || (needsSecret && !spec.clientSecret)) {
      throw new Error(
        `Provider "${spec.id}" is missing clientId/clientSecret. Set them in the provider config or via env.`,
      );
    }
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
    scopeDescriptions: {
      'read:user': 'Read your profile',
      repo: 'Read and write your repositories',
    },
    egressAllow: ['api.github.com'],
    ...egressOptions(cfg),
    refresh: 'none',
    pkce: false, // GitHub OAuth Apps use the client secret, not PKCE
    clientId: cfg.clientId ?? process.env.GITHUB_CLIENT_ID ?? '',
    clientSecret: cfg.clientSecret ?? process.env.GITHUB_CLIENT_SECRET ?? '',
    // Non-standard shape (DELETE + Basic + JSON + client_id in the path) → function escape hatch.
    revoke: async (p, token) => {
      const creds = Buffer.from(`${p.clientId}:${p.clientSecret}`).toString('base64');
      const r = await fetch(`https://api.github.com/applications/${p.clientId}/token`, {
        method: 'DELETE',
        headers: {
          Authorization: `Basic ${creds}`,
          Accept: 'application/vnd.github+json',
          'Content-Type': 'application/json',
          'User-Agent': 'vouchr',
        },
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
    scopeDescriptions: {
      openid: 'Sign you in with your Google identity',
      email: 'See your Google email address',
      'https://www.googleapis.com/auth/userinfo.profile': 'See your basic profile info (name and photo)',
      'https://www.googleapis.com/auth/calendar': 'See, edit, share, and delete all your calendars',
      'https://www.googleapis.com/auth/calendar.readonly': 'See your calendars and their events',
      'https://www.googleapis.com/auth/calendar.events': 'See and edit events on your calendars',
      'https://www.googleapis.com/auth/calendar.events.readonly': 'See events on your calendars',
    },
    egressAllow: ['www.googleapis.com', 'gmail.googleapis.com', 'people.googleapis.com'],
    ...egressOptions(cfg),
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
    scopeDescriptions: {
      read_user: 'Read your profile',
      api: 'Full read and write access to your projects, groups, and code',
    },
    egressAllow: ['gitlab.com'],
    ...egressOptions(cfg),
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
    ...egressOptions(cfg),
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

export interface DatabricksConfig extends ProviderConfig {
  /** The workspace URL, e.g. `https://dbc-abc123.cloud.databricks.com`. OAuth + API are workspace-scoped. */
  host: string;
}

/**
 * Built-in Databricks provider (per-user OAuth U2M), egress-LOCKED to the SQL Statement Execution API
 * by default. This is the point of the built-in: warehouse access as the connected human composes with
 * Unity Catalog row/column governance (masks, row filters, grants apply per human), but ONLY if the
 * agent can't reach the rest of the workspace. So the default egress allows exactly the statements API
 * — everything else (jobs, secrets, workspace admin, DBFS, SCIM) is off-limits until a caller widens
 * `egressPaths` explicitly.
 *
 * Both client shapes are supported (Databricks U2M allows either):
 *  - PUBLIC client: `databricks({ host, clientId })` — no secret; PKCE-only (publicClient inferred).
 *  - CONFIDENTIAL client: `databricks({ host, clientId, clientSecret })` — secret + PKCE.
 *
 * `all-apis` is the U2M scope for calling workspace APIs as the user; `offline_access` yields a refresh
 * token. POST is required to SUBMIT a statement, so a broker fronting this provider needs `allowWrites`
 * on plus this provider's `egressMethods` (GET+POST) for the submit path; GET alone only polls results.
 */
export function databricks(cfg: DatabricksConfig): Provider {
  if (!cfg.host) throw new Error('databricks({ host }) is required (the workspace URL, e.g. https://<ws>.cloud.databricks.com)');
  // Parse + validate the host STRICTLY: the OAuth code + any client secret are POSTed to
  // `${origin}/oidc/v1/token`, and that token exchange is NOT behind the egress https gate — so a
  // http:// or userinfo-bearing host would leak the exchange in cleartext / to the wrong party.
  // Require a clean HTTPS origin (no non-https scheme, credentials, path, query, or fragment) and build
  // the OAuth URLs from `url.origin`, so nothing from the raw string can smuggle into them.
  let origin: string;
  let hostname: string;
  try {
    const u = new URL(cfg.host);
    if (u.protocol !== 'https:') throw new Error('must be https');
    if (u.username || u.password) throw new Error('must not contain credentials');
    if (u.search || u.hash) throw new Error('must not contain a query or fragment');
    if (u.pathname !== '/' && u.pathname !== '') throw new Error('must be a bare workspace URL with no path');
    origin = u.origin;
    hostname = u.hostname;
  } catch (e) {
    throw new Error(`databricks({ host }) must be a bare HTTPS workspace URL like https://<ws>.cloud.databricks.com (${(e as Error).message})`);
  }
  const clientSecret = cfg.clientSecret ?? process.env.DATABRICKS_CLIENT_SECRET;
  return defineProvider({
    id: 'databricks',
    authorizeUrl: `${origin}/oidc/v1/authorize`,
    tokenUrl: `${origin}/oidc/v1/token`,
    scopesDefault: cfg.scopes ?? ['all-apis', 'offline_access'],
    egressAllow: [hostname],
    // One prefix covers BOTH `POST /api/2.0/sql/statements` (submit) and `GET /api/2.0/sql/statements/<id>`
    // (poll/cancel) via the injector's prefix rule, while still rejecting /api/2.0/secrets, /api/2.1/jobs,
    // and lookalikes like /api/2.0/sql/statements-evil. Callers widen this explicitly if they need more.
    egressPaths: cfg.egressPaths ?? ['/api/2.0/sql/statements'],
    egressMethods: cfg.egressMethods ?? ['GET', 'POST'],
    egressValidate: cfg.egressValidate,
    egressResponse: cfg.egressResponse,
    rateLimit: cfg.rateLimit,
    refresh: 'rotating', // offline_access → refresh token; Databricks rotates it (single-flight guards the swap)
    pkce: true, // U2M requires PKCE
    scopeDescriptions: {
      'all-apis': 'Call the workspace APIs as you (locked to SQL statement execution by default)',
      offline_access: 'Stay connected without re-authorizing (refresh token)',
    },
    clientId: cfg.clientId ?? process.env.DATABRICKS_CLIENT_ID ?? '',
    clientSecret,
    publicClient: !clientSecret, // no secret → public client (PKCE-only)
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
