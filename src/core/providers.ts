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
   * OPT-IN human-in-the-loop approval for sensitive writes (#113), enforced in the injector AFTER
   * every egress gate (an ADDITIONAL gate, never a bypass — an egress-denied target never prompts)
   * and BEFORE the secret is read or anything goes out on the wire. A matching request with no
   * live grant throws `ApprovalRequiredError` (the Bolt adapter posts Approve/Deny buttons; the
   * headless broker returns 403 `approval_required`). A grant is SINGLE-USE, TTL-bound, and matches
   * ONLY the exact (method, host, path) it was minted for — never the request body (see the threat
   * model: approval covers the endpoint + method, not the payload bytes).
   *  - `methods`: which HTTP methods require approval. Default: every non-read method (anything
   *    but GET/HEAD) — see `approvalNeeded` in the injector, the one place that default lives.
   *  - `paths`: narrow the requirement to these paths (same matcher semantics as `egressPaths`).
   *    Default: every path.
   *  - `approver`: REQUIRED — 'self' (the acting user confirms their own action) or 'admin' (an
   *    eligible channel admin confirms; same gate as the channel-config commands).
   *  - `ttlMs`: how long a granted approval stays spendable. Default 5 minutes.
   */
  approval?: { methods?: string[]; paths?: string[]; approver: 'self' | 'admin'; ttlMs?: number };
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
  /** Escape hatch for non-standard revoke endpoints; takes precedence over `revokeUrl`.
   *  `signal` (GHSA-25m2) aborts at the revoke deadline — pass it to your fetch: the caller races
   *  the deadline regardless, but honoring the signal releases the socket instead of leaking it. */
  revoke?: (provider: Provider, token: string, signal?: AbortSignal) => Promise<void>;
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

/**
 * Whether Vouchr brokers a human credential for this provider (see Provider.identity). The ONE
 * predicate every "is this a user-connectable / user-listed tool" check imports (STR-2): 'service'
 * tools run on the host's own service auth — never a Vouchr connection, never a Connect prompt,
 * never advertised as connectable. Accepts anything carrying the manifest `identity` field too.
 */
export const isBrokeredProvider = (p: Pick<Provider, 'identity'>): boolean => p.identity !== 'service';

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
  /** Optional human-in-the-loop approval for sensitive writes (see Provider). */
  approval?: Provider['approval'];
}

/** The per-config injection-boundary gates (egress + rate limit + approval), passed through to a built-in. */
function egressOptions(cfg: ProviderConfig): Pick<Provider, 'egressPaths' | 'egressMethods' | 'egressValidate' | 'egressResponse' | 'rateLimit' | 'approval'> {
  return {
    egressPaths: cfg.egressPaths,
    egressMethods: cfg.egressMethods,
    egressValidate: cfg.egressValidate,
    egressResponse: cfg.egressResponse,
    rateLimit: cfg.rateLimit,
    approval: cfg.approval,
  };
}

/**
 * A canonical absolute pathname for an `approval.paths` (or egress) path lock: starts with '/' and
 * survives a WHATWG URL round-trip UNCHANGED, so it actually equals `url.pathname` at request time.
 * Rejects the fail-open forms 'repos' (no leading slash), ' /repos' (leading space), '/a b'
 * (re-encoded to '/a%20b' on parse). ONE rule, shared by defineProvider and the env loader (STR-2).
 */
export function isCanonicalPath(p: string): boolean {
  if (typeof p !== 'string' || !p.startsWith('/')) return false;
  try {
    return new URL(p, 'https://placeholder.invalid').pathname === p;
  } catch {
    return false;
  }
}

const ENCODED_PATH_SEPARATOR = /%2f|%5c/i;
const ENCODED_OCTET = /%[0-9a-f]{2}/i;
const MAX_PATH_DECODE_PASSES = 8;

/**
 * Whether one or more decoding passes can change a path's routing structure. A proxy and its
 * application may each decode once, so checking only literal `%2f`/`%5c` misses `%252f` and an
 * encoded `..` segment. Decode only for validation (the original bytes still go upstream), reject
 * malformed encodings, and fail closed when excessive nesting remains after the bounded loop.
 */
export function hasAmbiguousPathEncoding(path: string): boolean {
  let candidate = path;
  for (let pass = 0; pass < MAX_PATH_DECODE_PASSES; pass += 1) {
    if (ENCODED_PATH_SEPARATOR.test(candidate)) return true;
    let decoded: string;
    try {
      decoded = decodeURIComponent(candidate);
    } catch {
      return true;
    }
    if (decoded === candidate) return false;
    if (decoded.includes('\\') || decoded.split('/').some((segment) => segment === '.' || segment === '..')) {
      return true;
    }
    candidate = decoded;
  }
  return ENCODED_OCTET.test(candidate) || candidate.includes('%');
}

/**
 * Canonicalize an HTTP method token to trimmed upper-case, or null if it isn't a bare method name
 * (letters only). 'POST ' → 'POST' (normalized, matches); 'PO ST'/'PO#ST' → null (rejected). The
 * matcher (`approvalNeeded`) compares upper-case, so 'POST ' with its trailing space would otherwise
 * never match — a silent fail-open. ONE rule, shared by defineProvider and the env loader (STR-2).
 */
export function canonicalMethod(m: string): string | null {
  if (typeof m !== 'string') return null;
  const t = m.trim().toUpperCase();
  return /^[A-Z]+$/.test(t) ? t : null;
}

/**
 * Loopback hosts exempt from the https / explicit-port rules — the "test-only local path" carve-out
 * (#211): a mock OAuth server and a local dev broker bind `http://127.0.0.1:<port>`. The injector's
 * egress guard uses the SAME set (STR-2), so a provider's OAuth-endpoint carve-out and its API-egress
 * carve-out can never disagree about what "local" means. Any non-loopback host is held to https.
 */
// WHATWG parses an IPv6 host into a BRACKETED `url.hostname` (`new URL('http://[::1]/').hostname` ===
// '[::1]'), so the bracketed form is what actually appears at the comparison sites; the bare '::1' is
// kept too so a caller comparing an un-bracketed host still matches.
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);

/** One read-only query for the shared local-development carve-out; callers cannot widen the set. */
export function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname);
}

/**
 * The OAuth authorize-URL query parameters Vouchr OWNS and sets itself in `consent.begin`
 * (client_id, redirect_uri, scope, state, response_type, PKCE challenge). A provider's
 * `authorizeParams` must never carry one of these: overriding `state` or `redirect_uri` would
 * defeat the single-use CSRF `state` (SEC-2) or point the code at another origin. ONE list, so the
 * definition-time guard (below) and the render order in `consent.begin` agree by construction.
 */
const RESERVED_AUTHORIZE_PARAMS = new Set([
  'client_id', 'redirect_uri', 'scope', 'state', 'response_type', 'code_challenge', 'code_challenge_method',
]);

/**
 * A conservative provider-id rule (#211): the id is interpolated into the client-secret env key
 * (`providerEnvKey`), audit rows, and Slack mrkdwn — so it must be a short, boring token. Start with
 * an alphanumeric, then alphanumerics plus `.`/`_`/`-`, ≤ 63 chars. Rejects spaces, slashes, path
 * traversal, control chars, and unicode before any of those sinks ever sees the value.
 */
const PROVIDER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
export function isValidProviderId(id: string): boolean {
  return typeof id === 'string' && PROVIDER_ID_RE.test(id);
}

/**
 * Normalize a provider id to the client-secret env-key stem: upper-cased, every run of non-alnum
 * collapsed to `_` (so `github` → `GITHUB`, `a.b` → `A_B`). The env loader reads
 * `VOUCHR_PROVIDER_<stem>_CLIENT_ID/_SECRET`; because the collapse is lossy, two distinct ids can
 * map to the same stem and silently share a secret — which is why `assertNoProviderCollisions`
 * rejects that below. ONE derivation, shared by the loader and the collision check (STR-2).
 */
export function providerEnvKey(id: string): string {
  return id.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
}

/**
 * Assert a provider OAuth endpoint (authorizeUrl / tokenUrl / revokeUrl) is safe to send credentials
 * to (#211). The token exchange POSTs the auth code + refresh token + (confidential) client secret to
 * `tokenUrl`, and revoke POSTs the live token to `revokeUrl` — NEITHER is behind the injector's egress
 * https gate — so an `http://` or userinfo-bearing endpoint would leak them in cleartext. Require
 * https (loopback may use http for local testing), and reject embedded credentials, a fragment, and an
 * explicit port (the local loopback test carve-out may use one). Extracted from
 * databricks()'s inline host check so every entry point shares one rule (STR-2/STR-3). `label`
 * identifies the field in the error; the URL VALUE is never interpolated (it may carry a query).
 */
export function assertSafeHttpsUrl(raw: string, label: string): URL {
  let unsafeRawCharacter = false;
  if (typeof raw === 'string') {
    for (let i = 0; i < raw.length; i += 1) {
      const code = raw.charCodeAt(i);
      if (code <= 0x1f || code === 0x7f || code === 0x5c) {
        unsafeRawCharacter = true;
        break;
      }
    }
  }
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw || unsafeRawCharacter) {
    throw new Error(`${label} must be a valid URL.`);
  }
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`${label} must be a valid URL.`);
  }
  // WHATWG normalizes alternate IPv4 spellings, empty/default ports, empty userinfo
  // (`https://@host`), and an empty fragment (`#`) away. Inspect the raw authority/delimiters so
  // every accepted URL has one unambiguous spelling before we trust the parsed destination.
  const authority = raw.match(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/)?.[1] ?? '';
  if (authority.includes('@') || u.username || u.password) throw new Error(`${label} must not contain URL credentials (userinfo).`);
  if (raw.includes('#')) throw new Error(`${label} must not contain a URL fragment.`);
  let rawHost = authority;
  let rawPort: string | undefined;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    rawHost = close < 0 ? '' : authority.slice(0, close + 1);
    const suffix = close < 0 ? '' : authority.slice(close + 1);
    if (suffix) rawPort = suffix.startsWith(':') ? suffix.slice(1) : '';
  } else {
    const colon = authority.lastIndexOf(':');
    if (colon >= 0) {
      rawHost = authority.slice(0, colon);
      rawPort = authority.slice(colon + 1);
    }
  }
  let canonicalRawHost = '';
  try {
    canonicalRawHost = canonicalEgressHost(rawHost);
  } catch {
    throw new Error(`${label} must contain one canonical hostname.`);
  }
  if (canonicalRawHost !== u.hostname) throw new Error(`${label} must contain one canonical hostname.`);
  const loopback = isLoopbackHost(u.hostname);
  if (u.protocol !== 'https:' && !(loopback && u.protocol === 'http:')) {
    throw new Error(`${label} must use https (only loopback may use http for local testing).`);
  }
  if (rawPort !== undefined) {
    if (!/^\d+$/.test(rawPort) || String(Number(rawPort)) !== rawPort) {
      throw new Error(`${label} must specify a canonical numeric port.`);
    }
    if (!loopback) throw new Error(`${label} must not specify an explicit port.`);
  }
  return u;
}

/**
 * Validate the OAuth callback/redirect URL an adapter builds from `baseUrl` + `callbackPath` (#211).
 * It becomes the browser redirect_uri AND the token-exchange redirect_uri, so it inherits the same
 * https / no-userinfo / no-fragment safety as the provider endpoints (loopback may use http for local
 * dev), and it must stay WITHIN the base origin — a `callbackPath` that resolves off-origin (an
 * absolute URL) would point the authorization code at another host. ONE helper both adapters import
 * (STR-3), so the Bolt and headless callback surfaces enforce the same rule.
 */
export function assertCallbackUrl(baseUrl: string, redirectUri: string): void {
  const cb = assertSafeHttpsUrl(redirectUri, 'callback URL (baseUrl + callbackPath)');
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    throw new Error('baseUrl must be a valid URL.');
  }
  if (cb.origin !== base.origin) {
    throw new Error('callbackPath must resolve within the baseUrl origin (not an absolute off-origin URL).');
  }
}

/** Build the one canonical OAuth callback URL shared by Bolt and the headless broker. */
export function buildCallbackUrl(baseUrl: string, callbackPath: string): string {
  if (
    typeof callbackPath !== 'string' || !isCanonicalPath(callbackPath) ||
    callbackPath.includes('\\') || callbackPath.includes('%') ||
    !/^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)$/.test(callbackPath)
  ) {
    throw new Error('callbackPath must be one canonical absolute path with no query or fragment.');
  }
  const base = assertSafeHttpsUrl(baseUrl, 'baseUrl');
  if (base.pathname !== '/' || base.search || baseUrl.includes('?')) {
    throw new Error('baseUrl must be an origin with no path, query, or fragment.');
  }
  const redirectUri = `${base.origin}${callbackPath}`;
  assertCallbackUrl(base.origin, redirectUri);
  return redirectUri;
}

/**
 * Canonicalize + validate one egress-allowlist host (#211): it is compared raw against `url.hostname`
 * (already lower-cased by WHATWG) in the injector, so a mis-cased or decorated entry silently never
 * matches. Accept only a bare hostname — no scheme, userinfo, port, path, query, or fragment — and
 * return it lower-cased so `egressAllow.includes(url.hostname)` works regardless of how it was written.
 */
export function canonicalEgressHost(host: string, _id?: string): string {
  if (typeof host !== 'string' || !host.trim()) {
    throw new Error('Provider has an invalid egressAllow host: entries must be non-empty bare hostnames.');
  }
  let u: URL;
  try {
    u = new URL(`https://${host}`);
  } catch {
    throw new Error('Provider has an invalid egressAllow host: entries must be bare hostnames.');
  }
  const canonical = host.toLowerCase();
  const hostnameShape = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(canonical) || /^\[[0-9a-f:]+\]$/.test(canonical);
  if (
    !hostnameShape || canonical.includes('..') || u.username || u.password || u.port ||
    u.pathname !== '/' || u.search || u.hash || u.hostname !== canonical
  ) {
    throw new Error('Provider has an invalid egressAllow host: entries must not include a scheme, port, wildcard, or path.');
  }
  return u.hostname;
}

/**
 * Reject duplicate provider ids AND normalized env-key collisions across a provider set (#211). Two
 * ids that collapse to the same `providerEnvKey` (e.g. `a.b` and `a-b` → `A_B`) would silently share
 * one `VOUCHR_PROVIDER_A_B_CLIENT_SECRET`. ONE guard, imported by BOTH the registry (programmatic /
 * built-in registration) and the env loader (STR-2/STR-3) so neither path can register a colliding
 * pair the other would catch.
 */
export function assertNoProviderCollisions(providers: Pick<Provider, 'id'>[]): void {
  const seen = new Set<string>();
  const seenEnvKey = new Map<string, string>();
  for (const p of providers) {
    if (seen.has(p.id)) throw new Error('duplicate provider id.');
    seen.add(p.id);
    const ek = providerEnvKey(p.id);
    const clash = seenEnvKey.get(ek);
    if (clash) throw new Error('Provider ids derive the same client-secret env key.');
    seenEnvKey.set(ek, p.id);
  }
}

const PROVIDER_FIELDS = new Set([
  'id', 'credential', 'identity', 'authorizeUrl', 'tokenUrl', 'scopesDefault',
  'scopeDescriptions', 'egressAllow', 'egressPaths', 'egressMethods', 'egressValidate',
  'egressResponse', 'mcp', 'rateLimit', 'approval', 'inject', 'refresh', 'pkce',
  'authorizeParams', 'tokenAuth', 'bodyFormat', 'revokeUrl', 'revokeAuth', 'revoke',
  'clientId', 'clientSecret', 'publicClient', 'accountProbe',
]);
const MAX_PROVIDER_ITEMS = 128;
const MAX_PROVIDER_SCOPES = 48; // intro + one worst-case section per scope + actions = Slack's 50-block ceiling
const MAX_PROVIDER_TEXT = 512; // escaped mrkdwn worst case remains below one 3,000-character section

function providerError(field: string, requirement: string): never {
  throw new Error(`Provider field "${field}" ${requirement}.`);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function assertKnownKeys(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    providerError(field, 'contains an unknown key');
  }
}

function stringArray(value: unknown, field: string, allowEmpty = false): string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > MAX_PROVIDER_ITEMS) {
    providerError(field, allowEmpty ? 'must be a bounded array of strings' : 'must be a non-empty bounded array of strings');
  }
  const out = value.map((item) => {
    if (typeof item !== 'string' || !item.trim() || item.length > MAX_PROVIDER_TEXT) {
      providerError(field, 'must contain only non-empty bounded strings');
    }
    return item;
  });
  if (new Set(out).size !== out.length) providerError(field, 'must not contain duplicates');
  return out;
}

function optionalEnum(value: unknown, field: string, allowed: readonly string[], fallback: string): string {
  const resolved = value === undefined ? fallback : value;
  if (typeof resolved !== 'string' || !allowed.includes(resolved)) providerError(field, 'must be one of its supported values');
  return resolved;
}

function optionalBoolean(value: unknown, field: string, fallback = false): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') providerError(field, 'must be a boolean');
  return value;
}

function cloneStringRecord(value: unknown, field: string, allowEmptyValues: boolean): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  if (!isPlainRecord(value) || Object.keys(value).length > MAX_PROVIDER_ITEMS) {
    providerError(field, 'must be a bounded object of string values');
  }
  const out: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (!key.trim() || key.length > MAX_PROVIDER_TEXT || typeof raw !== 'string' || raw.length > MAX_PROVIDER_TEXT || (!allowEmptyValues && !raw.trim())) {
      providerError(field, 'must contain only non-empty bounded string keys and values');
    }
    out[key] = raw;
  }
  return out;
}

function contentTypes(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  const values = stringArray(value, field).map((entry) => entry.toLowerCase());
  if (values.some((entry) => !/^[!#$%&'*+.^_`|~0-9a-z-]+\/[!#$%&'*+.^_`|~0-9a-z-]+$/.test(entry))) {
    providerError(field, 'must contain only bare media types');
  }
  if (new Set(values).size !== values.length) providerError(field, 'must not contain duplicates after normalization');
  return values;
}

function canonicalMethods(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  const values = stringArray(value, field).map((entry) => {
    const method = canonicalMethod(entry);
    if (!method) providerError(field, 'must contain only bare HTTP method names');
    return method;
  });
  if (new Set(values).size !== values.length) providerError(field, 'must not contain duplicates after normalization');
  return values;
}

function canonicalPaths(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  const values = stringArray(value, field);
  if (values.some((entry) => !isCanonicalPath(entry) || hasAmbiguousPathEncoding(entry))) {
    providerError(field, 'must contain only unambiguous canonical absolute paths');
  }
  return values;
}

function freezeProvider(provider: Provider): Provider {
  for (const key of ['scopesDefault', 'egressAllow', 'egressPaths', 'egressMethods'] as const) {
    if (provider[key]) Object.freeze(provider[key]);
  }
  for (const key of ['scopeDescriptions', 'authorizeParams'] as const) {
    if (provider[key]) Object.freeze(provider[key]);
  }
  for (const key of ['egressResponse', 'mcp', 'rateLimit', 'approval'] as const) {
    const nested = provider[key] as Record<string, unknown> | undefined;
    if (!nested) continue;
    for (const value of Object.values(nested)) if (Array.isArray(value)) Object.freeze(value);
    Object.freeze(nested);
  }
  return Object.freeze(provider);
}

/** Normalize, validate, defensively copy, and freeze every provider registration path. */
export function defineProvider(spec: Provider): Provider {
  if (!isPlainRecord(spec)) providerError('provider', 'must be an object');
  if (Object.keys(spec).some((key) => !PROVIDER_FIELDS.has(key))) providerError('provider', 'contains an unknown field');
  if (!isValidProviderId(spec.id)) providerError('id', 'is invalid; use a conservative identifier of at most 63 characters');

  const credential = optionalEnum(spec.credential, 'credential', ['oauth', 'key'], 'oauth') as Provider['credential'];
  const identity = optionalEnum(spec.identity, 'identity', ['service', 'acting_human'], 'acting_human') as Provider['identity'];
  const refresh = optionalEnum(spec.refresh, 'refresh', ['rotating', 'static', 'none'], 'none') as RefreshStrategy;
  const tokenAuth = optionalEnum(spec.tokenAuth, 'tokenAuth', ['body', 'basic'], 'body') as NonNullable<Provider['tokenAuth']>;
  const bodyFormat = optionalEnum(spec.bodyFormat, 'bodyFormat', ['form', 'json'], 'form') as NonNullable<Provider['bodyFormat']>;
  const revokeAuth = optionalEnum(spec.revokeAuth, 'revokeAuth', ['none', 'body'], 'none') as NonNullable<Provider['revokeAuth']>;
  const pkce = optionalBoolean(spec.pkce, 'pkce');
  const publicClient = optionalBoolean(spec.publicClient, 'publicClient');

  const scopesDefault = stringArray(spec.scopesDefault === undefined ? [] : spec.scopesDefault, 'scopesDefault', true);
  if (scopesDefault.length > MAX_PROVIDER_SCOPES) providerError('scopesDefault', 'must fit the bounded consent surface');
  if (scopesDefault.some((scope) => scope.trim() !== scope)) providerError('scopesDefault', 'must contain canonical values without surrounding whitespace');
  // RFC 6749 `scope-token`: printable ASCII except DQUOTE and backslash. In particular, one array
  // item may not contain whitespace and silently turn into multiple grants when joined with spaces.
  if (scopesDefault.some((scope) => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))) {
    providerError('scopesDefault', 'must contain one OAuth scope token per item');
  }
  const scopeDescriptions = cloneStringRecord(spec.scopeDescriptions, 'scopeDescriptions', false);
  if (scopeDescriptions && Object.keys(scopeDescriptions).some((key) => key.trim() !== key)) {
    providerError('scopeDescriptions', 'must contain canonical keys without surrounding whitespace');
  }
  const authorizeParams = cloneStringRecord(spec.authorizeParams, 'authorizeParams', true);
  if (authorizeParams && Object.keys(authorizeParams).some((key) => key.trim() !== key)) {
    providerError('authorizeParams', 'must contain canonical keys without surrounding whitespace');
  }
  if (authorizeParams && Object.keys(authorizeParams).some((key) => RESERVED_AUTHORIZE_PARAMS.has(key.toLowerCase()))) {
    providerError('authorizeParams', 'must not contain a Vouchr-owned OAuth parameter');
  }

  const egressAllow = stringArray(spec.egressAllow, 'egressAllow').map((host) => canonicalEgressHost(host));
  if (new Set(egressAllow).size !== egressAllow.length) providerError('egressAllow', 'must not contain duplicates after normalization');
  let egressPaths: string[] | undefined;
  try {
    egressPaths = canonicalPaths(spec.egressPaths, 'egressPaths');
  } catch {
    throw new Error('Provider has an invalid egressPaths entry: use canonical absolute paths.');
  }
  let egressMethods: string[] | undefined;
  try {
    egressMethods = canonicalMethods(spec.egressMethods, 'egressMethods');
  } catch {
    throw new Error('Provider has an invalid egressMethods entry: use bare HTTP method names.');
  }

  let egressResponse: Provider['egressResponse'];
  if (spec.egressResponse !== undefined) {
    if (!isPlainRecord(spec.egressResponse)) providerError('egressResponse', 'must be an object');
    assertKnownKeys(spec.egressResponse, ['maxBytes', 'allowContentTypes', 'stripHeaders'], 'egressResponse');
    const maxBytes = spec.egressResponse.maxBytes;
    if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || (maxBytes as number) <= 0)) {
      throw new Error('Provider has an invalid egressResponse.maxBytes: it must be a positive safe integer.');
    }
    let allowContentTypes: string[] | undefined;
    try {
      allowContentTypes = contentTypes(spec.egressResponse.allowContentTypes, 'egressResponse.allowContentTypes');
    } catch {
      throw new Error('Provider has an invalid egressResponse.allowContentTypes: use bare media types.');
    }
    const stripHeaders = spec.egressResponse.stripHeaders === undefined
      ? undefined
      : stringArray(spec.egressResponse.stripHeaders, 'egressResponse.stripHeaders', true).map((header) => {
        try {
          new Headers().delete(header);
        } catch {
          throw new Error('Provider has an invalid egressResponse.stripHeaders entry: use valid header names.');
        }
        return header.toLowerCase();
      });
    egressResponse = { ...(maxBytes === undefined ? {} : { maxBytes: maxBytes as number }), ...(allowContentTypes ? { allowContentTypes } : {}), ...(stripHeaders ? { stripHeaders } : {}) };
  }

  let mcp: Provider['mcp'];
  if (spec.mcp !== undefined) {
    if (!isPlainRecord(spec.mcp)) providerError('mcp', 'must be an object');
    assertKnownKeys(spec.mcp, ['paths', 'allowContentTypes'], 'mcp');
    const paths = canonicalPaths(spec.mcp.paths, 'mcp.paths');
    if (!paths) providerError('mcp.paths', 'is required');
    const allowContentTypes = contentTypes(spec.mcp.allowContentTypes, 'mcp.allowContentTypes');
    mcp = { paths, ...(allowContentTypes ? { allowContentTypes } : {}) };
  }

  let rateLimit: Provider['rateLimit'];
  if (spec.rateLimit !== undefined) {
    if (!isPlainRecord(spec.rateLimit)) providerError('rateLimit', 'must be an object');
    assertKnownKeys(spec.rateLimit, ['perMinute', 'burst'], 'rateLimit');
    const { perMinute, burst } = spec.rateLimit;
    if (typeof perMinute !== 'number' || !Number.isFinite(perMinute) || perMinute <= 0) throw new Error('Provider has an invalid rateLimit: perMinute must be a finite number greater than zero.');
    if (burst !== undefined && (typeof burst !== 'number' || !Number.isFinite(burst) || burst <= 0)) throw new Error('Provider has an invalid rateLimit: burst must be a finite number greater than zero.');
    if ((burst ?? perMinute) < 1) throw new Error('Provider has an invalid rateLimit: capacity must admit at least one request.');
    rateLimit = { perMinute, ...(burst === undefined ? {} : { burst }) };
  }

  let approval: Provider['approval'];
  if (spec.approval !== undefined) {
    if (!isPlainRecord(spec.approval)) providerError('approval', 'must be an object');
    assertKnownKeys(spec.approval, ['methods', 'paths', 'approver', 'ttlMs'], 'approval');
    if (spec.approval.approver !== 'self' && spec.approval.approver !== 'admin') providerError('approval.approver', 'has an unsupported value');
    const methods = canonicalMethods(spec.approval.methods, 'approval.methods');
    const paths = canonicalPaths(spec.approval.paths, 'approval.paths');
    const ttlMs = spec.approval.ttlMs;
    if (ttlMs !== undefined && (!Number.isSafeInteger(ttlMs) || (ttlMs as number) <= 0)) providerError('approval.ttlMs', 'must be a positive safe integer');
    approval = { approver: spec.approval.approver, ...(methods ? { methods } : {}), ...(paths ? { paths } : {}), ...(ttlMs === undefined ? {} : { ttlMs: ttlMs as number }) };
  }

  for (const field of ['egressValidate', 'inject', 'revoke', 'accountProbe'] as const) {
    if (spec[field] !== undefined && typeof spec[field] !== 'function') providerError(field, 'must be a function when registered from code');
  }
  for (const field of ['authorizeUrl', 'tokenUrl', 'revokeUrl', 'clientId', 'clientSecret'] as const) {
    if (spec[field] !== undefined && typeof spec[field] !== 'string') providerError(field, 'must be a string');
  }

  const authorizeUrl = spec.authorizeUrl ?? '';
  const tokenUrl = spec.tokenUrl ?? '';
  if (spec.revokeUrl !== undefined && !spec.revokeUrl) providerError('revokeUrl', 'must be non-empty when set');
  if (spec.revokeUrl) assertSafeHttpsUrl(spec.revokeUrl, 'Provider revokeUrl');
  if (!spec.revokeUrl && revokeAuth !== 'none') providerError('revokeAuth', 'requires revokeUrl');

  if (credential === 'oauth') {
    assertSafeHttpsUrl(authorizeUrl, 'Provider authorizeUrl');
    assertSafeHttpsUrl(tokenUrl, 'Provider tokenUrl');
    if (!spec.clientId || (!publicClient && !spec.clientSecret)) {
      throw new Error('Provider is missing clientId/clientSecret configuration.');
    }
    if (publicClient) {
      if (!pkce) throw new Error('Provider public client configuration is invalid: PKCE is required.');
      if (tokenAuth === 'basic') throw new Error('Provider public client configuration is invalid: Basic token authentication is not supported.');
      if (spec.clientSecret) providerError('clientSecret', 'must be absent for a public client');
      if (revokeAuth === 'body') providerError('revokeAuth', 'cannot use client-secret body authentication for a public client');
    }
  } else if (publicClient) {
    providerError('publicClient', 'is only valid for OAuth providers');
  }
  if (revokeAuth === 'body' && (!spec.clientId || !spec.clientSecret)) providerError('revokeAuth', 'requires clientId and clientSecret');

  return freezeProvider({
    ...spec,
    credential,
    identity,
    authorizeUrl,
    tokenUrl,
    scopesDefault: [...scopesDefault],
    ...(scopeDescriptions ? { scopeDescriptions: { ...scopeDescriptions } } : { scopeDescriptions: undefined }),
    egressAllow: [...egressAllow],
    ...(egressPaths ? { egressPaths: [...egressPaths] } : { egressPaths: undefined }),
    ...(egressMethods ? { egressMethods: [...egressMethods] } : { egressMethods: undefined }),
    egressResponse,
    mcp,
    rateLimit,
    approval,
    refresh,
    pkce,
    ...(authorizeParams ? { authorizeParams: { ...authorizeParams } } : { authorizeParams: undefined }),
    tokenAuth,
    bodyFormat,
    revokeAuth,
    publicClient,
    clientSecret: publicClient ? undefined : spec.clientSecret,
  });
}

/** Deadline for a built-in userinfo probe (#209). A probe runs during the OAuth callback to label the
 *  stored credential; a hung provider endpoint must not stall the connect flow. Matches the token
 *  round-trip bound (`TOKEN_FETCH_TIMEOUT_MS` in tokens.ts) — the same class of trusted OAuth call. */
const PROBE_TIMEOUT_MS = 10_000;

/**
 * Shared implementation for the built-in `accountProbe`s (#209): ONE finite deadline and ONE
 * socket-release discipline for all providers, instead of four hand-rolled fetches. On a non-OK
 * response the unread body is cancelled (undici otherwise pins the socket to it until GC, #172) and
 * on any timeout / network throw the probe resolves to null — the account label is a nicety, never a
 * reason to fail or hang the connect flow. `pick` reads the display field from the parsed JSON.
 */
async function probeAccount(
  url: string,
  headers: Record<string, string>,
  pick: (json: any) => string | null,
): Promise<string | null> {
  let r: Response;
  try {
    r = await fetch(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
  } catch {
    return null; // timeout or network failure — treat as "account unknown", same as a non-OK probe
  }
  if (!r.ok) {
    r.body?.cancel().catch(() => undefined);
    return null;
  }
  try {
    return pick(await r.json());
  } catch {
    r.body?.cancel().catch(() => undefined);
    return null;
  }
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
    revoke: async (p, token, signal) => {
      const creds = Buffer.from(`${p.clientId}:${p.clientSecret}`).toString('base64');
      const r = await fetch(`https://api.github.com/applications/${encodeURIComponent(p.clientId!)}/token`, {
        method: 'DELETE',
        redirect: 'manual',
        headers: {
          Authorization: `Basic ${creds}`,
          Accept: 'application/vnd.github+json',
          'Content-Type': 'application/json',
          'User-Agent': 'vouchr',
        },
        body: JSON.stringify({ access_token: token }),
        signal, // GHSA-25m2: a hung revoke endpoint must not stall offboarding
      });
      if (!r.ok && r.status !== 404) throw new Error(`GitHub token revoke returned HTTP ${r.status}`); // 404 = already gone
    },
    accountProbe: (token) =>
      probeAccount('https://api.github.com/user', { Authorization: `Bearer ${token}`, 'User-Agent': 'vouchr' }, (j) => j.login ?? null),
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
    accountProbe: (token) =>
      probeAccount('https://www.googleapis.com/oauth2/v2/userinfo', { Authorization: `Bearer ${token}` }, (j) => j.email ?? null),
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
    accountProbe: (token) =>
      probeAccount('https://gitlab.com/api/v4/user', { Authorization: `Bearer ${token}` }, (j) => j.username ?? null),
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
    accountProbe: (token) =>
      probeAccount(
        'https://api.notion.com/v1/users/me',
        { Authorization: `Bearer ${token}`, 'Notion-Version': '2022-06-28' },
        (j) => j?.bot?.owner?.user?.name ?? j?.name ?? null,
      ),
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
    approval: cfg.approval, // databricks builds its fields by hand (no egressOptions spread), so thread it explicitly
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
    // The registry is a public registration path, so it must not trust callers to have used the
    // factory. Re-normalize every input, then retain only frozen defensive copies: mutating either
    // the original object or a nested allowlist after registration cannot widen live egress.
    if (!Array.isArray(providers) || providers.length > MAX_PROVIDER_ITEMS) {
      providerError('providers', 'must be a bounded array');
    }
    const normalized = providers.map((provider) => defineProvider(provider));
    assertNoProviderCollisions(normalized);
    for (const provider of normalized) this.map.set(provider.id, provider);
  }
  get(id: string): Provider {
    const p = this.map.get(id);
    if (!p) {
      throw new Error('Unknown provider.');
    }
    return p;
  }
  has(id: string): boolean {
    return this.map.has(id);
  }
}
