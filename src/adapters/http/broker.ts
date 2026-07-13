import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { assertSchemaCurrent, type Db } from '../../core/db';
import type { Vault } from '../../core/vault';
import type { Audit, AuditSink } from '../../core/audit';
import type { Policy } from '../../core/policy';
import type { ChannelTools } from '../../core/tools';
import { ProviderRegistry, isBrokeredProvider, buildCallbackUrl, hasAmbiguousPathEncoding, type Provider } from '../../core/providers';
import { ConnectionHandle, EgressBlockedError, NoConnectionError, ResponseBlockedError, normalizeContentType, pathAllowed, DEFAULT_FETCH_DEADLINE_MS, type Resolvers, type EventSink, type VouchrEvent } from '../../core/injector';
import { MemoryRateLimitStore, RateLimitedError, type RateLimitStore } from '../../core/rateLimit';
import { assertInflightLimits, InflightLimiter, OverloadedError } from '../../core/inflight';
import { MAX_TIMER_MS } from '../../core/options';
import { awaitWithSignal, disposableDeadline } from '../../core/httpBounds';
import { safeEmit } from '../../core/safe-emit';
import type { CredentialHealthHook } from '../../core/health';
import { userOwner, channelOwner, type Owner } from '../../core/owner';
import { isChannelMode, type ChannelConfig, type ChannelMode } from '../../core/channelConfig';
import {
  authorizeProvider,
  resolveCredentialOwner,
  buildToolManifest,
  snapshotChannelModes,
  snapshotToolAllowlist,
} from '../../core/authz';
import type { SlackIdentity } from '../../core/identity';
import { Consent } from '../../core/consent';
import { SessionGrants } from '../../core/session';
import { Approvals, ApprovalRequiredError } from '../../core/approval';
import { disconnectProvider, offboardUser, offboardUserEverywhere } from '../../core/offboard';
import { assertDryRunFlag, assertDryRunLocalKey, assertDryRunVault, DryRunVaultError, dryRunAudit } from '../../core/dryRun';
import { handleOAuthCallback } from '../../core/oauthCallback';
import { verifyIdentity, IdentityError, normalizeIdentityConfig, assertIdentityPurposeDistinct, type IdentityClaims, type IdentityConfig } from './identity';
import { DbReplayStore } from './replayStore';
import type { BrokerAdminOkResponse, BrokerAdminConfigResponse, BrokerAuditResponse, BrokerChannelManifestResponse } from '../../broker-types';

/**
 * The opaque, NO-SECRET handle the caller holds. It names a provider; the owner is always the acting
 * user from the verified identity token, never this handle — so the handle can be forged without
 * granting any cross-tenant access.
 *
 * `owner: 'channel'` (#51) is a transport-agnostic channel gate: the broker still has no Slack client,
 * so the trusted caller supplies the Slack-derived facts (channel eligibility) as SIGNED claims and
 * the broker resolves the credential owner from those claims, never from this handle.
 * It stays fail-closed: a deployer must opt in with `BrokerOptions.channelConfig`, and the signed
 * `ownerKind` must match this field or the request is refused (a forged body `owner:'channel'` alone
 * can't reach a channel credential). See `resolveOwner`.
 */
export interface ConnectionHandleRef {
  provider: string;
  owner: 'user' | 'channel';
}

export interface BrokerFetchRequest {
  handle: ConnectionHandleRef;
  identityToken: string; // caller-minted, HS256-signed; broker verifies (see identity.ts)
  method: string;
  path: string; // appended to the provider host; the injector enforces the egress allowlist
  host?: string; // optional pick among a multi-host provider; defaults to egressAllow[0]
  query?: Record<string, string>;
  headers?: Record<string, string>; // allowlisted; Authorization is dropped (broker injects)
  body?: string; // optional small write payload; capped before forwarding
}

/**
 * #65 `POST /v1/mcp` request: the /v1/fetch envelope, specialized for ONE MCP Streamable-HTTP hop.
 * The upstream method is always POST (a JSON-RPC message), and `headers` admits only the MCP
 * plumbing set (Accept, Content-Type, Mcp-Session-Id, MCP-Protocol-Version) — everything else,
 * Authorization above all, is stripped exactly like /v1/fetch. Mint a FRESH `identityToken` per
 * JSON-RPC call: each token is single-use (replay guard), so the host's MCP transport signs one
 * per request — the broker itself holds no MCP session state.
 */
export interface BrokerMcpRequest {
  handle: ConnectionHandleRef;
  identityToken: string; // caller-minted, HS256-signed, single-use; broker verifies (see identity.ts)
  path: string; // the provider's MCP endpoint path, appended to the host; egress-allowlisted
  host?: string; // optional pick among a multi-host provider; defaults to egressAllow[0]
  headers?: Record<string, string>; // MCP plumbing allowlist only; Authorization is dropped (broker injects)
  body: string; // the JSON-RPC message, forwarded verbatim (capped like /v1/fetch write bodies)
}

export interface BrokerOptions {
  providers: Provider[];
  vault: Vault;
  audit: Audit;
  /** Used by /readyz to confirm the store and replay table are reachable. */
  db: Db;
  /**
   * Deployment-bound HS256 trust config shared ONLY by the upstream minter and this broker. The
   * packaged broker builds it from env via `loadIdentityConfig`; createBroker defensively normalizes
   * and freezes custom configs. Bare legacy secrets are rejected on this production boundary.
   */
  identitySecret: IdentityConfig;
  /**
   * #52 public HTTPS origin of THIS broker (e.g. `https://broker.example`). Setting it MOUNTS the OAuth
   * connect flow: `POST /v1/connect` (mint an authorize URL for the verified user) and
   * `GET <callbackPath>` (the provider redirect target). Unset → neither route mounts (additive; the
   * historical use-only broker is unchanged). The `redirectUri` handed to providers is the public
   * origin plus one validated canonical absolute callback pathname.
   */
  baseUrl?: string;
  /** #52 canonical absolute OAuth redirect pathname mounted under `baseUrl`. Default `/oauth/callback`. */
  callbackPath?: string;
  /**
   * Pluggable store for the per-(owner, provider) token buckets behind `provider.rateLimit`. Default
   * is in-memory per-process: a fleet of N broker replicas multiplies the effective limit by N —
   * supply a shared store for cluster-wide limits. Providers without `rateLimit` are never limited.
   * A limited /v1/fetch maps to 429 with a Retry-After header.
   */
  rateLimitStore?: RateLimitStore;
  resolvers?: Resolvers;
  /**
   * No-secret observability sink (the SAME EventSink the Bolt path uses). Without it the broker is an
   * operational black box: injected.ms / kms_decrypt / refreshed.ms / egress_denied.reason never fire.
   * Fire-and-forget; a throwing sink can never affect a request (ConnectionHandle swallows it).
   */
  onEvent?: EventSink;
  /**
   * Optional audit STREAM sink for host-side ingestion. Fires IN ADDITION to the authoritative
   * `audit` table on each /v1/fetch (action 'fetch') and on the refresh path. Unlike `onEvent`
   * (deliberately actor-free), it carries the RAW acting user id from the VERIFIED claims so a host
   * can answer "who used this token, when, against which host". This is the canonical host-side
   * ingestion surface (host != broker). Lossy by design; the table stays the source of truth. A
   * throwing sink can never affect a request (ConnectionHandle swallows it). No-op when unset.
   */
  auditSink?: AuditSink;
  /**
   * Operator authorization, identical to the Bolt path (#21/#22). When set, /v1/fetch enforces
   * `policy.check(provider, channel)` before injecting a credential; the channel comes from the
   * VERIFIED identity claims, never the request body. Unset = allow-all (same as a no-rule Policy).
   */
  policy?: Policy;
  /**
   * Per-channel tool allowlist, identical to the Bolt path. When set, /v1/fetch enforces
   * `channelTools.isEnabled(teamId, channel, provider)` (backward-compat: an unconfigured channel
   * allows all). Unset = no tool gate.
   */
  channelTools?: ChannelTools;
  /**
   * #51 transport-agnostic channel gate. Setting this ENABLES `owner: 'channel'` handles; unset keeps
   * the historical user-only broker (any `owner:'channel'` request is refused). The store resolves the
   * channel's mode (`shared` → the channel credential, audited as the acting human). Owner + eligibility
   * come ONLY from the signed identity claims, never the request body — so a forged body cannot assert a
   * channel credential.
   */
  channelConfig?: ChannelConfig;
  /**
   * #51 fail-closed eligibility. When true (default), a `owner:'channel'` request is refused unless the
   * SIGNED `channelEligible` claim is true — the caller must have computed `channelIneligibleReason()`
   * and signed the verdict. Set false ONLY if eligibility is enforced entirely upstream of the broker.
   */
  requireChannelEligibility?: boolean;
  /**
   * @deprecated Inert no-op, retained only for TypeScript API compatibility (the package is
   * published; consumers still passing it must keep compiling). Superseded by `allowWrites`, which
   * governs the write path. Setting this has NO runtime effect.
   */
  defaultDenyNonGet?: boolean;
  /**
   * Opt-in broker write path. Default false keeps the historical GET/HEAD-only broker behavior.
   * When true, non-GET/HEAD requests are still allowed only for providers with explicit
   * `egressMethods`; providers with no method allowlist remain GET/HEAD-only.
   */
  allowWrites?: boolean;
  /** #26 content-type allowlist (lower-cased, charset-stripped match). Default application/json. */
  allowedContentTypes?: string[];
  /** #26 response size cap in bytes; over-cap is rejected 413, never truncated. Default 1 MiB.
   * Must be a positive safe integer. */
  maxResponseBytes?: number;
  /**
   * #65 /v1/mcp streamed-response byte ceiling. Unlike /v1/fetch's whole-body `maxResponseBytes`,
   * an SSE stream has no end to buffer to, so this is counted WHILE relaying and the stream is
   * TERMINATED when exceeded (upstream fetch aborted, client socket destroyed — never a clean end,
   * so a truncation can't masquerade as a complete response). If the provider also sets
   * `egressResponse.maxBytes` (#110), the stricter of the two effectively applies — but the injector
   * enforces the provider cap by buffering up to it before the relay starts, so leave it unset on
   * streaming (SSE) providers and rely on this ceiling. Default 8 MiB. Must be a positive safe
   * integer (validated at createBroker — a NaN/Infinity cap would silently fail open).
   */
  maxStreamBytes?: number;
  /**
   * #65 /v1/mcp stream duration ceiling: a timer aborts the upstream fetch (and thereby the relay)
   * when one request's response runs longer than this. Default 5 minutes. Must be a positive safe
   * integer no greater than Node's 2,147,483,647ms timer ceiling.
   */
  maxStreamMs?: number;
  /**
   * #209 wall-clock deadline for a /v1/fetch upstream request (headers AND body). A hung provider
   * must not hold a request — a timer aborts the upstream fetch and, composed with client disconnect,
   * releases the provider socket. /v1/mcp uses maxStreamMs instead (streams run longer). Default 30s.
   * Must be a positive safe integer no greater than Node's 2,147,483,647ms timer ceiling.
   */
  fetchDeadlineMs?: number;
  /**
   * #209 per-broker GLOBAL in-flight ceiling: every functional HTTP request is admitted before async
   * perimeter authorization or body buffering and held through response finish/close. Liveness is
   * exempt; readiness collapses concurrent DB probes into one shared flight. Over the ceiling, work is
   * refused 503 + Retry-After. NOT a rate limit (that's provider.rateLimit, requests-per-window).
   * Packaged deployment runs one broker per process, so fleet capacity is replicas × this. Default
   * 200. Must be a positive safe integer.
   */
  maxInflight?: number;
  /**
   * #209 per-PROVIDER in-flight ceiling: the max concurrent upstream requests for any single provider,
   * so one slow provider can't consume the whole global budget. Over it → 503 + Retry-After. Default
   * 40. Must be a positive safe integer and ≤ maxInflight (validated at createBroker).
   */
  maxInflightPerProvider?: number;
  /**
   * #209 inbound server timeouts (ms), set on the http.Server. `headersTimeoutMs` bounds how long a
   * client may take to send request headers; `requestTimeoutMs` bounds the whole request (headers +
   * body) — a slow-loris drip is cut here; `keepAliveTimeoutMs` bounds an idle keep-alive socket.
   * Defaults 15s / 30s / 10s. Each must be a positive safe integer no greater than Node's
   * 2,147,483,647ms timer ceiling; requestTimeoutMs must be ≥ headersTimeoutMs.
   */
  headersTimeoutMs?: number;
  requestTimeoutMs?: number;
  keepAliveTimeoutMs?: number;
  /**
   * Optional coarse network gate (a shared `Authorization: Bearer <token>` on /v1/*). This is a
   * perimeter check ONLY, NOT identity — identity comes from the signed token. Documented per #22.
   */
  brokerToken?: string;
  /**
   * Optional pluggable perimeter check on /v1/* requests, called BEFORE identity verification. Throw
   * to reject (a thrown HttpError maps to its status; anything else → 401). Use this when the static
   * `brokerToken` cannot express your perimeter — e.g. a rotating per-request service token
   * (serviceauth/SPIFFE) read fresh from a mounted file, or a JWKS-validated caller assertion. When
   * set it REPLACES the static `brokerToken` gate. Still NOT identity — the signed `identityToken`
   * remains the only source of user claims. The optional signal is aborted when the client leaves;
   * Vouchr races it even for legacy hooks that ignore the signal, while cooperative hooks should use
   * it to cancel their own I/O. Keeps deployer-specific auth out of `src/`.
   */
  authorize?: (req: http.IncomingMessage, signal?: AbortSignal) => void | Promise<void>;
  /**
   * #117 credential-health hook: fired on a DEFINITIVELY dead refresh (`refresh_dead` — invalid_grant
   * or a bare 400/401 from the token endpoint, never a transient blip; see TokenEndpointError for
   * the exact classification). There is no Slack client here, so
   * headless deployments wire their own notifier; events carry the owning principal + provider,
   * never token material. Debounce with the exported `NotificationState`: `claim()` the 24h window
   * atomically (one winner per (owner, provider, type), cluster-wide on a shared Postgres), send,
   * `release()` on a failed send; reconnect and delete clear it. Pass the same hook to
   * `sweepExpired` to also get `expiring_soon`/`expired`. Fire-and-forget; a throwing or
   * async-rejecting hook never affects a request.
   */
  onCredentialHealth?: CredentialHealthHook;
  /**
   * #116 dry-run: identical semantics to `VouchrOptions.dryRun` — every gate runs for real, and NO
   * real network call leaves the process (outbound fetch, token exchange, refresh, and upstream
   * revoke are all stubbed or skipped). `/v1/connect` mints an authorize URL that points at THIS
   * broker's own callback (requires `baseUrl`), so a test client completes consent by simply
   * GETting it — the callback consumes the single-use state and writes a synthetic credential
   * marked `external_account: 'dry-run'`. `/v1/fetch` then runs policy, tool, owner, and egress
   * gates, reads the (synthetic) credential from the vault, and returns a
   * `200 { dryRun, method, url, wouldInjectAs }` echo instead of calling the provider; request-side
   * denials map to the same errors as production. The vault safety check runs asynchronously
   * (createBroker is sync): every request fails closed until it passes, the packaged broker
   * (`vouchr-broker`, `VOUCHR_DRY_RUN=1`) additionally hard-fails at boot, and a real row written
   * AFTER boot is refused per-request (never injected, never overwritten). Audit rows carry
   * `meta.dry_run: true`. Default false: zero behavior change.
   */
  dryRun?: boolean;
}

const DEFAULT_ALLOWED_CT = ['application/json'];
const DEFAULT_MAX_BYTES = 1024 * 1024;
const READ_REQUEST_CAP = 64 * 1024; // read envelopes are tiny; reject anything larger.
const WRITE_BODY_CAP = 64 * 1024;
const WRITE_REQUEST_CAP = WRITE_BODY_CAP + READ_REQUEST_CAP;
// #65 /v1/mcp stream ceilings (see BrokerOptions.maxStreamBytes / maxStreamMs).
const DEFAULT_MAX_STREAM_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_STREAM_MS = 5 * 60_000;
// #209 in-flight ceilings and inbound server timeouts (see BrokerOptions for each). In-process by
// design: fleet capacity is replicas × DEFAULT_MAX_INFLIGHT (guides/DEPLOYMENT.md).
const DEFAULT_MAX_INFLIGHT = 200;
const DEFAULT_MAX_INFLIGHT_PER_PROVIDER = 40;
const DEFAULT_HEADERS_TIMEOUT_MS = 15_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_KEEPALIVE_TIMEOUT_MS = 10_000;
// #65 default RESPONSE media types for /v1/mcp when `provider.mcp.allowContentTypes` is unset —
// the two MCP Streamable-HTTP transport types. Anything else is withheld unread (see handleMcp).
const DEFAULT_MCP_ALLOWED_CT = ['application/json', 'text/event-stream'];

export interface BrokerResourceBounds {
  fetchDeadlineMs: number;
  maxResponseBytes: number;
  maxStreamBytes: number;
  maxStreamMs: number;
  maxInflight: number;
  maxInflightPerProvider: number;
  headersTimeoutMs: number;
  requestTimeoutMs: number;
  keepAliveTimeoutMs: number;
}

export type BrokerResourceBoundsInput = Partial<Pick<
  BrokerOptions,
  | 'fetchDeadlineMs'
  | 'maxResponseBytes'
  | 'maxStreamBytes'
  | 'maxStreamMs'
  | 'maxInflight'
  | 'maxInflightPerProvider'
  | 'headersTimeoutMs'
  | 'requestTimeoutMs'
  | 'keepAliveTimeoutMs'
>>;

/**
 * Normalize every broker-owned byte, concurrency, and timer bound before any server, timer, socket,
 * or database pool is acquired. The packaged server calls this pure helper while parsing boot config;
 * createBroker calls it again as the public runtime boundary. One validator therefore owns defaults,
 * safe-integer rules, Node's timer ceiling, and cross-field relationships (STR-2).
 */
export function normalizeBrokerResourceBounds(input: BrokerResourceBoundsInput): BrokerResourceBounds {
  const positiveSafeInteger = (name: string, value: number, max = Number.MAX_SAFE_INTEGER): number => {
    if (!Number.isSafeInteger(value) || value <= 0 || value > max) {
      throw new Error(`createBroker: invalid ${name}: must be a positive safe integer no greater than ${max}.`);
    }
    return value;
  };
  const timer = (name: string, value: number): number => positiveSafeInteger(name, value, MAX_TIMER_MS);

  const maxInflight = input.maxInflight ?? DEFAULT_MAX_INFLIGHT;
  const maxInflightPerProvider = input.maxInflightPerProvider
    ?? Math.min(DEFAULT_MAX_INFLIGHT_PER_PROVIDER, maxInflight);
  assertInflightLimits(maxInflight, maxInflightPerProvider, 'createBroker');

  const headersTimeoutMs = timer('headersTimeoutMs', input.headersTimeoutMs ?? DEFAULT_HEADERS_TIMEOUT_MS);
  const requestTimeoutMs = timer('requestTimeoutMs', input.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);
  if (requestTimeoutMs < headersTimeoutMs) {
    throw new Error('createBroker: requestTimeoutMs must be >= headersTimeoutMs.');
  }

  return Object.freeze({
    fetchDeadlineMs: timer('fetchDeadlineMs', input.fetchDeadlineMs ?? DEFAULT_FETCH_DEADLINE_MS),
    maxResponseBytes: positiveSafeInteger('maxResponseBytes', input.maxResponseBytes ?? DEFAULT_MAX_BYTES),
    maxStreamBytes: positiveSafeInteger('maxStreamBytes', input.maxStreamBytes ?? DEFAULT_MAX_STREAM_BYTES),
    maxStreamMs: timer('maxStreamMs', input.maxStreamMs ?? DEFAULT_MAX_STREAM_MS),
    maxInflight,
    maxInflightPerProvider,
    headersTimeoutMs,
    requestTimeoutMs,
    keepAliveTimeoutMs: timer('keepAliveTimeoutMs', input.keepAliveTimeoutMs ?? DEFAULT_KEEPALIVE_TIMEOUT_MS),
  });
}
// The tiny per-route REQUEST header allowlists — everything else (Authorization above all) is
// stripped; the broker injects the credential itself. /v1/mcp adds the two Mcp-* session-plumbing
// headers (opaque and POTENTIALLY SENSITIVE per MCP security guidance: relayed verbatim, never
// stored or logged, never accepted as authentication) and keeps Accept + Content-Type because MCP
// Streamable HTTP requires `Accept: application/json, text/event-stream`.
const FETCH_FORWARD_HEADERS = ['accept', 'accept-language', 'if-none-match', 'content-type'];
const MCP_FORWARD_HEADERS = ['accept', 'content-type', 'mcp-session-id', 'mcp-protocol-version'];
// RESPONSE headers /v1/mcp relays back (content-type so SSE parses; the Mcp-* plumbing so the
// session id round-trips). Everything else is dropped; set-cookie was already stripped by the
// injector's guardResponse before the broker ever sees the response.
const MCP_RETURN_HEADERS = ['content-type', 'mcp-session-id', 'mcp-protocol-version'];

class HttpError extends Error {
  constructor(
    public status: number,
    public payload: Record<string, unknown>,
    /** Extra response headers (e.g. Retry-After on a 429). Non-secret values only. */
    public headers?: Record<string, string>,
    /** Refuse reuse when the request body crossed a cap or was rejected before it was consumed. */
    public closeConnection = false,
  ) {
    super(typeof payload.error === 'string' ? payload.error : 'error');
  }
}

/** #25: default-deny realized in the adapter (core stays unchanged): set GET/HEAD when unset. */
export function withEgressDefaults(p: Provider, defaultDenyNonGet?: boolean): Provider {
  if (defaultDenyNonGet && !p.egressMethods) return { ...p, egressMethods: ['GET', 'HEAD'] };
  return p;
}

function requestMethod(method: unknown): string {
  return typeof method === 'string' ? method.toUpperCase() : '';
}

function requestBody(body: unknown): string | undefined {
  if (body == null) return undefined;
  if (typeof body !== 'string') throw new HttpError(400, { error: 'invalid body' });
  if (Buffer.byteLength(body, 'utf8') > WRITE_BODY_CAP) {
    throw new HttpError(413, { error: 'request body too large' });
  }
  return body;
}

/** Escape for HTML text context — the OAuth landing page interpolates provider/account/error, and
 *  `error`/`account` are attacker- or provider-influenced, so this is a reflected-XSS guard (#52). */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

/** Minimal browser landing page for the OAuth callback (headless has no chat surface to nudge back to).
 *  Escapes `title`/`body` INTERNALLY (reflected-XSS guard #52) so callers pass raw values and a future
 *  caller can't reintroduce the vuln by forgetting to escape. Exported for the escaping regression test.
 *  @internal */
export function landingHtml(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"></head><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center"><h2>${escapeHtml(title)}</h2><p>${escapeHtml(body)}</p></body></html>`;
}

function responseHasNoBody(res: Response): boolean {
  const contentLength = res.headers.get('content-length');
  return res.status === 204 || res.status === 205 || (contentLength != null && Number(contentLength) === 0);
}

async function readJson(req: http.IncomingMessage, cap = READ_REQUEST_CAP): Promise<any> {
  // #209 fast-reject an oversize body on its declared Content-Length, before reading a single chunk —
  // a lying/absent header still can't get past the streamed byte counter below (fail-closed).
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > cap) {
    throw new HttpError(413, { error: 'request body too large' }, undefined, true);
  }
  const chunks: Buffer[] = [];
  let total = 0;
  // Do not let an early over-cap return make Readable's default async iterator destroy the socket
  // before the broker can send its stable 413. The error path marks Connection: close explicitly.
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    total += chunk.length;
    if (total > cap) throw new HttpError(413, { error: 'request body too large' }, undefined, true);
    chunks.push(chunk as Buffer);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, { error: 'invalid JSON body' });
  }
}

/** Read the upstream body with a hard cap. Over-cap throws 413 — never returns a truncated partial. */
async function readCapped(res: Response, cap: number): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > cap) {
    await res.body?.cancel().catch(() => undefined);
    throw new HttpError(413, { error: 'response too large; narrow your query or endpoint' });
  }
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > cap) {
      await reader.cancel().catch(() => undefined);
      throw new HttpError(413, { error: 'response too large; narrow your query or endpoint' });
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** W3C trace-context headers present on the incoming request, lower-cased; empty when none sent. */
function traceHeaders(req: http.IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const h of ['traceparent', 'tracestate']) {
    const v = req.headers[h];
    if (typeof v === 'string' && v) out[h] = v;
  }
  return out;
}

/** Build the outbound provider URL from the request envelope: default host = egressAllow[0]; the
 *  injector still enforces the egress allowlist on whatever comes out. Caller input -> 4xx, not 500.
 *  Shared by /v1/fetch and /v1/mcp (STR-3). */
function buildTargetUrl(provider: Provider, body: { host?: string; path?: string; query?: Record<string, string> }): URL {
  const host = body.host ?? provider.egressAllow[0];
  let url: URL;
  try {
    url = new URL(`https://${host}${body.path ?? '/'}`);
  } catch {
    throw new HttpError(400, { error: 'invalid host or path' });
  }
  for (const [k, v] of Object.entries(body.query ?? {})) url.searchParams.set(k, v);
  return url;
}

/** Forward only an allowlisted set of caller headers (case-insensitive match, original casing kept);
 *  never the caller's Authorization — the broker injects the credential itself. */
function pickHeaders(headers: Record<string, string> | undefined, allow: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) {
    if (allow.includes(k.toLowerCase())) out[k] = v;
  }
  return out;
}

/**
 * Map a ConnectionHandle.fetch throw to its HTTP error — ONE mapping shared by /v1/fetch and
 * /v1/mcp (STR-3), so the two egress doors can't drift. Typed classes, not a message regex. The
 * matching no-secret event + audit row already fired inside the injector before each throw, so
 * mapping here swallows nothing:
 *  - EgressBlockedError → 403 (allowlist/policy gate refused the target BEFORE any secret was read)
 *  - ApprovalRequiredError → 403 `{ error: 'approval_required', approvalId }` (#113). The broker
 *    cannot render Approve/Deny buttons, so the approval SURFACE stays the Bolt app: the caller's
 *    Slack-facing service routes the human there, then retries. The id is the pending-approval
 *    handle, not a secret and not authority (eligibility is re-checked at the click).
 *  - NoConnectionError → 409 (no stored credential for this owner+provider)
 *  - ResponseBlockedError → 413 over-cap / 502 disallowed type (provider.egressResponse withheld
 *    the response); the static message never carries the offending header value or body
 *  - RateLimitedError → 429 + Retry-After (whole seconds, rounded up; retryAfterMs rides the
 *    payload for callers that want ms precision)
 *  - anything else → 502 upstream fetch failed
 */
function mapUpstreamError(e: unknown): never {
  if (e instanceof EgressBlockedError) throw new HttpError(403, { error: 'egress blocked' });
  if (e instanceof ApprovalRequiredError) throw new HttpError(403, { error: 'approval_required', approvalId: e.approvalId });
  if (e instanceof NoConnectionError) throw new HttpError(409, { error: 'not connected' });
  if (e instanceof ResponseBlockedError) {
    throw new HttpError(e.reason === 'size' ? 413 : 502, { error: 'response blocked' });
  }
  if (e instanceof RateLimitedError) {
    throw new HttpError(429, { error: 'rate limited', retryAfterMs: e.retryAfterMs }, { 'retry-after': String(Math.ceil(e.retryAfterMs / 1000)) });
  }
  throw new HttpError(502, { error: 'upstream fetch failed' });
}

function isTimeoutError(error: unknown): boolean {
  return error instanceof Error && error.name === 'TimeoutError';
}

/**
 * #65 Relay an upstream MCP response to the caller AS-IS: upstream status, the MCP plumbing
 * headers (MCP_RETURN_HEADERS), and the body STREAMED through — never buffered — so
 * text/event-stream works. Every gate (identity, replay, policy, egress, write opt-ins) already ran
 * before the first byte flows; the only enforcement left here is the byte ceiling: a counting
 * Transform errors the pipeline past `capBytes`, which aborts upstream and DESTROYS the client
 * socket — headers are long flushed, so a truncated stream must look like a transport failure,
 * never a clean end. The maxStreamMs timer and a client disconnect surface here the same way: the
 * shared AbortController rejects the read and the catch tears the stream down.
 */
async function relayMcpResponse(upstream: Response, res: http.ServerResponse, abort: AbortController, capBytes: number): Promise<void> {
  const headers: Record<string, string> = {};
  for (const h of MCP_RETURN_HEADERS) {
    const v = upstream.headers.get(h);
    if (v != null) headers[h] = v;
  }
  let total = 0;
  const cap = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      total += chunk.length;
      // Over-cap: error the pipeline WITHOUT forwarding the overflowing chunk (the caller never
      // receives a byte past the ceiling). Abort before pipeline tears down its source: that
      // propagates cancellation through the injector's composed signal to the actual fetch rather
      // than relying only on Web-stream cancellation to free the upstream socket.
      if (total > capBytes) {
        abort.abort(new DOMException('stream ceiling exceeded', 'AbortError'));
        cb(new Error('stream ceiling exceeded'));
      } else cb(null, chunk);
    },
  });
  try {
    // writeHead sits INSIDE the try: a client that vanished between the upstream fetch resolving
    // and headers flushing (or an upstream header value writeHead refuses) belongs to THIS
    // teardown path — rethrowing to the outer catch would attempt a second writeHead.
    res.writeHead(upstream.status, headers);
    if (!upstream.body) {
      res.end();
      return;
    }
    // The abort signal is wired into the RELAY itself (not just the upstream fetch), so the
    // maxStreamMs timer / client disconnect terminate the pipe even if the upstream body ignores
    // the aborted fetch and keeps a read pending.
    await pipeline(Readable.fromWeb(upstream.body as unknown as WebReadableStream), cap, res, { signal: abort.signal });
  } catch {
    // Byte ceiling, maxStreamMs abort, upstream failure, or the client hanging up — in every case
    // the honest signal is a torn-down stream: stop the upstream read too, then drop the socket.
    abort.abort();
    res.destroy();
  }
}

function ownerFromClaims(c: IdentityClaims): { owner: Owner; acting: SlackIdentity } {
  const acting: SlackIdentity = { enterpriseId: c.enterpriseId ?? null, teamId: c.teamId, userId: c.userId };
  // The owner id comes ONLY from verified claims (the acting user). The request body's handle never
  // supplies an id, so a forged body can't cross tenants.
  return { owner: userOwner(acting), acting };
}

export function createBroker(rawOpts: BrokerOptions): http.Server {
  // #212 / PostgreSQL-only production: never accept a caller-supplied replay implementation. A
  // JavaScript caller may still carry the removed property after a type upgrade; reject it instead
  // of silently ignoring a process-local store and reporting false readiness.
  if (Object.hasOwn(rawOpts, 'replayStore')) {
    throw new Error('createBroker: replayStore is not configurable; PostgreSQL replay protection is required');
  }
  // #116 dryRun: SEC-4 fail-closed flag validation before anything is wired; when on, EVERY audit
  // row written through this broker carries meta.dry_run (the wrapped audit replaces the caller's).
  const dryRun = assertDryRunFlag(rawOpts.dryRun, 'createBroker');
  // #116: external KMS makes real wrap/unwrap network calls — refuse it fail-closed at construction
  // so the "no real network on any edge" guarantee stays literally true (the vault safety check is
  // async below; this one is synchronous — the envelope is known now).
  if (dryRun) assertDryRunLocalKey(rawOpts.vault.usesEnvelope);
  // #212 production broker boundary: no legacy bare-secret mode. Normalize once into a defensive,
  // deep-frozen config so caller mutation cannot change issuer/audience/keys after construction.
  const identityConfig = normalizeIdentityConfig(rawOpts.identitySecret);
  // Direct constructors do not pass through the env loader, but they still expose the broker bearer
  // and provider client secrets here. Enforce the same purpose-separation invariant before startup.
  assertIdentityPurposeDistinct(identityConfig, [
    ...(rawOpts.brokerToken ? [rawOpts.brokerToken] : []),
    ...rawOpts.providers.flatMap((provider) => provider.clientSecret ? [provider.clientSecret] : []),
  ], (secret) => rawOpts.vault.usesMasterKeyMaterial(secret));
  const opts: BrokerOptions = {
    ...rawOpts,
    identitySecret: identityConfig,
    ...(dryRun ? { audit: dryRunAudit(rawOpts.audit) } : {}),
  };
  // authorize REPLACES the static brokerToken gate (not AND). Setting both means the bearer is never
  // checked — reject it so nobody wires both expecting defense-in-depth.
  if (opts.authorize && opts.brokerToken) {
    throw new Error('createBroker: set either authorize or brokerToken, not both (authorize replaces the bearer gate)');
  }
  // #209 one pure normalizer owns every byte/count/timer default and invariant. The packaged server
  // invokes it before opening Postgres; this public direct-construction boundary invokes it too.
  const {
    fetchDeadlineMs,
    maxResponseBytes: maxBytes,
    maxStreamBytes,
    maxStreamMs,
    maxInflight,
    maxInflightPerProvider,
    headersTimeoutMs,
    requestTimeoutMs,
    keepAliveTimeoutMs,
  } = normalizeBrokerResourceBounds(opts);
  // #209 ONE limiter shared by every request (like the refresh `inflight` map and the rate-limit
  // store): live counters admit/reject at entry so a burst of slow upstreams can't pin sockets/memory.
  const limiter = new InflightLimiter(maxInflight, maxInflightPerProvider);
  const registry = new ProviderRegistry(opts.providers);
  const allowedCt = (opts.allowedContentTypes ?? DEFAULT_ALLOWED_CT).map((c) => c.toLowerCase());
  // #212: one supported replay path. Every broker replica consumes jtis through the shared
  // PostgreSQL table; there is no injectable/process-local alternative that can make readiness lie.
  // Store raw token expiry as the stable schema meaning. The store applies the three-skew cluster
  // horizon only to pruning; the one-time upgrade from pre-#212 brokers uses a drained cutover
  // because an old replica does not know that grace.
  const replay = new DbReplayStore(opts.db);
  // ONE inflight map shared by every request's ConnectionHandle, so concurrent requests for the same
  // owner+provider collapse to a single token refresh (rotating-refresh providers brick on a double
  // refresh). Per-request maps would defeat that. On Postgres the advisory lock also coordinates
  // cross-pod; this map covers the remaining in-process concurrency.
  const inflight = new Map<string, Promise<string | null>>();
  // ONE rate-limit bucket store shared by every request's ConnectionHandle (provider.rateLimit);
  // a per-request store would never accumulate budget across requests. Per-process by default.
  const rateLimits: RateLimitStore = opts.rateLimitStore ?? new MemoryRateLimitStore();

  // Broker-local metrics emit. Fire-and-forget: a throwing (or async-rejecting) sink must NEVER
  // affect the request (else a broken metrics sink would turn an intended 403 deny into a 500).
  // safeEmit swallows both failure shapes; the ConnectionHandle pass-through does the same.
  const emit = (ev: VouchrEvent) => safeEmit(opts.onEvent, ev);

  // #54 lifecycle: consent + session stores for offboarding (purge pending consent + thread grants so
  // neither can resurrect access after a user is removed). #52 OAuth connect flow (mounted only when
  // baseUrl is set) reuses the same Consent: it owns the single-use state + PKCE; handleOAuthCallback
  // owns the code exchange — the broker adds no crypto/state logic itself. Cheap Db wrappers.
  const consent = new Consent(opts.db, dryRun); // #116: dry-run mints local instantly-succeeding authorize URLs
  const sessions = new SessionGrants(opts.db);
  const approvals = new Approvals(opts.db); // #113 per-action approval requests/grants (provider.approval)
  const callbackPath = opts.callbackPath === undefined ? '/oauth/callback' : opts.callbackPath;
  // The same core helper owns origin/path validation for both adapters. A configured callback path
  // must be the exact pathname this server matches, never a relative/URL/query/fragment variant.
  const redirectUri = opts.baseUrl ? buildCallbackUrl(opts.baseUrl, callbackPath) : undefined;

  // #116 safety rail: dry-run must never serve against a vault holding REAL credential rows.
  // createBroker is sync, so the async check starts here and every request (health probes excepted)
  // awaits it FAIL-CLOSED below; the packaged broker (bin/broker-server) additionally awaits the
  // same check at boot for a true startup hard-fail. The refusal is remembered (never swallowed) —
  // the .catch only prevents an unhandled rejection from killing a host process before its first
  // request. Only DryRunVaultError's static message is printed; every other thrown value is reduced
  // to one static line because even constructor.name is attacker-overridable. ponytail: a transient
  // db error here wedges dry-run fail-closed with
  // no retry (while /readyz separately reports the db) — acceptable for a construction-time check;
  // restarting the process is the recovery, a retry loop belongs to the host's readiness probe.
  let dryRunRefusal: Error | undefined;
  const dryRunReady = dryRun
    ? assertDryRunVault(opts.db).catch((e: Error) => {
        dryRunRefusal = e;
        console.error(e instanceof DryRunVaultError ? `[vouchr] ${e.message}` : '[vouchr] dry-run vault check failed');
      })
    : undefined;

  /** Perimeter check on /v1/* BEFORE identity. Prefers a pluggable `authorize` hook (e.g. serviceauth),
   *  else the static `brokerToken` bearer, else no gate. NOT identity — that's the signed token. */
  async function perimeter(req: http.IncomingMessage, signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    if (opts.authorize) {
      try {
        const work = Promise.resolve(opts.authorize(req, signal));
        await (signal ? awaitWithSignal(work, signal) : work);
      } catch (e) {
        if (signal?.aborted) throw e;
        if (e instanceof HttpError) throw e;
        throw new HttpError(401, { error: 'unauthorized' });
      }
      signal?.throwIfAborted();
      return;
    }
    if (!opts.brokerToken) return;
    const a = Buffer.from(req.headers.authorization ?? '');
    const b = Buffer.from(`Bearer ${opts.brokerToken}`);
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new HttpError(401, { error: 'unauthorized' });
  }

  async function verify(token: string): Promise<IdentityClaims> {
    let claims: IdentityClaims;
    try {
      // Signature + claims + exp (pure, sync). Replay is enforced separately below so it can await a
      // shared (possibly async) store, making single-use cluster-wide rather than per-process.
      claims = verifyIdentity(token, opts.identitySecret);
    } catch (e) {
      if (e instanceof IdentityError) throw new HttpError(401, { error: 'invalid identity token' });
      throw e;
    }
    // #212: keep the persisted value as raw token expiry. DbReplayStore applies the fixed
    // cluster-skew grace to pruning, so every #212 replica preserves the row through every
    // verifier's acceptance window. The pre-#212 upgrade is drained because old replicas lack it.
    if (!(await replay.use(claims.jti, claims.exp))) {
      throw new HttpError(401, { error: 'invalid identity token' });
    }
    return claims;
  }

  /**
   * Operator authorization, mirroring the Bolt credential-use path (bolt.ts:173-185): Policy then the
   * channel tool allowlist. The channel/team come ONLY from verified claims. A deny is audited (no
   * secret) and returns 403 — the credential is never injected. Runs AFTER identity is verified, so a
   * denied request still spends its single-use jti (no free retries) but the vault is never read.
   */
  async function authorize(provider: string, claims: IdentityClaims): Promise<void> {
    const channel = claims.channel;
    const acting: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    // The Policy + channel-tool CHECK is the shared core decision; the broker keeps its own audit/emit/
    // status mapping (it emits policy_denied on BOTH a policy and a tool-disabled deny — the Bolt path does
    // not emit on tool-disabled, so the mapping deliberately stays per-adapter).
    const denial = await authorizeProvider(opts.policy, opts.channelTools, acting, channel, provider);
    if (denial === 'policy') {
      await opts.audit.record('denied', acting, provider, { channel });
      emit({ type: 'policy_denied', provider });
      throw new HttpError(403, { error: 'policy denies this provider in this channel' });
    }
    if (denial === 'tool-disabled') {
      await opts.audit.record('denied', acting, provider, { channel, reason: 'tool-disabled' });
      emit({ type: 'policy_denied', provider });
      throw new HttpError(403, { error: 'provider is not enabled in this channel' });
    }
  }

  /**
   * #51 owner resolution — the ONLY place the credential owner is chosen. It reads the SIGNED
   * `ownerKind` (never the body): the body handle's `owner` must merely MATCH the signed claim, so a
   * forged `owner:'channel'` on a plain user token is refused rather than silently downgraded. Channel
   * mode is fail-closed: refused unless `channelConfig` is set (opt-in) and the signed eligibility
   * verdict is present. `shared` keys the vault on the channel and audits the acting human.
   */
  async function resolveOwner(
    ref: ConnectionHandleRef,
    claims: IdentityClaims,
  ): Promise<{ owner: Owner; acting: SlackIdentity }> {
    const ownerKind = claims.ownerKind ?? 'user';
    // The body handle's owner must MATCH the signed ownerKind — a forged body owner:'channel' on a plain
    // user token is refused, never silently downgraded. This claims-integrity check is broker-specific
    // (Bolt has no untrusted body), so it runs here BEFORE the shared core decision.
    if (ref.owner !== ownerKind) throw new HttpError(403, { error: 'handle owner does not match verified claims' });
    const acting: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };

    if (ownerKind === 'user') {
      // SECURITY (#54): `session` mode is a user-owned credential gated behind a per-thread grant. This
      // gate now lives in ONE core function (resolveCredentialOwner) the Bolt path calls too, so the two
      // transports can no longer drift (that drift is how this check went missing on the broker). Only
      // meaningful when channelConfig is opted in; otherwise mode stays null and the gate is inert.
      let mode: ChannelMode | null = null;
      let hasSessionGrant = false;
      const thread = claims.threadTs ?? null;
      if (opts.channelConfig) {
        mode = await opts.channelConfig.getMode(claims.teamId, claims.channel, ref.provider);
        if (mode === 'session' && thread) {
          hasSessionGrant = await sessions.isGranted(acting, claims.channel, thread, ref.provider);
        }
      }
      const r = resolveCredentialOwner({ path: 'user', mode, principal: acting, channel: claims.channel, thread, hasSessionGrant });
      if (r.status === 'needs_session') {
        await opts.audit.record('denied', acting, ref.provider, { channel: claims.channel, reason: r.reason });
        throw new HttpError(403, { error: 'provider requires a thread-scoped session approval' });
      }
      // The broker never pre-reads the vault (hasUserCredential unset), so the user path only yields a
      // resolved owner here — the injector 409s later if the credential is missing.
      if (r.status !== 'resolved') throw new HttpError(409, { error: 'not connected' });
      return { owner: r.owner, acting: r.acting };
    }

    // ── channel-owned (opt-in, fail-closed) ──
    if (!opts.channelConfig) throw new HttpError(403, { error: 'channel-owned credentials are not enabled' });
    // Eligibility from the SIGNED verdict (the broker has no Slack client). Fail-closed: only an explicit
    // true is eligible. When eligibility is enforced entirely upstream, requireChannelEligibility:false
    // treats every channel-owned request as eligible (unchanged).
    const eligible = (opts.requireChannelEligibility ?? true) ? claims.channelEligible === true : true;
    const mode = await opts.channelConfig.getMode(claims.teamId, claims.channel, ref.provider);
    const r = resolveCredentialOwner({ path: 'channel', mode, principal: acting, channel: claims.channel, eligible });
    if (r.status === 'refused') {
      if (r.code === 'ineligible') {
        await opts.audit.record('denied', acting, ref.provider, { channel: claims.channel, owner: 'channel', reason: 'channel-ineligible' });
        throw new HttpError(403, { error: 'channel is ineligible for a shared credential' });
      }
      // 'per-user' / 'session' / unconfigured are user-owned modes; a channel handle can't reach them.
      throw new HttpError(403, { error: 'channel is not configured for a channel-owned credential' });
    }
    // The channel path only ever yields resolved or refused; anything else fails closed (defensive).
    if (r.status !== 'resolved') throw new HttpError(403, { error: 'channel is not configured for a channel-owned credential' });
    return { owner: r.owner, acting: r.acting };
  }

  // The ONE shared gate pipeline for the credential-use routes (/v1/fetch and /v1/mcp — STR-3):
  // identity verify + replay, provider existence, service refusal, policy + channel tools, owner
  // resolution. It needs only the envelope fields both request shapes share.
  async function resolveTarget(
    body: Pick<BrokerFetchRequest, 'handle' | 'identityToken'>,
    routeDeadlineMs: number,
    transportResponseMaxBytes?: number,
  ): Promise<{ handle: ConnectionHandle; provider: Provider; acting: SlackIdentity }> {
    const ref = body.handle;
    if (!ref || (ref.owner !== 'user' && ref.owner !== 'channel') || typeof ref.provider !== 'string') {
      throw new HttpError(400, { error: 'invalid handle' });
    }
    // Identity is verified BEFORE any provider-existence probe, so an unauthenticated caller past the
    // perimeter can't enumerate registered providers via distinct 404/403 responses (#enumeration).
    const claims = await verify(body.identityToken);
    if (!registry.has(ref.provider)) throw new HttpError(404, { error: 'unknown provider' });
    // Service-to-service tools have no human credential to broker (see ToolManifestEntry.identity):
    // Vouchr is deliberately not in that path, so the broker refuses them just like connect() does.
    if (!isBrokeredProvider(registry.get(ref.provider))) {
      throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    }
    await authorize(ref.provider, claims);
    const provider = withEgressDefaults(registry.get(ref.provider), opts.allowWrites);
    const { owner, acting } = await resolveOwner(ref, claims);
    // The 7th arg is the createBroker-scoped SHARED inflight map, so concurrent requests for the same
    // owner+provider collapse to one token refresh (rotating-refresh providers brick on a double
    // refresh). The 8th wires the metrics sink so the broker path stops being a black box; the 9th
    // wires the audit STREAM sink (raw actor id) for host-side ingestion. The 10th is the origin
    // channel from the signed claims, so per-channel usage stats see this request. The 11th is the
    // createBroker-scoped SHARED rate-limit bucket store (provider.rateLimit). The 12th is the #117
    // credential-health hook (definitive refresh death → owner identity, no tokens). The 13th/14th are
    // the #113 approval store + the signed thread (a provider.approval gate is enforced on this door
    // too; the broker maps the throw to 403 approval_required, approval SURFACE stays the Bolt app —
    // see mapUpstreamError). The 15th flags dry-run (#116): the injector stubs ONLY the final network
    // call, after every gate — the approval gate included.
    const handle = new ConnectionHandle(
      provider, owner, acting, opts.vault, opts.audit, opts.resolvers ?? {}, inflight, opts.onEvent,
      opts.auditSink, claims.channel ?? null, rateLimits, opts.onCredentialHealth, approvals,
      claims.threadTs ?? null, dryRun, routeDeadlineMs, transportResponseMaxBytes,
    );
    return { handle, provider, acting };
  }

  async function handleFetch(
    body: BrokerFetchRequest,
    trace: Record<string, string>,
    requestSignal: AbortSignal,
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    requestSignal.throwIfAborted();
    const method = requestMethod(body.method);
    // Default fail-closed read-only. Reject non-GET/HEAD with 405 BEFORE identity/vault/upstream.
    if (!opts.allowWrites && method !== 'GET' && method !== 'HEAD') {
      throw new HttpError(405, { error: 'only GET and HEAD are allowed' });
    }
    const outboundBody = requestBody(body.body);
    if ((method === 'GET' || method === 'HEAD') && outboundBody !== undefined) {
      throw new HttpError(400, { error: 'GET and HEAD requests cannot carry a body' });
    }
    const { handle, provider } = await resolveTarget(body, fetchDeadlineMs, maxBytes);
    // The client may have disappeared while identity/replay/authz/owner reads were in flight. The
    // response `close` event is edge-triggered, so check the persistent signal again immediately
    // before admitting or performing provider work.
    requestSignal.throwIfAborted();
    const url = buildTargetUrl(provider, body);

    // Forward only a tiny safe header allowlist; never the caller's Authorization (broker injects).
    // W3C trace context is read off the INCOMING request (not the body) and forwarded verbatim onto
    // the outbound provider fetch so a host can stitch the broker hop into the agent's trace.
    // Non-secret (traceid/spanid/flags only); no-op when the caller sends no traceparent.
    // ponytail: forward as-is rather than minting a child span — span management is the host's job.
    const headers = { ...pickHeaders(body.headers, FETCH_FORWARD_HEADERS), ...trace };

    // #209 per-provider in-flight admission (the route already admitted against the global ceiling).
    // Admit BEFORE arming the timer/listener so an OverloadedError leaks neither (→ 503, top-level catch).
    const releaseProvider = limiter.enterProvider(provider.id);
    // #209 one disposable signal bounds headers + response-body drain and preserves caller
    // cancellation. Unlike AbortSignal.timeout/any, its timer/listener are released on fast success.
    const deadline = disposableDeadline(fetchDeadlineMs, requestSignal);
    try {
      let res: Response;
      try {
        res = await handle.fetch(url.toString(), { method, headers, body: outboundBody, signal: deadline.signal });
      } catch (e) {
        if (deadline.timedOut() || isTimeoutError(e)) {
          throw new HttpError(504, { error: 'upstream timed out' });
        }
        requestSignal.throwIfAborted();
        mapUpstreamError(e);
      }

      const contentType = res.headers.get('content-type') ?? '';
      // HEAD/no-content responses have no body to guard or relay; return status + content-type only.
      if (method === 'HEAD' || responseHasNoBody(res)) {
        await res.body?.cancel().catch(() => undefined);
        return { status: 200, payload: { status: res.status, contentType, body: '' } };
      }
      // #26: content-type allowlist checked BEFORE the body is read (charset stripped, case-folded).
      if (!allowedCt.includes(normalizeContentType(contentType))) {
        await res.body?.cancel().catch(() => undefined);
        throw new HttpError(502, { error: 'disallowed content-type' });
      }
      // #26: size cap -> 413, never a truncated partial body. A slow-drip body that outruns the
      // deadline aborts the reader here too — surface it as the same stable 504 as a headers timeout.
      let text: string;
      try {
        text = await readCapped(res, maxBytes);
      } catch (e) {
        if (deadline.timedOut() || isTimeoutError(e)) {
          throw new HttpError(504, { error: 'upstream timed out' });
        }
        requestSignal.throwIfAborted();
        throw e;
      }
      return { status: 200, payload: { status: res.status, contentType, body: text } };
    } finally {
      deadline.dispose();
      releaseProvider();
    }
  }

  /**
   * #65 `POST /v1/mcp` — MCP-aware egress proxy for providers whose tool surface is an MCP server
   * over Streamable HTTP (which is just HTTP with a bearer). It runs the SAME pipeline as /v1/fetch
   * — perimeter, identity from the signed token (never the body), replay guard, policy + channel
   * tools, owner resolution (all via resolveTarget), then the injector's egress host/https/port/
   * method gates BEFORE the credential is read — and injects the credential inside the broker; the
   * caller never sees it. What /v1/fetch can't do, this route adds:
   *  - the response passes through AS-IS and STREAMED (text/event-stream included, never buffered),
   *    so listTools/callTool streaming works;
   *  - the MCP plumbing headers (Mcp-Session-Id, MCP-Protocol-Version) pass through in BOTH
   *    directions. Session ids are OPAQUE AND POTENTIALLY SENSITIVE (MCP security guidance treats
   *    them as hijackable): the broker relays them verbatim and never stores, logs, or audits
   *    them — and never accepts one as authentication; every request still needs a fresh signed
   *    identityToken and passes every gate.
   * The broker stays STATELESS: no MCP session table, no lifecycle handling — initialize/
   * capabilities/session management remain the host's MCP client's job. The optional GET listening
   * stream and DELETE session termination of the MCP spec are answered 405 + Allow: POST (see the
   * route), never proxied.
   *
   * The route is a DECLARATIVE per-provider opt-in (`provider.mcp`, defineProvider-validated):
   * the raw streamed passthrough skips the broker's /v1/fetch response envelope gates
   * (allowedContentTypes / maxResponseBytes), so a POST-enabled /v1/fetch provider must NOT be
   * reachable here by default. `mcp.paths` locks the endpoint (same matcher + fail-closed
   * encoded-separator rule as egressPaths), and the response must match `mcp.allowContentTypes`
   * (default application/json + text/event-stream) or it is withheld unread — which is what stops
   * an allowlisted-but-hostile upstream reflecting the injected Authorization header into a
   * text/plain error body.
   *
   * MCP callTool can mutate, so the whole route also sits behind the same two write opt-ins as a
   * /v1/fetch POST: broker `allowWrites` AND the provider's `egressMethods` including POST. An open
   * stream can't dodge the /v1/fetch size cap either: maxStreamBytes/maxStreamMs terminate it.
   */
  async function handleMcp(
    body: BrokerMcpRequest,
    trace: Record<string, string>,
    res: http.ServerResponse,
    requestSignal: AbortSignal,
  ): Promise<void> {
    requestSignal.throwIfAborted();
    // Fail-closed write gate BEFORE identity/vault/upstream, mirroring handleFetch's 405.
    if (!opts.allowWrites) throw new HttpError(405, { error: 'writes are disabled; /v1/mcp requires allowWrites' });
    const outboundBody = requestBody(body.body);
    if (outboundBody === undefined) throw new HttpError(400, { error: 'a JSON-RPC request body is required' });
    const { handle, provider, acting } = await resolveTarget(body, maxStreamMs);
    requestSignal.throwIfAborted();
    const url = buildTargetUrl(provider, body);
    // #65 the declarative opt-in gate, denied in the egress-denial shape (STR-4: same no-secret
    // event + the same `denied` meta keys as the injector's denyEgress) BEFORE the vault is read
    // or anything goes upstream. Runs after resolveTarget so an unauthenticated caller can't probe
    // which providers are MCP-enabled, and so the denial is attributed to the verified actor.
    const mcp = provider.mcp;
    if (!mcp) {
      emit({ type: 'egress_denied', provider: provider.id, host: url.hostname, reason: 'mcp' });
      await opts.audit.record('denied', acting, provider.id, { host: url.hostname, reason: 'mcp-not-enabled' });
      throw new HttpError(403, { error: 'provider is not enabled for /v1/mcp' });
    }
    // The declared MCP endpoint lock: the SAME matching semantics as egressPaths (shared matcher,
    // shared fail-closed encoded-separator rule — a path lock is a security boundary).
    if (hasAmbiguousPathEncoding(url.pathname) || !mcp.paths.some((p) => pathAllowed(url.pathname, p))) {
      emit({ type: 'egress_denied', provider: provider.id, host: url.hostname, reason: 'path' });
      await opts.audit.record('denied', acting, provider.id, { host: url.hostname, reason: 'path' });
      throw new HttpError(403, { error: 'path is not in the provider mcp.paths allowlist' });
    }
    const headers = { ...pickHeaders(body.headers, MCP_FORWARD_HEADERS), ...trace };
    // #209 per-provider in-flight admission (global admission ran at the route). After the deny gates
    // above, so a refused request never consumes a slot. Over the ceiling → 503 (top-level catch);
    // admit before arming the timer so a rejection leaks nothing. Released in the finally below.
    const releaseProvider = limiter.enterProvider(provider.id);
    // ONE AbortController covers the upstream fetch AND the relay: the maxStreamMs timer fires it,
    // a client disconnect fires it, and a byte-ceiling breach fires it — the upstream socket never
    // outlives the request it was serving.
    const abort = new AbortController();
    const deadline = disposableDeadline(maxStreamMs, requestSignal);
    const onAbort = () => abort.abort(deadline.signal.reason);
    if (deadline.signal.aborted) onAbort();
    else deadline.signal.addEventListener('abort', onAbort, { once: true });
    try {
      let upstream: Response;
      try {
        // The injector enforces every egress gate (and provider.egressResponse, incl. the always-on
        // set-cookie strip) before/around this call, and writes the same inject/denied audit rows +
        // events as a /v1/fetch — the audit trail cannot tell the two doors apart (STR-4).
        upstream = await handle.fetch(url.toString(), { method: 'POST', headers, body: outboundBody, signal: abort.signal });
      } catch (e) {
        if (deadline.timedOut() || isTimeoutError(e)) {
          throw new HttpError(504, { error: 'upstream timed out' });
        }
        requestSignal.throwIfAborted();
        mapUpstreamError(e); // denials map to the same JSON errors as /v1/fetch — no stream started yet
      }
      // #65 response policy: only the DECLARED transport media types stream through, compared on
      // the bare type (charset stripped, case-folded) BEFORE any byte is relayed — so a hostile
      // upstream reflecting request headers into e.g. a text/plain error body is withheld unread.
      // Bodyless responses (202 on notifications, 204) are exempt, same rule as /v1/fetch's gate.
      const ct = normalizeContentType(upstream.headers.get('content-type'));
      if (upstream.body !== null && !responseHasNoBody(upstream) && !(mcp.allowContentTypes ?? DEFAULT_MCP_ALLOWED_CT).some((c) => normalizeContentType(c) === ct)) {
        await upstream.body.cancel().catch(() => undefined);
        throw new HttpError(502, { error: 'disallowed content-type' });
      }
      await relayMcpResponse(upstream, res, abort, maxStreamBytes);
    } finally {
      deadline.signal.removeEventListener('abort', onAbort);
      deadline.dispose();
      releaseProvider();
    }
  }

  async function handleResolve(body: { handle: ConnectionHandleRef; identityToken: string }): Promise<Record<string, unknown>> {
    const ref = body.handle;
    if (!ref || ref.owner !== 'user' || typeof ref.provider !== 'string') {
      throw new HttpError(400, { error: 'invalid handle' });
    }
    // Verify identity BEFORE probing the registry so an unauthenticated caller can't enumerate providers.
    const claims = await verify(body.identityToken);
    if (!registry.has(ref.provider)) throw new HttpError(404, { error: 'unknown provider' });
    // Service-to-service tools are not brokered by Vouchr — don't even report their consent state
    // (else /v1/resolve would call a service tool "connected"/"needs_consent"). Refuse like /v1/fetch.
    if (!isBrokeredProvider(registry.get(ref.provider))) {
      throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    }
    const { owner } = ownerFromClaims(claims);
    const connected = (await opts.vault.get(owner, ref.provider)) != null;
    // NO secret: only existence + a coarse consent state. The token is never read into the response.
    return { connected, consentState: connected ? 'connected' : 'needs_consent' };
  }

  /**
   * #54 `POST /v1/disconnect` — the acting user revokes their OWN connection for one provider (the
   * headless analogue of `/vouchr disconnect <provider>`). Identity from the signed token; a forged
   * body can't disconnect someone else. Best-effort upstream revoke; local delete always wins. No secret.
   */
  async function handleDisconnect(body: { handle?: { provider?: unknown }; identityToken: string }): Promise<Record<string, unknown>> {
    const providerId = body.handle?.provider;
    if (typeof providerId !== 'string') throw new HttpError(400, { error: 'invalid handle' });
    const claims = await verify(body.identityToken);
    const identity: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    const { removed, ok } = await disconnectProvider(opts.vault, opts.audit, registry, identity, providerId);
    return { ok, revoked: removed ? [providerId] : [] };
  }

  /**
   * #54 `POST /v1/admin/offboard` — remove ALL of a target user's connections + pending consent +
   * thread grants (the headless analogue of the Bolt `registerOffboarding` hook). Admin authority
   * comes from the SIGNED `isAdmin` claim (the broker can't verify workspace admin itself); fail
   * closed. A signed `enterpriseId` routes the cross-workspace (Grid/SCIM) case to
   * offboardUserEverywhere. `targetUserId` is the subject, never the actor.
   */
  async function handleOffboard(body: { identityToken: string; targetUserId?: unknown }): Promise<Record<string, unknown>> {
    const claims = await verify(body.identityToken);
    if (claims.isAdmin !== true) {
      const actor: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
      await opts.audit.record('denied', actor, 'offboard', { reason: 'not-admin' });
      throw new HttpError(403, { error: 'admin authority required' });
    }
    const targetUserId = body.targetUserId;
    if (typeof targetUserId !== 'string' || !targetUserId) throw new HttpError(400, { error: 'targetUserId is required' });
    // Enterprise/Grid: span every workspace the target touches; else this one workspace.
    if (claims.enterpriseId) {
      const summary = await offboardUserEverywhere(opts.db, opts.vault, opts.audit, consent, { enterpriseId: claims.enterpriseId, userId: targetUserId }, registry);
      // Truthful completeness (GHSA-25m2 r3): ok:true ONLY when every touched workspace fully
      // offboarded. A credential left in one workspace must never read as a successful sweep.
      const incompleteTeams = summary.filter((s) => !s.ok).length;
      return { ok: incompleteTeams === 0, revoked: summary.flatMap((s) => s.providers), ...(incompleteTeams ? { incompleteTeams } : {}) };
    }
    const target: SlackIdentity = { enterpriseId: null, teamId: claims.teamId, userId: targetUserId };
    const providers = await offboardUser(opts.vault, opts.audit, consent, target, registry, 'offboarded', sessions);
    return { ok: true, revoked: providers };
  }

  /**
   * #53 `POST /v1/admin/reference` — configure a channel's SHARED credential as an external
   * secret-manager REFERENCE (never a raw secret over the wire). Inlines the same core actions as the
   * Bolt `referenceChannelSecret` (vault.reference + ChannelConfig.setMode('shared')) so NO @slack
   * dependency enters the broker. Admin authority + eligibility come ONLY from signed claims; fail
   * closed. Stores only the non-secret ref; the injector resolves it JIT at egress via `resolvers`.
   */
  async function handleAdminReference(body: {
    handle?: { provider?: unknown };
    identityToken: string;
    source?: unknown;
    secretRef?: unknown;
    scopes?: unknown;
  }): Promise<Record<string, unknown>> {
    if (!opts.channelConfig) throw new HttpError(403, { error: 'channel-owned credentials are not enabled' });
    const providerId = body.handle?.provider;
    if (typeof providerId !== 'string') throw new HttpError(400, { error: 'invalid handle' });
    if (typeof body.source !== 'string' || typeof body.secretRef !== 'string' || !body.source || !body.secretRef) {
      throw new HttpError(400, { error: 'source and secretRef are required' });
    }
    if (body.scopes !== undefined && typeof body.scopes !== 'string') throw new HttpError(400, { error: 'invalid scopes' });
    // Verify identity BEFORE probing the registry so an unauthenticated caller can't enumerate providers.
    const claims = await verify(body.identityToken);
    if (!registry.has(providerId)) throw new HttpError(404, { error: 'unknown provider' });
    if (!isBrokeredProvider(registry.get(providerId))) throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });

    const acting: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    // Admin authority: SIGNED claim only (the broker can't verify Slack admin). Fail closed + audited.
    if (claims.isAdmin !== true) {
      await opts.audit.record('denied', acting, providerId, { reason: 'not-admin', owner: 'channel', channel: claims.channel });
      throw new HttpError(403, { error: 'admin authority required' });
    }
    // Channel eligibility from the SIGNED verdict (shared creds refused on ineligible channels).
    if ((opts.requireChannelEligibility ?? true) && claims.channelEligible !== true) {
      await opts.audit.record('denied', acting, providerId, { reason: 'channel-ineligible', owner: 'channel', channel: claims.channel });
      throw new HttpError(403, { error: 'channel is ineligible for a shared credential' });
    }
    const owner = channelOwner(claims.teamId, claims.channel);
    // Refuse a channel locked to a user-owned mode (invariant 7) — mirrors referenceChannelSecret.
    const mode = await opts.channelConfig.getMode(claims.teamId, claims.channel, providerId);
    if (mode != null && mode !== 'shared') throw new HttpError(409, { error: `channel is ${mode} for this provider; shared references are not allowed` });
    await opts.vault.reference(owner, providerId, { source: body.source, secretRef: body.secretRef, scopes: body.scopes });
    await opts.channelConfig.setMode(claims.teamId, claims.channel, providerId, 'shared');
    await opts.audit.record('config', acting, providerId, { owner: 'channel', channel: claims.channel, mode: 'shared', kind: 'ref', source: body.source });
    return { ok: true };
  }

  /**
   * Provider must be a real, brokerable (non-service) provider. Verifies identity FIRST so an
   * unauthenticated caller past the perimeter can't enumerate providers via distinct 404/403s.
   * Shared by the admin config write routes below; mirrors the check in handleAdminReference.
   */
  async function verifyBrokerableProvider(providerId: string, token: string): Promise<IdentityClaims> {
    const claims = await verify(token);
    if (!registry.has(providerId)) throw new HttpError(404, { error: 'unknown provider' });
    if (!isBrokeredProvider(registry.get(providerId))) throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    return claims;
  }

  /** Admin gate, identical to the reference/offboard routes: authority is the SIGNED `isAdmin` claim
   *  ONLY (the broker can't verify workspace admin). Fail closed + audited (no secret). Never the body. */
  async function requireAdmin(claims: IdentityClaims, subject: string): Promise<SlackIdentity> {
    const acting: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    if (claims.isAdmin !== true) {
      await opts.audit.record('denied', acting, subject, { reason: 'not-admin', channel: claims.channel });
      throw new HttpError(403, { error: 'admin authority required' });
    }
    return acting;
  }

  /**
   * `POST /v1/admin/mode` — set the channel's credential MODE for a provider (the headless analogue of
   * `/vouchr mode`). Body `{ provider, mode }`; the channel/team come ONLY from the signed claims (never
   * the body), admin authority from the SIGNED `isAdmin` claim. Config, NOT secret ingest — calls the
   * SAME core `ChannelConfig.setMode` the Bolt path uses. Requires channelConfig opt-in; fail closed.
   */
  async function handleAdminMode(body: { provider?: unknown; mode?: unknown; identityToken: string }): Promise<BrokerAdminOkResponse> {
    if (!opts.channelConfig) throw new HttpError(403, { error: 'channel-owned credentials are not enabled' });
    const providerId = body.provider;
    if (typeof providerId !== 'string' || !providerId) throw new HttpError(400, { error: 'provider is required' });
    const mode = body.mode;
    if (!isChannelMode(mode)) {
      throw new HttpError(400, { error: 'mode must be one of shared|per-user|session' });
    }
    const claims = await verifyBrokerableProvider(providerId, body.identityToken);
    const acting = await requireAdmin(claims, providerId);
    const owner = channelOwner(claims.teamId, claims.channel);
    // Marking a channel `shared` must be symmetric with /v1/admin/reference (and Bolt's
    // assertChannelEligible): refuse a shared cred on an ineligible (Slack-Connect / externally-shared)
    // channel from the SIGNED verdict. Fail closed + audited. resolveOwner re-checks at use, so this is
    // defense-in-depth, but the two config doors must agree.
    if (mode === 'shared' && (opts.requireChannelEligibility ?? true) && claims.channelEligible !== true) {
      await opts.audit.record('denied', acting, providerId, { reason: 'channel-ineligible', owner: 'channel', channel: claims.channel });
      throw new HttpError(403, { error: 'channel is ineligible for a shared credential' });
    }
    // Flipping to a user-owned mode drops any live shared credential — the deliberate re-authorization
    // boundary (mirrors Bolt setChannelMode): else a dormant shared cred silently reactivates on a later
    // flip back to `shared` with no re-ingest/re-auth.
    if (mode !== 'shared') await opts.vault.delete(owner, providerId);
    await opts.channelConfig.setMode(claims.teamId, claims.channel, providerId, mode);
    await opts.audit.record('config', acting, providerId, { owner: 'channel', channel: claims.channel, mode });
    return { ok: true };
  }

  /**
   * `POST /v1/admin/tools` — enable/disable a provider in the channel's tool allowlist (the headless
   * analogue of `/vouchr enable|disable`). Body `{ provider, enabled }`; channel/team + admin authority
   * from the SIGNED claims only. Calls the SAME core `ChannelTools.setEnabled` the Bolt path uses.
   * Requires channelTools opt-in; fail closed. Config, NOT secret ingest.
   */
  async function handleAdminTools(body: { provider?: unknown; enabled?: unknown; identityToken: string }): Promise<BrokerAdminOkResponse> {
    if (!opts.channelTools) throw new HttpError(403, { error: 'channel tool allowlist is not enabled' });
    const providerId = body.provider;
    if (typeof providerId !== 'string' || !providerId) throw new HttpError(400, { error: 'provider is required' });
    if (typeof body.enabled !== 'boolean') throw new HttpError(400, { error: 'enabled must be a boolean' });
    const claims = await verifyBrokerableProvider(providerId, body.identityToken);
    const acting = await requireAdmin(claims, providerId);
    await opts.channelTools.setEnabled(claims.teamId, claims.channel, providerId, body.enabled);
    await opts.audit.record('config', acting, providerId, { owner: 'channel', channel: claims.channel, toolEnabled: body.enabled });
    return { ok: true };
  }

  /**
   * `GET /v1/admin/config` — the read side of the two write routes above: the caller's channel's
   * per-provider mode + tool-enabled state, so an agent can inspect before changing. Admin-gated
   * (SIGNED `isAdmin` only); the channel/team come from the signed claims (identity token in the
   * `x-vouchr-identity` header — a GET carries no JSON body). Service tools are omitted (not brokered).
   * NO secret: policy bits only. `mode` is null when channelConfig is unset; `enabled` defaults true
   * when channelTools is unset (the same backward-compat rule ChannelTools.isEnabled applies).
   */
  async function handleAdminConfig(token: string): Promise<BrokerAdminConfigResponse> {
    const claims = await verify(token);
    await requireAdmin(claims, 'config');
    const providerIds = opts.providers
      .filter((p) => isBrokeredProvider(registry.get(p.id))) // service tools aren't brokered by Vouchr
      .map((p) => p.id);
    if (providerIds.length === 0) return { providers: [] };
    // Two channel-scoped batch reads (mode + tool allowlist) instead of getMode/isEnabled per provider,
    // so the query count is bounded by the channel, not the provider count (#209). `enabled` is the raw
    // allowlist bit — same backward-compat rule ChannelTools.isEnabled applies — mode null when unset.
    const [modeOf, toolAllowed] = await Promise.all([
      opts.channelConfig
        ? snapshotChannelModes(opts.channelConfig, claims.teamId, claims.channel, providerIds)
        : Promise.resolve((_provider: string): ChannelMode | null => null),
      opts.channelTools
        ? snapshotToolAllowlist(opts.channelTools, claims.teamId, claims.channel, providerIds)
        : Promise.resolve((_provider: string) => true),
    ]);
    const providers = providerIds.map((provider) => ({
      provider,
      mode: modeOf(provider),
      enabled: toolAllowed(provider),
    }));
    return { providers };
  }

  /**
   * #52 `POST /v1/connect` — mint an OAuth authorize URL for the VERIFIED user. State is bound to the
   * identity in the signed token (never the body), so a forged body can't mint consent for someone
   * else. The broker handles no raw token here; the token is only ever written to the vault inside the
   * callback below. Refuses service tools (no human cred) and key providers (no OAuth handshake).
   */
  async function handleConnect(body: { handle?: { provider?: unknown }; identityToken: string }): Promise<Record<string, unknown>> {
    if (!redirectUri) throw new HttpError(404, { error: 'oauth connect is not configured' });
    const providerId = body.handle?.provider;
    if (typeof providerId !== 'string') throw new HttpError(400, { error: 'invalid handle' });
    // Verify identity BEFORE probing the registry so an unauthenticated caller can't enumerate providers.
    const claims = await verify(body.identityToken);
    if (!registry.has(providerId)) throw new HttpError(404, { error: 'unknown provider' });
    const provider = registry.get(providerId);
    if (!isBrokeredProvider(provider)) throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    if (provider.credential === 'key') throw new HttpError(400, { error: 'provider has no OAuth flow; supply a key instead' });
    // Carry the signed enterpriseId so the resulting connection is discoverable by an enterprise
    // offboard (Grid/SCIM) — else a headless-OAuth connection would be pinned to enterpriseId:null.
    const identity: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    // Consent.begin persists the single-use state + PKCE verifier and returns the provider authorize URL.
    return await consent.begin(identity, provider, redirectUri, claims.channel);
  }

  /**
   * #52 `GET <callbackPath>` — the OAuth redirect target a human's browser lands on. Thin wrapper over
   * the shared `handleOAuthCallback` (consume single-use state, exchange code, vault the token, audit),
   * returning a minimal HTML page rather than JSON. All interpolated values are escaped (the `error`
   * and `account` fields are attacker/provider-influenced → reflected-XSS guard).
   */
  async function handleCallback(url: URL, signal?: AbortSignal): Promise<{ status: number; html: string }> {
    const q = url.searchParams;
    const result = await handleOAuthCallback(
      // dryRun (#116) stubs only the token-exchange edge inside the shared callback.
      { registry, vault: opts.vault, audit: opts.audit, consent, redirectUri: redirectUri!, auditSink: opts.auditSink, dryRun },
      q.get('code') ?? undefined,
      q.get('state') ?? undefined,
      q.get('error') ?? undefined,
      signal,
    );
    if (result.ok) return { status: 200, html: landingHtml(`✅ ${result.provider} connected${result.account ? ` as ${result.account}` : ''}`, 'You can close this tab and return to your app.') };
    return { status: result.status, html: landingHtml('Connection failed', result.error) };
  }

  /**
   * #55 `POST /v1/status` — the acting user's connection state across ALL brokered providers in one
   * call (the batched form of /v1/resolve; saves N round-trips rendering a "your connected accounts"
   * view). NO secret: existence + coarse consent state only. Service tools aren't brokered, so they're
   * omitted (same rule as /v1/resolve refusing them). Identity from the signed token.
   */
  async function handleStatus(body: { identityToken: string }): Promise<Record<string, unknown>> {
    const claims = await verify(body.identityToken);
    const identity: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    // ONE query, ZERO decryption: listLiveForUser returns the user's LIVE connected providers (no
    // secret, no KMS unwrap; TTL-expired rows dropped exactly as vault.get would). Intersect with the
    // brokered list in memory instead of N sequential vault.get calls, each of which would decrypt
    // both tokens (2N KMS calls under envelope) just to test != null.
    const connected = new Set((await opts.vault.listLiveForUser(identity)).map((c) => c.provider));
    const providers = opts.providers
      .filter((p) => isBrokeredProvider(registry.get(p.id))) // service tools aren't brokered by Vouchr
      .map((p) => {
        const isConnected = connected.has(p.id);
        return { provider: p.id, connected: isConnected, consentState: isConnected ? 'connected' : 'needs_consent' };
      });
    return { providers };
  }

  /**
   * `POST /v1/audit` — the acting user's own last ~20 audit events (headless analogue of `/vouchr
   * audit`). Identity from the SIGNED token; strictly the caller's own rows (core filters on
   * user_id = caller). NO secret and NO `meta` — the read query omits it. Mirrors handleStatus.
   */
  async function handleAudit(body: { identityToken: string }): Promise<BrokerAuditResponse> {
    const claims = await verify(body.identityToken);
    const identity: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    const events = await opts.audit.listByOwnerUser(identity, 20);
    return { events };
  }

  /**
   * `POST /v1/admin/audit` — the current channel's last ~20 audit events (all activity tagged with the
   * channel, headless analogue of `/vouchr audit channel`). Channel/team come ONLY from the signed claims (never the
   * body); admin authority is the SIGNED `isAdmin` claim via requireAdmin (fail closed + audited).
   * NO secret and NO `meta`.
   */
  async function handleAdminAudit(body: { identityToken: string }): Promise<BrokerAuditResponse> {
    const claims = await verify(body.identityToken);
    await requireAdmin(claims, 'audit'); // non-admin → 403 + audited denial, before any read
    if (typeof claims.channel !== 'string' || !claims.channel) throw new HttpError(400, { error: 'channel-scoped identity token required' });
    const events = await opts.audit.listByChannel(claims.teamId, claims.channel, 20);
    return { events };
  }

  /**
   * #55 `GET /v1/manifest` — the provider manifest: each provider's id and whether the agent acts as
   * the human (Vouchr brokers it) or as a service (host wires its own auth). Purely non-secret policy
   * metadata; keeps the source of truth in one place so a host needn't re-derive it. No identity
   * needed (not user-specific), but it still sits behind the /v1/* perimeter gate.
   */
  function handleManifest(): Record<string, unknown> {
    return {
      providers: opts.providers.map((p) => ({ provider: p.id, identity: registry.get(p.id).identity ?? 'acting_human' })),
    };
  }

  /**
   * `POST /v1/manifest` — the CHANNEL-SCOPED tool manifest for the verified identity (the headless
   * analogue of Bolt's `toolManifest()`, via the SAME core builder so the two can't drift): per
   * provider, whether it's usable in the claims' channel, its credential mode, who the agent acts as,
   * and the preview VISIBILITY the host must honor when posting output ('private' → requester-only
   * with an explicit share). Channel/team come ONLY from the signed claims. Not admin-gated — the
   * same non-secret policy bits `/vouchr tools` shows every channel member. The GET above stays: it
   * is the channel-independent provider list; this is "what may I do HERE, and how must I post it".
   */
  async function handleChannelManifest(body: { identityToken: string }): Promise<BrokerChannelManifestResponse> {
    const claims = await verify(body.identityToken);
    const principal: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    const tools = await buildToolManifest({
      providerIds: opts.providers.map((p) => p.id), registry,
      policy: opts.policy, channelTools: opts.channelTools, channelConfig: opts.channelConfig,
      principal, channel: claims.channel || null, // '' (a channel-less token) behaves like Bolt's DM context
    });
    return { tools };
  }

  /**
   * #58 `POST /v1/user/reference` — the acting user points their OWN credential for a provider at an
   * external secret-manager REFERENCE (the headless analogue of the Bolt key-setup modal's "reference
   * a secret manager"). Self-service (NOT admin-gated — it's the user's own credential), identity from
   * the signed token. Reference only: no raw secret crosses the broker (the injector resolves it JIT
   * at egress via `resolvers`). Refuses service tools. No secret in the response.
   */
  async function handleUserReference(body: {
    handle?: { provider?: unknown };
    identityToken: string;
    source?: unknown;
    secretRef?: unknown;
    scopes?: unknown;
  }): Promise<Record<string, unknown>> {
    const providerId = body.handle?.provider;
    if (typeof providerId !== 'string') throw new HttpError(400, { error: 'invalid handle' });
    if (typeof body.source !== 'string' || typeof body.secretRef !== 'string' || !body.source || !body.secretRef) {
      throw new HttpError(400, { error: 'source and secretRef are required' });
    }
    if (body.scopes !== undefined && typeof body.scopes !== 'string') throw new HttpError(400, { error: 'invalid scopes' });
    // Verify identity BEFORE probing the registry so an unauthenticated caller can't enumerate providers.
    const claims = await verify(body.identityToken);
    if (!registry.has(providerId)) throw new HttpError(404, { error: 'unknown provider' });
    if (!isBrokeredProvider(registry.get(providerId))) throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    // Carry the signed enterpriseId so an enterprise offboard (Grid/SCIM) can discover this reference.
    const identity: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    // Owner is the VERIFIED acting user, never the body — a forged body can't reference into another's slot.
    await opts.vault.reference(userOwner(identity), providerId, { source: body.source, secretRef: body.secretRef, scopes: body.scopes });
    await opts.audit.record('config', identity, providerId, { owner: 'user', kind: 'ref', source: body.source });
    return { ok: true };
  }

  // #101 liveness: the process is up and serving. NO auth, NO db, NO secrets — a bare {ok:true} so a
  // k8s livenessProbe never restarts a pod for a transient db blip (that's readiness' job).
  function handleHealthz(): { status: number; payload: Record<string, unknown> } {
    return { status: 200, payload: { ok: true } };
  }

  // #101/#212 readiness: verify the schema marker plus non-mutating EXPLAINs of the exact replay
  // INSERT/prune statements, within ~2s. Concurrent probes share ONE DB flight. If the HTTP deadline
  // wins, that flight remains the shared owner until its bounded DB work settles, so an outage cannot
  // pile a new pair of queries onto the pool every two seconds. NO auth, NO vault, no error detail.
  let readinessFlight: { work: Promise<boolean>; result: Promise<boolean> } | undefined;
  async function handleReadyz(): Promise<{ status: number; payload: Record<string, unknown> }> {
    if (!readinessFlight) {
      // allSettled is load-bearing: one check may fail immediately while its sibling DB query is
      // still running. Keep ownership until BOTH settle, otherwise the next probe starts another pair.
      const work = Promise.allSettled([assertSchemaCurrent(opts.db), replay.ready()]).then(
        (results) => results.every((result) => result.status === 'fulfilled'),
      );
      let timeout: NodeJS.Timeout | undefined;
      const result = Promise.race([
        work,
        new Promise<boolean>((resolve) => {
          timeout = setTimeout(() => resolve(false), 2_000);
          timeout.unref();
        }),
      ]).finally(() => {
        if (timeout) clearTimeout(timeout);
      });
      const flight = { work, result };
      readinessFlight = flight;
      // Do not clear on the HTTP race: after a timeout, keep sharing the still-running DB work. `work`
      // never rejects (it maps failures to false), so this cleanup cannot become unhandled.
      void work.then(() => {
        if (readinessFlight === flight) readinessFlight = undefined;
      });
    }
    const ok = await readinessFlight.result;
    return { status: ok ? 200 : 503, payload: { ok } };
  }

  // Node enforces headersTimeout/requestTimeout on this polling cadence. Its 30s default can make a
  // small configured timeout ineffective for nearly an extra 30s, so derive a ≤1s checker up front.
  const connectionsCheckingInterval = Math.max(
    1,
    Math.min(1_000, Math.floor(Math.min(headersTimeoutMs, requestTimeoutMs) / 4)),
  );
  const server = http.createServer({ connectionsCheckingInterval }, (req, res) => {
    void (async () => {
      let markHandlerDone = () => {};
      let requestAbort: AbortController | undefined;
      const send = (
        status: number,
        payload: Record<string, unknown>,
        headers?: Record<string, string>,
        closeConnection = false,
      ) => {
        // A rejected request whose body was not consumed must never stay reusable: the unread bytes
        // would pin the socket (or be mistaken for the next keep-alive request). Explicit size errors
        // close even when Node happened to parse the full over-cap body before the handler ran.
        const close = closeConnection || !req.complete;
        if (close) res.shouldKeepAlive = false;
        res.writeHead(status, {
          'content-type': 'application/json',
          ...headers,
          ...(close ? { connection: 'close' } : {}),
        });
        res.end(JSON.stringify(payload));
      };
      try {
        const url = req.url ?? '/';
        // #101 liveness + readiness probes: registered FIRST, BEFORE the perimeter/identity gate and
        // exempt from replay — a k8s probe carries no bearer and must never touch the vault.
        if (req.method === 'GET' && (url === '/healthz' || url === '/health')) {
          const r = handleHealthz();
          return send(r.status, r.payload);
        }
        if (req.method === 'GET' && url === '/readyz') {
          // #116: a dry-run broker refused against real state is UP (liveness) but must NOT report
          // ready — every functional route 500s, so readiness is 503 (k8s pulls it from rotation).
          if (dryRunReady) {
            await dryRunReady;
            if (dryRunRefusal) return send(503, { ok: false });
          }
          const r = await handleReadyz();
          return send(r.status, r.payload);
        }

        // #209 one true global admission lease for every functional request. It is acquired before
        // async perimeter authorization or body buffering and released only after BOTH the handler
        // settled and the response finished/closed. Slow readers therefore remain inside the memory
        // envelope; invalid/control-plane requests cannot bypass it. Health stays exempt; readiness
        // has its separately-collapsed DB flight above so probes remain available under load.
        const releaseGlobal = limiter.enter();
        let handlerDone = false;
        let responseDone = false;
        let released = false;
        const releaseIfDone = () => {
          if (released || !handlerDone || !responseDone) return;
          released = true;
          releaseGlobal();
        };
        markHandlerDone = () => {
          handlerDone = true;
          releaseIfDone();
        };

        requestAbort = new AbortController();
        const abortRequest = () => requestAbort?.abort(new DOMException('client disconnected', 'AbortError'));
        const settleResponse = (aborted: boolean) => {
          if (responseDone) return;
          responseDone = true;
          if (aborted) abortRequest();
          req.removeListener('aborted', onRequestAborted);
          res.removeListener('finish', onResponseFinish);
          res.removeListener('close', onResponseClose);
          releaseIfDone();
        };
        const onRequestAborted = () => settleResponse(true);
        const onResponseFinish = () => settleResponse(false);
        const onResponseClose = () => settleResponse(!res.writableFinished);
        req.once('aborted', onRequestAborted);
        res.once('finish', onResponseFinish);
        res.once('close', onResponseClose);
        if (req.aborted || res.destroyed) settleResponse(true);
        const requestSignal = requestAbort.signal;

        // #116 dry-run safety rail: every route below can touch credentials or consent, so nothing
        // is served until the vault check passed — a refusal fails every request closed (500).
        if (dryRunReady) {
          await dryRunReady;
          if (dryRunRefusal) throw dryRunRefusal;
        }
        requestSignal.throwIfAborted();
        // #52 OAuth redirect target — a human's browser lands here, so it returns HTML (not JSON) and
        // has NO perimeter gate (the provider redirects the user's browser, which carries no bearer).
        // Only mounted when baseUrl is configured. Match on the pathname (a callback carries a query).
        if (req.method === 'GET' && redirectUri && new URL(url, 'http://localhost').pathname === callbackPath) {
          const r = await handleCallback(new URL(url, 'http://localhost'), requestSignal);
          res.writeHead(r.status, { 'content-type': 'text/html; charset=utf-8' });
          return res.end(r.html);
        }
        if (req.method === 'POST' && url === '/v1/connect') {
          await perimeter(req, requestSignal);
          return send(200, await handleConnect(await readJson(req)));
        }
        if (req.method === 'GET' && url === '/v1/manifest') {
          await perimeter(req, requestSignal);
          return send(200, handleManifest());
        }
        if (req.method === 'POST' && url === '/v1/manifest') {
          await perimeter(req, requestSignal);
          return send(200, { ...await handleChannelManifest(await readJson(req)) });
        }
        if (req.method === 'POST' && url === '/v1/fetch') {
          await perimeter(req, requestSignal);
          const r = await handleFetch(
            await readJson(req, opts.allowWrites ? WRITE_REQUEST_CAP : READ_REQUEST_CAP),
            traceHeaders(req),
            requestSignal,
          );
          return send(r.status, r.payload);
        }
        if (req.method === 'POST' && url === '/v1/mcp') {
          await perimeter(req, requestSignal);
          // Streams the upstream response straight onto `res` (SSE passthrough) — no send() envelope.
          return await handleMcp(
            await readJson(req, opts.allowWrites ? WRITE_REQUEST_CAP : READ_REQUEST_CAP),
            traceHeaders(req),
            res,
            requestSignal,
          );
        }
        if (url === '/v1/mcp') {
          // #65 MCP spec: a server that doesn't offer the optional GET listening stream or
          // client-initiated DELETE termination answers 405 — exactly this stateless proxy's
          // posture. NOT 404: a 404 on a session-bearing GET reads as "session ended" and can loop
          // clients into re-initialization. Static; no perimeter/identity/provider gates run and
          // nothing goes upstream (the process-wide admission lease still bounds every route).
          return send(405, { error: 'only POST is supported on /v1/mcp' }, { allow: 'POST' });
        }
        if (req.method === 'POST' && url === '/v1/resolve') {
          await perimeter(req, requestSignal);
          return send(200, await handleResolve(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/disconnect') {
          await perimeter(req, requestSignal);
          return send(200, await handleDisconnect(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/admin/offboard') {
          await perimeter(req, requestSignal);
          return send(200, await handleOffboard(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/admin/reference') {
          await perimeter(req, requestSignal);
          return send(200, await handleAdminReference(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/admin/mode') {
          await perimeter(req, requestSignal);
          return send(200, { ...await handleAdminMode(await readJson(req)) });
        }
        if (req.method === 'POST' && url === '/v1/admin/tools') {
          await perimeter(req, requestSignal);
          return send(200, { ...await handleAdminTools(await readJson(req)) });
        }
        if (req.method === 'GET' && url === '/v1/admin/config') {
          await perimeter(req, requestSignal);
          // A GET carries no JSON body, so the signed identity token rides a header (never a query
          // string — keeps it out of access logs). Channel/team/admin all come from this signed token.
          const token = req.headers['x-vouchr-identity'];
          if (typeof token !== 'string' || !token) throw new HttpError(401, { error: 'invalid identity token' });
          return send(200, { ...await handleAdminConfig(token) });
        }
        if (req.method === 'POST' && url === '/v1/status') {
          await perimeter(req, requestSignal);
          return send(200, await handleStatus(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/audit') {
          await perimeter(req, requestSignal);
          return send(200, { ...await handleAudit(await readJson(req)) });
        }
        if (req.method === 'POST' && url === '/v1/admin/audit') {
          await perimeter(req, requestSignal);
          return send(200, { ...await handleAdminAudit(await readJson(req)) });
        }
        if (req.method === 'POST' && url === '/v1/user/reference') {
          await perimeter(req, requestSignal);
          return send(200, await handleUserReference(await readJson(req)));
        }
        send(404, { error: 'not found' });
      } catch (e) {
        // A request-scoped abort means the caller is gone. Never continue with a JSON error write or
        // log it as an internal failure; the close/aborted listener already carries the no-secret cause.
        if (requestAbort?.signal.aborted) return res.destroy();
        // A streaming route (/v1/mcp) can only fail after its headers are flushed if the relay's own
        // catch somehow rethrew; a JSON error can no longer be written, so tear the stream down
        // instead of crashing on a second writeHead.
        if (res.headersSent) return res.destroy();
        if (e instanceof HttpError) return send(e.status, e.payload, e.headers, e.closeConnection);
        // #209 in-flight ceiling full → 503 + Retry-After (whole seconds; ms also rides the payload).
        // The scope ('global'/'provider') is a non-secret operator signal, never request content.
        if (e instanceof OverloadedError) {
          return send(503, { error: 'overloaded', scope: e.scope, retryAfterMs: e.retryAfterMs }, { 'retry-after': String(Math.ceil(e.retryAfterMs / 1000)) });
        }
        // Log no part of an unknown thrown value. An extension point (e.g. a custom provider.inject)
        // can throw AFTER touching the secret, and even constructor.name is attacker-overridable.
        console.error('[vouchr] request failed');
        send(500, { error: 'internal error' }); // never echo internals to the client either
      } finally {
        markHandlerDone();
      }
    })();
  });
  // #209 inbound server timeouts: bound how long a client may take to send headers, then the whole
  // request (a slow-loris drip is cut here — server.close on shutdown then completes without waiting on
  // it), and how long an idle keep-alive socket lingers. Node checks header/request expiry only on
  // `connectionsCheckingInterval`; bound that cadence too, otherwise a 15s setting can take 30s+
  // to act. A finite general socket inactivity timeout covers handler/slow-reader paths outside the
  // inbound request timer; maxStreamMs is the longest legitimate quiet broker operation.
  server.headersTimeout = headersTimeoutMs;
  server.requestTimeout = requestTimeoutMs;
  server.keepAliveTimeout = keepAliveTimeoutMs;
  server.timeout = Math.max(fetchDeadlineMs, maxStreamMs);
  server.maxHeadersCount = 100;
  return server;
}
