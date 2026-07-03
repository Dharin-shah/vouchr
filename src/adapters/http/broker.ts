import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import type { Db } from '../../core/db';
import type { Vault } from '../../core/vault';
import type { Audit, AuditSink } from '../../core/audit';
import type { Policy } from '../../core/policy';
import type { ChannelTools } from '../../core/tools';
import { ProviderRegistry, type Provider } from '../../core/providers';
import { ConnectionHandle, type Resolvers, type EventSink, type VouchrEvent } from '../../core/injector';
import { userOwner, channelOwner, type Owner } from '../../core/owner';
import type { ChannelConfig, ChannelMode } from '../../core/channelConfig';
import { authorizeProvider, resolveCredentialOwner } from '../../core/authz';
import type { SlackIdentity } from '../../core/identity';
import { Consent } from '../../core/consent';
import { SessionGrants } from '../../core/session';
import { disconnectProvider, offboardUser, offboardUserEverywhere } from '../../core/offboard';
import { handleOAuthCallback } from '../../core/oauthCallback';
import { verifyIdentity, IdentityError, ReplayGuard, type IdentityClaims, type ReplayStore } from './identity';

/**
 * The opaque, NO-SECRET handle the caller holds. It names a provider; the owner is always the acting
 * user from the verified identity token, never this handle — so the handle can be forged without
 * granting any cross-tenant access.
 *
 * `owner: 'channel'` (#51) is a transport-agnostic channel gate: the broker still has no Slack client,
 * so the trusted caller supplies the Slack-derived facts (eligibility, the union acting-member) as
 * SIGNED claims and the broker resolves the credential owner from those claims, never from this handle.
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

export interface BrokerOptions {
  providers: Provider[];
  vault: Vault;
  audit: Audit;
  /** Used by /healthz to confirm the store is reachable. */
  db: Db;
  /** HS256 secret shared ONLY by the upstream minter and this broker. */
  identitySecret: string;
  /**
   * #52 public HTTPS origin of THIS broker (e.g. `https://broker.example`). Setting it MOUNTS the OAuth
   * connect flow: `POST /v1/connect` (mint an authorize URL for the verified user) and
   * `GET <callbackPath>` (the provider redirect target). Unset → neither route mounts (additive; the
   * historical use-only broker is unchanged). The `redirectUri` handed to providers is
   * `new URL(callbackPath, baseUrl)`.
   */
  baseUrl?: string;
  /** #52 OAuth redirect path mounted under `baseUrl`. Default `/oauth/callback`. */
  callbackPath?: string;
  /**
   * Single-use jti store for replay protection. Default is an in-memory per-process guard, which is
   * single-use ONLY within one process — a horizontally scaled broker fleet MUST supply a shared
   * store (e.g. Redis `SET jti 1 NX PX=<ttl>`) or a signed token can be replayed once per pod within
   * its (<=5min) window. See ReplayStore / #22.
   */
  replayStore?: ReplayStore;
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
   * channel's mode (`shared` → the channel credential; `union` → the signed `actingMemberId`'s own
   * credential, audited as that member). Owner + eligibility come ONLY from the signed identity claims,
   * never the request body — so a forged body cannot assert a channel credential.
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
  /** #26 response size cap in bytes; over-cap is rejected 413, never truncated. Default 1 MiB. */
  maxResponseBytes?: number;
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
   * remains the only source of user claims. Keeps deployer-specific auth out of `src/`.
   */
  authorize?: (req: http.IncomingMessage) => void | Promise<void>;
}

const DEFAULT_ALLOWED_CT = ['application/json'];
const DEFAULT_MAX_BYTES = 1024 * 1024;
const READ_REQUEST_CAP = 64 * 1024; // read envelopes are tiny; reject anything larger.
const WRITE_BODY_CAP = 64 * 1024;
const WRITE_REQUEST_CAP = WRITE_BODY_CAP + READ_REQUEST_CAP;

class HttpError extends Error {
  constructor(public status: number, public payload: Record<string, unknown>) {
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

/** #26: normalize a content-type to its bare type, case-folded, charset/params dropped. */
function normalizeContentType(ct: string | null): string {
  return (ct ?? '').split(';')[0].trim().toLowerCase();
}

/** Escape for HTML text context — the OAuth landing page interpolates provider/account/error, and
 *  `error`/`account` are attacker- or provider-influenced, so this is a reflected-XSS guard (#52). */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

/** Minimal browser landing page for the OAuth callback (headless has no chat surface to nudge back to). */
function landingHtml(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"></head><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center"><h2>${title}</h2><p>${body}</p></body></html>`;
}

function responseHasNoBody(res: Response): boolean {
  const contentLength = res.headers.get('content-length');
  return res.status === 204 || res.status === 205 || (contentLength != null && Number(contentLength) === 0);
}

async function readJson(req: http.IncomingMessage, cap = READ_REQUEST_CAP): Promise<any> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > cap) throw new HttpError(413, { error: 'request body too large' });
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
    res.body?.cancel().catch(() => undefined);
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

function ownerFromClaims(c: IdentityClaims): { owner: Owner; acting: SlackIdentity } {
  const acting: SlackIdentity = { enterpriseId: c.enterpriseId ?? null, teamId: c.teamId, userId: c.userId };
  // The owner id comes ONLY from verified claims (the acting user). The request body's handle never
  // supplies an id, so a forged body can't cross tenants.
  return { owner: userOwner(acting), acting };
}

export function createBroker(opts: BrokerOptions): http.Server {
  if (!opts.identitySecret) throw new Error('createBroker: identitySecret is required');
  // authorize REPLACES the static brokerToken gate (not AND). Setting both means the bearer is never
  // checked — reject it so nobody wires both expecting defense-in-depth.
  if (opts.authorize && opts.brokerToken) {
    throw new Error('createBroker: set either authorize or brokerToken, not both (authorize replaces the bearer gate)');
  }
  const registry = new ProviderRegistry(opts.providers);
  const allowedCt = (opts.allowedContentTypes ?? DEFAULT_ALLOWED_CT).map((c) => c.toLowerCase());
  const maxBytes = opts.maxResponseBytes ?? DEFAULT_MAX_BYTES;
  // Default in-memory guard is single-process only; a multi-instance fleet passes a shared replayStore.
  const replay: ReplayStore = opts.replayStore ?? new ReplayGuard();
  // ONE inflight map shared by every request's ConnectionHandle, so concurrent requests for the same
  // owner+provider collapse to a single token refresh (rotating-refresh providers brick on a double
  // refresh). Per-request maps would defeat that. On Postgres the advisory lock also coordinates
  // cross-pod; this covers in-process concurrency (incl. the SQLite single-replica case).
  const inflight = new Map<string, Promise<string | null>>();

  // Broker-local metrics emit. Fire-and-forget: a throwing sink must NEVER affect the request (else a
  // broken metrics sink would turn an intended 403 deny into a 500). Mirrors the Bolt path's swallow;
  // the ConnectionHandle pass-through below swallows its own internally.
  const emit = (ev: VouchrEvent) => { try { opts.onEvent?.(ev); } catch { /* a throwing sink never affects the request */ } };

  // #54 lifecycle: consent + session stores for offboarding (purge pending consent + thread grants so
  // neither can resurrect access after a user is removed). #52 OAuth connect flow (mounted only when
  // baseUrl is set) reuses the same Consent: it owns the single-use state + PKCE; handleOAuthCallback
  // owns the code exchange — the broker adds no crypto/state logic itself. Cheap Db wrappers.
  const consent = new Consent(opts.db);
  const sessions = new SessionGrants(opts.db);
  const callbackPath = opts.callbackPath ?? '/oauth/callback';
  const redirectUri = opts.baseUrl ? new URL(callbackPath, opts.baseUrl).toString() : undefined;

  /** Perimeter check on /v1/* BEFORE identity. Prefers a pluggable `authorize` hook (e.g. serviceauth),
   *  else the static `brokerToken` bearer, else no gate. NOT identity — that's the signed token. */
  async function perimeter(req: http.IncomingMessage): Promise<void> {
    if (opts.authorize) {
      try {
        await opts.authorize(req);
      } catch (e) {
        if (e instanceof HttpError) throw e;
        throw new HttpError(401, { error: 'unauthorized' });
      }
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
   * verdict is present. `shared` keys the vault on the channel and audits the acting human; `union`
   * keys on and audits the signed acting member — never the channel, never the caller.
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
    const memberId = claims.actingMemberId;
    const actingMember: SlackIdentity | null = memberId
      ? { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: memberId }
      : null;
    const r = resolveCredentialOwner({ path: 'channel', mode, principal: acting, channel: claims.channel, eligible, actingMember });
    if (r.status === 'refused') {
      if (r.code === 'ineligible') {
        await opts.audit.record('denied', acting, ref.provider, { channel: claims.channel, owner: 'channel', reason: 'channel-ineligible' });
        throw new HttpError(403, { error: 'channel is ineligible for a shared credential' });
      }
      // 'per-user' / 'session' / unconfigured are user-owned modes; a channel handle can't reach them.
      throw new HttpError(403, { error: 'channel is not configured for a channel-owned credential' });
    }
    if (r.status !== 'resolved') {
      // union with no signed actingMemberId → no member to act as (the caller resolves it via the Slack
      // client and signs it). A bad request, not a policy denial.
      throw new HttpError(400, { error: 'union mode requires a signed actingMemberId' });
    }
    return { owner: r.owner, acting: r.acting };
  }

  async function resolveTarget(body: BrokerFetchRequest): Promise<{ handle: ConnectionHandle; provider: Provider }> {
    const ref = body.handle;
    if (!ref || (ref.owner !== 'user' && ref.owner !== 'channel') || typeof ref.provider !== 'string') {
      throw new HttpError(400, { error: 'invalid handle' });
    }
    if (!registry.has(ref.provider)) throw new HttpError(404, { error: 'unknown provider' });
    // Service-to-service tools have no human credential to broker (see ToolManifestEntry.identity):
    // Vouchr is deliberately not in that path, so the broker refuses them just like connect() does.
    if (registry.get(ref.provider).identity === 'service') {
      throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    }
    const claims = await verify(body.identityToken);
    await authorize(ref.provider, claims);
    const provider = withEgressDefaults(registry.get(ref.provider), opts.allowWrites);
    const { owner, acting } = await resolveOwner(ref, claims);
    // The 7th arg is the createBroker-scoped SHARED inflight map, so concurrent requests for the same
    // owner+provider collapse to one token refresh (rotating-refresh providers brick on a double
    // refresh). The 8th wires the metrics sink so the broker path stops being a black box; the 9th
    // wires the audit STREAM sink (raw actor id) for host-side ingestion.
    const handle = new ConnectionHandle(provider, owner, acting, opts.vault, opts.audit, opts.resolvers ?? {}, inflight, opts.onEvent, opts.auditSink);
    return { handle, provider };
  }

  async function handleFetch(body: BrokerFetchRequest, trace: Record<string, string> = {}): Promise<{ status: number; payload: Record<string, unknown> }> {
    const method = requestMethod(body.method);
    // Default fail-closed read-only. Reject non-GET/HEAD with 405 BEFORE identity/vault/upstream.
    if (!opts.allowWrites && method !== 'GET' && method !== 'HEAD') {
      throw new HttpError(405, { error: 'only GET and HEAD are allowed' });
    }
    const outboundBody = requestBody(body.body);
    if ((method === 'GET' || method === 'HEAD') && outboundBody !== undefined) {
      throw new HttpError(400, { error: 'GET and HEAD requests cannot carry a body' });
    }
    const { handle, provider } = await resolveTarget(body);

    const host = body.host ?? provider.egressAllow[0];
    let url: URL;
    try {
      url = new URL(`https://${host}${body.path ?? '/'}`); // caller input -> 4xx, not a 500
    } catch {
      throw new HttpError(400, { error: 'invalid host or path' });
    }
    for (const [k, v] of Object.entries(body.query ?? {})) url.searchParams.set(k, v);

    // Forward only a tiny safe header allowlist; never the caller's Authorization (broker injects).
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(body.headers ?? {})) {
      if (['accept', 'accept-language', 'if-none-match', 'content-type'].includes(k.toLowerCase())) headers[k] = v;
    }
    // W3C trace context read off the INCOMING request (not the body), forwarded verbatim onto the
    // outbound provider fetch so a host can stitch the broker hop into the agent's trace. Non-secret
    // (traceid/spanid/flags only); no-op when the caller sends no traceparent; no vendor dep.
    // ponytail: forward as-is rather than minting a child span — span management is the host's job.
    Object.assign(headers, trace);

    let res: Response;
    try {
      res = await handle.fetch(url.toString(), { method, headers, body: outboundBody });
    } catch (e) {
      const msg = (e as Error).message;
      if (/Egress blocked/.test(msg)) throw new HttpError(403, { error: 'egress blocked' });
      if (/No connection/.test(msg)) throw new HttpError(409, { error: 'not connected' });
      throw new HttpError(502, { error: 'upstream fetch failed' });
    }

    const contentType = res.headers.get('content-type') ?? '';
    // HEAD/no-content responses have no body to guard or relay; return status + content-type only.
    if (method === 'HEAD' || responseHasNoBody(res)) {
      res.body?.cancel().catch(() => undefined);
      return { status: 200, payload: { status: res.status, contentType, body: '' } };
    }
    // #26: content-type allowlist checked BEFORE the body is read (charset stripped, case-folded).
    if (!allowedCt.includes(normalizeContentType(contentType))) {
      res.body?.cancel().catch(() => undefined);
      throw new HttpError(502, { error: `disallowed content-type: ${normalizeContentType(contentType) || 'unknown'}` });
    }
    // #26: size cap -> 413, never a truncated partial body.
    const text = await readCapped(res, maxBytes);
    return { status: 200, payload: { status: res.status, contentType, body: text } };
  }

  async function handleResolve(body: { handle: ConnectionHandleRef; identityToken: string }): Promise<Record<string, unknown>> {
    const ref = body.handle;
    if (!ref || ref.owner !== 'user' || typeof ref.provider !== 'string') {
      throw new HttpError(400, { error: 'invalid handle' });
    }
    if (!registry.has(ref.provider)) throw new HttpError(404, { error: 'unknown provider' });
    // Service-to-service tools are not brokered by Vouchr — don't even report their consent state
    // (else /v1/resolve would call a service tool "connected"/"needs_consent"). Refuse like /v1/fetch.
    if (registry.get(ref.provider).identity === 'service') {
      throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    }
    const claims = await verify(body.identityToken);
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
      return { ok: true, revoked: summary.flatMap((s) => s.providers) };
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
    if (!registry.has(providerId)) throw new HttpError(404, { error: 'unknown provider' });
    if (registry.get(providerId).identity === 'service') throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });

    const claims = await verify(body.identityToken);
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
   * #52 `POST /v1/connect` — mint an OAuth authorize URL for the VERIFIED user. State is bound to the
   * identity in the signed token (never the body), so a forged body can't mint consent for someone
   * else. The broker handles no raw token here; the token is only ever written to the vault inside the
   * callback below. Refuses service tools (no human cred) and key providers (no OAuth handshake).
   */
  async function handleConnect(body: { handle?: { provider?: unknown }; identityToken: string }): Promise<Record<string, unknown>> {
    if (!redirectUri) throw new HttpError(404, { error: 'oauth connect is not configured' });
    const providerId = body.handle?.provider;
    if (typeof providerId !== 'string') throw new HttpError(400, { error: 'invalid handle' });
    if (!registry.has(providerId)) throw new HttpError(404, { error: 'unknown provider' });
    const provider = registry.get(providerId);
    if (provider.identity === 'service') throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    if (provider.credential === 'key') throw new HttpError(400, { error: 'provider has no OAuth flow; supply a key instead' });
    const claims = await verify(body.identityToken);
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
  async function handleCallback(url: URL): Promise<{ status: number; html: string }> {
    const q = url.searchParams;
    const result = await handleOAuthCallback(
      { registry, vault: opts.vault, audit: opts.audit, consent, redirectUri: redirectUri!, auditSink: opts.auditSink },
      q.get('code') ?? undefined,
      q.get('state') ?? undefined,
      q.get('error') ?? undefined,
    );
    if (result.ok) return { status: 200, html: landingHtml(`✅ ${escapeHtml(result.provider)} connected${result.account ? ` as ${escapeHtml(result.account)}` : ''}`, 'You can close this tab and return to your app.') };
    return { status: result.status, html: landingHtml('Connection failed', escapeHtml(result.error)) };
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
      .filter((p) => registry.get(p.id).identity !== 'service') // service tools aren't brokered by Vouchr
      .map((p) => {
        const isConnected = connected.has(p.id);
        return { provider: p.id, connected: isConnected, consentState: isConnected ? 'connected' : 'needs_consent' };
      });
    return { providers };
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
    if (!registry.has(providerId)) throw new HttpError(404, { error: 'unknown provider' });
    if (registry.get(providerId).identity === 'service') throw new HttpError(403, { error: 'service-to-service tool; not brokered by Vouchr' });
    const claims = await verify(body.identityToken);
    // Carry the signed enterpriseId so an enterprise offboard (Grid/SCIM) can discover this reference.
    const identity: SlackIdentity = { enterpriseId: claims.enterpriseId ?? null, teamId: claims.teamId, userId: claims.userId };
    // Owner is the VERIFIED acting user, never the body — a forged body can't reference into another's slot.
    await opts.vault.reference(userOwner(identity), providerId, { source: body.source, secretRef: body.secretRef, scopes: body.scopes });
    await opts.audit.record('config', identity, providerId, { owner: 'user', kind: 'ref', source: body.source });
    return { ok: true };
  }

  async function handleHealthz(): Promise<{ status: number; payload: Record<string, unknown> }> {
    let dbReachable = false;
    try {
      await opts.db.get('SELECT 1');
      dbReachable = true;
    } catch {
      dbReachable = false;
    }
    const signingKeyLoaded = Boolean(opts.identitySecret);
    const ok = dbReachable && signingKeyLoaded;
    return { status: ok ? 200 : 503, payload: { ok, dbReachable, signingKeyLoaded } };
  }

  return http.createServer((req, res) => {
    void (async () => {
      const send = (status: number, payload: Record<string, unknown>) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      try {
        const url = req.url ?? '/';
        if (req.method === 'GET' && (url === '/healthz' || url === '/health')) {
          const r = await handleHealthz();
          return send(r.status, r.payload);
        }
        // #52 OAuth redirect target — a human's browser lands here, so it returns HTML (not JSON) and
        // has NO perimeter gate (the provider redirects the user's browser, which carries no bearer).
        // Only mounted when baseUrl is configured. Match on the pathname (a callback carries a query).
        if (req.method === 'GET' && redirectUri && new URL(url, 'http://localhost').pathname === callbackPath) {
          const r = await handleCallback(new URL(url, 'http://localhost'));
          res.writeHead(r.status, { 'content-type': 'text/html; charset=utf-8' });
          return res.end(r.html);
        }
        if (req.method === 'POST' && url === '/v1/connect') {
          await perimeter(req);
          return send(200, await handleConnect(await readJson(req)));
        }
        if (req.method === 'GET' && url === '/v1/manifest') {
          await perimeter(req);
          return send(200, handleManifest());
        }
        if (req.method === 'POST' && url === '/v1/fetch') {
          await perimeter(req);
          const r = await handleFetch(await readJson(req, opts.allowWrites ? WRITE_REQUEST_CAP : READ_REQUEST_CAP), traceHeaders(req));
          return send(r.status, r.payload);
        }
        if (req.method === 'POST' && url === '/v1/resolve') {
          await perimeter(req);
          return send(200, await handleResolve(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/disconnect') {
          await perimeter(req);
          return send(200, await handleDisconnect(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/admin/offboard') {
          await perimeter(req);
          return send(200, await handleOffboard(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/admin/reference') {
          await perimeter(req);
          return send(200, await handleAdminReference(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/status') {
          await perimeter(req);
          return send(200, await handleStatus(await readJson(req)));
        }
        if (req.method === 'POST' && url === '/v1/user/reference') {
          await perimeter(req);
          return send(200, await handleUserReference(await readJson(req)));
        }
        send(404, { error: 'not found' });
      } catch (e) {
        if (e instanceof HttpError) return send(e.status, e.payload);
        // Log the error CLASS NAME only — never the message/stack/payload. An extension point (e.g. a
        // custom provider.inject) can throw AFTER touching the secret, so the message could carry the
        // token; logging it would break the "tokens never enter logs" invariant. The type still triages.
        console.error('[vouchr] request failed:', (e as Error)?.constructor?.name ?? 'Error');
        send(500, { error: 'internal error' }); // never echo internals to the client either
      }
    })();
  });
}
