import { LOOPBACK, type Provider } from './providers';
import type { Vault, StoredCredential } from './vault';
import type { SlackIdentity } from './identity';
import type { Owner } from './owner';
import type { Audit, AuditSink, VouchrAuditEvent } from './audit';
import { refreshToken, TokenEndpointError } from './tokens';
import { DryRunVaultError, dryRunEcho } from './dryRun';
import { MemoryRateLimitStore, RateLimitedError, type RateLimitStore } from './rateLimit';
import { safeEmit } from './safe-emit';
import type { CredentialHealthHook } from './health';
import { ApprovalRequiredError, queryDigest, type Approvals } from './approval';
import { randomUUID } from 'node:crypto';

/** Resolves an external secret-manager reference to a secret, just-in-time. Operator-provided. */
export type Resolvers = Record<string, (ref: string) => Promise<string>>;

/**
 * A structured, NO-SECRET observability event. Operators wire a single `EventSink` to feed
 * metrics/logs. Fields are non-secret only: provider id, host, status, counts, booleans.
 * NEVER carries tokens, secretRef values, user/team ids, or any user content.
 */
export type VouchrEvent =
  // `ms` = wall-clock latency of the outbound provider fetch (incl. a refresh-retry round trip).
  | { type: 'injected'; provider: string; host: string; status: number; ownerKind: 'user' | 'channel'; ms: number }
  // `ms` = wall-clock latency of the provider /token round trip.
  | { type: 'refreshed'; provider: string; ms: number }
  // Cross-process (Postgres) refresh coordination: time spent waiting for the advisory lock, and
  // whether this caller LOST the race and reused a concurrent winner's already-rotated token.
  | { type: 'refresh_lock_wait'; provider: string; waitMs: number; reused: boolean }
  // KMS/envelope decrypt volume: number of DEK unwraps (real KMS calls) for one credential read.
  // Only fires when envelope encryption is in use (count > 0); the legacy direct path makes no KMS call.
  | { type: 'kms_decrypt'; provider: string; count: number }
  // `reason` splits the single denial type by the gate that rejected: bad URL creds / non-allowlisted
  // host / non-https all map to 'host'; the finer egress gates map to 'path'/'method'/'validator';
  // 'mcp' = the headless broker's /v1/mcp per-provider opt-in gate (provider.mcp absent).
  | { type: 'egress_denied'; provider: string; host: string; reason: 'host' | 'method' | 'path' | 'validator' | 'mcp' }
  // The provider's RESPONSE violated a structural constraint (provider.egressResponse) and was
  // withheld from the caller: 'content_type' = disallowed Content-Type, 'size' = body over maxBytes.
  // Fires AFTER the outbound call (so it pairs with an 'injected' event for the same request);
  // never carries the offending header value or any body content.
  | { type: 'response_denied'; provider: string; host: string; reason: 'content_type' | 'size' }
  // The (owner, provider) token bucket was empty (see provider.rateLimit): the request was refused
  // BEFORE the vault read. `host` = url.hostname only (already allowlist-checked), never the full url.
  | { type: 'rate_limited'; provider: string; host: string }
  // No-secret UPSTREAM-FAILURE signal: a network-level throw (DNS/connection refused) or a token-refresh
  // throw. Without this a provider outage / refresh breakage is a silent black box (the broker maps it to
  // 502 with no event, no audit). `host` = url.hostname only, `reason` a static string ('fetch_failed'/
  // 'refresh_failed') — NEVER the error message (it could carry the secret).
  | { type: 'egress_error'; provider: string; host: string; reason: string }
  // #113 human-in-the-loop approval lifecycle: a request matched the provider's approval predicate
  // with no live grant (requested), and the human's decision (approved/denied). Provider + host
  // only — never the path, an approval id, the requester, or the approver (this sink is actor-free).
  | { type: 'approval_requested'; provider: string; host: string }
  | { type: 'approval_approved'; provider: string; host: string }
  | { type: 'approval_denied'; provider: string; host: string }
  | { type: 'resolver_failed'; provider: string; source: string }
  | { type: 'connect_prompted'; provider: string }
  | { type: 'connected'; provider: string }
  | { type: 'policy_denied'; provider: string }
  | { type: 'revoked'; provider: string; ok: boolean }
  | { type: 'expired'; count: number };

/** Fire-and-forget event sink. May be sync or async (`=> void` admits async functions — TS's
 *  void-callback rule); a throwing OR rejecting sink must never affect request behavior — every
 *  fire point routes through safeEmit, which swallows both failure shapes. Deliberately typed
 *  `=> void`, not `void | Promise<void>`: the union would reject the ubiquitous concise-arrow
 *  consumer `(e) => arr.push(e)` (void-substitution only applies to a bare `void` return). */
export type EventSink = (e: VouchrEvent) => void;

/**
 * A handle to a connection. The caller (and any LLM) gets this object, NEVER the
 * secret. The credential is attached to the outbound request inside `fetch`, after
 * the egress allowlist check.
 *
 * Two identities are carried separately and must never be conflated:
 *  - `owner`:  the principal that OWNS the credential (vault key); a user or a channel.
 *  - `acting`: the human who triggered this request (audit attribution), even when a
 *    shared channel credential is used. A shared cred never launders away who acted.
 */

/**
 * Egress allowlist / policy rejection — the requested target failed a gate BEFORE any secret was read.
 * The broker maps this to 403. The `.message` TEXT is preserved verbatim from the pre-typed
 * `Error('Egress blocked: …')` so callers that still string-match the message (e.g. bolt.ts) keep working;
 * this is purely additive typing so the broker can switch its regex to an `instanceof` check.
 */
export class EgressBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EgressBlockedError';
  }
}

/** No stored credential for this owner+provider. The broker maps this to 409. Message TEXT preserved. */
export class NoConnectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NoConnectionError';
  }
}

/**
 * The provider's RESPONSE violated a structural constraint (provider.egressResponse) — disallowed
 * content-type or an over-cap body — and was withheld from the caller. Unlike EgressBlockedError
 * this is thrown AFTER the request went out; the body is never returned, not even partially. The
 * message is Vouchr-authored and secret-free (safe for safeUserMessage); the broker maps this to
 * 413 (size) / 502 (content_type).
 */
export class ResponseBlockedError extends Error {
  constructor(
    message: string,
    public reason: 'content_type' | 'size',
  ) {
    super(message);
    this.name = 'ResponseBlockedError';
  }
}

/**
 * Path-lock matcher, shared by the `egressPaths` gate below and the broker's `/v1/mcp`
 * `provider.mcp.paths` gate (STR-2: one matcher, one semantics): `'/'` allows everything; a prefix
 * ending in `/` matches by startsWith; otherwise the exact segment or any subpath of it.
 */
export function pathAllowed(pathname: string, allowed: string): boolean {
  if (allowed === '/') return true;
  if (allowed.endsWith('/')) return pathname.startsWith(allowed);
  return pathname === allowed || pathname.startsWith(`${allowed}/`);
}

/**
 * Encoded path separators (%2f, %5c) survive WHATWG URL parsing UN-decoded, so a traversal segment
 * like `..%2f` can match an allowed prefix here yet resolve to a DIFFERENT path on an upstream that
 * later decodes it. Wherever a path lock IS the security boundary (`egressPaths` below, the
 * broker's `mcp.paths`), the ambiguity is refused fail-closed — a legitimate locked path never
 * contains an encoded separator. One rule, shared (STR-2).
 */
export const ENCODED_PATH_SEPARATOR = /%2f|%5c/i;

/**
 * Whether (method, path) falls under a provider's human-approval requirement (#113): the explicit
 * `approval.methods` list when set, else ANY non-read method (everything but GET/HEAD) — this is
 * the ONE place that default lives. `approval.paths` narrows by the same matcher semantics as
 * `egressPaths` (pathAllowed, STR-2); unset = every path. `method` is already upper-cased by fetch.
 */
export function approvalNeeded(a: NonNullable<Provider['approval']>, method: string, pathname: string): boolean {
  const methodMatch = a.methods
    ? a.methods.some((m) => m.toUpperCase() === method)
    : method !== 'GET' && method !== 'HEAD';
  if (!methodMatch) return false;
  if (!a.paths) return true;
  // `approval.paths` is a security boundary, so it inherits the egress guard's fail-closed rule
  // (STR-2, same ENCODED_PATH_SEPARATOR constant): an encoded separator (%2f/%5c) survives WHATWG
  // parsing here yet an upstream that decodes it routes to a DIFFERENT path — so `/payments%2Fsend`
  // could slip past a `/payments` lock unconfirmed. Require approval rather than let it through: the
  // human sees the odd path and decides. (When egressPaths is ALSO set, the injector's egress guard
  // already threw on the encoded separator before this ever runs; this covers the paths-without-
  // egressPaths case.)
  if (ENCODED_PATH_SEPARATOR.test(pathname)) return true;
  return a.paths.some((p) => pathAllowed(pathname, p));
}

/**
 * Normalize a content-type to its bare media type: case-folded, `; charset=`/params dropped. The
 * ONE matcher for both response gates (provider.egressResponse here, the broker's #26 allowlist) —
 * exact match on the bare type, so `application/json` admits `application/json; charset=utf-8`
 * but never `application/jsonp-evil`. A missing header normalizes to '' and matches nothing.
 */
export function normalizeContentType(ct: string | null): string {
  return (ct ?? '').split(';')[0].trim().toLowerCase();
}

export class ConnectionHandle {
  constructor(
    private provider: Provider,
    private owner: Owner,
    private acting: SlackIdentity,
    private vault: Vault,
    private audit: Audit,
    private resolvers: Resolvers = {},
    // Shared across handles so concurrent fetches for the same owner+provider refresh once.
    // Default = per-instance (no cross-request dedup), fine for direct construction in tests.
    private inflight: Map<string, Promise<string | null>> = new Map(),
    // No-secret observability hook. Default no-op (zero behavior change when unset).
    private sink: EventSink = () => {},
    // Optional audit STREAM sink (carries the raw actor id). Separate from `sink`, which is
    // deliberately actor-free. Default no-op. The authoritative copy is still the audit table.
    private auditSink: AuditSink = () => {},
    // The Slack channel this request originated in. Recorded on the inject audit for EVERY owner kind
    // (not just channel-owned), so `/vouchr stats` can attribute per-user / session usage to the
    // channel it happened in — otherwise those (the default modes) all read as "never used". Null when
    // there is no channel context (a DM, or a headless call whose token carries no channel).
    private originChannel: string | null = null,
    // Per-(owner, provider) token buckets for provider.rateLimit. Shared across handles (like
    // `inflight`) so the budget accumulates across requests; the adapters pass one store per
    // createVouchr/createBroker instance. Default = per-instance, fine for direct construction in tests.
    private rateLimits: RateLimitStore = new MemoryRateLimitStore(),
    // #117 credential-health hook: fired (post-rollback, outside the refresh lock) when a refresh
    // fails DEFINITIVELY (see doRefresh). Carries owner identity + provider, never token material —
    // deliberately separate from `sink`, whose no-user-ids contract is load-bearing. Default no-op.
    private health: CredentialHealthHook = () => {},
    // #113 human-in-the-loop approval store (provider.approval). Both adapters pass their
    // db-backed instance; null is fine for providers without the knob (the gate never runs), and
    // FAIL-CLOSED for providers with it (a declared approval must never be silently skipped).
    private approvals: Approvals | null = null,
    // The Slack thread this request runs in, binding an approval grant to its exact conversation
    // context (with originChannel). Null off-thread / headless-without-thread.
    private thread: string | null = null,
    // #116 dry-run: no real network call leaves this handle — the outbound call becomes a synthetic
    // echo (send()), the refresh /token round-trip is skipped (doRefresh), and any credential row
    // NOT carrying the dry-run marker is refused per-request (fetch). Every gate above the network
    // — egress, rate limit, vault read, header injection, AND the #113 approval gate — still runs.
    private dryRun = false,
  ) {}

  /** The identity key for this handle's (owner, provider) pair — the single-flight refresh map and
   *  the rate-limit buckets key on the same fact. */
  private ownerKey(): string {
    return `${this.owner.teamId}:${this.owner.kind}:${this.owner.id}:${this.provider.id}`;
  }

  /** The channel an injection is attributed to in the audit log: the explicit origin channel when known,
   *  else the owning channel for a channel-owned cred (preserves prior behavior), else null. */
  private auditChannel(): string | null {
    return this.originChannel ?? (this.owner.kind === 'channel' ? this.owner.id : null);
  }

  /** Fire the sink, swallowing any sync throw or async rejection. A bad sink must never break a request. */
  private emit(e: VouchrEvent): void {
    safeEmit(this.sink, e);
  }

  /**
   * Reject an egress attempt: fire the no-secret metric, write the AUTHORITATIVE audit row (who tried
   * to reach a non-allowlisted target), then throw. Meta carries ONLY the hostname + a static reason —
   * NEVER the raw url or headers: for URL-embedded-credential providers the secret lives in the url
   * userinfo, so logging the url would leak it.
   */
  private async denyEgress(
    host: string,
    reason: 'host' | 'method' | 'path' | 'validator',
    message: string,
  ): Promise<never> {
    this.emit({ type: 'egress_denied', provider: this.provider.id, host, reason });
    await this.audit.record('denied', this.acting, this.provider.id, { host, reason });
    throw new EgressBlockedError(message);
  }

  /**
   * Reject a provider RESPONSE that violates a structural constraint (provider.egressResponse):
   * fire the no-secret metric, write the audit row, then throw — the body is never handed back.
   * Mirrors denyEgress, but AFTER the outbound call: the 'inject' row for the call itself has
   * already been written, so the trail records both the call and the withheld response. Meta
   * carries the hostname + a static reason (+ the observed/declared byte count on a size breach) —
   * NEVER the Content-Type header value or any body content: those are unvalidated
   * provider-supplied strings, and an unvalidated string in an audit column is a stored-injection
   * bug (SEC-4).
   */
  private async denyResponse(host: string, reason: 'content_type' | 'size', message: string, bytes?: number): Promise<never> {
    this.emit({ type: 'response_denied', provider: this.provider.id, host, reason });
    await this.audit.record('denied', this.acting, this.provider.id, bytes === undefined ? { host, reason } : { host, reason, bytes });
    throw new ResponseBlockedError(message, reason);
  }

  /**
   * Structural response constraints at the injection boundary (#110), applied AFTER the fetch and
   * BEFORE the Response reaches the caller — so the Bolt handle and the HTTP broker inherit the
   * same guarantees. Structural only, never content inspection:
   *  - `set-cookie` is ALWAYS stripped (a credential-adjacent artifact the agent has no business
   *    seeing), plus any provider-listed `stripHeaders` — on every status, 3xx included (redirects
   *    are already `manual`, so the 3xx object itself is what the caller receives).
   *  - `allowContentTypes`: exact, case-insensitive match on the BARE media type (parameters like
   *    `; charset=` ignored; a missing header matches nothing — fail-closed), checked before any
   *    body byte is read; a mismatch cancels the unread body (undici otherwise pins the socket)
   *    and denies. Bodyless responses (res.body === null: 204/205/304, HEAD) are exempt — there
   *    is nothing to constrain.
   *  - `maxBytes`: fast-fail on a declared Content-Length, then enforced for real with a byte
   *    counter while streaming (a Content-Length can lie low; chunked bodies carry none).
   *    Buffering is bounded by the cap itself; past it the stream is cancelled — the connection is
   *    freed and the caller never sees a partial body.
   * A compliant response passes through byte-identical: untouched when there is nothing to strip
   * and no cap to enforce, else reconstructed with the same status/statusText/body bytes.
   */
  private async guardResponse(res: Response, host: string): Promise<Response> {
    const er = this.provider.egressResponse;
    // Bodyless responses (204/205/304; HEAD — undici gives res.body === null) carry nothing to
    // constrain: the content-type gate would otherwise fail-closed on their legitimately absent
    // Content-Type. Skip it for them (the maxBytes branch below is already body-gated); the
    // header strip still applies.
    if (er?.allowContentTypes && res.body !== null) {
      const ct = normalizeContentType(res.headers.get('content-type'));
      if (!er.allowContentTypes.some((allowed) => ct === normalizeContentType(allowed))) {
        res.body?.cancel().catch(() => undefined);
        await this.denyResponse(host, 'content_type', `Response blocked: content-type is not allowed for provider "${this.provider.id}"`);
      }
    }
    let body: BodyInit | null = res.body;
    if (er?.maxBytes !== undefined && res.body) {
      const cap = er.maxBytes;
      const message = `Response blocked: response exceeds ${cap} bytes for provider "${this.provider.id}"`;
      const declared = Number(res.headers.get('content-length'));
      if (Number.isFinite(declared) && declared > cap) {
        res.body.cancel().catch(() => undefined);
        await this.denyResponse(host, 'size', message, declared);
      }
      const reader = res.body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > cap) {
          // Abort mid-stream: never buffer past the cap; cancelling the reader frees the connection.
          await reader.cancel().catch(() => undefined);
          await this.denyResponse(host, 'size', message, total);
        }
        chunks.push(value);
      }
      body = Buffer.concat(chunks);
    }
    const strip = ['set-cookie', ...(er?.stripHeaders ?? [])];
    // Zero-change fast path: no cap buffering and nothing to strip → the original Response, untouched.
    if (body === res.body && !strip.some((h) => res.headers.has(h))) return res;
    const headers = new Headers(res.headers);
    for (const h of strip) headers.delete(h);
    // Reconstruct with the same status/statusText/bytes. Null-body statuses must pass null (the
    // Response constructor rejects any body on 204/205/304).
    const bodyless = res.status === 204 || res.status === 205 || res.status === 304;
    const out = new Response(bodyless ? null : body, { status: res.status, statusText: res.statusText, headers });
    // The Response constructor zeroes .url; carry the original through so callers that read it
    // (and the unconditional set-cookie strip puts ANY provider on this path) see no difference.
    Object.defineProperty(out, 'url', { value: res.url });
    return out;
  }

  /**
   * No-secret UPSTREAM-FAILURE signal for a network throw / refresh throw. Fires the egress_error metric
   * AND writes an attributable audit row so a provider outage / refresh breakage isn't a silent 502.
   * Meta carries ONLY the hostname + a static reason — NEVER the url, headers, or the error message (any
   * of which could carry the secret). Audit is best-effort: it must never mask the original throw.
   */
  private async egressError(host: string, reason: string): Promise<void> {
    this.emit({ type: 'egress_error', provider: this.provider.id, host, reason });
    // Carry the same origin channel as the success path so a FAILED call keeps its per-channel attribution.
    const ch = this.auditChannel();
    const channelMeta = ch ? { channel: ch } : {};
    await this.audit.record('inject', this.acting, this.provider.id, { host, reason, ok: false, ...channelMeta }).catch(() => undefined);
  }

  /** refreshAndStore + a no-secret failure signal on throw: refresh breakage must not be a silent 502.
   *  host = the OAuth TOKEN endpoint (where a refresh actually fails), not the target API host — matching
   *  the refresh-SUCCESS audit. tokenUrl is always present here (only OAuth providers refresh). */
  private async refreshSignalled(): Promise<string | null> {
    try {
      return await this.refreshAndStore();
    } catch (e) {
      await this.egressError(new URL(this.provider.tokenUrl).hostname, 'refresh_failed');
      throw e;
    }
  }

  /** Fire the audit stream sink, swallowing any sync throw or async rejection (safeEmit). Lossy
   *  convenience copy; the table is authoritative. */
  private emitAudit(action: VouchrAuditEvent['action'], egressHost: string, status: number, method?: string): void {
    safeEmit(this.auditSink, {
      ts: new Date().toISOString(),
      teamId: this.acting.teamId,
      userId: this.acting.userId, // raw actor id, never a token
      provider: this.provider.id,
      ownerKind: this.owner.kind,
      ownerId: this.owner.id,
      action,
      egressHost,
      method,
      status,
      jti: randomUUID(),
    });
  }

  async account(): Promise<string | null> {
    return (await this.vault.get(this.owner, this.provider.id))?.externalAccount ?? null;
  }

  async fetch(input: string, init: RequestInit = {}): Promise<Response> {
    const url = new URL(input);
    const method = (init.method ?? 'GET').toUpperCase();
    if (url.username || url.password) {
      await this.denyEgress(url.hostname, 'host', `Egress blocked: URL credentials are not allowed for provider "${this.provider.id}"`);
    }
    // Egress allowlist first, before any secret is even read.
    if (!this.provider.egressAllow.includes(url.hostname)) {
      await this.denyEgress(url.hostname, 'host', `Egress blocked: "${url.hostname}" is not in the allowlist for provider "${this.provider.id}"`);
    }
    // Allowlist matches hostname only, so an explicit port on a trusted host (e.g. api.provider.com:2375)
    // would otherwise sail through and let the broker connect to an arbitrary port. Fail-closed: only the
    // implicit HTTPS port is permitted: WHATWG normalizes the default `:443` to an empty `url.port`,
    // so `https://host:443` is allowed, while any non-default explicit port (e.g. `:2375`) is blocked.
    // Loopback is exempt for local dev, mirroring the https carve-out below (dev servers bind a port).
    if (url.port !== '' && !LOOPBACK.has(url.hostname)) {
      await this.denyEgress(url.hostname, 'host', `Egress blocked: explicit port ":${url.port}" is not allowed for provider "${this.provider.id}"`);
    }
    // The caller (and the LLM) controls this URL. Require https so the bearer is never sent in
    // cleartext (it goes out before any http→https redirect). Loopback is exempt for local dev.
    if (url.protocol !== 'https:' && !LOOPBACK.has(url.hostname)) {
      await this.denyEgress(url.hostname, 'host', `Egress blocked: provider "${this.provider.id}" requires https, got "${url.protocol}"`);
    }
    // Optional finer egress controls, all additive (unset = no constraint). Checked here so a denial
    // never reaches the vault: the secret is read strictly after every egress check passes.
    if (this.provider.egressPaths) {
      // See ENCODED_PATH_SEPARATOR: with a path lock in force the encoded-separator ambiguity is
      // refused fail-closed. (Providers WITHOUT a path lock, e.g. GitLab whose project ids are
      // `group%2Fproject`, are unaffected: this guard is gated on egressPaths.)
      if (ENCODED_PATH_SEPARATOR.test(url.pathname)) {
        await this.denyEgress(url.hostname, 'path', `Egress blocked: encoded path separator is not allowed for provider "${this.provider.id}"`);
      }
      if (!this.provider.egressPaths.some((p) => pathAllowed(url.pathname, p))) {
        await this.denyEgress(url.hostname, 'path', `Egress blocked: path "${url.pathname}" is not in the allowed paths for provider "${this.provider.id}"`);
      }
    }
    if (this.provider.egressMethods && !this.provider.egressMethods.some((m) => m.toUpperCase() === method)) {
      await this.denyEgress(url.hostname, 'method', `Egress blocked: method "${method}" is not allowed for provider "${this.provider.id}"`);
    }
    if (this.provider.egressValidate && !this.provider.egressValidate(url, init)) {
      await this.denyEgress(url.hostname, 'validator', `Egress blocked: validator rejected the request for provider "${this.provider.id}"`);
    }

    // Per-(owner, provider) throttle (provider.rateLimit) — checked AFTER the egress gates (a denied
    // target never spends budget) and BEFORE the vault read, so a rate-limited request never touches
    // the secret. Absent knob = unlimited, no behavior change. Meta mirrors denyEgress: hostname +
    // owner kind only — never the full url (a query string could carry sensitive params). Every value
    // written here is already validated: provider from the registry, host past the allowlist above,
    // owner kind from the typed Owner.
    const rl = this.provider.rateLimit;
    if (rl) {
      const taken = await this.rateLimits.take(this.ownerKey(), 1, rl.perMinute / 60_000, rl.burst ?? rl.perMinute);
      if (!taken.ok) {
        this.emit({ type: 'rate_limited', provider: this.provider.id, host: url.hostname });
        await this.audit.record('rate_limited', this.acting, this.provider.id, { host: url.hostname, owner: this.owner.kind });
        throw new RateLimitedError(this.provider.id, rl.perMinute, taken.retryAfterMs ?? 60_000);
      }
    }

    // #113 human-in-the-loop approval (provider.approval): an ADDITIONAL gate, never a bypass —
    // checked strictly AFTER every egress gate and the throttle above (an egress-denied or
    // rate-limited target never mints a prompt) and BEFORE the vault read below, so an unapproved
    // request never touches the secret and the decision is complete long before anything could
    // reach the wire. A live grant is spent here (single-use, EXACT method+host+path match); with
    // none, a pending request is recorded and the typed error tells the adapter to prompt.
    // The load-bearing invariant is NOT "a grant can't exist without a connection" (a broker handle
    // for an unconnected owner CAN mint a pending row here) — it is that a grant can never be SPENT
    // against a credential the human didn't approve: consume() runs BEFORE the vault read, so a
    // born-orphan grant just falls through to NoConnectionError below with zero injection, and any
    // (re)connect purges stale grants via the vault upsert before the new credential is usable.
    const ap = this.provider.approval;
    if (ap && approvalNeeded(ap, method, url.pathname)) {
      if (!this.approvals) {
        // Fail closed (STR-5): a provider that declares `approval` on a deployment that never wired
        // the store must hard-fail, not silently skip the gate. A wiring bug, and it says so.
        throw new Error(`Provider "${this.provider.id}" requires human approval but no approval store is wired.`);
      }
      // The grant carries TWO identities, matched independently on consume:
      //  - userId = the human DRIVING the agent (the caller = the acting user), who the adapter
      //    prompts and who self-approval matches.
      //  - ownerKind/ownerId = the credential this write will actually use. Binding it means a grant
      //    minted for one credential can't be spent after a per-user→shared mode change: the write can
      //    never run against a different credential than the human approved. It is also the purge key
      //    when the credential is revoked/reconnected (purgeApprovalsForOwner, run inside the vault
      //    mutation).
      // request() + consume() share this one key object, so both sites stay consistent by
      // construction. Audit still attributes to `acting` + the approver (below).
      const key = {
        teamId: this.acting.teamId, userId: this.acting.userId,
        ownerKind: this.owner.kind, ownerId: this.owner.id, provider: this.provider.id,
        // queryHash (GHSA-pg84): the grant binds the exact query string sent upstream, as a
        // digest — a retry with ANY textual change to the query re-prompts instead of spending
        // the human's approval.
        method, host: url.hostname, path: url.pathname, queryHash: queryDigest(url.search),
        channel: this.auditChannel(), thread: this.thread,
      };
      const grant = await this.approvals.consume(key);
      const apCh = this.auditChannel();
      const apChannelMeta = apCh ? { channel: apCh } : {};
      // Meta carries method + hostname + pathname only — never the body or any query value (SEC-1).
      const apMeta = { host: url.hostname, method, path: url.pathname, ...apChannelMeta };
      if (!grant) {
        const approvalId = await this.approvals.request(key);
        this.emit({ type: 'approval_requested', provider: this.provider.id, host: url.hostname });
        await this.audit.record('approval_requested', this.acting, this.provider.id, apMeta);
        // Only the parameter COUNT rides the error for the prompt display (GHSA-pg84): names are
        // as caller-controlled as values and must not reach Slack or logs (SEC-1). The exact
        // query is bound via the digest in the key above.
        throw new ApprovalRequiredError(this.provider.id, ap.approver, method, url.hostname, url.pathname, approvalId,
          [...url.searchParams.keys()].length);
      }
      // The grant is spent exactly once, right here — so the trail records the consumption even if
      // the upstream call later fails. The approver's identity rides the actor column (STR-4).
      await this.audit.record('approval_consumed', this.acting, this.provider.id, apMeta, grant.approvedBy ?? undefined);
    }

    // Count real KMS/envelope DEK unwraps incurred reading this credential (0 on the legacy path).
    let kms = 0;
    const cred = await this.vault.get(this.owner, this.provider.id, () => { kms++; });
    if (!cred) throw new NoConnectionError(`No connection for provider "${this.provider.id}"`);
    if (kms) this.emit({ type: 'kms_decrypt', provider: this.provider.id, count: kms });
    // #116 dry-run per-request rail: the startup vault check only sees rows that exist at boot —
    // a REAL row written afterward (a seeder, a sibling production process on the same database)
    // must never feed a dry-run request. Keyed off the trusted system-only dry_run column (never the
    // user/provider-controlled account label), off the row already in hand: zero extra reads.
    if (this.dryRun && !cred.dryRun) throw new DryRunVaultError();
    const vaulted = cred.source === 'vault';

    let token = vaulted ? await this.vaultToken(cred) : await this.resolveRef(cred);
    const send = async (t: string) => {
      // #116 dry-run: the outbound-fetch edge, stubbed at the exact point the network call would
      // happen — every gate above (egress, rate limit, vault read) has already run. Returned BEFORE
      // the production inject so the provider's inject hook runs EXACTLY ONCE (inside dryRunEcho,
      // with a <redacted> placeholder) and NEVER receives the real/synthetic token: calling it twice
      // — or with a token — could drift a stateful hook or make a real network call. `t` is unused here.
      if (this.dryRun) return dryRunEcho(this.provider, input, method);
      // Normalize caller headers (a Headers instance/tuple array would be dropped by a spread).
      const headers = new Headers(init.headers as HeadersInit | undefined);
      if (this.provider.inject) this.provider.inject(headers, t);
      else headers.set('Authorization', `Bearer ${t}`);
      try {
        // redirect:'manual', never auto-follow a 3xx off the allowlisted host with the bearer attached.
        return await fetch(input, { ...init, headers, redirect: 'manual' });
      } catch (e) {
        // Network-level throw (DNS/connection refused): fire the no-secret failure signal, then re-throw
        // so the broker still maps it to 502 — the signal is emitted, not swallowed.
        await this.egressError(url.hostname, 'fetch_failed');
        throw e;
      }
    };

    const t0 = Date.now();
    let res = await send(token);
    // Refresh-on-401 only applies to vaulted OAuth creds; referenced secrets rotate externally.
    if (res.status === 401 && vaulted && this.provider.refresh !== 'none') {
      let refreshed: string | null;
      try {
        refreshed = await this.refreshSignalled();
      } catch (e) {
        // #168: a refresh throw abandons the 401 too — drain it, or undici pins the socket to the
        // unread body until GC. Best-effort: cancelling must never mask the refresh error. (Not a
        // finally: when the refresh yields nothing the 401 itself is returned, body intact.)
        res.body?.cancel().catch(() => undefined);
        throw e;
      }
      if (refreshed) {
        // Drain the discarded 401: undici pins the socket to its unread body until GC otherwise.
        res.body?.cancel().catch(() => undefined);
        res = await send(refreshed);
      }
    }
    const fetchMs = Date.now() - t0;

    // Mark the connection used (resets its idle TTL) and audit AS THE ACTING HUMAN, never the secret.
    // Best-effort: the provider call already happened, so a bookkeeping failure must not surface as a
    // failed fetch (the caller might retry a non-idempotent request).
    await this.vault.touch(this.owner, this.provider.id).catch(() => undefined);
    // Attribute the injection to the channel it happened in (origin channel, or the owning channel for a
    // channel-owned cred). Powers per-channel usage analytics across ALL modes, not just shared.
    const ch = this.auditChannel();
    const channelMeta = ch ? { channel: ch } : {};
    await this.audit
      .record('inject', this.acting, this.provider.id, { host: url.hostname, method, status: res.status, ...channelMeta })
      .catch(() => undefined);
    // No-secret observability: provider/host/status/ownerKind only, never the token or the actor.
    this.emit({ type: 'injected', provider: this.provider.id, host: url.hostname, status: res.status, ownerKind: this.owner.kind, ms: fetchMs });
    // Audit stream copy (raw actor id, for host-side ingestion). Lossy; the audit table is authoritative.
    this.emitAudit('fetch', url.hostname, res.status, method);
    // #116 dry-run: skip the RESPONSE gate — there is no real provider response to constrain, and
    // applying provider.egressResponse to the synthetic echo would false-deny where production
    // passes (e.g. allowContentTypes without application/json, or maxBytes below the echo size).
    // Request-side gates all ran above; only the constraint on the synthetic body is meaningless.
    if (this.dryRun) return res;
    // Structural response constraints (provider.egressResponse) + the unconditional set-cookie
    // strip: enforced HERE, after the outbound call is booked (the call DID happen — its inject
    // audit/event stay truthful) and before the Response is handed back, so both doors (Bolt
    // handle + HTTP broker) inherit them. A breach throws; the caller never sees a partial body.
    return this.guardResponse(res, url.hostname);
  }

  /** Resolve an external-ref secret JIT. Never persisted, never cached, never logged. */
  private async resolveRef(cred: StoredCredential): Promise<string> {
    const resolver = this.resolvers[cred.source];
    if (!resolver) {
      throw new Error(`No resolver registered for secret source "${cred.source}"`);
    }
    if (!cred.secretRef) {
      throw new Error(`Referenced connection for "${this.provider.id}" has no secret_ref`);
    }
    try {
      return await resolver(cred.secretRef);
    } catch (e) {
      this.emit({ type: 'resolver_failed', provider: this.provider.id, source: cred.source });
      throw e;
    }
  }

  private async vaultToken(cred: StoredCredential): Promise<string> {
    const expiringSoon = cred.expiresAt != null && cred.expiresAt < Date.now() + 30_000;
    if (expiringSoon && cred.refreshToken && this.provider.refresh !== 'none') {
      const refreshed = await this.refreshSignalled();
      if (refreshed) return refreshed;
    }
    if (cred.accessToken == null) throw new Error(`Vaulted connection for "${this.provider.id}" has no token`);
    return cred.accessToken;
  }

  // Single-flight: concurrent fetches for the same owner+provider share one refresh. Without this,
  // rotating-refresh-token providers (the second refresh sees a consumed token) brick the connection.
  private async refreshAndStore(): Promise<string | null> {
    const key = this.ownerKey();
    const existing = this.inflight.get(key);
    if (existing) return existing;
    const p = this.doRefresh();
    this.inflight.set(key, p);
    try {
      return await p;
    } finally {
      this.inflight.delete(key);
    }
  }

  private async doRefresh(): Promise<string | null> {
    // Count real KMS/envelope DEK unwraps on BOTH refresh-path reads (the pre-lock read and the
    // re-read under the lock) so the kms_decrypt volume metric isn't understated on a refresh.
    let kms = 0;
    const onDecrypt = () => { kms++; };
    const emitKms = () => { if (kms) this.emit({ type: 'kms_decrypt', provider: this.provider.id, count: kms }); };
    // The refresh token we're about to consume. On Postgres a peer pod may rotate it while we wait
    // for the lock; we detect that by re-reading under the lock and comparing against this value.
    const before = await this.vault.get(this.owner, this.provider.id, onDecrypt);
    if (!before?.refreshToken) { emitKms(); return null; }
    // #116 dry-run: the refresh edge is a REAL /token network call — never make it. All refresh
    // triggers funnel through here (near-expiry in vaultToken, retry-on-401), so this one gate
    // covers e.g. a seeded dry-run row carrying a refreshToken + near expiresAt. The synthetic
    // token never truly expires; hand back the stored one unchanged, nothing rotates.
    if (this.dryRun) { emitKms(); return before.accessToken; }
    const lockWait = this.vault.crossProcessRefresh; // only emit the wait metric when a real lock exists
    const t0 = Date.now();
    // Track whether we actually rotated so the audit/emit run AFTER the transaction commits — never
    // inside it. On rotating-token providers the /token call has already consumed the old refresh
    // token by the time we write the new one, so if audit.record() threw inside withRefreshLock it
    // would ROLL BACK the freshly-stored token, leaving us holding an already-invalidated refresh
    // token and bricking the connection. Bookkeeping must not be able to undo a committed rotation.
    let rotated = false;
    let refreshMs = 0; // #27 timing, captured in-lock but emitted post-commit with the 'refreshed' event
    const token = await this.vault.withRefreshLock(this.owner, this.provider.id, async (vault) => {
      // Re-read UNDER the lock: another tx may already have rotated since the read above.
      const stored = await vault.get(this.owner, this.provider.id, onDecrypt);
      emitKms(); // both reads done — report total unwraps once for this refresh
      const waitMs = Date.now() - t0;
      if (!stored?.refreshToken) return null;
      // Loser path: the stored refresh token moved, so a concurrent winner already refreshed. Reuse
      // its access token — refreshing again would consume a token the winner invalidated (rotating
      // providers brick on a double refresh).
      if (stored.refreshToken !== before.refreshToken) {
        if (lockWait) this.emit({ type: 'refresh_lock_wait', provider: this.provider.id, waitMs, reused: true });
        return stored.accessToken;
      }
      if (lockWait) this.emit({ type: 'refresh_lock_wait', provider: this.provider.id, waitMs, reused: false });
      const r0 = Date.now();
      const refreshed = await refreshToken(this.provider, stored.refreshToken);
      // updateTokens, not upsert: refresh must not reset created_at (max-age TTL).
      await vault.updateTokens(this.owner, this.provider.id, {
        accessToken: refreshed.accessToken,
        refreshToken: refreshed.refreshToken ?? stored.refreshToken,
        scopes: refreshed.scopes ?? stored.scopes,
        expiresAt: refreshed.expiresAt,
      });
      rotated = true;
      refreshMs = Date.now() - r0;
      return refreshed.accessToken;
    }).catch((e: unknown) => {
      // #117: a DEFINITIVE token-endpoint failure (invalid_grant / 400/401 — the one classification,
      // on TokenEndpointError in tokens.ts) means the stored refresh token is dead and only a
      // reconnect fixes it. Fire the health hook HERE — after withRefreshLock has rolled back and
      // released the advisory lock, mirroring the post-commit audit placement below: a hook must
      // never run inside the lock. The instanceof gate also means a rollback for any OTHER reason
      // (a DB write failure after a successful /token call, a lock timeout) never claims the token
      // is dead, and transient failures (network throw, 5xx, timeout) never fire. safeEmit swallows
      // a throwing hook; the original error always re-throws unchanged.
      if (e instanceof TokenEndpointError && e.definitive) {
        safeEmit(this.health, { type: 'refresh_dead', owner: this.owner, provider: this.provider.id });
      }
      throw e;
    });
    // Post-commit, best-effort: a failed audit write must not surface as a failed refresh nor undo it.
    if (rotated) {
      await this.audit.record('refresh', this.acting, this.provider.id, {}).catch(() => undefined);
      this.emit({ type: 'refreshed', provider: this.provider.id, ms: refreshMs });
      // egressHost = the provider token endpoint we refreshed against; status 200 (it succeeded).
      this.emitAudit('refresh', new URL(this.provider.tokenUrl).hostname, 200);
    }
    return token;
  }
}
