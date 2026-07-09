import type { Provider } from './providers';
import type { Vault, StoredCredential } from './vault';
import type { SlackIdentity } from './identity';
import type { Owner } from './owner';
import type { Audit, AuditSink, VouchrAuditEvent } from './audit';
import { refreshToken } from './tokens';
import { MemoryRateLimitStore, RateLimitedError, type RateLimitStore } from './rateLimit';
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
  // host / non-https all map to 'host'; the finer egress gates map to 'path'/'method'/'validator'.
  | { type: 'egress_denied'; provider: string; host: string; reason: 'host' | 'method' | 'path' | 'validator' }
  // The (owner, provider) token bucket was empty (see provider.rateLimit): the request was refused
  // BEFORE the vault read. `host` = url.hostname only (already allowlist-checked), never the full url.
  | { type: 'rate_limited'; provider: string; host: string }
  // No-secret UPSTREAM-FAILURE signal: a network-level throw (DNS/connection refused) or a token-refresh
  // throw. Without this a provider outage / refresh breakage is a silent black box (the broker maps it to
  // 502 with no event, no audit). `host` = url.hostname only, `reason` a static string ('fetch_failed'/
  // 'refresh_failed') — NEVER the error message (it could carry the secret).
  | { type: 'egress_error'; provider: string; host: string; reason: string }
  | { type: 'resolver_failed'; provider: string; source: string }
  | { type: 'connect_prompted'; provider: string }
  | { type: 'connected'; provider: string }
  | { type: 'policy_denied'; provider: string }
  | { type: 'revoked'; provider: string; ok: boolean }
  | { type: 'expired'; count: number };

/** Fire-and-forget event sink. Sync; a throwing sink must never affect request behavior. */
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
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);

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

function pathAllowed(pathname: string, allowed: string): boolean {
  if (allowed === '/') return true;
  if (allowed.endsWith('/')) return pathname.startsWith(allowed);
  return pathname === allowed || pathname.startsWith(`${allowed}/`);
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
    // The human who TRIGGERED this request, when it differs from `acting` (union mode: `acting` is the
    // borrowed member, not the caller). Added to the inject audit meta so non-repudiation records BOTH
    // the acted-as member and the real triggerer. Default null = same as acting (nothing extra recorded).
    private triggeredBy: string | null = null,
    // The Slack channel this request originated in. Recorded on the inject audit for EVERY owner kind
    // (not just channel-owned), so `/vouchr stats` can attribute per-user / session / union usage to the
    // channel it happened in — otherwise those (the default modes) all read as "never used". Null when
    // there is no channel context (a DM, or a headless call whose token carries no channel).
    private originChannel: string | null = null,
    // Per-(owner, provider) token buckets for provider.rateLimit. Shared across handles (like
    // `inflight`) so the budget accumulates across requests; the adapters pass one store per
    // createVouchr/createBroker instance. Default = per-instance, fine for direct construction in tests.
    private rateLimits: RateLimitStore = new MemoryRateLimitStore(),
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

  /** Union non-repudiation: the real triggerer id when a union borrow makes it differ from the acted-as
   *  member; else undefined. A plain userId, never a secret. Populates the audit `actor` column so the
   *  owner's `/vouchr audit` view can surface WHO borrowed their credential. */
  private triggerActor(): string | undefined {
    return this.triggeredBy && this.triggeredBy !== this.acting.userId ? this.triggeredBy : undefined;
  }

  /** Same triggerer, in meta form for the audit-stream copy. Empty on every non-union path. */
  private triggerMeta(): Record<string, string> {
    const a = this.triggerActor();
    return a ? { triggeredBy: a } : {};
  }

  /** Fire the sink, swallowing any error. A bad sink must never break a request. */
  private emit(e: VouchrEvent): void {
    try {
      this.sink(e);
    } catch {
      // ignore: observability is best-effort, never fatal
    }
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
   * No-secret UPSTREAM-FAILURE signal for a network throw / refresh throw. Fires the egress_error metric
   * AND writes an attributable audit row so a provider outage / refresh breakage isn't a silent 502.
   * Meta carries ONLY the hostname + a static reason — NEVER the url, headers, or the error message (any
   * of which could carry the secret). Audit is best-effort: it must never mask the original throw.
   */
  private async egressError(host: string, reason: string): Promise<void> {
    this.emit({ type: 'egress_error', provider: this.provider.id, host, reason });
    // Carry the same union triggerer AND origin channel as the success path so a FAILED call keeps its
    // non-repudiation and its per-channel attribution.
    const ch = this.auditChannel();
    const channelMeta = ch ? { channel: ch } : {};
    await this.audit.record('inject', this.acting, this.provider.id, { host, reason, ok: false, ...channelMeta, ...this.triggerMeta() }, this.triggerActor()).catch(() => undefined);
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

  /** Fire the audit stream sink, swallowing any error. Lossy convenience copy; the table is authoritative. */
  private emitAudit(action: VouchrAuditEvent['action'], egressHost: string, status: number, method?: string): void {
    try {
      this.auditSink({
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
    } catch {
      // ignore: best-effort, never fatal
    }
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
      // Encoded path separators (%2f, %5c) survive WHATWG URL parsing UN-decoded, so a traversal
      // segment like `/statements/..%2f..%2fsecrets` still matches an allowed prefix here, yet
      // resolves to a DIFFERENT path on any upstream that later decodes %2f. When a path lock is in
      // force it IS the security boundary, so refuse the ambiguity fail-closed — a legitimate locked
      // path never contains an encoded separator. (Providers WITHOUT a path lock, e.g. GitLab whose
      // project ids are `group%2Fproject`, are unaffected: this guard is gated on egressPaths.)
      if (/%2f|%5c/i.test(url.pathname)) {
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

    // Count real KMS/envelope DEK unwraps incurred reading this credential (0 on the legacy path).
    let kms = 0;
    const cred = await this.vault.get(this.owner, this.provider.id, () => { kms++; });
    if (!cred) throw new NoConnectionError(`No connection for provider "${this.provider.id}"`);
    if (kms) this.emit({ type: 'kms_decrypt', provider: this.provider.id, count: kms });
    const vaulted = cred.source === 'vault';

    let token = vaulted ? await this.vaultToken(cred) : await this.resolveRef(cred);
    const send = async (t: string) => {
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
      const refreshed = await this.refreshSignalled();
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
      .record('inject', this.acting, this.provider.id, { host: url.hostname, method, status: res.status, ...channelMeta, ...this.triggerMeta() }, this.triggerActor())
      .catch(() => undefined);
    // No-secret observability: provider/host/status/ownerKind only, never the token or the actor.
    this.emit({ type: 'injected', provider: this.provider.id, host: url.hostname, status: res.status, ownerKind: this.owner.kind, ms: fetchMs });
    // Audit stream copy (raw actor id, for host-side ingestion). Lossy; the audit table is authoritative.
    this.emitAudit('fetch', url.hostname, res.status, method);
    return res;
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
