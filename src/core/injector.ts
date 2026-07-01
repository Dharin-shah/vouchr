import type { Provider } from './providers';
import type { Vault, StoredCredential } from './vault';
import type { SlackIdentity } from './identity';
import type { Owner } from './owner';
import type { Audit, AuditSink, VouchrAuditEvent } from './audit';
import { refreshToken } from './tokens';
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
  ) {}

  /** Fire the sink, swallowing any error. A bad sink must never break a request. */
  private emit(e: VouchrEvent): void {
    try {
      this.sink(e);
    } catch {
      // ignore: observability is best-effort, never fatal
    }
  }

  /** Fire the audit stream sink, swallowing any error. Lossy convenience copy; the table is authoritative. */
  private emitAudit(action: VouchrAuditEvent['action'], egressHost: string, status: number): void {
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
    if (url.username || url.password) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname, reason: 'host' });
      throw new Error(`Egress blocked: URL credentials are not allowed for provider "${this.provider.id}"`);
    }
    // Egress allowlist first, before any secret is even read.
    if (!this.provider.egressAllow.includes(url.hostname)) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname, reason: 'host' });
      throw new Error(
        `Egress blocked: "${url.hostname}" is not in the allowlist for provider "${this.provider.id}"`,
      );
    }
    // The caller (and the LLM) controls this URL. Require https so the bearer is never sent in
    // cleartext (it goes out before any http→https redirect). Loopback is exempt for local dev.
    if (url.protocol !== 'https:' && !LOOPBACK.has(url.hostname)) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname, reason: 'host' });
      throw new Error(`Egress blocked: provider "${this.provider.id}" requires https, got "${url.protocol}"`);
    }
    // Optional finer egress controls, all additive (unset = no constraint). Checked here so a denial
    // never reaches the vault: the secret is read strictly after every egress check passes.
    if (this.provider.egressPaths && !this.provider.egressPaths.some((p) => pathAllowed(url.pathname, p))) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname, reason: 'path' });
      throw new Error(
        `Egress blocked: path "${url.pathname}" is not in the allowed paths for provider "${this.provider.id}"`,
      );
    }
    if (this.provider.egressMethods) {
      const method = (init.method ?? 'GET').toUpperCase();
      if (!this.provider.egressMethods.some((m) => m.toUpperCase() === method)) {
        this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname, reason: 'method' });
        throw new Error(
          `Egress blocked: method "${method}" is not allowed for provider "${this.provider.id}"`,
        );
      }
    }
    if (this.provider.egressValidate && !this.provider.egressValidate(url, init)) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname, reason: 'validator' });
      throw new Error(`Egress blocked: validator rejected the request for provider "${this.provider.id}"`);
    }

    // Count real KMS/envelope DEK unwraps incurred reading this credential (0 on the legacy path).
    let kms = 0;
    const cred = await this.vault.get(this.owner, this.provider.id, () => { kms++; });
    if (!cred) throw new Error(`No connection for provider "${this.provider.id}"`);
    if (kms) this.emit({ type: 'kms_decrypt', provider: this.provider.id, count: kms });
    const vaulted = cred.source === 'vault';

    let token = vaulted ? await this.vaultToken(cred) : await this.resolveRef(cred);
    const send = (t: string) => {
      // Normalize caller headers (a Headers instance/tuple array would be dropped by a spread).
      const headers = new Headers(init.headers as HeadersInit | undefined);
      if (this.provider.inject) this.provider.inject(headers, t);
      else headers.set('Authorization', `Bearer ${t}`);
      // redirect:'manual', never auto-follow a 3xx off the allowlisted host with the bearer attached.
      return fetch(input, { ...init, headers, redirect: 'manual' });
    };

    const t0 = Date.now();
    let res = await send(token);
    // Refresh-on-401 only applies to vaulted OAuth creds; referenced secrets rotate externally.
    if (res.status === 401 && vaulted && this.provider.refresh !== 'none') {
      const refreshed = await this.refreshAndStore();
      if (refreshed) res = await send(refreshed);
    }
    const fetchMs = Date.now() - t0;

    // Mark the connection used (resets its idle TTL) and audit AS THE ACTING HUMAN, never the secret.
    // Best-effort: the provider call already happened, so a bookkeeping failure must not surface as a
    // failed fetch (the caller might retry a non-idempotent request).
    await this.vault.touch(this.owner, this.provider.id).catch(() => undefined);
    // Attribute the injection to the channel when the cred is channel-owned (owner.id IS the channel
    // id then). For a user-owned cred owner.id is a user id, not a channel. Leave channel unset.
    const channelMeta = this.owner.kind === 'channel' ? { channel: this.owner.id } : {};
    await this.audit
      .record('inject', this.acting, this.provider.id, { host: url.hostname, status: res.status, ...channelMeta })
      .catch(() => undefined);
    // No-secret observability: provider/host/status/ownerKind only, never the token or the actor.
    this.emit({ type: 'injected', provider: this.provider.id, host: url.hostname, status: res.status, ownerKind: this.owner.kind, ms: fetchMs });
    // Audit stream copy (raw actor id, for host-side ingestion). Lossy; the audit table is authoritative.
    this.emitAudit('fetch', url.hostname, res.status);
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
      const refreshed = await this.refreshAndStore();
      if (refreshed) return refreshed;
    }
    if (cred.accessToken == null) throw new Error(`Vaulted connection for "${this.provider.id}" has no token`);
    return cred.accessToken;
  }

  // Single-flight: concurrent fetches for the same owner+provider share one refresh. Without this,
  // rotating-refresh-token providers (the second refresh sees a consumed token) brick the connection.
  private async refreshAndStore(): Promise<string | null> {
    const key = `${this.owner.teamId}:${this.owner.kind}:${this.owner.id}:${this.provider.id}`;
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
