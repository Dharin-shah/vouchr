import type { Provider } from './providers';
import type { Vault, StoredCredential } from './vault';
import type { SlackIdentity } from './identity';
import type { Owner } from './owner';
import type { Audit } from './audit';
import { refreshToken } from './tokens';

/** Resolves an external secret-manager reference to a secret, just-in-time. Operator-provided. */
export type Resolvers = Record<string, (ref: string) => Promise<string>>;

/**
 * A structured, NO-SECRET observability event. Operators wire a single `EventSink` to feed
 * metrics/logs. Fields are non-secret only: provider id, host, status, counts, booleans.
 * NEVER carries tokens, secretRef values, user/team ids, or any user content.
 */
export type VouchrEvent =
  | { type: 'injected'; provider: string; host: string; status: number; ownerKind: 'user' | 'channel' }
  | { type: 'refreshed'; provider: string }
  | { type: 'egress_denied'; provider: string; host: string }
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
  ) {}

  /** Fire the sink, swallowing any error. A bad sink must never break a request. */
  private emit(e: VouchrEvent): void {
    try {
      this.sink(e);
    } catch {
      // ignore: observability is best-effort, never fatal
    }
  }

  async account(): Promise<string | null> {
    return (await this.vault.get(this.owner, this.provider.id))?.externalAccount ?? null;
  }

  async fetch(input: string, init: RequestInit = {}): Promise<Response> {
    const url = new URL(input);
    if (url.username || url.password) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname });
      throw new Error(`Egress blocked: URL credentials are not allowed for provider "${this.provider.id}"`);
    }
    // Egress allowlist first, before any secret is even read.
    if (!this.provider.egressAllow.includes(url.hostname)) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname });
      throw new Error(
        `Egress blocked: "${url.hostname}" is not in the allowlist for provider "${this.provider.id}"`,
      );
    }
    // The caller (and the LLM) controls this URL. Require https so the bearer is never sent in
    // cleartext (it goes out before any http→https redirect). Loopback is exempt for local dev.
    if (url.protocol !== 'https:' && !LOOPBACK.has(url.hostname)) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname });
      throw new Error(`Egress blocked: provider "${this.provider.id}" requires https, got "${url.protocol}"`);
    }
    // Optional finer egress controls, all additive (unset = no constraint). Checked here so a denial
    // never reaches the vault: the secret is read strictly after every egress check passes.
    if (this.provider.egressPaths && !this.provider.egressPaths.some((p) => pathAllowed(url.pathname, p))) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname });
      throw new Error(
        `Egress blocked: path "${url.pathname}" is not in the allowed paths for provider "${this.provider.id}"`,
      );
    }
    if (this.provider.egressMethods) {
      const method = (init.method ?? 'GET').toUpperCase();
      if (!this.provider.egressMethods.some((m) => m.toUpperCase() === method)) {
        this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname });
        throw new Error(
          `Egress blocked: method "${method}" is not allowed for provider "${this.provider.id}"`,
        );
      }
    }
    if (this.provider.egressValidate && !this.provider.egressValidate(url, init)) {
      this.emit({ type: 'egress_denied', provider: this.provider.id, host: url.hostname });
      throw new Error(`Egress blocked: validator rejected the request for provider "${this.provider.id}"`);
    }

    const cred = await this.vault.get(this.owner, this.provider.id);
    if (!cred) throw new Error(`No connection for provider "${this.provider.id}"`);
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

    let res = await send(token);
    // Refresh-on-401 only applies to vaulted OAuth creds; referenced secrets rotate externally.
    if (res.status === 401 && vaulted && this.provider.refresh !== 'none') {
      const refreshed = await this.refreshAndStore();
      if (refreshed) res = await send(refreshed);
    }

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
    this.emit({ type: 'injected', provider: this.provider.id, host: url.hostname, status: res.status, ownerKind: this.owner.kind });
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
    const stored = await this.vault.get(this.owner, this.provider.id);
    if (!stored?.refreshToken) return null;
    const refreshed = await refreshToken(this.provider, stored.refreshToken);
    // updateTokens, not upsert: refresh must not reset created_at (max-age TTL).
    await this.vault.updateTokens(this.owner, this.provider.id, {
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken ?? stored.refreshToken,
      scopes: refreshed.scopes ?? stored.scopes,
      expiresAt: refreshed.expiresAt,
    });
    await this.audit.record('refresh', this.acting, this.provider.id, {});
    this.emit({ type: 'refreshed', provider: this.provider.id });
    return refreshed.accessToken;
  }
}
