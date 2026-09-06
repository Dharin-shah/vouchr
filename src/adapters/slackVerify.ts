// #302: the Slack OpenID Connect hop that proves the browser completing provider OAuth is signed
// in to Slack as the user the consent `state` was bound to. Every Connect link goes through it. Slack-semantic
// (endpoint URLs, the `ok` envelope, id_token claim names) → adapter layer, like slack-identity.ts.
// ONE verifier shared by the Bolt routes and the headless broker owns the compare + spend + audit
// sequence (STR-3), so the two surfaces cannot drift.
import { randomUUID } from 'node:crypto';
import type { Audit, AuditSink, VouchrAuditEvent } from '../core/audit';
import type { Consent } from '../core/consent';
import type { ProviderRegistry } from '../core/providers';
import {
  DEFAULT_OAUTH_TIMEOUT_MS,
  cancelResponseBody,
  disposableDeadline,
  readResponseJsonCapped,
} from '../core/httpBounds';
import { safeEmit } from '../core/safe-emit';
import { CONNECT_PROMPT_STALE_TEXT } from './blocks';

// Slack's published endpoints, deliberately NOT configurable: the id_token is accepted without
// signature verification because it arrives directly from this token endpoint over TLS — a
// configurable endpoint would be a seam that receives the client secret + code and can fabricate
// any identity, defeating the feature. Offline tests stub `fetch` (TEST-3) instead.
export const SLACK_OIDC_AUTHORIZE_URL = 'https://slack.com/openid/connect/authorize';
export const SLACK_OIDC_TOKEN_URL = 'https://slack.com/api/openid.connect.token';
const SLACK_OIDC_ISSUER = 'https://slack.com';
const SLACK_TEAM_CLAIM = 'https://slack.com/team_id';

/** Slack app OIDC credentials for {@link BrowserIdentityVerifier}. */
export interface SlackOidcOptions {
  /** The Slack app's client id (the same app that owns the bot/installation). */
  clientId: string;
  /** The Slack app's client secret. Never logged, never persisted, never in any error. */
  clientSecret: string;
}

/** Validate the required OIDC config at startup (fail closed, before any listener/pool opens). The
 *  message names the env pair both surfaces read so a bare boot log says what to set. */
export function assertSlackOidcOptions(oidc: SlackOidcOptions | undefined, label: string): SlackOidcOptions {
  if (!oidc || typeof oidc.clientId !== 'string' || oidc.clientId.trim() === ''
    || typeof oidc.clientSecret !== 'string' || oidc.clientSecret.trim() === '') {
    throw new Error(
      `${label}: slackOidc.clientId and slackOidc.clientSecret are required ` +
        '(VOUCHR_SLACK_CLIENT_ID / VOUCHR_SLACK_CLIENT_SECRET, the Slack app OIDC credentials for the ' +
        'browser identity check on every Connect link). Refusing to start without them.',
    );
  }
  return oidc;
}

export type BrowserVerifyResult =
  | { ok: true; redirectUrl: string }
  | { ok: false; status: number; error: string };

// Fixed, non-reflecting outcomes. No Slack id, provider detail, or upstream error text ever appears
// here (SEC-1/SEC-5); the pages render these strings verbatim.
// #347: the Slack click that opened this page replaced the prompt with a "Send a new link" button.
const STALE: BrowserVerifyResult = {
  ok: false,
  status: 400,
  error: `${CONNECT_PROMPT_STALE_TEXT} The prompt in Slack now offers a new link.`,
};
// The state stays live. An in-channel prompt was replaced on click (#347) and a re-ask reposts the
// same generation; a channel-less DM prompt is durable and never redelivered. One sentence covers both.
const INCOMPLETE: BrowserVerifyResult = {
  ok: false,
  status: 400,
  error: 'Slack sign-in did not complete. Go back to Slack. If the connection prompt is still there, use it; if not, ask the agent again.',
};
const EXCHANGE_FAILED: BrowserVerifyResult = {
  ok: false,
  status: 502,
  error: 'Slack could not verify this browser session. Try again, or contact an administrator.',
};
const MISMATCH: BrowserVerifyResult = {
  ok: false,
  status: 403,
  error: 'This connection prompt was issued to a different Slack user. Ask the agent for your own connection prompt.',
};
// The state is spent but the durable audit row could not be written: an operational failure must
// stay distinguishable from a fully recorded denial (same rule as the callback's recorded ? x : 500).
const MISMATCH_UNRECORDED: BrowserVerifyResult = {
  ok: false,
  status: 500,
  error: 'This connection prompt was issued to a different Slack user, but Vouchr could not record the outcome. Contact an administrator.',
};

export interface BrowserIdentityVerifierDeps {
  consent: Consent;
  registry: ProviderRegistry;
  /** The provider OAuth redirect target (the existing callback URL) — rebuilt authorize URLs bind to it. */
  redirectUri: string;
  /** This hop's own browser redirect target (`<baseUrl>` + the adapter's Slack-callback path). */
  oidcRedirectUri: string;
  audit: Audit;
  auditSink?: AuditSink;
  oidc: SlackOidcOptions;
}

/**
 * The two-route state machine in front of provider OAuth:
 * `begin` (GET …/verify?state=S) redirects the browser to Slack's OIDC authorize, and `complete`
 * (GET …/slack?code&state) exchanges the code at Slack's token endpoint, compares the id_token
 * identity to the one bound in S, stamps `consent_request.slack_verified_at` on match, and only then
 * reveals the real provider authorize URL. On mismatch the state is spent (single-use) and the
 * outcome audited — the Slack identity observed in the id_token is compared and discarded, never
 * persisted, rendered, or audited as a value (SEC-1/SEC-4/SEC-5).
 */
export class BrowserIdentityVerifier {
  constructor(private deps: BrowserIdentityVerifierDeps) {}

  async begin(state: unknown): Promise<BrowserVerifyResult> {
    const row = typeof state === 'string' ? await this.deps.consent.activeRow(state) : null;
    if (!row) return STALE;
    const url = new URL(SLACK_OIDC_AUTHORIZE_URL);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid');
    url.searchParams.set('client_id', this.deps.oidc.clientId);
    url.searchParams.set('redirect_uri', this.deps.oidcRedirectUri);
    // The consent state doubles as the OIDC state: it binds Slack's redirect back to exactly this
    // consent row, and it is already an unguessable single-use 32-byte value (SEC-2).
    url.searchParams.set('state', row.state);
    return { ok: true, redirectUrl: url.toString() };
  }

  async complete(
    q: { code?: unknown; state?: unknown; error?: unknown },
    signal?: AbortSignal,
  ): Promise<BrowserVerifyResult> {
    const row = typeof q.state === 'string' ? await this.deps.consent.activeRow(q.state) : null;
    if (!row) return STALE;
    // A Slack-side authorize error (cancel, expired session) is not an identity mismatch: leave the
    // state live so the legitimate user can retry from the same prompt within the TTL.
    if (q.error !== undefined || typeof q.code !== 'string' || q.code.length === 0) return INCOMPLETE;

    const identity = await this.exchange(q.code, signal);
    if (!identity) return EXCHANGE_FAILED;

    // Byte-exact comparison against the bound tuple; the observed values are dropped right after.
    if (identity.sub !== row.identity.userId || identity.team !== row.identity.teamId) {
      // Spend the single-use state FIRST (fail closed even if the audit store is down), then record
      // the blocked hand-off attributed to the BOUND identity — never the completer's (SEC-4).
      await this.deps.consent.consume(row.state);
      let recorded = true;
      try {
        await this.deps.audit.record('denied', row.identity, row.provider, { reason: 'browser_identity_mismatch' });
      } catch {
        recorded = false; // state stays spent; the response must not claim a recorded denial
      }
      this.emitFailed(row.identity, row.provider, recorded ? 403 : 500);
      return recorded ? MISMATCH : MISMATCH_UNRECORDED;
    }

    // Stamp-then-reveal, atomic against consume/supersede/expiry: losing the race means the state
    // is no longer the newest generation, so the hop fails closed instead of resurrecting it.
    if (!(await this.deps.consent.markSlackVerified(row.state))) return STALE;
    if (!this.deps.registry.has(row.provider)) return STALE;
    const provider = this.deps.registry.get(row.provider);
    return {
      ok: true,
      redirectUrl: this.deps.consent.providerAuthorizeUrl(provider, this.deps.redirectUri, row.state, row.pkceVerifier),
    };
  }

  /**
   * Exchange the OIDC code at Slack's token endpoint and return the id_token identity, or null on
   * any failure. Vouchr-internal Slack call: like every token-endpoint edge it is outside the
   * provider egress gate, bounded by the same OAuth deadline and response cap as tokenRequest, with
   * redirects refused (the code is a replayable secret). The response's `access_token` is a Slack
   * user token Vouchr has no use for — it is never read, stored, or logged (SEC-1). Signature
   * verification is intentionally omitted per OIDC Core §3.1.3.7: the token arrives directly from
   * Slack's token endpoint over TLS in this same request; issuer/audience/expiry are still checked.
   */
  private async exchange(code: string, signal?: AbortSignal): Promise<{ sub: string; team: string } | null> {
    const deadline = disposableDeadline(DEFAULT_OAUTH_TIMEOUT_MS, signal);
    try {
      let res: Response;
      try {
        res = await fetch(SLACK_OIDC_TOKEN_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: this.deps.oidc.clientId,
            client_secret: this.deps.oidc.clientSecret,
            redirect_uri: this.deps.oidcRedirectUri,
          }).toString(),
          redirect: 'manual',
          signal: deadline.signal,
        });
      } catch (error) {
        if (signal?.aborted) throw error;
        return null;
      }
      if (!res.ok) {
        await cancelResponseBody(res);
        return null;
      }
      let json: unknown;
      try {
        json = await readResponseJsonCapped(res);
      } catch (error) {
        if (signal?.aborted) throw error;
        return null;
      }
      return idTokenIdentity(json, this.deps.oidc.clientId);
    } finally {
      deadline.dispose();
    }
  }

  /** Stream copy of a blocked hand-off. egressHost is Slack's token endpoint — the only host this
   *  verification egressed to (the provider was never contacted). Status mirrors the response: 403
   *  when the authoritative audit row was written, 500 when that write failed. */
  private emitFailed(identity: { teamId: string; userId: string }, provider: string, status: number): void {
    const e: VouchrAuditEvent = {
      ts: new Date().toISOString(),
      teamId: identity.teamId,
      userId: identity.userId,
      provider,
      ownerKind: 'user',
      ownerId: identity.userId,
      action: 'consent_failed',
      egressHost: new URL(SLACK_OIDC_TOKEN_URL).hostname,
      status,
      jti: randomUUID(),
    };
    safeEmit(this.deps.auditSink, e);
  }
}

/** Parse Slack's openid.connect.token envelope and validate the id_token claims. Returns null on
 *  ANY shape/issuer/audience/expiry problem — the caller maps null to one fixed error. */
function idTokenIdentity(json: unknown, clientId: string): { sub: string; team: string } | null {
  if (!json || typeof json !== 'object' || (json as { ok?: unknown }).ok !== true) return null;
  const idToken = (json as { id_token?: unknown }).id_token;
  if (typeof idToken !== 'string') return null;
  const parts = idToken.split('.');
  if (parts.length !== 3) return null;
  let claims: any;
  try {
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!claims || typeof claims !== 'object' || claims.iss !== SLACK_OIDC_ISSUER) return null;
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) return null;
  if (typeof claims.exp !== 'number' || claims.exp * 1000 <= Date.now()) return null;
  const sub = claims.sub;
  const team = claims[SLACK_TEAM_CLAIM];
  if (typeof sub !== 'string' || sub.length === 0) return null;
  if (typeof team !== 'string' || team.length === 0) return null;
  return { sub, team };
}
