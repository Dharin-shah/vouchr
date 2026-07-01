import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Verified claims about WHO is acting, minted by a trusted upstream (the receiver that already
 * verified the Slack event signature) and verified by the broker. The broker resolves the vault
 * owner key ONLY from these verified claims — never from the request body — so a prompt-injected
 * caller cannot assert another human's identity and borrow their token (cross-tenant probe).
 */
export interface IdentityClaims {
  teamId: string;
  userId: string; // the acting human, from the verified Slack event upstream
  channel: string;
  threadTs?: string;
  /** Absolute expiry, epoch milliseconds (Date.now()), to match the rest of the codebase. */
  exp: number;
  /** Single-use id (replay guard within the exp window). */
  jti: string;
}

/** Hard ceiling on a token's lifetime: a verified token is rejected if exp is further out than this. */
export const MAX_LIFETIME_MS = 5 * 60 * 1000;

/** Raised on any verification failure. Carries no token/secret material; the broker maps it to 401. */
export class IdentityError extends Error {
  constructor(reason: string) {
    super(`identity rejected: ${reason}`);
    this.name = 'IdentityError';
  }
}

const b64url = (s: string | Buffer): string => Buffer.from(s).toString('base64url');

/**
 * HS256 over the payload. Format is `base64url(json).base64url(hmac)` — deliberately NOT a full JWT:
 * there is no `alg` header to read from the token, so an algorithm-substitution attack has no surface.
 * Minter-side helper; the minter is responsible for setting `exp <= now + 5min` and a unique `jti`.
 */
export function signIdentity(claims: IdentityClaims, secret: string): string {
  const payload = b64url(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

/**
 * Single-use jti store. `use()` returns true if the jti is fresh (and records it until `exp`),
 * false if it was already used. May be async so a multi-instance broker can back it with a shared
 * store (e.g. Redis `SET jti 1 NX PX=<ttl-to-exp>`). Supply one via `BrokerOptions.replayStore`.
 */
export interface ReplayStore {
  use(jti: string, exp: number): boolean | Promise<boolean>;
}

/**
 * Default single-use jti replay guard: an in-memory per-process set.
 * ponytail: single process only. In a multi-instance broker fleet a jti can be replayed once PER
 * POD within its (<=5min) window, so single-use is NOT cluster-wide with this default — a horizontally
 * scaled broker MUST pass a shared `replayStore` (Redis SET NX PX). Upgrade path: any `ReplayStore`.
 */
export class ReplayGuard implements ReplayStore {
  private seen = new Map<string, number>(); // jti -> exp (epoch ms)

  /** Returns true if this jti is fresh (and records it); false if it was already used. */
  use(jti: string, exp: number, now = Date.now()): boolean {
    // Prune expired entries so the set stays bounded by the live (<=5min) token window.
    for (const [j, e] of this.seen) if (e <= now) this.seen.delete(j);
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, exp);
    return true;
  }
}

function isClaims(v: unknown): v is IdentityClaims {
  if (!v || typeof v !== 'object') return false;
  const c = v as Record<string, unknown>;
  return (
    typeof c.teamId === 'string' &&
    typeof c.userId === 'string' &&
    typeof c.channel === 'string' &&
    typeof c.exp === 'number' &&
    typeof c.jti === 'string' &&
    (c.threadTs === undefined || typeof c.threadTs === 'string')
  );
}

/**
 * Verify a minted identity token. Throws IdentityError on a bad/missing signature, a malformed or
 * incomplete payload, an expired token, an over-long lifetime (> 5min), or a replayed jti. On
 * success returns the verified claims; the broker builds the owner key from these and nothing else.
 */
export function verifyIdentity(
  token: string,
  secret: string,
  opts: { replay?: ReplayGuard; now?: number } = {},
): IdentityClaims {
  const now = opts.now ?? Date.now();
  if (typeof token !== 'string' || !token) throw new IdentityError('missing token');
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) throw new IdentityError('malformed');
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);

  const expected = createHmac('sha256', secret).update(payload).digest('base64url');
  // Constant-time compare; differing lengths can't be timingSafeEqual'd, so reject first.
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new IdentityError('bad signature');

  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    throw new IdentityError('malformed payload');
  }
  if (!isClaims(claims)) throw new IdentityError('incomplete claims');

  if (claims.exp <= now) throw new IdentityError('expired');
  if (claims.exp - now > MAX_LIFETIME_MS) throw new IdentityError('lifetime exceeds 5min');
  if (opts.replay && !opts.replay.use(claims.jti, claims.exp, now)) throw new IdentityError('replayed jti');

  return claims;
}
