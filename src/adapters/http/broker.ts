import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import type { Db } from '../../core/db';
import type { Vault } from '../../core/vault';
import type { Audit } from '../../core/audit';
import type { Policy } from '../../core/policy';
import type { ChannelTools } from '../../core/tools';
import { ProviderRegistry, type Provider } from '../../core/providers';
import { ConnectionHandle, type Resolvers } from '../../core/injector';
import { userOwner, type Owner } from '../../core/owner';
import type { SlackIdentity } from '../../core/identity';
import { verifyIdentity, IdentityError, ReplayGuard, type IdentityClaims } from './identity';

/**
 * The opaque, NO-SECRET handle the caller holds. It names a provider; the owner is always the acting
 * user from the verified identity token, never this handle — so the handle can be forged without
 * granting any cross-tenant access.
 *
 * ponytail: `owner` is user-only. A CHANNEL shared credential additionally needs the Slack-Connect
 * eligibility gate (channelIneligibleReason via conversations.info) and the requireMembership /
 * isChannelMember governance the Bolt adapter enforces (bolt.ts:362-393) — both of which require a
 * Slack WebClient a headless broker cannot have (hard rule: no @slack/* here). Shipping owner:'channel'
 * without those gates is a control bypass, so it's omitted until a transport-agnostic channel-gate exists.
 */
export interface ConnectionHandleRef {
  provider: string;
  owner: 'user';
}

/** Read-only by construction: the type itself admits only GET/HEAD; the runtime re-checks (#25). */
export interface BrokerFetchRequest {
  handle: ConnectionHandleRef;
  identityToken: string; // caller-minted, HS256-signed; broker verifies (see identity.ts)
  method: 'GET' | 'HEAD';
  path: string; // appended to the provider host; the injector enforces the egress allowlist
  host?: string; // optional pick among a multi-host provider; defaults to egressAllow[0]
  query?: Record<string, string>;
  headers?: Record<string, string>; // allowlisted; Authorization is dropped (broker injects)
}

export interface BrokerOptions {
  providers: Provider[];
  vault: Vault;
  audit: Audit;
  /** Used by /healthz to confirm the store is reachable. */
  db: Db;
  /** HS256 secret shared ONLY by the upstream minter and this broker. */
  identitySecret: string;
  resolvers?: Resolvers;
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
   * #25 provider-level fail-closed switch. When true, a provider with UNSET `egressMethods` is
   * treated as GET/HEAD-only (default-deny) instead of "any method". Providers that need writes
   * opt in explicitly with `egressMethods`. Off (default) preserves the additive behavior.
   */
  defaultDenyNonGet?: boolean;
  /** #26 content-type allowlist (lower-cased, charset-stripped match). Default application/json. */
  allowedContentTypes?: string[];
  /** #26 response size cap in bytes; over-cap is rejected 413, never truncated. Default 1 MiB. */
  maxResponseBytes?: number;
  /**
   * Optional coarse network gate (a shared `Authorization: Bearer <token>` on /v1/*). This is a
   * perimeter check ONLY, NOT identity — identity comes from the signed token. Documented per #22.
   */
  brokerToken?: string;
}

const DEFAULT_ALLOWED_CT = ['application/json'];
const DEFAULT_MAX_BYTES = 1024 * 1024;
const REQUEST_BODY_CAP = 64 * 1024; // request envelopes are tiny; reject anything larger.

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

/** #26: normalize a content-type to its bare type, case-folded, charset/params dropped. */
function normalizeContentType(ct: string | null): string {
  return (ct ?? '').split(';')[0].trim().toLowerCase();
}

async function readJson(req: http.IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > REQUEST_BODY_CAP) throw new HttpError(413, { error: 'request body too large' });
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

function ownerFromClaims(c: IdentityClaims): { owner: Owner; acting: SlackIdentity } {
  const acting: SlackIdentity = { enterpriseId: null, teamId: c.teamId, userId: c.userId };
  // The owner id comes ONLY from verified claims (the acting user). The request body's handle never
  // supplies an id, so a forged body can't cross tenants.
  return { owner: userOwner(acting), acting };
}

export function createBroker(opts: BrokerOptions): http.Server {
  if (!opts.identitySecret) throw new Error('createBroker: identitySecret is required');
  const registry = new ProviderRegistry(opts.providers);
  const allowedCt = (opts.allowedContentTypes ?? DEFAULT_ALLOWED_CT).map((c) => c.toLowerCase());
  const maxBytes = opts.maxResponseBytes ?? DEFAULT_MAX_BYTES;
  const replay = new ReplayGuard();

  /** Coarse network perimeter (NOT identity). When unset, no gate. Constant-time compare (it's a secret). */
  function networkGate(req: http.IncomingMessage): void {
    if (!opts.brokerToken) return;
    const a = Buffer.from(req.headers.authorization ?? '');
    const b = Buffer.from(`Bearer ${opts.brokerToken}`);
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new HttpError(401, { error: 'unauthorized' });
  }

  function verify(token: string): IdentityClaims {
    try {
      return verifyIdentity(token, opts.identitySecret, { replay });
    } catch (e) {
      if (e instanceof IdentityError) throw new HttpError(401, { error: 'invalid identity token' });
      throw e;
    }
  }

  /**
   * Operator authorization, mirroring the Bolt credential-use path (bolt.ts:173-185): Policy then the
   * channel tool allowlist. The channel/team come ONLY from verified claims. A deny is audited (no
   * secret) and returns 403 — the credential is never injected. Runs AFTER identity is verified, so a
   * denied request still spends its single-use jti (no free retries) but the vault is never read.
   */
  async function authorize(provider: string, claims: IdentityClaims): Promise<void> {
    const channel = claims.channel;
    const acting: SlackIdentity = { enterpriseId: null, teamId: claims.teamId, userId: claims.userId };
    if (opts.policy && !opts.policy.check(provider, channel)) {
      await opts.audit.record('denied', acting, provider, { channel });
      throw new HttpError(403, { error: 'policy denies this provider in this channel' });
    }
    if (opts.channelTools && !(await opts.channelTools.isEnabled(claims.teamId, channel, provider))) {
      await opts.audit.record('denied', acting, provider, { channel, reason: 'tool-disabled' });
      throw new HttpError(403, { error: 'provider is not enabled in this channel' });
    }
  }

  async function resolveTarget(body: BrokerFetchRequest): Promise<{ handle: ConnectionHandle; provider: Provider }> {
    const ref = body.handle;
    if (!ref || ref.owner !== 'user' || typeof ref.provider !== 'string') {
      throw new HttpError(400, { error: 'invalid handle' });
    }
    if (!registry.has(ref.provider)) throw new HttpError(404, { error: 'unknown provider' });
    const claims = verify(body.identityToken);
    await authorize(ref.provider, claims);
    const provider = withEgressDefaults(registry.get(ref.provider), opts.defaultDenyNonGet);
    const { owner, acting } = ownerFromClaims(claims);
    const handle = new ConnectionHandle(provider, owner, acting, opts.vault, opts.audit, opts.resolvers ?? {});
    return { handle, provider };
  }

  async function handleFetch(body: BrokerFetchRequest): Promise<{ status: number; payload: Record<string, unknown> }> {
    // #25: fail-closed read-only. Reject non-GET/HEAD with 405 BEFORE the vault is ever touched.
    if (body.method !== 'GET' && body.method !== 'HEAD') {
      throw new HttpError(405, { error: 'only GET and HEAD are allowed' });
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
      if (['accept', 'accept-language', 'if-none-match'].includes(k.toLowerCase())) headers[k] = v;
    }

    let res: Response;
    try {
      res = await handle.fetch(url.toString(), { method: body.method, headers });
    } catch (e) {
      const msg = (e as Error).message;
      if (/Egress blocked/.test(msg)) throw new HttpError(403, { error: 'egress blocked' });
      if (/No connection/.test(msg)) throw new HttpError(409, { error: 'not connected' });
      throw new HttpError(502, { error: 'upstream fetch failed' });
    }

    const contentType = res.headers.get('content-type') ?? '';
    // HEAD has no body to guard or relay; return status + content-type only.
    if (body.method === 'HEAD') {
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
    const claims = verify(body.identityToken);
    const { owner } = ownerFromClaims(claims);
    const connected = (await opts.vault.get(owner, ref.provider)) != null;
    // NO secret: only existence + a coarse consent state. The token is never read into the response.
    return { connected, consentState: connected ? 'connected' : 'needs_consent' };
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
        if (req.method === 'GET' && url === '/healthz') {
          const r = await handleHealthz();
          return send(r.status, r.payload);
        }
        if (req.method === 'POST' && url === '/v1/fetch') {
          networkGate(req);
          const r = await handleFetch(await readJson(req));
          return send(r.status, r.payload);
        }
        if (req.method === 'POST' && url === '/v1/resolve') {
          networkGate(req);
          return send(200, await handleResolve(await readJson(req)));
        }
        send(404, { error: 'not found' });
      } catch (e) {
        if (e instanceof HttpError) return send(e.status, e.payload);
        send(500, { error: 'internal error' }); // never echo internals (could carry detail)
      }
    })();
  });
}
