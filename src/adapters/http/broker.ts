import http from 'node:http';
import type { Db } from '../../core/db';
import type { Vault } from '../../core/vault';
import type { Audit } from '../../core/audit';
import { ProviderRegistry, type Provider } from '../../core/providers';
import { ConnectionHandle, type Resolvers } from '../../core/injector';
import { userOwner, channelOwner, type Owner } from '../../core/owner';
import type { SlackIdentity } from '../../core/identity';
import { verifyIdentity, IdentityError, ReplayGuard, type IdentityClaims } from './identity';

/**
 * The opaque, NO-SECRET handle the caller holds. It names a provider and whether the user's OWN
 * credential or the CHANNEL's shared one is wanted. The owner *id* (team/user/channel) is taken
 * from the verified identity token, never from this handle — so the handle can be forged without
 * granting any cross-tenant access.
 */
export interface ConnectionHandleRef {
  provider: string;
  owner: 'user' | 'channel';
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

function ownerFromClaims(c: IdentityClaims, kind: 'user' | 'channel'): { owner: Owner; acting: SlackIdentity } {
  const acting: SlackIdentity = { enterpriseId: null, teamId: c.teamId, userId: c.userId };
  // The owner id comes ONLY from verified claims: user -> the acting user, channel -> the claim's
  // channel. The request body's handle never supplies an id, so a forged body can't cross tenants.
  const owner = kind === 'channel' ? channelOwner(c.teamId, c.channel) : userOwner(acting);
  return { owner, acting };
}

export function createBroker(opts: BrokerOptions): http.Server {
  if (!opts.identitySecret) throw new Error('createBroker: identitySecret is required');
  const registry = new ProviderRegistry(opts.providers);
  const allowedCt = (opts.allowedContentTypes ?? DEFAULT_ALLOWED_CT).map((c) => c.toLowerCase());
  const maxBytes = opts.maxResponseBytes ?? DEFAULT_MAX_BYTES;
  const replay = new ReplayGuard();

  /** Coarse network perimeter (NOT identity). When unset, no gate. */
  function networkGate(req: http.IncomingMessage): void {
    if (!opts.brokerToken) return;
    const auth = req.headers.authorization ?? '';
    if (auth !== `Bearer ${opts.brokerToken}`) throw new HttpError(401, { error: 'unauthorized' });
  }

  function verify(token: string): IdentityClaims {
    try {
      return verifyIdentity(token, opts.identitySecret, { replay });
    } catch (e) {
      if (e instanceof IdentityError) throw new HttpError(401, { error: 'invalid identity token' });
      throw e;
    }
  }

  function resolveTarget(body: BrokerFetchRequest): { handle: ConnectionHandle; provider: Provider } {
    const ref = body.handle;
    if (!ref || (ref.owner !== 'user' && ref.owner !== 'channel') || typeof ref.provider !== 'string') {
      throw new HttpError(400, { error: 'invalid handle' });
    }
    if (!registry.has(ref.provider)) throw new HttpError(404, { error: 'unknown provider' });
    const claims = verify(body.identityToken);
    const provider = withEgressDefaults(registry.get(ref.provider), opts.defaultDenyNonGet);
    const { owner, acting } = ownerFromClaims(claims, ref.owner);
    const handle = new ConnectionHandle(provider, owner, acting, opts.vault, opts.audit, opts.resolvers ?? {});
    return { handle, provider };
  }

  async function handleFetch(body: BrokerFetchRequest): Promise<{ status: number; payload: Record<string, unknown> }> {
    // #25: fail-closed read-only. Reject non-GET/HEAD with 405 BEFORE the vault is ever touched.
    if (body.method !== 'GET' && body.method !== 'HEAD') {
      throw new HttpError(405, { error: 'only GET and HEAD are allowed' });
    }
    const { handle, provider } = resolveTarget(body);

    const host = body.host ?? provider.egressAllow[0];
    const url = new URL(`https://${host}${body.path ?? '/'}`);
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
    if (!ref || (ref.owner !== 'user' && ref.owner !== 'channel') || typeof ref.provider !== 'string') {
      throw new HttpError(400, { error: 'invalid handle' });
    }
    if (!registry.has(ref.provider)) throw new HttpError(404, { error: 'unknown provider' });
    const claims = verify(body.identityToken);
    const { owner } = ownerFromClaims(claims, ref.owner);
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
