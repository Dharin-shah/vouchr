import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';

// Use the transport-agnostic CORE directly (NOT the Bolt adapter). The whole point of the
// core/adapter split (enforced by test/architecture.test.ts) is that a sidecar can expose the
// broker over a local protocol so non-TS agents reuse the SAME security without re-implementing it.
import { openDb } from '../../src/core/db';
import { loadMasterKey } from '../../src/core/crypto';
import { Vault } from '../../src/core/vault';
import { Audit } from '../../src/core/audit';
import { ConnectionHandle } from '../../src/core/injector';
import { ProviderRegistry, github, google, gitlab, notion } from '../../src/core/providers';
import type { Provider } from '../../src/core/providers';
import type { Owner } from '../../src/core/owner';
import type { SlackIdentity } from '../../src/core/identity';

/**
 * ─── Trust model (the honest boundary) ───────────────────────────────────────────────────────
 * The sidecar is a LOCALHOST component. It trusts the authenticated CALLER (the app) to assert the
 * already-verified Slack identity in `owner`. The sidecar does NOT verify Slack itself — the caller
 * is responsible for having done so before it ever reaches here. Authentication here is a single
 * shared bearer token (VOUCHR_SIDECAR_TOKEN): it proves "you are the app I trust", nothing finer.
 *
 * What the sidecar still guarantees regardless of the caller:
 *  - The token is injected at the sidecar's EGRESS (inside ConnectionHandle.fetch) and is NEVER
 *    returned to the caller. Same leak-safe property as the embedded handle: the secret never
 *    leaves the vault boundary, the LLM/caller only ever sees the provider's RESPONSE.
 *  - Egress allowlist + https-only still apply — they live in ConnectionHandle, not here.
 *
 * What stays in the Slack app (NOT faked here): OAuth connect + consent. Those need a browser and a
 * verified Slack interaction; the embedded Bolt adapter owns them. The sidecar is purely the USE
 * path (proxying outbound calls with an already-stored credential) — which is what other-language
 * agents actually need to reuse. Connect once via Slack; both share the same vault DB.
 */

const PORT = process.env.VOUCHR_SIDECAR_PORT ? Number(process.env.VOUCHR_SIDECAR_PORT) : 8787;

/** Constant-time bearer compare. Hash both sides to a fixed length so the compare can't leak the length. */
function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

/** Validate an untrusted `owner` from the request body into a real Owner. Throws on bad shape. */
function parseOwner(raw: unknown): Owner {
  if (!raw || typeof raw !== 'object') throw new HttpError(400, 'owner is required');
  const o = raw as Record<string, unknown>;
  if (typeof o.teamId !== 'string' || !o.teamId) throw new HttpError(400, 'owner.teamId is required');
  if (o.kind !== 'user' && o.kind !== 'channel') throw new HttpError(400, "owner.kind must be 'user' or 'channel'");
  if (typeof o.id !== 'string' || !o.id) throw new HttpError(400, 'owner.id is required');
  return { teamId: o.teamId, kind: o.kind, id: o.id };
}

/**
 * The ACTING human (audit attribution). The caller asserts it; we default to the owner's id when the
 * owner IS a user, since for a user-owned credential the owner and the actor are the same person.
 * For a channel-owned (shared) credential there is no implicit actor — the caller MUST supply one,
 * so a shared credential never launders away WHO acted (see ConnectionHandle's owner/acting split).
 */
function parseActing(owner: Owner, rawActing: unknown): SlackIdentity {
  const a = (rawActing && typeof rawActing === 'object' ? rawActing : {}) as Record<string, unknown>;
  const userId = typeof a.userId === 'string' && a.userId ? a.userId : owner.kind === 'user' ? owner.id : null;
  if (!userId) throw new HttpError(400, 'acting.userId is required for a channel owner');
  const enterpriseId = typeof a.enterpriseId === 'string' ? a.enterpriseId : null;
  return { enterpriseId, teamId: owner.teamId, userId };
}

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/**
 * Register the built-in providers whose OAuth client env is configured. Built-ins throw at
 * construction if clientId/clientSecret are missing, so we skip the unconfigured ones rather than
 * crash at startup — the sidecar only needs the providers it'll actually serve.
 * Built-ins only; add custom defineProvider() calls here if you run your own providers.
 */
function buildRegistry(): ProviderRegistry {
  const providers: Provider[] = [];
  for (const make of [github, google, gitlab, notion]) {
    try {
      providers.push(make());
    } catch {
      // missing clientId/clientSecret for this built-in — skip it
    }
  }
  return new ProviderRegistry(providers);
}

interface Deps {
  vault: Vault;
  audit: Audit;
  registry: ProviderRegistry;
  // Shared across handles so concurrent fetches for the same owner+provider refresh a rotating token once.
  inflight: Map<string, Promise<string | null>>;
}

async function readJson(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'invalid JSON body');
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(payload);
}

/**
 * POST /proxy — the core USE path. Build a ConnectionHandle for owner+provider and call it; return
 * the provider's status/headers/body. The credential is injected inside handle.fetch and is NEVER
 * in our response. Egress allowlist + https-only are enforced inside the handle.
 */
async function handleProxy(req: IncomingMessage, res: ServerResponse, d: Deps): Promise<void> {
  const body = await readJson(req);
  const owner = parseOwner(body.owner);
  const acting = parseActing(owner, body.acting);
  if (typeof body.provider !== 'string') throw new HttpError(400, 'provider is required');
  const request = body.request;
  if (!request || typeof request !== 'object' || typeof request.url !== 'string') {
    throw new HttpError(400, 'request.url is required');
  }

  const provider = d.registry.get(body.provider); // throws -> 400 below for unknown provider
  // Resolvers default to {} — this reference serves vault-stored credentials only. Wire resolvers
  // here (same shape as the embedded handle) if you also serve external secret-manager references.
  const handle = new ConnectionHandle(provider, owner, acting, d.vault, d.audit, {}, d.inflight);

  const init: RequestInit = {};
  if (typeof request.method === 'string') init.method = request.method;
  if (request.headers && typeof request.headers === 'object') init.headers = request.headers as Record<string, string>;
  if (typeof request.body === 'string') init.body = request.body;

  const upstream = await handle.fetch(request.url, init);
  const headers: Record<string, string> = {};
  upstream.headers.forEach((v, k) => {
    headers[k] = v;
  });
  const text = await upstream.text();
  // NOTE: no token anywhere in this response — only the provider's own reply.
  send(res, 200, { status: upstream.status, headers, body: text });
}

/** POST /status — list the owner's connected providers (no secrets). */
async function handleStatus(req: IncomingMessage, res: ServerResponse, d: Deps): Promise<void> {
  const body = await readJson(req);
  const owner = parseOwner(body.owner);
  if (owner.kind !== 'user') {
    // The core Vault only exposes listForUser(). Channel-owned listing isn't a public vault method,
    // so we don't invent SQL here — surface the limitation honestly.
    throw new HttpError(400, 'status currently supports user owners only (core Vault exposes listForUser)');
  }
  const providers = await d.vault.listForUser({ enterpriseId: null, teamId: owner.teamId, userId: owner.id });
  send(res, 200, { providers });
}

/** POST /disconnect — delete the stored credential. Upstream OAuth revoke stays in the Slack app. */
async function handleDisconnect(req: IncomingMessage, res: ServerResponse, d: Deps): Promise<void> {
  const body = await readJson(req);
  const owner = parseOwner(body.owner);
  if (typeof body.provider !== 'string') throw new HttpError(400, 'provider is required');
  await d.vault.delete(owner, body.provider);
  send(res, 200, { ok: true });
}

function authorized(req: IncomingMessage, expected: string): boolean {
  const header = req.headers['authorization'];
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  return safeEqual(header.slice('Bearer '.length), expected);
}

export async function startServer(): Promise<ReturnType<typeof createServer>> {
  const token = process.env.VOUCHR_SIDECAR_TOKEN;
  if (!token) throw new Error('VOUCHR_SIDECAR_TOKEN is required (shared bearer the trusted caller presents)');

  const db = await openDb(); // same VOUCHR_DB / VOUCHR_DATABASE_URL the Slack app uses
  const deps: Deps = {
    vault: new Vault(db, loadMasterKey()),
    audit: new Audit(db),
    registry: buildRegistry(),
    inflight: new Map(),
  };

  const routes: Record<string, (req: IncomingMessage, res: ServerResponse, d: Deps) => Promise<void>> = {
    '/proxy': handleProxy,
    '/status': handleStatus,
    '/disconnect': handleDisconnect,
  };

  const server = createServer((req, res) => {
    (async () => {
      const path = (req.url ?? '').split('?')[0];
      // Unauthenticated liveness probe (no secrets, no DB work) for load balancers / k8s.
      if (req.method === 'GET' && path === '/health') return send(res, 200, { ok: true });
      if (req.method !== 'POST') throw new HttpError(405, 'POST only');
      const route = routes[path];
      if (!route) throw new HttpError(404, 'no such endpoint');
      if (!authorized(req, token)) throw new HttpError(401, 'unauthorized');
      await route(req, res, deps);
    })().catch((e) => {
      const status = e instanceof HttpError ? e.status : 500;
      // Provider/egress errors from ConnectionHandle surface as 400 (caller's request was rejected).
      const message = e instanceof Error ? e.message : 'internal error';
      send(res, status === 500 && /Egress blocked|No connection|Unknown provider/.test(message) ? 400 : status, {
        error: message,
      });
    });
  });

  // Bind to loopback only — this is a localhost component, never exposed to the network.
  await new Promise<void>((resolve) => server.listen(PORT, '127.0.0.1', resolve));
  console.log(`vouchr sidecar listening on http://127.0.0.1:${PORT}`);
  return server;
}

// One runnable check for the pure request-parsing logic (no DB/network needed): `tsx server.ts --selftest`.
function selftest(): void {
  const assert = (cond: boolean, msg: string) => {
    if (!cond) throw new Error(`selftest: ${msg}`);
  };
  const u = parseOwner({ teamId: 'T1', kind: 'user', id: 'U1' });
  assert(u.kind === 'user' && parseActing(u, undefined).userId === 'U1', 'user owner defaults acting to owner.id');
  const c = parseOwner({ teamId: 'T1', kind: 'channel', id: 'C1' });
  assert(parseActing(c, { userId: 'U9' }).userId === 'U9', 'channel owner uses supplied acting');
  let threw = false;
  try {
    parseActing(c, undefined);
  } catch {
    threw = true;
  }
  assert(threw, 'channel owner without acting must throw');
  for (const bad of [null, {}, { teamId: 'T', kind: 'x', id: 'I' }, { teamId: 'T', kind: 'user' }]) {
    let t = false;
    try {
      parseOwner(bad);
    } catch {
      t = true;
    }
    assert(t, `bad owner rejected: ${JSON.stringify(bad)}`);
  }
  assert(safeEqual('abc', 'abc') && !safeEqual('abc', 'abd'), 'constant-time compare');
  console.log('selftest ok');
}

if (require.main === module) {
  if (process.argv.includes('--selftest')) selftest();
  else startServer().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
