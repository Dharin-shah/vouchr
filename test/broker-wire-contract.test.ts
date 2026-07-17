import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Policy } from '../src/core/policy';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { defineProvider } from '../src/core/providers';
import { createBroker } from '../src/adapters/http/broker';
import { identityConfig, signIdentity, type IdentityClaims } from './support/identity';
import { userOwner } from '../src/core/owner';

// ─────────────────────────────────────────────────────────────────────────────
// Broker WIRE-CONTRACT snapshot tests (#129).
//
// HTTP integrators (the pilot) code against the broker's JSON shapes and status codes — not the
// TypeScript types, which only protect npm consumers. This suite drives one canonical request per
// endpoint/outcome through a real in-process broker and freezes the response's STATUS CODE + the
// SHAPE of the JSON body (exact key set + the type of each value) into a checked-in golden file.
// Values (state strings, bodies, ids) vary run-to-run and are intentionally NOT frozen — only the
// contract is. Renaming/removing a field, adding a new field, changing a type, or changing a status
// code fails CI. The golden dir (test/golden/wire) IS the wire contract; see its README.
//
// Regenerate after an INTENTIONAL change: `UPDATE_GOLDENS=1 npm test` — and treat it as semver-major
// for HTTP integrators (update the CHANGELOG breaking-changes section).
// ─────────────────────────────────────────────────────────────────────────────

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';
const GOLDEN_DIR = path.join(__dirname, 'golden', 'wire');

const acme = defineProvider({
  id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false,
  clientId: 'id', clientSecret: 'sec',
});
const svc = defineProvider({
  id: 'svc', identity: 'service', credential: 'key',
  authorizeUrl: 'https://svc.example/auth', tokenUrl: 'https://svc.example/token',
  scopesDefault: ['x'], egressAllow: ['api.svc.example'], refresh: 'none', pkce: false,
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}
const userToken = (over: Partial<IdentityClaims> = {}) => signIdentity(claims(over), SECRET);
const adminToken = (over: Partial<IdentityClaims> = {}) =>
  signIdentity(claims({ isAdmin: true, channelEligible: true, ...over }), SECRET);

async function makeBroker(t: TestContext, opts: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  // Seed U1's acme credential so /v1/fetch, /v1/resolve, /v1/status have something to report.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({
    providers: [acme, svc], vault, audit, db, identitySecret: identityConfig(SECRET),
    channelConfig: new ChannelConfig(db), channelTools: new ChannelTools(db),
    baseUrl: 'https://broker.example', callbackPath: '/oauth/callback',
    resolvers: { 'aws-sm': async () => SECRET_TOKEN },
    ...opts,
  });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, vault, db, port: (server.address() as any).port };
}

function request(
  port: number, method: string, urlPath: string, body?: unknown, headers: Record<string, string> = {},
): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path: urlPath, method,
        headers: { ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}), ...headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json: any = null;
          try { json = JSON.parse(raw); } catch { /* non-JSON body → null */ }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

/** Reduce a JSON value to its structural shape: key set + the TYPE of each leaf, values dropped.
 *  An array freezes the shape of its elements, not its length — so a provider list captures its row
 *  shape stably across runs. A homogeneous array collapses to `[shape]`; a heterogeneous one keeps
 *  every DISTINCT element shape, so drift in element[1..n] (not just [0]) still trips the guard. */
function shape(value: unknown): unknown {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    if (!value.length) return 'array:empty';
    const distinct: unknown[] = [];
    for (const el of value.map(shape)) {
      if (!distinct.some((d) => JSON.stringify(d) === JSON.stringify(el))) distinct.push(el);
    }
    return distinct.length === 1 ? [distinct[0]] : distinct;
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as object).sort()) out[k] = shape((value as any)[k]);
    return out;
  }
  return typeof value; // 'string' | 'number' | 'boolean'
}

function checkGolden(name: string, status: number, json: unknown): void {
  const file = path.join(GOLDEN_DIR, `${name}.json`);
  const serialized = `${JSON.stringify({ status, shape: shape(json) }, null, 2)}\n`;
  if (process.env.UPDATE_GOLDENS) {
    fs.mkdirSync(GOLDEN_DIR, { recursive: true });
    fs.writeFileSync(file, serialized);
    return;
  }
  assert.ok(
    fs.existsSync(file),
    `missing wire-contract golden ${name}.json — create it with: UPDATE_GOLDENS=1 npm test`,
  );
  assert.equal(
    serialized, fs.readFileSync(file, 'utf8'),
    `wire contract changed for "${name}" — if intentional, this is SEMVER-MAJOR for HTTP integrators: ` +
    `regenerate with UPDATE_GOLDENS=1 npm test AND record it in the CHANGELOG breaking-changes section.`,
  );
}

/** One canonical request per endpoint/outcome. Each drives a real broker, then freezes {status, shape}. */
const CASES: { name: string; run: (t: TestContext) => Promise<{ status: number; json: unknown }> }[] = [
  // ── success shapes ──
  { name: 'fetch.success', run: async (t) => {
      const { server, port } = await makeBroker(t);
      const real = globalThis.fetch;
      globalThis.fetch = (async () => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
      try { return await request(port, 'POST', '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: userToken(), method: 'GET', path: '/data' }); }
      finally { globalThis.fetch = real; server.close(); }
  } },
  { name: 'status', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/status', { identityToken: userToken() }); } finally { server.close(); }
  } },
  { name: 'resolve.connected', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/resolve', { handle: { provider: 'acme', owner: 'user' }, identityToken: userToken() }); } finally { server.close(); }
  } },
  { name: 'connect', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/connect', { handle: { provider: 'acme' }, identityToken: userToken() }); } finally { server.close(); }
  } },
  { name: 'manifest', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'GET', '/v1/manifest'); } finally { server.close(); }
  } },
  { name: 'admin.mode.ok', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: adminToken() }); } finally { server.close(); }
  } },
  { name: 'admin.tools.ok', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/admin/tools', { provider: 'acme', enabled: true, identityToken: adminToken() }); } finally { server.close(); }
  } },
  { name: 'admin.config', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try {
        await request(port, 'POST', '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: adminToken() }); // configure so mode reads back non-null
        return await request(port, 'GET', '/v1/admin/config', undefined, { 'x-vouchr-identity': adminToken() });
      } finally { server.close(); }
  } },
  { name: 'admin.config.unconfigured', run: async (t) => {
      // The read side before any mode is set: `mode` is null (ChannelMode | null). Freezes that the
      // null branch is part of the contract, alongside admin.config's configured (mode:string) shape.
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'GET', '/v1/admin/config', undefined, { 'x-vouchr-identity': adminToken() }); } finally { server.close(); }
  } },
  { name: 'audit.self', run: async (t) => {
      const { server, db, port } = await makeBroker(t);
      try {
        await new Audit(db).record('inject', { enterpriseId: null, teamId: 'T1', userId: 'U1' }, 'acme', { host: 'api.acme.example' });
        return await request(port, 'POST', '/v1/audit', { identityToken: userToken() });
      } finally { server.close(); }
  } },
  { name: 'admin.audit', run: async (t) => {
      const { server, db, port } = await makeBroker(t);
      try {
        await new Audit(db).record('inject', { enterpriseId: null, teamId: 'T1', userId: 'U1' }, 'acme', { channel: 'C1' });
        return await request(port, 'POST', '/v1/admin/audit', { identityToken: adminToken() });
      } finally { server.close(); }
  } },
  { name: 'admin.reference.ok', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/admin/reference', { handle: { provider: 'acme' }, identityToken: adminToken(), secretRef: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/channel' }); } finally { server.close(); }
  } },
  { name: 'user.reference.ok', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/user/reference', { handle: { provider: 'acme' }, identityToken: userToken(), secretRef: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/user' }); } finally { server.close(); }
  } },
  { name: 'health.ok', run: async (t) => {
      // /healthz and /health share one handler — liveness only: a bare {ok:true}, no DB touch.
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'GET', '/healthz'); } finally { server.close(); }
  } },
  { name: 'readyz.ok', run: async (t) => {
      // Readiness: DB round-trip OK → 200 {ok:true}. k8s readinessProbe pulls the pod when this 503s.
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'GET', '/readyz'); } finally { server.close(); }
  } },
  { name: 'readyz.down.503', run: async (t) => {
      // DB unreachable → 503 {ok:false}. The 503 status is the contract k8s readiness relies on.
      const { server, db, port } = await makeBroker(t);
      try { await db.close(); return await request(port, 'GET', '/readyz'); } finally { server.close(); }
  } },
  { name: 'disconnect', run: async (t) => {
      // U1 has the seeded acme credential, so `revoked` is non-empty → its element type is frozen.
      const { server, vault, port } = await makeBroker(t);
      const credentialId = await vault.liveId(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme');
      try { return await request(port, 'POST', '/v1/disconnect', { handle: { provider: 'acme', credentialId }, identityToken: userToken() }); } finally { server.close(); }
  } },
  { name: 'admin.offboard.ok', run: async (t) => {
      // Admin offboards U1 (who has acme) → revoked:[string].
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/admin/offboard', { identityToken: adminToken({ userId: 'ADMIN' }), targetUserId: 'U1' }); } finally { server.close(); }
  } },

  // ── error shapes (every 4xx/5xx body is `{ error: string }`; the STATUS is the contract) ──
  { name: 'error.fetch.badToken.401', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: 'not-a-real-token', method: 'GET', path: '/data' }); } finally { server.close(); }
  } },
  { name: 'error.fetch.methodNotAllowed.405', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: userToken(), method: 'POST', path: '/data', body: '{}' }); } finally { server.close(); }
  } },
  { name: 'error.fetch.egressDenied.403', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'POST', '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: userToken(), method: 'GET', path: '/data', host: 'evil.example.com' }); } finally { server.close(); }
  } },
  { name: 'error.fetch.policyDenied.403', run: async (t) => {
      const { server, port } = await makeBroker(t, { policy: new Policy({ acme: { defaultAllow: true, denyChannels: ['C1'] } }) });
      try { return await request(port, 'POST', '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: userToken(), method: 'GET', path: '/data' }); } finally { server.close(); }
  } },
  { name: 'error.fetch.notConnected.409', run: async (t) => {
      const { server, port } = await makeBroker(t);
      // U2 has no seeded acme credential → resolves owner, injector 409s (not connected).
      try { return await request(port, 'POST', '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: userToken({ userId: 'U2' }), method: 'GET', path: '/data' }); } finally { server.close(); }
  } },
  { name: 'error.fetch.timeout.504', run: async (t) => {
      const { server, port } = await makeBroker(t, { fetchDeadlineMs: 20 });
      const real = globalThis.fetch;
      globalThis.fetch = ((_url: unknown, init: RequestInit) => new Promise((_resolve, reject) => {
        const signal = init.signal;
        const abort = () => reject(signal?.reason ?? new DOMException('aborted', 'AbortError'));
        if (signal?.aborted) abort();
        else signal?.addEventListener('abort', abort, { once: true });
      })) as any;
      try {
        return await request(port, 'POST', '/v1/fetch', {
          handle: { provider: 'acme', owner: 'user' }, identityToken: userToken(), method: 'GET', path: '/data',
        });
      } finally {
        globalThis.fetch = real;
        server.close();
      }
  } },
  { name: 'error.overloaded.503', run: async (t) => {
      let entered!: () => void;
      let release!: () => void;
      const enteredAuthorize = new Promise<void>((resolve) => { entered = resolve; });
      const authorizeGate = new Promise<void>((resolve) => { release = resolve; });
      const { server, port } = await makeBroker(t, {
        maxInflight: 1,
        authorize: async () => { entered(); await authorizeGate; },
      });
      const first = request(port, 'GET', '/v1/manifest');
      await enteredAuthorize;
      try {
        return await request(port, 'GET', '/v1/manifest');
      } finally {
        release();
        await first;
        server.close();
      }
  } },
  { name: 'error.admin.mode.forbidden.403', run: async (t) => {
      const { server, port } = await makeBroker(t);
      // Non-admin token; a forged body `isAdmin` must be ignored (authority = signed claim only).
      try { return await request(port, 'POST', '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: userToken(), isAdmin: true } as any); } finally { server.close(); }
  } },
  { name: 'error.admin.offboard.forbidden.403', run: async (t) => {
      const { server, port } = await makeBroker(t);
      // Non-admin token; forged body isAdmin ignored (authority = signed claim only).
      try { return await request(port, 'POST', '/v1/admin/offboard', { identityToken: userToken(), targetUserId: 'U2', isAdmin: true } as any); } finally { server.close(); }
  } },
  { name: 'error.notFound.404', run: async (t) => {
      const { server, port } = await makeBroker(t);
      try { return await request(port, 'GET', '/v1/does-not-exist'); } finally { server.close(); }
  } },
];

for (const c of CASES) {
  test(`wire-contract: ${c.name}`, async (t) => {
    const { status, json } = await c.run(t);
    checkGolden(c.name, status, json);
  });
}
