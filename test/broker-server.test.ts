import { test, type TestContext } from 'node:test';
import { testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { loadProviders } from '../bin/providerConfig';
import { buildBrokerServer } from '../bin/broker-server';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';
import { signIdentity } from '../src/adapters/http/identity';

const KEY_B64 = Buffer.alloc(32, 7).toString('base64');
const CONFLUENCE = {
  id: 'confluence', authorizeUrl: 'https://auth.atlassian.com/authorize',
  tokenUrl: 'https://auth.atlassian.com/oauth/token', scopesDefault: ['read:confluence'],
  egressAllow: ['api.atlassian.com'], refresh: 'rotating', pkce: true,
};

function get(port: number, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    http.get({ port, path }, (res) => { res.resume(); resolve(res.statusCode!); }).on('error', reject);
  });
}

// ── T7: env-driven provider config ───────────────────────────────────────────

test('loadProviders: parses an OAuth provider, resolving client creds from per-provider env', () => {
  const env = {
    VOUCHR_PROVIDERS: JSON.stringify([CONFLUENCE]),
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid',
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
  } as any;
  const [p] = loadProviders(env);
  assert.equal(p.id, 'confluence');
  assert.equal(p.clientId, 'cid');
  assert.equal(p.egressMethods, undefined); // unset -> broker default-denies non-GET/HEAD
});

test('loadProviders: rejects an unknown/non-declarative field (fail closed)', () => {
  const env = { VOUCHR_PROVIDERS: JSON.stringify([{ ...CONFLUENCE, inject: 'x' }]) } as any;
  assert.throws(() => loadProviders(env), /unknown field "inject"/);
});

test('loadProviders: rejects invalid declarative enum values', () => {
  const env = {
    VOUCHR_PROVIDERS: JSON.stringify([{ ...CONFLUENCE, refresh: 'eventually', pkce: 'yes' }]),
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid',
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
  } as any;
  assert.throws(() => loadProviders(env), /field "refresh" must be one of/);
});

test('loadProviders: a missing OAuth client secret fails clearly', () => {
  const env = { VOUCHR_PROVIDERS: JSON.stringify([CONFLUENCE]), VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid' } as any;
  assert.throws(() => loadProviders(env), /missing clientId\/clientSecret/);
});

test('loadProviders: ids that derive the same client-secret env key are rejected', () => {
  const env = { VOUCHR_PROVIDERS: JSON.stringify([
    { id: 'a.b', credential: 'key', egressAllow: ['h'] },
    { id: 'a-b', credential: 'key', egressAllow: ['h'] }, // both → VOUCHR_PROVIDER_A_B_*
  ]) } as any;
  assert.throws(() => loadProviders(env), /same client-secret env key/);
});

test('loadProviders: a provider without egressAllow is rejected', () => {
  const env = { VOUCHR_PROVIDERS: JSON.stringify([{ id: 'x', credential: 'key' }]) } as any;
  assert.throws(() => loadProviders(env), /egressAllow/);
});

// #65 the /v1/mcp opt-in must be env-declarable, or the SHIPPED standalone broker can never serve
// an MCP provider (the knob would only exist for custom createBroker wrappers).
const MCP_INTERNAL = {
  id: 'internal', credential: 'key', egressAllow: ['mcp.internal.example'],
  egressMethods: ['POST'], mcp: { paths: ['/mcp'] },
};

test('#65 loadProviders: the mcp knob loads and reaches the provider', () => {
  const [p] = loadProviders({ VOUCHR_PROVIDERS: JSON.stringify([MCP_INTERNAL]) } as any);
  assert.deepEqual(p.mcp, { paths: ['/mcp'] });
  // allowContentTypes passes through untouched too
  const [q] = loadProviders({ VOUCHR_PROVIDERS: JSON.stringify([{ ...MCP_INTERNAL, mcp: { paths: ['/mcp'], allowContentTypes: ['application/json'] } }]) } as any);
  assert.deepEqual(q.mcp, { paths: ['/mcp'], allowContentTypes: ['application/json'] });
});

test('#65 loadProviders: invalid mcp shapes are rejected at config load with the loader\'s message', () => {
  const load = (mcp: unknown) => () =>
    loadProviders({ VOUCHR_PROVIDERS: JSON.stringify([{ ...MCP_INTERNAL, mcp }]) } as any);
  assert.throws(load('yes'), /field "mcp" must be an object/);
  assert.throws(load({ paths: [] }), /"mcp\.paths" must be a non-empty array/);
  assert.throws(load({ paths: [42] }), /"mcp\.paths" must be a non-empty array/);
  assert.throws(load({ paths: [' '] }), /"mcp\.paths" must be a non-empty array/);
  assert.throws(load({ paths: ['/mcp'], allowContentTypes: [] }), /"mcp\.allowContentTypes" must be a non-empty array/);
  assert.throws(load({ paths: ['/mcp'], allowContentType: ['x'] }), /unknown key "allowContentType"/); // typo fails closed
});

// #113 the approval knob must be env-declarable too, or the SHIPPED standalone broker could never
// enforce human-in-the-loop approval for a declaratively configured provider.
const APPROVAL_INTERNAL = {
  id: 'internal', credential: 'key', egressAllow: ['api.internal.example'],
  egressMethods: ['GET', 'POST'], approval: { approver: 'admin' },
};

test('#113 loadProviders: the approval knob loads and reaches the provider', () => {
  const [p] = loadProviders({ VOUCHR_PROVIDERS: JSON.stringify([APPROVAL_INTERNAL]) } as any);
  assert.deepEqual(p.approval, { approver: 'admin' });
  // every optional field passes through untouched too
  const full = { methods: ['POST'], paths: ['/repos'], approver: 'self', ttlMs: 60_000 };
  const [q] = loadProviders({ VOUCHR_PROVIDERS: JSON.stringify([{ ...APPROVAL_INTERNAL, approval: full }]) } as any);
  assert.deepEqual(q.approval, full);
});

test("#113 loadProviders: invalid approval shapes are rejected at config load with the loader's message", () => {
  const load = (approval: unknown) => () =>
    loadProviders({ VOUCHR_PROVIDERS: JSON.stringify([{ ...APPROVAL_INTERNAL, approval }]) } as any);
  assert.throws(load('yes'), /field "approval" must be an object/);
  assert.throws(load({}), /"approval\.approver" must be "self" or "admin"/);
  assert.throws(load({ approver: 'anyone' }), /"approval\.approver" must be "self" or "admin"/);
  assert.throws(load({ approver: 'self', methods: [] }), /"approval\.methods" must be a non-empty array/);
  assert.throws(load({ approver: 'self', methods: [42] }), /"approval\.methods" must be a non-empty array/);
  assert.throws(load({ approver: 'self', ttlMs: 0 }), /"approval\.ttlMs" must be a finite number > 0/);
  assert.throws(load({ approver: 'self', ttlMs: '5m' }), /"approval\.ttlMs" must be a finite number > 0/);
  assert.throws(load({ approver: 'self', ttl: 5 }), /unknown key "ttl"/); // typo fails closed
  // P2-D fail-OPEN forms: non-empty but non-canonical → they'd never match at runtime, so reject.
  assert.throws(load({ approver: 'self', paths: [' '] }), /"approval\.paths" entries must be absolute paths/);
  assert.throws(load({ approver: 'self', paths: ['repos'] }), /"approval\.paths" entries must be absolute paths/); // no leading slash
  assert.throws(load({ approver: 'self', paths: [' /repos'] }), /"approval\.paths" entries must be absolute paths/); // leading space
  assert.throws(load({ approver: 'self', methods: ['PO ST'] }), /"approval\.methods" entries must be bare HTTP method names/);
});

test('#113 loadProviders: canonicalizable approval methods are normalized (trim + upper-case)', () => {
  // 'post ' would never match the upper-cased request method — the loader accepts it and
  // defineProvider normalizes it to 'POST' so it actually enforces (fail-closed, not fail-open).
  const [p] = loadProviders({ VOUCHR_PROVIDERS: JSON.stringify([{ ...APPROVAL_INTERNAL, approval: { approver: 'self', methods: ['post '] } }]) } as any);
  assert.deepEqual(p.approval!.methods, ['POST']);
});

// ── T6: broker-server entrypoint ─────────────────────────────────────────────

async function baseEnv(t: TestContext, extra: Record<string, string> = {}): Promise<any> {
  return {
    VOUCHR_IDENTITY_SECRET: 'shhh',
    VOUCHR_MASTER_KEY: KEY_B64,
    VOUCHR_DATABASE_URL: await testDbUrl(t), // PostgreSQL-only; a fresh isolated schema per broker
    VOUCHR_PROVIDERS: JSON.stringify([{ id: 'internal', credential: 'key', egressAllow: ['api.internal.example'] }]),
    ...extra,
  };
}

test('buildBrokerServer: boots on PostgreSQL and serves /healthz + /health + /readyz', async (t) => {
  const built = await buildBrokerServer(await baseEnv(t, { VOUCHR_PORT: '0' }));
  await new Promise<void>((r) => built.server.listen(0, r));
  const port = (built.server.address() as any).port;
  try {
    assert.equal(built.backend, 'postgres');
    assert.deepEqual(built.providerIds, ['internal']);
    assert.equal(await get(port, '/healthz'), 200);
    assert.equal(await get(port, '/health'), 200);
    assert.equal(await get(port, '/readyz'), 200); // readiness passes over the live Postgres db
  } finally {
    built.server.close();
    await built.db.close();
  }
});

test('#65 buildBrokerServer: an env-declared mcp provider serves POST /v1/mcp end to end', async (t) => {
  // The whole distribution path in one test: documented JSON config -> loadProviders ->
  // buildBrokerServer -> /v1/mcp, with the env-declared provider's credential injected upstream.
  const built = await buildBrokerServer(await baseEnv(t, {
    VOUCHR_ALLOW_WRITES: '1',
    VOUCHR_PROVIDERS: JSON.stringify([MCP_INTERNAL]),
  }));
  await new Promise<void>((r) => built.server.listen(0, r));
  const port = (built.server.address() as any).port;
  const real = globalThis.fetch;
  let upstreamAuth: string | null = null;
  globalThis.fetch = (async (_u: any, init: any) => {
    upstreamAuth = new Headers(init?.headers).get('authorization');
    return new Response('{"jsonrpc":"2.0","id":1,"result":{}}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    await new Vault(built.db, Buffer.from(KEY_B64, 'base64')).upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'internal', {
      accessToken: 'tok_mcp_secret', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
    const identityToken = signIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() }, 'shhh');
    const body = JSON.stringify({
      handle: { provider: 'internal', owner: 'user' }, identityToken, path: '/mcp',
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
    });
    const r = await new Promise<{ status: number; raw: string }>((resolve, reject) => {
      const req = http.request(
        { port, path: '/v1/mcp', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => resolve({ status: res.statusCode ?? 0, raw: Buffer.concat(chunks).toString('utf8') }));
        },
      );
      req.on('error', reject);
      req.end(body);
    });
    assert.equal(r.status, 200, `env-declared mcp config must reach /v1/mcp (got ${r.status}: ${r.raw})`);
    assert.equal(r.raw, '{"jsonrpc":"2.0","id":1,"result":{}}');
    assert.equal(upstreamAuth, 'Bearer tok_mcp_secret', 'the env-declared provider\'s credential was injected');
    assert.ok(!r.raw.includes('tok_mcp_secret'), 'and never revealed to the caller');
  } finally {
    globalThis.fetch = real;
    built.server.close();
    await built.db.close();
  }
});

test('#54 buildBrokerServer.sweep removes an expired connection (headless TTL sweep)', async (t) => {
  const built = await buildBrokerServer(await baseEnv(t));
  try {
    const vault = new Vault(built.db, Buffer.from(KEY_B64, 'base64'));
    await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'internal', {
      accessToken: 'x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
    // Backdate so the default idle-TTL (7d) reclaims the row (created_at=now would not be expired yet).
    await built.db.run(`UPDATE connection SET last_used_at=0, created_at=0 WHERE owner_id='U1' AND provider='internal'`);
    const n = await built.sweep();
    assert.equal(n, 1);
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'internal'), null);
  } finally {
    await built.db.close();
  }
});

test('#54 sweep interval: default is hourly; VOUCHR_SWEEP_INTERVAL_MS=0 disables it', async (t) => {
  const dflt = await buildBrokerServer(await baseEnv(t));
  assert.equal(dflt.sweepIntervalMs, 60 * 60 * 1000);
  await dflt.db.close();
  const off = await buildBrokerServer(await baseEnv(t, { VOUCHR_SWEEP_INTERVAL_MS: '0' }));
  assert.equal(off.sweepIntervalMs, 0);
  await off.db.close();
  await assert.rejects(buildBrokerServer(await baseEnv(t, { VOUCHR_SWEEP_INTERVAL_MS: 'nope' })), /VOUCHR_SWEEP_INTERVAL_MS/);
});

test('#116 VOUCHR_DRY_RUN: parses like VOUCHR_ALLOW_WRITES and hard-fails boot on a real vault', async (t) => {
  // Parse + wire-through: 1/true → on, absent/anything else → off (production behavior).
  const on = await buildBrokerServer(await baseEnv(t, { VOUCHR_DRY_RUN: '1' }));
  try {
    assert.equal(on.dryRun, true);
    // The bin's SWEEP shares the marked audit instance, so its revoke rows carry meta.dry_run too
    // (createBroker only wraps its own copy — the bin must wrap the one the sweep closure holds).
    const vault = new Vault(on.db, Buffer.from(KEY_B64, 'base64'));
    await vault.upsertDryRun(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'internal', {
      accessToken: 'x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'dry-run',
    });
    await on.db.run(`UPDATE connection SET last_used_at=0, created_at=0 WHERE owner_id='U1'`);
    assert.equal(await on.sweep(), 1);
    const swept = (await on.db.all(`SELECT meta FROM audit WHERE action='revoke'`)) as any[];
    assert.equal(swept.length, 1);
    assert.equal(JSON.parse(swept[0].meta).dry_run, true);
  } finally {
    await on.db.close();
  }
  const off = await buildBrokerServer(await baseEnv(t));
  assert.equal(off.dryRun, false);
  await off.db.close();

  // Boot-time refusal: a vault holding a non-dry-run row must stop the server before it listens.
  const _dir = mkdtempSync(join(tmpdir(), 'vouchr-dryrun-'));
  const dbPath = await testDbUrl(t);
  const db = await openDb({ databaseUrl: dbPath });
  await new Vault(db, Buffer.from(KEY_B64, 'base64')).upsert(
    userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }),
    'internal',
    { accessToken: 't', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null },
  );
  await db.close();
  await assert.rejects(
    buildBrokerServer(await baseEnv(t, { VOUCHR_DRY_RUN: 'true', VOUCHR_DATABASE_URL: dbPath })),
    /refusing dryRun against a vault with real credentials/,
  );
});

test('buildBrokerServer: fails fast naming the missing secret', async (t) => {
  const { VOUCHR_IDENTITY_SECRET, ...noSecret } = await baseEnv(t);
  await assert.rejects(buildBrokerServer(noSecret), /VOUCHR_IDENTITY_SECRET/);
  await assert.rejects(buildBrokerServer({ ...await baseEnv(t), VOUCHR_MASTER_KEY: undefined }), /VOUCHR_MASTER_KEY/);
  await assert.rejects(buildBrokerServer({ ...await baseEnv(t), VOUCHR_MASTER_KEY: 'dG9vc2hvcnQ=' }), /32 bytes/);
});

// ── T8: seed CLI ─────────────────────────────────────────────────────────────

test('broker-seed: reference mode writes a credential the broker can resolve', async (t) => {
  const _dir = mkdtempSync(join(tmpdir(), 'vouchr-seed-'));
  const dbPath = await testDbUrl(t);
  const env = { ...process.env, VOUCHR_DATABASE_URL: dbPath, VOUCHR_MASTER_KEY: KEY_B64 };
  execFileSync(process.execPath, [
    '--import', 'tsx', 'bin/broker-seed.ts', 'reference',
    '--provider', 'confluence', '--team', 'T1', '--user', 'U1',
    '--source', 'aws-sm', '--secret-ref', 'arn:aws:secretsmanager:xyz',
  ], { env, stdio: 'pipe' });

  const db = await openDb({ databaseUrl: dbPath });
  try {
    const cred = await new Vault(db, Buffer.from(KEY_B64, 'base64')).get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'confluence');
    assert.equal(cred?.secretRef, 'arn:aws:secretsmanager:xyz'); // provisioned without Slack
  } finally {
    await db.close();
  }
});
