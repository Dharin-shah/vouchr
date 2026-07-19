import { test, type TestContext } from 'node:test';
import { testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { loadProviders } from '../bin/providerConfig';
import { beginBrokerDrain, buildBrokerServer } from '../bin/broker-server';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ChannelTools, configureChannelTools } from '../src/core/tools';
import { userOwner } from '../src/core/owner';
import { mintIdentity, loadIdentityConfig } from '../src/adapters/http/identity';

// #212 the packaged broker verifies deployment-bound assertions: a strong identity secret + a
// deployment id, minted in config mode. loadIdentityConfig with the same secret/id yields the same
// issuer/audience/kid, so a token minted here verifies against the broker built from baseEnv.
const IDENTITY_SECRET = 'test-identity-secret-at-least-32-bytes-long!!';
const DEPLOYMENT_ID = 'test-deployment';
const idConfig = () => loadIdentityConfig({ VOUCHR_IDENTITY_SECRET: IDENTITY_SECRET, VOUCHR_DEPLOYMENT_ID: DEPLOYMENT_ID } as any);
import { defineProvider } from '../src/core/providers';

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

function requestJson(
  port: number,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; json: any; raw: string }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request({
      host: '127.0.0.1',
      port,
      path,
      method,
      headers: {
        ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}),
        ...headers,
      },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json: any = null;
        try { json = JSON.parse(raw); } catch { /* streamed/non-JSON responses stay null */ }
        resolve({ status: res.statusCode ?? 0, json, raw });
      });
    });
    req.on('error', reject);
    req.end(data);
  });
}

// ── T7: env-driven provider config ───────────────────────────────────────────

test('loadProviders: parses an OAuth provider, resolving client creds from per-provider env', () => {
  const env = {
    VOUCHR_PROVIDERS: JSON.stringify([{ ...CONFLUENCE, oauthTimeoutMs: 2_500 }]),
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid',
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
  } as any;
  const [p] = loadProviders(env);
  assert.equal(p.id, 'confluence');
  assert.equal(p.clientId, 'cid');
  assert.equal(p.egressMethods, undefined); // unset -> broker default-denies non-GET/HEAD
  assert.equal(p.oauthTimeoutMs, 2_500); // declarative JSON reaches the canonical core validator
});

test('loadProviders: rejects an unknown/non-declarative field (fail closed)', () => {
  const env = { VOUCHR_PROVIDERS: JSON.stringify([{ ...CONFLUENCE, inject: 'x' }]) } as any;
  assert.throws(() => loadProviders(env), /unknown field/);
});

test('loadProviders: provider-file read and parse errors never echo the configured path', () => {
  const sentinel = 'ghp_PROVIDER_FILE_SENTINEL_123';
  for (const file of [
    join(tmpdir(), `${sentinel}-missing.json`),
    (() => {
      const path = join(mkdtempSync(join(tmpdir(), 'vouchr-provider-')), `${sentinel}.json`);
      writeFileSync(path, '{not-json', 'utf8');
      return path;
    })(),
  ]) {
    let message = '';
    try { loadProviders({ VOUCHR_PROVIDERS_FILE: file } as any); } catch (error) { message = (error as Error).message; }
    assert.ok(message);
    assert.equal(message.includes(sentinel), false, message);
    assert.equal(message.includes(file), false, message);
  }
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
  assert.throws(load({ paths: [] }), /mcp\.paths.*non-empty.*array/);
  assert.throws(load({ paths: [42] }), /mcp\.paths.*strings/);
  assert.throws(load({ paths: [' '] }), /mcp\.paths.*strings/);
  assert.throws(load({ paths: ['/mcp'], allowContentTypes: [] }), /mcp\.allowContentTypes.*non-empty.*array/);
  assert.throws(load({ paths: ['/mcp'], allowContentType: ['x'] }), /mcp.*unknown key/); // typo fails closed without reflecting input
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
  assert.throws(load({}), /approval\.approver.*unsupported/);
  assert.throws(load({ approver: 'anyone' }), /approval\.approver.*unsupported/);
  assert.throws(load({ approver: 'self', methods: [] }), /approval\.methods.*non-empty.*array/);
  assert.throws(load({ approver: 'self', methods: [42] }), /approval\.methods.*strings/);
  assert.throws(load({ approver: 'self', ttlMs: 0 }), /approval\.ttlMs.*positive safe integer/);
  assert.throws(load({ approver: 'self', ttlMs: '5m' }), /approval\.ttlMs.*positive safe integer/);
  assert.throws(load({ approver: 'self', ttl: 5 }), /approval.*unknown key/); // typo fails closed
  // P2-D fail-OPEN forms: non-empty but non-canonical → they'd never match at runtime, so reject.
  assert.throws(load({ approver: 'self', paths: [' '] }), /approval\.paths/);
  assert.throws(load({ approver: 'self', paths: ['repos'] }), /approval\.paths/); // no leading slash
  assert.throws(load({ approver: 'self', paths: [' /repos'] }), /approval\.paths/); // leading space
  assert.throws(load({ approver: 'self', methods: ['PO ST'] }), /approval\.methods/);
});

test('#113 loadProviders: canonicalizable approval methods are normalized (trim + upper-case)', () => {
  // 'post ' would never match the upper-cased request method — the loader accepts it and
  // defineProvider normalizes it to 'POST' so it actually enforces (fail-closed, not fail-open).
  const [p] = loadProviders({ VOUCHR_PROVIDERS: JSON.stringify([{ ...APPROVAL_INTERNAL, approval: { approver: 'self', methods: ['post '] } }]) } as any);
  assert.deepEqual(p.approval!.methods, ['POST']);
});

// #211 the remaining declarative knobs (scope descriptions, authorize params, public client, standard
// revocation, finite request/response limits) must be env-declarable too, routing through the same
// core validator as the built-in factories — otherwise the standalone broker can't reach them.
test('#211 loadProviders: the expanded declarative fields load and reach the provider', () => {
  const env = {
    VOUCHR_PROVIDERS: JSON.stringify([{
      ...CONFLUENCE,
      scopeDescriptions: { 'read:confluence': 'Read your Confluence pages' },
      authorizeParams: { audience: 'api.atlassian.com', prompt: 'consent' },
      revokeUrl: 'https://auth.atlassian.com/oauth/revoke',
      revokeAuth: 'body',
      revokeTarget: 'both',
      egressResponse: { maxBytes: 1048576, allowContentTypes: ['application/json'] },
      rateLimit: { perMinute: 60, burst: 10 },
    }]),
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid',
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
  } as any;
  const [p] = loadProviders(env);
  assert.deepEqual(p.scopeDescriptions, { 'read:confluence': 'Read your Confluence pages' });
  assert.deepEqual(p.authorizeParams, { audience: 'api.atlassian.com', prompt: 'consent' });
  assert.equal(p.revokeUrl, 'https://auth.atlassian.com/oauth/revoke');
  assert.equal(p.revokeAuth, 'body');
  assert.equal(p.revokeTarget, 'both');
  assert.deepEqual(p.egressResponse, { maxBytes: 1048576, allowContentTypes: ['application/json'] });
  assert.deepEqual(p.rateLimit, { perMinute: 60, burst: 10 });
});

test('#211 loadProviders: a public-client provider (no secret, PKCE-only) loads from JSON', () => {
  const env = {
    VOUCHR_PROVIDERS: JSON.stringify([{ ...CONFLUENCE, publicClient: true, pkce: true }]),
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid', // no _CLIENT_SECRET — a public client needs none
  } as any;
  const [p] = loadProviders(env);
  assert.equal(p.publicClient, true);
  assert.equal(p.clientSecret, undefined);
});

test('#211 loadProviders: an http tokenUrl / revokeUrl is rejected via the core validator (no cleartext secret)', () => {
  const bad = (over: Record<string, unknown>) => () =>
    loadProviders({
      VOUCHR_PROVIDERS: JSON.stringify([{ ...CONFLUENCE, ...over }]),
      VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid', VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
    } as any);
  assert.throws(bad({ tokenUrl: 'http://auth.atlassian.com/oauth/token' }), /tokenUrl must use https/);
  assert.throws(bad({ revokeUrl: 'http://auth.atlassian.com/oauth/revoke' }), /revokeUrl must use https/);
});

test('#211 loadProviders: a reserved authorizeParams key (state) is rejected at load', () => {
  const env = {
    VOUCHR_PROVIDERS: JSON.stringify([{ ...CONFLUENCE, authorizeParams: { state: 'attacker' } }]),
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid', VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
  } as any;
  assert.throws(() => loadProviders(env), /authorizeParams.*Vouchr-owned/);
});

test('#211 loadProviders: malformed shapes for the new fields fail closed with a config-shaped message', () => {
  const bad = (over: Record<string, unknown>) => () =>
    loadProviders({
      VOUCHR_PROVIDERS: JSON.stringify([{ ...CONFLUENCE, ...over }]),
      VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid', VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
    } as any);
  assert.throws(bad({ publicClient: 'yes' }), /field "publicClient" must be a boolean/);
  assert.throws(bad({ revokeAuth: 'header' }), /field "revokeAuth" must be one of/);
  assert.throws(bad({ scopeDescriptions: { x: 1 } }), /scopeDescriptions/);
  assert.throws(bad({ rateLimit: { burst: 5 } }), /invalid rateLimit/);
  assert.throws(bad({ rateLimit: { perMinute: 60, nope: 1 } }), /rateLimit.*unknown key/);
  assert.throws(bad({ egressResponse: { maxBytes: 'big' } }), /invalid egressResponse\.maxBytes/);
  assert.throws(bad({ egressResponse: { nope: 1 } }), /egressResponse.*unknown key/);
});

test('#211 loadProviders: JSON and code normalize to the same immutable provider', () => {
  const raw = { ...CONFLUENCE, egressAllow: ['API.ATLASSIAN.COM'], egressMethods: [' get ', 'POST'] };
  const env = {
    VOUCHR_PROVIDERS: JSON.stringify([raw]),
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid',
    VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
  } as any;
  const [fromJson] = loadProviders(env);
  const fromCode = defineProvider({ ...raw, clientId: 'cid', clientSecret: 'csecret' } as any);
  assert.deepEqual(fromJson, fromCode);
  assert.equal(Object.isFrozen(fromJson), true);
  assert.equal(Object.isFrozen(fromJson.egressMethods), true);
});

test('#211 loadProviders: errors never reflect hostile ids, keys, or nested values', () => {
  const sentinel = 'ghp_SECRET_SENTINEL_123';
  const configs = [
    [{ ...CONFLUENCE, id: sentinel.repeat(4) }],
    [{ ...CONFLUENCE, [sentinel]: true }],
    [{ ...CONFLUENCE, egressResponse: { maxBytes: 1, [sentinel]: true } }],
    [{ ...CONFLUENCE, authorizeParams: { state: sentinel } }],
  ];
  for (const config of configs) {
    let message = '';
    try {
      loadProviders({
        VOUCHR_PROVIDERS: JSON.stringify(config),
        VOUCHR_PROVIDER_CONFLUENCE_CLIENT_ID: 'cid',
        VOUCHR_PROVIDER_CONFLUENCE_CLIENT_SECRET: 'csecret',
      } as any);
    } catch (error) {
      message = (error as Error).message;
    }
    assert.ok(message);
    assert.equal(message.includes(sentinel), false, message);
  }
});

// ── T6: broker-server entrypoint ─────────────────────────────────────────────

async function baseEnv(t: TestContext, extra: Record<string, string> = {}): Promise<any> {
  return {
    VOUCHR_IDENTITY_SECRET: IDENTITY_SECRET,
    VOUCHR_DEPLOYMENT_ID: DEPLOYMENT_ID,
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

test('#236 packaged policy trusts the signed channel and denies before credential resolution', async (t) => {
  const env = await baseEnv(t, {
    VOUCHR_POLICY: JSON.stringify({
      defaultDeny: true,
      rules: {
        internal: { defaultAllow: false, allowChannels: ['C_ALLOWED'] },
      },
    }),
  });
  let resolverCalls = 0;
  const resolvedSecret = 'resolved-test-value';
  const built = await buildBrokerServer(env, {
    resolvers: {
      'aws-sm': async () => {
        resolverCalls++;
        return resolvedSecret;
      },
    },
  });
  await new Promise<void>((resolve) => built.server.listen(0, resolve));
  const port = (built.server.address() as any).port;
  const vault = new Vault(built.db, Buffer.from(KEY_B64, 'base64'));
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  await vault.reference(owner, 'internal', {
    source: 'aws-sm',
    secretRef: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:policy-test',
  });

  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  let upstreamAuthorization: string | null = null;
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    upstreamCalls++;
    upstreamAuthorization = new Headers(init?.headers).get('authorization');
    return new Response('{"ok":true}', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as any;
  const identityToken = (channel: string) => mintIdentity({
    teamId: 'T1', userId: 'U1', channel,
  }, idConfig());

  try {
    const denied = await requestJson(port, 'POST', '/v1/fetch', {
      handle: { provider: 'internal', owner: 'user' },
      identityToken: identityToken('C_DENIED'),
      method: 'GET',
      path: '/data',
      // Request JSON is forgeable. This must not override the verified C_DENIED claim above.
      channel: 'C_ALLOWED',
    });
    assert.equal(denied.status, 403);
    assert.deepEqual(denied.json, {
      error: 'policy denies this provider in this channel',
      code: 'policy_denied',
      retryable: false,
      recovery: 'contact_admin',
    });
    assert.equal(resolverCalls, 0, 'policy must run before an external reference is resolved');
    assert.equal(upstreamCalls, 0, 'policy must run before provider I/O');

    const allowed = await requestJson(port, 'POST', '/v1/fetch', {
      handle: { provider: 'internal', owner: 'user' },
      identityToken: identityToken('C_ALLOWED'),
      method: 'GET',
      path: '/data',
      // The inverse forgery also has no authority: the signed C_ALLOWED claim controls the result.
      channel: 'C_DENIED',
    });
    assert.equal(allowed.status, 200, allowed.raw);
    assert.equal(resolverCalls, 1);
    assert.equal(upstreamCalls, 1);
    assert.equal(upstreamAuthorization, `Bearer ${resolvedSecret}`);
    assert.equal(allowed.raw.includes(resolvedSecret), false);

    // SEC-1: resolving a reference is ephemeral. The credential may reach the allowlisted upstream,
    // but it must never be copied into either authoritative persistence surface.
    const persisted = {
      connection: await built.db.all(`SELECT * FROM connection WHERE team_id=? AND provider=?`, ['T1', 'internal']),
      audit: await built.db.all(`SELECT * FROM audit WHERE team_id=? AND provider=?`, ['T1', 'internal']),
    };
    assert.equal(JSON.stringify(persisted).includes(resolvedSecret), false);
  } finally {
    globalThis.fetch = realFetch;
    built.server.close();
    await built.db.close();
  }
});

test('#236 packaged default-deny policy with zero rules emits a deny-all boot warning', async (t) => {
  const env = await baseEnv(t, {
    VOUCHR_POLICY: JSON.stringify({ defaultDeny: true }),
  });
  const warnings: string[] = [];
  const realWarn = console.warn;
  let built: Awaited<ReturnType<typeof buildBrokerServer>> | undefined;
  console.warn = (...args: unknown[]) => warnings.push(args.map(String).join(' '));
  try {
    built = await buildBrokerServer(env);
    assert.deepEqual(warnings, [
      '[vouchr] static policy has defaultDeny=true and zero rules; all providers are denied',
    ]);
  } finally {
    console.warn = realWarn;
    await built?.db.close();
  }
});

test('#240 packaged broker shares and enforces channel governance across every data-plane door', async (t) => {
  const providerConfig = [
    { id: 'fetcher', credential: 'key', egressAllow: ['api.fetcher.example'] },
    {
      id: 'mcp-governed', credential: 'key', egressAllow: ['mcp.governed.example'],
      egressMethods: ['POST'], mcp: { paths: ['/mcp'] },
    },
    { id: 'service-tool', identity: 'service', credential: 'key', egressAllow: ['service.example'] },
  ];
  const env = await baseEnv(t, {
    VOUCHR_ALLOW_WRITES: '1',
    VOUCHR_PROVIDERS: JSON.stringify(providerConfig),
  });
  let resolverCalls = 0;
  const built = await buildBrokerServer(env, {
    resolvers: { 'aws-sm': async () => { resolverCalls++; return 'resolved-secret'; } },
  });
  await new Promise<void>((resolve) => built.server.listen(0, resolve));
  const port = (built.server.address() as any).port;
  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = (async () => {
    upstreamCalls++;
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;

  const token = (over: Record<string, unknown> = {}) => mintIdentity({
    teamId: 'T1', userId: 'U1', channel: 'C1', ...over,
  }, idConfig());
  const adminToken = () => token({ isAdmin: true, channelEligible: true });
  const owner = userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  const vault = new Vault(built.db, Buffer.from(KEY_B64, 'base64'));

  try {
    // References make a forbidden request observable if authorization ever drifts below resolution.
    await vault.reference(owner, 'fetcher', {
      source: 'aws-sm',
      secretRef: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:fetcher',
    });
    await vault.reference(owner, 'mcp-governed', {
      source: 'aws-sm',
      secretRef: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-governed',
    });

    // Force the latest possible failure in the admin mutation: both allowlist statements run, then
    // PostgreSQL rejects the config audit insert. The route must report failure AND leave no live
    // governance state, proving materialization, final upsert, and audit share one transaction.
    const storedTools = new ChannelTools(built.db);
    await built.db.exec(
      `ALTER TABLE audit ADD CONSTRAINT issue240_reject_config_audit CHECK (action <> 'config')`,
    );
    const auditRejected = await requestJson(port, 'POST', '/v1/admin/tools', {
      provider: 'fetcher', enabled: false, identityToken: adminToken(),
    });
    assert.equal(auditRejected.status, 500);
    assert.deepEqual(auditRejected.json, {
      error: 'internal error',
      code: 'internal_error',
      retryable: false,
      recovery: 'contact_admin',
    });
    const rolledBackTools = await built.db.get<{ n: number }>(
      `SELECT count(*)::int AS n FROM channel_tool WHERE team_id=? AND channel=?`,
      ['T1', 'C1'],
    );
    const rolledBackAudits = await built.db.get<{ n: number }>(
      `SELECT count(*)::int AS n FROM audit
       WHERE team_id=? AND channel=? AND provider=? AND action='config'`,
      ['T1', 'C1', 'fetcher'],
    );
    assert.equal(rolledBackTools?.n, 0);
    assert.equal(rolledBackAudits?.n, 0);
    assert.equal(await storedTools.isConfigured('T1', 'C1'), false);
    assert.equal(await storedTools.isEnabled('T1', 'C1', 'fetcher'), true);
    await built.db.exec(`ALTER TABLE audit DROP CONSTRAINT issue240_reject_config_audit`);

    // Once the audit sink recovers, the same route commits the full allowlist and audit together.
    const disabled = await requestJson(port, 'POST', '/v1/admin/tools', {
      provider: 'fetcher',
      enabled: false,
      identityToken: adminToken(),
      // Forgeable body scope has no authority; only the signed T1/C1 claims may be written.
      teamId: 'TEVIL',
      channel: 'CEVIL',
      isAdmin: false,
    });
    assert.equal(disabled.status, 200);
    assert.equal(await storedTools.isEnabled('T1', 'C1', 'fetcher'), false);
    assert.equal(await storedTools.isConfigured('TEVIL', 'CEVIL'), false);
    const committedAudit = await built.db.get<{ meta: string }>(
      `SELECT meta FROM audit
       WHERE team_id=? AND channel=? AND provider=? AND action='config' ORDER BY at DESC LIMIT 1`,
      ['T1', 'C1', 'fetcher'],
    );
    assert.deepEqual(JSON.parse(committedAudit?.meta ?? 'null'), {
      owner: 'channel', channel: 'C1', tool: 'disabled',
    });

    const config = await requestJson(
      port,
      'GET',
      '/v1/admin/config',
      undefined,
      { 'x-vouchr-identity': adminToken() },
    );
    assert.equal(config.status, 200);
    assert.deepEqual(config.json.providers, [
      { provider: 'fetcher', mode: null, enabled: false },
      { provider: 'mcp-governed', mode: null, enabled: true },
      { provider: 'service-tool', mode: null, enabled: true },
    ]);

    let manifest = await requestJson(port, 'POST', '/v1/manifest', { identityToken: token() });
    assert.equal(manifest.status, 200);
    assert.equal(manifest.json.tools.find((tool: any) => tool.provider === 'fetcher').enabled, false);
    assert.equal(manifest.json.tools.find((tool: any) => tool.provider === 'mcp-governed').enabled, true);
    assert.deepEqual(manifest.json.tools.find((tool: any) => tool.provider === 'service-tool'), {
      provider: 'service-tool', mode: null, enabled: true, identity: 'service',
    });

    const fetchDenied = await requestJson(port, 'POST', '/v1/fetch', {
      handle: { provider: 'fetcher', owner: 'user' },
      identityToken: token(),
      method: 'GET',
      path: '/data',
    });
    assert.equal(fetchDenied.status, 403);
    assert.equal(fetchDenied.json.error, 'provider is not enabled in this channel');
    assert.equal(resolverCalls, 0);
    assert.equal(upstreamCalls, 0);

    // Simulate a separate trusted Slack control-plane process: a distinct pool writes through the
    // same shared core mutation while the packaged broker keeps serving from its own pool.
    const controlDb = await openDb({ databaseUrl: env.VOUCHR_DATABASE_URL });
    try {
      const controlVault = new Vault(controlDb, randomBytes(32));
      const issuance = await controlVault.userProvisioningIssuedAt();
      await configureChannelTools({
        channelTools: new ChannelTools(controlDb),
        vault: controlVault,
        audit: new Audit(controlDb),
        identity: { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' },
        channel: 'C1',
        changes: [['mcp-governed', false]],
        allProviders: providerConfig.map((provider) => provider.id),
        authorize: async () => true,
        assertEligible: async () => undefined,
        issuance,
      });
    } finally {
      await controlDb.close();
    }

    manifest = await requestJson(port, 'POST', '/v1/manifest', { identityToken: token() });
    assert.equal(manifest.json.tools.find((tool: any) => tool.provider === 'mcp-governed').enabled, false);
    const mcpDenied = await requestJson(port, 'POST', '/v1/mcp', {
      handle: { provider: 'mcp-governed', owner: 'user' },
      identityToken: token(),
      path: '/mcp',
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
    });
    assert.equal(mcpDenied.status, 403);
    assert.equal(mcpDenied.json.error, 'provider is not enabled in this channel');
    assert.equal(resolverCalls, 0);
    assert.equal(upstreamCalls, 0);

    // Service credentials never enter Vouchr, but their shared governance bit is writable and
    // visible so the trusted host can enforce the same manifest decision on its own egress path.
    const serviceDisabled = await requestJson(port, 'POST', '/v1/admin/tools', {
      provider: 'service-tool', enabled: false, identityToken: adminToken(),
    });
    assert.equal(serviceDisabled.status, 200);
    manifest = await requestJson(port, 'POST', '/v1/manifest', { identityToken: token() });
    assert.equal(manifest.json.tools.find((tool: any) => tool.provider === 'service-tool').enabled, false);
  } finally {
    globalThis.fetch = realFetch;
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
    const identityToken = mintIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1' }, idConfig());
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
  assert.equal(dflt.shutdownTimeoutMs, 10_000);
  await dflt.db.close();
  const off = await buildBrokerServer(await baseEnv(t, {
    VOUCHR_SWEEP_INTERVAL_MS: '0',
    VOUCHR_SHUTDOWN_TIMEOUT_MS: '2500',
  }));
  assert.equal(off.sweepIntervalMs, 0);
  assert.equal(off.shutdownTimeoutMs, 2500);
  await off.db.close();
  await assert.rejects(buildBrokerServer(await baseEnv(t, { VOUCHR_SWEEP_INTERVAL_MS: 'nope' })), /VOUCHR_SWEEP_INTERVAL_MS/);
});

test('#209 graceful drain stops accepts, closes idle sockets, clears a clean deadline, and times out if stuck', async () => {
  const calls: string[] = [];
  let closeCallback!: () => void;
  let drained = 0;
  let timedOut = 0;
  const server = {
    close(callback: () => void) {
      calls.push('close');
      closeCallback = callback;
      return this;
    },
    closeIdleConnections() { calls.push('closeIdleConnections'); },
  } as unknown as http.Server;

  const cleanTimer = beginBrokerDrain(server, 1_000, () => { drained++; }, () => { timedOut++; });
  assert.deepEqual(calls, ['close', 'closeIdleConnections'], 'stop accepting before dropping idle connections');
  closeCallback();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(drained, 1);
  assert.equal(timedOut, 0);
  assert.equal(cleanTimer.hasRef(), false, 'the hard deadline never keeps the process alive by itself');

  const stuckServer = {
    close() { return this; },
    closeIdleConnections() {},
  } as unknown as http.Server;
  await new Promise<void>((resolve) => {
    const timer = beginBrokerDrain(stuckServer, 5, () => assert.fail('a stuck drain must not report clean'), () => {
      timedOut++;
      resolve();
    });
    timer.ref(); // The production deadline is unref'd; this focused test keeps Node alive to observe it.
  });
  assert.equal(timedOut, 1, 'a stuck active connection reaches the hard deadline exactly once');
});

test('#209 resource config is canonical, secret-safe, and rejected before Postgres acquisition', async (t) => {
  const base = await baseEnv(t, {
    // A syntactically valid but unreachable database proves each configuration failure wins before
    // openDb can attempt a connection. The test stays fast and deterministic only in that order.
    VOUCHR_DATABASE_URL: 'postgres://vouchr:vouchr@127.0.0.1:1/vouchr',
  });
  const sentinel = 'ghp_RESOURCE_CONFIG_MUST_NOT_BE_ECHOED';
  for (const name of [
    'VOUCHR_FETCH_DEADLINE_MS',
    'VOUCHR_MAX_INFLIGHT',
    'VOUCHR_MAX_INFLIGHT_PER_PROVIDER',
    'VOUCHR_HEADERS_TIMEOUT_MS',
    'VOUCHR_REQUEST_TIMEOUT_MS',
    'VOUCHR_KEEPALIVE_TIMEOUT_MS',
    'VOUCHR_SHUTDOWN_TIMEOUT_MS',
    'VOUCHR_SWEEP_INTERVAL_MS',
    'VOUCHR_TTL_IDLE_MS',
    'VOUCHR_PORT',
    'VOUCHR_ALLOW_WRITES',
    'VOUCHR_DRY_RUN',
    'VOUCHR_CHANNEL_MODES',
  ]) {
    await assert.rejects(
      buildBrokerServer({ ...base, [name]: sentinel }),
      (error: Error) => error.message.includes(name) && !error.message.includes(sentinel),
    );
  }

  await assert.rejects(
    buildBrokerServer({ ...base, VOUCHR_MAX_INFLIGHT: '1', VOUCHR_MAX_INFLIGHT_PER_PROVIDER: '2' }),
    /maxInflightPerProvider must be <= maxInflight/,
  );
  await assert.rejects(
    buildBrokerServer({ ...base, VOUCHR_HEADERS_TIMEOUT_MS: '20', VOUCHR_REQUEST_TIMEOUT_MS: '10' }),
    /requestTimeoutMs must be >= headersTimeoutMs/,
  );
  await assert.rejects(
    buildBrokerServer({ ...base, VOUCHR_FETCH_DEADLINE_MS: '2147483648' }),
    /VOUCHR_FETCH_DEADLINE_MS/,
  );
});

test('#116 VOUCHR_DRY_RUN: parses like VOUCHR_ALLOW_WRITES and hard-fails boot on a real vault', async (t) => {
  // Parse + wire-through: 1/true → on, 0/false/absent → off; typos fail during config validation.
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

// #212: the packaged broker fails closed at startup on a weak/placeholder identity secret, a missing
// deployment id, or a secret reused as the master key — before it ever accepts an assertion.
test('buildBrokerServer: fails closed on a weak/placeholder/reused identity secret and a missing deployment id', async (t) => {
  await assert.rejects(buildBrokerServer({ ...await baseEnv(t), VOUCHR_IDENTITY_SECRET: 'short' }), /at least 32 bytes/);
  // An obvious placeholder is rejected with a placeholder-specific message (case-insensitive).
  await assert.rejects(buildBrokerServer({ ...await baseEnv(t), VOUCHR_IDENTITY_SECRET: 'ChangeMe' }), /placeholder/);
  const { VOUCHR_DEPLOYMENT_ID, ...noDeploy } = await baseEnv(t);
  await assert.rejects(buildBrokerServer(noDeploy), /VOUCHR_DEPLOYMENT_ID/);
  await assert.rejects(
    buildBrokerServer({ ...await baseEnv(t), VOUCHR_DEPLOYMENT_ID: 'REPLACE_ME-vouchr-production' }),
    /placeholder/,
  );
  // Reused-purpose: identity secret == the base64 master key value.
  await assert.rejects(buildBrokerServer({ ...await baseEnv(t), VOUCHR_IDENTITY_SECRET: KEY_B64 }), /distinct from the master key/);
  // Reused-purpose: identity secret == a provider OAuth client secret (a value shared with a third party).
  await assert.rejects(
    buildBrokerServer({ ...await baseEnv(t), VOUCHR_PROVIDER_GITHUB_CLIENT_SECRET: IDENTITY_SECRET }),
    /provider client secrets/,
  );
  // Compare KEY MATERIAL, not only equal env text: the identity secret below is the raw 32-byte
  // ASCII value whose base64 form is used as the encryption master key.
  const sameKeyBytes = 'M7vouchrMasterKey2026abcdef12345';
  await assert.rejects(
    buildBrokerServer({
      ...await baseEnv(t),
      VOUCHR_IDENTITY_SECRET: sameKeyBytes,
      VOUCHR_MASTER_KEY: Buffer.from(sameKeyBytes).toString('base64'),
    }),
    /distinct from the master key/,
  );
  // A leaked Slack signing/provider OAuth secret must not also mint broker identities.
  await assert.rejects(
    buildBrokerServer({ ...await baseEnv(t), SLACK_SIGNING_SECRET: IDENTITY_SECRET }),
    /Slack signing secret/,
  );
  await assert.rejects(
    buildBrokerServer({ ...await baseEnv(t), GITHUB_CLIENT_SECRET: IDENTITY_SECRET }),
    /provider client secrets/,
  );
});

test('buildBrokerServer: hook overrides cannot replace identity/replay/provider security configuration', async (t) => {
  const env = await baseEnv(t);
  await assert.rejects(
    buildBrokerServer(env, { identitySecret: 'weak-legacy-secret' } as any),
    /unsupported override; allowed hooks:/,
  );
  const sentinel = 'ghp_unknown_override_secret';
  await assert.rejects(
    buildBrokerServer(env, { [sentinel]: true } as any),
    (e: Error) => /unsupported override; allowed hooks:/.test(e.message) && !e.message.includes(sentinel),
  );
  // The intentional wrapper hook remains supported.
  const built = await buildBrokerServer(env, { authorize: () => undefined });
  await built.db.close();
});
