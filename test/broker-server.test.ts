import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { loadProviders } from '../bin/providerConfig';
import { buildBrokerServer } from '../bin/broker-server';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';

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

// ── T6: broker-server entrypoint ─────────────────────────────────────────────

function baseEnv(extra: Record<string, string> = {}): any {
  return {
    VOUCHR_IDENTITY_SECRET: 'shhh',
    VOUCHR_MASTER_KEY: KEY_B64,
    VOUCHR_DB: ':memory:',
    VOUCHR_PROVIDERS: JSON.stringify([{ id: 'internal', credential: 'key', egressAllow: ['api.internal.example'] }]),
    ...extra,
  };
}

test('buildBrokerServer: boots on SQLite and serves /healthz + /health', async () => {
  const built = await buildBrokerServer(baseEnv({ VOUCHR_PORT: '0' }));
  await new Promise<void>((r) => built.server.listen(0, r));
  const port = (built.server.address() as any).port;
  try {
    assert.equal(built.backend, 'sqlite');
    assert.deepEqual(built.providerIds, ['internal']);
    assert.equal(await get(port, '/healthz'), 200);
    assert.equal(await get(port, '/health'), 200);
  } finally {
    built.server.close();
    await built.db.close();
  }
});

test('#54 buildBrokerServer.sweep removes an expired connection (headless TTL sweep)', async () => {
  const built = await buildBrokerServer(baseEnv());
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

test('#54 sweep interval: default is hourly; VOUCHR_SWEEP_INTERVAL_MS=0 disables it', async () => {
  const dflt = await buildBrokerServer(baseEnv());
  assert.equal(dflt.sweepIntervalMs, 60 * 60 * 1000);
  await dflt.db.close();
  const off = await buildBrokerServer(baseEnv({ VOUCHR_SWEEP_INTERVAL_MS: '0' }));
  assert.equal(off.sweepIntervalMs, 0);
  await off.db.close();
  await assert.rejects(buildBrokerServer(baseEnv({ VOUCHR_SWEEP_INTERVAL_MS: 'nope' })), /VOUCHR_SWEEP_INTERVAL_MS/);
});

test('buildBrokerServer: fails fast naming the missing secret', async () => {
  const { VOUCHR_IDENTITY_SECRET, ...noSecret } = baseEnv();
  await assert.rejects(buildBrokerServer(noSecret), /VOUCHR_IDENTITY_SECRET/);
  await assert.rejects(buildBrokerServer({ ...baseEnv(), VOUCHR_MASTER_KEY: undefined }), /VOUCHR_MASTER_KEY/);
  await assert.rejects(buildBrokerServer({ ...baseEnv(), VOUCHR_MASTER_KEY: 'dG9vc2hvcnQ=' }), /32 bytes/);
});

// ── T8: seed CLI ─────────────────────────────────────────────────────────────

test('broker-seed: reference mode writes a credential the broker can resolve', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vouchr-seed-'));
  const dbPath = join(dir, 'v.db');
  const env = { ...process.env, VOUCHR_DB: dbPath, VOUCHR_MASTER_KEY: KEY_B64 };
  execFileSync(process.execPath, [
    '--import', 'tsx', 'bin/broker-seed.ts', 'reference',
    '--provider', 'confluence', '--team', 'T1', '--user', 'U1',
    '--source', 'aws-sm', '--secret-ref', 'arn:aws:secretsmanager:xyz',
  ], { env, stdio: 'pipe' });

  const db = await openDb({ dbPath });
  try {
    const cred = await new Vault(db, Buffer.from(KEY_B64, 'base64')).get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'confluence');
    assert.equal(cred?.secretRef, 'arn:aws:secretsmanager:xyz'); // provisioned without Slack
  } finally {
    await db.close();
  }
});
