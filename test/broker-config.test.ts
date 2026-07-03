import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { defineProvider } from '../src/core/providers';
import { createBroker } from '../src/adapters/http/broker';
import { signIdentity, type IdentityClaims } from '../src/adapters/http/identity';

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';

const acme = defineProvider({
  id: 'acme',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  refresh: 'none',
  pkce: false,
  clientId: 'id',
  clientSecret: 'sec',
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}

/** A broker with BOTH channel config stores wired to the SAME in-memory db, so a config write via
 *  the admin routes is reflected by a subsequent GET /v1/admin/config read (and vice versa). */
async function makeConfigBroker() {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  const channelTools = new ChannelTools(db);
  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: SECRET, channelConfig, channelTools });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, db, channelConfig, channelTools, port: (server.address() as any).port };
}

function post(port: number, path: string, body: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json: any = null;
          try { json = JSON.parse(raw); } catch { /* leave null */ }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

/** GET with the signed identity token on the header the config read expects. */
function getConfig(port: number, token?: string): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    http.get(
      { host: '127.0.0.1', port, path: '/v1/admin/config', headers: token ? { 'x-vouchr-identity': token } : {} },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
      },
    ).on('error', reject);
  });
}

const admin = (over: Partial<IdentityClaims> = {}) => signIdentity(claims({ isAdmin: true, ...over }), SECRET);

// (a) an admin token can set the mode, and GET /v1/admin/config reflects it.
test('admin/mode: an admin claim sets the channel mode; GET /v1/admin/config reflects it', async () => {
  const { server, port } = await makeConfigBroker();
  try {
    const before = await getConfig(port, admin());
    assert.equal(before.status, 200);
    assert.equal(before.json.providers.find((p: any) => p.provider === 'acme').mode, null);

    const set = await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: admin() });
    assert.equal(set.status, 200);
    assert.equal(set.json.ok, true);

    const after = await getConfig(port, admin());
    assert.equal(after.json.providers.find((p: any) => p.provider === 'acme').mode, 'shared');
  } finally {
    server.close();
  }
});

// (b) an admin token can toggle a provider in the channel's tool allowlist.
test('admin/tools: an admin claim toggles a provider on/off; GET /v1/admin/config reflects it', async () => {
  const { server, port } = await makeConfigBroker();
  try {
    // Disable acme -> the channel becomes an allowlist that does not include it.
    const off = await post(port, '/v1/admin/tools', { provider: 'acme', enabled: false, identityToken: admin() });
    assert.equal(off.status, 200);
    let cfg = await getConfig(port, admin());
    assert.equal(cfg.json.providers.find((p: any) => p.provider === 'acme').enabled, false);

    // Re-enable it.
    const on = await post(port, '/v1/admin/tools', { provider: 'acme', enabled: true, identityToken: admin() });
    assert.equal(on.status, 200);
    cfg = await getConfig(port, admin());
    assert.equal(cfg.json.providers.find((p: any) => p.provider === 'acme').enabled, true);
  } finally {
    server.close();
  }
});

// (c) a NON-admin token is refused (403) on all three routes — fail closed. A forged body isAdmin is ignored.
test('config routes fail closed: a non-admin token gets 403 on mode/tools/config (forged body isAdmin ignored)', async () => {
  const { server, port, channelConfig } = await makeConfigBroker();
  try {
    const userTok = () => signIdentity(claims(), SECRET); // no isAdmin claim

    const mode = await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: userTok(), isAdmin: true } as any);
    assert.equal(mode.status, 403);

    const tools = await post(port, '/v1/admin/tools', { provider: 'acme', enabled: false, identityToken: userTok(), isAdmin: true } as any);
    assert.equal(tools.status, 403);

    const cfg = await getConfig(port, userTok());
    assert.equal(cfg.status, 403);

    // A refused write changed nothing.
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), null);
  } finally {
    server.close();
  }
});

// (d) channel/mode cannot be spoofed via the body — the channel written is the SIGNED one.
test('admin/mode: channel comes from the signed claim, never the body (no spoofing)', async () => {
  const { server, port, channelConfig } = await makeConfigBroker();
  try {
    // Sign for channel C1 but stuff a different channel + team in the body — both must be ignored.
    const r = await post(port, '/v1/admin/mode', {
      provider: 'acme', mode: 'union',
      identityToken: admin({ channel: 'C1' }),
      channel: 'CEVIL', teamId: 'TEVIL',
    } as any);
    assert.equal(r.status, 200);

    // The mode was written to the SIGNED channel (T1/C1), not the body-supplied CEVIL/TEVIL.
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), 'union');
    assert.equal(await channelConfig.getMode('TEVIL', 'CEVIL', 'acme'), null);

    // And the read side, scoped to a token signed for CEVIL, sees no config there.
    const evil = await getConfig(port, admin({ channel: 'CEVIL', teamId: 'TEVIL' }));
    assert.equal(evil.json.providers.find((p: any) => p.provider === 'acme').mode, null);
  } finally {
    server.close();
  }
});

// Guardrails: bad mode / non-boolean enabled / opt-out broker.
test('admin config routes validate input and require the stores to be enabled', async () => {
  const { server, port } = await makeConfigBroker();
  try {
    const badMode = await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'nonsense', identityToken: admin() });
    assert.equal(badMode.status, 400);
    const badEnabled = await post(port, '/v1/admin/tools', { provider: 'acme', enabled: 'yes', identityToken: admin() } as any);
    assert.equal(badEnabled.status, 400);
  } finally {
    server.close();
  }

  // A broker with neither store wired refuses the writes (fail closed), but still reads config (all defaults).
  const db = await openDb({ dbPath: ':memory:' });
  const bare = createBroker({ providers: [acme], vault: new Vault(db, KEY), audit: new Audit(db), db, identitySecret: SECRET });
  await new Promise<void>((r) => bare.listen(0, r));
  const p2 = (bare.address() as any).port;
  try {
    const mode = await post(p2, '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: admin() });
    assert.equal(mode.status, 403);
    const tools = await post(p2, '/v1/admin/tools', { provider: 'acme', enabled: true, identityToken: admin() });
    assert.equal(tools.status, 403);
    const cfg = await getConfig(p2, admin());
    assert.equal(cfg.status, 200);
    assert.equal(cfg.json.providers[0].mode, null);
    assert.equal(cfg.json.providers[0].enabled, true); // channelTools unset -> default enabled
  } finally {
    bare.close();
  }
});
