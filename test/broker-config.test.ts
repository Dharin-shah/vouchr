import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { channelOwner } from '../src/core/owner';
import { defineProvider } from '../src/core/providers';
import { createBroker } from '../src/adapters/http/broker';
import { signIdentity, type IdentityClaims } from '../src/adapters/http/identity';

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';

const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';

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

// A service-to-service tool the config routes must refuse (no human credential to broker).
const svc = defineProvider({
  id: 'svc', identity: 'service', credential: 'key',
  authorizeUrl: 'https://svc.example/auth', tokenUrl: 'https://svc.example/token',
  scopesDefault: ['x'], egressAllow: ['api.svc.example'], refresh: 'none', pkce: false,
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}

/** A broker with BOTH channel config stores wired to the SAME in-memory db, so a config write via
 *  the admin routes is reflected by a subsequent GET /v1/admin/config read (and vice versa). */
async function makeConfigBroker(t: TestContext) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  const channelTools = new ChannelTools(db);
  const server = createBroker({ providers: [acme, svc], vault, audit, db, identitySecret: SECRET, channelConfig, channelTools });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, db, vault, channelConfig, channelTools, port: (server.address() as any).port };
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

// Admin token; channelEligible defaults true so a `shared` write passes the eligibility gate (parity
// with /v1/admin/reference and Bolt's assertChannelEligible). Override to false to exercise the refusal.
const admin = (over: Partial<IdentityClaims> = {}) => signIdentity(claims({ isAdmin: true, channelEligible: true, ...over }), SECRET);

// #211: the callback-URL guard is actually wired into createBroker (not just unit-tested on the helper)
// — an off-origin or non-https redirect_uri must fail construction so the OAuth code can't leave the origin.
test('#211 createBroker: an off-origin or non-https callback is rejected at construction', async (t) => {
  const db = await openTestDb(t);
  const opts = { providers: [acme], vault: new Vault(db, KEY), audit: new Audit(db), db, identitySecret: SECRET, baseUrl: 'https://broker.example' };
  assert.throws(() => createBroker({ ...opts, callbackPath: 'https://evil.example/cb' }), /within the baseUrl origin/);
  assert.throws(() => createBroker({ ...opts, baseUrl: 'http://broker.example' }), /must use https/);
});

// (a) an admin token can set the mode, and GET /v1/admin/config reflects it.
test('admin/mode: an admin claim sets the channel mode; GET /v1/admin/config reflects it', async (t) => {
  const { server, port } = await makeConfigBroker(t);
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
test('admin/tools: an admin claim toggles a provider on/off; GET /v1/admin/config reflects it', async (t) => {
  const { server, port } = await makeConfigBroker(t);
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
test('config routes fail closed: a non-admin token gets 403 on mode/tools/config (forged body isAdmin ignored)', async (t) => {
  const { server, port, channelConfig } = await makeConfigBroker(t);
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
test('admin/mode: channel comes from the signed claim, never the body (no spoofing)', async (t) => {
  const { server, port, channelConfig } = await makeConfigBroker(t);
  try {
    // Sign for channel C1 but stuff a different channel + team in the body — both must be ignored.
    const r = await post(port, '/v1/admin/mode', {
      provider: 'acme', mode: 'session',
      identityToken: admin({ channel: 'C1' }),
      channel: 'CEVIL', teamId: 'TEVIL',
    } as any);
    assert.equal(r.status, 200);

    // The mode was written to the SIGNED channel (T1/C1), not the body-supplied CEVIL/TEVIL.
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), 'session');
    assert.equal(await channelConfig.getMode('TEVIL', 'CEVIL', 'acme'), null);

    // And the read side, scoped to a token signed for CEVIL, sees no config there.
    const evil = await getConfig(port, admin({ channel: 'CEVIL', teamId: 'TEVIL' }));
    assert.equal(evil.json.providers.find((p: any) => p.provider === 'acme').mode, null);
  } finally {
    server.close();
  }
});

// Guardrails: bad mode / non-boolean enabled / opt-out broker.
test('admin config routes validate input and require the stores to be enabled', async (t) => {
  const { server, port } = await makeConfigBroker(t);
  try {
    const badMode = await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'nonsense', identityToken: admin() });
    assert.equal(badMode.status, 400);
    const badEnabled = await post(port, '/v1/admin/tools', { provider: 'acme', enabled: 'yes', identityToken: admin() } as any);
    assert.equal(badEnabled.status, 400);
  } finally {
    server.close();
  }

  // A broker with neither store wired refuses the writes (fail closed), but still reads config (all defaults).
  const db = await openTestDb(t);
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

// P1: flipping a channel OFF `shared` deletes the shared credential (the re-authorization boundary),
// and it does NOT silently resurrect on a later flip back to `shared`.
test('admin/mode: flipping shared -> per-user deletes the shared credential (no dormant resurrection)', async (t) => {
  const { server, port, vault } = await makeConfigBroker(t);
  const owner = channelOwner('T1', 'C1');
  // The channel owns a shared credential + is marked shared.
  await vault.upsert(owner, 'acme', { accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: admin() });
  assert.ok(await vault.get(owner, 'acme'), 'precondition: shared cred exists');

  // Flip to a user-owned mode -> the shared cred is dropped.
  const flip = await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'per-user', identityToken: admin() });
  assert.equal(flip.status, 200);
  assert.equal(await vault.get(owner, 'acme'), null, 'shared cred was deleted on the non-shared flip');

  // Flip back to shared -> NO resurrection; the operator must re-ingest a credential.
  await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: admin() });
  assert.equal(await vault.get(owner, 'acme'), null, 'no dormant credential silently reactivated');
  server.close();
});

// P2: marking `shared` on an ineligible channel is refused (parity with /v1/admin/reference + Bolt).
test('admin/mode: `shared` on an ineligible channel is refused (eligibility parity)', async (t) => {
  const { server, port, channelConfig } = await makeConfigBroker(t);
  try {
    const r = await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: admin({ channelEligible: false }) });
    assert.equal(r.status, 403);
    assert.equal(await channelConfig.getMode('T1', 'C1', 'acme'), null, 'refused: no mode written');
    // A user-owned mode has no eligibility requirement, so it still succeeds on the same channel.
    const ok = await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'per-user', identityToken: admin({ channelEligible: false }) });
    assert.equal(ok.status, 200);
  } finally {
    server.close();
  }
});

// P3(d): a mode write emits a `config` audit row (the non-repudiation claim).
test('admin/mode: a mode write is audited as `config` with owner:channel (non-repudiation)', async (t) => {
  const { server, port, db } = await makeConfigBroker(t);
  try {
    await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'session', identityToken: admin() });
    const row = (await db.get(`SELECT user_id, channel, meta FROM audit WHERE action='config' ORDER BY at DESC LIMIT 1`)) as any;
    assert.ok(row, 'a config audit row was written');
    assert.equal(row.user_id, 'U1'); // the acting admin, from the SIGNED claims
    assert.equal(row.channel, 'C1');
    const meta = JSON.parse(row.meta);
    assert.equal(meta.mode, 'session');
    assert.equal(meta.owner, 'channel');
  } finally {
    server.close();
  }
});

// P3(a): the channel is the SIGNED one on /tools too — a body-supplied channel is ignored.
test('admin/tools: channel comes from the signed claim, never the body (no spoofing)', async (t) => {
  const { server, port, channelTools } = await makeConfigBroker(t);
  try {
    const r = await post(port, '/v1/admin/tools', {
      provider: 'acme', enabled: false, identityToken: admin({ channel: 'C1' }),
      channel: 'CEVIL', teamId: 'TEVIL',
    } as any);
    assert.equal(r.status, 200);
    assert.equal(await channelTools.isEnabled('T1', 'C1', 'acme'), false, 'written to the signed channel');
    assert.equal(await channelTools.isEnabled('TEVIL', 'CEVIL', 'acme'), true, 'body channel untouched (unconfigured -> all enabled)');
  } finally {
    server.close();
  }
});

// P3(b): unknown provider -> 404, service-to-service provider -> 403, on both write routes.
test('admin config write routes reject unknown (404) and service (403) providers', async (t) => {
  const { server, port } = await makeConfigBroker(t);
  try {
    const unknownMode = await post(port, '/v1/admin/mode', { provider: 'nope', mode: 'shared', identityToken: admin() });
    assert.equal(unknownMode.status, 404);
    const unknownTools = await post(port, '/v1/admin/tools', { provider: 'nope', enabled: true, identityToken: admin() });
    assert.equal(unknownTools.status, 404);
    const svcMode = await post(port, '/v1/admin/mode', { provider: 'svc', mode: 'shared', identityToken: admin() });
    assert.equal(svcMode.status, 403);
    const svcTools = await post(port, '/v1/admin/tools', { provider: 'svc', enabled: true, identityToken: admin() });
    assert.equal(svcTools.status, 403);
  } finally {
    server.close();
  }
});

// P3(c): an unsigned/expired identity token -> 401 on all three routes.
test('admin config routes reject an invalid/expired identity token (401)', async (t) => {
  const { server, port } = await makeConfigBroker(t);
  try {
    const badMode = await post(port, '/v1/admin/mode', { provider: 'acme', mode: 'shared', identityToken: 'not.a.token' });
    assert.equal(badMode.status, 401);
    const badTools = await post(port, '/v1/admin/tools', { provider: 'acme', enabled: true, identityToken: 'not.a.token' });
    assert.equal(badTools.status, 401);
    const expired = signIdentity(claims({ isAdmin: true, exp: Date.now() - 1 }), SECRET);
    const badConfig = await getConfig(port, expired);
    assert.equal(badConfig.status, 401);
  } finally {
    server.close();
  }
});

// (e) POST /v1/manifest — the CHANNEL-SCOPED manifest any member can read (the headless analogue of
// Bolt's toolManifest, same core builder). This is how a headless host learns preview `visibility`
// (a 'private' provider's output must go only to the requester), plus mode/enabled per channel.
test('manifest: POST returns the channel-scoped manifest including preview visibility', async (t) => {
  const { server, port, channelConfig } = await makeConfigBroker(t);
  try {
    await channelConfig.setVisibility('T1', 'C1', 'acme', 'private');
    await channelConfig.setMode('T1', 'C1', 'acme', 'session');
    const r = await post(port, '/v1/manifest', { identityToken: signIdentity(claims(), SECRET) });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.tools.find((t: any) => t.provider === 'acme'), {
      provider: 'acme', mode: 'session', enabled: true, identity: 'acting_human', visibility: 'private',
    });
    // Service tools appear (identity tells the host who runs them) with the channel's visibility bit.
    assert.equal(r.json.tools.find((t: any) => t.provider === 'svc').identity, 'service');
  } finally {
    server.close();
  }
});

test('manifest: POST requires a valid signed identity and reads only the claims channel', async (t) => {
  const { server, port, channelConfig } = await makeConfigBroker(t);
  try {
    const bad = await post(port, '/v1/manifest', { identityToken: 'garbage' });
    assert.equal(bad.status, 401);
    // A 'private' bit on ANOTHER channel must not leak into this channel's manifest.
    await channelConfig.setVisibility('T1', 'C_OTHER', 'acme', 'private');
    const r = await post(port, '/v1/manifest', { identityToken: signIdentity(claims(), SECRET) }); // channel C1
    assert.equal(r.json.tools.find((t: any) => t.provider === 'acme').visibility, 'public');
  } finally {
    server.close();
  }
});
