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
import { defineProvider, type Provider } from '../src/core/providers';
import { createBroker } from '../src/adapters/http/broker';
import { createVouchr } from '../src/adapters/bolt';
import { identityConfig, signIdentity, IDENTITY_SKEW_MS, type IdentityClaims } from './support/identity';
import type { Db } from '../src/core/db';
import { countingDb } from './support/counting-db';

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';

const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';

const INVALID_CALLBACK_PATHS = [
  null as unknown as string,
  '',
  '   ',
  'oauth/callback',
  'https://broker.example/oauth/callback',
  '//broker.example/oauth/callback',
  '/oauth/callback?next=1',
  '/oauth/callback#fragment',
  '/oauth/../callback',
  '/oauth/./callback',
  '/oauth/%2e%2e/callback',
  '/oauth\\callback',
  '/oauth%2fcallback',
  '/oauth%5ccallback',
  '/oauth/*callback',
  '/oauth/(callback)',
  '/oauth/[callback]',
  '/oauth/+callback',
  '/oauth/:callback',
];

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

/** A broker with BOTH channel config stores wired to the SAME real test database, so a config write via
 *  the admin routes is reflected by a subsequent GET /v1/admin/config read (and vice versa). */
async function makeConfigBroker(t: TestContext, opts: { providers?: Provider[]; db?: Db } = {}) {
  const db = opts.db ?? await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const channelConfig = new ChannelConfig(db);
  const channelTools = new ChannelTools(db);
  const server = createBroker({
    providers: opts.providers ?? [acme, svc],
    vault,
    audit,
    db,
    identitySecret: identityConfig(SECRET),
    channelConfig,
    channelTools,
  });
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

function getStatus(port: number, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    }).on('error', reject);
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

// #211: callbackPath is BOTH a Node route matcher and part of the public OAuth redirect URI. Admit
// exactly one canonical absolute pathname so those parsers cannot disagree about what is mounted.
test('#211 createBroker: only a canonical callback pathname is accepted and the accepted path routes', async (t) => {
  const db = await openTestDb(t);
  const opts = { providers: [acme], vault: new Vault(db, KEY), audit: new Audit(db), db, identitySecret: identityConfig(SECRET), baseUrl: 'https://broker.example' };
  for (const callbackPath of INVALID_CALLBACK_PATHS) {
    assert.throws(
      () => createBroker({ ...opts, callbackPath }),
      /callbackPath must be one canonical absolute path/,
      callbackPath || '(empty)',
    );
  }
  assert.throws(() => createBroker({ ...opts, baseUrl: 'http://broker.example' }), /must use https/);

  const server = createBroker({ ...opts, callbackPath: '/custom/oauth/callback' });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;
  try {
    assert.equal(await getStatus(port, '/custom/oauth/callback'), 400, 'the exact configured callback route is mounted');
    assert.equal(await getStatus(port, '/oauth/callback'), 404, 'the default route is not also mounted');
  } finally {
    server.close();
  }
});

test('#211 createVouchr: the same callback pathname contract runs before DB access', async (t) => {
  const previousKey = process.env.VOUCHR_MASTER_KEY;
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  t.after(() => {
    if (previousKey === undefined) delete process.env.VOUCHR_MASTER_KEY;
    else process.env.VOUCHR_MASTER_KEY = previousKey;
  });

  for (const callbackPath of INVALID_CALLBACK_PATHS) {
    let dbRead = false;
    const opts: any = { providers: [acme], baseUrl: 'https://broker.example', callbackPath };
    Object.defineProperty(opts, 'db', {
      get() {
        dbRead = true;
        throw new Error('database must not be read for invalid callback configuration');
      },
    });
    await assert.rejects(createVouchr(opts), /callbackPath must be one canonical absolute path/, callbackPath || '(empty)');
    assert.equal(dbRead, false, `callbackPath ${JSON.stringify(callbackPath)} must fail before DB access`);
  }

  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme],
    baseUrl: 'https://broker.example',
    callbackPath: '/custom/vouchr/oauth/callback',
    db,
  });
  let mountedPath: string | undefined;
  vouchr.mountRoutes({ get: (path: string) => { mountedPath = path; } });
  assert.equal(mountedPath, '/custom/vouchr/oauth/callback');
  await vouchr.close(); // injected DB remains owned by the test fixture
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

test('GET /v1/admin/config keeps real-route reads fixed as providers grow and skips empty work (#209)', async (t) => {
  const read = async (providerCount: number) => {
    const base = await openTestDb(t);
    const counted = countingDb(base);
    const providers = providerCount === 0
      ? []
      : Array.from({ length: providerCount }, (_, i) => defineProvider({
          id: `perf${i}`,
          authorizeUrl: 'https://perf.example/auth',
          tokenUrl: 'https://perf.example/token',
          scopesDefault: [],
          egressAllow: ['api.perf.example'],
          refresh: 'none',
          pkce: false,
          clientId: 'id',
          clientSecret: 'sec',
        }));
    const { server, port } = await makeConfigBroker(t, { providers, db: counted.db });
    counted.reset();
    try {
      const response = await getConfig(port, admin());
      assert.equal(response.status, 200);
      assert.equal(response.json.providers.length, providerCount);
      return { ...counted.counts };
    } finally {
      server.close();
    }
  };

  assert.deepEqual(await read(2), { get: 0, all: 2 });
  assert.deepEqual(await read(51), { get: 0, all: 2 });
  assert.deepEqual(await read(0), { get: 0, all: 0 });
});

// (b) an admin token can toggle a provider in the channel's tool allowlist.
test('admin/tools: an admin claim toggles a provider on/off; GET /v1/admin/config reflects it', async (t) => {
  const { server, port, db } = await makeConfigBroker(t);
  try {
    // Disable acme on the first write. The channel becomes an explicit allowlist, but the service
    // bystander must stay enabled rather than disappearing because it had no row of its own.
    const off = await post(port, '/v1/admin/tools', { provider: 'acme', enabled: false, identityToken: admin() });
    assert.equal(off.status, 200);
    let cfg = await getConfig(port, admin());
    assert.equal(cfg.json.providers.find((p: any) => p.provider === 'acme').enabled, false);
    assert.deepEqual(cfg.json.providers.find((p: any) => p.provider === 'svc'), {
      provider: 'svc', mode: null, enabled: true,
    });
    const audited = (await db.get(
      `SELECT meta FROM audit WHERE action='config' AND provider='acme' ORDER BY at DESC LIMIT 1`,
    )) as { meta: string };
    assert.deepEqual(JSON.parse(audited.meta), {
      owner: 'channel', channel: 'C1', tool: 'disabled',
    });

    // Re-enable it without altering the service tool's bit.
    const on = await post(port, '/v1/admin/tools', { provider: 'acme', enabled: true, identityToken: admin() });
    assert.equal(on.status, 200);
    cfg = await getConfig(port, admin());
    assert.equal(cfg.json.providers.find((p: any) => p.provider === 'acme').enabled, true);
    assert.equal(cfg.json.providers.find((p: any) => p.provider === 'svc').enabled, true);

    // Enabling an already-default-on provider as the first write in a different channel must also
    // materialize the untouched bystander as enabled.
    const freshOn = await post(port, '/v1/admin/tools', {
      provider: 'acme', enabled: true, identityToken: admin({ channel: 'C2' }),
    });
    assert.equal(freshOn.status, 200);
    const freshCfg = await getConfig(port, admin({ channel: 'C2' }));
    assert.equal(freshCfg.json.providers.find((p: any) => p.provider === 'acme').enabled, true);
    assert.equal(freshCfg.json.providers.find((p: any) => p.provider === 'svc').enabled, true);
  } finally {
    server.close();
  }
});

test('admin/tools: concurrent first writes retain both changes and every bystander', async (t) => {
  const peer = defineProvider({
    id: 'peer', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
    egressAllow: ['api.peer.example'], refresh: 'none', pkce: false,
  });
  const { server, port, channelTools } = await makeConfigBroker(t, { providers: [acme, svc, peer] });
  try {
    const [a, b] = await Promise.all([
      post(port, '/v1/admin/tools', { provider: 'acme', enabled: false, identityToken: admin() }),
      post(port, '/v1/admin/tools', { provider: 'svc', enabled: false, identityToken: admin() }),
    ]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.equal(await channelTools.isEnabled('T1', 'C1', 'acme'), false);
    assert.equal(await channelTools.isEnabled('T1', 'C1', 'svc'), false);
    assert.equal(await channelTools.isEnabled('T1', 'C1', 'peer'), true);
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
  const bare = createBroker({ providers: [acme], vault: new Vault(db, KEY), audit: new Audit(db), db, identitySecret: identityConfig(SECRET) });
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

// P3(b): modes remain credential-only, while the service tool's manifest bit stays governable.
test('admin config rejects unknown providers and governs service tools without a credential mode', async (t) => {
  const { server, port } = await makeConfigBroker(t);
  try {
    const unknownMode = await post(port, '/v1/admin/mode', { provider: 'nope', mode: 'shared', identityToken: admin() });
    assert.equal(unknownMode.status, 404);
    const unknownTools = await post(port, '/v1/admin/tools', { provider: 'nope', enabled: true, identityToken: admin() });
    assert.equal(unknownTools.status, 404);
    const svcMode = await post(port, '/v1/admin/mode', { provider: 'svc', mode: 'shared', identityToken: admin() });
    assert.equal(svcMode.status, 403);
    const svcTools = await post(port, '/v1/admin/tools', { provider: 'svc', enabled: false, identityToken: admin() });
    assert.equal(svcTools.status, 200);
    const cfg = await getConfig(port, admin());
    assert.deepEqual(cfg.json.providers.find((p: any) => p.provider === 'svc'), {
      provider: 'svc', mode: null, enabled: false,
    });
    const manifest = await post(port, '/v1/manifest', { identityToken: signIdentity(claims(), SECRET) });
    assert.deepEqual(manifest.json.tools.find((p: any) => p.provider === 'svc'), {
      provider: 'svc', mode: null, enabled: false, identity: 'service', visibility: 'public',
    });
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
    const expired = signIdentity(claims({ isAdmin: true, exp: Date.now() - IDENTITY_SKEW_MS - 1 }), SECRET);
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
