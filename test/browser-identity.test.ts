// #302/#340: the Slack OIDC hop that binds the browser completing provider OAuth to the Slack
// identity bound in the consent state — the only consent path on both surfaces. Offline: Slack's
// OIDC token endpoint and the provider token endpoint are fetch-stubbed (TEST-3); the broker/bolt
// routes run for real.
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { openTestDb } from './support/pg';
import { listen } from './support/http';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { createBroker } from '../src/adapters/http/broker';
import { createVouchr } from '../src/adapters/bolt';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { SLACK_OIDC_AUTHORIZE_URL, SLACK_OIDC_TOKEN_URL } from '../src/adapters/slackVerify';
import { signIdentity, identityConfig, type IdentityClaims } from './support/identity';
import { TEST_SLACK_OIDC } from './support/slackOidc';

const KEY = randomBytes(32);
const SECRET = 'browser-identity-signing-secret';
// Endpoints are deliberately NOT configurable (a configurable token endpoint would be a seam that
// receives the client secret + code and can fabricate any identity); tests stub fetch instead.
const OIDC = TEST_SLACK_OIDC;

const acme = defineProvider({
  id: 'acme',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  refresh: 'none',
  pkce: true,
  clientId: 'id',
  clientSecret: 'sec',
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}

const b64u = (s: string) => Buffer.from(s).toString('base64url');

/** Hand-built id_token: header.payload.signature — the verifier decodes the payload and accepts the
 *  TLS-direct token without signature verification, so the signature segment is arbitrary. */
function idToken(over: Record<string, unknown> = {}): string {
  const payload = {
    iss: 'https://slack.com',
    aud: OIDC.clientId,
    exp: Math.floor(Date.now() / 1000) + 300,
    sub: 'U1',
    'https://slack.com/team_id': 'T1',
    ...over,
  };
  return `${b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${b64u(JSON.stringify(payload))}.sig`;
}

interface StubLog { slackTokenCalls: number; providerTokenCalls: number; }

/** Stub Slack's OIDC token endpoint + the provider token endpoint. Restore in finally (TEST-3). */
function stubFetch(idTokenBody: () => { status: number; body: unknown }): { log: StubLog; restore: () => void } {
  const real = globalThis.fetch;
  const log: StubLog = { slackTokenCalls: 0, providerTokenCalls: 0 };
  globalThis.fetch = (async (u: any) => {
    const url = String(u);
    if (url.startsWith(SLACK_OIDC_TOKEN_URL)) {
      log.slackTokenCalls += 1;
      const r = idTokenBody();
      return new Response(JSON.stringify(r.body), { status: r.status, headers: { 'content-type': 'application/json' } });
    }
    if (url.startsWith('https://acme.example/token')) {
      log.providerTokenCalls += 1;
      return new Response(JSON.stringify({ access_token: 'PROVIDER_TOKEN' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`unexpected outbound fetch in offline test: ${url}`);
  }) as any;
  return { log, restore: () => { globalThis.fetch = real; } };
}

async function makeVerifiedBroker(t: TestContext, extra: Partial<Parameters<typeof createBroker>[0]> = {}) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const server = createBroker({
    providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET),
    baseUrl: 'https://broker.example', slackOidc: OIDC, ...extra,
  });
  await listen(t, server);
  return { server, vault, audit, db, port: (server.address() as any).port };
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
          try { json = JSON.parse(raw); } catch { /* HTML */ }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

function getRaw(port: number, path: string): Promise<{ status: number; raw: string; location: string | null }> {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        raw: Buffer.concat(chunks).toString('utf8'),
        location: (res.headers.location as string | undefined) ?? null,
      }));
    }).on('error', reject);
  });
}

/** connect → hop 1, returning the state and hop-1 redirect for the per-test continuation. */
async function beginFlow(port: number) {
  const c = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: signIdentity(claims(), SECRET) });
  assert.equal(c.status, 200);
  const authorize = new URL(c.json.authorizeUrl);
  const state: string = c.json.state;
  return { authorize, state };
}

// ── the verify hop rewires the prompt URL ────────────────────────────────────

test('#302 /v1/connect mints the Vouchr verify URL, and hop 1 redirects to Slack OIDC authorize', async (t) => {
  const { server, port } = await makeVerifiedBroker(t);
  try {
    const { authorize, state } = await beginFlow(port);
    // The prompt URL is Vouchr's verify hop — never the provider's authorize URL.
    assert.equal(authorize.origin, 'https://broker.example');
    assert.equal(authorize.pathname, '/oauth/verify');
    assert.equal(authorize.searchParams.get('state'), state);

    const hop1 = await getRaw(port, `/oauth/verify?state=${encodeURIComponent(state)}`);
    assert.equal(hop1.status, 302);
    const slack = new URL(hop1.location!);
    assert.equal(`${slack.origin}${slack.pathname}`, SLACK_OIDC_AUTHORIZE_URL);
    assert.equal(slack.searchParams.get('response_type'), 'code');
    assert.equal(slack.searchParams.get('scope'), 'openid');
    assert.equal(slack.searchParams.get('client_id'), OIDC.clientId);
    assert.equal(slack.searchParams.get('redirect_uri'), 'https://broker.example/oauth/slack');
    assert.equal(slack.searchParams.get('state'), state);
  } finally {
    server.close();
  }
});

test('#302 hop 1 with an unknown/expired state is a fixed 400 and never redirects to Slack', async (t) => {
  const { server, port } = await makeVerifiedBroker(t);
  try {
    const r = await getRaw(port, `/oauth/verify?state=${randomBytes(32).toString('base64url')}`);
    assert.equal(r.status, 400);
    assert.equal(r.location, null);
  } finally {
    server.close();
  }
});

// ── match → provider redirect → callback writes ──────────────────────────────

test('#302 matching Slack identity: hop 2 redirects to the provider, callback vaults the credential', async (t) => {
  const { server, vault, port } = await makeVerifiedBroker(t);
  const stub = stubFetch(() => ({ status: 200, body: { ok: true, access_token: 'xoxp-ignored', id_token: idToken() } }));
  try {
    const { state } = await beginFlow(port);
    const hop2 = await getRaw(port, `/oauth/slack?code=slack-code&state=${encodeURIComponent(state)}`);
    assert.equal(hop2.status, 302, hop2.raw);
    const provider = new URL(hop2.location!);
    // The real provider authorize URL is revealed only now, with the SAME single-use state + PKCE.
    assert.equal(`${provider.origin}${provider.pathname}`, 'https://acme.example/auth');
    assert.equal(provider.searchParams.get('state'), state);
    assert.equal(provider.searchParams.get('redirect_uri'), 'https://broker.example/oauth/callback');
    assert.ok(provider.searchParams.get('code_challenge'));
    assert.equal(stub.log.slackTokenCalls, 1);

    const cb = await getRaw(port, `/oauth/callback?code=abc123&state=${encodeURIComponent(state)}`);
    assert.equal(cb.status, 200, cb.raw);
    assert.match(cb.raw, /connected/);
    const cred = await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme');
    assert.equal(cred?.accessToken, 'PROVIDER_TOKEN');
  } finally {
    stub.restore();
    server.close();
  }
});

// ── mismatch fails closed ────────────────────────────────────────────────────

test('#302 mismatched Slack identity: fixed non-reflecting refusal, state spent, nothing written, audited', async (t) => {
  const { server, vault, port, db } = await makeVerifiedBroker(t);
  const stub = stubFetch(() => ({ status: 200, body: { ok: true, id_token: idToken({ sub: 'U-EVIL' }) } }));
  try {
    const { state } = await beginFlow(port);
    const hop2 = await getRaw(port, `/oauth/slack?code=slack-code&state=${encodeURIComponent(state)}`);
    assert.equal(hop2.status, 403);
    assert.equal(hop2.location, null);
    // Fixed error only: neither the completer's nor the bound user's Slack id is reflected (SEC-5).
    assert.ok(!hop2.raw.includes('U-EVIL'));
    assert.ok(!hop2.raw.includes('U1'));

    // The single-use state is spent: the provider callback can no longer use it…
    const cb = await getRaw(port, `/oauth/callback?code=abc123&state=${encodeURIComponent(state)}`);
    assert.equal(cb.status, 400);
    // …and no credential was written, no provider exchange ever ran.
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
    assert.equal(stub.log.providerTokenCalls, 0);

    // Audited against the BOUND identity with a fixed reason; the observed values never persist (SEC-4).
    const row = (await db.get(
      `SELECT user_id, meta FROM audit WHERE action='denied' AND provider='acme'`,
    )) as any;
    assert.equal(row.user_id, 'U1');
    assert.match(row.meta, /browser_identity_mismatch/);
    assert.ok(!row.meta.includes('U-EVIL'));
  } finally {
    stub.restore();
    server.close();
  }
});

test('#302 mismatched team fails closed even when the user id matches', async (t) => {
  const { server, port } = await makeVerifiedBroker(t);
  const stub = stubFetch(() => ({ status: 200, body: { ok: true, id_token: idToken({ 'https://slack.com/team_id': 'T-OTHER' }) } }));
  try {
    const { state } = await beginFlow(port);
    const hop2 = await getRaw(port, `/oauth/slack?code=slack-code&state=${encodeURIComponent(state)}`);
    assert.equal(hop2.status, 403);
  } finally {
    stub.restore();
    server.close();
  }
});

// ── REV-2 guardrail: the hop cannot be bypassed ──────────────────────────────

test('#302 guardrail: a direct callback on an unverified consent can never write a credential', async (t) => {
  const { server, vault, port } = await makeVerifiedBroker(t);
  const stub = stubFetch(() => ({ status: 200, body: { ok: true, id_token: idToken() } }));
  try {
    const { state } = await beginFlow(port);
    // Skip both hops and hit the provider callback directly with a valid-looking code.
    const cb = await getRaw(port, `/oauth/callback?code=abc123&state=${encodeURIComponent(state)}`);
    assert.equal(cb.status, 403);
    // No provider token was minted, nothing landed in the vault, and the state is spent.
    assert.equal(stub.log.providerTokenCalls, 0);
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
    const replay = await getRaw(port, `/oauth/callback?code=abc123&state=${encodeURIComponent(state)}`);
    assert.equal(replay.status, 400);
    // Completing the hop AFTER the burned callback cannot resurrect the flow either.
    const late = await getRaw(port, `/oauth/slack?code=slack-code&state=${encodeURIComponent(state)}`);
    assert.equal(late.status, 400);
  } finally {
    stub.restore();
    server.close();
  }
});

test('#302 two replicas sharing the database: the stamp travels with the row, so either callback enforces it', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const base = { providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), baseUrl: 'https://broker.example', slackOidc: OIDC };
  const serverA = createBroker({ ...base });
  const serverB = createBroker({ ...base });
  await listen(t, serverA);
  await listen(t, serverB);
  const portA = (serverA.address() as any).port;
  const portB = (serverB.address() as any).port;
  const stub = stubFetch(() => ({ status: 200, body: { ok: true, id_token: idToken() } }));
  try {
    // Minted on A, never verified: B's callback refuses it — the state is spent, nothing written.
    const { state } = await beginFlow(portA);
    const cb = await getRaw(portB, `/oauth/callback?code=abc123&state=${encodeURIComponent(state)}`);
    assert.equal(cb.status, 403, cb.raw);
    assert.equal(stub.log.providerTokenCalls, 0, 'the provider code must never be exchanged');
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);

    // Minted on A, verified on A, completed on B: the stamp is in the shared row.
    const second = await beginFlow(portA);
    const hop2 = await getRaw(portA, `/oauth/slack?code=slack-code&state=${encodeURIComponent(second.state)}`);
    assert.equal(hop2.status, 302, hop2.raw);
    const done = await getRaw(portB, `/oauth/callback?code=abc123&state=${encodeURIComponent(second.state)}`);
    assert.equal(done.status, 200, done.raw);
  } finally {
    stub.restore();
    serverA.close();
    serverB.close();
  }
});

test('#302 mismatch with a failing audit store: state stays spent, but the response is 500 contact-admin, never a recorded-looking 403', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  audit.record = async () => { throw new Error('audit store down'); };
  const server = createBroker({
    providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET),
    baseUrl: 'https://broker.example', slackOidc: OIDC,
  });
  await listen(t, server);
  const port = (server.address() as any).port;
  const stub = stubFetch(() => ({ status: 200, body: { ok: true, id_token: idToken({ sub: 'U-EVIL' }) } }));
  try {
    const { state } = await beginFlow(port);
    const hop2 = await getRaw(port, `/oauth/slack?code=slack-code&state=${encodeURIComponent(state)}`);
    assert.equal(hop2.status, 500);
    assert.match(hop2.raw, /could not record/i);
    assert.ok(!hop2.raw.includes('U-EVIL'));
    // The single-use state is spent regardless — audit trouble never resurrects authority…
    const cb = await getRaw(port, `/oauth/callback?code=abc123&state=${encodeURIComponent(state)}`);
    assert.equal(cb.status, 400);
    // …and nothing was written.
    assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
    assert.equal(stub.log.providerTokenCalls, 0);
  } finally {
    stub.restore();
    server.close();
  }
});

// ── Slack-side failures leave the state usable (not an identity mismatch) ────

test('#302 a Slack authorize error or missing code is a fixed 400 that does NOT spend the state', async (t) => {
  const { server, port } = await makeVerifiedBroker(t);
  const stub = stubFetch(() => ({ status: 200, body: { ok: true, id_token: idToken() } }));
  try {
    const { state } = await beginFlow(port);
    const cancel = await getRaw(port, `/oauth/slack?error=access_denied&state=${encodeURIComponent(state)}`);
    assert.equal(cancel.status, 400);
    // One sentence that is true for a replaced channel ephemeral AND a durable DM prompt (#348).
    assert.match(cancel.raw, /Slack sign-in did not complete\. Go back to Slack\. If the connection prompt is still there, use it; if not, ask the agent again\./);
    assert.equal(stub.log.slackTokenCalls, 0);
    // The legitimate user can still complete from the same prompt.
    const hop2 = await getRaw(port, `/oauth/slack?code=slack-code&state=${encodeURIComponent(state)}`);
    assert.equal(hop2.status, 302);
  } finally {
    stub.restore();
    server.close();
  }
});

test('#302 a failing/invalid Slack token exchange is a fixed 502 that does NOT spend the state', async (t) => {
  const { server, port } = await makeVerifiedBroker(t);
  let mode: 'http500' | 'notOk' | 'badIss' | 'badAud' | 'expired' | 'good' = 'http500';
  const stub = stubFetch(() => {
    switch (mode) {
      case 'http500': return { status: 500, body: {} };
      case 'notOk': return { status: 200, body: { ok: false, error: 'invalid_code' } };
      case 'badIss': return { status: 200, body: { ok: true, id_token: idToken({ iss: 'https://evil.example' }) } };
      case 'badAud': return { status: 200, body: { ok: true, id_token: idToken({ aud: 'someone-else' }) } };
      case 'expired': return { status: 200, body: { ok: true, id_token: idToken({ exp: Math.floor(Date.now() / 1000) - 60 }) } };
      case 'good': return { status: 200, body: { ok: true, id_token: idToken() } };
    }
  });
  try {
    const { state } = await beginFlow(port);
    for (const m of ['http500', 'notOk', 'badIss', 'badAud', 'expired'] as const) {
      mode = m;
      const r = await getRaw(port, `/oauth/slack?code=slack-code&state=${encodeURIComponent(state)}`);
      assert.equal(r.status, 502, `mode ${m}`);
      assert.ok(!r.raw.includes('invalid_code'), 'upstream error text is never reflected');
    }
    mode = 'good';
    const ok = await getRaw(port, `/oauth/slack?code=slack-code&state=${encodeURIComponent(state)}`);
    assert.equal(ok.status, 302);
  } finally {
    stub.restore();
    server.close();
  }
});

// ── construction-time validation (fail closed, both surfaces) ────────────────

test('#340 createBroker fails closed without the Slack OIDC credentials or baseUrl, naming the variable', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const base = { providers: [acme], vault, audit: new Audit(db), db, identitySecret: identityConfig(SECRET) };
  assert.throws(
    () => createBroker({ ...base, baseUrl: 'https://b.example', slackOidc: undefined as any }),
    /VOUCHR_SLACK_CLIENT_ID \/ VOUCHR_SLACK_CLIENT_SECRET/,
  );
  for (const partial of [{ clientId: '', clientSecret: 'x' }, { clientId: 'x', clientSecret: '' }, { clientId: 'x' } as any,
    { clientId: ' ', clientSecret: 'x' }, { clientId: 'x', clientSecret: '\t' }]) { // IMP-3: whitespace is empty
    assert.throws(() => createBroker({ ...base, baseUrl: 'https://b.example', slackOidc: partial }), /slackOidc\.clientSecret/);
  }
  for (const baseUrl of [undefined as any, '', ' ']) {
    assert.throws(() => createBroker({ ...base, slackOidc: OIDC, baseUrl }), /baseUrl is required \(VOUCHR_BASE_URL\)/);
  }
  assert.throws(
    () => createBroker({ ...base, baseUrl: 'https://b.example', callbackPath: '/oauth/verify', slackOidc: OIDC }),
    /must not end in/,
  );
  // dryRun (#116) coexists with the required credentials: its synthetic authorize URL stands in
  // for the Slack hop as it does for the provider, so a dry-run broker constructs.
  const dry = createBroker({ ...base, baseUrl: 'https://b.example', slackOidc: OIDC, dryRun: true });
  dry.close();
});

test('#340 createVouchr fails closed without the Slack OIDC credentials (option or env), naming the variable', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const saved = { id: process.env.VOUCHR_SLACK_CLIENT_ID, secret: process.env.VOUCHR_SLACK_CLIENT_SECRET };
  t.after(() => {
    delete process.env.VOUCHR_MASTER_KEY;
    process.env.VOUCHR_SLACK_CLIENT_ID = saved.id;
    process.env.VOUCHR_SLACK_CLIENT_SECRET = saved.secret;
  });
  delete process.env.VOUCHR_SLACK_CLIENT_ID;
  delete process.env.VOUCHR_SLACK_CLIENT_SECRET;
  await assert.rejects(
    createVouchr({ providers: [acme], baseUrl: 'https://x.example' }),
    /createVouchr: slackOidc\.clientId and slackOidc\.clientSecret are required \(VOUCHR_SLACK_CLIENT_ID \/ VOUCHR_SLACK_CLIENT_SECRET/,
  );
  process.env.VOUCHR_SLACK_CLIENT_ID = 'only-the-id';
  await assert.rejects(createVouchr({ providers: [acme], baseUrl: 'https://x.example' }), /VOUCHR_SLACK_CLIENT_SECRET/);
  await assert.rejects(
    createVouchr({ providers: [acme], baseUrl: 'https://x.example', callbackPath: '/vouchr/oauth/slack', slackOidc: OIDC }),
    /must not end in/,
  );
});

// ── the Bolt surface mounts the same hop ─────────────────────────────────────

test('#302 Bolt: prompt URL is the verify hop; hop → callback completes and writes the credential', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  t.after(() => { delete process.env.VOUCHR_MASTER_KEY; });
  const db = await openTestDb(t);
  const lan = await createVouchr({ providers: [acme], baseUrl: 'https://bolt.example', db, slackOidc: OIDC });
  await setChannelToolEnabled(new ChannelTools(db), 'T1', 'C1', 'acme', true);

  const routes: Record<string, (req: any, res: any) => Promise<any>> = {};
  lan.mountRoutes({ get: (p: string, h: any) => { routes[p] = h; } });
  assert.ok(routes['/vouchr/oauth/verify'] && routes['/vouchr/oauth/slack'] && routes['/vouchr/oauth/callback']);

  // Post the connect prompt via the middleware, exactly as Bolt would.
  const posts: any[] = [];
  const client = { chat: { postEphemeral: async (a: any) => posts.push(a), postMessage: async (a: any) => posts.push(a) } };
  const ctx: any = {};
  await lan.middleware({ context: ctx, client, event: { channel: 'C1', user: 'U1', team: 'T1' }, next: async () => {} });
  await ctx.vouchr.connect('acme').catch(() => undefined); // ConsentRequiredError: the prompt was posted
  const actions = posts[0].blocks.find((b: any) => b.type === 'actions');
  const promptUrl = new URL(actions.elements[0].url);
  assert.equal(`${promptUrl.origin}${promptUrl.pathname}`, 'https://bolt.example/vouchr/oauth/verify');
  const state = promptUrl.searchParams.get('state')!;

  const fakeRes = () => {
    const res: any = { statusCode: 200, headers: {} as Record<string, string>, body: '' };
    res.status = (c: number) => { res.statusCode = c; return res; };
    res.set = (h: any, v?: string) => {
      if (typeof h === 'string') res.headers[h] = v;
      else Object.assign(res.headers, h);
      return res;
    };
    res.send = (b?: string) => { res.body = b ?? ''; return res; };
    return res;
  };

  const stub = stubFetch(() => ({ status: 200, body: { ok: true, id_token: idToken() } }));
  try {
    // Hop 1: redirect to Slack.
    const r1 = fakeRes();
    await routes['/vouchr/oauth/verify']({ query: { state } }, r1);
    assert.equal(r1.statusCode, 302);
    assert.ok(String(r1.headers.location).startsWith(SLACK_OIDC_AUTHORIZE_URL));
    assert.equal(new URL(r1.headers.location).searchParams.get('redirect_uri'), 'https://bolt.example/vouchr/oauth/slack');

    // Hop 2: matching identity → provider redirect.
    const r2 = fakeRes();
    await routes['/vouchr/oauth/slack']({ query: { code: 'slack-code', state } }, r2);
    assert.equal(r2.statusCode, 302, r2.body);
    assert.ok(String(r2.headers.location).startsWith('https://acme.example/auth'));

    // Provider callback completes; the credential lands for the bound user.
    const r3 = fakeRes();
    await routes['/vouchr/oauth/callback']({ query: { code: 'abc123', state } }, r3);
    assert.equal(r3.statusCode, 200, r3.body);
    const cred = await lan.vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme');
    assert.equal(cred?.accessToken, 'PROVIDER_TOKEN');
  } finally {
    stub.restore();
  }
});

test('#302 Bolt guardrail: a direct callback is refused and writes nothing', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  t.after(() => { delete process.env.VOUCHR_MASTER_KEY; });
  const db = await openTestDb(t);
  const lan = await createVouchr({ providers: [acme], baseUrl: 'https://bolt.example', db, slackOidc: OIDC });
  await setChannelToolEnabled(new ChannelTools(db), 'T1', 'C1', 'acme', true);
  const routes: Record<string, (req: any, res: any) => Promise<any>> = {};
  lan.mountRoutes({ get: (p: string, h: any) => { routes[p] = h; } });
  const posts: any[] = [];
  const client = { chat: { postEphemeral: async (a: any) => posts.push(a), postMessage: async (a: any) => posts.push(a) } };
  const ctx: any = {};
  await lan.middleware({ context: ctx, client, event: { channel: 'C1', user: 'U1', team: 'T1' }, next: async () => {} });
  await ctx.vouchr.connect('acme').catch(() => undefined);
  const actions = posts[0].blocks.find((b: any) => b.type === 'actions');
  const state = new URL(actions.elements[0].url).searchParams.get('state')!;

  const stub = stubFetch(() => ({ status: 200, body: { ok: true, id_token: idToken() } }));
  try {
    const res: any = { statusCode: 200, headers: {}, body: '' };
    res.status = (c: number) => { res.statusCode = c; return res; };
    res.set = (h: any) => { Object.assign(res.headers, typeof h === 'string' ? {} : h); return res; };
    res.send = (b?: string) => { res.body = b ?? ''; return res; };
    await routes['/vouchr/oauth/callback']({ query: { code: 'abc123', state } }, res);
    assert.equal(res.statusCode, 403);
    assert.equal(stub.log.providerTokenCalls, 0);
    assert.equal(await lan.vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme'), null);
  } finally {
    stub.restore();
  }
});
