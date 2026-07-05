import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createVouchr, defineProvider, github, ConsentRequiredError } from '../src';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle } from '../src/core/injector';
import { userOwner } from '../src/core/owner';

// A real local OAuth provider + API, so the flow is exercised over HTTP end to end.
function startMockProvider(): Promise<{
  base: string;
  reqs: { url: string; method: string; body: string; auth?: string }[];
  close: () => Promise<void>;
}> {
  const reqs: { url: string; method: string; body: string; auth?: string }[] = [];
  const server: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      reqs.push({
        url: req.url ?? '',
        method: req.method ?? '',
        body,
        auth: req.headers.authorization as string | undefined,
      });
      if (req.url === '/token') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ access_token: 'AT123', token_type: 'bearer', scope: 'read' }));
      } else if ((req.url ?? '').startsWith('/api/me')) {
        const ok = req.headers.authorization === 'Bearer AT123';
        res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ login: 'octocat' }));
      } else if (req.url === '/redirect') {
        res.writeHead(302, { location: '/api/me' });
        res.end();
      } else {
        res.writeHead(404);
        res.end();
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as any).port;
      resolve({
        base: `http://127.0.0.1:${port}`,
        reqs,
        close: () => new Promise((r) => server.close(() => r(undefined))),
      });
    });
  });
}

function fakeRes() {
  const r: any = { statusCode: 200, body: '', headers: {} };
  r.status = (c: number) => { r.statusCode = c; return r; };
  r.send = (b: any) => { r.body = b; return r; };
  r.set = (k: any, v?: any) => { if (typeof k === 'object') Object.assign(r.headers, k); else r.headers[k] = v; return r; };
  return r;
}

test('integration: middleware → connect prompt → OAuth callback → vault → leak-safe fetch', async () => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const mock = await startMockProvider();
  try {
    const provider = defineProvider({
      id: 'mock',
      authorizeUrl: `${mock.base}/authorize`,
      tokenUrl: `${mock.base}/token`,
      scopesDefault: ['read'],
      egressAllow: ['127.0.0.1'],
      refresh: 'none',
      pkce: true,
      clientId: 'cid',
      clientSecret: 'csec',
      accountProbe: async (t) => {
        const r = await fetch(`${mock.base}/api/me`, { headers: { Authorization: `Bearer ${t}` } });
        return r.ok ? (await r.json()).login : null;
      },
    });
    const lan = await createVouchr({ providers: [provider], baseUrl: mock.base, dbPath: ':memory:' });

    // Capture the OAuth callback handler that mountRoutes registers on the router.
    let callback: any;
    lan.mountRoutes({ get: (_p: string, h: any) => (callback = h) });

    // Fake Slack client to capture the ephemeral "Connect" prompt.
    const posts: any[] = [];
    const client = { chat: { postEphemeral: async (a: any) => posts.push(a), postMessage: async (a: any) => posts.push(a) } };

    // 1. Run the middleware as Bolt would, then call connect(), should prompt + throw.
    const ctx: any = {};
    await lan.middleware({
      context: ctx,
      client,
      event: { channel: 'C1', user: 'U1', team: 'T1' },
      next: async () => {},
    });
    await assert.rejects(() => ctx.vouchr.connect('mock'), ConsentRequiredError);

    // Extract the single-use state from the Connect button URL.
    const url = new URL(posts[0].blocks[1].elements[0].url);
    const state = url.searchParams.get('state')!;
    assert.ok(state && url.searchParams.get('code_challenge')); // PKCE present

    // 2. Drive the OAuth callback (as the browser redirect would).
    const res = fakeRes();
    await callback({ query: { code: 'AUTHCODE', state } }, res);
    assert.equal(res.statusCode, 200);
    assert.match(res.body, /connected/i);

    // The token endpoint was called with the auth code; token never appears in our response.
    const tokenReq = mock.reqs.find((r) => r.url === '/token')!;
    assert.match(tokenReq.body, /code=AUTHCODE/);
    assert.ok(!res.body.includes('AT123'));

    // 3. Now connect() returns a handle; fetch injects the token at the HTTP boundary.
    const handle = await ctx.vouchr.connect('mock');
    assert.equal(await handle.account(), 'octocat');
    assert.ok(!('accessToken' in handle)); // the handle exposes no token field
    const apiRes = await handle.fetch(`${mock.base}/api/me`);
    assert.equal(apiRes.status, 200);
    const apiReq = mock.reqs.find((r) => (r.url ?? '').startsWith('/api/me'))!;
    assert.equal(apiReq.auth, 'Bearer AT123'); // injected, though our code never saw it
  } finally {
    await mock.close();
  }
});

test('integration: handle.fetch does not follow a redirect off the allowlisted path', async () => {
  const mock = await startMockProvider();
  try {
    const db = await openDb({ dbPath: ':memory:' });
    const vault = new Vault(db, randomBytes(32));
    const audit = new Audit(db);
    const id = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
    await vault.upsert(userOwner(id), 'mock', {
      accessToken: 'AT123',
      refreshToken: null,
      scopes: '',
      expiresAt: null,
      externalAccount: null,
    });
    const provider = defineProvider({
      id: 'mock',
      authorizeUrl: `${mock.base}/a`,
      tokenUrl: `${mock.base}/t`,
      scopesDefault: ['x'],
      egressAllow: ['127.0.0.1'],
      refresh: 'none',
      pkce: false,
      clientId: 'c',
      clientSecret: 's',
    });
    const handle = new ConnectionHandle(provider, userOwner(id), id, vault, audit);
    await handle.fetch(`${mock.base}/redirect`); // 302 → /api/me
    assert.ok(mock.reqs.some((r) => r.url === '/redirect'));
    assert.ok(!mock.reqs.some((r) => (r.url ?? '').startsWith('/api/me'))); // NOT followed
  } finally {
    await mock.close();
  }
});

test('integration: Slack deactivation auto-revokes the user\'s connections (user_change)', async () => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [github({ clientId: 'a', clientSecret: 'b' })],
    baseUrl: 'http://127.0.0.1:1',
    dbPath: ':memory:',
    ttl: {}, // disable expiry so the seeded rows survive
  });
  let handler: any;
  lan.registerOffboarding({ event: (_n: string, h: any) => (handler = h) });

  const id = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const seed = { accessToken: 't', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null };
  await lan.vault.upsert(userOwner(id), 'github', seed);
  await lan.vault.upsert(userOwner({ ...id, userId: 'U2' }), 'github', seed);

  // A non-deactivation user_change is ignored.
  await handler({ event: { user: { id: 'U1', team_id: 'T1', deleted: false } } });
  assert.equal((await lan.vault.listForUser(id)).length, 1);

  // Deactivation cleans up just that user; others untouched.
  await handler({ event: { user: { id: 'U1', team_id: 'T1', deleted: true } } });
  assert.equal((await lan.vault.listForUser(id)).length, 0);
  assert.equal((await lan.vault.listForUser({ ...id, userId: 'U2' })).length, 1);
});

test('integration: /vouchr status lists connections and disconnect revokes', async () => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [github({ clientId: 'a', clientSecret: 'b' })],
    baseUrl: 'http://127.0.0.1:1',
    dbPath: ':memory:',
  });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });

  const id = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  await lan.vault.upsert(userOwner(id), 'github', {
    accessToken: 't',
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: 'octocat',
  });

  const out: string[] = [];
  const respond = async (m: any) => out.push(typeof m === 'string' ? m : JSON.stringify(m));

  await handler({ command: { team_id: 'T1', user_id: 'U1', text: 'status' }, ack: async () => {}, respond });
  assert.match(out[0], /github/);
  assert.match(out[0], /octocat/);

  await handler({ command: { team_id: 'T1', user_id: 'U1', text: 'disconnect github' }, ack: async () => {}, respond });
  assert.match(out[1], /Disconnected/);
  assert.equal((await lan.vault.listForUser(id)).length, 0); // revoked
});

test('integration: install() wires middleware, routes, commands, offboarding in one call', async () => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [github({ clientId: 'a', clientSecret: 'b' })],
    baseUrl: 'http://127.0.0.1:1',
    dbPath: ':memory:',
  });

  const wired = { middleware: false, route: false, command: false, event: false };
  const app = {
    use: (_m: any) => { wired.middleware = true; },
    command: (_n: string, _h: any) => { wired.command = true; },
    view: () => undefined,
    action: () => undefined,
    event: (_n: string, _h: any) => { wired.event = true; },
  };
  const receiver = { router: { get: (_p: string, _h: any) => { wired.route = true; } } };

  // sweepIntervalMs: 0 → no background timer to leak into the test run.
  const handle = lan.install(app, receiver, { sweepIntervalMs: 0 });
  assert.deepEqual(wired, { middleware: true, route: true, command: true, event: true });
  assert.equal(typeof handle.stop, 'function');
  handle.stop(); // idempotent no-op when the timer is disabled
});
