import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createVouchr, defineProvider, github, ConsentRequiredError } from '../src';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle } from '../src/core/injector';
import { userOwner } from '../src/core/owner';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';

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

test('integration: middleware → connect prompt → OAuth callback → vault → leak-safe fetch', async (t) => {
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
    const lan = await createVouchr({ providers: [provider], baseUrl: mock.base, db: await openTestDb(t) });
    // Deny-by-default: opt the provider into the channel this test exercises.
    await setChannelToolEnabled(new ChannelTools(lan.db), 'T1', 'C1', provider.id, true);

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

    assert.match(posts[0].text, /Connecting grants the agent/i);
    assert.match(posts[0].text, /read/);
    assert.match(posts[0].text, /never shown to the agent/i);

    // Extract the single-use state from the Connect button URL.
    const actions = posts[0].blocks.find((b: any) => b.type === 'actions');
    const url = new URL(actions.elements[0].url);
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

test('integration: maximum-valid OAuth scopes still produce one bounded connect prompt', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const scopes = Array.from({ length: 48 }, (_, i) => `scope-${i}`);
  const provider = defineProvider({
    id: 'max-scopes',
    authorizeUrl: 'https://provider.test/authorize',
    tokenUrl: 'https://provider.test/token',
    scopesDefault: scopes,
    scopeDescriptions: Object.fromEntries(scopes.map((scope) => [scope, '&'.repeat(512)])),
    egressAllow: ['api.provider.test'],
    refresh: 'none',
    pkce: true,
    clientId: 'cid',
    clientSecret: 'csec',
  });
  const lan = await createVouchr({ providers: [provider], baseUrl: 'https://vouchr.test', db: await openTestDb(t) });
  // Deny-by-default: opt the provider into the channel this test exercises.
  await setChannelToolEnabled(new ChannelTools(lan.db), 'T1', 'C1', provider.id, true);
  const posts: any[] = [];
  const client = {
    chat: {
      postEphemeral: async (args: any) => { posts.push(args); },
      postMessage: async (args: any) => { posts.push(args); },
    },
  };
  const context: any = {};
  await lan.middleware({
    context,
    client,
    event: { channel: 'C1', user: 'U1', team: 'T1' },
    next: async () => {},
  });

  await assert.rejects(() => context.vouchr.connect('max-scopes'), ConsentRequiredError);
  assert.equal(posts.length, 1);
  assert.equal(posts[0].text, undefined, 'over-40k top-level text must be omitted so Slack synthesizes it');
  assert.ok(posts[0].blocks.length <= 50);
  for (const block of posts[0].blocks) {
    if (block?.type === 'section') assert.ok(block.text.text.length <= 3_000);
  }
  const renderedScopeRows = posts[0].blocks
    .filter((block: any) => block?.type === 'section')
    .flatMap((block: any) => block.text.text.split('\n'))
    .filter((line: string) => line.startsWith('• '));
  assert.equal(renderedScopeRows.length, scopes.length, 'every configured scope needs one consent row');
  assert.ok(renderedScopeRows.every((line: string) => line === `• ${'&amp;'.repeat(512)}`));
});

test('integration: OAuth callback error is served as inert text/plain, not text/html (#177)', async (t) => {
  // A hostile provider can redirect the victim back with ?error=<markup> holding a valid in-flight
  // state. Core must not reflect that provider-controlled value at all; text/plain + nosniff remains
  // defense in depth for every static callback failure.
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const mock = await startMockProvider();
  try {
    const provider = defineProvider({
      id: 'mock', authorizeUrl: `${mock.base}/authorize`, tokenUrl: `${mock.base}/token`,
      scopesDefault: ['read'], egressAllow: ['127.0.0.1'], refresh: 'none', pkce: true,
      clientId: 'cid', clientSecret: 'csec',
    });
    const lan = await createVouchr({ providers: [provider], baseUrl: mock.base, db: await openTestDb(t) });
    // Deny-by-default: opt the provider into the channel this test exercises.
    await setChannelToolEnabled(new ChannelTools(lan.db), 'T1', 'C1', provider.id, true);
    let callback: any;
    lan.mountRoutes({ get: (_p: string, h: any) => (callback = h) });

    // Drive one consent to mint a real, valid state (the error path consumes it, reaching the echo).
    const posts: any[] = [];
    const client = { chat: { postEphemeral: async (a: any) => posts.push(a), postMessage: async (a: any) => posts.push(a) } };
    const ctx: any = {};
    await lan.middleware({ context: ctx, client, event: { channel: 'C1', user: 'U1', team: 'T1' }, next: async () => {} });
    await assert.rejects(() => ctx.vouchr.connect('mock'), ConsentRequiredError);
    const state = new URL(posts[0].blocks.find((b: any) => b.type === 'actions').elements[0].url).searchParams.get('state')!;

    const evil = '<img src=x onerror=alert(1)>';
    const res = fakeRes();
    await callback({ query: { state, error: evil } }, res);

    // An unknown, non-access_denied error value is a permanent provider-side failure (500 +
    // fix_configuration), not a user denial — and regardless of classification it must be served
    // inert and never reflected.
    assert.equal(res.statusCode, 500);
    assert.match(String(res.headers['content-type']), /text\/plain/); // never text/html
    assert.equal(res.headers['x-content-type-options'], 'nosniff'); // and no content sniffing back to html
    assert.equal(res.body, 'The provider rejected this authorization. Ask an administrator to check the Vouchr OAuth configuration.');
    assert.ok(!res.body.includes(evil), 'provider-controlled error text must never reach output');
  } finally {
    await mock.close();
  }
});

test('integration: handle.fetch does not follow a redirect off the allowlisted path', async (t) => {
  const mock = await startMockProvider();
  try {
    const db = await openTestDb(t);
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

test('integration: Slack deactivation auto-revokes the user\'s connections (user_change)', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [github({ clientId: 'a', clientSecret: 'b' })],
    baseUrl: 'http://127.0.0.1:1',
    db: await openTestDb(t),
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

test('integration: /vouchr status lists connections and disconnect revokes', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [github({ clientId: 'a', clientSecret: 'b' })],
    baseUrl: 'http://127.0.0.1:1',
    db: await openTestDb(t),
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

test('integration: install() wires middleware, routes, commands, offboarding in one call', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [github({ clientId: 'a', clientSecret: 'b' })],
    baseUrl: 'http://127.0.0.1:1',
    db: await openTestDb(t),
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
