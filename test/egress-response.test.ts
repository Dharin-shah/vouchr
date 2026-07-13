import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle, ResponseBlockedError, type VouchrEvent } from '../src/core/injector';
import { defineProvider, github, type Provider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';
import { createBroker } from '../src/adapters/http/broker';
import { identityConfig, signIdentity, type IdentityClaims } from './support/identity';

// Structural response constraints at the injection boundary (#110): per-provider egressResponse
// (maxBytes / allowContentTypes / stripHeaders) enforced in the injector AFTER the fetch, plus the
// UNCONDITIONAL set-cookie strip on every provider response. Both doors (Bolt handle + HTTP broker)
// inherit the same guard; a breach throws with the body withheld, an event, and an audit row.

const KEY = randomBytes(32);
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';
const U1: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };

function provider(id: string, egressResponse?: Provider['egressResponse']): Provider {
  return defineProvider({
    id,
    authorizeUrl: 'https://acme.example/auth',
    tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'],
    egressAllow: ['api.acme.example'],
    refresh: 'none',
    pkce: false,
    clientId: 'id',
    clientSecret: 'sec',
    egressResponse,
  });
}

async function makeHandle(t: TestContext, p: Provider) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = userOwner(U1);
  await vault.reference(owner, p.id, { source: 'ext', secretRef: 'arn:secret' });
  const events: VouchrEvent[] = [];
  const handle = new ConnectionHandle(
    p, owner, U1, vault, new Audit(db),
    { ext: async () => SECRET_TOKEN },
    new Map(), (e) => events.push(e),
  );
  return { handle, db, events };
}

function stubFetch(make: () => Response) {
  const real = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => { calls++; return make(); }) as any;
  return { getCalls: () => calls, restore: () => { globalThis.fetch = real; } };
}

/** An endless streaming body that counts pulls and records cancellation — the abort probe.
 *  highWaterMark 0 disables the machinery's construction-time prefill, so a pull count of 0
 *  really means "nothing ever created read demand". */
function endlessBody(chunkBytes = 1024) {
  let pulls = 0;
  let cancelled = false;
  const stream = new ReadableStream({
    pull(c) { pulls++; c.enqueue(new Uint8Array(chunkBytes).fill(65)); },
    cancel() { cancelled = true; },
  }, { highWaterMark: 0 });
  return { stream, getPulls: () => pulls, wasCancelled: () => cancelled };
}

test('response: oversized chunked body (no Content-Length) aborts at the cap — no partial body, stream cancelled, event + audit', async (t) => {
  const probe = endlessBody(1024);
  const up = stubFetch(() => new Response(probe.stream, { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const { handle, db, events } = await makeHandle(t, provider('cap', { maxBytes: 4096 }));
    const err = await handle.fetch('https://api.acme.example/rows').then(() => null, (e: unknown) => e);
    assert.ok(err instanceof ResponseBlockedError, `expected ResponseBlockedError, got ${String(err)}`);
    assert.equal(err.reason, 'size');
    assert.ok(!err.message.includes(SECRET_TOKEN));
    // The stream was aborted just past the cap (never buffered to completion) and cancelled, so the
    // connection is released rather than pinned to an unread body.
    assert.ok(probe.wasCancelled(), 'over-cap stream must be cancelled');
    assert.ok(probe.getPulls() <= 8, `read far past the cap: ${probe.getPulls()} pulls`);

    // Event: no ids, no header values, no body content — provider/host/static reason only.
    const ev = events.find((e) => e.type === 'response_denied');
    assert.deepEqual(ev, { type: 'response_denied', provider: 'cap', host: 'api.acme.example', reason: 'size' });
    for (const e of events) assert.ok(!JSON.stringify(e).includes(SECRET_TOKEN));

    // Audit: same 'denied' action + meta shape as an egress denial, plus the byte count (numbers
    // only — never body content). The inject row for the call that DID go out stays: the denial is
    // on the response, not the request.
    const denied = await db.get(`SELECT user_id, provider, meta FROM audit WHERE action='denied'`);
    assert.ok(denied, 'denied audit row missing');
    assert.equal(denied.user_id, 'U1');
    assert.equal(denied.provider, 'cap');
    const meta = JSON.parse(denied.meta);
    assert.deepEqual(Object.keys(meta).sort(), ['bytes', 'host', 'reason']);
    assert.equal(meta.host, 'api.acme.example');
    assert.equal(meta.reason, 'size');
    assert.ok(meta.bytes > 4096, `audited byte count ${meta.bytes} not past the cap`);
    assert.ok(!denied.meta.includes(SECRET_TOKEN));
    assert.ok(await db.get(`SELECT id FROM audit WHERE action='inject'`), 'the outbound call itself must stay audited');
  } finally {
    up.restore();
  }
});

test('response: a lying-big Content-Length fast-fails before a single body byte is read', async (t) => {
  const probe = endlessBody();
  const up = stubFetch(() => new Response(probe.stream, { status: 200, headers: { 'content-length': '5000' } }));
  try {
    const { handle, db } = await makeHandle(t, provider('cl', { maxBytes: 100 }));
    const err = await handle.fetch('https://api.acme.example/rows').then(() => null, (e: unknown) => e);
    assert.ok(err instanceof ResponseBlockedError);
    assert.equal(err.reason, 'size');
    assert.equal(probe.getPulls(), 0, 'fast-fail must not read the body');
    assert.ok(probe.wasCancelled(), 'the unread body must still be cancelled');
    // The audited byte count is the (range-checked) declared length.
    const meta = JSON.parse((await db.get(`SELECT meta FROM audit WHERE action='denied'`)).meta);
    assert.deepEqual(meta, { host: 'api.acme.example', reason: 'size', bytes: 5000 });
  } finally {
    up.restore();
  }
});

test('response: disallowed content-type denies with the body unread; the header value never enters the audit', async (t) => {
  const probe = endlessBody();
  const up = stubFetch(() => new Response(probe.stream, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } }));
  try {
    const { handle, db, events } = await makeHandle(t, provider('ct', { allowContentTypes: ['application/json'] }));
    const err = await handle.fetch('https://api.acme.example/login').then(() => null, (e: unknown) => e);
    assert.ok(err instanceof ResponseBlockedError);
    assert.equal(err.reason, 'content_type');
    assert.ok(!err.message.includes('text/html'), 'error text must not echo the provider-supplied header');
    assert.equal(probe.getPulls(), 0, 'a content-type deny must not read the body');
    assert.ok(probe.wasCancelled(), 'the unread body must still be cancelled');
    const ev = events.find((e) => e.type === 'response_denied');
    assert.deepEqual(ev, { type: 'response_denied', provider: 'ct', host: 'api.acme.example', reason: 'content_type' });
    // SEC-4: the offending Content-Type is an unvalidated provider string — static reason only.
    const row = await db.get(`SELECT meta FROM audit WHERE action='denied'`);
    assert.deepEqual(JSON.parse(row.meta), { host: 'api.acme.example', reason: 'content_type' });
    assert.ok(!row.meta.includes('html'));
  } finally {
    up.restore();
  }
});

test('response: allowContentTypes matches the bare media type exactly — params/case ignored, prefix lookalikes denied', async (t) => {
  let contentType = 'Application/JSON; charset=UTF-8';
  const up = stubFetch(() => new Response('{"ok":1}', { status: 200, headers: { 'content-type': contentType } }));
  try {
    const { handle } = await makeHandle(t, provider('ct2', { allowContentTypes: ['application/json'] }));
    const res = await handle.fetch('https://api.acme.example/rows');
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: 1 });
    // Exact match on the bare type: 'application/json' must NOT admit 'application/jsonp-evil'.
    contentType = 'application/jsonp-evil';
    const err = await handle.fetch('https://api.acme.example/rows').then(() => null, (e: unknown) => e);
    assert.ok(err instanceof ResponseBlockedError, `expected ResponseBlockedError, got ${String(err)}`);
    assert.equal(err.reason, 'content_type');
  } finally {
    up.restore();
  }
});

test('response: a missing Content-Type header under allowContentTypes denies fail-closed', async (t) => {
  // A BufferSource body implies no content-type (a string body would auto-set text/plain).
  const up = stubFetch(() => new Response(new TextEncoder().encode('{"ok":1}'), { status: 200 }));
  try {
    const { handle } = await makeHandle(t, provider('noct', { allowContentTypes: ['application/json'] }));
    const err = await handle.fetch('https://api.acme.example/rows').then(() => null, (e: unknown) => e);
    assert.ok(err instanceof ResponseBlockedError, `expected ResponseBlockedError, got ${String(err)}`);
    assert.equal(err.reason, 'content_type');
  } finally {
    up.restore();
  }
});

test('response: a body exactly AT maxBytes passes — the cap boundary is >, not >=', async (t) => {
  const BODY = 'x'.repeat(16);
  const up = stubFetch(() => new Response(BODY, { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const { handle, events } = await makeHandle(t, provider('atcap', { maxBytes: 16 }));
    const res = await handle.fetch('https://api.acme.example/rows');
    assert.equal(res.status, 200);
    assert.equal(await res.text(), BODY);
    assert.ok(!events.some((e) => e.type === 'response_denied'));
  } finally {
    up.restore();
  }
});

test('response: a 204 with no Content-Type passes allowContentTypes — bodyless, nothing to constrain; set-cookie still stripped', async (t) => {
  const up = stubFetch(() => new Response(null, { status: 204, headers: { 'set-cookie': 'sid=1' } }));
  try {
    const { handle, db, events } = await makeHandle(t, provider('nc', { allowContentTypes: ['application/json'] }));
    const res = await handle.fetch('https://api.acme.example/rows', { method: 'GET' });
    assert.equal(res.status, 204);
    assert.equal(res.headers.get('set-cookie'), null, 'strip must still apply to bodyless responses');
    assert.ok(!events.some((e) => e.type === 'response_denied'));
    assert.equal(Number((await db.get(`SELECT count(*) AS n FROM audit WHERE action='denied'`)).n), 0);
  } finally {
    up.restore();
  }
});

test('response: a HEAD response (null body) passes allowContentTypes', async (t) => {
  const up = stubFetch(() => new Response(null, { status: 200, headers: { 'set-cookie': 'sid=1', etag: '"v1"' } }));
  try {
    const { handle, events } = await makeHandle(t, provider('hd', { allowContentTypes: ['application/json'] }));
    const res = await handle.fetch('https://api.acme.example/rows', { method: 'HEAD' });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('etag'), '"v1"');
    assert.equal(res.headers.get('set-cookie'), null);
    assert.ok(!events.some((e) => e.type === 'response_denied'));
  } finally {
    up.restore();
  }
});

test('response: a 204 under maxBytes passes — the null-body cap path never touches a reader', async (t) => {
  const up = stubFetch(() => new Response(null, { status: 204, headers: { 'set-cookie': 'sid=1' } }));
  try {
    const { handle, events } = await makeHandle(t, provider('nb', { maxBytes: 8 }));
    const res = await handle.fetch('https://api.acme.example/rows');
    assert.equal(res.status, 204);
    assert.equal(res.headers.get('set-cookie'), null);
    assert.ok(!events.some((e) => e.type === 'response_denied'));
  } finally {
    up.restore();
  }
});

test('response: .url survives reconstruction (the set-cookie strip / cap-buffer path)', async (t) => {
  const up = stubFetch(() => {
    const r = new Response('{}', { status: 200, headers: { 'set-cookie': 'sid=1', 'content-type': 'application/json' } });
    // Constructed Responses carry url:''; simulate the url a real undici fetch would set.
    Object.defineProperty(r, 'url', { value: 'https://api.acme.example/rows' });
    return r;
  });
  try {
    const { handle } = await makeHandle(t, provider('urlkeep'));
    const res = await handle.fetch('https://api.acme.example/rows');
    assert.equal(res.headers.get('set-cookie'), null, 'reconstruction must actually have happened');
    assert.equal(res.url, 'https://api.acme.example/rows');
  } finally {
    up.restore();
  }
});

test('response: set-cookie is stripped on a NON-opt-in provider — unconditional hardening, body intact', async (t) => {
  const up = stubFetch(() => new Response('{"a":1}', {
    status: 200,
    headers: { 'set-cookie': 'sid=SESSIONSECRET; HttpOnly', 'content-type': 'application/json', 'x-keep': 'yes' },
  }));
  try {
    const { handle, db, events } = await makeHandle(t, provider('plain')); // no egressResponse knob
    const res = await handle.fetch('https://api.acme.example/rows');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('set-cookie'), null, 'set-cookie must never reach the caller');
    assert.equal(res.headers.get('x-keep'), 'yes', 'other headers pass through');
    assert.equal(res.headers.get('content-type'), 'application/json');
    assert.deepEqual(await res.json(), { a: 1 }); // .json() still works on the reconstructed Response
    // Stripping is hardening, not a denial: no event, no denied audit row.
    assert.ok(!events.some((e) => e.type === 'response_denied'));
    assert.equal(Number((await db.get(`SELECT count(*) AS n FROM audit WHERE action='denied'`)).n), 0);
  } finally {
    up.restore();
  }
});

test('response: set-cookie is stripped from a 3xx too (redirects are manual — the 3xx object reaches the caller)', async (t) => {
  const up = stubFetch(() => new Response(null, {
    status: 302,
    headers: { location: 'https://api.acme.example/next', 'set-cookie': 'sid=abc' },
  }));
  try {
    const { handle } = await makeHandle(t, provider('plain3xx'));
    const res = await handle.fetch('https://api.acme.example/old');
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('set-cookie'), null);
    assert.equal(res.headers.get('location'), 'https://api.acme.example/next', 'location survives for the manual-redirect caller');
  } finally {
    up.restore();
  }
});

test('response: opt-in stripHeaders are removed (case-insensitive) alongside set-cookie; the rest is byte-identical', async (t) => {
  const BODY = '{"rows":[1,2,3],"cursor":"abc"}';
  const up = stubFetch(() => new Response(BODY, {
    status: 200,
    headers: {
      'set-cookie': 'sid=1',
      'X-Internal-Trace': 'trace-123',
      'content-type': 'application/json',
      etag: '"v1"',
    },
  }));
  try {
    const { handle } = await makeHandle(t, provider('strip', { stripHeaders: ['x-internal-trace'] }));
    const res = await handle.fetch('https://api.acme.example/rows');
    assert.equal(res.headers.get('set-cookie'), null);
    assert.equal(res.headers.get('x-internal-trace'), null);
    assert.equal(res.headers.get('etag'), '"v1"');
    assert.equal(await res.text(), BODY, 'body must pass through byte-identical');
  } finally {
    up.restore();
  }
});

test('response: a compliant response under maxBytes+allowContentTypes passes; .json() works on the buffered path', async (t) => {
  const up = stubFetch(() => new Response('{"rows":[1,2,3]}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const { handle, events } = await makeHandle(t, provider('ok', { maxBytes: 1024, allowContentTypes: ['application/json'] }));
    const res = await handle.fetch('https://api.acme.example/rows');
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { rows: [1, 2, 3] });
    assert.ok(!events.some((e) => e.type === 'response_denied'));
  } finally {
    up.restore();
  }
});

test('response: no knob + no set-cookie preserves the response contract while retaining deadline cleanup', async (t) => {
  let original!: Response;
  const up = stubFetch(() => {
    original = new Response('{"a":1}', { status: 200, headers: { 'content-type': 'application/json' } });
    return original;
  });
  try {
    const { handle } = await makeHandle(t, provider('untouched'));
    const res = await handle.fetch('https://api.acme.example/rows');
    // The injector may wrap the body so its finite deadline remains active until the caller consumes
    // or cancels it. Object identity is not part of the fetch contract; status, headers, URL, and bytes
    // are. Keep this regression focused on those observable semantics.
    assert.equal(res.status, original.status);
    assert.equal(res.statusText, original.statusText);
    assert.equal(res.headers.get('content-type'), original.headers.get('content-type'));
    assert.equal(res.url, original.url);
    assert.equal(await res.text(), '{"a":1}');
  } finally {
    up.restore();
  }
});

test('response: defineProvider rejects bad maxBytes, bad strip-header names, and empty allowContentTypes', () => {
  // A NaN cap would silently DISABLE the guard (NaN comparisons are all false) — the misconfig that
  // reads as protection but isn't; a bad header name would throw per-request, after the token was spent.
  for (const egressResponse of [{ maxBytes: 0 }, { maxBytes: -5 }, { maxBytes: Number.NaN }]) {
    assert.throws(() => provider('bad', egressResponse), /invalid egressResponse\.maxBytes/);
  }
  assert.throws(() => provider('bad', { stripHeaders: ['bad header\n'] }), /invalid egressResponse\.stripHeaders/);
  // Empty array = silent deny-all; empty entry = a never-matching type. Both are misconfig, not policy.
  for (const allowContentTypes of [[], [''], ['application/json', '  ']]) {
    assert.throws(() => provider('bad', { allowContentTypes }), /invalid egressResponse\.allowContentTypes/);
  }
});

test('response: built-in provider factories pass through egressResponse', () => {
  const p = github({ clientId: 'id', clientSecret: 'sec', egressResponse: { maxBytes: 1024, allowContentTypes: ['application/json'] } });
  assert.deepEqual(p.egressResponse, { maxBytes: 1024, allowContentTypes: ['application/json'] });
});

// ── broker surface: the wire path inherits the SAME injector guard ───────────

function postJson(port: number, path: string, body: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

test('broker: provider-level size/content-type breaches deny on the wire (413/502), body never relayed, audit written', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  // Caps far below the broker's own #26 defaults, so a deny here proves the INJECTOR gate fired.
  const capped = provider('acme', { maxBytes: 8 });
  const typed = provider('acmect', { allowContentTypes: ['application/json'] });
  for (const id of ['acme', 'acmect']) {
    await vault.upsert(userOwner(U1), id, {
      accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  const server = createBroker({ providers: [capped, typed], vault, audit, db, identitySecret: identityConfig('broker-secret') });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  const realFetch = globalThis.fetch;
  const OVERSIZED = '{"data":"THIS_BODY_MUST_NEVER_LEAK"}';
  try {
    const call = (providerId: string) => postJson(port, '/v1/fetch', {
      handle: { provider: providerId, owner: 'user' },
      identityToken: signIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() } satisfies IdentityClaims, 'broker-secret'),
      method: 'GET', path: '/rows',
    });

    globalThis.fetch = (async () => new Response(OVERSIZED, { status: 200, headers: { 'content-type': 'application/json' } })) as any;
    const big = await call('acme');
    assert.equal(big.status, 413);
    assert.equal(big.json.error, 'response blocked'); // the injector's static message, not the broker's own #26 gate
    assert.ok(!JSON.stringify(big.json).includes('MUST_NEVER_LEAK'), 'over-cap body leaked onto the wire');
    assert.ok(!JSON.stringify(big.json).includes(SECRET_TOKEN));

    globalThis.fetch = (async () => new Response('<html>login</html>', { status: 200, headers: { 'content-type': 'text/html' } })) as any;
    const wrong = await call('acmect');
    assert.equal(wrong.status, 502);
    assert.equal(wrong.json.error, 'response blocked');
    assert.ok(!JSON.stringify(wrong.json).includes('login'), 'disallowed body leaked onto the wire');

    const rows = await db.all(`SELECT provider, meta FROM audit WHERE action='denied' ORDER BY at`);
    assert.equal(rows.length, 2, 'each wire deny must write its audit row');
    assert.equal(JSON.parse(rows[0].meta).reason, 'size');
    assert.equal(JSON.parse(rows[1].meta).reason, 'content_type');
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});

test('broker: a compliant response with set-cookie relays the body with the cookie stripped upstream of the wire', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const p = provider('acme');
  await vault.upsert(userOwner(U1), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [p], vault, audit: new Audit(db), db, identitySecret: identityConfig('broker-secret') });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{"ok":true}', {
    status: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'sid=UPSTREAMCOOKIE' },
  })) as any;
  try {
    const r = await postJson(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' },
      identityToken: signIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() } satisfies IdentityClaims, 'broker-secret'),
      method: 'GET', path: '/rows',
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.body, '{"ok":true}');
    assert.ok(!JSON.stringify(r.json).includes('UPSTREAMCOOKIE'), 'set-cookie leaked through the broker');
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});
