import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle, type VouchrEvent } from '../src/core/injector';
import { github, defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';
import { TokenEndpointError } from '../src/core/tokens';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);
const TOKEN = 'tok_secret_xyz'; // the value that must never appear in any event

// Build a handle wired to a sink that records every event, with a vaulted github cred.
async function handleWithSink(t: TestContext, sink: (e: VouchrEvent) => void) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const provider = github({ clientId: 'cid', clientSecret: 'csec' }); // egressAllow: api.github.com
  await vault.upsert(O1, 'github', { accessToken: TOKEN, refreshToken: null, scopes: 'repo', expiresAt: null, externalAccount: null });
  return new ConnectionHandle(provider, O1, ID, vault, audit, {}, new Map(), sink);
}

test('observability: injected fires with host/status/ownerKind on a successful fetch', async (t) => {
  const events: VouchrEvent[] = [];
  const handle = await handleWithSink(t, (e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    const res = await handle.fetch('https://api.github.com/user');
    assert.equal(res.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(events.length, 1);
  const ev = events[0] as Extract<VouchrEvent, { type: 'injected' }>;
  assert.equal(ev.type, 'injected');
  assert.equal(ev.provider, 'github');
  assert.equal(ev.host, 'api.github.com');
  assert.equal(ev.status, 200);
  assert.equal(ev.ownerKind, 'user');
  // fetch latency: a finite, non-negative wall-clock measurement
  assert.equal(typeof ev.ms, 'number');
  assert.ok(Number.isFinite(ev.ms) && ev.ms >= 0, `bad latency: ${ev.ms}`);
});

test('observability: egress_denied fires AND the fetch still throws for a disallowed host', async (t) => {
  const events: VouchrEvent[] = [];
  const handle = await handleWithSink(t, (e) => events.push(e));
  await assert.rejects(() => handle.fetch('https://evil.example.com/steal'), /Egress blocked/);
  assert.deepEqual(events, [{ type: 'egress_denied', provider: 'github', host: 'evil.example.com', reason: 'host' }]);
});

test('observability: egress_denied carries the per-gate reason (host/method/path/validator)', async (t) => {
  const TICKET = randomBytes(32); // a secret that must never reach an event
  // A provider with all four finer egress gates wired, so each denial site is reachable.
  const provider = {
    ...github({ clientId: 'cid', clientSecret: 'csec' }),
    egressPaths: ['/user'],
    egressMethods: ['GET'],
    egressValidate: (u: URL) => !u.searchParams.has('x'),
  };
  async function handleFor(p: any) {
    const db = await openTestDb(t);
    const vault = new Vault(db, KEY);
    const audit = new Audit(db);
    await vault.upsert(O1, 'github', { accessToken: TOKEN, refreshToken: null, scopes: 'repo', expiresAt: null, externalAccount: null });
    const seen: VouchrEvent[] = [];
    return { handle: new ConnectionHandle(p, O1, ID, vault, audit, {}, new Map(), (e) => seen.push(e)), seen };
  }
  const cases: [string, RequestInit, 'host' | 'method' | 'path' | 'validator'][] = [
    [`https://${TICKET.toString('hex')}@api.github.com/user`, {}, 'host'], // URL creds
    ['https://nope.example.com/user', {}, 'host'],                          // not allowlisted
    ['http://api.github.com/user', {}, 'host'],                             // not https
    ['https://api.github.com/secrets', {}, 'path'],                         // path gate
    ['https://api.github.com/user', { method: 'DELETE' }, 'method'],        // method gate
    ['https://api.github.com/user?x=1', {}, 'validator'],                   // validator gate
  ];
  for (const [url, init, reason] of cases) {
    const { handle, seen } = await handleFor(provider);
    await assert.rejects(() => handle.fetch(url, init), /Egress blocked/);
    assert.equal(seen.length, 1, `expected one event for ${url}`);
    const e = seen[0] as Extract<VouchrEvent, { type: 'egress_denied' }>;
    assert.equal(e.type, 'egress_denied');
    assert.equal(e.reason, reason, `wrong reason for ${url}`);
    // the URL-cred secret must never appear in the event
    assert.ok(!JSON.stringify(e).includes(TICKET.toString('hex')), 'egress event leaked URL secret');
  }
});

test('observability: kms_decrypt counts real DEK unwraps and never leaks the secret', async (t) => {
  const events: VouchrEvent[] = [];
  const db = await openTestDb(t);
  // A fake KMS: XOR-wrap the DEK so unwrap is a real (counted) call but no SDK is needed.
  const KEK = randomBytes(32);
  const xor = (b: Buffer) => Buffer.from(b.map((x, i) => x ^ KEK[i % KEK.length]));
  const envelope = { wrapDataKey: async (d: Buffer) => xor(d), unwrapDataKey: async (w: Buffer) => xor(w) };
  const vault = new Vault(db, KEY, {}, envelope);
  const audit = new Audit(db);
  const provider = github({ clientId: 'cid', clientSecret: 'csec' });
  // refreshToken present too, so the read decrypts TWO secrets => two unwraps.
  await vault.upsert(O1, 'github', { accessToken: TOKEN, refreshToken: 'refresh_secret_abc', scopes: 'repo', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(provider, O1, ID, vault, audit, {}, new Map(), (e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    await handle.fetch('https://api.github.com/user');
  } finally {
    globalThis.fetch = realFetch;
  }
  const kms = events.find((e) => e.type === 'kms_decrypt') as Extract<VouchrEvent, { type: 'kms_decrypt' }> | undefined;
  assert.ok(kms, 'kms_decrypt event not emitted under envelope encryption');
  assert.equal(kms.count, 2); // access + refresh token both unwrapped
  for (const e of events) assert.ok(!JSON.stringify(e).includes(TOKEN), 'event leaked token');
});

test('observability: no kms_decrypt event on the legacy (non-envelope) path', async (t) => {
  const events: VouchrEvent[] = [];
  const handle = await handleWithSink(t, (e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    await handle.fetch('https://api.github.com/user');
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.ok(!events.some((e) => e.type === 'kms_decrypt'), 'legacy path must make no KMS call');
});

test('observability: no event ever carries a token, user id, or team id', async (t) => {
  const events: VouchrEvent[] = [];
  const handle = await handleWithSink(t, (e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    await handle.fetch('https://api.github.com/user'); // injected
    await assert.rejects(() => handle.fetch('https://evil.example.com/x')); // egress_denied
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.ok(events.length >= 2);
  for (const e of events) {
    const blob = JSON.stringify(e);
    assert.ok(!blob.includes(TOKEN), `event leaked token: ${blob}`);
    assert.ok(!blob.includes(ID.userId), `event leaked user id: ${blob}`);
    assert.ok(!blob.includes(ID.teamId), `event leaked team id: ${blob}`);
  }
});

test('observability: refreshed carries a refresh-latency ms on a 401-triggered refresh', async (t) => {
  const events: VouchrEvent[] = [];
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const acme = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
    clientId: 'c', clientSecret: 's',
  });
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(acme, O1, ID, vault, audit, {}, new Map(), (e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url).includes('/token')) {
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const auth = new Headers(init?.headers).get('authorization');
    if (auth === 'Bearer old') return new Response('expired', { status: 401 });
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const res = await handle.fetch('https://api.acme.example/data');
    assert.equal(res.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
  const r = events.find((e) => e.type === 'refreshed') as Extract<VouchrEvent, { type: 'refreshed' }> | undefined;
  assert.ok(r, 'refreshed event not emitted');
  assert.equal(typeof r.ms, 'number');
  assert.ok(Number.isFinite(r.ms) && r.ms >= 0, `bad refresh latency: ${r.ms}`);
});

test('observability: a throwing refresh cancels the discarded 401 body and still propagates the error (#168)', async (t) => {
  const events: VouchrEvent[] = [];
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const acme = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
    clientId: 'c', clientSecret: 's',
  });
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(acme, O1, ID, vault, new Audit(db), {}, new Map(), (e) => events.push(e));
  let cancelled = false;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: any) => {
    if (String(url).includes('/token')) throw new Error('token endpoint down');
    // The abandoned 401 whose unread body would pin the socket until GC if not drained.
    const body = new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(64)); }, cancel() { cancelled = true; } });
    return new Response(body, { status: 401 });
  }) as any;
  try {
    await assert.rejects(
      () => handle.fetch('https://api.acme.example/data'),
      (error: unknown) => error instanceof TokenEndpointError
        && error.kind === 'transient'
        && error.message === 'Token endpoint request failed',
    );
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.ok(cancelled, 'discarded 401 body must be cancelled when the refresh throws');
  // The no-secret failure signal still fires against the token endpoint host.
  const err = events.find((e) => e.type === 'egress_error') as Extract<VouchrEvent, { type: 'egress_error' }> | undefined;
  assert.ok(err, 'egress_error must fire on a refresh throw');
  assert.equal(err.reason, 'refresh_failed');
});

test('observability: the discarded 401 body is cancelled on a successful refresh-retry too', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const acme = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
    clientId: 'c', clientSecret: 's',
  });
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(acme, O1, ID, vault, new Audit(db), {}, new Map(), () => {});
  let cancelled = false;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url).includes('/token')) {
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const auth = new Headers(init?.headers).get('authorization');
    if (auth === 'Bearer old') {
      const body = new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(64)); }, cancel() { cancelled = true; } });
      return new Response(body, { status: 401 });
    }
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const res = await handle.fetch('https://api.acme.example/data');
    assert.equal(res.status, 200); // retried with the refreshed token
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.ok(cancelled, 'discarded 401 body must be cancelled on the success path');
});

test('observability: kms_decrypt also counts the refresh-path reads on a 401-triggered refresh', async (t) => {
  const events: VouchrEvent[] = [];
  const db = await openTestDb(t);
  const KEK = randomBytes(32);
  const xor = (b: Buffer) => Buffer.from(b.map((x, i) => x ^ KEK[i % KEK.length]));
  let unwraps = 0;
  const envelope = { wrapDataKey: async (d: Buffer) => xor(d), unwrapDataKey: async (w: Buffer) => { unwraps++; return xor(w); } };
  const vault = new Vault(db, KEY, {}, envelope);
  const audit = new Audit(db);
  const acme = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
    clientId: 'c', clientSecret: 's',
  });
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(acme, O1, ID, vault, audit, {}, new Map(), (e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url).includes('/token')) {
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const auth = new Headers(init?.headers).get('authorization');
    if (auth === 'Bearer old') return new Response('expired', { status: 401 });
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const res = await handle.fetch('https://api.acme.example/data');
    assert.equal(res.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
  // Real DEK unwraps that actually happened: 2 (primary fetch read) + 4 (the two doRefresh reads,
  // each decrypting access+refresh). The kms_decrypt counts must SUM to that — the refresh reads
  // were previously uncounted, silently understating the metric.
  const kmsTotal = events.filter((e) => e.type === 'kms_decrypt')
    .reduce((n, e) => n + (e as Extract<VouchrEvent, { type: 'kms_decrypt' }>).count, 0);
  assert.equal(kmsTotal, unwraps, `kms_decrypt undercounts: reported ${kmsTotal}, actual unwraps ${unwraps}`);
  assert.ok(kmsTotal >= 4, `expected refresh-path reads to be counted, got ${kmsTotal}`);
});

test('observability: a throwing sink does not break handle.fetch', async (t) => {
  const handle = await handleWithSink(t, () => { throw new Error('bad sink'); });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    const res = await handle.fetch('https://api.github.com/user');
    assert.equal(res.status, 200); // sink blew up, request unaffected
  } finally {
    globalThis.fetch = realFetch;
  }
});
