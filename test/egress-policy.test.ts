import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle, type VouchrEvent } from '../src/core/injector';
import { defineProvider, github } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);

// A provider that exercises every optional egress control on top of the hostname allowlist.
const guarded = defineProvider({
  id: 'guarded',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  egressPaths: ['/repos/', '/user'],
  egressMethods: ['GET', 'POST'],
  egressValidate: (url) => !url.searchParams.has('blocked'),
  refresh: 'none',
  pkce: false,
  clientId: 'id',
  clientSecret: 'sec',
});

// Wire the handle so its secret comes ONLY from the resolver, and a resolver call count of 0 proves
// the token was never read. The injector reads the secret strictly after every egress check passes.
async function makeHandle(t: TestContext, provider = guarded) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  let resolverCalls = 0;
  await vault.reference(O1, provider.id, { source: 'ext', secretRef: 'arn:secret' });
  const resolvers = {
    ext: async () => {
      resolverCalls++;
      return 'super-secret-token';
    },
  };
  const handle = new ConnectionHandle(provider, O1, ID, vault, audit, resolvers);
  return { handle, calls: () => resolverCalls };
}

test('egress: allowed path + method passes, reads the token, and injects', async (t) => {
  const realFetch = globalThis.fetch;
  let sawAuth: string | null = null;
  globalThis.fetch = (async (_url: any, init: any) => {
    sawAuth = new Headers(init.headers).get('authorization');
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const { handle, calls } = await makeHandle(t);
    const res = await handle.fetch('https://api.acme.example/repos/x', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(sawAuth, 'Bearer super-secret-token'); // token resolved and injected
    assert.equal(calls(), 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// WHATWG URL parses a hostname of any length, so an agent-supplied target of tens of kilobytes used to
// sail into denyEgress and land verbatim in the `denied` audit row's meta.host and the egress_denied
// event — an unbounded, unvalidated external value persisted before any check (SEC-4). Past the RFC
// 1035 ceiling a name cannot resolve: it is a malformed URL, refused with no row, no event, no gate.
test('egress: an over-long hostname is a malformed URL — no audit row, no event, no secret read (SEC-4)', async (t) => {
  const realFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = (async () => {
    fetched = true;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    const db = await openTestDb(t);
    const vault = new Vault(db, KEY);
    const audit = new Audit(db);
    let resolverCalls = 0;
    await vault.reference(O1, guarded.id, { source: 'ext', secretRef: 'arn:secret' });
    const events: VouchrEvent[] = [];
    const handle = new ConnectionHandle(
      guarded, O1, ID, vault, audit,
      { ext: async () => { resolverCalls++; return 'super-secret-token'; } },
      new Map(), (e) => events.push(e),
    );
    // 254 chars: one past the ceiling. A dotted label pattern so audit's high-entropy redaction cannot
    // mask the persistence (a bare 40+ alnum run would be scrubbed to '[redacted]' and hide the bug).
    const host = `${'a.'.repeat(126)}ab`;
    assert.equal(host.length, 254);
    await assert.rejects(() => handle.fetch(`https://${host}/user`), TypeError);
    assert.deepEqual(await db.all(`SELECT action FROM audit`), []);
    assert.deepEqual(events, []);
    assert.equal(resolverCalls, 0);
    assert.equal(fetched, false);
    // Exactly at the ceiling is still a real (non-allowlisted) target: audited and denied as before.
    const maxHost = `${'a.'.repeat(126)}a`;
    assert.equal(maxHost.length, 253);
    await assert.rejects(() => handle.fetch(`https://${maxHost}/user`), /not in the allowlist/);
    assert.deepEqual(await db.all(`SELECT action, meta FROM audit`), [{ action: 'denied', meta: JSON.stringify({ host: maxHost, reason: 'host' }) }]);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('egress: disallowed path is denied before the token is read', async (t) => {
  const realFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = (async () => {
    fetched = true;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    const { handle, calls } = await makeHandle(t);
    await assert.rejects(() => handle.fetch('https://api.acme.example/secrets', { method: 'GET' }), /not in the allowed paths/);
    await assert.rejects(() => handle.fetch('https://api.acme.example/userish', { method: 'GET' }), /not in the allowed paths/);
    assert.equal(calls(), 0); // resolver never called, secret never read
    assert.equal(fetched, false); // request never went out
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('egress: URL userinfo is denied before the token is read', async (t) => {
  const realFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = (async () => {
    fetched = true;
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    const { handle, calls } = await makeHandle(t);
    await assert.rejects(
      () => handle.fetch('https://caller:password@api.acme.example/user', { method: 'GET' }),
      /URL credentials are not allowed/,
    );
    assert.equal(calls(), 0);
    assert.equal(fetched, false);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('egress: disallowed method is denied before the token is read', async (t) => {
  const { handle, calls } = await makeHandle(t);
  await assert.rejects(() => handle.fetch('https://api.acme.example/repos/x', { method: 'DELETE' }), /method "DELETE" is not allowed/);
  assert.equal(calls(), 0);
});

test('egress: default method is GET (no init.method)', async (t) => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    // GET is allowed; absence of init.method must not deny.
    const { handle } = await makeHandle(t);
    const res = await handle.fetch('https://api.acme.example/user');
    assert.equal(res.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('egress: validator returning false denies before the token is read', async (t) => {
  const { handle, calls } = await makeHandle(t);
  await assert.rejects(() => handle.fetch('https://api.acme.example/user?blocked=1', { method: 'GET' }), /validator rejected/);
  assert.equal(calls(), 0);
});

test('egress: provider WITHOUT the new fields is unchanged (hostname-only baseline)', async (t) => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    const plain = defineProvider({
      id: 'plain',
      authorizeUrl: 'https://acme.example/auth',
      tokenUrl: 'https://acme.example/token',
      scopesDefault: ['x'],
      egressAllow: ['api.acme.example'], // no egressPaths/egressMethods/egressValidate
      refresh: 'none',
      pkce: false,
      clientId: 'id',
      clientSecret: 'sec',
    });
    const { handle } = await makeHandle(t, plain);
    // Any path, any method: only the hostname allowlist applies, exactly as before.
    const res = await handle.fetch('https://api.acme.example/anything/at/all', { method: 'DELETE' });
    assert.equal(res.status, 200);
    // And a disallowed host is still blocked.
    await assert.rejects(() => handle.fetch('https://evil.example/x'), /Egress blocked/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('egress: built-in provider factories pass through fine-grained egress controls', () => {
  const validate = () => true;
  const provider = github({
    clientId: 'id',
    clientSecret: 'sec',
    egressPaths: ['/user'],
    egressMethods: ['GET'],
    egressValidate: validate,
  });
  assert.deepEqual(provider.egressPaths, ['/user']);
  assert.deepEqual(provider.egressMethods, ['GET']);
  assert.equal(provider.egressValidate, validate);
});
