import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { defineProvider, github, ProviderRegistry } from '../src/core/providers';
import { revokeToken } from '../src/core/tokens';
import { handleOAuthCallback } from '../src/core/oauthCallback';
import { offboardUser, offboardUserEverywhere, disconnectProvider } from '../src/core/offboard';
import { userOwner } from '../src/core/owner';
import type { EnvelopeProvider } from '../src/core/crypto';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);

// Google-like: form body `token=<token>`, no client auth.
const revocable = defineProvider({
  id: 'revocable',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  refresh: 'rotating',
  pkce: true,
  revokeUrl: 'https://acme.example/revoke',
  clientId: 'id',
  clientSecret: 'sec',
});

// No revoke capability (Notion-style): revokeToken must be a no-op.
const norevoke = defineProvider({
  id: 'norevoke',
  authorizeUrl: 'https://no.example/auth',
  tokenUrl: 'https://no.example/token',
  scopesDefault: [],
  egressAllow: ['api.no.example'],
  refresh: 'none',
  pkce: false,
  clientId: 'id',
  clientSecret: 'sec',
});

test('revokeToken posts token to revokeUrl (form, no creds by default)', async () => {
  const realFetch = globalThis.fetch;
  const calls: any[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    calls.push({ url, init });
    return new Response('', { status: 200 });
  }) as any;
  try {
    await revokeToken(revocable, 'TOK');
    assert.equal(calls.length, 1);
    assert.equal(String(calls[0].url), 'https://acme.example/revoke');
    assert.equal(calls[0].init.method, 'POST');
    assert.equal(calls[0].init.headers['Content-Type'], 'application/x-www-form-urlencoded');
    const form = new URLSearchParams(calls[0].init.body);
    assert.equal(form.get('token'), 'TOK');
    assert.equal(form.get('client_id'), null); // revokeAuth defaults to 'none'
    // GHSA-25m2: the revoke call is time-bounded so a hung endpoint can't stall offboarding.
    assert.ok(calls[0].init.signal instanceof AbortSignal);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('revokeToken sends client creds in the body when revokeAuth=body (GitLab-style)', async () => {
  const gitlabLike = defineProvider({ ...revocable, id: 'gl', revokeAuth: 'body' });
  const realFetch = globalThis.fetch;
  let body = '';
  globalThis.fetch = (async (_url: any, init: any) => {
    body = init.body;
    return new Response('', { status: 200 });
  }) as any;
  try {
    await revokeToken(gitlabLike, 'TOK');
    const form = new URLSearchParams(body);
    assert.equal(form.get('client_id'), 'id');
    assert.equal(form.get('client_secret'), 'sec');
    assert.equal(form.get('token'), 'TOK');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('revokeToken is a no-op for a provider with no revoke capability (fetch not called)', async () => {
  const realFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = (async () => {
    called = true;
    return new Response('', { status: 200 });
  }) as any;
  try {
    await revokeToken(norevoke, 'TOK'); // must not throw, must not fetch
    assert.equal(called, false);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('built-in GitHub revoke uses the non-standard DELETE + Basic + JSON shape', async () => {
  const realFetch = globalThis.fetch;
  let seen: any = null;
  globalThis.fetch = (async (url: any, init: any) => {
    seen = { url, init };
    return new Response(null, { status: 204 });
  }) as any;
  try {
    await revokeToken(github({ clientId: 'cid', clientSecret: 'csec' }), 'TOK');
    assert.equal(String(seen.url), 'https://api.github.com/applications/cid/token');
    assert.equal(seen.init.method, 'DELETE');
    assert.equal(seen.init.headers.Authorization, `Basic ${Buffer.from('cid:csec').toString('base64')}`);
    assert.equal(seen.init.headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(seen.init.body), { access_token: 'TOK' });
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('offboardUser deletes locally even when upstream revoke throws, and audits ok:false', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([revocable]);
  await vault.upsert(O1, 'revocable', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('nope', { status: 500 })) as any; // upstream revoke fails
  try {
    const removed = await offboardUser(vault, audit, consent, ID, registry);
    assert.deepEqual(removed, ['revocable']);
    assert.equal(await vault.get(O1, 'revocable'), null); // local delete happened despite the throw
  } finally {
    globalThis.fetch = realFetch;
  }

  const rows = (await db.all('SELECT action, meta FROM audit WHERE action=?', ['revoke'])) as any[];
  assert.equal(rows.length, 1);
  const meta = JSON.parse(rows[0].meta);
  assert.equal(meta.ok, false); // best-effort revoke recorded as failed
  // No token value anywhere in the audit meta.
  assert.ok(!rows[0].meta.includes('SECRET_TOK'));
});

test('offboardUser records ok:true when upstream revoke succeeds; no token in meta', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([revocable]);
  await vault.upsert(O1, 'revocable', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const realFetch = globalThis.fetch;
  let sawToken: string | null = null;
  globalThis.fetch = (async (_url: any, init: any) => {
    sawToken = new URLSearchParams(init.body).get('token');
    return new Response('', { status: 200 });
  }) as any;
  try {
    await offboardUser(vault, audit, consent, ID, registry);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(sawToken, 'SECRET_TOK'); // the real token was sent to the revoke endpoint

  const rows = (await db.all('SELECT meta FROM audit WHERE action=?', ['revoke'])) as any[];
  assert.equal(JSON.parse(rows[0].meta).ok, true);
  assert.ok(!rows[0].meta.includes('SECRET_TOK')); // never in the audit log
});

const revocable2 = defineProvider({ ...revocable, id: 'revocable2' });

async function countConnections(db: any): Promise<number> {
  return ((await db.get('SELECT COUNT(*) AS n FROM connection')) as any).n;
}

// GHSA-25m2: a decrypt/KMS failure must only skip the upstream revoke — every local delete
// still happens, for every provider, and nothing is stranded until "KMS recovers".
test('offboardUser deletes ALL rows even when the KMS envelope unwrap fails', async () => {
  const kmsDown: EnvelopeProvider = {
    async wrapDataKey(dek) { return Buffer.from(dek); }, // sealing works…
    async unwrapDataKey() { throw new Error('kms endpoint unreachable'); }, // …decrypting never does
  };
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, {}, kmsDown);
  const registry = new ProviderRegistry([revocable, revocable2]);
  for (const p of ['revocable', 'revocable2']) {
    await vault.upsert(O1, p, { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  }

  const realFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = (async () => { fetched = true; return new Response('', { status: 200 }); }) as any;
  try {
    const removed = await offboardUser(vault, new Audit(db), new Consent(db), ID, registry);
    assert.deepEqual(removed.sort(), ['revocable', 'revocable2']); // truthful: both actually deleted
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(await countConnections(db), 0); // no stranded credential rows
  assert.equal(fetched, false); // no token was readable, so no upstream revoke was attempted
  // Truthful audit (review r3): revocation was DUE but couldn't run — never reported as ok:true.
  for (const r of (await db.all(`SELECT meta FROM audit WHERE action='revoke'`)) as any[]) {
    const meta = JSON.parse(r.meta);
    assert.equal(meta.ok, false);
    assert.equal(meta.upstream, 'skipped');
  }
});

// Review r3: a failed credential DELETE must surface as incomplete, never as partial success.
test('offboardUser throws when a credential deletion fails, after attempting the other rows', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const seeder = new Vault(db, KEY);
  for (const p of ['revocable', 'revocable2']) {
    await seeder.upsert(O1, p, { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  }
  // DELETEs against the connection table fail for the FIRST provider only.
  let failed = 0;
  const flakyDb = {
    get: db.get.bind(db),
    all: db.all.bind(db),
    exec: db.exec.bind(db),
    close: db.close.bind(db),
    run: (sql: string, params?: unknown[]) => {
      if (sql.includes('DELETE FROM connection') && (params as any[])?.includes('revocable') && failed === 0) {
        failed++;
        return Promise.reject(new Error('connection table down'));
      }
      return db.run(sql, params as any[]);
    },
  } as any;
  const vault = new Vault(flakyDb, KEY);
  await assert.rejects(offboardUser(vault, new Audit(db), new Consent(db), ID), /credential deletion\(s\) failed/);
  // The OTHER provider's delete was still attempted and succeeded before the throw.
  const left = (await db.all(`SELECT provider FROM connection`)) as any[];
  assert.deepEqual(left.map((r) => r.provider), ['revocable']);
});

// GHSA-25m2: an audit failure on one row must not abort the deletes for the remaining rows.
test('offboardUser deletes every row even when audit.record throws mid-loop', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  for (const p of ['revocable', 'revocable2']) {
    await vault.upsert(O1, p, { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  }
  const badAudit = { record: async () => { throw new Error('audit db down'); } } as unknown as Audit;
  const removed = await offboardUser(vault, badAudit, new Consent(db), ID);
  assert.deepEqual(removed.sort(), ['revocable', 'revocable2']);
  assert.equal(await countConnections(db), 0);
});

// GHSA-25m2: a row past its LOCAL TTL may still be live upstream — disconnect must still revoke
// it there, and `removed` reflects the actual delete (the row existed), not the TTL-gated read.
test('disconnectProvider revokes an expired-here token upstream and reports removed:true', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, { maxAgeMs: 1 }); // everything expires ~immediately
  const registry = new ProviderRegistry([revocable]);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await new Promise((r) => setTimeout(r, 5)); // let the row cross the TTL
  assert.equal(await vault.get(O1, 'revocable'), null); // sanity: expired for injection purposes

  const realFetch = globalThis.fetch;
  let sawToken: string | null = null;
  globalThis.fetch = (async (_url: any, init: any) => {
    sawToken = new URLSearchParams(init.body).get('token');
    return new Response('', { status: 200 });
  }) as any;
  try {
    const { removed, ok } = await disconnectProvider(vault, new Audit(db), registry, ID, 'revocable');
    assert.equal(removed, true);
    assert.equal(ok, true);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(sawToken, 'SECRET_TOK'); // the upstream revoke still happened
  assert.equal(await countConnections(db), 0);
});

// GHSA-25m2 review: EVERY revoke implementation is bounded — including a custom hook that never
// settles and ignores the abort signal — so one hung endpoint cannot stall the offboarding loop.
test('revokeToken bounds a never-settling custom revoke and hands the hook an abort signal', async () => {
  let seenSignal: unknown;
  const hang = defineProvider({
    ...revocable,
    id: 'hang',
    revoke: (_p, _t, signal) => {
      seenSignal = signal;
      return new Promise(() => {}); // never settles, ignores the signal
    },
  });
  await assert.rejects(revokeToken(hang, 'SECRET_TOK', 25), (e: Error) => {
    assert.match(e.message, /timed out/);
    assert.ok(!e.message.includes('SECRET_TOK')); // never the token
    return true;
  });
  assert.ok(seenSignal instanceof AbortSignal); // well-behaved hooks can cancel their own fetch
});

test('revokeToken bounds the standard RFC 7009 revoke when the endpoint hangs', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (() => new Promise(() => {})) as any; // endpoint never responds
  try {
    await assert.rejects(revokeToken(revocable, 'TOK', 25), /timed out/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('offboardUser: a hung custom revoke on the first provider does not strand the second (GHSA-25m2)', async () => {
  const hangp = defineProvider({ ...revocable, id: 'hangp', revoke: () => new Promise(() => {}) });
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const registry = new ProviderRegistry([hangp, revocable2]);
  await vault.upsert(O1, 'hangp', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await vault.upsert(O1, 'revocable2', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

  // Shrink the revoke deadline so the test doesn't wait the production 10s: clamp only LONG timer
  // delays (the deadline is the only multi-second timer in this path); restored in finally.
  const realSetTimeout = globalThis.setTimeout;
  (globalThis as any).setTimeout = (fn: any, ms?: number, ...rest: any[]) =>
    realSetTimeout(fn, ms != null && ms > 1000 ? 20 : ms, ...rest);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('', { status: 200 })) as any; // revocable2's revoke succeeds
  try {
    const removed = await offboardUser(vault, new Audit(db), new Consent(db), ID, registry);
    assert.deepEqual(removed.sort(), ['hangp', 'revocable2']);
  } finally {
    globalThis.setTimeout = realSetTimeout;
    globalThis.fetch = realFetch;
  }
  assert.equal(await countConnections(db), 0); // the hang deleted nothing extra and stranded nothing
  const metas = ((await db.all(`SELECT provider, meta FROM audit WHERE action='revoke'`)) as any[])
    .map((r) => [r.provider, JSON.parse(r.meta).ok] as [string, boolean]);
  assert.deepEqual(new Map(metas).get('hangp'), false); // the timeout is reported truthfully
  assert.deepEqual(new Map(metas).get('revocable2'), true);
});

// GHSA-25m2 review: auxiliary cleanup failures must not prevent the credential deletes (the
// tombstone gate still landed, so the failed purge stays fail-closed — see the callback test).
test('offboardUser deletes credentials even when the consent cleanup throws', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const consent = new Consent(db);
  (consent as any).deleteForUser = async () => { throw new Error('consent table down'); };
  const removed = await offboardUser(vault, new Audit(db), consent, ID);
  assert.deepEqual(removed, ['revocable']);
  assert.equal(await countConnections(db), 0);
});

// GHSA-25m2 review: a satellite-purge failure must not roll back (or block) the credential delete.
test('vault.delete removes the credential even when the satellite purge fails', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const seeder = new Vault(db, KEY);
  await seeder.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const failingDb = {
    get: db.get.bind(db),
    all: db.all.bind(db),
    exec: db.exec.bind(db),
    close: db.close.bind(db),
    run: (sql: string, params?: unknown[]) =>
      sql.includes('notification_state') ? Promise.reject(new Error('satellite table down')) : db.run(sql, params as any[]),
  } as any;
  const vault = new Vault(failingDb, KEY);
  assert.equal(await vault.delete(O1, 'revocable'), true); // truthful, and it did not throw
  assert.equal(await countConnections(db), 0); // the delete committed despite the failed purge
});

// GHSA-25m2 round 2: a pending consent must not be able to resurrect an offboarded user's
// credential EVEN WHEN the offboarding consent purge transiently fails — the durable tombstone
// written first makes the saved callback fail closed.
test('offboarding gates the OAuth callback: a saved pre-offboard consent cannot recreate the credential', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([revocable]);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  // A pending "Connect" exists when the user is offboarded…
  const { state } = await consent.begin(ID, revocable, 'https://cb.example/x', null);
  // …and the offboarding row-purge FAILS (transient DB error) while everything else works.
  const realPurge = consent.deleteForUser.bind(consent);
  (consent as any).deleteForUser = async () => { throw new Error('consent table down'); };
  const removed = await offboardUser(vault, audit, consent, ID);
  assert.deepEqual(removed, ['revocable']); // the credential deletes still ran
  (consent as any).deleteForUser = realPurge;
  // The consent row survived the failed purge — but the callback must still fail closed.
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'NEW_TOK' }), { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    const res = await handleOAuthCallback({ registry, vault, audit, consent, redirectUri: 'https://cb.example/x' }, 'CODE', state);
    assert.equal(res.ok, false); // invalid/expired state — the tombstone gate refused it
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(await countConnections(db), 0, 'no credential was resurrected');

  // A NEW consent begun AFTER offboarding + the skew margin (legitimate re-onboarding) still
  // works. Fake clock: the margin is a full state lifetime (~10 min), so jump past it.
  const realNow = Date.now;
  const base = realNow();
  Date.now = () => base + 11 * 60_000;
  try {
    const again = await consent.begin(ID, revocable, 'https://cb.example/x', null);
    globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'NEW_TOK' }), { status: 200, headers: { 'content-type': 'application/json' } })) as any;
    const res = await handleOAuthCallback({ registry, vault, audit, consent, redirectUri: 'https://cb.example/x' }, 'CODE', again.state);
    assert.equal(res.ok, true);
  } finally {
    Date.now = realNow;
    globalThis.fetch = realFetch;
  }
  assert.equal(await countConnections(db), 1); // re-onboarding is not bricked

  // Inside the margin window a consent is still refused — the skew tolerance is fail-closed.
  Date.now = () => base + 5 * 60_000;
  try {
    const tooSoon = await consent.begin(ID, revocable, 'https://cb.example/x', null);
    assert.equal(await consent.consume(tooSoon.state), null);
  } finally {
    Date.now = realNow;
  }
});

test('offboardUser throws (after attempting every delete) only when BOTH the tombstone and the purge fail', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const consent = new Consent(db);
  (consent as any).markOffboarded = async () => { throw new Error('tombstone write failed'); };
  (consent as any).deleteForUser = async () => { throw new Error('consent table down'); };
  await assert.rejects(offboardUser(vault, new Audit(db), consent, ID), /offboarding incomplete/);
  assert.equal(await countConnections(db), 0, 'the credential deletes were still attempted first');
});

// GHSA-25m2: rows written outside Grid store enterprise_id=NULL; an enterprise-scoped sweep must
// still discover a team whose only artifact is such a row (userId is org-unique in Grid).
test('offboardUserEverywhere with enterpriseId still finds NULL-enterprise rows', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null }); // O1 carries no enterpriseId → NULL row
  const summary = await offboardUserEverywhere(db, vault, new Audit(db), new Consent(db), { enterpriseId: 'E1', userId: ID.userId });
  assert.deepEqual(summary, [{ teamId: 'T1', providers: ['revocable'] }]);
  assert.equal(await countConnections(db), 0);
});
