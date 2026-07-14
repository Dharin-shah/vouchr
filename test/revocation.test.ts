import { test } from 'node:test';
import { openTestDb, testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
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
import { openDb } from '../src/core/db';

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

test('revokeToken refuses redirects without forwarding credentials or exposing the endpoint', async () => {
  const endpointSecret = 'REVOKE_URL_QUERY_SECRET';
  const tokenSecret = 'LIVE_TOKEN_SECRET';
  const clientSecret = 'REVOKE_CLIENT_SECRET';
  const provider = defineProvider({
    ...revocable,
    id: 'redirecting-revoke',
    revokeUrl: `https://acme.example/revoke?private=${endpointSecret}`,
    revokeAuth: 'body',
    clientSecret,
  });
  const redirectDestination = 'https://attacker.example/collect';
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response(null, { status: 308, headers: { location: redirectDestination } });
  }) as typeof fetch;
  try {
    await assert.rejects(() => revokeToken(provider, tokenSecret), (error: Error) => {
      assert.equal(error.message, 'Revoke endpoint returned HTTP 308');
      assert.ok(!error.message.includes(endpointSecret));
      assert.ok(!error.message.includes(provider.revokeUrl!));
      return true;
    });
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.equal(calls.length, 1, 'only the original revoke endpoint receives a request');
  assert.notEqual(calls[0].url, redirectDestination, 'redirect destination receives no request');
  assert.equal(calls[0].init.redirect, 'manual');
  const body = String(calls[0].init.body);
  assert.equal(new URLSearchParams(body).get('token'), tokenSecret, 'test exercised the live-token path');
  assert.equal(new URLSearchParams(body).get('client_secret'), clientSecret, 'test exercised revoke client authentication');
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

test('offboardUser deletes locally even when upstream revoke throws, and audits ok:false', async (t) => {
  const db = await openTestDb(t);
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

test('offboardUser records ok:true when upstream revoke succeeds; no token in meta', async (t) => {
  const db = await openTestDb(t);
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
test('offboardUser deletes ALL rows even when the KMS envelope unwrap fails', async (t) => {
  const kmsDown: EnvelopeProvider = {
    async wrapDataKey(dek) { return Buffer.from(dek); }, // sealing works…
    async unwrapDataKey() { throw new Error('kms endpoint unreachable'); }, // …decrypting never does
  };
  const db = await openTestDb(t);
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
test('offboardUser throws when a credential deletion fails, after attempting the other rows', async (t) => {
  const db = await openTestDb(t);
  const seeder = new Vault(db, KEY);
  for (const p of ['revocable', 'revocable2']) {
    await seeder.upsert(O1, p, { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  }
  // DELETEs against the connection table fail for the FIRST provider only.
  let failed = 0;
  const flakyDb = {
    get: (sql: string, params?: unknown[]) => {
      if (sql.includes('DELETE FROM connection') && (params as any[])?.includes('revocable') && failed === 0) {
        failed++;
        return Promise.reject(new Error('connection table down'));
      }
      return db.get(sql, params as any[]);
    },
    all: db.all.bind(db),
    exec: db.exec.bind(db),
    close: db.close.bind(db),
    run: db.run.bind(db),
  } as any;
  const vault = new Vault(flakyDb, KEY);
  await assert.rejects(offboardUser(vault, new Audit(db), new Consent(db), ID), /credential deletion\(s\) failed/);
  // The OTHER provider's delete was still attempted and succeeded before the throw.
  const left = (await db.all(`SELECT provider FROM connection`)) as any[];
  assert.deepEqual(left.map((r) => r.provider), ['revocable']);
});

// GHSA-25m2: an audit failure on one row must not abort the deletes for the remaining rows.
test('offboardUser deletes every row even when audit.record throws mid-loop', async (t) => {
  const db = await openTestDb(t);
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
test('disconnectProvider revokes an expired-here token upstream and reports removed:true', async (t) => {
  const db = await openTestDb(t);
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
    const outcome = await disconnectProvider(vault, new Audit(db), registry, ID, 'revocable');
    assert.deepEqual(outcome, { recognized: true, removed: true, ok: true, audited: true });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(sawToken, 'SECRET_TOK'); // the upstream revoke still happened
  assert.equal(await countConnections(db), 0);
});

test('disconnectProvider reports a referenced revocable credential as unresolved upstream debt', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const reference = 'TEST_EXTERNAL_REFERENCE';
  await vault.reference(O1, 'revocable', { source: 'external', secretRef: reference });

  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = (async () => {
    upstreamCalls++;
    return new Response('', { status: 200 });
  }) as any;
  let outcome: Awaited<ReturnType<typeof disconnectProvider>>;
  try {
    outcome = await disconnectProvider(
      vault,
      new Audit(db),
      new ProviderRegistry([revocable]),
      ID,
      'revocable',
    );
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.deepEqual(outcome, { recognized: true, removed: true, ok: false, audited: true });
  assert.equal(upstreamCalls, 0, 'an unresolved external reference cannot be sent to the provider');
  assert.equal(await vault.has(O1, 'revocable'), false);
  const row = (await db.get(
    `SELECT meta FROM audit WHERE action='revoke' AND provider='revocable'`,
  )) as { meta: string };
  assert.deepEqual(JSON.parse(row.meta), { ok: false, upstream: 'skipped' });
  assert.ok(!row.meta.includes(reference));
});

test('concurrent disconnects atomically claim one row, upstream revoke, and audit', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  const vaultA = new Vault(dbA, KEY);
  const vaultB = new Vault(dbB, KEY);
  await vaultA.upsert(O1, 'revocable', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  // Two distinct pools model separate replicas. Hold both callers immediately before the production
  // DELETE ... RETURNING claim so they contend on the same committed row rather than arriving serially.
  let arrivals = 0;
  let release!: () => void;
  const together = new Promise<void>((resolve) => { release = resolve; });
  for (const vault of [vaultA, vaultB]) {
    const claim = vault.deleteForRevoke.bind(vault);
    vault.deleteForRevoke = async (...args: Parameters<Vault['deleteForRevoke']>) => {
      arrivals++;
      if (arrivals === 2) release();
      await together;
      return claim(...args);
    };
  }

  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = (async () => {
    upstreamCalls++;
    return new Response('', { status: 200 });
  }) as any;
  try {
    const registry = new ProviderRegistry([revocable]);
    const outcomes = await Promise.all([
      disconnectProvider(vaultA, new Audit(dbA), registry, ID, 'revocable'),
      disconnectProvider(vaultB, new Audit(dbB), registry, ID, 'revocable'),
    ]);
    assert.deepEqual(outcomes.map((o) => o.removed).sort(), [false, true]);
    assert.ok(outcomes.every((o) => o.recognized && o.audited));
    assert.equal(upstreamCalls, 1);
    assert.equal(await countConnections(dbA), 0);
    assert.equal(((await dbA.get(`SELECT COUNT(*) AS n FROM audit WHERE action='revoke'`)) as any).n, 1);
  } finally {
    globalThis.fetch = realFetch;
    await Promise.all([dbA.close(), dbB.close()]);
  }
});

test('disconnectProvider rejects an unregistered, unstored provider before any mutation or audit', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const provider = 'untrusted-provider';
  // The atomic DELETE claim must not purge satellites when no credential row authorizes the stale id.
  // Keeping this row proves the untrusted value reached no committed mutation or audit.
  await db.run(
    `INSERT INTO notification_state
       (team_id, owner_kind, owner_id, provider, type, last_notified_at)
     VALUES (?, 'user', ?, ?, 'refresh_dead', ?)`,
    [ID.teamId, ID.userId, provider, Date.now()],
  );

  const outcome = await disconnectProvider(vault, new Audit(db), new ProviderRegistry([]), ID, provider);
  assert.deepEqual(outcome, { recognized: false, removed: false, ok: false, audited: false });
  assert.equal(await countConnections(db), 0);
  assert.equal(((await db.get(`SELECT COUNT(*) AS n FROM audit`)) as any).n, 0);
  assert.equal(((await db.get(`SELECT COUNT(*) AS n FROM notification_state WHERE provider=?`, [provider])) as any).n, 1);
});

test('disconnectProvider deletes a stale stored provider without decrypting and reports upstream debt', async (t) => {
  const kmsDown: EnvelopeProvider = {
    async wrapDataKey(dek) { return Buffer.from(dek); },
    async unwrapDataKey() { throw new Error('stale credential must not be decrypted'); },
  };
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY, {}, kmsDown);
  const provider = 'retired-provider';
  await vault.upsert(O1, provider, {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  assert.equal(await vault.has(O1, provider), true);

  const outcome = await disconnectProvider(vault, new Audit(db), new ProviderRegistry([]), ID, provider);
  assert.deepEqual(outcome, { recognized: true, removed: true, ok: false, audited: true });
  assert.equal(await vault.has(O1, provider), false);
  const row = (await db.get(`SELECT provider, meta FROM audit WHERE action='revoke'`)) as any;
  assert.equal(row.provider, provider);
  assert.deepEqual(JSON.parse(row.meta), { ok: false, upstream: 'skipped' });
  assert.ok(!row.meta.includes('SECRET_TOK'));
});

test('disconnectProvider removes a stale dry-run row without decrypting or inventing upstream debt', async (t) => {
  const kmsDown: EnvelopeProvider = {
    async wrapDataKey(dek) { return Buffer.from(dek); },
    async unwrapDataKey() { throw new Error('synthetic stale credential must not be decrypted'); },
  };
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY, {}, kmsDown);
  const provider = 'retired-dry-run';
  await vault.upsertDryRun(O1, provider, {
    accessToken: 'SYNTHETIC_SECRET', refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'dry-run',
  });

  const realFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = (async () => { fetched = true; return new Response('', { status: 200 }); }) as any;
  try {
    const outcome = await disconnectProvider(vault, new Audit(db), new ProviderRegistry([]), ID, provider);
    assert.deepEqual(outcome, { recognized: true, removed: true, ok: true, audited: true });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(fetched, false);
  assert.equal(await vault.has(O1, provider), false);
  const row = (await db.get(`SELECT meta FROM audit WHERE action='revoke' AND provider=?`, [provider])) as any;
  assert.deepEqual(JSON.parse(row.meta), { ok: true, upstream: 'skipped' });
  assert.ok(!row.meta.includes('SYNTHETIC_SECRET'));
});

test('disconnectProvider preserves revoke failure and local removal when audit also fails', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const auditError = 'ghp_AUDIT_FAILURE_MUST_NOT_ESCAPE';
  const badAudit = { record: async () => { throw new Error(auditError); } } as unknown as Audit;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('upstream unavailable', { status: 503 })) as any;
  let outcome: Awaited<ReturnType<typeof disconnectProvider>> | undefined;
  try {
    outcome = await disconnectProvider(vault, badAudit, new ProviderRegistry([revocable]), ID, 'revocable');
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.deepEqual(outcome, { recognized: true, removed: true, ok: false, audited: false });
  assert.equal(await vault.has(O1, 'revocable'), false);
  assert.ok(!JSON.stringify(outcome).includes(auditError));
});

test('disconnectProvider keeps upstream ok separate from an audit failure', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'norevoke', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const badAudit = { record: async () => { throw new Error('audit db down'); } } as unknown as Audit;

  const outcome = await disconnectProvider(vault, badAudit, new ProviderRegistry([norevoke]), ID, 'norevoke');
  assert.deepEqual(outcome, { recognized: true, removed: true, ok: true, audited: false });
  assert.equal(await vault.has(O1, 'norevoke'), false);
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

test('offboardUser: a hung custom revoke on the first provider does not strand the second (GHSA-25m2)', async (t) => {
  const hangp = defineProvider({ ...revocable, id: 'hangp', revoke: () => new Promise(() => {}) });
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const registry = new ProviderRegistry([hangp, revocable2]);
  await vault.upsert(O1, 'hangp', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await vault.upsert(O1, 'revocable2', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

  // Shrink the revoke deadline so the test doesn't wait the production 10s: clamp only LONG timer
  // delays (the deadline is the only multi-second timer in this path); restored in finally. 250ms
  // (not ~20ms) leaves slack so the deadline still fires + audits reliably when the full parallel
  // suite saturates the CPU — a tighter clamp flakes into a missing revoke-audit row under load.
  const realSetTimeout = globalThis.setTimeout;
  (globalThis as any).setTimeout = (fn: any, ms?: number, ...rest: any[]) =>
    realSetTimeout(fn, ms != null && ms > 1000 ? 250 : ms, ...rest);
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
test('offboardUser deletes credentials even when the consent cleanup throws', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const consent = new Consent(db);
  (consent as any).deleteForUser = async () => { throw new Error('consent table down'); };
  const removed = await offboardUser(vault, new Audit(db), consent, ID);
  assert.deepEqual(removed, ['revocable']);
  assert.equal(await countConnections(db), 0);
});

// GHSA-25m2 review: a satellite-purge failure must not roll back (or block) the credential delete.
test('vault.delete removes the credential even when the satellite purge fails', async (t) => {
  const db = await openTestDb(t);
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

test('vault.delete fallback never removes a reconnect that lands after satellite rollback', async (t) => {
  const db = await openTestDb(t);
  const seeder = new Vault(db, KEY);
  await seeder.upsert(O1, 'revocable', {
    accessToken: 'OLD_SECRET', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  let reconnected = false;
  const racyDb = {
    get: async (sql: string, params?: unknown[]) => {
      // claimDelete reaches this generation-bound fallback only after the failed transaction rolled
      // back. Land a reconnect first; the retry must not delete that newer row.
      if (!reconnected && sql.includes('DELETE FROM connection') && sql.includes('AND id=?')) {
        reconnected = true;
        await seeder.upsert(O1, 'revocable', {
          accessToken: 'NEW_SECRET', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
        });
      }
      return db.get(sql, params as any[]);
    },
    all: db.all.bind(db),
    run: db.run.bind(db),
    exec: db.exec.bind(db),
    close: db.close.bind(db),
    transaction: (fn: (tx: any) => Promise<unknown>) => db.transaction!((tx) => fn({
      get: tx.get.bind(tx),
      all: tx.all.bind(tx),
      exec: tx.exec.bind(tx),
      close: tx.close.bind(tx),
      transaction: tx.transaction?.bind(tx),
      run: (sql: string, params?: unknown[]) =>
        sql.includes('notification_state')
          ? Promise.reject(new Error('satellite table down'))
          : tx.run(sql, params as any[]),
    })),
  } as any;

  const vault = new Vault(racyDb, KEY);
  await assert.rejects(vault.delete(O1, 'revocable'), /could not be confirmed/);
  assert.equal(reconnected, true);
  assert.equal((await vault.get(O1, 'revocable'))?.accessToken, 'NEW_SECRET');
});

// GHSA-25m2 r3: if the purge fails AND the credential DELETE cannot be re-committed, that is a
// genuinely stranded credential — delete() must reject, never report the strand as a success.
test('vault.delete propagates when both the purge and the delete re-run fail', async (t) => {
  const db = await openTestDb(t);
  const seeder = new Vault(db, KEY);
  await seeder.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  let deletes = 0;
  const failingDb = {
    get: (sql: string, params?: unknown[]) => {
      if (sql.includes('DELETE FROM connection') && deletes++ > 0) {
        return Promise.reject(new Error('connection table down')); // credential-only re-run fails
      }
      return db.get(sql, params as any[]);
    },
    all: db.all.bind(db),
    exec: db.exec.bind(db),
    close: db.close.bind(db),
    run: (sql: string, params?: unknown[]) => {
      if (sql.includes('notification_state')) return Promise.reject(new Error('satellite table down'));
      return db.run(sql, params as any[]);
    },
  } as any;
  const vault = new Vault(failingDb, KEY);
  await assert.rejects(vault.delete(O1, 'revocable'), /connection table down/);
});

// GHSA-25m2 round 2: a pending consent must not be able to resurrect an offboarded user's
// credential EVEN WHEN the offboarding consent purge transiently fails — the durable tombstone
// written first makes the saved callback fail closed.
test('offboarding gates the OAuth callback: a saved pre-offboard consent cannot recreate the credential', async (t) => {
  const db = await openTestDb(t);
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

// GHSA-25m2 r3 barrier: the callback consumes its state, then offboarding COMPLETES (tombstone +
// every credential deleted) DURING token exchange, then the write runs. The atomic write-gate must
// refuse the resurrection — the saved-state test starts the callback after offboarding and misses
// this ordering (the credential write racing a tombstone written after consume).
test('offboarding during token exchange cannot resurrect the credential (atomic write-gate)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([revocable]);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const { state } = await consent.begin(ID, revocable, 'https://cb.example/x', null); // consumed at callback start, BEFORE any tombstone
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    await offboardUser(vault, audit, consent, ID); // offboard fully completes mid-exchange: tombstone written + credential deleted
    return new Response(JSON.stringify({ access_token: 'NEW_TOK' }), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const res = await handleOAuthCallback({ registry, vault, audit, consent, redirectUri: 'https://cb.example/x' }, 'CODE', state);
    assert.equal(res.ok, false); // the tombstone written after consume() still blocks the write, atomically
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(await countConnections(db), 0, 'no credential resurrected by a callback that raced offboarding');
});

// GHSA-25m2 r3: the tombstone is the load-bearing fence, so a tombstone-write failure makes the
// offboarding incomplete ON ITS OWN — even when the (best-effort) consent-row purge succeeds.
test('offboardUser throws when the tombstone write fails, even if the consent purge succeeds', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const consent = new Consent(db);
  (consent as any).markOffboarded = async () => { throw new Error('tombstone write failed'); }; // fence down…
  // …but deleteForUser (the consent-row purge) is left REAL and succeeds.
  await assert.rejects(offboardUser(vault, new Audit(db), consent, ID), /offboarding incomplete/);
  assert.equal(await countConnections(db), 0, 'the credential deletes were still attempted first');
});

// A purge-only failure with the tombstone intact is NOT incomplete: the fence holds and the stale
// consent rows are TTL-swept.
test('offboardUser succeeds when only the consent-row purge fails but the tombstone landed', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const consent = new Consent(db);
  (consent as any).deleteForUser = async () => { throw new Error('consent table down'); }; // purge fails, tombstone still written
  assert.deepEqual(await offboardUser(vault, new Audit(db), consent, ID), ['revocable']);
  assert.equal(await countConnections(db), 0);
});

// GHSA-25m2: rows written outside Grid store enterprise_id=NULL; an enterprise-scoped sweep must
// still discover a team whose only artifact is such a row (userId is org-unique in Grid).
test('offboardUserEverywhere with enterpriseId still finds NULL-enterprise rows', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null }); // O1 carries no enterpriseId → NULL row
  const summary = await offboardUserEverywhere(db, vault, new Audit(db), new Consent(db), { enterpriseId: 'E1', userId: ID.userId });
  assert.deepEqual(summary, [{ teamId: 'T1', providers: ['revocable'], ok: true }]);
  assert.equal(await countConnections(db), 0);
});

// GHSA-25m2 r3: one workspace's delete failure must be SURFACED (ok:false for that team), never
// buried as a blanket success, while the other workspaces still offboard.
test('offboardUserEverywhere surfaces a per-team failure and still offboards the others', async (t) => {
  const db = await openTestDb(t);
  const seeder = new Vault(db, KEY);
  const T2 = userOwner({ enterpriseId: null, teamId: 'T2', userId: ID.userId });
  await seeder.upsert(O1, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await seeder.upsert(T2, 'revocable', { accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  // DELETEs against T1's connection fail; T2's succeed.
  const flakyDb = {
    get: (sql: string, params?: unknown[]) =>
      sql.includes('DELETE FROM connection') && (params as any[])?.includes('T1')
        ? Promise.reject(new Error('T1 connection table down'))
        : db.get(sql, params as any[]),
    all: db.all.bind(db), exec: db.exec.bind(db), close: db.close.bind(db), run: db.run.bind(db),
  } as any;
  const vault = new Vault(flakyDb, KEY);
  const summary = await offboardUserEverywhere(db, vault, new Audit(db), new Consent(db), { userId: ID.userId });
  const byTeam = new Map(summary.map((s) => [s.teamId, s.ok]));
  assert.equal(byTeam.get('T1'), false); // failure surfaced, not buried
  assert.equal(byTeam.get('T2'), true); // the other workspace still offboarded
  assert.equal(await countConnections(db), 1); // only T1's row remains (its delete failed)
});
