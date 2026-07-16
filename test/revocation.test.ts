import { test } from 'node:test';
import { openTestDb, testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent, offboardLockKey } from '../src/core/consent';
import { defineProvider, github, ProviderRegistry } from '../src/core/providers';
import { revokeToken } from '../src/core/tokens';
import { handleOAuthCallback } from '../src/core/oauthCallback';
import {
  offboardUser,
  offboardUserDetailed,
  offboardUserEverywhere,
  disconnectProvider,
  disconnectProviderAtReceipt,
  purgePendingForProvider,
} from '../src/core/offboard';
import { channelOwner, userOwner } from '../src/core/owner';
import type { EnvelopeProvider } from '../src/core/crypto';
import type { SlackIdentity } from '../src/core/identity';
import { openDb } from '../src/core/db';
import {
  ChannelProvisioningRequests,
  configureUserCredential,
  UserProvisioningRequests,
} from '../src/core/provisioning';
import { DRY_RUN_CODE } from '../src/core/dryRun';
import { configureChannelCredential, setChannelCredentialMode } from '../src/core/channelCredential';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools, configureChannelTools } from '../src/core/tools';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);

async function disconnectNow(
  vault: Vault,
  audit: Audit,
  registry: ProviderRegistry | undefined,
  identity: SlackIdentity,
  provider: string,
) {
  const issuedAt = await vault.userProvisioningIssuedAt();
  return disconnectProviderAtReceipt(vault, audit, registry, identity, provider, issuedAt);
}

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

test('concurrent detailed offboards both fail closed when the delete winner leaves revoke debt', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const registry = new ProviderRegistry([revocable]);
  await vault.upsert(O1, 'revocable', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  // Make both callers inventory the same live row before either can claim its deletion. Only one
  // caller can then own the upstream result; the loser must not guess that unknown result was clean.
  const listForUser = vault.listForUser.bind(vault);
  let inventories = 0;
  let release!: () => void;
  const bothInventoried = new Promise<void>((resolve) => { release = resolve; });
  vault.listForUser = (async (identity: SlackIdentity) => {
    const rows = await listForUser(identity);
    inventories++;
    if (inventories === 2) release();
    await bothInventoried;
    return rows;
  }) as typeof vault.listForUser;

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('nope', { status: 500 })) as any;
  try {
    const outcomes = await Promise.all([
      offboardUserDetailed(vault, new Audit(db), new Consent(db), ID, registry),
      offboardUserDetailed(vault, new Audit(db), new Consent(db), ID, registry),
    ]);
    assert.ok(outcomes.every((outcome) => outcome.ok === false));
    assert.deepEqual(outcomes.flatMap((outcome) => outcome.providers), ['revocable']);
    assert.equal(await vault.has(O1, 'revocable'), false);
    assert.equal(
      (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='revoke'`))?.n,
      1,
    );
  } finally {
    globalThis.fetch = realFetch;
  }
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

test('the public five-argument disconnectProvider wrapper captures trusted server time', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'norevoke', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const outcome = await disconnectProvider(
    vault,
    new Audit(db),
    new ProviderRegistry([norevoke]),
    ID,
    'norevoke',
  );

  assert.deepEqual(outcome, { recognized: true, removed: true, ok: true, audited: true });
  assert.equal(await vault.has(O1, 'norevoke'), false);
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
    const outcome = await disconnectNow(vault, new Audit(db), registry, ID, 'revocable');
    assert.deepEqual(outcome, { recognized: true, removed: true, ok: true, audited: true });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(sawToken, 'SECRET_TOK'); // the upstream revoke still happened
  assert.equal(await countConnections(db), 0);
});

test('disconnectProvider revokes the claimed token before reporting a failed provisioning fence', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const registry = new ProviderRegistry([revocable]);
  await vault.upsert(O1, 'revocable', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const sentinel = 'ghp_PROVISIONING_FENCE_FAILURE_MUST_NOT_ESCAPE';
  await db.exec(`
    CREATE FUNCTION fail_provisioning_fence() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION '${sentinel}';
    END;
    $$ LANGUAGE plpgsql;
    CREATE TRIGGER fail_provisioning_fence
      BEFORE INSERT OR UPDATE ON provisioning_revocation_tombstone
      FOR EACH ROW EXECUTE FUNCTION fail_provisioning_fence();
  `);

  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  let sawToken: string | null = null;
  globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
    upstreamCalls++;
    sawToken = new URLSearchParams(String(init.body)).get('token');
    return new Response('', { status: 200 });
  }) as typeof fetch;
  let outcome: Awaited<ReturnType<typeof disconnectProvider>>;
  try {
    outcome = await disconnectNow(vault, new Audit(db), registry, ID, 'revocable');
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.deepEqual(outcome, { recognized: true, removed: true, ok: false, audited: true });
  assert.equal(await vault.has(O1, 'revocable'), false, 'the local credential is still removed');
  assert.equal(upstreamCalls, 1, 'the delete winner retains the only upstream revoke opportunity');
  assert.equal(sawToken, 'SECRET_TOK');
  assert.equal(
    (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone`))?.n,
    0,
  );
  const row = await db.get<{ meta: string }>(
    `SELECT meta FROM audit WHERE action='revoke' AND provider='revocable'`,
  );
  assert.deepEqual(JSON.parse(row!.meta), { ok: false });
  assert.ok(!row!.meta.includes(sentinel));
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
    outcome = await disconnectNow(
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
      disconnectNow(vaultA, new Audit(dbA), registry, ID, 'revocable'),
      disconnectNow(vaultB, new Audit(dbB), registry, ID, 'revocable'),
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

  const outcome = await disconnectNow(vault, new Audit(db), new ProviderRegistry([]), ID, provider);
  assert.deepEqual(outcome, { recognized: false, removed: false, ok: false, audited: false });
  assert.equal(await countConnections(db), 0);
  assert.equal(((await db.get(`SELECT COUNT(*) AS n FROM audit`)) as any).n, 0);
  assert.equal(((await db.get(`SELECT COUNT(*) AS n FROM notification_state WHERE provider=?`, [provider])) as any).n, 1);
  assert.equal(
    ((await db.get(`SELECT COUNT(*) AS n FROM provisioning_revocation_tombstone`)) as any).n,
    0,
  );
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

  const outcome = await disconnectNow(vault, new Audit(db), new ProviderRegistry([]), ID, provider);
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
    const outcome = await disconnectNow(vault, new Audit(db), new ProviderRegistry([]), ID, provider);
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
    outcome = await disconnectNow(vault, badAudit, new ProviderRegistry([revocable]), ID, 'revocable');
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

  const outcome = await disconnectNow(vault, badAudit, new ProviderRegistry([norevoke]), ID, 'norevoke');
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
  const vault = new Vault(failingDb, KEY);
  assert.equal(await vault.delete(O1, 'revocable'), true); // truthful, and it did not throw
  assert.equal(await countConnections(db), 0); // the delete committed despite the failed purge
});

test('vault.delete reports a failed provisioning fence only after removing the local credential', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'revocable', {
    accessToken: 'SECRET_TOK', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const sentinel = 'injected provisioning fence failure';
  await db.exec(`
    CREATE FUNCTION fail_delete_provisioning_fence() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION '${sentinel}';
    END;
    $$ LANGUAGE plpgsql;
    CREATE TRIGGER fail_delete_provisioning_fence
      BEFORE INSERT OR UPDATE ON provisioning_revocation_tombstone
      FOR EACH ROW EXECUTE FUNCTION fail_delete_provisioning_fence();
  `);

  await assert.rejects(vault.delete(O1, 'revocable'), (error: Error) => {
    assert.match(error.message, new RegExp(sentinel));
    assert.ok(!error.message.includes('SECRET_TOK'));
    return true;
  });
  assert.equal(await vault.has(O1, 'revocable'), false, 'the local delete still commits');
  assert.equal(
    (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone`))?.n,
    0,
  );
});

test('disconnect fence blocks an exposed key form after credential-only cleanup fallback', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY, { maxAgeMs: 1 });
  await vault.upsert(O1, 'revocable', {
    accessToken: 'EXPIRED_PHYSICAL_KEY',
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: null,
  });
  await db.run(
    `UPDATE connection SET created_at=0, updated_at=0, last_used_at=0
     WHERE team_id=? AND owner_kind='user' AND owner_id=? AND provider=?`,
    [ID.teamId, ID.userId, 'revocable'],
  );
  const requests = new UserProvisioningRequests(db, vault);
  const requestId = await requests.issue(ID, 'revocable');
  assert.ok(requestId, 'an expired physical row must not suppress current setup');

  await db.exec(`
    CREATE FUNCTION fail_user_setup_delete() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'injected setup cleanup failure';
    END;
    $$ LANGUAGE plpgsql;
    CREATE TRIGGER fail_user_setup_delete
      BEFORE DELETE ON user_provisioning_request
      FOR EACH ROW EXECUTE FUNCTION fail_user_setup_delete();
  `);
  const removed = await vault.deleteForRevoke(O1, 'revocable', false);
  assert.equal(removed.removed, true);
  assert.equal(await vault.has(O1, 'revocable'), false);
  assert.equal(
    (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM user_provisioning_request`))?.n,
    1,
    'the injected cleanup failure must exercise the credential-only fallback',
  );
  await db.exec(`
    DROP TRIGGER fail_user_setup_delete ON user_provisioning_request;
    DROP FUNCTION fail_user_setup_delete();
  `);

  assert.equal(
    await configureUserCredential({
      vault,
      audit: new Audit(db),
      identity: ID,
      providerId: 'revocable',
      credential: {
        kind: 'secret',
        token: {
          accessToken: 'STALE_RECREATE_KEY',
          refreshToken: null,
          scopes: '',
          expiresAt: null,
          externalAccount: null,
        },
      },
      issuance: requests.issuance(requestId, ID, 'revocable'),
    }),
    'revoked',
  );
  assert.equal(await vault.has(O1, 'revocable'), false);
  assert.equal(
    (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`))?.n,
    0,
  );
});

test('vault.delete fallback never removes a reconnect that lands after satellite rollback', async (t) => {
  const db = await openTestDb(t);
  const seeder = new Vault(db, KEY);
  await seeder.upsert(O1, 'revocable', {
    accessToken: 'OLD_SECRET', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  let reconnected = false;
  const guardedGet = async (
    sql: string,
    params: unknown[] | undefined,
    read: (sql: string, params?: any[]) => Promise<unknown>,
  ) => {
    // claimDelete reaches this generation-bound fallback only after the failed transaction rolled
    // back. Land a reconnect first; the retry must not delete that newer row. The fallback itself
    // now runs under a fresh lifecycle transaction, so intercept that transaction-bound read too.
    if (!reconnected && sql.includes('DELETE FROM connection') && sql.includes('AND id=?')) {
      reconnected = true;
      await seeder.upsert(O1, 'revocable', {
        accessToken: 'NEW_SECRET', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
      });
    }
    return read(sql, params as any[]);
  };
  const racyDb = {
    get: (sql: string, params?: unknown[]) => guardedGet(sql, params, db.get.bind(db)),
    all: db.all.bind(db),
    run: db.run.bind(db),
    exec: db.exec.bind(db),
    close: db.close.bind(db),
    transaction: (fn: (tx: any) => Promise<unknown>) => db.transaction!((tx) => fn({
      get: (sql: string, params?: unknown[]) => guardedGet(sql, params, tx.get.bind(tx)),
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

for (const kind of ['secret', 'reference'] as const) {
  test(`two replicas: offboarding fences an in-flight user ${kind} write and its audit`, async (t) => {
    const url = await testDbUrl(t);
    const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
    t.after(() => Promise.all([dbA.close(), dbB.close()]));
    const vaultA = new Vault(dbA, KEY);
    const issuedAt = await vaultA.userProvisioningIssuedAt();

    // Hold replica A after it owns the credential lifecycle lock but before it asks for the user
    // offboard fence. Replica B can then commit the tombstone first; when A resumes, the one core
    // fence must refuse both credential shapes before connection/satellite/audit mutation.
    const realLock = vaultA.withCredentialLock.bind(vaultA);
    let entered!: () => void;
    let release!: () => void;
    const atFence = new Promise<void>((resolve) => { entered = resolve; });
    const resume = new Promise<void>((resolve) => { release = resolve; });
    vaultA.withCredentialLock = ((owner, provider, fn) => realLock(owner, provider, async (locked, tx) => {
      entered();
      await resume;
      return fn(locked, tx);
    })) as Vault['withCredentialLock'];

    const identity = { ...ID };
    const credential = kind === 'secret'
      ? {
          kind: 'secret' as const,
          token: {
            accessToken: 'STATIC_TEST_KEY', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
          },
        }
      : {
          kind: 'ref' as const,
          reference: {
            source: 'aws-sm' as const,
            secretRef: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:vouchr/race',
          },
        };
    const provisioning = configureUserCredential({
      vault: vaultA,
      audit: new Audit(dbA),
      identity,
      providerId: 'revocable',
      credential,
      issuance: issuedAt,
    });
    await atFence;

    await offboardUser(new Vault(dbB, KEY), new Audit(dbB), new Consent(dbB), identity);
    release();
    assert.equal(await provisioning, 'offboarded');
    assert.equal(await vaultA.has(O1, 'revocable'), false);
    assert.equal(
      ((await dbA.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`))?.n),
      0,
      'a fenced credential write cannot leave a success audit',
    );
  });
}

test('two replicas: a setup intent that starts before offboarding cannot issue afterward', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const vaultA = new Vault(dbA, KEY);
  const realLock = vaultA.withCredentialLock.bind(vaultA);
  let entered!: () => void;
  let release!: () => void;
  const beforeLock = new Promise<void>((resolve) => { entered = resolve; });
  const resume = new Promise<void>((resolve) => { release = resolve; });
  // issue() has already captured its PostgreSQL timestamp when it reaches this method, but has not
  // taken either lifecycle lock. Let replica B establish the newer tombstone first.
  vaultA.withCredentialLock = (async (...args: Parameters<Vault['withCredentialLock']>) => {
    entered();
    await resume;
    return realLock(...args);
  }) as Vault['withCredentialLock'];

  const pending = new UserProvisioningRequests(dbA, vaultA).issue(ID, 'revocable');
  await beforeLock;
  await offboardUser(new Vault(dbB, KEY), new Audit(dbB), new Consent(dbB), ID);
  release();

  assert.equal(await pending, null);
  assert.equal((await dbA.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM user_provisioning_request`))?.n, 0);
});

test('two replicas: a sibling credential write prevents delayed setup-ticket issuance', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const vaultA = new Vault(dbA, KEY);
  const vaultB = new Vault(dbB, KEY);
  const realLock = vaultA.withCredentialLock.bind(vaultA);
  let entered!: () => void;
  let release!: () => void;
  const beforeLock = new Promise<void>((resolve) => { entered = resolve; });
  const resume = new Promise<void>((resolve) => { release = resolve; });
  vaultA.withCredentialLock = (async (...args: Parameters<Vault['withCredentialLock']>) => {
    entered();
    await resume;
    return realLock(...args);
  }) as Vault['withCredentialLock'];

  const pending = new UserProvisioningRequests(dbA, vaultA).issue(ID, 'revocable');
  await beforeLock;
  assert.equal(await configureUserCredential({
    vault: vaultB,
    audit: new Audit(dbB),
    identity: ID,
    providerId: 'revocable',
    credential: {
      kind: 'secret',
      token: { accessToken: 'SIBLING_KEY', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null },
    },
    issuance: await vaultB.userProvisioningIssuedAt(),
  }), 'stored');
  release();

  assert.equal(await pending, null);
  assert.equal((await dbA.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM user_provisioning_request`))?.n, 0);
});

test('a delayed Slack setup ticket reasserts credential absence before overwriting', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const vaultA = new Vault(dbA, KEY);
  const vaultB = new Vault(dbB, KEY);
  const storeA = new UserProvisioningRequests(dbA, vaultA);
  const requestId = await storeA.issue(ID, 'revocable');
  assert.ok(requestId);
  const request = await dbA.get<{ created_at: number; expires_at: number }>(
    `SELECT created_at, expires_at FROM user_provisioning_request WHERE id=?`,
    [requestId],
  );
  assert.ok(request);

  assert.equal(await configureUserCredential({
    vault: vaultB,
    audit: new Audit(dbB),
    identity: ID,
    providerId: 'revocable',
    credential: {
      kind: 'secret',
      token: { accessToken: 'NEWER_KEY', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null },
    },
    issuance: await vaultB.userProvisioningIssuedAt(),
  }), 'stored');
  // The sibling write normally purges the ticket atomically. Reinsert the exact old row to prove
  // the final under-lock absence predicate is independently load-bearing against stale residue.
  await dbA.run(
    `INSERT INTO user_provisioning_request
       (id, team_id, user_id, provider, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
    [requestId, ID.teamId, ID.userId, 'revocable', request!.created_at, request!.expires_at],
  );

  const delayed = await configureUserCredential({
    vault: vaultA,
    audit: new Audit(dbA),
    identity: ID,
    providerId: 'revocable',
    credential: {
      kind: 'secret',
      token: { accessToken: 'STALE_KEY', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null },
    },
    issuance: storeA.issuance(requestId, ID, 'revocable'),
  });
  assert.equal(delayed, 'stale');
  assert.equal((await vaultA.get(O1, 'revocable'))?.accessToken, 'NEWER_KEY');
  assert.equal((await dbA.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`))?.n, 1);
});

test('expired user-provisioning requests are swept', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const store = new UserProvisioningRequests(db, vault);
  const requestId = await store.issue(ID, 'revocable');
  assert.ok(requestId);
  await db.run(`UPDATE user_provisioning_request SET expires_at=0 WHERE id=?`, [requestId]);
  assert.equal(await store.sweepExpired(), 1);
  assert.equal(await store.resolveForModal(requestId, ID), null);
});

test('expired channel-provisioning requests are swept', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const store = new ChannelProvisioningRequests(db, vault);
  const requestId = await store.issue(
    ID,
    'C1',
    'revocable',
    await vault.userProvisioningIssuedAt(),
  );
  assert.ok(requestId);
  await db.run(`UPDATE channel_provisioning_request SET expires_at=0 WHERE id=?`, [requestId]);
  assert.equal(await store.sweepExpired(), 1);
  assert.equal(await store.resolveForModal(requestId, ID), null);
});

test('direct channel credential writes invalidate every older setup form', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const requests = new ChannelProvisioningRequests(db, vault);
  const channelConfig = new ChannelConfig(db);

  const mutations = [
    {
      label: 'vault',
      write: (owner: ReturnType<typeof channelOwner>, provider: string) => vault.upsert(owner, provider, {
        accessToken: 'CURRENT_VAULT_KEY',
        refreshToken: null,
        scopes: '',
        expiresAt: null,
        externalAccount: null,
      }),
      expected: { source: 'vault', accessToken: 'CURRENT_VAULT_KEY', secretRef: null, dryRun: false },
    },
    {
      label: 'dry-run',
      write: (owner: ReturnType<typeof channelOwner>, provider: string) => vault.upsertDryRun(owner, provider, {
        accessToken: 'CURRENT_DRY_RUN_KEY',
        refreshToken: null,
        scopes: '',
        expiresAt: null,
        externalAccount: null,
      }),
      expected: { source: 'vault', accessToken: 'CURRENT_DRY_RUN_KEY', secretRef: null, dryRun: true },
    },
    {
      label: 'reference',
      write: (owner: ReturnType<typeof channelOwner>, provider: string) => vault.reference(owner, provider, {
        source: 'aws-sm',
        secretRef: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:current',
      }),
      expected: {
        source: 'aws-sm',
        accessToken: null,
        secretRef: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:current',
        dryRun: false,
      },
    },
  ] as const;

  for (const [index, mutation] of mutations.entries()) {
    const channel = `C_SIBLING_${index}`;
    const provider = `sibling-${index}`;
    const owner = channelOwner(ID.teamId, channel);
    const requestId = await requests.issue(
      ID,
      channel,
      provider,
      await vault.userProvisioningIssuedAt(),
    );
    assert.ok(requestId, mutation.label);

    await mutation.write(owner, provider);
    assert.equal(await requests.resolveForModal(requestId, ID), null, mutation.label);
    assert.equal(
      await configureChannelCredential({
        vault,
        audit: new Audit(db),
        channelConfig,
        identity: ID,
        channel,
        providerId: provider,
        issuance: requests.issuance(requestId, ID, channel, provider),
        credential: {
          kind: 'secret',
          token: {
            accessToken: 'STALE_FORM_KEY',
            refreshToken: null,
            scopes: '',
            expiresAt: null,
            externalAccount: null,
          },
        },
        modeConflict: (mode) => { throw new Error(`unexpected mode ${mode}`); },
      }),
      false,
      mutation.label,
    );
    const stored = await vault.get(owner, provider);
    assert.deepEqual(
      stored && {
        source: stored.source,
        accessToken: stored.accessToken,
        secretRef: stored.secretRef,
        dryRun: stored.dryRun,
      },
      mutation.expected,
      mutation.label,
    );
  }

  assert.equal(
    (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`))?.n,
    0,
  );
});

test('channel credential mutations fence an earlier setup receipt before its ticket exists', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const requests = new ChannelProvisioningRequests(db, vault);
  const cases = [
    {
      label: 'vault',
      mutate: (owner: ReturnType<typeof channelOwner>, provider: string) => vault.upsert(owner, provider, {
        accessToken: 'NEW_VAULT_KEY', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
      }),
    },
    {
      label: 'dry-run',
      mutate: (owner: ReturnType<typeof channelOwner>, provider: string) => vault.upsertDryRun(owner, provider, {
        accessToken: 'NEW_DRY_RUN_KEY', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
      }),
    },
    {
      label: 'reference',
      mutate: (owner: ReturnType<typeof channelOwner>, provider: string) => vault.reference(owner, provider, {
        source: 'aws-sm',
        secretRef: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:newer',
      }),
    },
  ] as const;

  for (const [index, entry] of cases.entries()) {
    const channel = `C_PREINSERT_${index}`;
    const provider = `preinsert-${index}`;
    const receipt = await vault.userProvisioningIssuedAt();
    await entry.mutate(channelOwner(ID.teamId, channel), provider);
    assert.equal(await requests.issue(ID, channel, provider, receipt), null, entry.label);
  }

  const deleteOwner = channelOwner(ID.teamId, 'C_PREINSERT_DELETE');
  await vault.upsert(deleteOwner, 'preinsert-delete', {
    accessToken: 'DELETE_ME', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const deleteReceipt = await vault.userProvisioningIssuedAt();
  assert.equal(await vault.delete(deleteOwner, 'preinsert-delete'), true);
  assert.equal(
    await requests.issue(ID, deleteOwner.id, 'preinsert-delete', deleteReceipt),
    null,
    'delete',
  );
});

test('effective channel governance changes fence setup receipts while no-op retries preserve forms', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const requests = new ChannelProvisioningRequests(db, vault);
  const audit = new Audit(db);
  const modeProvider = 'mode-epoch';
  const modeChannel = 'C_MODE_EPOCH';
  const modeReceipt = await vault.userProvisioningIssuedAt();
  await setChannelCredentialMode({
    vault,
    audit,
    channelConfig: new ChannelConfig(db),
    identity: ID,
    channel: modeChannel,
    providerId: modeProvider,
    mode: 'shared',
    issuance: modeReceipt,
  });
  assert.equal(await requests.issue(ID, modeChannel, modeProvider, modeReceipt), null);
  const liveModeIssuance = await vault.userProvisioningIssuedAt();
  const liveModeRequest = await requests.issue(
    ID,
    modeChannel,
    modeProvider,
    liveModeIssuance,
  );
  assert.ok(liveModeRequest);
  await setChannelCredentialMode({
    vault,
    audit,
    channelConfig: new ChannelConfig(db),
    identity: ID,
    channel: modeChannel,
    providerId: modeProvider,
    mode: 'shared',
    issuance: liveModeIssuance,
  });
  assert.deepEqual(
    await requests.resolveForModal(liveModeRequest, ID),
    { channel: modeChannel, provider: modeProvider },
  );

  const toolProvider = 'tool-epoch';
  const toolChannel = 'C_TOOL_EPOCH';
  const toolReceipt = await vault.userProvisioningIssuedAt();
  const configureTool = (issuance: number) => configureChannelTools({
    channelTools: new ChannelTools(db),
    vault,
    audit,
    identity: ID,
    channel: toolChannel,
    changes: [[toolProvider, false]],
    allProviders: [toolProvider],
    authorize: async () => true,
    assertEligible: async () => undefined,
    issuance,
  });
  assert.equal(await configureTool(toolReceipt), 'configured');
  assert.equal(await requests.issue(ID, toolChannel, toolProvider, toolReceipt), null);
  const liveToolIssuance = await vault.userProvisioningIssuedAt();
  const liveToolRequest = await requests.issue(
    ID,
    toolChannel,
    toolProvider,
    liveToolIssuance,
  );
  assert.ok(liveToolRequest);
  assert.equal(await configureTool(liveToolIssuance), 'configured');
  assert.deepEqual(
    await requests.resolveForModal(liveToolRequest, ID),
    { channel: toolChannel, provider: toolProvider },
  );
});

test('two replicas: offboarding fences an already-open channel credential form', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const vaultA = new Vault(dbA, KEY);
  const store = new ChannelProvisioningRequests(dbA, vaultA);
  const requestId = await store.issue(
    ID,
    'C1',
    'revocable',
    await vaultA.userProvisioningIssuedAt(),
  );
  assert.ok(requestId);
  const realLock = vaultA.withCredentialLock.bind(vaultA);
  let entered!: () => void;
  let release!: () => void;
  const beforeLock = new Promise<void>((resolve) => { entered = resolve; });
  const resume = new Promise<void>((resolve) => { release = resolve; });
  vaultA.withCredentialLock = (async (...args: Parameters<Vault['withCredentialLock']>) => {
    entered();
    await resume;
    return realLock(...args);
  }) as Vault['withCredentialLock'];

  const writing = configureChannelCredential({
    vault: vaultA,
    audit: new Audit(dbA),
    channelConfig: new ChannelConfig(dbA),
    identity: ID,
    channel: 'C1',
    providerId: 'revocable',
    issuance: store.issuance(requestId, ID, 'C1', 'revocable'),
    credential: {
      kind: 'secret',
      token: {
        accessToken: 'STALE_CHANNEL_KEY',
        refreshToken: null,
        scopes: '',
        expiresAt: null,
        externalAccount: null,
      },
    },
    modeConflict: (mode) => { throw new Error(`unexpected mode ${mode}`); },
  });
  await beforeLock;
  await offboardUser(new Vault(dbB, KEY), new Audit(dbB), new Consent(dbB), ID);
  release();

  assert.equal(await writing, false);
  assert.equal(await vaultA.has(channelOwner(ID.teamId, 'C1'), 'revocable'), false);
  assert.equal(
    (await dbA.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`))?.n,
    0,
  );
});

test('channel KMS preparation does not hold the acting admin offboard fence', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  // PostgreSQL advisory locks are database-global, while the test suite isolates state by schema.
  // Use a unique identity so another parallel schema exercising the common T1/U1 tuple cannot
  // transiently own this probe's otherwise-unrelated lock and make the try-lock assertion flaky.
  const admin: SlackIdentity = {
    enterpriseId: null,
    teamId: `T_KMS_${randomBytes(6).toString('hex')}`,
    userId: 'U_ADMIN',
  };
  let wrapStarted!: () => void;
  let releaseWrap!: () => void;
  const atWrap = new Promise<void>((resolve) => { wrapStarted = resolve; });
  const resumeWrap = new Promise<void>((resolve) => { releaseWrap = resolve; });
  const envelope: EnvelopeProvider = {
    wrapDataKey: async (dek) => {
      wrapStarted();
      await resumeWrap;
      return Buffer.from(dek);
    },
    unwrapDataKey: async (wrapped) => Buffer.from(wrapped),
  };
  const vaultA = new Vault(dbA, KEY, {}, envelope);
  const requests = new ChannelProvisioningRequests(dbA, vaultA);
  const requestId = await requests.issue(
    admin,
    'C1',
    'revocable',
    await vaultA.userProvisioningIssuedAt(),
  );
  assert.ok(requestId);
  const configuring = configureChannelCredential({
    vault: vaultA,
    audit: new Audit(dbA),
    channelConfig: new ChannelConfig(dbA),
    identity: admin,
    channel: 'C1',
    providerId: 'revocable',
    issuance: requests.issuance(requestId, admin, 'C1', 'revocable'),
    credential: {
      kind: 'secret',
      token: {
        accessToken: 'CHANNEL_KMS_KEY',
        refreshToken: null,
        scopes: '',
        expiresAt: null,
        externalAccount: null,
      },
    },
    modeConflict: (mode) => { throw new Error(`unexpected mode ${mode}`); },
  });
  await atWrap;

  const lock = await dbB.transaction!((tx) => tx.get<{ acquired: boolean }>(
    `SELECT pg_try_advisory_xact_lock(hashtext(?)) AS acquired`,
    [offboardLockKey(admin.teamId, admin.userId)],
  ));
  const acquired = lock?.acquired === true;
  try {
    if (acquired) {
      await offboardUser(new Vault(dbB, KEY), new Audit(dbB), new Consent(dbB), admin);
    }
  } finally {
    releaseWrap();
  }

  const configured = await configuring;
  assert.equal(acquired, true, 'external KMS work must happen before the offboard lock');
  assert.equal(configured, false);
  assert.equal(await vaultA.has(channelOwner(admin.teamId, 'C1'), 'revocable'), false);
  assert.equal(
    (await dbA.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`))?.n,
    0,
  );
});

test('OAuth credential and connect audit commit or roll back together', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const consent = new Consent(db);
  const audit = new Audit(db);
  const registry = new ProviderRegistry([revocable]);
  const pending = await consent.begin(ID, revocable, 'https://cb.example/x', null);
  (audit as any).record = async () => { throw new Error('audit unavailable'); };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(
    JSON.stringify({ access_token: 'ROLLBACK_TEST_TOKEN' }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  )) as any;
  try {
    const result = await handleOAuthCallback(
      { registry, vault, audit, consent, redirectUri: 'https://cb.example/x' },
      'CODE',
      pending.state,
    );
    assert.equal(result.ok, false);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(await countConnections(db), 0);
  assert.equal((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit`))?.n, 0);
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

  // A NEW consent begun after offboarding (legitimate re-onboarding) works immediately. Both the
  // tombstone and consent use PostgreSQL clock time, so exact ordering replaces the retired pod-skew
  // margin and no application-clock manipulation can affect authority.
  const again = await consent.begin(ID, revocable, 'https://cb.example/x', null);
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'NEW_TOK' }), { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    const res = await handleOAuthCallback({ registry, vault, audit, consent, redirectUri: 'https://cb.example/x' }, 'CODE', again.state);
    assert.equal(res.ok, true);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(await countConnections(db), 1); // re-onboarding is not bricked
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

test('break-glass revoke during token exchange invalidates the old OAuth write but permits a fresh flow', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const vault = new Vault(dbA, KEY);
  const audit = new Audit(dbA);
  const consent = new Consent(dbA);
  const registry = new ProviderRegistry([revocable]);
  const { state } = await consent.begin(ID, revocable, 'https://cb.example/x', null);
  const realFetch = globalThis.fetch;
  let revokeDuringExchange = true;
  globalThis.fetch = (async () => {
    if (revokeDuringExchange) {
      revokeDuringExchange = false;
      await purgePendingForProvider(
        dbB,
        { provider: 'revocable' },
        { providerRegistered: true },
      );
    }
    return new Response(
      JSON.stringify({ access_token: 'POST_REVOKE_TOKEN' }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as any;
  try {
    const result = await handleOAuthCallback(
      { registry, vault, audit, consent, redirectUri: 'https://cb.example/x' },
      'CODE',
      state,
    );
    assert.deepEqual(result, {
      ok: false,
      status: 409,
      error: 'Connection setup changed while authorization was completing. Start a new connection request.',
    });
    assert.equal(await countConnections(dbA), 0);
    assert.equal(
      (await dbA.get<{ n: number }>(
        `SELECT COUNT(*)::int AS n FROM audit WHERE action='connect'`,
      ))?.n,
      0,
    );
    const denied = await dbA.get<{ meta: string }>(
      `SELECT meta FROM audit WHERE action='denied' ORDER BY at DESC LIMIT 1`,
    );
    assert.deepEqual(JSON.parse(denied?.meta ?? '{}'), { reason: 'revoked' });

    await new Promise((resolve) => setTimeout(resolve, 5));
    const fresh = await consent.begin(ID, revocable, 'https://cb.example/x', null);
    const freshResult = await handleOAuthCallback(
      { registry, vault, audit, consent, redirectUri: 'https://cb.example/x' },
      'NEW_CODE',
      fresh.state,
    );
    assert.equal(freshResult.ok, true);
    assert.equal(await countConnections(dbA), 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('dry-run OAuth uses the same offboard fence after state consumption', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(() => Promise.all([dbA.close(), dbB.close()]));
  const vaultA = new Vault(dbA, KEY);
  const consent = new Consent(dbA, true);
  const audit = new Audit(dbA);
  const registry = new ProviderRegistry([revocable]);
  const pending = await consent.begin(ID, revocable, 'https://cb.example/x', null);

  const realWrite = vaultA.upsertDryRunUser.bind(vaultA);
  vaultA.upsertDryRunUser = (async (...args: Parameters<Vault['upsertDryRunUser']>) => {
    await offboardUser(new Vault(dbB, KEY), new Audit(dbB), new Consent(dbB), ID);
    return realWrite(...args);
  }) as Vault['upsertDryRunUser'];

  const result = await handleOAuthCallback(
    { registry, vault: vaultA, audit, consent, redirectUri: 'https://cb.example/x', dryRun: true },
    DRY_RUN_CODE,
    pending.state,
  );
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
  assert.equal(await countConnections(dbA), 0);
  assert.equal((await dbA.get<any>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='connect'`)).n, 0);
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

test('repeated team and global offboarding never move an existing tombstone backward', async (t) => {
  const db = await openTestDb(t);
  const future = Date.now() + 60_000;
  const identity = { enterpriseId: null, teamId: 'T_MONOTONIC', userId: 'U_MONOTONIC' };
  await db.run(
    `INSERT INTO offboard_tombstone (team_id, user_id, created_at) VALUES (?,?,?)`,
    [identity.teamId, identity.userId, future],
  );
  await new Consent(db).markOffboarded(identity);
  assert.equal(
    (await db.get<{ created_at: number }>(
      `SELECT created_at FROM offboard_tombstone WHERE team_id=? AND user_id=?`,
      [identity.teamId, identity.userId],
    ))?.created_at,
    future,
  );

  await db.run(
    `INSERT INTO user_offboard_scope_tombstone
       (scope_kind, scope_id, user_id, created_at) VALUES ('global','',?,?)`,
    [identity.userId, future],
  );
  assert.deepEqual(
    await offboardUserEverywhere(
      db,
      new Vault(db, KEY),
      new Audit(db),
      new Consent(db),
      { userId: identity.userId },
    ),
    [],
  );
  assert.equal(
    (await db.get<{ created_at: number }>(
      `SELECT created_at FROM user_offboard_scope_tombstone
       WHERE scope_kind='global' AND scope_id='' AND user_id=?`,
      [identity.userId],
    ))?.created_at,
    future,
  );
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

test('offboardUserEverywhere discovers a team represented only by channel setup authority', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const identity = { enterpriseId: 'E1', teamId: 'T_MODAL', userId: 'U_MODAL' };
  const requests = new ChannelProvisioningRequests(db, vault);
  assert.ok(await requests.issue(
    identity,
    'C_MODAL',
    'revocable',
    await vault.userProvisioningIssuedAt(),
  ));

  const summary = await offboardUserEverywhere(
    db,
    vault,
    new Audit(db),
    new Consent(db),
    { enterpriseId: identity.enterpriseId, userId: identity.userId },
  );
  assert.deepEqual(summary, [{ teamId: identity.teamId, providers: [], ok: true }]);
  assert.equal(
    (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM channel_provisioning_request`))?.n,
    0,
  );
});

test('two replicas: enterprise offboard waits for a scope-locked write, then discovers and deletes it', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([openDb({ databaseUrl: url }), openDb({ databaseUrl: url })]);
  t.after(() => Promise.all([dbA.close(), dbB.close()]));
  const vaultA = new Vault(dbA, KEY);
  const identity = { enterpriseId: 'E_RACE', teamId: 'T_RACE', userId: 'U_RACE' };
  const owner = userOwner(identity);
  const issuedAt = await vaultA.userProvisioningIssuedAt();
  let writeReachedAudit!: () => void;
  let releaseWrite!: () => void;
  const atAudit = new Promise<void>((resolve) => { writeReachedAudit = resolve; });
  const resumeWrite = new Promise<void>((resolve) => { releaseWrite = resolve; });
  const configAudit = new Audit(dbA);

  const writing = vaultA.upsertUser(
    owner,
    'revocable',
    {
      accessToken: 'ENTERPRISE_RACE_KEY',
      refreshToken: null,
      scopes: '',
      expiresAt: null,
      externalAccount: null,
    },
    issuedAt,
    async (tx) => {
      // The connection exists inside replica A's transaction while its credential + enterprise
      // scope locks remain held. Keep it there until replica B has attempted the cross-team fence.
      writeReachedAudit();
      await resumeWrite;
      await configAudit.record(
        'config',
        identity,
        'revocable',
        { owner: 'user', kind: 'secret' },
        undefined,
        tx,
      );
    },
  );
  await atAudit;

  let offboardSettled = false;
  const offboarding = offboardUserEverywhere(
    dbB,
    new Vault(dbB, KEY),
    new Audit(dbB),
    new Consent(dbB),
    { enterpriseId: identity.enterpriseId, userId: identity.userId },
  );
  void offboarding.then(
    () => { offboardSettled = true; },
    () => { offboardSettled = true; },
  );
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(offboardSettled, false, 'cross-team offboard waits on the held enterprise scope lock');

  releaseWrite();
  assert.equal(await writing, 'stored');
  assert.deepEqual(await offboarding, [{ teamId: 'T_RACE', providers: ['revocable'], ok: true }]);
  assert.equal(await vaultA.has(owner, 'revocable'), false);
});

test('cross-team tombstones distinguish enterprise, unscoped, and global provisioning', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const token = {
    accessToken: 'SCOPE_TEST_KEY',
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: null,
  };
  const e1 = { enterpriseId: 'E1', teamId: 'T_E1_EMPTY', userId: 'U_SCOPE' };
  const unscoped = { enterpriseId: null, teamId: 'T_NULL_EMPTY', userId: 'U_SCOPE' };
  const e2 = { enterpriseId: 'E2', teamId: 'T_E2_EMPTY', userId: 'U_SCOPE' };
  const [oldE1, oldUnscoped, oldE2] = await Promise.all([
    vault.userProvisioningIssuedAt(),
    vault.userProvisioningIssuedAt(),
    vault.userProvisioningIssuedAt(),
  ]);

  assert.deepEqual(
    await offboardUserEverywhere(db, vault, audit, consent, { enterpriseId: 'E1', userId: 'U_SCOPE' }),
    [],
    'all three teams are artifact-free at the enterprise offboard snapshot',
  );
  assert.equal(await vault.upsertUser(userOwner(e1), 'revocable', token, oldE1), 'offboarded');
  assert.equal(
    await vault.upsertUser(userOwner(unscoped), 'revocable', token, oldUnscoped),
    'offboarded',
    'enterprise offboard conservatively fences legacy NULL-enterprise authority',
  );
  assert.equal(
    await vault.upsertUser(userOwner(e2), 'revocable', token, oldE2),
    'stored',
    'an E1 tombstone must not deny the same user id in named enterprise E2',
  );
  await assert.rejects(
    vault.upsertUser(
      userOwner({ enterpriseId: '', teamId: 'T_EMPTY_ENTERPRISE', userId: 'U_SCOPE' }),
      'revocable',
      token,
      oldE1,
    ),
    /enterprise offboard scope is invalid/,
    'an empty signed enterprise id cannot select an impossible scope and bypass the fence',
  );
  assert.deepEqual(
    await db.all<{ scope_kind: string; scope_id: string }>(
      `SELECT scope_kind, scope_id FROM user_offboard_scope_tombstone
       WHERE user_id='U_SCOPE' ORDER BY scope_kind`,
    ),
    [
      { scope_kind: 'enterprise', scope_id: 'E1' },
      { scope_kind: 'unscoped', scope_id: '' },
    ],
  );

  const globalE = { enterpriseId: 'E1', teamId: 'T_GLOBAL_E', userId: 'U_GLOBAL' };
  const globalNull = { enterpriseId: null, teamId: 'T_GLOBAL_NULL', userId: 'U_GLOBAL' };
  const [oldGlobalE, oldGlobalNull] = await Promise.all([
    vault.userProvisioningIssuedAt(),
    vault.userProvisioningIssuedAt(),
  ]);
  assert.deepEqual(
    await offboardUserEverywhere(db, vault, audit, consent, { userId: 'U_GLOBAL' }),
    [],
  );
  assert.equal(await vault.upsertUser(userOwner(globalE), 'revocable', token, oldGlobalE), 'offboarded');
  assert.equal(await vault.upsertUser(userOwner(globalNull), 'revocable', token, oldGlobalNull), 'offboarded');

  const globalTombstone = await db.get<{ created_at: number }>(
    `SELECT created_at FROM user_offboard_scope_tombstone
     WHERE scope_kind='global' AND scope_id='' AND user_id='U_GLOBAL'`,
  );
  assert.ok(globalTombstone);
  await new Promise((resolve) => setTimeout(resolve, 2));
  const fresh = await vault.userProvisioningIssuedAt();
  assert.ok(fresh > globalTombstone.created_at);
  assert.equal(
    await vault.upsertUser(userOwner(globalE), 'revocable', token, fresh),
    'stored',
    'a PostgreSQL-issued request after the global tombstone is legitimate re-onboarding',
  );
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
    transaction: (fn: (tx: any) => Promise<unknown>) => db.transaction!((tx) => fn({
      get: (sql: string, params?: unknown[]) =>
        sql.includes('DELETE FROM connection') && (params as any[])?.includes('T1')
          ? Promise.reject(new Error('T1 connection table down'))
          : tx.get(sql, params as any[]),
      all: tx.all.bind(tx),
      exec: tx.exec.bind(tx),
      close: tx.close.bind(tx),
      transaction: tx.transaction?.bind(tx),
      run: tx.run.bind(tx),
    })),
  } as any;
  const vault = new Vault(flakyDb, KEY);
  const summary = await offboardUserEverywhere(db, vault, new Audit(db), new Consent(db), { userId: ID.userId });
  const byTeam = new Map(summary.map((s) => [s.teamId, s.ok]));
  assert.equal(byTeam.get('T1'), false); // failure surfaced, not buried
  assert.equal(byTeam.get('T2'), true); // the other workspace still offboarded
  assert.equal(await countConnections(db), 1); // only T1's row remains (its delete failed)
});
