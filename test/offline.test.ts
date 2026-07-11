import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { encrypt, decrypt, sha256base64url } from '../src/core/crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ConnectionHandle } from '../src/core/injector';
import { resolveIdentity } from '../src/adapters/slack-identity';
import { Policy } from '../src/core/policy';
import { github, google, gitlab, notion, defineProvider, ProviderRegistry } from '../src/core/providers';
import { exchangeCode } from '../src/core/tokens';
import { offboardUser } from '../src/core/offboard';
import { sweepExpired } from '../src/core/sweep';
import { UnionOptin } from '../src/core/unionOptin';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);
const O2 = userOwner({ ...ID, userId: 'U2' });

test('crypto: AES-GCM round-trips and tampering fails', () => {
  const blob = encrypt('ghp_secret_value', KEY);
  assert.equal(decrypt(blob, KEY), 'ghp_secret_value');
  assert.ok(!blob.toString('utf8').includes('ghp_secret_value')); // ciphertext, not plaintext
  blob[blob.length - 1] ^= 0xff; // tamper
  assert.throws(() => decrypt(blob, KEY));
});

test('crypto: PKCE challenge is stable base64url', () => {
  assert.equal(sha256base64url('abc'), sha256base64url('abc'));
  assert.match(sha256base64url('abc'), /^[A-Za-z0-9_-]+$/);
});

test('vault: tokens are stored encrypted and round-trip by Slack identity', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  assert.equal(await vault.get(O1, 'github'), null);
  await vault.upsert(O1, 'github', {
    accessToken: 'tok_a',
    refreshToken: 'tok_r',
    scopes: 'repo',
    expiresAt: null,
    externalAccount: 'octocat',
  });
  const got = await vault.get(O1, 'github');
  assert.equal(got?.accessToken, 'tok_a');
  assert.equal(got?.externalAccount, 'octocat');

  // Stored ciphertext must not contain the plaintext token.
  const raw = await db.get('SELECT access_token_enc FROM connection') as any;
  assert.ok(!Buffer.from(raw.access_token_enc).toString('utf8').includes('tok_a'));

  // Different user => no leakage across identities.
  assert.equal(await vault.get(O2, 'github'), null);
  await vault.delete(O1, 'github');
  assert.equal(await vault.get(O1, 'github'), null);
});

test('consent: state is single-use and expires', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const consent = new Consent(db);
  const provider = github({ clientId: 'cid', clientSecret: 'csec' });
  const { state, authorizeUrl } = await consent.begin(ID, provider, 'https://x/cb', 'C1');
  assert.match(authorizeUrl, /response_type=code/);
  assert.match(authorizeUrl, /state=/);

  const row = await consent.consume(state);
  assert.equal(row?.identity.userId, 'U1');
  assert.equal(row?.provider, 'github');
  // Single-use: second consume returns null.
  assert.equal(await consent.consume(state), null);
});

test('providers: ANY OAuth2 provider works via generic defineProvider', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const consent = new Consent(db);
  // A provider Vouchr ships nothing for, defined in ~10 lines by the user.
  const acme = defineProvider({
    id: 'acme',
    authorizeUrl: 'https://acme.example/oauth/authorize',
    tokenUrl: 'https://acme.example/oauth/token',
    scopesDefault: ['read', 'write'],
    egressAllow: ['api.acme.example'],
    refresh: 'rotating',
    pkce: true,
    authorizeParams: { access_type: 'offline' },
    clientId: 'id',
    clientSecret: 'sec',
  });
  const { authorizeUrl } = await consent.begin(ID, acme, 'https://x/cb', 'C1');
  const u = new URL(authorizeUrl);
  assert.equal(u.origin + u.pathname, 'https://acme.example/oauth/authorize');
  assert.equal(u.searchParams.get('client_id'), 'id');
  assert.equal(u.searchParams.get('scope'), 'read write');
  assert.equal(u.searchParams.get('access_type'), 'offline'); // provider-specific param
  assert.ok(u.searchParams.get('code_challenge')); // PKCE applied
});

test('providers: registry resolves multiple built-ins, not just github', () => {
  const reg = new ProviderRegistry([
    github({ clientId: 'a', clientSecret: 'b' }),
    google({ clientId: 'a', clientSecret: 'b' }),
    gitlab({ clientId: 'a', clientSecret: 'b' }),
  ]);
  assert.ok(reg.has('github') && reg.has('google') && reg.has('gitlab'));
  assert.equal(reg.get('google').refresh, 'rotating');
  assert.equal(reg.get('google').authorizeParams?.access_type, 'offline');
  assert.throws(() => reg.get('nope'), /Unknown provider/);
});

test('tokens: client auth + body format honor the provider (Basic+JSON vs body+form)', async () => {
  const realFetch = globalThis.fetch;
  const calls: any[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ access_token: 'AT' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as any;
  try {
    // Notion-style: Basic auth header, JSON body, no creds in the body.
    await exchangeCode(notion({ clientId: 'cid', clientSecret: 'csec' }), 'CODE', 'https://cb', 'v');
    let { init } = calls[0];
    assert.equal(init.headers.Authorization, `Basic ${Buffer.from('cid:csec').toString('base64')}`);
    assert.equal(init.headers['Content-Type'], 'application/json');
    let body = JSON.parse(init.body);
    assert.equal(body.code, 'CODE');
    assert.equal(body.client_id, undefined); // creds are in the header, not the body

    // GitHub-style (defaults): form body carries the creds, no Authorization header.
    await exchangeCode(github({ clientId: 'cid', clientSecret: 'csec' }), 'CODE', 'https://cb', 'v');
    ({ init } = calls[1]);
    assert.equal(init.headers.Authorization, undefined);
    assert.equal(init.headers['Content-Type'], 'application/x-www-form-urlencoded');
    const form = new URLSearchParams(init.body);
    assert.equal(form.get('client_secret'), 'csec');
    assert.equal(form.get('code'), 'CODE');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('tokens: provider-supplied OAuth error text is not propagated', async () => {
  const realFetch = globalThis.fetch;
  const leaked = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  globalThis.fetch = (async () => new Response(JSON.stringify({
    error: 'invalid_grant',
    error_description: `provider echoed ${leaked}`,
  }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })) as any;
  try {
    await assert.rejects(
      () => exchangeCode(github({ clientId: 'cid', clientSecret: 'csec' }), 'CODE', 'https://cb', 'v'),
      (e: any) => {
        assert.match(e.message, /OAuth error/);
        assert.ok(!e.message.includes(leaked));
        assert.ok(!e.message.includes('provider echoed'));
        return true;
      },
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('injector: egress allowlist blocks disallowed hosts before any token use', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const provider = github({ clientId: 'cid', clientSecret: 'csec' });
  await vault.upsert(O1, 'github', {
    accessToken: 'tok',
    refreshToken: null,
    scopes: 'repo',
    expiresAt: null,
    externalAccount: null,
  });
  const handle = new ConnectionHandle(provider, O1, ID, vault, audit);
  await assert.rejects(() => handle.fetch('https://evil.example.com/steal'), /Egress blocked/);
});

test('injector: blocks cleartext http to an allowlisted host (no bearer over the wire)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const provider = github({ clientId: 'cid', clientSecret: 'csec' }); // egressAllow includes api.github.com
  await vault.upsert(O1, 'github', { accessToken: 'tok', refreshToken: null, scopes: 'repo', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(provider, O1, ID, vault, audit);
  await assert.rejects(() => handle.fetch('http://api.github.com/user'), /requires https/);
});

test('injector: concurrent fetches share a single token refresh (no rotating-token brick)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const provider = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
    clientId: 'id', clientSecret: 'sec',
  });
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });

  const realFetch = globalThis.fetch;
  let tokenCalls = 0;
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url) === 'https://acme.example/token') {
      tokenCalls++;
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    const auth = new Headers(init.headers).get('authorization');
    if (auth === 'Bearer old') return new Response('expired', { status: 401 });
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const inflight = new Map<string, Promise<string | null>>();
    const h = () => new ConnectionHandle(provider, O1, ID, vault, audit, {}, inflight);
    const [a, b] = await Promise.all([h().fetch('https://api.acme.example/x'), h().fetch('https://api.acme.example/y')]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.equal(tokenCalls, 1); // both 401s collapsed into one refresh
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('injector: refreshes on 401, retries with the new token, and persists it', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const provider = defineProvider({
    id: 'acme',
    authorizeUrl: 'https://acme.example/auth',
    tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'],
    egressAllow: ['api.acme.example'],
    refresh: 'rotating',
    pkce: true,
    clientId: 'id',
    clientSecret: 'sec',
  });
  await vault.upsert(O1, 'acme', {
    accessToken: 'old',
    refreshToken: 'r1',
    scopes: 'x',
    expiresAt: null,
    externalAccount: null,
  });

  const realFetch = globalThis.fetch;
  let apiCalls = 0;
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url) === 'https://acme.example/token') {
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    apiCalls++;
    const auth = new Headers(init.headers).get('authorization'); // injector now passes a Headers instance
    if (auth === 'Bearer old') return new Response('expired', { status: 401 });
    return new Response(JSON.stringify({ saw: auth }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as any;
  try {
    const handle = new ConnectionHandle(provider, O1, ID, vault, audit);
    const res = await handle.fetch('https://api.acme.example/thing');
    assert.equal(res.status, 200);
    assert.equal(apiCalls, 2); // first 401, retried after refresh
    assert.equal((await res.json()).saw, 'Bearer new');
    assert.equal((await vault.get(O1, 'acme'))?.accessToken, 'new'); // rotated token persisted
    assert.equal((await vault.get(O1, 'acme'))?.refreshToken, 'r2');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('injector: an audit failure during refresh does NOT roll back or fail the rotation', async () => {
  // The provider consumes (rotates) the old refresh token during /token, so audit must run AFTER the
  // refresh commits and be best-effort — otherwise a thrown audit write would undo the stored new
  // token and leave us holding an already-invalidated refresh token (bricked connection).
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const brokenAudit = {
    record: async (action: string) => { if (action === 'refresh') throw new Error('audit sink down'); },
  } as unknown as Audit;
  const provider = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true, clientId: 'id', clientSecret: 'sec',
  });
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url) === 'https://acme.example/token') {
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const auth = new Headers(init.headers).get('authorization');
    if (auth === 'Bearer old') return new Response('expired', { status: 401 });
    return new Response(JSON.stringify({ saw: auth }), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const handle = new ConnectionHandle(provider, O1, ID, vault, brokenAudit);
    const res = await handle.fetch('https://api.acme.example/thing'); // must not throw despite audit failure
    assert.equal(res.status, 200);
    assert.equal((await res.json()).saw, 'Bearer new');
    assert.equal((await vault.get(O1, 'acme'))?.accessToken, 'new'); // rotation survived the audit failure
    assert.equal((await vault.get(O1, 'acme'))?.refreshToken, 'r2');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('injector: the /token refresh fetch is given a bounded (10s) abort signal', async () => {
  // A refresh runs while holding the advisory lock + refresh-pool connection; without a timeout a hung
  // /token endpoint would pin both. Assert the signal is armed (~10s) — captured, not waited on.
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const provider = defineProvider({
    id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
    scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true, clientId: 'id', clientSecret: 'sec',
  });
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });

  const realFetch = globalThis.fetch;
  const realTimeout = AbortSignal.timeout;
  let tokenSignalMs = -1;
  (AbortSignal as any).timeout = (ms: number) => { tokenSignalMs = ms; return realTimeout.call(AbortSignal, ms); };
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url) === 'https://acme.example/token') {
      assert.ok(init.signal instanceof AbortSignal); // the refresh fetch carries an abort signal
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const auth = new Headers(init.headers).get('authorization');
    if (auth === 'Bearer old') return new Response('expired', { status: 401 });
    return new Response(JSON.stringify({ saw: auth }), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const res = await new ConnectionHandle(provider, O1, ID, vault, audit).fetch('https://api.acme.example/thing');
    assert.equal(res.status, 200);
    assert.equal(tokenSignalMs, 10_000); // TOKEN_FETCH_TIMEOUT_MS — bounded, not unbounded
  } finally {
    globalThis.fetch = realFetch;
    (AbortSignal as any).timeout = realTimeout;
  }
});

test('vault: list returns a user\'s connected providers, isolated per identity', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'github', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'octocat' });
  await vault.upsert(O1, 'google', { accessToken: 'b', refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'me@x.com' });
  await vault.upsert(O2, 'github', { accessToken: 'c', refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'other' });
  const mine = (await vault.listForUser(ID)).map((c) => c.provider).sort();
  assert.deepEqual(mine, ['github', 'google']);
  assert.equal((await vault.listForUser({ ...ID, userId: 'U2' })).length, 1);
});

const FRESH = { accessToken: 't', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null };

test('vault TTL: idle and max-age expiry; touch resets idle; empty policy never expires', async () => {
  // idle timeout
  const db1 = await openDb({ dbPath: ':memory:' });
  const idleVault = new Vault(db1, KEY, { idleMs: 1000 });
  await idleVault.upsert(O1, 'github', FRESH);
  assert.ok(await idleVault.get(O1, 'github')); // fresh
  await db1.run('UPDATE connection SET last_used_at=? WHERE provider=?', [Date.now() - 5000, 'github']);
  assert.equal(await idleVault.get(O1, 'github'), null); // idle-expired
  await idleVault.touch(O1, 'github');
  assert.ok(await idleVault.get(O1, 'github')); // touch reset the idle clock

  // absolute max-age (expires even if recently used)
  const db2 = await openDb({ dbPath: ':memory:' });
  const ageVault = new Vault(db2, KEY, { maxAgeMs: 1000 });
  await ageVault.upsert(O1, 'github', FRESH);
  await db2.run('UPDATE connection SET created_at=? WHERE provider=?', [Date.now() - 5000, 'github']);
  assert.equal(await ageVault.get(O1, 'github'), null);

  // empty policy never expires
  const db3 = await openDb({ dbPath: ':memory:' });
  const noVault = new Vault(db3, KEY, {});
  await noVault.upsert(O1, 'github', FRESH);
  await db3.run('UPDATE connection SET created_at=?, last_used_at=? WHERE provider=?', [1, 1, 'github']);
  assert.ok(await noVault.get(O1, 'github'));
});

test('vault.updateTokens preserves created_at so refresh cannot defeat max-age TTL', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, { maxAgeMs: 1000 });
  await vault.upsert(O1, 'github', FRESH);
  await db.run('UPDATE connection SET created_at=? WHERE provider=?', [Date.now() - 5000, 'github']);
  // A silent refresh updates the token but must NOT reset the birth time.
  await vault.updateTokens(O1, 'github', { accessToken: 'new', refreshToken: 'r2', scopes: '', expiresAt: null });
  assert.equal(await vault.get(O1, 'github'), null); // still max-age expired
});

test('sweepExpired deletes past-TTL connections and audits them', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, { idleMs: 1000 });
  const audit = new Audit(db);
  const consent = new Consent(db);
  await vault.upsert(O1, 'github', FRESH);
  await vault.upsert(O1, 'google', FRESH);
  await db.run('UPDATE connection SET last_used_at=? WHERE provider=?', [Date.now() - 5000, 'github']);
  assert.equal(await sweepExpired(vault, audit, consent), 1);
  assert.deepEqual((await vault.listForUser(ID)).map((c) => c.provider), ['google']); // only the stale one swept
});

// #192: a reconnect between the sweep's snapshot and its delete must survive — the delete is
// conditional on the row STILL being expired, and nothing is audited/notified for the fresh row.
test('sweepExpired: a reconnect after the expiry snapshot survives the sweep (no delete, no audit, no event)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, { idleMs: 1000 });
  const audit = new Audit(db);
  const consent = new Consent(db);
  await vault.upsert(O1, 'github', FRESH);
  await db.run('UPDATE connection SET last_used_at=?, created_at=? WHERE provider=?', [Date.now() - 5000, Date.now() - 5000, 'github']);
  // Barrier: interpose on listExpired so the reconnect lands AFTER the snapshot, BEFORE the delete.
  const snapshot = vault.listExpired.bind(vault);
  (vault as any).listExpired = async () => {
    const rows = await snapshot();
    await vault.upsert(O1, 'github', FRESH); // the user reconnects mid-sweep
    return rows;
  };
  const events: any[] = [];
  assert.equal(await sweepExpired(vault, audit, consent, undefined, undefined, (e) => events.push(e)), 0);
  assert.deepEqual((await vault.listForUser(ID)).map((c) => c.provider), ['github']); // fresh row survived
  assert.notEqual(await vault.get(O1, 'github'), null); // and is live, satellites untouched
  assert.equal(((await db.all(`SELECT * FROM audit WHERE action='revoke'`)) as any[]).length, 0, 'no expired audit row');
  assert.equal(events.filter((e) => e.type === 'expired').length, 0, 'no expired health event');
});

// #192 review r1: a union-channel reconnect (upsert + joinUnion) racing the sweep keeps its FRESH
// opt-in — the opt-in postdates the purge inside deleteExpired's satellite boundary.
test('sweepExpired: a reconnect + re-opt-in after the atomic delete keeps its fresh union opt-in', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, { idleMs: 1000 });
  const optin = new UnionOptin(db);
  await vault.upsert(O1, 'github', FRESH);
  await optin.join(ID, 'C1', 'github'); // an OLD opt-in exists on the expiring credential
  await db.run('UPDATE connection SET last_used_at=?, created_at=? WHERE provider=?', [Date.now() - 5000, Date.now() - 5000, 'github']);
  // Barrier: interpose on deleteExpired so the reconnect + fresh opt-in land right after it.
  const realDelete = vault.deleteExpired.bind(vault);
  (vault as any).deleteExpired = async (owner: any, provider: string) => {
    const deleted = await realDelete(owner, provider);
    await vault.upsert(O1, 'github', FRESH); // the OAuth reconnect (union channel)…
    await optin.join(ID, 'C1', 'github'); // …and its auto re-opt-in (joinUnion path)
    return deleted;
  };
  assert.equal(await sweepExpired(vault, new Audit(db), new Consent(db)), 1); // the stale row WAS swept
  assert.ok((await optin.optedIn(ID.teamId, 'C1', 'github')).has(ID.userId), 'fresh opt-in survived the stale sweep');
  assert.notEqual(await vault.get(O1, 'github'), null); // fresh credential intact
});

// #192 review r2: a DM/non-union reconnect racing the sweep does NOT resurrect the OLD opt-in —
// delegation consent belongs to one credential generation, and the fresh credential has none.
test('sweepExpired: a DM reconnect (no re-opt-in) does not inherit the pre-expiry union opt-in', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, { idleMs: 1000 });
  const optin = new UnionOptin(db);
  await vault.upsert(O1, 'github', FRESH);
  await optin.join(ID, 'C1', 'github'); // the OLD delegation consent
  await db.run('UPDATE connection SET last_used_at=?, created_at=? WHERE provider=?', [Date.now() - 5000, Date.now() - 5000, 'github']);
  const realDelete = vault.deleteExpired.bind(vault);
  (vault as any).deleteExpired = async (owner: any, provider: string) => {
    const deleted = await realDelete(owner, provider);
    await vault.upsert(O1, 'github', FRESH); // DM reconnect: no union channel, no joinUnion
    return deleted;
  };
  assert.equal(await sweepExpired(vault, new Audit(db), new Consent(db)), 1);
  assert.equal((await optin.optedIn(ID.teamId, 'C1', 'github')).size, 0, 'old opt-in did not survive into the new generation');
  assert.notEqual(await vault.get(O1, 'github'), null); // the fresh credential itself is intact
});

// #192 review r2: the satellite boundary also covers plain reconnects — an upsert purges the old
// generation's opt-ins (the union-channel callback re-adds one immediately via joinUnion).
test('vault.upsert purges the previous generation\'s union opt-ins', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const optin = new UnionOptin(db);
  await vault.upsert(O1, 'github', FRESH);
  await optin.join(ID, 'C1', 'github');
  await vault.upsert(O1, 'github', FRESH); // reconnect
  assert.equal((await optin.optedIn(ID.teamId, 'C1', 'github')).size, 0, 'delegation requires fresh opt-in after reconnect');
});

test('sweepExpired also clears abandoned consent requests', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, {});
  const audit = new Audit(db);
  const consent = new Consent(db);
  const { state } = await consent.begin(ID, github({ clientId: 'a', clientSecret: 'b' }), 'https://x/cb', null);
  await db.run('UPDATE consent_request SET created_at=? WHERE state=?', [1, state]); // ancient
  await sweepExpired(vault, audit, consent);
  assert.equal(await consent.consume(state), null); // gone
});

test('offboardUser removes connections + pending consent, idempotently, leaving others', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  await vault.upsert(O1, 'github', { ...FRESH, externalAccount: 'octocat' });
  await vault.upsert(O1, 'google', FRESH);
  await vault.upsert(O2, 'github', FRESH);
  // an in-flight consent for the user that must NOT survive offboarding
  const { state } = await consent.begin(ID, github({ clientId: 'a', clientSecret: 'b' }), 'https://x/cb', null);

  assert.deepEqual((await offboardUser(vault, audit, consent, ID)).sort(), ['github', 'google']);
  assert.equal((await vault.listForUser(ID)).length, 0);
  assert.equal(await consent.consume(state), null); // pending consent purged (no resurrection)
  assert.equal((await vault.listForUser({ ...ID, userId: 'U2' })).length, 1); // other user untouched
  assert.deepEqual(await offboardUser(vault, audit, consent, ID), []); // idempotent
});

test('identity: resolves actor over installer and needs team+user', () => {
  assert.deepEqual(
    resolveIdentity({ context: { teamId: 'T1', actorUserId: 'U9' } }),
    { enterpriseId: null, teamId: 'T1', userId: 'U9' },
  );
  assert.equal(resolveIdentity({ context: { teamId: 'T1' } }), null);
});

test('policy: default allow, deny by channel, allowlist when default-deny', () => {
  const p = new Policy({
    payments: { defaultAllow: false, allowChannels: ['C_FIN'] },
    github: { defaultAllow: true, denyChannels: ['C_PUBLIC'] },
  });
  assert.equal(p.check('unknown', 'C1'), true); // no rule => allow
  assert.equal(p.check('payments', 'C1'), false);
  assert.equal(p.check('payments', 'C_FIN'), true);
  assert.equal(p.check('github', 'C_PUBLIC'), false);
  assert.equal(p.check('github', 'C1'), true);
});
