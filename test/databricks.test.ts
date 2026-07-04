import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ConnectionHandle } from '../src/core/injector';
import { databricks, defineProvider } from '../src/core/providers';
import { exchangeCode } from '../src/core/tokens';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

// Built-in Databricks provider (#106): per-user OAuth U2M, egress-locked to the SQL Statement
// Execution API. The security-critical guarantee is the egress lock — everything below the
// construction tests exercises it.

const HOST = 'https://dbc-test.cloud.databricks.com';
const HOSTNAME = 'dbc-test.cloud.databricks.com';
const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);

// ── construction / shape ──────────────────────────────────────────────────────

test('databricks: public client (no secret) is valid — PKCE-only, correct workspace-scoped URLs', () => {
  const p = databricks({ host: HOST, clientId: 'cid' });
  assert.equal(p.id, 'databricks');
  assert.equal(p.authorizeUrl, `${HOST}/oidc/v1/authorize`);
  assert.equal(p.tokenUrl, `${HOST}/oidc/v1/token`);
  assert.equal(p.pkce, true);
  assert.equal(p.publicClient, true, 'no secret → public client inferred');
  assert.equal(p.clientSecret, undefined);
  assert.deepEqual(p.scopesDefault, ['all-apis', 'offline_access']);
  assert.equal(p.refresh, 'rotating');
  assert.deepEqual(p.egressAllow, [HOSTNAME]);
  assert.deepEqual(p.egressPaths, ['/api/2.0/sql/statements']);
  assert.deepEqual(p.egressMethods, ['GET', 'POST']);
});

test('databricks: confidential client (with secret) is NOT flagged public', () => {
  const p = databricks({ host: HOST, clientId: 'cid', clientSecret: 'csec' });
  assert.equal(p.publicClient, false);
  assert.equal(p.clientSecret, 'csec');
});

test('databricks: a trailing slash on host does not double up the OAuth path; malformed host throws', () => {
  const p = databricks({ host: `${HOST}/`, clientId: 'cid' });
  assert.equal(p.authorizeUrl, `${HOST}/oidc/v1/authorize`);
  assert.throws(() => databricks({ host: 'not a url', clientId: 'cid' }));
  assert.throws(() => databricks({ host: '', clientId: 'cid' }), /host.*required/i);
});

test('databricks: an unsafe host is rejected — the token exchange is not behind the egress https gate', () => {
  // The OAuth code + any client secret are POSTed to `${host}/oidc/v1/token`; a http:// or
  // userinfo/path/query host would leak or misdirect that exchange. All must fail at construction.
  for (const bad of [
    'http://dbc-test.cloud.databricks.com',              // cleartext
    'http://dbc-test.cloud.databricks.com',              // non-https
    'https://user:pass@dbc-test.cloud.databricks.com',   // embedded credentials
    'https://dbc-test.cloud.databricks.com/some/path',   // path (would smuggle into the OAuth URL)
    'https://dbc-test.cloud.databricks.com/?x=1',        // query
    'https://dbc-test.cloud.databricks.com/#frag',       // fragment
  ]) {
    assert.throws(() => databricks({ host: bad, clientId: 'cid' }), /bare HTTPS workspace URL/i, `should reject ${bad}`);
  }
});

test('defineProvider: a public client cannot use Basic token auth (Basic carries a secret it lacks)', () => {
  assert.throws(
    () => defineProvider({
      id: 'x', authorizeUrl: 'https://h/a', tokenUrl: 'https://h/t', scopesDefault: [],
      egressAllow: ['h'], refresh: 'none', pkce: true, clientId: 'cid', publicClient: true, tokenAuth: 'basic',
    }),
    /public client.*Basic/i,
  );
});

test('databricks: callers can widen egress explicitly (jobs), overriding the statements-only default', () => {
  const p = databricks({ host: HOST, clientId: 'cid', egressPaths: ['/api/2.0/sql/statements', '/api/2.1/jobs/'] });
  assert.deepEqual(p.egressPaths, ['/api/2.0/sql/statements', '/api/2.1/jobs/']);
});

test('defineProvider: a public client with PKCE disabled is refused (no client authentication at all)', () => {
  assert.throws(
    () => defineProvider({
      id: 'x', authorizeUrl: 'https://h/a', tokenUrl: 'https://h/t', scopesDefault: [],
      egressAllow: ['h'], refresh: 'none', pkce: false, clientId: 'cid', publicClient: true,
    }),
    /public client.*PKCE/i,
  );
});

// ── authorize URL ─────────────────────────────────────────────────────────────

test('databricks: authorize URL carries client_id, PKCE challenge, and the U2M scopes', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const consent = new Consent(db);
  const p = databricks({ host: HOST, clientId: 'cid' });
  const { authorizeUrl } = await consent.begin(ID, p, 'https://app/cb', null);
  assert.ok(authorizeUrl.startsWith(`${HOST}/oidc/v1/authorize?`));
  const sp = new URL(authorizeUrl).searchParams;
  assert.equal(sp.get('client_id'), 'cid');
  assert.equal(sp.get('response_type'), 'code');
  assert.equal(sp.get('code_challenge_method'), 'S256');
  assert.ok(sp.get('code_challenge'), 'PKCE challenge present');
  assert.equal(sp.get('scope'), 'all-apis offline_access');
});

// ── token exchange: public omits client_secret; confidential sends it ──────────

test('databricks: public-client token exchange sends code_verifier and NO client_secret', async () => {
  const realFetch = globalThis.fetch;
  const calls: any[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ access_token: 'AT', refresh_token: 'RT' }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  }) as any;
  try {
    await exchangeCode(databricks({ host: HOST, clientId: 'cid' }), 'CODE', 'https://cb', 'verifier');
    const form = new URLSearchParams(calls[0].init.body);
    assert.equal(calls[0].url, `${HOST}/oidc/v1/token`);
    assert.equal(calls[0].init.headers.Authorization, undefined, 'public client uses no Basic header');
    assert.equal(form.get('client_id'), 'cid');
    assert.equal(form.get('client_secret'), null, 'public client must NOT send a client_secret');
    assert.equal(form.get('code_verifier'), 'verifier', 'PKCE verifier proves the client');
    assert.equal(form.get('grant_type'), 'authorization_code');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('databricks: confidential-client token exchange includes the client_secret', async () => {
  const realFetch = globalThis.fetch;
  const calls: any[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ access_token: 'AT' }), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    await exchangeCode(databricks({ host: HOST, clientId: 'cid', clientSecret: 'csec' }), 'CODE', 'https://cb', 'verifier');
    const form = new URLSearchParams(calls[0].init.body);
    assert.equal(form.get('client_secret'), 'csec');
    assert.equal(form.get('code_verifier'), 'verifier');
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ── egress lock (the point of the built-in) ───────────────────────────────────

async function makeHandle() {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const p = databricks({ host: HOST, clientId: 'cid' });
  let calls = 0;
  // Referenced credential: the ONLY way to read the secret is the resolver, so calls===0 proves a
  // denied request never even read the token (fail-closed before injection).
  await vault.reference(O1, p.id, { source: 'ext', secretRef: 'arn:secret' });
  const resolvers = { ext: async () => { calls++; return 'dapi-super-secret'; } };
  const handle = new ConnectionHandle(p, O1, ID, vault, new Audit(db), resolvers);
  return { handle, getCalls: () => calls, reset: () => { calls = 0; } };
}

test('databricks egress: statement submit (POST) and status poll (GET) are allowed', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{"ok":1}', { status: 200 })) as any;
  try {
    const { handle, getCalls, reset } = await makeHandle();
    // POST submit
    reset();
    const submit = await handle.fetch(`${HOST}/api/2.0/sql/statements`, { method: 'POST', body: '{"statement":"select 1"}' });
    assert.equal(submit.status, 200);
    assert.equal(getCalls(), 1, 'secret injected for the allowed submit');
    // GET poll of a specific statement id (subpath)
    reset();
    const poll = await handle.fetch(`${HOST}/api/2.0/sql/statements/01ef-abc`, { method: 'GET' });
    assert.equal(poll.status, 200);
    assert.equal(getCalls(), 1, 'secret injected for the allowed poll');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('databricks egress: everything outside statement execution is DENIED, secret never read', async () => {
  const realFetch = globalThis.fetch;
  let wentOut = false;
  globalThis.fetch = (async () => { wentOut = true; return new Response('{}', { status: 200 }); }) as any;
  try {
    const { handle, getCalls, reset } = await makeHandle();
    const denied: [string, string][] = [
      [`${HOST}/api/2.0/secrets/acls/get`, 'GET'],   // secrets API — off limits
      [`${HOST}/api/2.1/jobs/list`, 'GET'],          // jobs API — off limits
      [`${HOST}/api/2.0/dbfs/read`, 'GET'],          // DBFS — off limits
      [`${HOST}/api/2.0/sql/statements-evil`, 'GET'], // lookalike prefix must NOT slip through
      [`https://evil.example.com/api/2.0/sql/statements`, 'GET'], // wrong host
      // Encoded-slash traversal: WHATWG leaves %2f un-decoded, so this keeps matching the allowed
      // prefix but resolves to /api/2.0/secrets on an upstream that decodes %2f. Must be denied.
      [`${HOST}/api/2.0/sql/statements/..%2f..%2fsecrets/acls/list`, 'GET'],
      [`${HOST}/api/2.0/sql/statements/..%2F..%2Fjobs/runs/list`, 'POST'],
      [`${HOST}/api/2.0/sql/statements/..%5c..%5csecrets`, 'GET'], // backslash variant
    ];
    for (const [url, method] of denied) {
      reset();
      wentOut = false;
      await assert.rejects(() => handle.fetch(url, { method }), /Egress blocked/, `should deny ${method} ${url}`);
      assert.equal(getCalls(), 0, `secret read for denied ${url}`);
      assert.equal(wentOut, false, `request went upstream for denied ${url}`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});
