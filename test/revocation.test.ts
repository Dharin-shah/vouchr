import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { defineProvider, github, ProviderRegistry } from '../src/core/providers';
import { revokeToken } from '../src/core/tokens';
import { offboardUser } from '../src/core/offboard';
import { userOwner } from '../src/core/owner';
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
