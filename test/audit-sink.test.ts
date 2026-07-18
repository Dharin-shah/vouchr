import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit, type VouchrAuditEvent } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ConnectionHandle } from '../src/core/injector';
import { handleOAuthCallback } from '../src/core/oauthCallback';
import { github, defineProvider, ProviderRegistry } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);
const TOKEN = 'xoxb-super-secret-access-token-value'; // must never appear in any audit event
const REFRESH = 'refresh_secret_abcdefghijklmnop'; // must never appear either

// A rotating provider with its own token endpoint, so the refresh path is exercisable.
const ACME = defineProvider({
  id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
  clientId: 'c', clientSecret: 's',
});

async function handleWith(t: TestContext, auditSink: (e: VouchrAuditEvent) => void, provider = github({ clientId: 'cid', clientSecret: 'csec' })) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner(ID), provider.id, { accessToken: TOKEN, refreshToken: REFRESH, scopes: 'repo', expiresAt: null, externalAccount: null });
  // 9th arg = the audit stream sink (the no-secret EventSink is the 8th, left as default no-op).
  return new ConnectionHandle(provider, O1, ID, vault, audit, {}, new Map(), () => {}, auditSink);
}

test('audit-sink: fetch emits a VouchrAuditEvent with the RAW actor id and a jti, no token', async (t) => {
  const events: VouchrAuditEvent[] = [];
  const handle = await handleWith(t, (e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    await handle.fetch('https://api.github.com/user');
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(events.length, 1);
  const e = events[0];
  assert.equal(e.action, 'fetch');
  assert.equal(e.provider, 'github');
  assert.equal(e.teamId, 'T1');
  assert.equal(e.userId, 'U1'); // RAW actor id, not a hash
  assert.equal(e.ownerKind, 'user');
  assert.equal(e.ownerId, 'U1');
  assert.equal(e.egressHost, 'api.github.com');
  assert.equal(e.status, 200);
  assert.ok(e.jti && typeof e.jti === 'string', 'jti missing');
  assert.ok(!Number.isNaN(Date.parse(e.ts)), 'ts not an ISO timestamp');
});

test('audit-sink: refresh on a 401 emits a refresh audit event; never the token/refresh-token', async (t) => {
  const events: VouchrAuditEvent[] = [];
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: REFRESH, scopes: 'x', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(ACME, O1, ID, vault, audit, {}, new Map(), () => {}, (e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url).includes('/token')) {
      return new Response(JSON.stringify({ access_token: TOKEN, refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const auth = new Headers(init?.headers).get('authorization');
    if (auth === 'Bearer old') return new Response('expired', { status: 401 });
    return new Response('{}', { status: 200 });
  }) as any;
  try {
    await handle.fetch('https://api.acme.example/data');
  } finally {
    globalThis.fetch = realFetch;
  }
  const refresh = events.find((e) => e.action === 'refresh');
  assert.ok(refresh, 'refresh audit event not emitted');
  assert.equal(refresh.egressHost, 'acme.example'); // the token endpoint host
  assert.equal(refresh.userId, 'U1');
  assert.ok(refresh.jti, 'jti missing on refresh event');
  for (const e of events) {
    const blob = JSON.stringify(e);
    assert.ok(!blob.includes(TOKEN), `audit event leaked access token: ${blob}`);
    assert.ok(!blob.includes(REFRESH), `audit event leaked refresh token: ${blob}`);
  }
});

test('audit-sink: consent_granted fires on a successful OAuth callback; no token, has jti', async (t) => {
  const events: VouchrAuditEvent[] = [];
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([ACME]);
  const { state } = await consent.begin(ID, ACME, 'https://app.example/cb', null);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: TOKEN, refresh_token: REFRESH }), { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    const res = await handleOAuthCallback({ registry, vault, audit, consent, redirectUri: 'https://app.example/cb', auditSink: (e) => events.push(e) }, 'thecode', state);
    assert.equal(res.ok, true);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(events.length, 1);
  const e = events[0];
  assert.equal(e.action, 'consent_granted');
  assert.equal(e.userId, 'U1');
  assert.equal(e.ownerKind, 'user');
  assert.equal(e.egressHost, 'acme.example');
  assert.ok(e.jti, 'jti missing');
  assert.ok(!JSON.stringify(e).includes(TOKEN), 'consent event leaked token');
});

test('audit-sink: consent_denied fires on a REAL user denial (?error=access_denied), status 400', async (t) => {
  const events: VouchrAuditEvent[] = [];
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([ACME]);
  const { state } = await consent.begin(ID, ACME, 'https://app.example/cb', null);
  // No code, an error param, and a valid state: the user clicked "Deny" at the provider.
  const res = await handleOAuthCallback(
    { registry, vault, audit, consent, redirectUri: 'https://app.example/cb', auditSink: (e) => events.push(e) },
    undefined, state, 'access_denied',
  );
  assert.equal(res.ok, false);
  assert.equal(events.length, 1, 'user denial emitted no consent_denied event');
  assert.equal(events[0].action, 'consent_denied');
  assert.equal(events[0].status, 400); // real denial is 400, distinct from the synthetic 500 below
  assert.equal(events[0].userId, 'U1'); // attributed to the resolved identity
  assert.ok(events[0].jti, 'jti missing');
  // State was consumed by the denial: it can't be replayed for a later exchange.
  assert.equal((await consent.consume(state)).status, 'unavailable');
});

test('audit-sink: a token-exchange failure emits consent_failed, not consent_denied', async (t) => {
  const events: VouchrAuditEvent[] = [];
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([ACME]);
  const { state } = await consent.begin(ID, ACME, 'https://app.example/cb', null);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('nope', { status: 400 })) as any; // exchange fails
  try {
    const res = await handleOAuthCallback({ registry, vault, audit, consent, redirectUri: 'https://app.example/cb', auditSink: (e) => events.push(e) }, 'thecode', state);
    assert.equal(res.ok, false);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(events.length, 1);
  assert.equal(events[0].action, 'consent_failed', 'a provider/exchange failure must not claim a human denial');
  assert.equal(events[0].userId, 'U1');
  assert.ok(events[0].jti, 'jti missing');
});

test('audit-sink: a provider redirect error emits consent_failed, but access_denied stays consent_denied', async (t) => {
  const db = await openTestDb(t);
  const registry = new ProviderRegistry([ACME]);
  const mk = () => ({ vault: new Vault(db, KEY), audit: new Audit(db), consent: new Consent(db), registry, redirectUri: 'https://app.example/cb' });

  const denied: VouchrAuditEvent[] = [];
  const s1 = (await mk().consent.begin(ID, ACME, 'https://app.example/cb', null)).state;
  await handleOAuthCallback({ ...mk(), auditSink: (e) => denied.push(e) }, undefined, s1, 'access_denied');
  assert.equal(denied[0].action, 'consent_denied', 'a real user denial is consent_denied');

  const failed: VouchrAuditEvent[] = [];
  const s2 = (await mk().consent.begin(ID, ACME, 'https://app.example/cb', null)).state;
  await handleOAuthCallback({ ...mk(), auditSink: (e) => failed.push(e) }, undefined, s2, 'temporarily_unavailable');
  assert.equal(failed[0].action, 'consent_failed', 'a provider-side error is consent_failed');
});

test('audit-sink: an offboard/revoke race during exchange emits consent_failed, not consent_denied', async (t) => {
  const db = await openTestDb(t);
  const registry = new ProviderRegistry([ACME]);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'x' }), {
    status: 200, headers: { 'content-type': 'application/json' },
  })) as any;
  try {
    // consent_failed spans distinct lifecycle statuses: 403 offboarded, 409 revoked (contract doc).
    for (const [outcome, status] of [['offboarded', 403], ['revoked', 409]] as const) {
      const consent = new Consent(db);
      const { state } = await consent.begin(ID, ACME, 'https://app.example/cb', null);
      const events: VouchrAuditEvent[] = [];
      // The lifecycle invalidation wins the fence during token exchange (upsert returns the outcome).
      const vault = { upsertUser: async () => outcome } as any;
      const res = await handleOAuthCallback(
        { registry, vault, audit: new Audit(db), consent, redirectUri: 'https://app.example/cb', auditSink: (e) => events.push(e) },
        'code', state,
      );
      assert.equal(res.ok, false);
      assert.equal(events.at(-1)?.action, 'consent_failed', `${outcome} must not claim a human denial`);
      assert.equal(events.at(-1)?.status, status, `${outcome} consent_failed carries status ${status}`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('audit-sink: unset sink is a no-op and a throwing sink never breaks the request', async (t) => {
  // Unset (default no-op): fetch must succeed.
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'github', { accessToken: TOKEN, refreshToken: null, scopes: 'repo', expiresAt: null, externalAccount: null });
  const plain = new ConnectionHandle(github({ clientId: 'cid', clientSecret: 'csec' }), O1, ID, vault, new Audit(db), {}, new Map());
  // Throwing sink: fetch must still succeed.
  const throwing = await handleWith(t, () => { throw new Error('bad audit sink'); });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    assert.equal((await plain.fetch('https://api.github.com/user')).status, 200);
    assert.equal((await throwing.fetch('https://api.github.com/user')).status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
});
