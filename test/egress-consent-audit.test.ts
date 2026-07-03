import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ConnectionHandle } from '../src/core/injector';
import { handleOAuthCallback } from '../src/core/oauthCallback';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);
const TOKEN = 'xoxb-super-secret-access-token-value'; // must never land in an audit meta

const ACME = defineProvider({
  id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
  clientId: 'c', clientSecret: 's',
});

async function deniedRows(db: any): Promise<Array<{ user_id: string; provider: string; meta: any }>> {
  const rows = (await db.all(`SELECT user_id, provider, meta FROM audit WHERE action='denied' ORDER BY at`)) as any[];
  return rows.map((r) => ({ user_id: r.user_id, provider: r.provider, meta: JSON.parse(r.meta) }));
}

// (a) A refused host and a refused port each write a `denied` audit row carrying ONLY {host, reason}.
test('egress deny: refused host + refused port each audit denied with only host+reason (no token/url)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'acme', { accessToken: TOKEN, refreshToken: null, scopes: 'x', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(ACME, O1, ID, vault, new Audit(db));

  const realFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = (async () => { fetched = true; return new Response('{}', { status: 200 }); }) as any;
  try {
    await assert.rejects(() => handle.fetch('https://evil.example/x'), /not in the allowlist/);
    await assert.rejects(() => handle.fetch('https://api.acme.example:2375/x'), /explicit port/);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(fetched, false); // neither request ever left the box

  const rows = await deniedRows(db);
  assert.equal(rows.length, 2);
  const [host, port] = rows;
  assert.equal(host.user_id, 'U1');
  assert.deepEqual(host.meta, { host: 'evil.example', reason: 'host' });
  assert.deepEqual(port.meta, { host: 'api.acme.example', reason: 'host' }); // hostname only, NOT host:2375
  for (const r of rows) {
    assert.deepEqual(Object.keys(r.meta).sort(), ['host', 'reason']); // nothing else smuggled in
    const blob = JSON.stringify(r.meta);
    assert.ok(!blob.includes(TOKEN), 'denied meta leaked the vaulted token');
    assert.ok(!blob.includes('2375'), 'denied meta leaked the caller-supplied port');
    assert.ok(!blob.includes('/x'), 'denied meta leaked the raw url path');
  }
});

// (b) The 401 -> refresh retry cancels the first (discarded) body and returns the refreshed response.
test('401 refresh-retry: drains the discarded 401 body and returns the refreshed 200', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  await vault.upsert(O1, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });
  const handle = new ConnectionHandle(ACME, O1, ID, vault, new Audit(db));

  const realFetch = globalThis.fetch;
  let cancelled = false;
  globalThis.fetch = (async (url: any, init: any) => {
    if (String(url).includes('/token')) {
      return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const auth = new Headers(init?.headers).get('authorization');
    if (auth === 'Bearer old') {
      const body = new ReadableStream({
        start(c) { c.enqueue(new TextEncoder().encode('expired')); },
        cancel() { cancelled = true; },
      });
      return new Response(body, { status: 401 });
    }
    return new Response('{}', { status: 200 }); // Bearer new
  }) as any;
  try {
    const res = await handle.fetch('https://api.acme.example/data');
    assert.equal(res.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(cancelled, true, 'first 401 body was not cancelled/drained');
});

// (c) A consent denial and a post-consent exchange failure each write a `denied` row for the right identity.
test('consent deny: user denial + exchange failure each audit denied attributed to the state identity', async () => {
  // User clicked "Deny": ?error=access_denied, valid state, no code.
  const db1 = await openDb({ dbPath: ':memory:' });
  const consent1 = new Consent(db1);
  const registry = new ProviderRegistry([ACME]);
  const { state: s1 } = await consent1.begin(ID, ACME, 'https://app.example/cb', null);
  const denyRes = await handleOAuthCallback(
    { registry, vault: new Vault(db1, KEY), audit: new Audit(db1), consent: consent1, redirectUri: 'https://app.example/cb' },
    undefined, s1, 'access_denied',
  );
  assert.equal(denyRes.ok, false);
  const r1 = await deniedRows(db1);
  assert.equal(r1.length, 1);
  assert.equal(r1[0].user_id, 'U1');
  assert.equal(r1[0].provider, 'acme');
  assert.deepEqual(r1[0].meta, { reason: 'consent_denied' });

  // Post-consent failure: valid code+state, but the token exchange 400s.
  const db2 = await openDb({ dbPath: ':memory:' });
  const consent2 = new Consent(db2);
  const { state: s2 } = await consent2.begin(ID, ACME, 'https://app.example/cb', null);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('nope', { status: 400 })) as any;
  try {
    const failRes = await handleOAuthCallback(
      { registry, vault: new Vault(db2, KEY), audit: new Audit(db2), consent: consent2, redirectUri: 'https://app.example/cb' },
      'thecode', s2,
    );
    assert.equal(failRes.ok, false);
  } finally {
    globalThis.fetch = realFetch;
  }
  const r2 = await deniedRows(db2);
  assert.equal(r2.length, 1);
  assert.equal(r2[0].user_id, 'U1');
  assert.deepEqual(r2[0].meta, { reason: 'exchange_failed' });
});
