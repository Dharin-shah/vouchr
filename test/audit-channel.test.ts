import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Audit } from '../src/core/audit';
import { Vault } from '../src/core/vault';
import { ConnectionHandle } from '../src/core/injector';
import { channelOwner } from '../src/core/owner';
import { defineProvider } from '../src/core/providers';
import type { SlackIdentity } from '../src/core/identity';

const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const KEY = randomBytes(32);
const tok = (t: string) => ({ accessToken: t, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

// Read the channel COLUMN directly (not via JSON meta): this is the whole point of the change.
const lastChannel = (db: any) =>
  db.get('SELECT channel FROM audit ORDER BY at DESC LIMIT 1').then((r: any) => r.channel);

test('audit: meta.channel is promoted to the channel column', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const audit = new Audit(db);
  await audit.record('config', ID, 'github', { owner: 'channel', channel: 'C123', mode: 'shared' });
  assert.equal(await lastChannel(db), 'C123');
});

test('audit: a user event with no channel leaves the column null', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const audit = new Audit(db);
  await audit.record('config', ID, 'github', { owner: 'user', kind: 'secret' });
  assert.equal(await lastChannel(db), null);
});

test('audit: a channel-owned injection attributes the channel column', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const owner = channelOwner('T1', 'C999');
  await vault.upsert(owner, 'github', tok('xoxb-secret-token'));
  const provider = defineProvider({
    id: 'github', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
  try {
    await new ConnectionHandle(provider, owner, ID, vault, new Audit(db)).fetch('https://api.test/x');
  } finally {
    globalThis.fetch = realFetch;
  }

  const row = await db.get(`SELECT action, channel, meta FROM audit WHERE action='inject' ORDER BY at DESC LIMIT 1`) as any;
  assert.equal(row.channel, 'C999'); // injection is attributed to the channel
  assert.ok(!JSON.stringify(row.meta).includes('xoxb-secret-token')); // and no secret leaked into meta
});
