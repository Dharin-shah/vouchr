import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unlinkSync } from 'node:fs';
import Database from 'better-sqlite3';
import { encrypt } from '../src/core/crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle } from '../src/core/injector';
import { offboardUser } from '../src/core/offboard';
import { Consent } from '../src/core/consent';
import { userOwner, channelOwner } from '../src/core/owner';
import { defineProvider } from '../src/core/providers';

const KEY = randomBytes(32);
const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

// T3 + invariant 4: a user cred and a channel cred sharing an id string, and the same channel
// id in another team, are all independently addressable. No lookup satisfies another's.
test('owner isolation: (team,channel) vs (team,user) vs (otherTeam,channel) never cross', async () => {
  const vault = new Vault(await openDb({ dbPath: ':memory:' }), KEY);
  await vault.upsert(channelOwner('T1', 'X'), 'p', tok('chan-T1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p', tok('user-T1'));
  await vault.upsert(channelOwner('T2', 'X'), 'p', tok('chan-T2'));

  assert.equal((await vault.get(channelOwner('T1', 'X'), 'p'))?.accessToken, 'chan-T1');
  assert.equal((await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p'))?.accessToken, 'user-T1');
  assert.equal((await vault.get(channelOwner('T2', 'X'), 'p'))?.accessToken, 'chan-T2');
  // A channel lookup must never resolve to the same-id user cred or a foreign team's channel.
  assert.notEqual((await vault.get(channelOwner('T1', 'X'), 'p'))?.accessToken, 'user-T1');
  assert.equal(await vault.get(channelOwner('T3', 'X'), 'p'), null); // unknown team → nothing
});

// The AWS-delegate model: a referenced secret lives in an external manager. We persist only a
// non-secret ref; the resolver produces the secret JIT at injection; it is never stored.
test('referenced secret-source: resolved JIT, injected, never persisted', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const owner = channelOwner('T1', 'C_FIN');
  await vault.reference(owner, 'mcp', { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:...:k' });

  // The secret itself appears nowhere in the row. Only the ARN ref does.
  const row = await db.get('SELECT access_token_enc, secret_ref, source FROM connection') as any;
  assert.equal(row.access_token_enc, null);
  assert.equal(row.source, 'aws-sm');
  assert.equal(row.secret_ref, 'arn:aws:secretsmanager:...:k');

  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });

  const realFetch = globalThis.fetch;
  let seenAuth: string | null = null;
  let resolvedWith: string | null = null;
  const resolvers = { 'aws-sm': async (ref: string) => { resolvedWith = ref; return 'SECRET_FROM_AWS'; } };
  globalThis.fetch = (async (_u: any, init: any) => {
    seenAuth = new Headers(init.headers).get('authorization');
    return new Response('ok', { status: 200 });
  }) as any;
  try {
    const acting = { enterpriseId: null, teamId: 'T1', userId: 'Uacting' };
    const handle = new ConnectionHandle(provider, owner, acting, vault, audit, resolvers);
    await handle.fetch('https://api.test/thing');
    assert.equal(resolvedWith, 'arn:aws:secretsmanager:...:k'); // resolver got the ref
    assert.equal(seenAuth, 'Bearer SECRET_FROM_AWS'); // resolved secret injected at the boundary
    // The resolved secret was never written back to the DB.
    const after = await db.get('SELECT access_token_enc FROM connection') as any;
    assert.equal(after.access_token_enc, null);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('referenced secret-source: missing resolver fails closed (no silent skip)', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const owner = channelOwner('T1', 'C1');
  await vault.reference(owner, 'mcp', { source: 'aws-sm', secretRef: 'arn:x' });
  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  const handle = new ConnectionHandle(provider, owner, { enterpriseId: null, teamId: 'T1', userId: 'U' }, vault, new Audit(db), {});
  await assert.rejects(() => handle.fetch('https://api.test/x'), /No resolver registered/);
});

// T5: offboarding a member who linked a shared channel cred must NOT delete the channel's cred,
// and `/vouchr status` (listForUser) must never surface it.
test('offboard leaves channel-owned creds; status never lists them', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const id = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  await vault.upsert(userOwner(id), 'github', tok('mine'));
  await vault.upsert(channelOwner('T1', 'C_FIN'), 'mcp', tok('channel-key'));

  assert.deepEqual((await vault.listForUser(id)).map((c) => c.provider), ['github']); // channel cred not listed
  assert.deepEqual(await offboardUser(vault, audit, consent, id), ['github']);
  assert.equal(await vault.get(userOwner(id), 'github'), null); // user cred gone
  assert.equal((await vault.get(channelOwner('T1', 'C_FIN'), 'mcp'))?.accessToken, 'channel-key'); // channel survives
});

// T9: a shared-channel-cred injection audits the ACTING human, never the channel.
test('audit attribution: shared-cred injection records the acting user, not the channel', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const owner = channelOwner('T1', 'C_FIN');
  await vault.upsert(owner, 'mcp', tok('shared'));
  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
  try {
    const acting = { enterpriseId: null, teamId: 'T1', userId: 'U_HUMAN' };
    await new ConnectionHandle(provider, owner, acting, vault, audit).fetch('https://api.test/x');
    const row = await db.get(`SELECT user_id FROM audit WHERE action='inject'`) as any;
    assert.equal(row.user_id, 'U_HUMAN'); // the human who acted, not 'C_FIN'
  } finally {
    globalThis.fetch = realFetch;
  }
});

// Migration: a pre-owner-keying DB (user_id, no owner_kind) is rebuilt: each row becomes an
// owner_kind='user' row with ciphertext + timestamps preserved verbatim.
test('migration: legacy user_id rows backfill to owner_kind=user, ciphertext preserved', async () => {
  const path = join(tmpdir(), `vouchr-mig-${randomBytes(6).toString('hex')}.db`);
  try {
    const old = new Database(path);
    old.exec(`CREATE TABLE connection (
      id TEXT PRIMARY KEY, enterprise_id TEXT, team_id TEXT NOT NULL, user_id TEXT NOT NULL,
      provider TEXT NOT NULL, access_token_enc BLOB NOT NULL, refresh_token_enc BLOB,
      scopes TEXT NOT NULL, expires_at INTEGER, external_account TEXT,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_used_at INTEGER,
      UNIQUE (team_id, user_id, provider));`);
    old.prepare(`INSERT INTO connection
      (id, enterprise_id, team_id, user_id, provider, access_token_enc, scopes, created_at, updated_at, last_used_at)
      VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run('row1', null, 'T1', 'U1', 'github', encrypt('legacy-token', KEY), 'repo', 1000, 1000, 2000);
    old.close();

    const db = await openDb({ dbPath: path }); // runs the rebuild migration
    const cols = (await db.all(`PRAGMA table_info(connection)`) as any[]).map((c) => c.name);
    assert.ok(cols.includes('owner_kind') && cols.includes('source') && !cols.includes('user_id'));

    const vault = new Vault(db, KEY);
    const got = await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'github');
    assert.equal(got?.accessToken, 'legacy-token'); // ciphertext decrypts → preserved
    assert.equal(got?.source, 'vault');
    const row = await db.get(`SELECT owner_kind, owner_id, created_at FROM connection`) as any;
    assert.equal(row.owner_kind, 'user');
    assert.equal(row.owner_id, 'U1');
    assert.equal(row.created_at, 1000); // timestamp preserved
    await db.close();
  } finally {
    try { unlinkSync(path); } catch {}
  }
});
