import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
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
test('owner isolation: (team,channel) vs (team,user) vs (otherTeam,channel) never cross', async (t) => {
  const vault = new Vault(await openTestDb(t), KEY);
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
test('referenced secret-source: resolved JIT, injected, never persisted', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const owner = channelOwner('T1', 'C_FIN');
  const reference = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/owner-test';
  await vault.reference(owner, 'mcp', { source: 'aws-sm', secretRef: reference });

  // The secret itself appears nowhere in the row. Only the ARN ref does.
  const row = await db.get('SELECT access_token_enc, secret_ref, source FROM connection') as any;
  assert.equal(row.access_token_enc, null);
  assert.equal(row.source, 'aws-sm');
  assert.equal(row.secret_ref, reference);

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
    assert.equal(resolvedWith, reference); // resolver got the ref
    assert.equal(seenAuth, 'Bearer SECRET_FROM_AWS'); // resolved secret injected at the boundary
    // The resolved secret was never written back to the DB.
    const after = await db.get('SELECT access_token_enc FROM connection') as any;
    assert.equal(after.access_token_enc, null);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('referenced secret-source: missing resolver fails closed (no silent skip)', async (t) => {
  const db = await openTestDb(t);
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
test('offboard leaves channel-owned creds; status never lists them', async (t) => {
  const db = await openTestDb(t);
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
test('audit attribution: shared-cred injection records the acting user, not the channel', async (t) => {
  const db = await openTestDb(t);
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
