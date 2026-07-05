import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { ConnectContext, ConsentRequiredError } from '../src/adapters/bolt';
import { userOwner } from '../src/core/owner';

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_MAYA' };
const SECRET = 'test-user-key-7777';

// A key-based provider: no OAuth client; the user pastes their own key.
const keyProvider = defineProvider({
  id: 'customdb', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false,
  inject: (h, s) => h.set('x-api-key', s),
});

async function ctx(channel: string | null = 'C1', client: any = {}) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const c = new ConnectContext({
    identity: ID, channel, client, registry: new ProviderRegistry([keyProvider]), vault, audit,
    consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
    channelConfig: new ChannelConfig(db),
  });
  return { c, db, vault, audit };
}
const auditRows = async (db: any) => await db.all('SELECT action, meta FROM audit') as any[];

// defineProvider must NOT require clientId/clientSecret for a key provider.
test('defineProvider: key provider needs no OAuth client', () => {
  assert.doesNotThrow(() =>
    defineProvider({ id: 'k', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [], egressAllow: ['a'], refresh: 'none', pkce: false }),
  );
  // OAuth provider still requires them.
  assert.throws(() =>
    defineProvider({ id: 'o', authorizeUrl: 'x', tokenUrl: 'y', scopesDefault: [], egressAllow: ['a'], refresh: 'none', pkce: false } as any),
  );
});

// Self-service: a user sets their OWN key: no admin gate, keyed to the user.
test('setUserSecret: self-service, stored under the user', async () => {
  const { c, vault } = await ctx();
  await c.setUserSecret('customdb', SECRET);
  assert.equal((await vault.get(userOwner(ID), 'customdb'))?.accessToken, SECRET);
});

// Leak-safe: the user's key never lands in audit meta / return / error.
test('setUserSecret: secret never leaks to audit/return', async () => {
  const { c, db } = await ctx();
  const ret = await c.setUserSecret('customdb', SECRET);
  assert.equal(ret, undefined);
  for (const r of await auditRows(db)) assert.ok(!r.meta.includes(SECRET));
  assert.deepEqual((await auditRows(db)).map((r) => r.action), ['config']);
});

// referenceUserSecret stores a non-secret pointer under the user.
test('referenceUserSecret: external ref under the user, no secret stored', async () => {
  const { c, vault } = await ctx();
  await c.referenceUserSecret('customdb', { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:r:k' });
  const cred = await vault.get(userOwner(ID), 'customdb');
  assert.equal(cred?.source, 'aws-sm');
  assert.equal(cred?.secretRef, 'arn:aws:secretsmanager:r:k');
  assert.equal(cred?.accessToken, null);
});

// connect() on a key provider with no cred → posts the key-setup prompt (NOT OAuth), then stops.
test('connect: key provider, no cred → ephemeral key-setup prompt + ConsentRequiredError', async () => {
  let ephemeral: any = null;
  const client = { chat: { postEphemeral: async (a: any) => { ephemeral = a; return {}; } } };
  const { c } = await ctx('C1', client);
  await assert.rejects(() => c.connect('customdb'), ConsentRequiredError);
  assert.equal(ephemeral.user, 'U_MAYA'); // posted to the asking user, ephemeral
  // It's the key-setup button (has an action_id), not an OAuth url button.
  const json = JSON.stringify(ephemeral.blocks);
  assert.ok(json.includes('vouchr_setup_key'));
  assert.ok(!json.includes('authorizeUrl') && !json.includes('"url"'));
});

// Once the user has set their key, connect() returns a handle (no prompt).
test('connect: key provider with cred → handle, no prompt', async () => {
  const { c } = await ctx('C1', {});
  await c.setUserSecret('customdb', SECRET);
  const handle = await c.connect('customdb'); // must not call any client method
  assert.ok(handle);
});
