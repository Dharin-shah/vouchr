import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
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
const AWS_REF = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/user-key';

// A key-based provider: no OAuth client; the user pastes their own key.
const keyProvider = defineProvider({
  id: 'customdb', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false,
  inject: (h, s) => h.set('x-api-key', s),
});

async function ctx(
  t: TestContext,
  channel: string | null = 'C1',
  client: any = {},
  resolvers: any = { 'aws-sm': async () => SECRET },
) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const c = new ConnectContext({
    identity: ID, channel, client, registry: new ProviderRegistry([keyProvider]), vault, audit,
    consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
    channelConfig: new ChannelConfig(db), resolvers,
  });
  return { c, db, vault, audit };
}
const auditRows = async (db: any) => await db.all('SELECT action, meta FROM audit') as any[];

// defineProvider must NOT require clientId/clientSecret for a key provider.
test('defineProvider: key provider needs no OAuth client', () => {
  assert.doesNotThrow(() =>
    defineProvider({ id: 'k', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [], egressAllow: ['a'], refresh: 'none', pkce: false }),
  );
  // OAuth provider still requires them (valid URLs, so it's the missing client that trips it).
  assert.throws(
    () =>
      defineProvider({ id: 'o', authorizeUrl: 'https://o.example/a', tokenUrl: 'https://o.example/t', scopesDefault: [], egressAllow: ['a'], refresh: 'none', pkce: false } as any),
    /missing clientId\/clientSecret/,
  );
});

// Self-service: a user sets their OWN key: no admin gate, keyed to the user.
test('setUserSecret: self-service, stored under the user', async (t) => {
  const { c, vault } = await ctx(t);
  await c.setUserSecret('customdb', SECRET);
  assert.equal((await vault.get(userOwner(ID), 'customdb'))?.accessToken, SECRET);
});

// Leak-safe: the user's key never lands in audit meta / return / error.
test('setUserSecret: secret never leaks to audit/return', async (t) => {
  const { c, db } = await ctx(t);
  const ret = await c.setUserSecret('customdb', SECRET);
  assert.equal(ret, undefined);
  for (const r of await auditRows(db)) assert.ok(!r.meta.includes(SECRET));
  assert.deepEqual((await auditRows(db)).map((r) => r.action), ['config']);
});

// referenceUserSecret stores a non-secret pointer under the user.
test('referenceUserSecret: external ref under the user, no secret stored', async (t) => {
  const { c, db, vault } = await ctx(t);
  await c.referenceUserSecret('customdb', { secretRef: AWS_REF });
  const cred = await vault.get(userOwner(ID), 'customdb');
  assert.equal(cred?.source, 'aws-sm');
  assert.equal(cred?.secretRef, AWS_REF);
  assert.equal(cred?.scopes, '');
  assert.equal(cred?.accessToken, null);
  assert.deepEqual(JSON.parse((await auditRows(db))[0].meta), { owner: 'user', kind: 'ref', source: 'aws-sm' });
});

test('referenceUserSecret rolls back the connection when its audit write fails', async (t) => {
  const { c, db, vault, audit } = await ctx(t);
  audit.record = async () => { throw new Error('audit unavailable'); };

  await assert.rejects(() => c.referenceUserSecret('customdb', { secretRef: AWS_REF }), /audit unavailable/);
  assert.equal(await vault.get(userOwner(ID), 'customdb'), null);
  assert.deepEqual(await auditRows(db), []);
});

test('referenceUserSecret: invalid input or missing resolver writes no connection or audit', async (t) => {
  const sentinel = 'sk_live_USER_REFERENCE_SENTINEL';
  const cases = [
    { value: { secretRef: sentinel }, resolvers: undefined },
    { value: { secretRef: ` ${AWS_REF}` }, resolvers: undefined },
    { value: { secretRef: AWS_REF, source: 'gcp-sm' }, resolvers: undefined },
    { value: { secretRef: AWS_REF, scopes: sentinel }, resolvers: undefined },
    { value: { secretRef: AWS_REF, scopes: 'read  write' }, resolvers: undefined },
    { value: { secretRef: AWS_REF }, resolvers: {} },
  ];

  for (const entry of cases) {
    const { c, db, vault } = await ctx(t, 'C1', {}, entry.resolvers);
    await assert.rejects(
      () => c.referenceUserSecret('customdb', entry.value),
      (error: Error) => !error.message.includes(sentinel),
    );
    assert.equal(await vault.get(userOwner(ID), 'customdb'), null);
    assert.deepEqual(await auditRows(db), []);
  }
});

// connect() on a key provider with no cred → posts the key-setup prompt (NOT OAuth), then stops.
test('connect: key provider, no cred → ephemeral key-setup prompt + ConsentRequiredError', async (t) => {
  let ephemeral: any = null;
  const client = { chat: { postEphemeral: async (a: any) => { ephemeral = a; return {}; } } };
  const { c } = await ctx(t, 'C1', client);
  await assert.rejects(() => c.connect('customdb'), ConsentRequiredError);
  assert.equal(ephemeral.user, 'U_MAYA'); // posted to the asking user, ephemeral
  // It's the key-setup button (has an action_id), not an OAuth url button.
  const json = JSON.stringify(ephemeral.blocks);
  assert.ok(json.includes('vouchr_setup_key'));
  assert.ok(!json.includes('authorizeUrl') && !json.includes('"url"'));
  assert.match(ephemeral.text, /stored encrypted/i);
  assert.match(ephemeral.text, /never shown to the agent/i);
});

// Once the user has set their key, connect() returns a handle (no prompt).
test('connect: key provider with cred → handle, no prompt', async (t) => {
  const { c } = await ctx(t, 'C1', {});
  await c.setUserSecret('customdb', SECRET);
  const handle = await c.connect('customdb'); // must not call any client method
  assert.ok(handle);
});
