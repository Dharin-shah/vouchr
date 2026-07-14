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
import { ConnectContext } from '../src/adapters/bolt';

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };
const SECRET = 'sk-super-secret-value-9999';
const AWS_REF = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/channel-key';

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

// `convo` shapes the mocked conversations.info: a class object (default normal), or a thrower.
async function ctx(
  t: TestContext,
  isAdmin: boolean,
  channel: string | null = 'C_FIN',
  convo: any = {},
  policy = new Policy(),
  resolvers: any = { 'aws-sm': async () => SECRET },
) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const client = {
    users: { info: async () => ({ user: { is_admin: isAdmin } }) },
    conversations: {
      info: async () => {
        if (convo === 'throw') throw new Error('channel_not_found');
        return { channel: { id: 'C_FIN', is_channel: true, ...convo } };
      },
    },
  } as any;
  const c = new ConnectContext({
    identity: ID, channel, client, registry: new ProviderRegistry([provider]), vault, audit,
    consent: new Consent(db), policy, redirectUri: 'http://x', channelConfig: new ChannelConfig(db),
    resolvers,
  });
  return { c, db, vault, audit };
}

const auditRows = async (db: any) => await db.all('SELECT action, meta FROM audit') as any[];
const connCount = async (db: any) => ((await db.get('SELECT COUNT(*) n FROM connection')) as any).n;

// T6: non-admin denied+audited; admin allowed+audited; overwrite is atomic.
test('T6 setChannelSecret: admin-gated, audited, atomic overwrite', async (t) => {
  const deny = await ctx(t, false);
  await assert.rejects(() => deny.c.setChannelSecret('mcp', SECRET), /admin/);
  assert.equal(await deny.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'), null); // nothing stored
  assert.deepEqual((await auditRows(deny.db)).map((r) => r.action), ['denied']);

  const ok = await ctx(t, true);
  await ok.c.setChannelSecret('mcp', SECRET);
  assert.equal((await ok.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'))?.accessToken, SECRET);
  await ok.c.setChannelSecret('mcp', 'second-value'); // overwrite
  assert.equal((await ok.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'))?.accessToken, 'second-value');
  assert.equal(await connCount(ok.db), 1); // exactly one connection row → atomic, not duplicated
  assert.deepEqual((await auditRows(ok.db)).map((r) => r.action), ['config', 'config']);
});

// T7: the secret appears in NO audit meta, NO error string, and is not returned.
test('T7 setChannelSecret: secret never leaks to audit/return/error', async (t) => {
  const ok = await ctx(t, true);
  const ret = await ok.c.setChannelSecret('mcp', SECRET);
  assert.equal(ret, undefined); // method returns nothing
  for (const r of await auditRows(ok.db)) assert.ok(!r.meta.includes(SECRET), 'secret in audit meta');

  // Non-admin path's error must not echo the secret either.
  let msg = '';
  try {
    await (await ctx(t, false)).c.setChannelSecret('mcp', SECRET);
  } catch (e) {
    msg = (e as Error).message;
  }
  assert.ok(msg && !msg.includes(SECRET));
});

// invariant 7: a per-user-locked channel refuses static keys and references.
test('per-user lock refuses shared creds (invariant 7)', async (t) => {
  const { c } = await ctx(t, true);
  await c.setChannelMode('mcp', 'per-user');
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /per-user/);
  await assert.rejects(
    () => c.referenceChannelSecret('mcp', { secretRef: AWS_REF }),
    /per-user/,
  );
});

// referenceChannelSecret stores only the non-secret ref + source; rotation stays external.
test('referenceChannelSecret stores the ARN pointer, not a secret', async (t) => {
  const { c, db, vault } = await ctx(t, true);
  await c.referenceChannelSecret('mcp', { secretRef: AWS_REF });
  const cred = await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp');
  assert.equal(cred?.source, 'aws-sm');
  assert.equal(cred?.secretRef, AWS_REF);
  assert.equal(cred?.scopes, '');
  assert.equal(cred?.accessToken, null); // no secret material in the row
  const row = await db.get('SELECT access_token_enc FROM connection') as any;
  assert.equal(row.access_token_enc, null);
  assert.deepEqual(JSON.parse((await auditRows(db))[0].meta), {
    owner: 'channel', channel: 'C_FIN', mode: 'shared', kind: 'ref', source: 'aws-sm',
  });
});

test('referenceChannelSecret rejects invalid input before connection, mode, or audit state', async (t) => {
  const sentinel = 'sk_live_CHANNEL_REFERENCE_SENTINEL';
  const cases = [
    { value: { secretRef: sentinel }, resolvers: undefined },
    { value: { secretRef: `${AWS_REF} ` }, resolvers: undefined },
    { value: { secretRef: AWS_REF, source: 'gcp-sm' }, resolvers: undefined },
    { value: { secretRef: AWS_REF, scopes: sentinel }, resolvers: undefined },
    { value: { secretRef: AWS_REF, scopes: 'read\nwrite' }, resolvers: undefined },
    { value: { secretRef: AWS_REF }, resolvers: {} },
  ];

  for (const entry of cases) {
    const { c, db, vault } = await ctx(t, true, 'C_FIN', {}, new Policy(), entry.resolvers);
    await assert.rejects(
      () => c.referenceChannelSecret('mcp', entry.value),
      (error: Error) => !error.message.includes(sentinel),
    );
    assert.equal(await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'), null);
    assert.equal(await new ChannelConfig(db).getMode('T1', 'C_FIN', 'mcp'), null);
    assert.deepEqual(await auditRows(db), []);
  }
});

// connectChannel returns a handle for the shared cred; per-user lock & missing cred both refuse.
test('connectChannel: handle on shared cred, refuses per-user and unconfigured', async (t) => {
  const ok = await ctx(t, true);
  await assert.rejects(async () => ok.c.connectChannel('mcp'), /No channel credential/); // unconfigured
  await ok.c.setChannelSecret('mcp', SECRET);
  assert.ok(await ok.c.connectChannel('mcp')); // shared cred → handle

  // Flip to per-user: the shared cred is removed and connectChannel refuses.
  await ok.c.setChannelMode('mcp', 'per-user');
  assert.equal(await ok.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'), null);
  await assert.rejects(async () => ok.c.connectChannel('mcp'), /per-user/);
});

// Policy denial applies to shared channel creds, not just per-user connect().
test('connectChannel: refused + audited when policy denies the provider in this channel', async (t) => {
  const deny = new Policy({ mcp: { defaultAllow: true, denyChannels: ['C_FIN'] } });
  const ok = await ctx(t, true, 'C_FIN', {}, deny);
  await ok.c.setChannelSecret('mcp', SECRET); // config is admin-gated, not policy-gated
  await assert.rejects(async () => ok.c.connectChannel('mcp'), /Policy denies/);
  assert.ok((await auditRows(ok.db)).some((r) => r.action === 'denied'));
});

// A null channel (e.g. a DM-less context) cannot configure a channel credential.
test('no channel in context → refuse', async (t) => {
  const { c } = await ctx(t, true, null);
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /No channel/);
});

// T2 invariant 6: shared creds are refused on channel classes whose membership ≠ workspace members.
test('T2 channel-class restriction: disallowed classes refuse config (invariant 6)', async (t) => {
  const cases: Array<[any, RegExp]> = [
    [{ is_ext_shared: true }, /externally shared/],
    [{ is_shared: true }, /externally shared/],
    [{ is_pending_ext_shared: true }, /externally shared/],
    [{ is_im: true }, /DMs/],
    [{ is_mpim: true }, /DMs/],
    [{ is_archived: true }, /archived/],
  ];
  for (const [convo, reason] of cases) {
    const { c, vault } = await ctx(t, true, 'C_FIN', convo);
    await assert.rejects(() => c.setChannelSecret('mcp', SECRET), reason);
    await assert.rejects(
      () => c.referenceChannelSecret('mcp', { secretRef: AWS_REF }),
      reason,
    );
    await assert.rejects(() => c.setChannelMode('mcp', 'shared'), reason);
    assert.equal(await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'), null); // nothing stored
  }
});

// T2 fail-closed: if we can't read the channel class, deny.
test('T2 channel-class restriction: fails closed when conversations.info throws', async (t) => {
  const { c } = await ctx(t, true, 'C_FIN', 'throw');
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /verify the channel type/);
});

// T2 normal channel is allowed (the happy path keeps working).
test('T2 channel-class restriction: a normal channel is allowed', async (t) => {
  const { c, vault } = await ctx(t, true, 'C_FIN', { is_channel: true });
  await c.setChannelSecret('mcp', SECRET);
  assert.equal((await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'))?.accessToken, SECRET);
});
