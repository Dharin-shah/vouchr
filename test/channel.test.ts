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
import { ConnectContext } from '../src/adapters/bolt';

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };
const SECRET = 'sk-super-secret-value-9999';

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

async function ctx(isAdmin: boolean, channel: string | null = 'C_FIN') {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const client = { users: { info: async () => ({ user: { is_admin: isAdmin } }) } } as any;
  const c = new ConnectContext(
    ID, channel, client, new ProviderRegistry([provider]), vault, audit,
    new Consent(db), new Policy(), 'http://x', {}, new ChannelConfig(db),
  );
  return { c, db, vault, audit };
}

const auditRows = async (db: any) => await db.all('SELECT action, meta FROM audit') as any[];
const connCount = async (db: any) => ((await db.get('SELECT COUNT(*) n FROM connection')) as any).n;

// T6: non-admin denied+audited; admin allowed+audited; overwrite is atomic.
test('T6 setChannelSecret: admin-gated, audited, atomic overwrite', async () => {
  const deny = await ctx(false);
  await assert.rejects(() => deny.c.setChannelSecret('mcp', SECRET), /admin/);
  assert.equal(await deny.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'), null); // nothing stored
  assert.deepEqual((await auditRows(deny.db)).map((r) => r.action), ['denied']);

  const ok = await ctx(true);
  await ok.c.setChannelSecret('mcp', SECRET);
  assert.equal((await ok.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'))?.accessToken, SECRET);
  await ok.c.setChannelSecret('mcp', 'second-value'); // overwrite
  assert.equal((await ok.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'))?.accessToken, 'second-value');
  assert.equal(await connCount(ok.db), 1); // exactly one connection row → atomic, not duplicated
  assert.deepEqual((await auditRows(ok.db)).map((r) => r.action), ['config', 'config']);
});

// T7: the secret appears in NO audit meta, NO error string, and is not returned.
test('T7 setChannelSecret: secret never leaks to audit/return/error', async () => {
  const ok = await ctx(true);
  const ret = await ok.c.setChannelSecret('mcp', SECRET);
  assert.equal(ret, undefined); // method returns nothing
  for (const r of await auditRows(ok.db)) assert.ok(!r.meta.includes(SECRET), 'secret in audit meta');

  // Non-admin path's error must not echo the secret either.
  let msg = '';
  try {
    await (await ctx(false)).c.setChannelSecret('mcp', SECRET);
  } catch (e) {
    msg = (e as Error).message;
  }
  assert.ok(msg && !msg.includes(SECRET));
});

// invariant 7: a per-user-locked channel refuses static keys and references.
test('per-user lock refuses shared creds (invariant 7)', async () => {
  const { c } = await ctx(true);
  await c.setChannelMode('mcp', 'per-user');
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /per-user/);
  await assert.rejects(
    () => c.referenceChannelSecret('mcp', { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:x' }),
    /per-user/,
  );
});

// referenceChannelSecret stores only the non-secret ref + source; rotation stays external.
test('referenceChannelSecret stores the ARN pointer, not a secret', async () => {
  const { c, db, vault } = await ctx(true);
  await c.referenceChannelSecret('mcp', { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:r:k' });
  const cred = await vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp');
  assert.equal(cred?.source, 'aws-sm');
  assert.equal(cred?.secretRef, 'arn:aws:secretsmanager:r:k');
  assert.equal(cred?.accessToken, null); // no secret material in the row
  const row = await db.get('SELECT access_token_enc FROM connection') as any;
  assert.equal(row.access_token_enc, null);
});

// connectChannel returns a handle for the shared cred; per-user lock & missing cred both refuse.
test('connectChannel: handle on shared cred, refuses per-user and unconfigured', async () => {
  const ok = await ctx(true);
  await assert.rejects(async () => ok.c.connectChannel('mcp'), /No channel credential/); // unconfigured
  await ok.c.setChannelSecret('mcp', SECRET);
  assert.ok(await ok.c.connectChannel('mcp')); // shared cred → handle

  // Flip to per-user: the shared cred is removed and connectChannel refuses.
  await ok.c.setChannelMode('mcp', 'per-user');
  assert.equal(await ok.vault.get({ teamId: 'T1', kind: 'channel', id: 'C_FIN' }, 'mcp'), null);
  await assert.rejects(async () => ok.c.connectChannel('mcp'), /per-user/);
});

// A null channel (e.g. a DM-less context) cannot configure a channel credential.
test('no channel in context → refuse', async () => {
  const { c } = await ctx(true, null);
  await assert.rejects(() => c.setChannelSecret('mcp', SECRET), /No channel/);
});
