import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { userOwner, channelOwner } from '../src/core/owner';

const KEY = randomBytes(32);
const tok = { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null };

// enterprise_id is persisted for user-owned creds (so enterprise-scoped offboarding can match),
// but it is NOT part of the isolation key.
test('vault persists enterprise_id for user owner, null for channel owner', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const id = { enterpriseId: 'E1', teamId: 'T1', userId: 'U1' };

  await vault.upsert(userOwner(id), 'github', tok);
  await vault.upsert(channelOwner('T1', 'C1'), 'github', tok);

  const userRow = (await db.get(
    `SELECT enterprise_id FROM connection WHERE owner_kind='user' AND owner_id='U1' AND provider='github'`,
  )) as any;
  const chanRow = (await db.get(
    `SELECT enterprise_id FROM connection WHERE owner_kind='channel' AND owner_id='C1' AND provider='github'`,
  )) as any;

  assert.equal(userRow.enterprise_id, 'E1');
  assert.equal(chanRow.enterprise_id, null);

  // Still retrievable by the full owner key (enterprise_id is not part of it).
  assert.ok(await vault.get(userOwner(id), 'github'));
});
