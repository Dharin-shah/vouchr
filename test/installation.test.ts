import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type { Installation } from '@slack/bolt';
import { DbInstallationStore } from '../src/adapters/installationStore';

const KEY = randomBytes(32);

/** A minimal team-level (single-workspace) install. */
const teamInstall = (teamId: string, botToken: string, enterpriseId?: string): Installation => ({
  team: { id: teamId, name: `team-${teamId}` },
  enterprise: enterpriseId ? { id: enterpriseId, name: 'Org' } : undefined,
  user: { id: 'U_INSTALLER', token: undefined, scopes: undefined },
  bot: { token: botToken, scopes: ['chat:write'], id: 'B1', userId: 'UB1' },
  isEnterpriseInstall: false,
  appId: 'A1',
  authVersion: 'v2',
});

/** A minimal org-wide (Enterprise Grid) install: no team, keyed by enterprise. */
const orgInstall = (enterpriseId: string, botToken: string): Installation => ({
  team: undefined,
  enterprise: { id: enterpriseId, name: 'Org' },
  user: { id: 'U_INSTALLER', token: undefined, scopes: undefined },
  bot: { token: botToken, scopes: ['chat:write'], id: 'B1', userId: 'UB1' },
  isEnterpriseInstall: true,
  appId: 'A1',
  authVersion: 'v2',
});

test('team install: store → fetch → delete round-trip', async (t) => {
  const store = new DbInstallationStore(await openTestDb(t), KEY);
  await store.storeInstallation(teamInstall('T1', 'xoxb-T1'));

  const got = await store.fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false });
  assert.equal(got.team?.id, 'T1');
  assert.equal(got.bot?.token, 'xoxb-T1');

  await store.deleteInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false });
  await assert.rejects(
    () => store.fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false }),
    /No installation found/,
  );
});

test('org-wide install: store → fetch → delete; team queries in the org fall back to it', async (t) => {
  const store = new DbInstallationStore(await openTestDb(t), KEY);
  await store.storeInstallation(orgInstall('E1', 'xoxb-E1'));

  const got = await store.fetchInstallation({ teamId: undefined, enterpriseId: 'E1', isEnterpriseInstall: true });
  assert.equal(got.enterprise?.id, 'E1');
  assert.equal(got.bot?.token, 'xoxb-E1');

  // A team-level query for any workspace inside the org resolves to the org-wide install.
  const viaTeam = await store.fetchInstallation({ teamId: 'T_ANY', enterpriseId: 'E1', isEnterpriseInstall: false });
  assert.equal(viaTeam.bot?.token, 'xoxb-E1');

  // isEnterpriseInstall without an enterpriseId is invalid.
  await assert.rejects(
    () => store.fetchInstallation({ teamId: undefined, enterpriseId: undefined, isEnterpriseInstall: true }),
    /enterpriseId is required/,
  );

  await store.deleteInstallation({ teamId: undefined, enterpriseId: 'E1', isEnterpriseInstall: true });
  await assert.rejects(
    () => store.fetchInstallation({ teamId: undefined, enterpriseId: 'E1', isEnterpriseInstall: true }),
    /No installation found/,
  );
});

test('per-team token resolution returns the right workspace token', async (t) => {
  const store = new DbInstallationStore(await openTestDb(t), KEY);
  await store.storeInstallation(teamInstall('T1', 'xoxb-T1'));
  await store.storeInstallation(teamInstall('T2', 'xoxb-T2'));

  const t1 = await store.fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false });
  const t2 = await store.fetchInstallation({ teamId: 'T2', enterpriseId: undefined, isEnterpriseInstall: false });
  assert.equal(t1.bot?.token, 'xoxb-T1');
  assert.equal(t2.bot?.token, 'xoxb-T2');
  assert.notEqual(t1.bot?.token, t2.bot?.token);

  // A workspace with no install resolves to nothing (fetch throws, caller treats as best-effort).
  await assert.rejects(
    () => store.fetchInstallation({ teamId: 'T_UNKNOWN', enterpriseId: undefined, isEnterpriseInstall: false }),
    /No installation found/,
  );
});

test('secrets are encrypted at rest (no plaintext token in the row)', async (t) => {
  const db = await openTestDb(t);
  const store = new DbInstallationStore(db, KEY);
  await store.storeInstallation(teamInstall('T1', 'xoxb-SECRET'));

  const row = (await db.get('SELECT bot_token, data FROM installation')) as { bot_token: unknown; data: unknown };
  assert.ok(!Buffer.from(row.bot_token as any).toString('utf8').includes('xoxb-SECRET'));
  assert.ok(!Buffer.from(row.data as any).toString('utf8').includes('xoxb-SECRET'));
});
