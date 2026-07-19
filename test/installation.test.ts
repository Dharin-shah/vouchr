import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { Installation } from '@slack/bolt';
import { DbInstallationStore } from '../src/adapters/installationStore';
import { type EnvelopeProvider } from '../src/core/crypto';
import { Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';

const KEY = randomBytes(32);

/**
 * Mock EnvelopeProvider (mirrors test/envelope.test.ts): the KEK is a local AES-256-GCM key, so
 * wrap = encrypt the DEK under the KEK, unwrap = decrypt it. `unwraps` proves the read path calls
 * the provider; `fail` forces a KMS outage to check the fail-closed read.
 */
function fakeEnvelope() {
  const KEK = randomBytes(32);
  const state = { unwraps: 0, fail: false, failWrap: false };
  const provider: EnvelopeProvider = {
    async wrapDataKey(dek) {
      if (state.failWrap) throw new Error('KMS unavailable');
      const iv = randomBytes(12);
      const c = createCipheriv('aes-256-gcm', KEK, iv);
      const ct = Buffer.concat([c.update(dek), c.final()]);
      return Buffer.concat([iv, c.getAuthTag(), ct]);
    },
    async unwrapDataKey(w) {
      state.unwraps++;
      if (state.fail) throw new Error('KMS unavailable');
      const d = createDecipheriv('aes-256-gcm', KEK, w.subarray(0, 12));
      d.setAuthTag(w.subarray(12, 28));
      return Buffer.concat([d.update(w.subarray(28)), d.final()]);
    },
  };
  return { provider, state };
}

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

// ── #241: KMS envelope encryption for multi-workspace installation tokens ──────────────────────────

/**
 * The durable guardrail: with an envelope configured, BOTH installation columns are envelope-format
 * (scheme 0x01) ciphertext that requires the KEK to open, and the read invokes the provider. This
 * proves the wired envelope is actually used and would fail if a future refactor silently fell back
 * to direct encryption. Covers single-team and Enterprise Grid (org-wide) installs.
 */
for (const shape of ['team', 'org'] as const) {
  test(`envelope: ${shape} install seals bot_token + data as scheme 0x01 and unwraps on read`, async (t) => {
    const db = await openTestDb(t);
    const { provider, state } = fakeEnvelope();
    const store = new DbInstallationStore(db, KEY, provider);
    const install = shape === 'team' ? teamInstall('T1', 'xoxb-ENV') : orgInstall('E1', 'xoxb-ENV');
    await store.storeInstallation(install);

    // Stored bytes carry the envelope scheme byte on BOTH columns, and never the plaintext token.
    const row = (await db.get('SELECT bot_token, data FROM installation')) as { bot_token: unknown; data: unknown };
    const botBuf = Buffer.from(row.bot_token as any);
    const dataBuf = Buffer.from(row.data as any);
    assert.equal(botBuf[0], 0x01, 'bot_token is envelope-format (scheme 0x01), not direct');
    assert.equal(dataBuf[0], 0x01, 'data is envelope-format (scheme 0x01), not direct');
    assert.ok(!botBuf.toString('utf8').includes('xoxb-ENV'));
    assert.ok(!dataBuf.toString('utf8').includes('xoxb-ENV'));

    const query = shape === 'team'
      ? { teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false }
      : { teamId: undefined, enterpriseId: 'E1', isEnterpriseInstall: true };
    const before = state.unwraps;
    const got = await store.fetchInstallation(query);
    assert.equal(got.bot?.token, 'xoxb-ENV');
    assert.ok(state.unwraps > before, 'the KEK unwrap must run on read (envelope actually invoked)');

    // The KEK is load-bearing: a store WITHOUT the provider cannot read the envelope row (a
    // database + direct-master compromise does not expose the installation token).
    const noKek = new DbInstallationStore(db, KEY);
    await assert.rejects(() => noKek.fetchInstallation(query));
  });
}

test('envelope: an unwrap (KMS) failure fails closed with a secret-free error', async (t) => {
  const db = await openTestDb(t);
  const { provider, state } = fakeEnvelope();
  const store = new DbInstallationStore(db, KEY, provider);
  await store.storeInstallation(teamInstall('T1', 'xoxb-TOPSECRET'));

  state.fail = true; // simulate a KMS outage on the read path
  try {
    await store.fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false });
    assert.fail('a KMS unwrap outage must fail the read, never silently fall back to a direct decrypt');
  } catch (e) {
    assert.ok(!String((e as Error).message).includes('xoxb-TOPSECRET'), 'the error must not leak the token');
  }
});

test('envelope: a wrap (KMS) failure commits no partial installation row', async (t) => {
  const db = await openTestDb(t);
  const { provider, state } = fakeEnvelope();
  const store = new DbInstallationStore(db, KEY, provider);
  state.failWrap = true; // KMS outage on the write path
  await assert.rejects(
    () => store.storeInstallation(teamInstall('T1', 'xoxb-NEVERWRITTEN')),
    /KMS unavailable/,
  );
  // seal() runs before the INSERT, so a wrap failure leaves NO row behind.
  assert.equal((await db.all('SELECT 1 AS x FROM installation')).length, 0);
});

test('envelope: legacy direct rows still read under an envelope store, and convert on next write (migration)', async (t) => {
  const db = await openTestDb(t);
  // A row written BEFORE the envelope was enabled (direct scheme-0).
  await new DbInstallationStore(db, KEY).storeInstallation(teamInstall('T1', 'xoxb-LEGACY'));
  const legacyRow = (await db.get('SELECT data FROM installation')) as { data: unknown };
  assert.notEqual(Buffer.from(legacyRow.data as any)[0], 0x01, 'precondition: the seed row is direct, not envelope');

  // An envelope-enabled store reads the legacy row (no forced re-auth to migrate).
  const { provider } = fakeEnvelope();
  const env = new DbInstallationStore(db, KEY, provider);
  const got = await env.fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false });
  assert.equal(got.bot?.token, 'xoxb-LEGACY');

  // Re-storing (re-install / token refresh) converts the row to envelope format.
  await env.storeInstallation(teamInstall('T1', 'xoxb-LEGACY'));
  const converted = (await db.get('SELECT data FROM installation')) as { data: unknown };
  assert.equal(Buffer.from(converted.data as any)[0], 0x01, 'the next write converts the row to envelope');
});

/**
 * Acceptance criterion: a rotation/backup-restore path covers provider credentials AND Slack
 * installation tokens TOGETHER. Both are sealed under the same envelope; a "backup restored to a
 * deployment that still holds the KEK" reads both back, and a deployment missing the KEK reads
 * neither (the KEK, not the database, is the boundary).
 */
test('envelope: a backup restored with the KEK reads both credentials and installation tokens; without it, neither', async (t) => {
  const db = await openTestDb(t);
  const { provider } = fakeEnvelope();

  // Two credential-bearing surfaces sealed under the same envelope.
  const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  await new Vault(db, KEY, {}, provider).upsert(userOwner(ID), 'github', {
    accessToken: 'tok_env', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  await new DbInstallationStore(db, KEY, provider).storeInstallation(teamInstall('T1', 'xoxb-ENV'));

  // Restore #1: same master key + the SAME KEK (provider) → both read back.
  assert.equal((await new Vault(db, KEY, {}, provider).get(userOwner(ID), 'github'))?.accessToken, 'tok_env');
  assert.equal(
    (await new DbInstallationStore(db, KEY, provider).fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false })).bot?.token,
    'xoxb-ENV',
  );

  // Restore #2: the database + the master key, but NO KEK (envelope omitted) → neither opens. The
  // envelope moved the compromise boundary from the master key to the external KEK for BOTH.
  await assert.rejects(() => new Vault(db, KEY).get(userOwner(ID), 'github'));
  await assert.rejects(
    () => new DbInstallationStore(db, KEY).fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false }),
  );
});
