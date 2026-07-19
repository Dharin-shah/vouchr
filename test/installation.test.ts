import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { Installation } from '@slack/bolt';
import { DbInstallationStore } from '../src/adapters/installationStore';
import {
  boundedEnvelopeProvider,
  EnvelopeConfigurationError,
  EnvelopeOverloadedError,
  EnvelopeTimeoutError,
  EnvelopeUnavailableError,
  openEnvelope,
  seal,
  tryDecryptDirect,
  type EnvelopeProvider,
} from '../src/core/crypto';
import type { Db } from '../src/core/db';
import { CredentialLockdownError, Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';

const KEY = randomBytes(32);

/**
 * Mock EnvelopeProvider (mirrors test/envelope.test.ts): the KEK is a local AES-256-GCM key, so
 * wrap = encrypt the DEK under the KEK, unwrap = decrypt it. `unwraps` proves the read path calls
 * the provider; `fail` forces a KMS outage to check the fail-closed read.
 */
function fakeEnvelope() {
  const KEK = randomBytes(32);
  const state = { unwraps: 0, fail: false };
  const provider: EnvelopeProvider = {
    async wrapDataKey(dek) {
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

type VersionedKekState = {
  active: number;
  keys: Map<number, Buffer>;
};

/** A KMS-shaped provider whose wrapped DEK records the backing KEK version. */
function versionedEnvelope(state: VersionedKekState): EnvelopeProvider {
  return {
    async wrapDataKey(dek) {
      const kek = state.keys.get(state.active);
      if (!kek) throw new Error('KMS active key version is unavailable');
      const version = Buffer.alloc(4);
      version.writeUInt32BE(state.active);
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', kek, iv);
      const ciphertext = Buffer.concat([cipher.update(dek), cipher.final()]);
      return Buffer.concat([version, iv, cipher.getAuthTag(), ciphertext]);
    },
    async unwrapDataKey(wrapped) {
      const kek = state.keys.get(wrapped.readUInt32BE(0));
      if (!kek) throw new Error('KMS key version is unavailable');
      const decipher = createDecipheriv('aes-256-gcm', kek, wrapped.subarray(4, 16));
      decipher.setAuthTag(wrapped.subarray(16, 32));
      return Buffer.concat([decipher.update(wrapped.subarray(32)), decipher.final()]);
    },
  };
}

const CONNECTION_COLUMNS = [
  'id', 'enterprise_id', 'team_id', 'owner_kind', 'owner_id', 'provider', 'source',
  'access_token_enc', 'refresh_token_enc', 'secret_ref', 'scopes', 'expires_at',
  'external_account', 'dry_run', 'generation_at', 'created_at', 'updated_at', 'last_used_at',
] as const;
const INSTALLATION_COLUMNS = [
  'id', 'enterprise_id', 'team_id', 'bot_token', 'data', 'updated_at',
] as const;

/** Copy exact production ciphertext into a separately migrated PostgreSQL schema (restore proof). */
async function restoreRows(
  source: Db,
  destination: Db,
  table: 'connection' | 'installation',
  columns: readonly string[],
): Promise<void> {
  const rows = await source.all<Record<string, unknown>>(`SELECT ${columns.join(', ')} FROM ${table} ORDER BY id`);
  for (const row of rows) {
    await destination.run(
      `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`,
      columns.map((column) => row[column]),
    );
  }
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

test('installation-store migration options reject non-plain and mistyped input', async (t) => {
  const db = await openTestDb(t);
  assert.throws(
    () => new DbInstallationStore(db, KEY, undefined, null as any),
    /options must be a plain object/,
  );
  assert.throws(
    () => new DbInstallationStore(db, KEY, undefined, [] as any),
    /options must be a plain object/,
  );
  assert.throws(
    () => new DbInstallationStore(db, KEY, undefined, { allowDirectRowsDuringMigration: 'true' } as any),
    /allowDirectRowsDuringMigration must be boolean/,
  );
  assert.throws(
    () => new DbInstallationStore(db, KEY, undefined, { lockdown: 'true' } as any),
    /lockdown must be boolean/,
  );

  const previous = process.env.VOUCHR_LOCKDOWN;
  const sentinel = 'xoxb-misplaced-secret';
  let providerReads = 0;
  const provider = Object.defineProperty({}, 'wrapDataKey', {
    get() {
      providerReads++;
      throw new Error('provider accessor must not run');
    },
  });
  process.env.VOUCHR_LOCKDOWN = sentinel;
  try {
    assert.throws(
      () => new DbInstallationStore(db, KEY, provider as EnvelopeProvider),
      (error: Error) => {
        assert.match(error.message, /VOUCHR_LOCKDOWN/);
        assert.ok(!error.message.includes(sentinel));
        return true;
      },
    );
    assert.equal(providerReads, 0, 'deployment containment must parse before provider access');
  } finally {
    if (previous === undefined) delete process.env.VOUCHR_LOCKDOWN;
    else process.env.VOUCHR_LOCKDOWN = previous;
  }
});

test('lockdown refuses installation token reads and writes before DB or KMS access but permits deletion', async () => {
  let dbCalls = 0;
  let kmsCalls = 0;
  const db: Db = {
    async get() { dbCalls++; throw new Error('database must not be read'); },
    async all() { dbCalls++; throw new Error('database must not be read'); },
    async run() { dbCalls++; return { changes: 1 }; },
    async exec() { dbCalls++; throw new Error('database must not be changed'); },
    async close() {},
  };
  const envelope: EnvelopeProvider = {
    async wrapDataKey(dek) { kmsCalls++; return dek; },
    async unwrapDataKey(wrapped) { kmsCalls++; return wrapped; },
  };
  const firstReplica = new DbInstallationStore(db, KEY, envelope, { lockdown: true });
  const secondReplica = new DbInstallationStore(db, KEY, envelope, { lockdown: true });
  const query = { teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false } as const;

  await assert.rejects(() => firstReplica.fetchInstallation(query), CredentialLockdownError);
  await assert.rejects(
    () => secondReplica.storeInstallation(teamInstall('T1', 'xoxb-NEVER-TOUCHED')),
    CredentialLockdownError,
  );
  assert.equal(dbCalls, 0, 'containment must refuse before reading or writing PostgreSQL');
  assert.equal(kmsCalls, 0, 'containment must refuse before wrapping or unwrapping a token');

  await firstReplica.deleteInstallation(query);
  assert.equal(dbCalls, 1, 'local invalidation remains available during containment');
});

test('VOUCHR_LOCKDOWN cannot be disabled by the installation-store host option', async () => {
  const previous = process.env.VOUCHR_LOCKDOWN;
  process.env.VOUCHR_LOCKDOWN = '1';
  try {
    const db: Db = {
      async get() { throw new Error('database must not be read'); },
      async all() { throw new Error('database must not be read'); },
      async run() { throw new Error('database must not be written'); },
      async exec() { throw new Error('database must not be changed'); },
      async close() {},
    };
    const store = new DbInstallationStore(db, KEY, undefined, { lockdown: false });
    await assert.rejects(
      () => store.fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false }),
      CredentialLockdownError,
    );
  } finally {
    if (previous === undefined) delete process.env.VOUCHR_LOCKDOWN;
    else process.env.VOUCHR_LOCKDOWN = previous;
  }
});

test('envelope: invalid runtime provider values cannot silently downgrade to direct encryption', async (t) => {
  const db = await openTestDb(t);
  for (const invalid of [null, false, '', 0, {}, { wrapDataKey: async () => Buffer.alloc(32) }]) {
    assert.throws(
      () => new DbInstallationStore(db, KEY, invalid as any),
      EnvelopeConfigurationError,
    );
    assert.throws(
      () => new Vault(db, KEY, {}, invalid as any),
      EnvelopeConfigurationError,
    );
  }
  assert.doesNotThrow(() => new DbInstallationStore(db, KEY, undefined));
  assert.doesNotThrow(() => new Vault(db, KEY, {}, undefined));
});

// ── #241: KMS envelope encryption for multi-workspace installation tokens ──────────────────────────

test('envelope: default bounds share one cached wrapper per provider', () => {
  const { provider } = fakeEnvelope();
  const bounded = boundedEnvelopeProvider(provider);
  assert.equal(boundedEnvelopeProvider(provider), bounded);
  assert.equal(boundedEnvelopeProvider(bounded), bounded, 'wrapping an already-bounded provider is idempotent');
});

test('envelope: a throwing unwrap observer still scrubs the plaintext DEK', async () => {
  let unwrappedDek = Buffer.alloc(0);
  const provider: EnvelopeProvider = {
    async wrapDataKey(dek) {
      unwrappedDek = Buffer.from(dek);
      return Buffer.from('wrapped-key');
    },
    async unwrapDataKey() { return unwrappedDek; },
  };
  const ciphertext = await seal('secret payload', KEY, provider);
  const observerFailure = new Error('observer failed');
  await assert.rejects(
    () => openEnvelope(ciphertext, provider, () => { throw observerFailure; }),
    (error) => error === observerFailure,
  );
  assert.ok(unwrappedDek.every((byte) => byte === 0), 'the plaintext DEK must be scrubbed in finally');
});

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
  await assert.rejects(
    () => store.fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false }),
    (error: Error & { cause?: unknown }) => {
      assert.ok(error instanceof EnvelopeUnavailableError);
      assert.equal(error.message, 'vouchr: envelope key service is unavailable');
      assert.equal(error.cause, undefined);
      assert.ok(!String(error).includes('xoxb-TOPSECRET'));
      assert.ok(!String(error).includes('KMS unavailable'), 'provider error text must be sanitized');
      return true;
    },
  );
});

test('envelope: a provider cannot smuggle detail through an internal-looking error', async () => {
  const sentinel = 'provider-DEK-detail-must-not-escape';
  const hostile = new EnvelopeUnavailableError();
  hostile.message = sentinel;
  Object.assign(hostile, { cause: sentinel });
  const envelope = boundedEnvelopeProvider({
    async wrapDataKey() { throw hostile; },
    async unwrapDataKey(wrapped) { return wrapped; },
  });
  await assert.rejects(
    () => envelope.wrapDataKey(Buffer.alloc(32, 1)),
    (error: Error & { cause?: unknown }) => {
      assert.notEqual(error, hostile);
      assert.ok(error instanceof EnvelopeUnavailableError);
      assert.equal(error.message, 'vouchr: envelope key service is unavailable');
      assert.equal(error.cause, undefined);
      assert.ok(!String(error).includes(sentinel));
      return true;
    },
  );
});

test('envelope: a hanging wrap is aborted at the bounded deadline and writes no row', async (t) => {
  const db = await openTestDb(t);
  let observedAbort = false;
  const hanging = boundedEnvelopeProvider({
    async wrapDataKey(_dek, signal) {
      assert.ok(signal, 'the bounded wrapper must propagate an AbortSignal');
      return new Promise<Buffer>((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          observedAbort = true;
          reject(signal.reason);
        }, { once: true });
      });
    },
    async unwrapDataKey(wrapped) { return wrapped; },
  }, { timeoutMs: 25, maxUnresolved: 2 });

  await assert.rejects(
    () => new DbInstallationStore(db, KEY, hanging).storeInstallation(teamInstall('T1', 'xoxb-HANG')),
    EnvelopeTimeoutError,
  );
  assert.equal(observedAbort, true, 'the underlying KMS operation must be cancelled');
  assert.equal((await db.all('SELECT 1 FROM installation')).length, 0);
});

test('envelope: a hanging unwrap is aborted at the bounded deadline', async (t) => {
  const db = await openTestDb(t);
  const { provider } = fakeEnvelope();
  await new DbInstallationStore(db, KEY, provider).storeInstallation(teamInstall('T1', 'xoxb-HANG'));

  let observedAbort = false;
  const hanging = boundedEnvelopeProvider({
    async wrapDataKey(dek) { return dek; },
    async unwrapDataKey(_wrapped, signal) {
      assert.ok(signal, 'the bounded wrapper must propagate an AbortSignal');
      return new Promise<Buffer>((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          observedAbort = true;
          reject(signal.reason);
        }, { once: true });
      });
    },
  }, { timeoutMs: 25, maxUnresolved: 2 });

  await assert.rejects(
    () => new DbInstallationStore(db, KEY, hanging).fetchInstallation({
      teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false,
    }),
    EnvelopeTimeoutError,
  );
  assert.equal(observedAbort, true, 'the underlying KMS operation must be cancelled');
});

test('envelope: providers that ignore abort retain slots and hit the unresolved-work ceiling', async (t) => {
  const db = await openTestDb(t);
  const { provider } = fakeEnvelope();
  await new DbInstallationStore(db, KEY, provider).storeInstallation(teamInstall('T1', 'xoxb-HANG'));

  const lateResolvers: Array<(value: Buffer) => void> = [];
  const ignoresAbort = boundedEnvelopeProvider({
    async wrapDataKey(dek) { return dek; },
    async unwrapDataKey() {
      return new Promise<Buffer>((resolve) => { lateResolvers.push(resolve); });
    },
  }, { timeoutMs: 25, maxUnresolved: 2 });
  const stuck = new DbInstallationStore(db, KEY, ignoresAbort);
  const query = { teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false } as const;

  await Promise.all([
    assert.rejects(() => stuck.fetchInstallation(query), EnvelopeTimeoutError),
    assert.rejects(() => stuck.fetchInstallation(query), EnvelopeTimeoutError),
  ]);
  await assert.rejects(() => stuck.fetchInstallation(query), EnvelopeOverloadedError);

  // A late plaintext DEK has no consumer after timeout. The wrapper scrubs it on settlement and only
  // then releases its admission slot.
  const lateDek = Buffer.alloc(32, 0x7f);
  lateResolvers[0](lateDek);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.ok(lateDek.every((byte) => byte === 0), 'a late unwrapped DEK must be zeroed');
});

test('envelope: caller cancellation is preserved and a late provider result is scrubbed', async () => {
  let resolveLate!: (value: Buffer) => void;
  const envelope = boundedEnvelopeProvider({
    async wrapDataKey() {
      return new Promise<Buffer>((resolve) => { resolveLate = resolve; });
    },
    async unwrapDataKey(wrapped) { return wrapped; },
  }, { timeoutMs: 1_000, maxUnresolved: 1 });
  const controller = new AbortController();
  const reason = new DOMException('caller stopped', 'AbortError');
  const pending = envelope.wrapDataKey(Buffer.alloc(32, 1), controller.signal);
  await new Promise<void>((resolve) => setImmediate(resolve)); // ensure the provider call has started
  controller.abort(reason);
  await assert.rejects(pending, (error) => error === reason);

  const late = Buffer.alloc(32, 0x5a);
  resolveLate(late);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.ok(late.every((byte) => byte === 0), 'a post-cancellation DEK must be zeroed');
});

test('envelope: second-wrap failure commits neither a partial row nor a partial update', async (t) => {
  for (const existing of [false, true]) {
    await t.test(existing ? 'existing row' : 'new row', async (st) => {
      const db = await openTestDb(st);
      if (existing) {
        await new DbInstallationStore(db, KEY).storeInstallation(teamInstall('T1', 'xoxb-ORIGINAL'));
      }
      const before = await db.get<{ bot_token: Buffer; data: Buffer }>(
        'SELECT bot_token, data FROM installation WHERE id=?',
        [':T1'],
      );
      let wraps = 0;
      const provider: EnvelopeProvider = {
        async wrapDataKey(dek) {
          wraps += 1;
          if (wraps === 2) throw new Error('foreign KMS detail');
          return Buffer.from(dek);
        },
        async unwrapDataKey(wrapped) { return wrapped; },
      };

      await assert.rejects(
        () => new DbInstallationStore(db, KEY, provider).storeInstallation(
          teamInstall('T1', 'xoxb-NEVERWRITTEN'),
        ),
        EnvelopeUnavailableError,
      );
      assert.equal(wraps, 2, 'the failure must occur after bot_token wrapped successfully');
      const after = await db.get<{ bot_token: Buffer; data: Buffer }>(
        'SELECT bot_token, data FROM installation WHERE id=?',
        [':T1'],
      );
      if (!existing) assert.equal(after, undefined);
      else {
        assert.ok(before);
        assert.ok(after);
        assert.ok(after.bot_token.equals(before.bot_token));
        assert.ok(after.data.equals(before.data));
      }
    });
  }
});

test('envelope: invalid fulfilled wrap output is rejected before persistence', async (t) => {
  for (const wrappedLength of [0, 0x1_0000]) {
    await t.test(`${wrappedLength} bytes`, async (st) => {
      const db = await openTestDb(st);
      const invalidWrapped = Buffer.alloc(wrappedLength, 0x5a);
      const provider: EnvelopeProvider = {
        async wrapDataKey() { return invalidWrapped; },
        async unwrapDataKey(wrapped) { return wrapped; },
      };
      await assert.rejects(
        () => new DbInstallationStore(db, KEY, provider).storeInstallation(
          teamInstall('T1', 'xoxb-INVALID-WRAP'),
        ),
        EnvelopeUnavailableError,
      );
      assert.equal((await db.all('SELECT 1 AS x FROM installation')).length, 0);
      assert.ok(invalidWrapped.every((byte) => byte === 0), 'invalid provider output is scrubbed');
    });
  }
});

test('envelope: malformed or misplaced authenticated plaintext has one fixed secret-free error', async (t) => {
  const db = await openTestDb(t);
  const { provider } = fakeEnvelope();
  const store = new DbInstallationStore(db, KEY, provider);
  const token = 'xoxb-SYNTHETIC-NOT-A-REAL-TOKEN';
  await store.storeInstallation(teamInstall('T1', token));
  const query = { teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false } as const;

  const expectFixedError = async () => {
    await assert.rejects(
      () => store.fetchInstallation(query),
      (error: Error & { cause?: unknown }) => {
        assert.equal(error.message, 'vouchr: stored Slack installation data is invalid');
        assert.equal(error.cause, undefined, 'the plaintext-bearing parser error must not survive as a cause');
        assert.ok(!String(error).includes(token));
        return true;
      },
    );
  };

  // Both columns contain valid envelope ciphertext. A DB corruption/swap must not turn the decrypted
  // bot token into JSON.parse's input-reflecting error text.
  await db.run('UPDATE installation SET data=bot_token WHERE id=?', [':T1']);
  await expectFixedError();

  // Valid JSON of the wrong top-level shape is the same fixed failure, never a cast-through value.
  const scalar = await seal(JSON.stringify(token), KEY, provider);
  await db.run('UPDATE installation SET data=? WHERE id=?', [scalar, ':T1']);
  await expectFixedError();
});

test('envelope: direct rows require the explicit migration window and convert on write', async (t) => {
  const db = await openTestDb(t);
  // A row written BEFORE the envelope was enabled (direct scheme-0).
  await new DbInstallationStore(db, KEY).storeInstallation(teamInstall('T1', 'xoxb-LEGACY'));
  const legacyRow = (await db.get('SELECT data FROM installation')) as { data: unknown };
  const direct = tryDecryptDirect(Buffer.from(legacyRow.data as any), KEY);
  assert.ok(direct.ok && direct.scheme === 0, 'precondition: the seed row is authenticated scheme-0');

  // Production defaults fail closed: an envelope-enabled store never silently accepts a direct row.
  const { provider } = fakeEnvelope();
  await assert.rejects(
    () => new DbInstallationStore(db, KEY, provider).fetchInstallation({
      teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false,
    }),
  );

  // An operator must explicitly open the temporary migration window to read and rewrite direct rows.
  const env = new DbInstallationStore(
    db,
    KEY,
    provider,
    { allowDirectRowsDuringMigration: true },
  );
  const got = await env.fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false });
  assert.equal(got.bot?.token, 'xoxb-LEGACY');

  // Re-storing (re-install / token refresh) converts the row to envelope format.
  await env.storeInstallation(teamInstall('T1', 'xoxb-LEGACY'));
  const converted = (await db.get('SELECT data FROM installation')) as { data: unknown };
  assert.equal(Buffer.from(converted.data as any)[0], 0x01, 'the next write converts the row to envelope');
});

test('envelope: rotated KEK versions restore Vault + installation ciphertext into fresh PostgreSQL', async (t) => {
  const source = await openTestDb(t);
  const restored = await openTestDb(t);
  const oldKek = randomBytes(32);
  const newKek = randomBytes(32);
  const sourceState: VersionedKekState = {
    active: 1,
    keys: new Map([[1, oldKek], [2, newKek]]),
  };
  const sourceEnvelope = versionedEnvelope(sourceState);
  const oldIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U_OLD' };
  const newIdentity = { enterpriseId: null, teamId: 'T2', userId: 'U_NEW' };

  // Version 1 ciphertext exists on both credential-bearing production surfaces.
  await new Vault(source, KEY, {}, sourceEnvelope).upsert(userOwner(oldIdentity), 'github', {
    accessToken: 'tok-old', refreshToken: 'ref-old', scopes: '', expiresAt: null, externalAccount: null,
  });
  await new DbInstallationStore(source, KEY, sourceEnvelope)
    .storeInstallation(teamInstall('T1', 'xoxb-OLD'));

  // Rotate behind the stable provider: new writes use version 2 while version 1 remains available.
  sourceState.active = 2;
  await new Vault(source, KEY, {}, sourceEnvelope).upsert(userOwner(newIdentity), 'github', {
    accessToken: 'tok-new', refreshToken: 'ref-new', scopes: '', expiresAt: null, externalAccount: null,
  });
  await new DbInstallationStore(source, KEY, sourceEnvelope)
    .storeInstallation(teamInstall('T2', 'xoxb-NEW'));

  // Restore the exact ciphertext bytes—not re-sealed values—into a separately migrated schema.
  await restoreRows(source, restored, 'connection', CONNECTION_COLUMNS);
  await restoreRows(source, restored, 'installation', INSTALLATION_COLUMNS);

  // A new process/provider with both retained KEK versions opens old and new rows on both surfaces.
  const restoreState: VersionedKekState = {
    active: 2,
    keys: new Map([[1, Buffer.from(oldKek)], [2, Buffer.from(newKek)]]),
  };
  const restoreEnvelope = versionedEnvelope(restoreState);
  const restoreVault = new Vault(restored, KEY, {}, restoreEnvelope);
  const restoreInstallations = new DbInstallationStore(restored, KEY, restoreEnvelope);
  assert.equal((await restoreVault.get(userOwner(oldIdentity), 'github'))?.accessToken, 'tok-old');
  assert.equal((await restoreVault.get(userOwner(newIdentity), 'github'))?.refreshToken, 'ref-new');
  assert.equal((await restoreInstallations.fetchInstallation({
    teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false,
  })).bot?.token, 'xoxb-OLD');
  assert.equal((await restoreInstallations.fetchInstallation({
    teamId: 'T2', enterpriseId: undefined, isEnterpriseInstall: false,
  })).bot?.token, 'xoxb-NEW');
  const restoredTokenRows = await restored.all<{ team_id: string; bot_token: Buffer }>(
    'SELECT team_id, bot_token FROM installation ORDER BY team_id',
  );
  assert.deepEqual(
    await Promise.all(restoredTokenRows.map(async (row) => [
      row.team_id,
      await openEnvelope(Buffer.from(row.bot_token), restoreEnvelope),
    ])),
    [['T1', 'xoxb-OLD'], ['T2', 'xoxb-NEW']],
    'the separately encrypted bot_token column also restores under both KEK versions',
  );

  // The database + direct master key alone opens neither envelope surface.
  await assert.rejects(() => new Vault(restored, KEY).get(userOwner(oldIdentity), 'github'));
  await assert.rejects(() => new DbInstallationStore(restored, KEY).fetchInstallation({
    teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false,
  }));

  // Retiring a still-referenced old KEK version fails closed for old rows while version-2 rows remain
  // healthy. This is why operators retain every version referenced by live rows and backups.
  restoreState.keys.delete(1);
  await assert.rejects(() => restoreVault.get(userOwner(oldIdentity), 'github'), EnvelopeUnavailableError);
  await assert.rejects(
    () => restoreInstallations.fetchInstallation({
      teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false,
    }),
    EnvelopeUnavailableError,
  );
  assert.equal((await restoreVault.get(userOwner(newIdentity), 'github'))?.accessToken, 'tok-new');
  assert.equal((await restoreInstallations.fetchInstallation({
    teamId: 'T2', enterpriseId: undefined, isEnterpriseInstall: false,
  })).bot?.token, 'xoxb-NEW');
});
