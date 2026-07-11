import { test, type TestContext } from 'node:test';
import { openTestDb, testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { openDb, type Db } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { rekey } from '../src/core/rekey';
import { toBuffer, tryDecryptDirect, type EnvelopeProvider, type Keyring } from '../src/core/crypto';
import { DbInstallationStore } from '../src/adapters/installationStore';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

// `vouchr rekey` engine (#115): converge every direct-path blob onto the primary key without
// ever losing a row. Seeds are written through the SAME code paths production uses (Vault,
// DbInstallationStore) so the fixtures are real current-format ciphertexts, never committed blobs.

const OLD = randomBytes(32);
const NEW = randomBytes(32);

const ring = (primary: { id: string | null; key: Buffer }, rest: { id: string; key: Buffer }[] = [], idless?: Buffer): Keyring => {
  const listed = primary.id === null ? rest : [{ id: primary.id as string, key: primary.key }, ...rest];
  const idlessKey = primary.id === null ? primary.key : idless;
  return {
    primary,
    byId: new Map(listed.map((e) => [e.id, e.key])),
    legacy: [...(idlessKey ? [{ id: null as string | null, key: idlessKey }] : []), ...listed],
  };
};
/** The migration-window ring: new primary 'k2025', old key still listed as 'k2019'. */
const ROTATION = ring({ id: 'k2025', key: NEW }, [{ id: 'k2019', key: OLD }]);
/** After rotation completes and the old key is removed from env. */
const NEW_ONLY = ring({ id: 'k2025', key: NEW });

const ident = (u: string): SlackIdentity => ({ enterpriseId: null, teamId: 'T1', userId: u });
const tok = (accessToken: string, refreshToken: string | null = null) =>
  ({ accessToken, refreshToken, scopes: 's', expiresAt: null, externalAccount: null });

const KEK = randomBytes(32);
const envelope: EnvelopeProvider = {
  async wrapDataKey(dek) {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', KEK, iv);
    const ct = Buffer.concat([c.update(dek), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]);
  },
  async unwrapDataKey(w) {
    const d = createDecipheriv('aes-256-gcm', KEK, w.subarray(0, 12));
    d.setAuthTag(w.subarray(12, 28));
    return Buffer.concat([d.update(w.subarray(28)), d.final()]);
  },
};

/** Mixed-history store: scheme-0 rows (old code), a keyed non-primary row, an envelope row, a
 *  secret-free reference row, and an installation row — every case rekey must discriminate. */
async function seed(t: TestContext): Promise<Db> {
  const db = await openTestDb(t);
  const legacyVault = new Vault(db, OLD); // today's direct writer → scheme-0
  await legacyVault.upsert(userOwner(ident('U1')), 'github', tok('TOK_U1', 'REF_U1'));
  await legacyVault.upsert(userOwner(ident('U2')), 'github', tok('TOK_U2'));
  // Written mid-migration under the OLD key while it was already listed with an id → scheme-2 'k2019'.
  await new Vault(db, ring({ id: 'k2019', key: OLD })).upsert(userOwner(ident('U3')), 'github', tok('TOK_U3'));
  // Envelope row: rotation is the KMS's job; rekey must leave the bytes alone.
  await new Vault(db, OLD, {}, envelope).upsert(userOwner(ident('U4')), 'github', tok('TOK_U4'));
  // External-reference row: no ciphertext at all.
  await legacyVault.reference(userOwner(ident('U5')), 'github', { source: 'aws-sm', secretRef: 'arn:aws:sm:x' });
  // Installation row (bot_token + data), written by the current store under the old key.
  await new DbInstallationStore(db, OLD).storeInstallation({
    team: { id: 'T1' }, enterprise: undefined, isEnterpriseInstall: false,
    bot: { token: 'xoxb-INSTALL-SECRET', scopes: [], id: 'B1', userId: 'UB' },
  } as any);
  return db;
}

async function allBlobs(db: Db): Promise<Buffer[]> {
  const conn = await db.all<any>('SELECT access_token_enc, refresh_token_enc FROM connection');
  const inst = await db.all<any>('SELECT bot_token, data FROM installation');
  return [
    ...conn.flatMap((r) => [r.access_token_enc, r.refresh_token_enc]),
    ...inst.flatMap((r) => [r.bot_token, r.data]),
  ].filter((b) => b != null).map(toBuffer);
}

test('rekey: dry-run classifies per key/scheme and writes nothing', async (t) => {
  const db = await seed(t);
  const before = (await allBlobs(db)).map((b) => b.toString('hex')).sort();

  const r = await rekey(db, ROTATION, { dryRun: true });
  // 7 direct blobs (U1 access+refresh, U2 access, U3 access, install bot_token+data... wait: 6) + 1 envelope.
  assert.equal(r.bySource['scheme0 (id-less key)'], undefined, 'no id-less key in this ring');
  assert.equal(r.bySource["scheme0 (key 'k2019')"], 5, 'U1 access+refresh, U2 access, install bot+data');
  assert.equal(r.bySource["scheme2 (key 'k2019')"], 1, 'U3 access');
  assert.equal(r.envelope, 1, 'U4 access is KMS-wrapped');
  assert.equal(r.reencrypted, 6);
  assert.equal(r.alreadyPrimary, 0);
  assert.equal(r.unreadable, 0);
  assert.equal(r.scanned, 7);

  const after = (await allBlobs(db)).map((b) => b.toString('hex')).sort();
  assert.deepEqual(after, before, 'dry-run must not touch a single byte');
  await db.close();
});

test('rekey: converges the store onto the primary, skips envelope rows, stays idempotent', async (t) => {
  const db = await seed(t);
  const envBefore = toBuffer((await db.get<any>(`SELECT access_token_enc AS b FROM connection WHERE owner_id='U4'`)).b);

  const r = await rekey(db, ROTATION);
  assert.equal(r.reencrypted, 6);
  assert.equal(r.unreadable, 0);
  assert.equal(r.skippedConcurrent, 0);

  // Everything direct now reads with the NEW key alone — the old key can leave the env.
  const rotated = new Vault(db, NEW_ONLY);
  assert.equal((await rotated.get(userOwner(ident('U1')), 'github'))?.accessToken, 'TOK_U1');
  assert.equal((await rotated.get(userOwner(ident('U1')), 'github'))?.refreshToken, 'REF_U1');
  assert.equal((await rotated.get(userOwner(ident('U2')), 'github'))?.accessToken, 'TOK_U2');
  assert.equal((await rotated.get(userOwner(ident('U3')), 'github'))?.accessToken, 'TOK_U3');
  const fetched = await new DbInstallationStore(db, NEW_ONLY).fetchInstallation({ teamId: 'T1', enterpriseId: undefined, isEnterpriseInstall: false });
  assert.equal(fetched.bot?.token, 'xoxb-INSTALL-SECRET');

  // Reference row untouched; envelope bytes untouched; SEC-1: no plaintext in any persisted blob.
  const ref = await db.get<any>(`SELECT source, secret_ref, access_token_enc FROM connection WHERE owner_id='U5'`);
  assert.equal(ref.source, 'aws-sm');
  assert.equal(ref.access_token_enc, null);
  const envAfter = toBuffer((await db.get<any>(`SELECT access_token_enc AS b FROM connection WHERE owner_id='U4'`)).b);
  assert.ok(envAfter.equals(envBefore), 'envelope rows are the KMS\'s to rotate, not rekey\'s');
  for (const b of await allBlobs(db)) {
    const s = b.toString('latin1');
    for (const secret of ['TOK_U1', 'REF_U1', 'TOK_U2', 'TOK_U3', 'TOK_U4', 'xoxb-INSTALL-SECRET']) {
      assert.ok(!s.includes(secret), 'no persisted blob may contain a plaintext secret');
    }
  }

  // Idempotent: run 2 rewrites nothing, and the dry-run "zero old-key rows" check the runbook
  // relies on holds.
  const again = await rekey(db, ROTATION, { dryRun: true });
  assert.equal(again.reencrypted, 0);
  assert.equal(again.alreadyPrimary, 6);
  assert.equal(again.bySource["scheme0 (key 'k2019')"], undefined);
  assert.equal(again.bySource["scheme2 (key 'k2019')"], undefined);
  assert.equal(again.bySource["scheme2 (key 'k2025')"], 6);
  await db.close();
});

test('rekey: interrupted mid-run leaves a mixed but fully readable store; a re-run converges', async (t) => {
  const db = await seed(t);
  // Abort partway through the connection table (rows stream in random-UUID order; after 3 of the
  // 5 rows at least one direct row was rewritten, and the installation table was never reached).
  await assert.rejects(
    rekey(db, ROTATION, {
      batchSize: 1,
      onProgress: (table, done) => { if (table === 'connection' && done >= 3) throw new Error('simulated crash'); },
    }),
    /simulated crash/,
  );

  // Mixed state: at least one blob still under the old key, but EVERY blob readable via the
  // migration ring (this is what makes the crash safe to retry).
  const mixed = await allBlobs(db);
  const sources = mixed.map((b) => tryDecryptDirect(b, ROTATION));
  assert.ok(sources.some((r) => r.ok && r.keyId === 'k2025'), 'some rows were rewritten before the crash');
  assert.ok(sources.some((r) => r.ok && r.keyId === 'k2019'), 'some rows still carry the old key');
  assert.ok(sources.every((r) => r.ok || r.reason === 'maybe-envelope'), 'nothing became unreadable');

  const r = await rekey(db, ROTATION);
  assert.equal(r.unreadable, 0);
  const converged = await rekey(db, ROTATION, { dryRun: true });
  assert.equal(converged.reencrypted, 0, 're-run converges the interrupted rotation');
  assert.equal(converged.alreadyPrimary, 6);
  await db.close();
});

test('rekey: a concurrent token refresh mid-run is never clobbered (guarded write, re-run converges)', async (t) => {
  const db = await seed(t);
  const legacyVault = new Vault(db, OLD);
  const u1RowId = ((await db.get<any>(`SELECT id FROM connection WHERE owner_id='U1'`)) as any).id as string;
  // Interleave via the Db seam: just before rekey's guarded UPDATE on U1's row lands, that row's
  // tokens are refreshed out-of-band (exactly what a live injector refresh does mid-rotation).
  let raced = false;
  const racy: Db = {
    get: db.get.bind(db),
    all: db.all.bind(db),
    exec: db.exec.bind(db),
    close: db.close.bind(db),
    run: async (sql, params) => {
      if (!raced && sql.trimStart().startsWith('UPDATE connection') && params?.includes(u1RowId)) {
        raced = true;
        await legacyVault.updateTokens(userOwner(ident('U1')), 'github', {
          accessToken: 'TOK_U1_ROTATED', refreshToken: null, scopes: 's', expiresAt: null,
        });
      }
      return db.run(sql, params);
    },
  };

  const r = await rekey(racy, ROTATION, { batchSize: 1 });
  assert.ok(raced);
  assert.equal(r.skippedConcurrent, 2, "U1's access+refresh write lost the race and was left alone");
  // The refreshed (newer) token survived — rekey did not resurrect the stale one.
  assert.equal((await new Vault(db, ROTATION).get(userOwner(ident('U1')), 'github'))?.accessToken, 'TOK_U1_ROTATED');

  const again = await rekey(db, ROTATION);
  assert.equal(again.unreadable, 0);
  assert.equal((await rekey(db, ROTATION, { dryRun: true })).reencrypted, 0, 're-run converges');
  assert.equal((await new Vault(db, NEW_ONLY).get(userOwner(ident('U1')), 'github'))?.accessToken, 'TOK_U1_ROTATED');
  await db.close();
});

test('vouchr rekey CLI: dry-run → rekey → clean dry-run; counts only, never key material or tokens', async (t) => {
  const dbPath = await testDbUrl(t);
  {
    const db = await openDb({ databaseUrl: dbPath });
    const vault = new Vault(db, OLD);
    await vault.upsert(userOwner(ident('U1')), 'github', tok('TOK_CLI_SECRET'));
    await vault.upsert(userOwner(ident('U2')), 'github', tok('TOK_CLI_SECRET2'));
    await db.close();
  }
  const env = {
    ...process.env,
    VOUCHR_DATABASE_URL: dbPath,
    VOUCHR_MASTER_KEY: OLD.toString('base64'), // the id-less legacy key, still deployed
    VOUCHR_MASTER_KEYS: `k2025:${NEW.toString('base64')}`,
  };
  const run = (...args: string[]) =>
    spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'rekey', ...args], { env, encoding: 'utf8' });

  const dry = run('--dry-run');
  assert.equal(dry.status, 0, dry.stderr);
  assert.match(dry.stdout, /No changes made/);
  assert.match(dry.stdout, /would re-encrypt: 2/);
  {
    // dry-run really wrote nothing: rows still decrypt under the OLD key alone
    const db = await openDb({ databaseUrl: dbPath });
    assert.equal((await new Vault(db, OLD).get(userOwner(ident('U1')), 'github'))?.accessToken, 'TOK_CLI_SECRET');
    await db.close();
  }

  const real = run();
  assert.equal(real.status, 0, real.stderr);
  assert.match(real.stdout, /re-encrypted: 2/);
  const after = run('--dry-run'); // the runbook's "zero old-key rows" verification
  assert.equal(after.status, 0);
  assert.match(after.stdout, /already under primary: 2/);
  assert.match(after.stdout, /would re-encrypt: 0/);

  // SEC-1: no key material, no token plaintext, in any output of any invocation.
  for (const out of [dry, real, after].flatMap((r) => [r.stdout, r.stderr])) {
    assert.ok(!out.includes(OLD.toString('base64')) && !out.includes(NEW.toString('base64')), 'no key material in output');
    assert.ok(!out.includes('TOK_CLI_SECRET'), 'no token plaintext in output');
  }
  {
    const db = await openDb({ databaseUrl: dbPath });
    assert.equal((await new Vault(db, NEW_ONLY).get(userOwner(ident('U2')), 'github'))?.accessToken, 'TOK_CLI_SECRET2');
    await db.close();
  }

  // Fail-closed CLI path: a key removed too early → non-zero exit + actionable error (UX-5).
  const gone = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'rekey', '--dry-run'], {
    env: { ...process.env, VOUCHR_DATABASE_URL: dbPath, VOUCHR_MASTER_KEYS: `k2026:${randomBytes(32).toString('base64')}` },
    encoding: 'utf8',
  });
  assert.equal(gone.status, 1);
  assert.match(gone.stderr, /NO configured key/);
  assert.match(gone.stderr, /k2025/, 'names the missing key id');
  assert.match(gone.stderr, /VOUCHR_MASTER_KEYS/, 'says how to fix it');
});

test('rekey: blobs under a missing key are reported (with the unknown id), never dropped or rewritten', async (t) => {
  const db = await seed(t);
  const GONE = randomBytes(32);
  await new Vault(db, ring({ id: 'retired', key: GONE })).upsert(userOwner(ident('U9')), 'github', tok('TOK_U9'));
  const strandedBefore = toBuffer((await db.get<any>(`SELECT access_token_enc AS b FROM connection WHERE owner_id='U9'`)).b);

  const r = await rekey(db, ROTATION);
  assert.equal(r.unreadable, 1);
  assert.deepEqual(r.unknownKeyIds, ['retired']);
  const strandedAfter = toBuffer((await db.get<any>(`SELECT access_token_enc AS b FROM connection WHERE owner_id='U9'`)).b);
  assert.ok(strandedAfter.equals(strandedBefore), 'an unreadable blob must be left byte-for-byte intact');
  // Restore the missing key → the same row converges.
  const healed = await rekey(db, ring({ id: 'k2025', key: NEW }, [{ id: 'retired', key: GONE }]));
  assert.equal(healed.unreadable, 0);
  assert.equal((await new Vault(db, NEW_ONLY).get(userOwner(ident('U9')), 'github'))?.accessToken, 'TOK_U9');
  await db.close();
});
