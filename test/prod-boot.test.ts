import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { assertProductionConfig, usingPostgres, isProduction } from '../src/core/options';
import { createVouchr, defineProvider } from '../src';

// A throwaway envelope provider stand-in: the assertion only checks presence (!= null), never calls it.
const ENVELOPE: any = { wrapDataKey: async () => Buffer.alloc(0), unwrapDataKey: async () => Buffer.alloc(0) };
const PG = 'postgres://u:p@localhost:5432/v';

// Keep these tests hermetic: the env can carry DB URLs / NODE_ENV that would otherwise leak in.
function withCleanEnv(fn: () => void): void {
  const saved = { ...process.env };
  delete process.env.DATABASE_URL;
  delete process.env.VOUCHR_DATABASE_URL;
  delete process.env.VOUCHR_PRODUCTION;
  delete process.env.NODE_ENV;
  try { fn(); } finally { process.env = saved; }
}

test('prod + SQLite (no databaseUrl) fails fast', () => {
  withCleanEnv(() => {
    assert.throws(
      () => assertProductionConfig({ production: true, envelope: ENVELOPE }),
      /requires Postgres in production/,
    );
  });
});

test('prod + Postgres but envelope OFF fails fast (the footgun: URL alone is not enough)', () => {
  withCleanEnv(() => {
    assert.equal(usingPostgres({ databaseUrl: PG }), true); // URL scheme is fine...
    assert.throws(
      () => assertProductionConfig({ production: true, databaseUrl: PG }), // ...but envelope is undefined
      /requires an envelope provider in production/,
    );
  });
});

test('prod + Postgres + envelope passes', () => {
  withCleanEnv(() => {
    assert.doesNotThrow(() =>
      assertProductionConfig({ production: true, databaseUrl: PG, envelope: ENVELOPE }),
    );
  });
});

test('non-production: SQLite + no envelope is fine (zero-config dev path unchanged)', () => {
  withCleanEnv(() => {
    assert.equal(isProduction({}), false);
    assert.doesNotThrow(() => assertProductionConfig({})); // no production flag, no env
  });
});

test('NODE_ENV=production opts in even without an explicit flag', () => {
  withCleanEnv(() => {
    process.env.NODE_ENV = 'production';
    assert.throws(() => assertProductionConfig({}), /requires Postgres in production/);
  });
});

test('createVouchr: non-prod SQLite boots; prod SQLite throws before opening the DB', async () => {
  await withCleanEnvAsync(async () => {
    const provider = defineProvider({
      id: 'acme', credential: 'key', authorizeUrl: '', tokenUrl: '',
      scopesDefault: [], egressAllow: ['api.acme.test'], refresh: 'none', pkce: false,
    });
    // Default (non-prod) path: SQLite in-memory still boots.
    const lan = await createVouchr({ providers: [provider], baseUrl: 'https://x.test', dbPath: ':memory:' });
    await lan.db.close();
    // Prod on SQLite: must reject (and before any DB side effect — no databaseUrl given).
    await assert.rejects(
      createVouchr({ providers: [provider], baseUrl: 'https://x.test', dbPath: ':memory:', production: true }),
      /requires Postgres in production/,
    );
  });
});

async function withCleanEnvAsync(fn: () => Promise<void>): Promise<void> {
  const saved = { ...process.env };
  delete process.env.DATABASE_URL;
  delete process.env.VOUCHR_DATABASE_URL;
  delete process.env.VOUCHR_PRODUCTION;
  delete process.env.NODE_ENV;
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64'); // loadMasterKey needs one to boot
  try { await fn(); } finally { process.env = saved; }
}
