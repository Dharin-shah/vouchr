// FROZEN FIXTURE — the database exactly as vouchr v0.2.0 shipped it.
//
// DO NOT update this file when the schema changes — that is the point. It exists so
// test/migration-upgrade.test.ts can build a REAL previous-version database and prove that the
// CURRENT openDb() migrations upgrade it losslessly (rows intact, encrypted tokens still decrypt,
// idempotent re-open). On each future release, add a NEW frozen fixture file next to this one.
//
// The DDL below is copied verbatim from `git show v0.2.0:src/core/db.ts` (schema()), including its
// blob/int type-name parameterization, so the SQLite and Postgres legs are both faithful to what
// actually shipped: v0.2.0 had NO channel_preview table and NO meta/schema_version marker.
// Deliberately self-contained: it imports NOTHING from current src/ (that would defeat the
// freeze) — the DDL and encryptV020() below are both verbatim copies of what v0.2.0 shipped, so
// a future schema OR crypto/storage-format change cannot silently alter what this fixture writes.
// The upgrade test decrypting these bytes with the CURRENT code is the real cross-version check.
import { createCipheriv, randomBytes } from 'node:crypto';

export type FixtureEngine = 'sqlite' | 'pg';

/** Fixed, obviously-fake test key (never a real secret): 32 bytes of 0x42. */
export const FIXTURE_KEY = Buffer.alloc(32, 0x42);

/**
 * v0.2.0's encrypt(), copied verbatim from `git show v0.2.0:src/core/crypto.ts` — the frozen
 * WRITE side of this fixture. AES-256-GCM direct under the master key, layout iv(12)|tag(16)|ct,
 * no scheme byte. Only the random IV varies per run; the format is what the freeze protects.
 */
function encryptV020(plaintext: string, key: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

/** Fixed seed epoch (ms) so every seeded timestamp is exactly assertable after migration. */
const T = 1750000000000;

/**
 * Everything the fixture seeds, exported so the upgrade test can assert losslessness value-for-value.
 * Tokens are obviously-fake `test-token-…` strings (SEC-1: the test asserts the plaintext never
 * appears in the encrypted columns at rest).
 */
export const SEED = {
  teamId: 'T_FIXTURE',
  /** Two per-user credentials (one with a refresh token, one without). */
  users: [
    {
      connectionId: 'test-conn-v020-alice',
      userId: 'U_ALICE',
      provider: 'github',
      accessToken: 'test-token-alice-github-v020',
      refreshToken: 'test-refresh-alice-github-v020',
      scopes: 'read:user repo',
      externalAccount: 'alice-gh',
      createdAt: T,
      updatedAt: T,
      lastUsedAt: T,
    },
    {
      connectionId: 'test-conn-v020-bob',
      userId: 'U_BOB',
      provider: 'github',
      accessToken: 'test-token-bob-github-v020',
      refreshToken: null,
      scopes: 'repo',
      externalAccount: null,
      createdAt: T + 1000,
      updatedAt: T + 1000,
      lastUsedAt: null,
    },
  ],
  /** One shared channel-owned credential. */
  channel: {
    connectionId: 'test-conn-v020-ops',
    channelId: 'C_OPS',
    provider: 'github',
    accessToken: 'test-token-ops-channel-v020',
    refreshToken: null,
    scopes: 'repo',
    externalAccount: 'ops-bot',
    createdAt: T + 2000,
    updatedAt: T + 2000,
    lastUsedAt: null,
  },
  /** One session grant. */
  sessionGrant: {
    channel: 'C_OPS',
    thread: '1750000000.000100',
    userId: 'U_ALICE',
    provider: 'github',
    createdAt: T,
    expiresAt: T + 3_600_000,
  },
  /** One in-flight consent request. */
  consent: {
    state: 'test-state-v020-fixture',
    userId: 'U_BOB',
    provider: 'github',
    channel: 'C_OPS',
    pkceVerifier: 'test-pkce-verifier-v020',
    createdAt: T,
  },
  /** Audit rows shaped exactly as v0.2.0's audit.record() wrote them. */
  audit: [
    {
      id: 'test-audit-v020-1',
      userId: 'U_ALICE',
      provider: 'github',
      action: 'connect',
      actor: null,
      channel: null,
      meta: '{"account":"alice-gh"}',
      at: T,
    },
    {
      id: 'test-audit-v020-2',
      userId: 'U_ALICE',
      provider: 'github',
      action: 'inject',
      actor: null,
      channel: 'C_OPS',
      meta: '{"host":"api.github.com","method":"GET","status":200,"channel":"C_OPS"}',
      at: T + 5000,
    },
  ],
} as const;

/**
 * v0.2.0 schema DDL, verbatim, through the same type-name parameterization v0.2.0's openDb() used:
 * schema('BLOB', 'INTEGER') on SQLite, schema('BYTEA', 'BIGINT') on Postgres.
 */
export function schemaSqlV020(engine: FixtureEngine): string {
  const [blob, int] = engine === 'pg' ? ['BYTEA', 'BIGINT'] : ['BLOB', 'INTEGER'];
  return `
    CREATE TABLE IF NOT EXISTS connection (
      id TEXT PRIMARY KEY,
      enterprise_id TEXT,
      team_id TEXT NOT NULL,
      owner_kind TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'vault',
      access_token_enc ${blob},
      refresh_token_enc ${blob},
      secret_ref TEXT,
      scopes TEXT NOT NULL,
      expires_at ${int},
      external_account TEXT,
      created_at ${int} NOT NULL,
      updated_at ${int} NOT NULL,
      last_used_at ${int},
      UNIQUE (team_id, owner_kind, owner_id, provider)
    );

    CREATE TABLE IF NOT EXISTS consent_request (
      state TEXT PRIMARY KEY,
      enterprise_id TEXT,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      channel TEXT,
      pkce_verifier TEXT NOT NULL,
      created_at ${int} NOT NULL
    );

    CREATE TABLE IF NOT EXISTS channel_config (
      team_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      provider TEXT NOT NULL,
      mode TEXT NOT NULL,
      PRIMARY KEY (team_id, channel, provider)
    );

    CREATE TABLE IF NOT EXISTS channel_tool (
      team_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      provider TEXT NOT NULL,
      enabled ${int} NOT NULL,
      PRIMARY KEY (team_id, channel, provider)
    );

    CREATE TABLE IF NOT EXISTS session_grant (
      team_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      thread TEXT NOT NULL,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      created_at ${int} NOT NULL,
      expires_at ${int} NOT NULL,
      PRIMARY KEY (team_id, channel, thread, user_id, provider)
    );

    CREATE TABLE IF NOT EXISTS audit (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      action TEXT NOT NULL,
      actor TEXT,
      channel TEXT,
      meta TEXT,
      at ${int} NOT NULL
    );

    CREATE TABLE IF NOT EXISTS installation (
      id TEXT PRIMARY KEY,
      enterprise_id TEXT,
      team_id TEXT,
      bot_token ${blob},
      data ${blob} NOT NULL,
      updated_at ${int} NOT NULL
    );`;
}

/**
 * Seed SQL: the SEED rows above, laid out exactly as v0.2.0 wrote them (column lists match
 * v0.2.0's Vault.upsert / Consent.begin / SessionGrants.grant / Audit.record inserts). Encrypted
 * columns are produced at call time by the frozen encryptV020() above against FIXTURE_KEY, emitted
 * as engine-native blob literals. Every non-blob value is a fixed, quote-free constant, so inlining
 * literals (no placeholders) is safe and keeps the fixture runnable with a bare exec() on both
 * engines.
 */
export function seedSqlV020(engine: FixtureEngine): string {
  const blob = (b: Buffer) => (engine === 'pg' ? `'\\x${b.toString('hex')}'` : `X'${b.toString('hex')}'`);
  const enc = (plaintext: string) => blob(encryptV020(plaintext, FIXTURE_KEY));
  const s = (v: string | null) => (v === null ? 'NULL' : `'${v}'`);
  const n = (v: number | null) => (v === null ? 'NULL' : String(v));

  const connections = [
    ...SEED.users.map((u) => ({ ...u, ownerKind: 'user', ownerId: u.userId })),
    { ...SEED.channel, ownerKind: 'channel', ownerId: SEED.channel.channelId },
  ];
  const stmts = connections.map(
    (c) => `INSERT INTO connection
      (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
       access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
       external_account, created_at, updated_at, last_used_at)
     VALUES (${s(c.connectionId)}, NULL, ${s(SEED.teamId)}, ${s(c.ownerKind)}, ${s(c.ownerId)}, ${s(c.provider)}, 'vault',
       ${enc(c.accessToken)}, ${c.refreshToken === null ? 'NULL' : enc(c.refreshToken)}, NULL, ${s(c.scopes)}, NULL,
       ${s(c.externalAccount)}, ${n(c.createdAt)}, ${n(c.updatedAt)}, ${n(c.lastUsedAt)});`,
  );

  const g = SEED.sessionGrant;
  stmts.push(`INSERT INTO session_grant (team_id, channel, thread, user_id, provider, created_at, expires_at)
     VALUES (${s(SEED.teamId)}, ${s(g.channel)}, ${s(g.thread)}, ${s(g.userId)}, ${s(g.provider)}, ${n(g.createdAt)}, ${n(g.expiresAt)});`);

  const c = SEED.consent;
  stmts.push(`INSERT INTO consent_request (state, enterprise_id, team_id, user_id, provider, channel, pkce_verifier, created_at)
     VALUES (${s(c.state)}, NULL, ${s(SEED.teamId)}, ${s(c.userId)}, ${s(c.provider)}, ${s(c.channel)}, ${s(c.pkceVerifier)}, ${n(c.createdAt)});`);

  for (const a of SEED.audit) {
    stmts.push(`INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at)
     VALUES (${s(a.id)}, ${s(SEED.teamId)}, ${s(a.userId)}, ${s(a.provider)}, ${s(a.action)}, ${s(a.actor)}, ${s(a.channel)}, ${s(a.meta)}, ${n(a.at)});`);
  }

  return stmts.join('\n');
}
