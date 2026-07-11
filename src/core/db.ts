import BetterSqlite3 from 'better-sqlite3';
import { Pool, types, type PoolClient } from 'pg';
import { isPostgresUrl } from './options';

/**
 * Minimal async data handle: the seam that lets the same store code run on SQLite
 * (embedded, the zero-config default) or Postgres (for stateless / multi-instance infra).
 * Not a public extension point: just the two backends this project ships.
 *
 * All store SQL uses `?` placeholders; the Postgres driver rewrites them to `$1..$n`.
 */
export interface Db {
  get<T = any>(sql: string, params?: any[]): Promise<T | undefined>;
  all<T = any>(sql: string, params?: any[]): Promise<T[]>;
  run(sql: string, params?: any[]): Promise<{ changes: number }>;
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
  /**
   * Postgres only: run `fn` inside a transaction holding a cross-process advisory lock for `key`,
   * with `fn`'s Db bound to that locked transaction (so its reads/writes see the same tx, and a
   * concurrent caller blocks until COMMIT). Absent on SQLite — a single process is already
   * serialized by the in-process single-flight map in the injector, so callers fall back to
   * running `fn` directly. Used by refresh coordination to re-read-under-lock and avoid two pods
   * both consuming a rotating refresh token.
   */
  withRefreshLock?<T>(key: string, fn: (txDb: Db) => Promise<T>): Promise<T>;
  /**
   * Run `fn`'s statements atomically (BEGIN … COMMIT, ROLLBACK on throw), with `fn`'s Db bound to
   * the transaction. Used where one logical mutation spans two tables (e.g. a connection write +
   * its notification_state purge, #117) so a mid-sequence failure can't half-commit. Optional only
   * so minimal test stubs keep compiling — BOTH shipped backends implement it; callers without it
   * fall back to sequential statements (pre-#117 behavior).
   */
  transaction?<T>(fn: (txDb: Db) => Promise<T>): Promise<T>;
}

export interface DbOptions {
  /** SQLite file path (default). `:memory:` for tests. */
  dbPath?: string;
  /** Postgres connection string. Takes precedence over dbPath when set. */
  databaseUrl?: string;
}

class SqliteDb implements Db {
  // FIFO mutex over the ONE better-sqlite3 connection. EVERY external operation — ordinary
  // get/all/run/exec AND whole transaction() blocks — runs through this queue in strict arrival
  // order. Without it, a statement awaited by another handler while a transaction holds BEGIN
  // would execute on the same connection, silently JOIN that transaction, report success — and
  // then vanish if the transaction rolls back (reproduced data loss, not a theoretical race).
  // A promise chain is inherently fair: each operation appends behind the current tail, so a
  // long-running transaction can never be overtaken.
  private queue: Promise<unknown> = Promise.resolve();
  constructor(private db: BetterSqlite3.Database) {}

  /** Append `op` to the connection queue (FIFO). A failed op must not poison the queue. */
  private enqueue<T>(op: () => T | Promise<T>): Promise<T> {
    const run = this.queue.then(op);
    this.queue = run.catch(() => undefined);
    return run;
  }

  async get(sql: string, params: any[] = []) { return this.enqueue(() => this.db.prepare(sql).get(...params) as any); }
  async all(sql: string, params: any[] = []) { return this.enqueue(() => this.db.prepare(sql).all(...params) as any[]); }
  async run(sql: string, params: any[] = []) { return this.enqueue(() => ({ changes: this.db.prepare(sql).run(...params).changes })); }
  async exec(sql: string) { await this.enqueue(() => { this.db.exec(sql); }); } // migrations queue too

  async transaction<T>(fn: (txDb: Db) => Promise<T>): Promise<T> {
    // Holds the queue for the WHOLE transaction, so no outside statement can interleave into the
    // open BEGIN…COMMIT. `fn` receives a BOUND CHILD Db that executes directly against the
    // connection (reentrant — it must bypass the queue its owner already holds, or the first
    // in-transaction statement would deadlock), mirroring PgClientDb so store code stays
    // backend-agnostic. Nested transaction() on the child runs inline, like PgClientDb.
    return this.enqueue(async () => {
      this.db.exec('BEGIN IMMEDIATE');
      try {
        const out = await fn(new SqliteTxDb(this.db));
        this.db.exec('COMMIT');
        return out;
      } catch (e) {
        try { this.db.exec('ROLLBACK'); } catch { /* already rolled back (e.g. by SQLite itself) */ }
        throw e;
      }
    });
  }

  async close() { await this.enqueue(() => { this.db.close(); }); } // after every queued op drains
}

/** A Db bound INSIDE an open SQLite transaction: executes directly on the connection (the owning
 *  SqliteDb.transaction already holds the queue for its whole duration). Mirrors PgClientDb. */
class SqliteTxDb implements Db {
  constructor(private db: BetterSqlite3.Database) {}
  async get(sql: string, params: any[] = []) { return this.db.prepare(sql).get(...params) as any; }
  async all(sql: string, params: any[] = []) { return this.db.prepare(sql).all(...params) as any[]; }
  async run(sql: string, params: any[] = []) { return { changes: this.db.prepare(sql).run(...params).changes }; }
  async exec(sql: string) { this.db.exec(sql); }
  /** Already inside an open transaction: run inline, atomic with the outer tx (like PgClientDb). */
  async transaction<T>(fn: (txDb: Db) => Promise<T>): Promise<T> { return fn(this); }
  async close() { /* lifecycle owned by SqliteDb.transaction; nothing to do here */ }
}

// Positional rewrite. Our SQL never contains a literal '?', so a plain replace is safe.
function toPositional(sql: string): string { let i = 0; return sql.replace(/\?/g, () => `$${++i}`); }

class PgDb implements Db {
  // Dedicated small pool for token refresh, separate from the read pool, so a hung provider
  // /token endpoint inside a held lock can't starve the connections serving normal requests.
  private refreshPool?: Pool;
  constructor(private pool: Pool, private connectionString: string) {}
  async get(sql: string, params: any[] = []) { return (await this.pool.query(toPositional(sql), params)).rows[0]; }
  async all(sql: string, params: any[] = []) { return (await this.pool.query(toPositional(sql), params)).rows; }
  async run(sql: string, params: any[] = []) { return { changes: (await this.pool.query(toPositional(sql), params)).rowCount ?? 0 }; }
  async exec(sql: string) { await this.pool.query(sql); }

  async withRefreshLock<T>(key: string, fn: (txDb: Db) => Promise<T>): Promise<T> {
    if (!this.refreshPool) {
      this.refreshPool = new Pool({
        connectionString: this.connectionString,
        max: 4, // bounded: a stuck token endpoint caps at this many pinned backends, never the read pool
        connectionTimeoutMillis: 5_000,
        idleTimeoutMillis: 30_000,
      });
      // Attach the idle-client error handler exactly ONCE, at pool creation. If this sat after the
      // lazy-init it would re-register on every withRefreshLock call (unbounded 'error' listeners +
      // MaxListenersExceededWarning over a long-lived pod's lifetime).
      this.refreshPool.on('error', (e) => console.error('[vouchr] postgres refresh-pool idle-client error:', e.message));
    }
    const client = await this.refreshPool.connect();
    try {
      await client.query('BEGIN');
      // ponytail: hashtext is 32-bit, so two distinct keys can collide and over-serialize. That only
      // adds latency, never incorrectness. Upgrade to a 64-bit key (two-arg pg_advisory_xact_lock)
      // only if a real collision hot-spot shows up.
      // Acquire the lock BEFORE arming statement_timeout: a loser blocks on this SELECT until the
      // winner COMMITs, which can exceed 8s for a slow /token round-trip. If the 8s capped this wait
      // the loser would abort and throw instead of reusing the winner's rotated token. statement_timeout
      // is set only after the lock, to bound the in-lock DB statements (re-read / updateTokens) — not the
      // /token fetch, which is JS and bounded by the refresh pool size, not by statement_timeout.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [key]); // released at COMMIT
      await client.query("SET LOCAL statement_timeout = '8s'");
      const out = await fn(new PgClientDb(client));
      await client.query('COMMIT');
      return out;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw e;
    } finally {
      client.release();
    }
  }

  /** Plain transaction on one checked-out client (same shape as withRefreshLock, minus the lock). */
  async transaction<T>(fn: (txDb: Db) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const out = await fn(new PgClientDb(client));
      await client.query('COMMIT');
      return out;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw e;
    } finally {
      client.release();
    }
  }

  async close() {
    await this.pool.end();
    if (this.refreshPool) await this.refreshPool.end();
  }
}

/** A Db bound to a single checked-out client, so every query runs on the same (locked) transaction. */
class PgClientDb implements Db {
  constructor(private client: PoolClient) {}
  async get(sql: string, params: any[] = []) { return (await this.client.query(toPositional(sql), params)).rows[0]; }
  async all(sql: string, params: any[] = []) { return (await this.client.query(toPositional(sql), params)).rows; }
  async run(sql: string, params: any[] = []) { return { changes: (await this.client.query(toPositional(sql), params)).rowCount ?? 0 }; }
  async exec(sql: string) { await this.client.query(sql); }
  /** Already inside an open transaction (BEGIN'd by the owner): run inline, atomic with the outer tx. */
  async transaction<T>(fn: (txDb: Db) => Promise<T>): Promise<T> { return fn(this); }
  async close() { /* lifecycle owned by withRefreshLock (BEGIN/COMMIT/release); nothing to do here */ }
}

/**
 * Monotonic version of the schema this build writes, stamped into the `meta` table on every open.
 * Bump it whenever the schema changes shape. Version 1 = the schema at the release that introduced
 * the marker (post-v0.2.0: everything in schema() below, incl. channel_preview and audit.channel).
 * Version 2 = + the `union_optin` table (#112, purely additive).
 * Version 3 = + the `notification_state` table (#117, purely additive).
 * Version 4 = + the `approval_request` table (#113) AND the `connection.dry_run` column (#116) —
 *   both purely additive and idempotent (CREATE TABLE / ADD COLUMN IF NOT EXISTS run every open),
 *   so they share one version stamp: a v3 DB gains both, and either single-feature deploy converges.
 * Version 5 = + the `approval_request.query_hash` column (GHSA-pg84, purely additive). The DEFAULT
 *   '' means a pre-v5 grant matches only query-less requests after the upgrade — fail closed.
 */
export const SCHEMA_VERSION = 5;

// The marker table. TEXT-only, so it needs no engine type parameterization.
const META_DDL = `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`;

/**
 * Downgrade guard — runs BEFORE any migration DDL.
 *
 * - Marker present and newer than this build → throw, fail closed. Old code "migrating" a newer
 *   database is the one unrecoverable failure mode: it can corrupt encrypted credential rows.
 * - Marker present and ≤ current → proceed; the idempotent migrations bring the schema to current.
 * - No marker → either an EMPTY database (fresh install) or an existing PRE-MARKER deployment
 *   (tables, no `meta` row). Documented assumption: a marker-less database with tables was written
 *   by a vouchr ≤ the release that shipped this marker (≤ v0.2.x). That is safe to proceed on,
 *   because every schema change up to that release is an idempotent in-place migration that
 *   openDb() runs unconditionally — after which either kind of database IS at SCHEMA_VERSION,
 *   which is what stampSchemaVersion() then records. Newer databases always carry the marker, so
 *   from this release on the ambiguity cannot recur.
 */
async function guardSchemaVersion(db: Db): Promise<void> {
  await db.exec(META_DDL);
  const row = await db.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`);
  if (!row) return;
  const found = Number(row.value);
  if (!Number.isInteger(found) || found > SCHEMA_VERSION) {
    throw new Error(
      `vouchr: this database reports schema version ${row.value}, but this vouchr build supports up to ` +
        `schema version ${SCHEMA_VERSION}. Refusing to open it: running older code against a newer schema ` +
        `could corrupt encrypted credential rows. Upgrade the vouchr package to one that supports schema ` +
        `version ${row.value}, or restore a database backup taken at schema version ${SCHEMA_VERSION} or older.`,
    );
  }
}

/** Record that the database is now at this build's schema version (after migrations ran). */
async function stampSchemaVersion(db: Db): Promise<void> {
  await db.run(
    `INSERT INTO meta (key, value) VALUES ('schema_version', ?)
     ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
    [String(SCHEMA_VERSION)],
  );
}

/** Schema DDL, parameterized by the engine's blob/integer type names. */
function schema(blob: string, int: string): string {
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
      dry_run ${int} NOT NULL DEFAULT 0,
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

    CREATE TABLE IF NOT EXISTS channel_preview (
      team_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      provider TEXT NOT NULL,
      visibility TEXT NOT NULL,
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

    CREATE TABLE IF NOT EXISTS union_optin (
      team_id TEXT NOT NULL,
      channel_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      created_at ${int} NOT NULL,
      PRIMARY KEY (team_id, channel_id, user_id, provider)
    );

    CREATE TABLE IF NOT EXISTS approval_request (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      owner_kind TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      method TEXT NOT NULL,
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      query_hash TEXT NOT NULL DEFAULT '',
      channel TEXT NOT NULL,
      thread TEXT NOT NULL,
      status TEXT NOT NULL,
      approved_by TEXT,
      created_at ${int} NOT NULL,
      expires_at ${int} NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notification_state (
      team_id TEXT NOT NULL,
      owner_kind TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      type TEXT NOT NULL,
      last_notified_at ${int} NOT NULL,
      PRIMARY KEY (team_id, owner_kind, owner_id, provider, type)
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

/** Open (and migrate) the credential store. Postgres if a connection string is set, else SQLite. */
export async function openDb(opts: DbOptions = {}): Promise<Db> {
  const url = opts.databaseUrl ?? process.env.VOUCHR_DATABASE_URL ?? process.env.DATABASE_URL;
  if (isPostgresUrl(url)) {
    types.setTypeParser(20, (v) => parseInt(v, 10)); // int8 → JS number (ms timestamps are < 2^53)
    const pool = new Pool({
      connectionString: url,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
      statement_timeout: 10_000, // fail a request fast instead of hanging the Bolt handler
    });
    // pg emits 'error' on idle backend clients (DB restart, network drop). With no listener this
    // throws and kills the whole process; swallow it, pg reconnects on the next query.
    pool.on('error', (e) => console.error('[vouchr] postgres idle-client error:', e.message));
    const db = new PgDb(pool, url);
    try {
      await guardSchemaVersion(db); // fail closed on a newer-schema DB, before any migration runs
      await db.exec(schema('BYTEA', 'BIGINT'));
      // CREATE TABLE IF NOT EXISTS won't add `channel` to a pre-existing audit table; do it idempotently.
      await db.exec(`ALTER TABLE audit ADD COLUMN IF NOT EXISTS channel TEXT`);
      // #116 v4: system-only dry-run provenance on the credential row (never user/provider data).
      await db.exec(`ALTER TABLE connection ADD COLUMN IF NOT EXISTS dry_run BIGINT NOT NULL DEFAULT 0`);
      // GHSA-pg84 v5: canonical query digest on approval rows (a digest, never raw query values).
      await db.exec(`ALTER TABLE approval_request ADD COLUMN IF NOT EXISTS query_hash TEXT NOT NULL DEFAULT ''`);
      await stampSchemaVersion(db);
    } catch (e) {
      await db.close().catch(() => undefined);
      throw e;
    }
    return db;
  }

  const raw = new BetterSqlite3(opts.dbPath ?? process.env.VOUCHR_DB ?? 'vouchr.db');
  raw.pragma('journal_mode = WAL');
  raw.pragma('busy_timeout = 5000'); // wait, don't instantly SQLITE_BUSY, on a concurrent writer
  const db = new SqliteDb(raw);
  try {
    await guardSchemaVersion(db); // fail closed on a newer-schema DB, before any migration runs
    migrateSqlite(raw);
    await stampSchemaVersion(db);
  } catch (e) {
    await db.close().catch(() => undefined);
    throw e;
  }
  return db;
}

/** SQLite schema + the legacy (pre-owner-keying) rebuild. Postgres deploys start clean. */
function migrateSqlite(db: BetterSqlite3.Database): void {
  db.exec(schema('BLOB', 'INTEGER'));

  // Forward-migrate a pre-owner-keying DB (had user_id, no owner_kind) by rebuilding the table:
  // SQLite can't ALTER a UNIQUE constraint. Each old per-user row becomes an owner_kind='user' row;
  // ciphertext, enterprise_id and timestamps are preserved verbatim.
  const cols = (db.prepare(`PRAGMA table_info(connection)`).all() as any[]).map((c) => c.name);
  if (cols.includes('user_id') && !cols.includes('owner_kind')) {
    const lastUsed = cols.includes('last_used_at') ? 'last_used_at' : 'NULL';
    const connectionNew = schema('BLOB', 'INTEGER')
      .split(';')[0]
      .replace('connection', 'connection_new');
    db.exec(`
      ${connectionNew};
      INSERT INTO connection_new
        (id, enterprise_id, team_id, owner_kind, owner_id, provider, source,
         access_token_enc, refresh_token_enc, secret_ref, scopes, expires_at,
         external_account, created_at, updated_at, last_used_at)
      SELECT id, enterprise_id, team_id, 'user', user_id, provider, 'vault',
             access_token_enc, refresh_token_enc, NULL, scopes, expires_at,
             external_account, created_at, updated_at, ${lastUsed}
      FROM connection;
      DROP TABLE connection;
      ALTER TABLE connection_new RENAME TO connection;
    `);
  }

  // Add the `channel` audit column to a pre-existing audit table (plain ADD COLUMN, no UNIQUE rebuild).
  const auditCols = (db.prepare(`PRAGMA table_info(audit)`).all() as any[]).map((c) => c.name);
  if (!auditCols.includes('channel')) {
    db.exec(`ALTER TABLE audit ADD COLUMN channel TEXT`);
  }

  // #116 v4: system-only dry-run provenance on a pre-existing connection table (plain ADD COLUMN).
  // Re-read: the table may have just been rebuilt above.
  const connCols = (db.prepare(`PRAGMA table_info(connection)`).all() as any[]).map((c) => c.name);
  if (!connCols.includes('dry_run')) {
    db.exec(`ALTER TABLE connection ADD COLUMN dry_run INTEGER NOT NULL DEFAULT 0`);
  }

  // GHSA-pg84 v5: canonical query digest on a pre-existing approval_request table.
  const apCols = (db.prepare(`PRAGMA table_info(approval_request)`).all() as any[]).map((c) => c.name);
  if (!apCols.includes('query_hash')) {
    db.exec(`ALTER TABLE approval_request ADD COLUMN query_hash TEXT NOT NULL DEFAULT ''`);
  }
}
