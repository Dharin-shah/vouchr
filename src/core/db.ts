import BetterSqlite3 from 'better-sqlite3';
import { Pool, types } from 'pg';

/**
 * Minimal async data handle — the seam that lets the same store code run on SQLite
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
}

export interface DbOptions {
  /** SQLite file path (default). `:memory:` for tests. */
  dbPath?: string;
  /** Postgres connection string. Takes precedence over dbPath when set. */
  databaseUrl?: string;
}

class SqliteDb implements Db {
  constructor(private db: BetterSqlite3.Database) {}
  async get(sql: string, params: any[] = []) { return this.db.prepare(sql).get(...params) as any; }
  async all(sql: string, params: any[] = []) { return this.db.prepare(sql).all(...params) as any[]; }
  async run(sql: string, params: any[] = []) { return { changes: this.db.prepare(sql).run(...params).changes }; }
  async exec(sql: string) { this.db.exec(sql); }
  async close() { this.db.close(); }
}

class PgDb implements Db {
  constructor(private pool: Pool) {}
  // Note: positional rewrite. Our SQL never contains a literal '?', so a plain replace is safe.
  private q(sql: string): string { let i = 0; return sql.replace(/\?/g, () => `$${++i}`); }
  async get(sql: string, params: any[] = []) { return (await this.pool.query(this.q(sql), params)).rows[0]; }
  async all(sql: string, params: any[] = []) { return (await this.pool.query(this.q(sql), params)).rows; }
  async run(sql: string, params: any[] = []) { return { changes: (await this.pool.query(this.q(sql), params)).rowCount ?? 0 }; }
  async exec(sql: string) { await this.pool.query(sql); }
  async close() { await this.pool.end(); }
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
  if (url && /^postgres(ql)?:\/\//.test(url)) {
    types.setTypeParser(20, (v) => parseInt(v, 10)); // int8 → JS number (ms timestamps are < 2^53)
    const pool = new Pool({
      connectionString: url,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
      statement_timeout: 10_000, // fail a request fast instead of hanging the Bolt handler
    });
    // pg emits 'error' on idle backend clients (DB restart, network drop). With no listener this
    // throws and kills the whole process; swallow it — pg reconnects on the next query.
    pool.on('error', (e) => console.error('[vouchr] postgres idle-client error:', e.message));
    const db = new PgDb(pool);
    await db.exec(schema('BYTEA', 'BIGINT'));
    // CREATE TABLE IF NOT EXISTS won't add `channel` to a pre-existing audit table; do it idempotently.
    await db.exec(`ALTER TABLE audit ADD COLUMN IF NOT EXISTS channel TEXT`);
    return db;
  }

  const raw = new BetterSqlite3(opts.dbPath ?? process.env.VOUCHR_DB ?? 'vouchr.db');
  raw.pragma('journal_mode = WAL');
  raw.pragma('busy_timeout = 5000'); // wait, don't instantly SQLITE_BUSY, on a concurrent writer
  migrateSqlite(raw);
  return new SqliteDb(raw);
}

/** SQLite schema + the legacy (pre-owner-keying) rebuild. Postgres deploys start clean. */
function migrateSqlite(db: BetterSqlite3.Database): void {
  db.exec(schema('BLOB', 'INTEGER'));

  // Forward-migrate a pre-owner-keying DB (had user_id, no owner_kind) by rebuilding the table —
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

  // Add the `channel` audit column to a pre-existing audit table (plain ADD COLUMN — no UNIQUE rebuild).
  const auditCols = (db.prepare(`PRAGMA table_info(audit)`).all() as any[]).map((c) => c.name);
  if (!auditCols.includes('channel')) {
    db.exec(`ALTER TABLE audit ADD COLUMN channel TEXT`);
  }
}
