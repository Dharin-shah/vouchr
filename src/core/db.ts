import { Pool, types, type PoolClient } from 'pg';
import { hideInternals } from './redact';
import { isPostgresUrl, optionalPositiveEnv } from './options';
import { POSTGRES_NOW_US_SQL } from './interaction';

/** Runtime pool bounds used by lease-sensitive callers when reserving enough time for one final
 * database mutation. Keep the pool configuration and those callers on these single sources of truth. */
export const DB_CONNECTION_TIMEOUT_MS = 5_000;
/** End-to-end client read bound for one runtime query after pool acquisition. The server statement
 * bound matches it so a timed-out query is also cancelled at PostgreSQL instead of running on. */
export const DB_RUNTIME_QUERY_TIMEOUT_MS = 10_000;
export const DB_RUNTIME_STATEMENT_TIMEOUT_MS = DB_RUNTIME_QUERY_TIMEOUT_MS;

/**
 * Minimal async data handle over the store. Vouchr is PostgreSQL-only (#204): multi-replica
 * Postgres is the one supported production shape, so there is a single backend and no embedded
 * mode. The interface stays because the injector/vault/etc. are written against it, and test
 * support opens the same real Postgres in an isolated throwaway schema (see test/support/pg).
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
   * Run `fn` inside a transaction holding a cross-process advisory lock for `key`, with `fn`'s Db
   * bound to that locked transaction (so its reads/writes see the same tx, and a concurrent caller
   * blocks until COMMIT). Used by refresh coordination to re-read-under-lock and avoid two pods
   * both consuming a rotating refresh token. Optional only so minimal test stubs keep compiling.
   */
  withRefreshLock?<T>(key: string, fn: (txDb: Db) => Promise<T>): Promise<T>;
  /** Acquire several advisory locks in canonical order inside one transaction. Credential-mode,
   *  tool-governance, and pending-interaction mutations use this when one logical write touches
   *  several provider keys; canonical ordering prevents cross-replica deadlocks. */
  withRefreshLocks?<T>(keys: readonly string[], fn: (txDb: Db) => Promise<T>): Promise<T>;
  /**
   * Run `fn`'s statements atomically (BEGIN … COMMIT, ROLLBACK on throw), with `fn`'s Db bound to
   * the transaction. Used where one logical mutation spans two tables (e.g. a connection write +
   * its notification_state purge, #117) so a mid-sequence failure can't half-commit. Optional only
   * so minimal test stubs keep compiling — the shipped backend implements it. Logical mutations
   * that require atomicity fail closed when it is absent; narrower test-only paths may fall back
   * only where their own semantics explicitly permit it.
   */
  transaction?<T>(fn: (txDb: Db) => Promise<T>): Promise<T>;
}

export interface DbOptions {
  /** Postgres connection string. Falls back to `VOUCHR_DATABASE_URL`. There is deliberately NO
   *  generic `DATABASE_URL` fallback (#204): a platform-injected app database must never be selected
   *  by accident and have Vouchr tables created in it. */
  databaseUrl?: string;
}

// Positional rewrite. Our SQL never contains a literal '?', so a plain replace is safe.
function toPositional(sql: string): string { let i = 0; return sql.replace(/\?/g, () => `$${++i}`); }

/** Take every advisory transaction lock in canonical (sorted, de-duplicated) order with ONE round trip.
 *  unnest() emits the array elements in order and the lock call runs per emitted row, so the
 *  canonical order that keeps concurrent multi-key writers deadlock-free is preserved; a loop of
 *  single-key statements cost one round trip per key on every fenced credential use. */
async function acquireXactLocks(client: PoolClient, keys: readonly string[]): Promise<void> {
  await client.query(
    'SELECT pg_advisory_xact_lock(hashtext(k)) FROM unnest($1::text[]) AS k',
    [[...new Set(keys)].sort()],
  );
}

class PgDb implements Db {
  // Dedicated small pool for token refresh, separate from the read pool, so a hung provider
  // /token endpoint inside a held lock can't starve the connections serving normal requests.
  private refreshPool?: Pool;
  constructor(private pool: Pool, private connectionString: string) {
    // SEC-1: `connectionString` carries the database password and `createVouchr` returns this object
    // to the host, so JSON.stringify/spread/a structured logger would print it. Same TS-erasure
    // problem as ConnectionHandle; see core/redact.
    hideInternals(this);
  }
  async get(sql: string, params: any[] = []) { return (await this.pool.query(toPositional(sql), params)).rows[0]; }
  async all(sql: string, params: any[] = []) { return (await this.pool.query(toPositional(sql), params)).rows; }
  async run(sql: string, params: any[] = []) { return { changes: (await this.pool.query(toPositional(sql), params)).rowCount ?? 0 }; }
  async exec(sql: string) { await this.pool.query(sql); }

  async withRefreshLock<T>(key: string, fn: (txDb: Db) => Promise<T>): Promise<T> {
    return this.withRefreshLocks([key], fn);
  }

  async withRefreshLocks<T>(keys: readonly string[], fn: (txDb: Db) => Promise<T>): Promise<T> {
    if (!this.refreshPool) {
      this.refreshPool = new Pool({
        connectionString: this.connectionString,
        application_name: 'vouchr-refresh', // distinct in pg_stat_activity from the main pool
        max: 4, // bounded: a stuck token endpoint caps at this many pinned backends, never the read pool
        connectionTimeoutMillis: DB_CONNECTION_TIMEOUT_MS,
        idleTimeoutMillis: 30_000,
        maxLifetimeSeconds: 3600,
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
      // Acquire locks BEFORE arming statement_timeout: a loser blocks until the winner COMMITs,
      // which can exceed 8s for a slow /token round-trip. Canonical order prevents two multi-key
      // governance writers from deadlocking while retaining the single-key refresh behavior.
      await acquireXactLocks(client, keys);
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

  // Idempotent: `pg-pool` rejects a second `end()`, and two shutdown paths can both call close()
  // (install().stop() AND the standalone close(), or a test's t.after AND an explicit close). Memoize
  // so every caller after the first awaits the same teardown instead of throwing.
  private closing?: Promise<void>;
  async close() {
    this.closing ??= (async () => {
      await this.pool.end();
      if (this.refreshPool) await this.refreshPool.end();
    })();
    return this.closing;
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
  async withRefreshLock<T>(key: string, fn: (txDb: Db) => Promise<T>): Promise<T> {
    return this.withRefreshLocks([key], fn);
  }
  async withRefreshLocks<T>(keys: readonly string[], fn: (txDb: Db) => Promise<T>): Promise<T> {
    await acquireXactLocks(this.client, keys);
    return fn(this);
  }
  async close() { /* lifecycle owned by withRefreshLock (BEGIN/COMMIT/release); nothing to do here */ }
}

/**
 * Version of the schema this build writes, stamped into the `meta` table by the migration command.
 * Version 1 is the whole current schema in one DDL (#340): Vouchr is greenfield, so the 1.0.0
 * migration ladder (v12-v15 and its data conversions) was deleted rather than carried, and a
 * database stamped with any other version is recreated fresh. Future schema changes add steps from
 * v1 and bump this number; the lineage stays MONOTONIC from here. The `meta` marker keeps a
 * mismatched binary off the data: `openDb` requires exactly this version, so rolling versions can
 * never interpret stored controls differently.
 */
export const SCHEMA_VERSION = 1;

// The marker table. TEXT-only, so it needs no engine type parameterization.
const META_DDL = `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`;

/**
 * Migration entry guard — runs BEFORE any DDL. `migrate()` creates a fresh baseline or idempotently
 * verifies one already at {@link SCHEMA_VERSION}. The ONLY inputs it can correctly converge are:
 *  - a genuinely FRESH schema (no version marker AND no vouchr tables) → baseline;
 *  - a database already at this version → idempotent no-op.
 * Everything else fails closed rather than getting stamped over an unknown shape: a marker from the
 * deleted 1.0.0 ladder (v12-v15), a pre-marker legacy schema whose columns this build never
 * created, or a newer version this build does not know. The fix for a rejected database is to
 * recreate it fresh, not to add historical migrations.
 */
async function guardSchemaVersion(db: Db): Promise<number | null> {
  // Probe the marker WITHOUT creating `meta` first, so a genuinely empty schema is distinguishable
  // from a markerless legacy one. `to_regclass` returns NULL (never errors) for a missing table — a
  // SELECT on the missing table would raise 42P01 and, since this runs inside migrate's transaction,
  // abort it. Only read the marker row once we know `meta` exists.
  const metaReg = (await db.get<{ reg: string | null }>(`SELECT to_regclass('meta') AS reg`))?.reg;
  const marker = metaReg
    ? await db.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`)
    : undefined;
  if (!marker) {
    // No version marker. A fresh install requires a genuinely EMPTY schema — reject a markerless
    // schema that already holds ANY relation (connection, channel_config, audit, a view, …): it is a
    // pre-marker legacy layout this build never created and cannot correctly migrate. `meta` itself
    // is excluded (it may exist empty, and we create it just below for a truly fresh schema).
    const rel = await db.get<{ n: number }>(
      `SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema = current_schema() AND table_name <> 'meta'`,
    );
    if ((rel?.n ?? 0) > 0) {
      throw new Error(
        'vouchr: unrecognized database — the schema already contains relations but has no schema-version ' +
          'marker (a pre-marker legacy layout). Vouchr is PostgreSQL-only and greenfield; migrate into a ' +
          'fresh, empty database.',
      );
    }
    await db.exec(META_DDL); // fresh → ensure the marker table exists for the version stamp
    return null; // migrate() creates the baseline and stamps SCHEMA_VERSION
  }
  const found = Number(marker.value);
  if (!Number.isInteger(found)) throw new Error(`vouchr: unreadable schema_version "${marker.value}".`);
  if (found !== SCHEMA_VERSION) {
    throw new Error(
      `vouchr: schema version ${found} is not supported for migration. Only a fresh database, or one at ` +
        `version ${SCHEMA_VERSION}, can be migrated — recreate the database fresh and run \`vouchr migrate\`. ` +
        'There is no data migration from a 1.0.0 (schema 15) or earlier database.',
    );
  }
  return found;
}

/** Record that the database is now at this build's schema version (after migrations ran). */
async function stampSchemaVersion(db: Db): Promise<void> {
  await db.run(
    `INSERT INTO meta (key, value) VALUES ('schema_version', ?)
     ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
    [String(SCHEMA_VERSION)],
  );
}

/** The single schema DDL (PostgreSQL). Defined once at its current shape (#204, #340) — no
 *  incremental migration history, because greenfield means there are no deployed databases to
 *  migrate. Idempotent (CREATE ... IF NOT EXISTS) so `migrate()` can run it unconditionally. */
function schema(): string {
  const blob = 'BYTEA';
  const int = 'BIGINT';
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
      generation_at ${int} NOT NULL DEFAULT ${POSTGRES_NOW_US_SQL},
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
      created_at ${int} NOT NULL,
      consumed_at ${int},
      superseded_at ${int},
      delivery_token TEXT,
      delivery_lease_expires_at ${int} NOT NULL DEFAULT 0,
      delivered_at ${int},
      -- #302: when the browser completing this consent proved the bound Slack identity through the
      -- Slack OIDC hop. NULL until then; the OAuth callback refuses an unstamped row.
      slack_verified_at ${int}
    );
    -- Runtime recovery sweeps use created_at as an exact range condition; the partial unique index
    -- enforces the single-active-generation consent invariant.
    CREATE INDEX IF NOT EXISTS idx_consent_request_created_at ON consent_request (created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS uq_consent_request_active
      ON consent_request (team_id, user_id, provider)
      WHERE superseded_at IS NULL;

    CREATE TABLE IF NOT EXISTS user_provisioning_request (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      created_at ${int} NOT NULL,
      expires_at ${int} NOT NULL,
      delivery_token TEXT,
      delivery_lease_expires_at ${int} NOT NULL DEFAULT 0,
      delivered_at ${int}
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_user_provisioning_owner_provider
      ON user_provisioning_request (team_id, user_id, provider);
    CREATE INDEX IF NOT EXISTS idx_user_provisioning_expiry
      ON user_provisioning_request (expires_at);

    CREATE TABLE IF NOT EXISTS channel_provisioning_request (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      created_at ${int} NOT NULL,
      expires_at ${int} NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_channel_provisioning_actor_target
      ON channel_provisioning_request (team_id, channel, user_id, provider);
    CREATE INDEX IF NOT EXISTS idx_channel_provisioning_expiry
      ON channel_provisioning_request (expires_at);

    CREATE TABLE IF NOT EXISTS channel_interaction_tombstone (
      team_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      provider TEXT NOT NULL,
      created_at ${int} NOT NULL,
      PRIMARY KEY (team_id, channel, provider),
      CHECK (provider ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')
    );

    CREATE TABLE IF NOT EXISTS user_offboard_scope_tombstone (
      scope_kind TEXT NOT NULL,
      scope_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at ${int} NOT NULL,
      PRIMARY KEY (scope_kind, scope_id, user_id),
      CHECK (scope_kind IN ('enterprise', 'unscoped', 'global')),
      CHECK (
        (scope_kind='enterprise' AND scope_id<>'') OR
        (scope_kind IN ('unscoped', 'global') AND scope_id='')
      )
    );

    CREATE TABLE IF NOT EXISTS provisioning_revocation_tombstone (
      provider TEXT NOT NULL,
      scope_kind TEXT NOT NULL,
      scope_key TEXT NOT NULL,
      created_at ${int} NOT NULL,
      PRIMARY KEY (provider, scope_key),
      CHECK (provider ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'),
      CHECK (scope_kind IN ('global', 'team', 'user', 'team-user', 'channel', 'team-channel')),
      CHECK (scope_key ~ '^[A-Za-z0-9_-]{43}$')
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
      credential_id TEXT NOT NULL,
      created_at ${int} NOT NULL,
      expires_at ${int} NOT NULL,
      PRIMARY KEY (team_id, channel, thread, user_id, provider)
    );

    CREATE TABLE IF NOT EXISTS session_request (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      thread TEXT NOT NULL,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      credential_id TEXT NOT NULL,
      created_at ${int} NOT NULL,
      expires_at ${int} NOT NULL,
      delivery_token TEXT,
      delivery_lease_expires_at ${int} NOT NULL DEFAULT 0,
      delivered_at ${int},
      UNIQUE (team_id, channel, thread, user_id, provider)
    );

    CREATE TABLE IF NOT EXISTS approval_request (
      id TEXT PRIMARY KEY,
      action_key TEXT NOT NULL,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      owner_kind TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      credential_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      method TEXT NOT NULL,
      origin TEXT NOT NULL,
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      query_hash TEXT NOT NULL DEFAULT '',
      channel TEXT NOT NULL,
      thread TEXT NOT NULL,
      -- The mutable-GOVERNANCE scope for this action's channel at request time. Empty string is an
      -- explicitly personal conversation; otherwise it equals channel. NOT NULL prevents an old or
      -- unclassified row from being interpreted as ungoverned.
      governable_channel TEXT NOT NULL,
      status TEXT NOT NULL,
      approved_by TEXT,
      created_at ${int} NOT NULL,
      expires_at ${int} NOT NULL,
      delivery_token TEXT,
      delivery_lease_expires_at ${int} NOT NULL DEFAULT 0,
      delivered_at ${int},
      delivery_audience TEXT,
      -- #296 backchannel authorization: the host-supplied plain transaction statement rendered on
      -- the decision surface. Non-NULL marks an agent-initiated request the Bolt control plane
      -- delivers on its own timer (no relayed denial); NULL is an in-process/fetch-minted row.
      binding_message TEXT
    );
    -- Exact-action approval deduplication depends on this uniqueness.
    CREATE UNIQUE INDEX IF NOT EXISTS uq_approval_request_action ON approval_request (action_key);

    CREATE TABLE IF NOT EXISTS notification_state (
      team_id TEXT NOT NULL,
      owner_kind TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      type TEXT NOT NULL,
      last_notified_at ${int} NOT NULL,
      PRIMARY KEY (team_id, owner_kind, owner_id, provider, type)
    );

    CREATE TABLE IF NOT EXISTS offboard_tombstone (
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at ${int} NOT NULL,
      PRIMARY KEY (team_id, user_id)
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
    -- Audit read paths (#208). Each serves a real query — no speculative indexes on this insert-heavy
    -- table. Composite (…, at DESC) so the ORDER BY at DESC LIMIT reads straight off the index.
    --  · owner history (listByOwnerUser): team_id, user_id, at DESC
    --  · channel history + stats + last-config (listByChannel / statsByChannel / lastChannelConfigActor):
    --    team_id, channel, at DESC
    --  · retention prune (pruneOlderThan): a plain (at) btree for the global at<cutoff batch scan.
    CREATE INDEX IF NOT EXISTS idx_audit_team_user_at ON audit (team_id, user_id, at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_team_channel_at ON audit (team_id, channel, at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_at ON audit (at);
    -- lastChannelConfigActor looks up the newest 'config' row for (team, channel, provider). 'config'
    -- rows are rare among injects, so a PARTIAL index on just those keeps the "who configured this"
    -- lookup from scanning the channel's whole history. Small (only config rows).
    CREATE INDEX IF NOT EXISTS idx_audit_config ON audit (team_id, channel, provider, at DESC) WHERE action = 'config';

    CREATE TABLE IF NOT EXISTS installation (
      id TEXT PRIMARY KEY,
      enterprise_id TEXT,
      team_id TEXT,
      bot_token ${blob},
      data ${blob} NOT NULL,
      updated_at ${int} NOT NULL
    );

    -- Cluster-wide single-use identity jti (DbReplayStore). Part of the baseline so no adapter runs
    -- its own CREATE TABLE: two broker replicas constructing a store on one DB would otherwise race
    -- the DDL (pg_type 23505). exp is epoch-ms.
    CREATE TABLE IF NOT EXISTS broker_jti (jti TEXT PRIMARY KEY, exp ${int} NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_broker_jti_exp ON broker_jti (exp);`;
}

/** Validated pool size from `VOUCHR_PG_POOL_MAX` (pg's default when unset). A non-integer or < 1
 *  value fails closed rather than silently becoming NaN/0 and starving the pool. */
function poolMax(): number | undefined {
  return optionalPositiveEnv(process.env.VOUCHR_PG_POOL_MAX, 'VOUCHR_PG_POOL_MAX', { integer: true });
}

/** pg lets connection-string parameters override Pool object options. Pin both timeout parameters in
 * the URL passed to the main pool so `?statement_timeout=60000` / `?query_timeout=60000` cannot
 * silently invalidate a lease-sensitive runtime bound. Keep the original URL for the refresh pool,
 * whose advisory-lock wait intentionally precedes its local statement timeout. */
function boundedMainPoolUrl(url: string, timeoutMs: number): string {
  const bounded = new URL(url);
  bounded.searchParams.set('statement_timeout', String(timeoutMs));
  bounded.searchParams.set('query_timeout', String(timeoutMs));
  return bounded.toString();
}

/** Resolve + validate the connection string and build a pool. No DDL, no schema check — the shared
 *  guts of {@link openDb} and {@link migrate}. TLS is native: put `sslmode=require` (or stricter) in
 *  the connection string and the pg driver negotiates it; there is no separate TLS knob to drift.
 *  `statementTimeoutMs` defaults to the runtime's tight 10s; the migration path passes a longer one
 *  so a slow DDL, data conversion, or advisory-lock WAIT (a concurrent migrate holding the lock)
 *  isn't cancelled mid-migration. */
function connectDb(
  opts: DbOptions,
  statementTimeoutMs = DB_RUNTIME_STATEMENT_TIMEOUT_MS,
  appName = 'vouchr',
): PgDb {
  const url = opts.databaseUrl ?? process.env.VOUCHR_DATABASE_URL;
  if (!isPostgresUrl(url)) {
    throw new Error(
      'vouchr: a PostgreSQL connection string is required (VOUCHR_DATABASE_URL, or the databaseUrl ' +
        'option). Vouchr is PostgreSQL-only; there is no embedded/SQLite mode and no generic ' +
        'DATABASE_URL fallback. The URL must include a host (e.g. postgres://user:pass@host:5432/db).',
    );
  }
  types.setTypeParser(20, (v) => parseInt(v, 10)); // int8 → JS number (µs/ms timestamps are < 2^53)
  const pool = new Pool({
    connectionString: boundedMainPoolUrl(url, statementTimeoutMs),
    application_name: appName, // names the backend in pg_stat_activity for operators
    // Explicit pool size (VOUCHR_PG_POOL_MAX; pg's default 10 otherwise). Deployments size this to
    // their `max_connections` / replica count. NOTE: each replica also lazily opens a SEPARATE 4-conn
    // refresh pool (application_name 'vouchr-refresh') on first token refresh — budget max + 4 per replica.
    max: poolMax(),
    connectionTimeoutMillis: DB_CONNECTION_TIMEOUT_MS,
    idleTimeoutMillis: 30_000,
    maxLifetimeSeconds: 3600, // recycle a backend after an hour so a long-lived pod doesn't pin aging connections
    statement_timeout: statementTimeoutMs,
    query_timeout: statementTimeoutMs,
  });
  // pg emits 'error' on idle backend clients (DB restart, network drop). With no listener this
  // throws and kills the whole process; swallow it, pg reconnects on the next query.
  pool.on('error', (e) => console.error('[vouchr] postgres idle-client error:', e.message));
  return new PgDb(pool, url);
}

/**
 * Verify the database has been migrated to EXACTLY this build's schema version. Does NO DDL, so the
 * runtime can connect with a DML-only role (no CREATE/ALTER grants). Fail closed:
 *  - meta table / marker absent → the database was never migrated (`vouchr migrate` first);
 *  - any other version → a database this build cannot serve. With one schema version there is
 *    nothing to converge: a 1.0.0 (v15) or older marker means recreate fresh, and a newer marker
 *    means this binary is older than the data (old code against a newer schema can corrupt
 *    encrypted rows) — either way the process must not touch it.
 */
export async function assertSchemaCurrent(db: Db): Promise<void> {
  let row: { value: string } | undefined;
  try {
    row = await db.get<{ value: string }>(`SELECT value FROM meta WHERE key='schema_version'`);
  } catch (e: any) {
    if (e?.code === '42P01') row = undefined; // relation "meta" does not exist → never migrated
    else throw e;
  }
  if (!row) {
    throw new Error(
      'vouchr: this database has not been initialized. Run `vouchr migrate` (with a role that can ' +
        'create tables) before starting the runtime.',
    );
  }
  const found = Number(row.value);
  if (!Number.isInteger(found)) throw new Error(`vouchr: unreadable schema_version "${row.value}".`);
  if (found !== SCHEMA_VERSION) {
    throw new Error(
      `vouchr: this database is at schema version ${found}, but this build needs ${SCHEMA_VERSION}. ` +
        'Refusing to open it. Recreate the database fresh and run `vouchr migrate` (there is no data ' +
        'migration from a 1.0.0 or earlier schema), or run the vouchr build that matches it.',
    );
  }
}

/**
 * Create the schema at this build's version, or verify it is already there. Run by the
 * `vouchr migrate` command (and the test harness) with a role that can CREATE — NOT the DML-only
 * runtime role. Idempotent and safe to run concurrently: an xact advisory lock keyed by the target
 * schema serializes replicas so they can't race `CREATE TABLE` (which is not atomic against the
 * internal pg_type row → 23505). Opens a short-lived connection and closes it before returning.
 * A future schema change adds its step here, gated on the version the guard returns.
 */
export async function migrate(opts: DbOptions = {}): Promise<{ version: number }> {
  const db = connectDb(opts, 300_000, 'vouchr-migrate'); // generous timeout: DDL + lock wait, not a request
  try {
    await db.transaction(async (tx) => {
      await tx.get('SELECT pg_advisory_xact_lock(hashtext(current_schema()))'); // released at COMMIT
      await guardSchemaVersion(tx); // fail closed before any DDL
      await tx.exec(schema()); // idempotent (CREATE ... IF NOT EXISTS)
      await stampSchemaVersion(tx);
    });
    return { version: SCHEMA_VERSION };
  } finally {
    await db.close();
  }
}

/**
 * Open the credential store for the RUNTIME. PostgreSQL only (#204): a valid `postgres://` URL is
 * required (via `databaseUrl` or `VOUCHR_DATABASE_URL`) and boot fails closed on a missing or
 * non-Postgres value. Runs NO DDL — it only verifies the schema is at this build's version (see
 * {@link assertSchemaCurrent}), so a DML-only role can run it. Migrate first with `vouchr migrate`.
 */
export async function openDb(opts: DbOptions = {}): Promise<Db> {
  const db = connectDb(opts);
  try {
    await assertSchemaCurrent(db);
  } catch (e) {
    await db.close().catch(() => undefined);
    throw e;
  }
  return db;
}
