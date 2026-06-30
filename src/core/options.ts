import assert from 'node:assert';

/** The subset of VouchrOptions the boot assertions read. Kept local so this module has no import
 *  cycle with the adapter and stays trivially unit-testable. */
export interface BootConfig {
  databaseUrl?: string;
  envelope?: unknown;
  /**
   * Opt into production safety mode. When true (or VOUCHR_PRODUCTION=1 / NODE_ENV=production),
   * boot fails fast unless the deployment is multi-instance safe: Postgres + an envelope provider.
   * Default false keeps the zero-config dev path (SQLite, no envelope) working unchanged.
   */
  production?: boolean;
}

/** True when the store resolves to Postgres. Mirrors openDb's resolution order EXACTLY so the boot
 *  check sees the same backend openDb will actually open (env fallbacks included). */
export function usingPostgres(opts: BootConfig): boolean {
  const url = opts.databaseUrl ?? process.env.VOUCHR_DATABASE_URL ?? process.env.DATABASE_URL;
  return !!url && /^postgres(ql)?:\/\//.test(url);
}

/** True when the operator opted into production mode (explicit flag or env). */
export function isProduction(opts: BootConfig): boolean {
  return opts.production === true
    || process.env.VOUCHR_PRODUCTION === '1'
    || process.env.NODE_ENV === 'production';
}

/**
 * Fail fast on an unsafe production configuration. In production both must hold:
 *   1. Postgres — SQLite is a single-file lock, no cross-instance story.
 *   2. An envelope provider — KMS-wrapped DEKs, not just storage-level encryption.
 * The envelope check is the footgun: databaseUrl can be Postgres while envelope is undefined, so a
 * URL-scheme check alone is insufficient. Non-production is untouched (SQLite + no envelope is fine).
 */
export function assertProductionConfig(opts: BootConfig): void {
  if (!isProduction(opts)) return;
  assert(usingPostgres(opts), 'Vouchr requires Postgres in production (multi-instance safe)');
  assert(opts.envelope != null, 'Vouchr requires an envelope provider in production (KMS-wrapped DEKs)');
}
