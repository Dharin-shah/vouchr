import assert from 'node:assert';

/** The subset of VouchrOptions the boot assertions read. Kept local so this module has no import
 *  cycle with the adapter and stays trivially unit-testable. */
export interface BootConfig {
  databaseUrl?: string;
  envelope?: unknown;
  /**
   * Opt into production safety mode. When true (or via the Vouchr-namespaced VOUCHR_PRODUCTION=1),
   * boot fails fast unless the deployment is multi-instance safe: Postgres + an envelope provider.
   * Default false keeps the zero-config dev path (SQLite, no envelope) working unchanged.
   *
   * Deliberately NOT triggered by NODE_ENV=production: nearly every Node host sets that, so keying
   * off it would hard-fail existing zero-config SQLite deployments on upgrade (acceptance: default
   * behavior is unchanged). Opt-in must be explicit and Vouchr-specific.
   */
  production?: boolean;
}

/** The one place that classifies a connection string as Postgres. Every backend-resolution site
 *  (openDb, the bin/ entrypoints, usingPostgres) tests the SAME URL scheme through this. */
export function isPostgresUrl(url?: string): url is string {
  return !!url && /^postgres(ql)?:\/\//.test(url);
}

/** True when the store resolves to Postgres. Mirrors openDb's resolution order EXACTLY so the boot
 *  check sees the same backend openDb will actually open (env fallbacks included). */
export function usingPostgres(opts: BootConfig): boolean {
  return isPostgresUrl(opts.databaseUrl ?? process.env.VOUCHR_DATABASE_URL ?? process.env.DATABASE_URL);
}

/** True when the operator explicitly opted into production mode (flag or Vouchr-namespaced env). */
export function isProduction(opts: BootConfig): boolean {
  return opts.production === true || process.env.VOUCHR_PRODUCTION === '1';
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
