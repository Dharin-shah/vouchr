/** The subset of VouchrOptions the backend-resolution helpers read. Kept local so this module has no
 *  import cycle with the adapter and stays trivially unit-testable. */
export interface BootConfig {
  databaseUrl?: string;
  envelope?: unknown;
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
