/** The subset of VouchrOptions the backend-resolution helpers read. Kept local so this module has no
 *  import cycle with the adapter and stays trivially unit-testable. */
export interface BootConfig {
  databaseUrl?: string;
  envelope?: unknown;
}

/** The one place that classifies a connection string as Postgres. Every backend-resolution site
 *  (openDb, the bin/ entrypoints, usingPostgres) tests the SAME URL through this. Requires a
 *  `postgres`/`postgresql` scheme AND a host: a bare `postgres://` (or `postgres:///db`) is REJECTED,
 *  because pg would otherwise resolve it from ambient local defaults (PGHOST/PGUSER/socket) — an
 *  implicit database selection, exactly what the explicit-URL contract forbids. */
export function isPostgresUrl(url?: string): url is string {
  if (!url) return false;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return (u.protocol === 'postgres:' || u.protocol === 'postgresql:') && u.hostname !== '';
}

/** True when the store resolves to Postgres. Mirrors openDb's resolution order EXACTLY (only
 *  `databaseUrl` then `VOUCHR_DATABASE_URL` — no generic `DATABASE_URL` fallback, #204) so the boot
 *  check sees the same backend openDb will actually open. */
export function usingPostgres(opts: BootConfig): boolean {
  return isPostgresUrl(opts.databaseUrl ?? process.env.VOUCHR_DATABASE_URL);
}
