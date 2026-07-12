/** The subset of VouchrOptions the backend-resolution helpers read. Kept local so this module has no
 *  import cycle with the adapter and stays trivially unit-testable. */
export interface BootConfig {
  databaseUrl?: string;
  envelope?: unknown;
}

/** The one place that classifies a connection string as Postgres. Every backend-resolution site
 *  (openDb, the bin/ entrypoints, usingPostgres) tests the SAME URL through this. Requires a
 *  `postgres`/`postgresql` scheme, a HOST, AND an explicit database name in the path. A bare
 *  `postgres://`, `postgres://host`, or `postgres://host/` is REJECTED, because pg would otherwise
 *  resolve the host and/or database from ambient local defaults (PGHOST / PGDATABASE / PGUSER /
 *  socket) — an implicit selection, exactly what the explicit-URL contract forbids. */
export function isPostgresUrl(url?: string): url is string {
  if (!url) return false;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol !== 'postgres:' && u.protocol !== 'postgresql:') return false;
  if (u.hostname === '') return false;
  return u.pathname.replace(/^\//, '') !== ''; // an explicit database name, not '' or '/'
}

/** True when the store resolves to Postgres. Mirrors openDb's resolution order EXACTLY (only
 *  `databaseUrl` then `VOUCHR_DATABASE_URL` — no generic `DATABASE_URL` fallback, #204) so the boot
 *  check sees the same backend openDb will actually open. */
export function usingPostgres(opts: BootConfig): boolean {
  return isPostgresUrl(opts.databaseUrl ?? process.env.VOUCHR_DATABASE_URL);
}
