/** The subset of VouchrOptions the backend-resolution helpers read. Kept local so this module has no
 *  import cycle with the adapter and stays trivially unit-testable. */
export interface BootConfig {
  databaseUrl?: string;
  envelope?: unknown;
}

/** Largest delay Node's timers represent without clamping to 1ms and emitting a warning. */
export const MAX_TIMER_MS = 2_147_483_647;

/**
 * Parse one optional positive numeric environment setting without ever reflecting its value into an
 * error. Environment values are operator-controlled but are still an unsafe output boundary: a
 * credential pasted into the wrong variable must not be copied into boot logs (SEC-1).
 *
 * Explicitly-empty values are invalid. Counts use safe integers; timer callers pass MAX_TIMER_MS so
 * Node cannot silently turn an overflowing delay into a near-immediate timeout.
 */
export function optionalPositiveEnv(
  raw: string | undefined,
  name: string,
  opts: { integer?: boolean; max?: number } = {},
): number | undefined {
  if (raw === undefined) return undefined;
  const n = Number(raw);
  const canonical = opts.integer
    ? /^[1-9]\d*$/.test(raw)
    : /^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(raw);
  const numeric = opts.integer ? Number.isSafeInteger(n) : Number.isFinite(n);
  if (!canonical || !numeric || n <= 0 || (opts.max !== undefined && n > opts.max)) {
    const kind = opts.integer ? 'positive safe integer' : 'positive finite number';
    const ceiling = opts.max === undefined ? '' : ` no greater than ${opts.max}`;
    throw new Error(`vouchr: ${name} must be a ${kind}${ceiling}.`);
  }
  return n;
}

/** Parse a finite, safe integer that may be zero (zero disables an optional job/limit). */
export function nonNegativeIntegerEnv(
  raw: string | undefined,
  name: string,
  dflt: number,
  max = Number.MAX_SAFE_INTEGER,
): number {
  if (raw === undefined) return dflt;
  const n = Number(raw);
  if (!/^(?:0|[1-9]\d*)$/.test(raw) || !Number.isSafeInteger(n) || n < 0 || n > max) {
    throw new Error(`vouchr: ${name} must be a non-negative safe integer no greater than ${max}.`);
  }
  return n;
}

/**
 * Parse an optional boolean environment flag without silently turning a typo into the opposite
 * security posture. Accept the two spellings already documented by the binaries, plus their
 * explicit false forms; errors name only the variable, never the supplied text (SEC-1/SEC-4).
 */
export function booleanEnv(raw: string | undefined, name: string, dflt = false): boolean {
  if (raw === undefined) return dflt;
  if (raw === '1' || raw === 'true') return true;
  if (raw === '0' || raw === 'false') return false;
  throw new Error(`vouchr: ${name} must be one of 1|0|true|false.`);
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
