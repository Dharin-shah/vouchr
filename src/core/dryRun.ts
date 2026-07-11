import { randomBytes } from 'node:crypto';
import type { Db } from './db';
import type { Provider } from './providers';
import type { TokenResponse } from './tokens';
import type { Audit } from './audit';

/**
 * Dry-run mode (#116): exercise the REAL consent state machine, policy, channel tools, egress
 * gates, vault, and audit — under the invariant that NO real network call leaves the process on
 * ANY edge. The edges, each handled at the exact point the call would otherwise happen:
 *  - outbound provider fetch → the synthetic echo (injector.send)
 *  - OAuth token exchange    → a synthetic marked credential (oauthCallback)
 *  - token refresh           → skipped; the stored synthetic token is returned (injector.doRefresh)
 *  - upstream token revoke   → skipped for rows the trusted `dry_run` column marks synthetic
 *    (offboard.ts — data-driven off the row, so flagless callers like the CLI are covered too)
 * consent.begin additionally substitutes the authorize URL (no network activity — it just points
 * the Connect button at the real local callback). Everything else runs the production code paths,
 * so dry-run behavior cannot drift from production anywhere else.
 *
 * Provenance is a SYSTEM-ONLY boolean column (`connection.dry_run`), set only on synthetic writes —
 * never the user/provider-controlled `external_account`. Every safety + revoke decision keys off it
 * ({@link assertDryRunVault}, the injector per-request rail, the offboard revoke-skips), so a REAL
 * account whose label is literally "dry-run" is never mistaken for synthetic and always revokes
 * normally. External KMS is refused at startup ({@link assertDryRunLocalKey}) — its wrap/unwrap
 * would be real network calls.
 */

/**
 * COSMETIC display label written to `external_account` on a synthetic row, so a human browsing the
 * table or `/vouchr status` sees "dry-run" instead of a random blob. It is NOT load-bearing: every
 * trust decision keys off the system-only `dry_run` column (see StoredCredential.dryRun), never
 * this string — a real account legitimately labelled "dry-run" must never be mistaken for synthetic.
 */
export const DRY_RUN_ACCOUNT = 'dry-run';

/** The synthetic authorization code in a dry-run authorize URL. The single-use `state` remains the
 *  security boundary; the dry-run callback additionally REQUIRES this exact code, so a real
 *  provider redirect (a code the local stub didn't mint) fails loudly instead of being silently
 *  swallowed into a synthetic row. */
export const DRY_RUN_CODE = 'dry-run';

/** SEC-4 runtime guard for the `dryRun` option, next to the constants it gates and shared by every
 *  entry point (createVouchr, createBroker): undefined → off, a boolean → itself, anything else
 *  (env strings, numbers, truthy objects) fails closed with a clear construction-time error. */
export function assertDryRunFlag(v: unknown, factory: string): boolean {
  if (v === undefined) return false;
  if (typeof v !== 'boolean') throw new Error(`${factory}: dryRun must be a boolean`);
  return v;
}

/** Thrown by {@link assertDryRunVault}. A distinct class so the broker's class-name-only error log
 *  still names the refusal (its message is static and secret-free). */
export class DryRunVaultError extends Error {
  constructor() {
    super(
      'refusing dryRun against a vault with real credentials — point dryRun at a fresh database ' +
        '(dbPath: ":memory:" or a dedicated test file)',
    );
    this.name = 'DryRunVaultError';
  }
}

/**
 * Safety rail: dry-run must never run against production state. Trusts the SYSTEM-ONLY `dry_run`
 * column (never the user/provider-controlled `external_account`): any row not explicitly marked
 * synthetic (`dry_run=1`) is treated as REAL and hard-fails — including a vault holding a MIX of
 * real and dry-run rows. An empty vault, or one holding only dry-run rows (a re-run against the
 * same test database), passes. createVouchr awaits this at startup; createBroker (sync) runs it at
 * construction and fails every request closed until it passes. This boot check only sees rows that
 * exist at boot; rows written AFTER it are caught data-driven off the same column — the injector
 * refuses to use, and the dry-run callback refuses (atomically) to overwrite, any unmarked row.
 */
export async function assertDryRunVault(db: Db): Promise<void> {
  const real = await db.get(`SELECT 1 AS present FROM connection WHERE dry_run != 1 LIMIT 1`);
  if (real) throw new DryRunVaultError();
}

/**
 * Safety rail: an external KMS envelope makes REAL network calls (wrapDataKey on every synthetic
 * write, unwrapDataKey on every fetch), which would break dry-run's "no real network on any edge"
 * guarantee — the tests only stub globalThis.fetch and would miss it. Refuse fail-closed at
 * startup; use a local master key (VOUCHR_MASTER_KEY) for dry-run instead.
 */
export function assertDryRunLocalKey(usesEnvelope: boolean): void {
  // ponytail: refuses ANY envelope. The only in-tree provider is AWS kmsEnvelope (network), so
  // refusing all is correct for the shipped surface; relax to local-vs-KMS if a local envelope ships.
  if (usesEnvelope) {
    throw new Error(
      'dryRun requires a local master key, not an external KMS envelope: KMS wrap/unwrap are real ' +
        'network calls that would break the offline guarantee. Unset the envelope / VOUCHR_KMS_KEY_ID.',
    );
  }
}

/** The synthetic token-exchange result: a random value that is stored (encrypted) and treated as a
 *  secret everywhere like any real token (SEC-1) — it just never authenticates anything. No refresh
 *  token and no expiry, so the refresh path is structurally unreachable in dry-run. */
export function dryRunTokenResponse(): TokenResponse {
  return { accessToken: randomBytes(32).toString('hex'), refreshToken: null, scopes: null, expiresAt: null };
}

/** Every audit row recorded through the returned instance carries `meta.dry_run: true`, so dry-run
 *  activity is distinguishable in the one table without touching any call site — the rest of each
 *  row's meta shape stays exactly what the real path writes (STR-4). Reads delegate untouched.
 *  DEPENDS on `Audit`'s `db` being a soft-private constructor property (not an ES `#db`): the
 *  Object.create prototype delegation resolves `this.db` for the read methods (listByOwnerUser, …)
 *  through the chain. If Audit ever adopts `#db`, replace this with an explicit forwarding subclass. */
export function dryRunAudit(audit: Audit): Audit {
  const marked: Audit = Object.create(audit);
  marked.record = (action, i, provider, meta, actor) =>
    audit.record(action, i, provider, { ...meta, dry_run: true }, actor);
  return marked;
}

/**
 * The synthetic `200` echo returned INSTEAD of the outbound provider call (injector.send — the one
 * place the flag gates egress). `wouldInjectAs` describes the injection shape by running the
 * provider's own `inject` with a redacted placeholder; the function deliberately never takes the
 * credential, so no code path can put real bytes in the echo (SEC-1).
 */
export function dryRunEcho(provider: Provider, url: string, method: string): Response {
  const h = new Headers();
  if (provider.inject) provider.inject(h, '<redacted>');
  else h.set('Authorization', 'Bearer <redacted>');
  const wouldInjectAs = [...h].map(([k, v]) => `${k}: ${v}`).join(', ');
  const res = new Response(JSON.stringify({ dryRun: true, method, url, wouldInjectAs }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  // A fetched Response carries .url; the constructor zeroes it. Carry the target through so host
  // code branching on res.url behaves identically in dry-run (mirrors guardResponse's carry-over).
  Object.defineProperty(res, 'url', { value: url });
  return res;
}
