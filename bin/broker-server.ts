#!/usr/bin/env node
/**
 * broker-server: the standalone headless Vouchr broker (no Slack, no Bolt).
 *
 * Reads config from env, wires the same core (openDb → Vault → Audit → createBroker) the Bolt path
 * uses, and serves /v1/fetch, /v1/resolve, and the /healthz + /readyz probes. Postgres + KMS + the
 * required shared jti store (DbReplayStore) make it multi-replica safe; see DEPLOYMENT.md.
 * Run: `node dist/bin/broker-server.js`.
 */
import http from 'node:http';
import { openDb, type Db } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { createBroker, normalizeBrokerResourceBounds, type BrokerOptions } from '../src/adapters/http/broker';
import { loadIdentityConfig, type IdentityConfig } from '../src/adapters/http/identity';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import { sweepExpired } from '../src/core/sweep';
import { Approvals } from '../src/core/approval';
import { loadKeyring, type EnvelopeProvider, type Keyring } from '../src/core/crypto';
import { assertDryRunVault, dryRunAudit } from '../src/core/dryRun';
import { loadProviders } from './providerConfig';
import { booleanEnv, MAX_TIMER_MS, nonNegativeIntegerEnv, optionalPositiveEnv } from '../src/core/options';

function fail(msg: string): never {
  throw new Error(msg);
}

export interface BuiltBroker {
  server: http.Server;
  db: Db;
  port: number;
  backend: 'postgres';
  providerIds: string[];
  allowWrites: boolean;
  /** #116 dry-run: real gates, no real network on any edge (VOUCHR_DRY_RUN). */
  dryRun: boolean;
  /** #54 TTL sweep: delete expired connections + stale consent + expired thread grants. Idempotent,
   *  so overlapping runs across replicas are safe (noisy, not destructive). Returns the count swept. */
  sweep: () => Promise<number>;
  /** #54 sweep interval (ms); 0 disables the timer (VOUCHR_SWEEP_INTERVAL_MS). Default hourly. */
  sweepIntervalMs: number;
  /** #209 graceful-drain deadline (ms; VOUCHR_SHUTDOWN_TIMEOUT_MS). Default 10s. */
  shutdownTimeoutMs: number;
}

/**
 * Start one bounded graceful drain. `close()` first stops new accepts, idle keep-alive sockets are
 * dropped immediately, and active requests keep their connections until they settle. The hard
 * deadline is cleared on a clean drain. Exported so this production ordering has a deterministic
 * regression instead of living only inside signal-handler glue.
 */
export function beginBrokerDrain(
  server: http.Server,
  timeoutMs: number,
  onDrained: () => void,
  onTimeout: () => void,
): NodeJS.Timeout {
  const timer = setTimeout(onTimeout, timeoutMs);
  timer.unref();
  try {
    server.close(() => {
      clearTimeout(timer);
      onDrained();
    });
    server.closeIdleConnections();
    return timer;
  } catch (error) {
    clearTimeout(timer);
    throw error;
  }
}

/**
 * The standalone builder owns every security/configuration value derived from env. A thin wrapper may
 * inject only code hooks that cannot replace that identity, database, provider, replay, or egress
 * configuration. Direct-construction users who need full BrokerOptions use createBroker instead.
 */
export type BrokerServerOverrides = Pick<
  BrokerOptions,
  'authorize' | 'resolvers' | 'onEvent' | 'auditSink' | 'onCredentialHealth'
>;

const BROKER_SERVER_OVERRIDE_KEYS = new Set<keyof BrokerServerOverrides>([
  'authorize', 'resolvers', 'onEvent', 'auditSink', 'onCredentialHealth',
]);

function assertBrokerServerOverrides(overrides: BrokerServerOverrides): void {
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
    fail('buildBrokerServer: overrides must be an object containing only supported hook fields');
  }
  for (const key of Reflect.ownKeys(overrides)) {
    if (typeof key !== 'string' || !BROKER_SERVER_OVERRIDE_KEYS.has(key as keyof BrokerServerOverrides)) {
      // Never echo an unknown key: externally supplied object keys can themselves contain secrets.
      fail(`buildBrokerServer: unsupported override; allowed hooks: ${[...BROKER_SERVER_OVERRIDE_KEYS].join(', ')}`);
    }
  }
  for (const key of ['authorize', 'onEvent', 'auditSink', 'onCredentialHealth'] as const) {
    if (overrides[key] !== undefined && typeof overrides[key] !== 'function') {
      fail(`buildBrokerServer: ${key} override must be a function`);
    }
  }
  if (overrides.resolvers !== undefined) {
    if (!overrides.resolvers || typeof overrides.resolvers !== 'object' || Array.isArray(overrides.resolvers)
      || Object.values(overrides.resolvers).some((resolver) => typeof resolver !== 'function')) {
      fail('buildBrokerServer: resolvers override must be an object of functions');
    }
  }
}

/**
 * Build (but do not listen on) the broker from `env`. Exported so tests drive it with an injected env
 * and no process side effects. `overrides` lets a deployer inject the explicit non-declarative hook
 * allowlist (authorize, resolvers, observability/audit/health sinks) from a thin wrapper without
 * letting that wrapper replace env-owned identity, replay, provider, database, or egress config.
 */
export async function buildBrokerServer(
  env: NodeJS.ProcessEnv = process.env,
  overrides: BrokerServerOverrides = {},
): Promise<BuiltBroker> {
  // Validate before reading secrets or opening Postgres. In JavaScript, the exported TypeScript type
  // is not a runtime boundary; a caller must not smuggle identitySecret/replayStore/providers through
  // an `as any` object and replace the fail-closed env configuration below.
  assertBrokerServerOverrides(overrides);
  // Master key(s): VOUCHR_MASTER_KEY and/or VOUCHR_MASTER_KEYS (#115). loadKeyring reads the
  // injected env for testability; its errors already name the variable and the 32-byte rule.
  let masterKey: Keyring;
  try {
    masterKey = loadKeyring(env);
  } catch (e: any) {
    fail(e?.message ?? String(e));
  }
  // #212 deployment-bound identity: build the issuer/audience/key set from env and fail closed on a
  // weak/missing secret, a missing deployment id, or a secret reused for ANOTHER purpose — Slack
  // signing, the master key (both env forms), the broker bearer, AND every provider OAuth client
  // secret (a value shared with a third party must never double as the identity trust root). The resulting
  // IdentityConfig — not a bare secret — is what makes an assertion minted for another deployment
  // un-acceptable here.
  let identityConfig: IdentityConfig;
  try {
    // The shared loader inventories Slack/broker/provider env secrets itself (STR-2). Pass the
    // already-decoded keyring too: purpose separation compares actual key bytes, not base64 text.
    identityConfig = loadIdentityConfig(env, masterKey.legacy.map(({ key }) => key));
  } catch (e: any) {
    fail(e?.message ?? String(e));
  }

  const port = nonNegativeIntegerEnv(env.VOUCHR_PORT, 'VOUCHR_PORT', 3000, 65_535);

  const allowWrites = booleanEnv(env.VOUCHR_ALLOW_WRITES, 'VOUCHR_ALLOW_WRITES');
  // #116 dry-run: real gates, stubbed network edges (see BrokerOptions.dryRun). Same env style as
  // VOUCHR_ALLOW_WRITES; explicit 1/true enables and 0/false disables, while typos fail boot.
  const dryRun = booleanEnv(env.VOUCHR_DRY_RUN, 'VOUCHR_DRY_RUN');
  const brokerToken = env.VOUCHR_BROKER_TOKEN || undefined;
  // #52 setting VOUCHR_BASE_URL mounts the OAuth connect flow (/v1/connect + the callback). Unset →
  // the historical use-only broker (no consent kickoff).
  const baseUrl = env.VOUCHR_BASE_URL || undefined;
  const callbackPath = env.VOUCHR_CALLBACK_PATH || undefined;

  const providers = loadProviders(env);
  if (!providers.length) fail('no providers configured (set VOUCHR_PROVIDERS or VOUCHR_PROVIDERS_FILE)');

  // Parse and cross-check EVERY pure resource setting before KMS or Postgres is acquired. Values are
  // canonical decimal integers and errors name only the variable/contract — never the supplied text,
  // which may be a credential pasted into the wrong variable (SEC-1). createBroker reuses the exact
  // same normalizer at its public boundary (STR-2).
  const timerEnv = (raw: string | undefined, name: string) =>
    optionalPositiveEnv(raw, name, { integer: true, max: MAX_TIMER_MS });
  const countEnv = (raw: string | undefined, name: string) =>
    optionalPositiveEnv(raw, name, { integer: true });
  const resourceBounds = normalizeBrokerResourceBounds({
    fetchDeadlineMs: timerEnv(env.VOUCHR_FETCH_DEADLINE_MS, 'VOUCHR_FETCH_DEADLINE_MS'),
    maxInflight: countEnv(env.VOUCHR_MAX_INFLIGHT, 'VOUCHR_MAX_INFLIGHT'),
    maxInflightPerProvider: countEnv(env.VOUCHR_MAX_INFLIGHT_PER_PROVIDER, 'VOUCHR_MAX_INFLIGHT_PER_PROVIDER'),
    headersTimeoutMs: timerEnv(env.VOUCHR_HEADERS_TIMEOUT_MS, 'VOUCHR_HEADERS_TIMEOUT_MS'),
    requestTimeoutMs: timerEnv(env.VOUCHR_REQUEST_TIMEOUT_MS, 'VOUCHR_REQUEST_TIMEOUT_MS'),
    keepAliveTimeoutMs: timerEnv(env.VOUCHR_KEEPALIVE_TIMEOUT_MS, 'VOUCHR_KEEPALIVE_TIMEOUT_MS'),
  });
  const shutdownTimeoutMs = timerEnv(env.VOUCHR_SHUTDOWN_TIMEOUT_MS, 'VOUCHR_SHUTDOWN_TIMEOUT_MS') ?? 10_000;

  // #54 TTL policy: 0 disables one dimension. TTLs are stored timestamps, not Node timers, so they
  // may exceed MAX_TIMER_MS but must still be canonical non-negative safe integers.
  const ttlDim = (raw: string | undefined, name: string, dflt: number): number | undefined => {
    const n = nonNegativeIntegerEnv(raw, name, dflt);
    return n === 0 ? undefined : n;
  };
  const ttl = {
    idleMs: ttlDim(env.VOUCHR_TTL_IDLE_MS, 'VOUCHR_TTL_IDLE_MS', 7 * 24 * 60 * 60 * 1000),
    maxAgeMs: ttlDim(env.VOUCHR_TTL_MAX_AGE_MS, 'VOUCHR_TTL_MAX_AGE_MS', 30 * 24 * 60 * 60 * 1000),
  };
  const sweepIntervalMs = nonNegativeIntegerEnv(
    env.VOUCHR_SWEEP_INTERVAL_MS,
    'VOUCHR_SWEEP_INTERVAL_MS',
    60 * 60 * 1000,
    MAX_TIMER_MS,
  );

  const url = env.VOUCHR_DATABASE_URL; // explicit only — no generic DATABASE_URL fallback (#204)
  const backend = 'postgres' as const; // PostgreSQL-only (#204); openDb fails closed if url unset/non-PG

  // #51 opt-in channel gate. Parse this pure switch with the rest of boot configuration so a typo
  // fails before KMS loading or Postgres acquisition; the store itself is created after openDb.
  const channelModes = booleanEnv(env.VOUCHR_CHANNEL_MODES, 'VOUCHR_CHANNEL_MODES');

  // Optional KMS envelope — only when configured.
  let envelope: EnvelopeProvider | undefined;
  if (env.VOUCHR_KMS_KEY_ID) {
    const { kmsEnvelope, awsKmsClient } = await import('../src/adapters/kms.js');
    envelope = kmsEnvelope(env.VOUCHR_KMS_KEY_ID, await awsKmsClient({ region: env.AWS_REGION }));
  }

  const db = await openDb({ databaseUrl: url });
  try {
  // #116 startup hard-fail (createBroker re-runs the same check lazily): never dry-run a real vault.
  if (dryRun) await assertDryRunVault(db);
  const vault = new Vault(db, masterKey, ttl, envelope);
  // #116: the SAME marked audit instance goes to createBroker AND the local sweep closure below, so
  // sweep-written rows (revoke reason 'expired') carry meta.dry_run too — createBroker only wraps
  // its own copy, which would leave the sweep writing unmarked rows.
  const audit = dryRun ? dryRunAudit(new Audit(db)) : new Audit(db);
  // createBroker always uses DbReplayStore (shared jti table), so a scaled fleet gets cluster-wide
  // single-use with no alternate replay path to wire here. #100/#212.

  // #51 opt-in channel gate: enables owner:'channel' handles resolved from SIGNED claims. Off by
  // default (user-only broker). The caller supplies eligibility facts as signed claims; the store
  // here only maps (team, channel, provider) → mode.
  const channelConfig = channelModes ? new ChannelConfig(db) : undefined;
  // #240 runtime channel governance is always available on the packaged path. Bolt and the broker
  // share this PostgreSQL table, so one signed admin toggle is reflected in the channel manifest and
  // enforced by both credential-use doors without an additional process-local switch or cache.
  const channelTools = new ChannelTools(db);

  const server = createBroker({
    providers,
    vault,
    audit,
    db,
    identitySecret: identityConfig,
    allowWrites,
    brokerToken,
    channelConfig,
    channelTools,
    baseUrl,
    callbackPath,
    dryRun,
    ...resourceBounds,
    authorize: overrides.authorize,
    resolvers: overrides.resolvers,
    onEvent: overrides.onEvent,
    auditSink: overrides.auditSink,
    onCredentialHealth: overrides.onCredentialHealth,
  });

  // #54 TTL sweep, wired the same way the Bolt path does (core sweepExpired + session-grant sweep).
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);
  const approvals = new Approvals(db); // #113: expired approval prompts/grants are reclaimed (and audited) too
  const sweep = async (): Promise<number> => {
    // #117: the deployer's onCredentialHealth override (if any) also hears expiring_soon/expired.
    const n = await sweepExpired(vault, audit, consent, undefined, overrides.onCredentialHealth, approvals);
    await sessions.sweepExpired();
    return n;
  };
  return {
    server,
    db,
    port,
    backend,
    providerIds: providers.map((p) => p.id),
    allowWrites,
    dryRun,
    sweep,
    sweepIntervalMs,
    shutdownTimeoutMs,
  };
  } catch (e) {
    await db.close().catch(() => undefined); // boot failed after the pool opened — don't leak it
    throw e;
  }
}

const USAGE = `vouchr-broker — standalone headless Vouchr credential broker (no Slack)

Usage: vouchr-broker            start the broker, config from env
       vouchr-broker --help     show this message

Required env: VOUCHR_IDENTITY_SECRET (>= 32 random bytes; distinct from every other secret),
              VOUCHR_DEPLOYMENT_ID (binds every identity assertion to this deployment),
              VOUCHR_MASTER_KEY (base64 of 32 bytes), VOUCHR_DATABASE_URL (PostgreSQL).
Optional env: VOUCHR_IDENTITY_SECRET_PREVIOUS (rolling key rotation), VOUCHR_IDENTITY_ISSUER (default
              'vouchr'), VOUCHR_PORT (3000), VOUCHR_KMS_KEY_ID, VOUCHR_ALLOW_WRITES, VOUCHR_DRY_RUN,
              VOUCHR_SWEEP_INTERVAL_MS.
Resource bounds (#209): VOUCHR_FETCH_DEADLINE_MS (30000), VOUCHR_MAX_INFLIGHT (200),
              VOUCHR_MAX_INFLIGHT_PER_PROVIDER (40), VOUCHR_HEADERS_TIMEOUT_MS (15000),
              VOUCHR_REQUEST_TIMEOUT_MS (30000), VOUCHR_KEEPALIVE_TIMEOUT_MS (10000),
              VOUCHR_SHUTDOWN_TIMEOUT_MS (10000). Limits are per process; the global fleet upper
              bound is replicas × VOUCHR_MAX_INFLIGHT, with an additional per-provider cap. See DEPLOYMENT.md.`;

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(USAGE);
    return;
  }
  const built = await buildBrokerServer();
  built.server.listen(built.port, () => {
    // One line, no secrets — startup provenance for ops.
    console.log(
      `[vouchr] broker listening port=${built.port} backend=${built.backend} ` +
        `providers=[${built.providerIds.join(',')}] allowWrites=${built.allowWrites}` +
        (built.dryRun ? ' dryRun=true' : ''),
    );
  });

  // #54 TTL sweep: once at startup, then on an interval. Idempotent, so multi-replica overlap is safe
  // (a log line is enough — no distributed lock). Set VOUCHR_SWEEP_INTERVAL_MS=0 to defer to an
  // external scheduler driving built.sweep() instead. Errors are logged, never fatal.
  const runSweep = () => built.sweep().then(
    (n) => { if (n) console.log(`[vouchr] sweep removed ${n} expired connection(s)`); },
    (e) => console.error(`[vouchr] sweep failed: ${(e as Error).message}`),
  );
  let sweepTimer: NodeJS.Timeout | undefined;
  if (built.sweepIntervalMs > 0) {
    void runSweep();
    sweepTimer = setInterval(runSweep, built.sweepIntervalMs);
    sweepTimer.unref(); // never keep the process alive for the sweep alone
  }

  let closing = false;
  const shutdown = (sig: string) => {
    if (closing) return;
    closing = true;
    if (sweepTimer) clearInterval(sweepTimer);
    console.log(`[vouchr] ${sig} received; draining connections`);
    // #209 stop accepting new work AND drop idle keep-alive sockets so close() completes on the
    // in-flight requests alone, instead of blocking on idle sockets until keepAliveTimeout (or the
    // hard-kill below). In-flight requests keep their connection until they finish.
    beginBrokerDrain(
      built.server,
      built.shutdownTimeoutMs,
      () => { built.db.close().catch(() => undefined).finally(() => process.exit(0)); },
      () => process.exit(1),
    );
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

if (require.main === module) {
  main().catch((e) => {
    console.error(`[vouchr] boot failed: ${(e as Error).message}`);
    process.exit(1);
  });
}
