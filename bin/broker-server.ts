#!/usr/bin/env node
/**
 * broker-server: the standalone headless Vouchr broker (no Slack, no Bolt).
 *
 * Reads config from env, wires the same core (openDb → Vault → Audit → createBroker) the Bolt path
 * uses, and serves /v1/fetch, /v1/resolve, and the /healthz + /readyz probes. Postgres + KMS + the
 * default shared jti store (DbReplayStore) make it multi-replica safe; see DEPLOYMENT.md.
 * Run: `node dist/bin/broker-server.js`.
 */
import http from 'node:http';
import { openDb, type Db } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { createBroker, type BrokerOptions } from '../src/adapters/http/broker';
import { loadIdentityConfig, type IdentityConfig } from '../src/adapters/http/identity';
import { ChannelConfig } from '../src/core/channelConfig';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import { sweepExpired } from '../src/core/sweep';
import { Approvals } from '../src/core/approval';
import { loadKeyring, type EnvelopeProvider, type Keyring } from '../src/core/crypto';
import { assertDryRunVault, dryRunAudit } from '../src/core/dryRun';
import { loadProviders } from './providerConfig';

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
}

/**
 * Build (but do not listen on) the broker from `env`. Exported so tests drive it with an injected env
 * and no process side effects. `overrides` lets a deployer inject non-declarative bits (e.g. an
 * `authorize` hook) from a thin wrapper without forking this file.
 */
export async function buildBrokerServer(
  env: NodeJS.ProcessEnv = process.env,
  overrides: Partial<BrokerOptions> = {},
): Promise<BuiltBroker> {
  // Master key(s): VOUCHR_MASTER_KEY and/or VOUCHR_MASTER_KEYS (#115). loadKeyring reads the
  // injected env for testability; its errors already name the variable and the 32-byte rule.
  let masterKey: Keyring;
  try {
    masterKey = loadKeyring(env);
  } catch (e: any) {
    fail(e?.message ?? String(e));
  }
  // #212 deployment-bound identity: build the issuer/audience/key set from env and fail closed on a
  // weak/missing secret, a missing deployment id, or a secret reused for ANOTHER purpose — the master
  // key (both env forms), the broker bearer, AND every provider OAuth client secret (a value shared
  // with a third-party provider must never double as the identity trust root). The resulting
  // IdentityConfig — not a bare secret — is what makes an assertion minted for another deployment
  // un-acceptable here.
  const otherSecrets = [
    env.VOUCHR_MASTER_KEY,
    ...(env.VOUCHR_MASTER_KEYS ?? '').split(',').map((e) => e.split(':').slice(1).join(':').trim()),
    env.VOUCHR_BROKER_TOKEN,
    ...Object.entries(env)
      .filter(([k]) => /^VOUCHR_PROVIDER_.+_CLIENT_SECRET$/.test(k))
      .map(([, v]) => v),
  ].filter((s): s is string => !!s);
  let identityConfig: IdentityConfig;
  try {
    identityConfig = loadIdentityConfig(env, otherSecrets);
  } catch (e: any) {
    fail(e?.message ?? String(e));
  }

  const port = Number(env.VOUCHR_PORT ?? 3000);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail(`VOUCHR_PORT invalid: ${env.VOUCHR_PORT}`);

  const allowWrites = env.VOUCHR_ALLOW_WRITES === '1' || env.VOUCHR_ALLOW_WRITES === 'true';
  // #116 dry-run: real gates, stubbed network edges (see BrokerOptions.dryRun). Same env style as
  // VOUCHR_ALLOW_WRITES; anything but an explicit 1/true stays off (production behavior).
  const dryRun = env.VOUCHR_DRY_RUN === '1' || env.VOUCHR_DRY_RUN === 'true';
  const brokerToken = env.VOUCHR_BROKER_TOKEN || undefined;
  // #52 setting VOUCHR_BASE_URL mounts the OAuth connect flow (/v1/connect + the callback). Unset →
  // the historical use-only broker (no consent kickoff).
  const baseUrl = env.VOUCHR_BASE_URL || undefined;
  const callbackPath = env.VOUCHR_CALLBACK_PATH || undefined;

  const providers = loadProviders(env);
  if (!providers.length) fail('no providers configured (set VOUCHR_PROVIDERS or VOUCHR_PROVIDERS_FILE)');

  const url = env.VOUCHR_DATABASE_URL; // explicit only — no generic DATABASE_URL fallback (#204)
  const backend = 'postgres' as const; // PostgreSQL-only (#204); openDb fails closed if url unset/non-PG

  // Optional KMS envelope — only when configured.
  let envelope: EnvelopeProvider | undefined;
  if (env.VOUCHR_KMS_KEY_ID) {
    const { kmsEnvelope, awsKmsClient } = await import('../src/adapters/kms.js');
    envelope = kmsEnvelope(env.VOUCHR_KMS_KEY_ID, await awsKmsClient({ region: env.AWS_REGION }));
  }

  // #54 TTL policy: without one, get()-time expiry and the sweep are both no-ops (a credential lives
  // forever). Default matches the Bolt path (7d idle / 30d max), so the two front doors behave the
  // same on a shared database. Override per-dimension via env; set a var to 0 to disable that limit.
  const ttlDim = (raw: string | undefined, dflt: number): number | undefined => {
    if (raw === undefined) return dflt;
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) fail(`invalid TTL env value: ${raw}`);
    return n === 0 ? undefined : n; // 0 → disable this dimension (null in TtlPolicy)
  };
  const ttl = {
    idleMs: ttlDim(env.VOUCHR_TTL_IDLE_MS, 7 * 24 * 60 * 60 * 1000),
    maxAgeMs: ttlDim(env.VOUCHR_TTL_MAX_AGE_MS, 30 * 24 * 60 * 60 * 1000),
  };

  const db = await openDb({ databaseUrl: url });
  try {
  // #116 startup hard-fail (createBroker re-runs the same check lazily): never dry-run a real vault.
  if (dryRun) await assertDryRunVault(db);
  const vault = new Vault(db, masterKey, ttl, envelope);
  // #116: the SAME marked audit instance goes to createBroker AND the local sweep closure below, so
  // sweep-written rows (revoke reason 'expired') carry meta.dry_run too — createBroker only wraps
  // its own copy, which would leave the sweep writing unmarked rows.
  const audit = dryRun ? dryRunAudit(new Audit(db)) : new Audit(db);
  // Multi-replica safety is now the createBroker default: with a db configured it uses DbReplayStore
  // (shared jti table), so a scaled fleet gets cluster-wide single-use with no wiring here. #100.

  // #51 opt-in channel gate: enables owner:'channel' handles resolved from SIGNED claims. Off by
  // default (user-only broker). The caller supplies eligibility facts as signed claims; the store
  // here only maps (team, channel, provider) → mode.
  const channelModes = env.VOUCHR_CHANNEL_MODES === '1' || env.VOUCHR_CHANNEL_MODES === 'true';
  const channelConfig = channelModes ? new ChannelConfig(db) : undefined;

  const server = createBroker({
    providers,
    vault,
    audit,
    db,
    identitySecret: identityConfig,
    allowWrites,
    brokerToken,
    channelConfig,
    baseUrl,
    callbackPath,
    dryRun,
    ...overrides,
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
  const rawInterval = env.VOUCHR_SWEEP_INTERVAL_MS;
  const sweepIntervalMs = rawInterval !== undefined ? Number(rawInterval) : 60 * 60 * 1000;
  if (!Number.isFinite(sweepIntervalMs) || sweepIntervalMs < 0) fail(`VOUCHR_SWEEP_INTERVAL_MS invalid: ${rawInterval}`);

  return { server, db, port, backend, providerIds: providers.map((p) => p.id), allowWrites, dryRun, sweep, sweepIntervalMs };
  } catch (e) {
    await db.close().catch(() => undefined); // boot failed after the pool opened — don't leak it
    throw e;
  }
}

const USAGE = `vouchr-broker — standalone headless Vouchr credential broker (no Slack)

Usage: vouchr-broker            start the broker, config from env
       vouchr-broker --help     show this message

Required env: VOUCHR_IDENTITY_SECRET (>= 32 random bytes; distinct from the master key),
              VOUCHR_DEPLOYMENT_ID (binds every identity assertion to this deployment),
              VOUCHR_MASTER_KEY (base64 of 32 bytes), VOUCHR_DATABASE_URL (PostgreSQL).
Optional env: VOUCHR_IDENTITY_SECRET_PREVIOUS (rolling key rotation), VOUCHR_IDENTITY_ISSUER (default
              'vouchr'), VOUCHR_PORT (3000), VOUCHR_KMS_KEY_ID, VOUCHR_ALLOW_WRITES, VOUCHR_DRY_RUN,
              VOUCHR_SWEEP_INTERVAL_MS. See DEPLOYMENT.md.`;

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
    built.server.close(() => {
      built.db.close().catch(() => undefined).finally(() => process.exit(0));
    });
    // Don't hang forever on a stuck connection.
    setTimeout(() => process.exit(1), 10_000).unref();
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
