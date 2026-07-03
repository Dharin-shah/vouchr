#!/usr/bin/env node
/**
 * broker-server: the standalone headless Vouchr broker (no Slack, no Bolt).
 *
 * Reads config from env, wires the same core (openDb → Vault → Audit → createBroker) the Bolt path
 * uses, and serves /v1/fetch, /v1/resolve, /healthz. Postgres + KMS + a shared jti ReplayStore make
 * it multi-replica safe; see DEPLOYMENT.md. Run: `node dist/bin/broker-server.js`.
 */
import http from 'node:http';
import { openDb, type Db } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { createBroker, type BrokerOptions } from '../src/adapters/http/broker';
import { ChannelConfig } from '../src/core/channelConfig';
import { DbReplayStore } from '../src/adapters/http/replayStore';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import { sweepExpired } from '../src/core/sweep';
import type { EnvelopeProvider } from '../src/core/crypto';
import { assertProductionConfig } from '../src/core/options';
import { loadProviders } from './providerConfig';

function fail(msg: string): never {
  throw new Error(msg);
}

export interface BuiltBroker {
  server: http.Server;
  db: Db;
  port: number;
  backend: 'postgres' | 'sqlite';
  providerIds: string[];
  allowWrites: boolean;
  production: boolean;
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
  const identitySecret = env.VOUCHR_IDENTITY_SECRET;
  if (!identitySecret || !identitySecret.trim()) {
    fail('VOUCHR_IDENTITY_SECRET is required (the HS256 secret shared with the identity-token minter)');
  }
  // Master key: base64 → 32 bytes. Mirrors loadMasterKey() but reads the injected env for testability.
  const b64 = env.VOUCHR_MASTER_KEY;
  if (!b64) fail('VOUCHR_MASTER_KEY is required (base64 of 32 bytes). Generate: openssl rand -base64 32');
  const masterKey = Buffer.from(b64, 'base64');
  if (masterKey.length !== 32) fail('VOUCHR_MASTER_KEY must decode to exactly 32 bytes');

  const port = Number(env.VOUCHR_PORT ?? 3000);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail(`VOUCHR_PORT invalid: ${env.VOUCHR_PORT}`);

  const allowWrites = env.VOUCHR_ALLOW_WRITES === '1' || env.VOUCHR_ALLOW_WRITES === 'true';
  const brokerToken = env.VOUCHR_BROKER_TOKEN || undefined;
  // #52 setting VOUCHR_BASE_URL mounts the OAuth connect flow (/v1/connect + the callback). Unset →
  // the historical use-only broker (no consent kickoff).
  const baseUrl = env.VOUCHR_BASE_URL || undefined;
  const callbackPath = env.VOUCHR_CALLBACK_PATH || undefined;

  const providers = loadProviders(env);
  if (!providers.length) fail('no providers configured (set VOUCHR_PROVIDERS or VOUCHR_PROVIDERS_FILE)');

  const url = env.VOUCHR_DATABASE_URL ?? env.DATABASE_URL;
  const backend: 'postgres' | 'sqlite' = !!url && /^postgres(ql)?:\/\//.test(url) ? 'postgres' : 'sqlite';
  const production = env.VOUCHR_PRODUCTION === '1';

  // Optional KMS envelope — only when configured. Built BEFORE the prod assertion so an unset KMS in
  // production fails fast with the assertion's message rather than a confusing later error.
  let envelope: EnvelopeProvider | undefined;
  if (env.VOUCHR_KMS_KEY_ID) {
    const { kmsEnvelope, awsKmsClient } = await import('../src/adapters/kms');
    envelope = kmsEnvelope(env.VOUCHR_KMS_KEY_ID, await awsKmsClient({ region: env.AWS_REGION }));
  }

  // Fail fast on an unsafe production config (SQLite or no envelope) BEFORE opening the store. Pass
  // `url ?? ''` (not undefined) so the assertion checks the SAME resolved backend openDb will open,
  // instead of falling back to an ambient process.env DATABASE_URL that isn't what we opened.
  assertProductionConfig({ databaseUrl: url ?? '', envelope, production });

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

  const db = await openDb(backend === 'postgres' ? { databaseUrl: url } : { dbPath: env.VOUCHR_DB });
  const vault = new Vault(db, masterKey, ttl, envelope);
  const audit = new Audit(db);
  // Multi-replica safety: a shared durable jti store on Postgres. SQLite is single-replica, so the
  // broker's default in-memory guard is sufficient there.
  const replayStore = backend === 'postgres' ? new DbReplayStore(db) : undefined;

  // #51 opt-in channel gate: enables owner:'channel' handles resolved from SIGNED claims. Off by
  // default (user-only broker). The caller supplies eligibility/union facts as signed claims; the
  // store here only maps (team, channel, provider) → mode.
  const channelModes = env.VOUCHR_CHANNEL_MODES === '1' || env.VOUCHR_CHANNEL_MODES === 'true';
  const channelConfig = channelModes ? new ChannelConfig(db) : undefined;

  const server = createBroker({
    providers,
    vault,
    audit,
    db,
    identitySecret,
    allowWrites,
    brokerToken,
    replayStore,
    channelConfig,
    baseUrl,
    callbackPath,
    ...overrides,
  });

  // #54 TTL sweep, wired the same way the Bolt path does (core sweepExpired + session-grant sweep).
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);
  const sweep = async (): Promise<number> => {
    const n = await sweepExpired(vault, audit, consent);
    await sessions.sweepExpired();
    return n;
  };
  const rawInterval = env.VOUCHR_SWEEP_INTERVAL_MS;
  const sweepIntervalMs = rawInterval !== undefined ? Number(rawInterval) : 60 * 60 * 1000;
  if (!Number.isFinite(sweepIntervalMs) || sweepIntervalMs < 0) fail(`VOUCHR_SWEEP_INTERVAL_MS invalid: ${rawInterval}`);

  return { server, db, port, backend, providerIds: providers.map((p) => p.id), allowWrites, production, sweep, sweepIntervalMs };
}

async function main(): Promise<void> {
  const built = await buildBrokerServer();
  built.server.listen(built.port, () => {
    // One line, no secrets — startup provenance for ops.
    console.log(
      `[vouchr] broker listening port=${built.port} backend=${built.backend} ` +
        `providers=[${built.providerIds.join(',')}] allowWrites=${built.allowWrites} ` +
        `mode=${built.production ? 'production' : 'non-production'}`,
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
