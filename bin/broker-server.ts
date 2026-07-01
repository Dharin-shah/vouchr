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
import { DbReplayStore } from '../src/adapters/http/replayStore';
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

  const db = await openDb(backend === 'postgres' ? { databaseUrl: url } : { dbPath: env.VOUCHR_DB });
  const vault = new Vault(db, masterKey, {}, envelope);
  const audit = new Audit(db);
  // Multi-replica safety: a shared durable jti store on Postgres. SQLite is single-replica, so the
  // broker's default in-memory guard is sufficient there.
  const replayStore = backend === 'postgres' ? new DbReplayStore(db) : undefined;

  const server = createBroker({
    providers,
    vault,
    audit,
    db,
    identitySecret,
    allowWrites,
    brokerToken,
    replayStore,
    ...overrides,
  });

  return { server, db, port, backend, providerIds: providers.map((p) => p.id), allowWrites, production };
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

  let closing = false;
  const shutdown = (sig: string) => {
    if (closing) return;
    closing = true;
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
