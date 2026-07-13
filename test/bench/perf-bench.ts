/**
 * Opt-in load harness for #209. It runs several independent broker instances and PostgreSQL pools
 * against one throwaway schema, then records the HTTP admission envelope rather than extrapolating
 * throughput from one machine:
 *   - successful and all-attempt P50/P95/P99 latency plus successful throughput;
 *   - global/per-provider overload responses while honouring the broker's Retry-After header;
 *   - peak RSS for this ONE benchmark process (replicas + client);
 *   - aggregate main-pool sessions (total/active/waiting) across the simulated replicas;
 *   - KMS-shaped envelope wrap/unwrap counts (local crypto, so this measures calls, not KMS latency).
 *
 * Run:  npm run bench:perf         (uses VOUCHR_TEST_PG_URL)
 * Tune: BENCH_REPLICAS=2 BENCH_MAX_INFLIGHT=50 BENCH_MAX_INFLIGHT_PER_PROVIDER=40
 *       BENCH_CONCURRENCY=120 BENCH_DURATION_MS=5000 PROVIDER_MS=8
 */
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { Client, type Pool } from 'pg';
import { migrate, openDb, type Db } from '../../src/core/db';
import { Vault } from '../../src/core/vault';
import { Audit } from '../../src/core/audit';
import { createBroker } from '../../src/adapters/http/broker';
import { userOwner } from '../../src/core/owner';
import { defineProvider } from '../../src/core/providers';
import { decrypt, encrypt, type EnvelopeProvider } from '../../src/core/crypto';
import { MAX_TIMER_MS, nonNegativeIntegerEnv, optionalPositiveEnv } from '../../src/core/options';
import { identityConfig, signIdentity } from '../support/identity';

const PG = process.env.VOUCHR_TEST_PG_URL ?? 'postgres://vouchr:vouchr@localhost:5433/vouchr';
const SECRET = 'bench-identity';
const U1 = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const MASTER_KEY = Buffer.alloc(32, 7);
const ENVELOPE_KEY = Buffer.alloc(32, 9);

interface BenchConfig {
  replicas: number;
  maxInflight: number;
  maxInflightPerProvider: number;
  concurrency: number;
  durationMs: number;
  providerMs: number;
}

function positiveInteger(name: string, fallback: number, max: number): number {
  return optionalPositiveEnv(process.env[name], name, { integer: true, max }) ?? fallback;
}

function loadConfig(): BenchConfig {
  const replicas = positiveInteger('BENCH_REPLICAS', 2, 32);
  const maxInflight = positiveInteger('BENCH_MAX_INFLIGHT', 50, 10_000);
  const maxInflightPerProvider = positiveInteger(
    'BENCH_MAX_INFLIGHT_PER_PROVIDER', Math.min(40, maxInflight), maxInflight,
  );
  return {
    replicas,
    maxInflight,
    maxInflightPerProvider,
    concurrency: positiveInteger('BENCH_CONCURRENCY', 120, 100_000),
    durationMs: positiveInteger('BENCH_DURATION_MS', 5_000, 600_000),
    providerMs: nonNegativeIntegerEnv(process.env.PROVIDER_MS, 'PROVIDER_MS', 8, MAX_TIMER_MS),
  };
}

function percentile(values: number[], percentileValue: number): number {
  if (!values.length) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  return sorted[Math.max(0, Math.ceil((percentileValue / 100) * sorted.length) - 1)];
}

const acme = defineProvider({
  id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false,
  clientId: 'id', clientSecret: 'sec',
});

function token(): string {
  return signIdentity(
    { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() },
    SECRET,
  );
}

interface Attempt {
  status: number;
  retryAfterMs: number;
}

function post(port: number): Promise<Attempt> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify({
      handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'GET', path: '/x',
    }));
    const req = http.request(
      {
        host: '127.0.0.1', port, path: '/v1/fetch', method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': data.length },
      },
      (res) => {
        res.resume();
        res.on('end', () => {
          const rawRetryAfter = Array.isArray(res.headers['retry-after'])
            ? res.headers['retry-after'][0]
            : res.headers['retry-after'];
          const retrySeconds = Number(rawRetryAfter);
          resolve({
            status: res.statusCode ?? 0,
            retryAfterMs: Number.isFinite(retrySeconds) && retrySeconds >= 0 ? retrySeconds * 1_000 : 1_000,
          });
        });
      },
    );
    req.on('error', reject);
    req.setTimeout(60_000, () => req.destroy(new Error('benchmark client deadline exceeded')));
    req.end(data);
  });
}

interface PoolSnapshot {
  total: number;
  active: number;
  waiting: number;
}

/** Benchmark-only visibility into PgDb's pool counters; every replica owns a distinct PgDb/pool. */
function poolSnapshot(databases: Db[]): PoolSnapshot {
  return databases.reduce<PoolSnapshot>((sum, db) => {
    const pool = (db as unknown as { pool?: Pool }).pool;
    if (!pool) throw new Error('bench:perf requires the PostgreSQL pool-backed Db');
    sum.total += pool.totalCount;
    sum.active += pool.totalCount - pool.idleCount;
    sum.waiting += pool.waitingCount;
    return sum;
  }, { total: 0, active: 0, waiting: 0 });
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    server.once('error', onError);
    server.listen(0, () => {
      server.removeListener('error', onError);
      resolve((server.address() as { port: number }).port);
    });
  });
}

async function closeServer(server: http.Server): Promise<void> {
  await new Promise<void>((resolve) => {
    let closed = false;
    let deadline: NodeJS.Timeout | undefined;
    const finish = () => {
      if (closed) return;
      closed = true;
      if (deadline) clearTimeout(deadline);
      resolve();
    };
    deadline = setTimeout(() => {
      server.closeAllConnections();
      finish();
    }, 2_000);
    deadline.unref();
    server.close(finish);
    server.closeIdleConnections();
  });
}

async function main(): Promise<void> {
  const cfg = loadConfig();
  const schema = `perf_bench_${process.pid}_${Date.now()}`;
  const admin = new Client(PG);
  const databases: Db[] = [];
  const servers: http.Server[] = [];
  const ports: number[] = [];
  const realFetch = globalThis.fetch;
  let adminConnected = false;
  let schemaCreated = false;
  let sampleTimer: NodeJS.Timeout | undefined;
  let kmsWraps = 0;
  let kmsUnwraps = 0;

  // A local envelope exercises the same Vault wrap/unwrap call sites as KMS and counts them. It does
  // not simulate KMS network latency; a deployment proof must run the real configured KMS adapter.
  const envelope: EnvelopeProvider = {
    async wrapDataKey(dataKey) {
      kmsWraps++;
      return encrypt(dataKey.toString('base64'), ENVELOPE_KEY);
    },
    async unwrapDataKey(wrapped) {
      kmsUnwraps++;
      return Buffer.from(decrypt(wrapped, ENVELOPE_KEY), 'base64');
    },
  };

  try {
    globalThis.fetch = ((_url: unknown, init: RequestInit | undefined) => new Promise((resolve, reject) => {
      const signal = init?.signal;
      let settled = false;
      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener('abort', onAbort);
        fn();
      };
      const timer = setTimeout(() => finish(() => resolve(
        new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }),
      )), cfg.providerMs);
      const onAbort = () => {
        clearTimeout(timer);
        finish(() => reject(new DOMException('aborted', 'AbortError')));
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) onAbort();
    })) as typeof fetch;

    await admin.connect();
    adminConnected = true;
    await admin.query(`CREATE SCHEMA "${schema}"`);
    schemaCreated = true;
    const url = new URL(PG);
    url.searchParams.set('options', `-c search_path=${schema}`);
    await migrate({ databaseUrl: url.toString() });

    // One pool per simulated replica, as in production. Sharing one Db here would hide pool pressure
    // and make the supposed replica envelope only a multi-server/single-pool measurement.
    for (let i = 0; i < cfg.replicas; i++) databases.push(await openDb({ databaseUrl: url.toString() }));
    const vaults = databases.map((db) => new Vault(db, MASTER_KEY, {}, envelope));
    await vaults[0].upsert(userOwner(U1), 'acme', {
      accessToken: 'tok', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });

    for (let i = 0; i < cfg.replicas; i++) {
      const server = createBroker({
        providers: [acme], vault: vaults[i], audit: new Audit(databases[i]), db: databases[i],
        identitySecret: identityConfig(SECRET), maxInflight: cfg.maxInflight,
        maxInflightPerProvider: cfg.maxInflightPerProvider,
      });
      servers.push(server);
      ports.push(await listen(server));
    }

    // This harness drives one provider, so its effective per-replica ceiling is the stricter of the
    // global and per-provider settings. Multi-provider traffic may use more of the global allowance.
    const perReplicaCeiling = Math.min(cfg.maxInflight, cfg.maxInflightPerProvider);
    const fleetCeiling = cfg.replicas * perReplicaCeiling;
    console.log(
      `\nfleet: ${cfg.replicas} replicas; global=${cfg.maxInflight}, per-provider=${cfg.maxInflightPerProvider}; ` +
      `single-provider active ceiling=${fleetCeiling}`,
    );
    console.log(
      `load:  ${cfg.concurrency} client workers, ${cfg.durationMs}ms, provider latency ${cfg.providerMs}ms\n`,
    );

    const servedLatencies: number[] = [];
    const attemptLatencies: number[] = [];
    let served = 0;
    let overloaded = 0;
    let other = 0;
    let peakRss = process.memoryUsage().rss;
    let peakPool = poolSnapshot(databases);
    const sample = () => {
      peakRss = Math.max(peakRss, process.memoryUsage().rss);
      const current = poolSnapshot(databases);
      peakPool = {
        total: Math.max(peakPool.total, current.total),
        active: Math.max(peakPool.active, current.active),
        waiting: Math.max(peakPool.waiting, current.waiting),
      };
    };
    sampleTimer = setInterval(sample, 50);
    sampleTimer.unref();

    const end = Date.now() + cfg.durationMs;
    let roundRobin = 0;
    const worker = async () => {
      while (Date.now() < end) {
        const port = ports[roundRobin++ % ports.length];
        const started = Date.now();
        const result = await post(port).catch(() => ({ status: -1, retryAfterMs: 0 }));
        const elapsedMs = Date.now() - started;
        attemptLatencies.push(elapsedMs);
        if (result.status === 200) {
          served++;
          servedLatencies.push(elapsedMs);
        } else if (result.status === 503) {
          overloaded++;
          // Model the documented client behavior instead of hot-looping retries beneath the hint.
          await new Promise((resolve) => setTimeout(resolve, Math.max(1, result.retryAfterMs)));
        } else {
          other++;
        }
      }
    };

    const started = Date.now();
    await Promise.all(Array.from({ length: cfg.concurrency }, worker));
    const elapsedSeconds = (Date.now() - started) / 1_000;
    sample();
    clearInterval(sampleTimer);
    sampleTimer = undefined;

    const latencyLine = (values: number[]) =>
      `P50=${percentile(values, 50)} P95=${percentile(values, 95)} P99=${percentile(values, 99)} ` +
      `max=${Math.max(0, ...values)}`;
    console.log(`served:     ${served}  (${(served / elapsedSeconds).toFixed(0)} req/s)`);
    console.log(`overloaded: ${overloaded}  (503; Retry-After honoured before this worker retries)`);
    console.log(`other:      ${other}`);
    console.log(`served latency ms: ${latencyLine(servedLatencies)}`);
    console.log(`all HTTP attempt latency ms: ${latencyLine(attemptLatencies)}`);
    console.log(
      `peak main-pool sessions: total=${peakPool.total} active=${peakPool.active} waiting=${peakPool.waiting} ` +
      `(aggregate across ${cfg.replicas} independent pools)`,
    );
    console.log(
      `envelope operations: wraps=${kmsWraps} unwraps=${kmsUnwraps} ` +
      '(local KMS-shaped provider; counts calls, not network latency)',
    );
    console.log(
      `peak RSS: ${(peakRss / 1_048_576).toFixed(0)} MiB ` +
      `(one benchmark process hosts ${cfg.replicas} replicas + client)`,
    );
    console.log(
      `\nenvelope: ${cfg.concurrency} callers against a ${fleetCeiling}-slot single-provider fleet; ` +
      `${overloaded > 0 ? 'admission engaged' : 'no overload observed'}. ` +
      'These measurements describe this run; throughput is not extrapolated linearly across replicas.\n',
    );
  } finally {
    if (sampleTimer) clearInterval(sampleTimer);
    globalThis.fetch = realFetch;
    await Promise.allSettled(servers.map(closeServer));
    await Promise.allSettled(databases.map((db) => db.close()));
    if (adminConnected && schemaCreated) {
      await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
    }
    if (adminConnected) await admin.end().catch(() => undefined);
  }
}

main().catch((error: unknown) => {
  // Canonical numeric-parser errors name only a known knob/contract and are safe to show. Every
  // dependency error gets static copy so a connection URL, credential, or response cannot leak.
  const message = error instanceof Error && /^vouchr: (?:BENCH_[A-Z_]+|PROVIDER_MS) must /.test(error.message)
    ? error.message
    : 'failed; check PostgreSQL availability and BENCH_* configuration';
  console.error(`[bench:perf] ${message}`);
  process.exitCode = 1;
});
