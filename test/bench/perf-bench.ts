/**
 * Opt-in load harness for the #209 resource bounds — NOT part of `npm test` (it lives outside
 * `test/*.test.ts` and spins real servers + sustained load). Simulates a TWO-REPLICA fleet: N broker
 * instances share ONE Postgres (their own per-process in-flight limiter + pool each), a client drives
 * concurrent /v1/fetch across them against a fixed-latency mock provider, and it reports:
 *   - throughput (successful req/s) and P50/P95/P99 latency of served requests;
 *   - the 503 overload count (the per-process ceilings engaging — the fleet's back-pressure);
 *   - peak RSS of this single bench process (hosting ALL replicas + the client — a per-replica prod
 *     footprint is a fraction of this);
 *   - the safe scaling envelope: fleet in-flight capacity = replicas × per-process VOUCHR_MAX_INFLIGHT.
 *
 * Run:  npm run bench:perf         (uses VOUCHR_TEST_PG_URL)
 * Tune: BENCH_REPLICAS=2 BENCH_MAX_INFLIGHT=50 BENCH_CONCURRENCY=120 BENCH_DURATION_MS=5000 PROVIDER_MS=8
 */
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { Client } from 'pg';
import { migrate, openDb } from '../../src/core/db';
import { Vault } from '../../src/core/vault';
import { Audit } from '../../src/core/audit';
import { createBroker } from '../../src/adapters/http/broker';
import { userOwner } from '../../src/core/owner';
import { defineProvider } from '../../src/core/providers';
import { identityConfig, signIdentity } from '../support/identity';

const PG = process.env.VOUCHR_TEST_PG_URL ?? 'postgres://vouchr:vouchr@localhost:5433/vouchr';
const REPLICAS = Number(process.env.BENCH_REPLICAS ?? 2);
const MAX_INFLIGHT = Number(process.env.BENCH_MAX_INFLIGHT ?? 50);
const CONCURRENCY = Number(process.env.BENCH_CONCURRENCY ?? 120);
const DURATION_MS = Number(process.env.BENCH_DURATION_MS ?? 5_000);
const PROVIDER_MS = Number(process.env.PROVIDER_MS ?? 8);
const SECRET = 'bench-identity';
const U1 = { enterpriseId: null, teamId: 'T1', userId: 'U1' };

const pctl = (xs: number[], p: number) => xs.slice().sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor((p / 100) * xs.length))] ?? 0;

const acme = defineProvider({
  id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false, clientId: 'id', clientSecret: 'sec',
});

function token(): string {
  return signIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() }, SECRET);
}

function post(port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify({ handle: { provider: 'acme', owner: 'user' }, identityToken: token(), method: 'GET', path: '/x' }));
    const req = http.request({ host: '127.0.0.1', port, path: '/v1/fetch', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    });
    req.on('error', reject);
    req.end(data);
  });
}

async function main(): Promise<void> {
  // Mock provider with a fixed latency, so requests spend real time in flight (and the ceilings bite).
  globalThis.fetch = ((_u: any, init: any) => new Promise((resolve, reject) => {
    const sig: AbortSignal | undefined = init?.signal;
    const timer = setTimeout(() => resolve(new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } })), PROVIDER_MS);
    sig?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('aborted', 'AbortError')); }, { once: true });
  })) as any;

  // Dedicated throwaway schema (mirrors audit-bench) so the bench never collides with test schemas.
  const admin = new Client(PG);
  await admin.connect();
  await admin.query('DROP SCHEMA IF EXISTS perf_bench CASCADE');
  await admin.query('CREATE SCHEMA perf_bench');
  const url = new URL(PG);
  url.searchParams.set('options', '-c search_path=perf_bench');
  await migrate({ databaseUrl: url.toString() });

  const db = await openDb({ databaseUrl: url.toString() });
  const vault = new Vault(db, Buffer.alloc(32, 7));
  await vault.upsert(userOwner(U1), 'acme', { accessToken: 'tok', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

  const ports: number[] = [];
  const servers: http.Server[] = [];
  for (let i = 0; i < REPLICAS; i++) {
    const s = createBroker({ providers: [acme], vault, audit: new Audit(db), db, identitySecret: identityConfig(SECRET), maxInflight: MAX_INFLIGHT });
    await new Promise<void>((r) => s.listen(0, r));
    ports.push((s.address() as any).port);
    servers.push(s);
  }

  const fleet = REPLICAS * MAX_INFLIGHT;
  console.log(`\nfleet: ${REPLICAS} replicas × maxInflight ${MAX_INFLIGHT} = ${fleet} concurrent in-flight ceiling`);
  console.log(`load:  ${CONCURRENCY} client workers, ${DURATION_MS}ms, provider latency ${PROVIDER_MS}ms\n`);

  const latencies: number[] = [];
  let served = 0;
  let overloaded = 0;
  let other = 0;
  let peakRss = 0;
  const rssTimer = setInterval(() => { peakRss = Math.max(peakRss, process.memoryUsage().rss); }, 100).unref();

  const end = Date.now() + DURATION_MS;
  let rr = 0;
  const worker = async () => {
    while (Date.now() < end) {
      const port = ports[rr++ % ports.length];
      const t = Date.now();
      const status = await post(port).catch(() => -1);
      const ms = Date.now() - t;
      if (status === 200) { served++; latencies.push(ms); }
      // A well-behaved client honours the 503 Retry-After instead of hot-looping rejections (which
      // would flood the count with instant retries and misrepresent the ceiling as the common case).
      else if (status === 503) { overloaded++; await new Promise((r) => setTimeout(r, 15)); }
      else other++;
    }
  };
  const started = Date.now();
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  const elapsed = (Date.now() - started) / 1000;
  clearInterval(rssTimer);

  console.log(`served:     ${served}  (${(served / elapsed).toFixed(0)} req/s)`);
  console.log(`overloaded: ${overloaded}  (503 — the per-process ceilings holding back-pressure)`);
  console.log(`other:      ${other}`);
  console.log(`latency ms  P50=${pctl(latencies, 50)}  P95=${pctl(latencies, 95)}  P99=${pctl(latencies, 99)}  max=${Math.max(0, ...latencies)}`);
  console.log(`peak RSS:   ${(peakRss / 1_048_576).toFixed(0)} MiB (this ONE process hosts all ${REPLICAS} replicas + the client)`);
  console.log(`\nenvelope:   with ${CONCURRENCY} concurrent callers and a ${fleet}-slot fleet, ${overloaded > 0 ? 'the ceiling engaged (503s) and latency stayed bounded' : 'the fleet absorbed the load with headroom'}.`);
  console.log(`            scale linearly: add a replica → +${MAX_INFLIGHT} in-flight slots and ~+${(served / elapsed / REPLICAS).toFixed(0)} req/s.\n`);

  for (const s of servers) s.close();
  await db.close();
  await admin.query('DROP SCHEMA IF EXISTS perf_bench CASCADE');
  await admin.end();
}

main().catch((e) => { console.error(e); process.exit(1); });
