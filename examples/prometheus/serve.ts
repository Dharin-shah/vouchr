import { createServer } from 'node:http';
import { metricsSink } from './metrics';
import type { VouchrEvent } from '../../src/core/injector';

/**
 * A GET /metrics exporter for Prometheus, built on the no-secret `EventSink` (see ./metrics.ts).
 *
 * In a real deployment you pass `metrics.sink` as the `EventSink` argument to `ConnectionHandle`
 * (or wherever the broker is constructed) and let live traffic fill the counters. Here we seed a
 * short demo sequence so a STANDALONE scrape returns non-empty, valid exposition text with nothing
 * more than `node --import tsx examples/prometheus/serve.ts` — no DB, no provider creds, no network.
 */
const metrics = metricsSink();

// Wire it into the broker like this (the events then flow from real traffic):
//   new ConnectionHandle(provider, owner, acting, vault, audit, resolvers, inflight, metrics.sink)
const demo: VouchrEvent[] = [
  { type: 'injected', provider: 'github', host: 'api.github.com', status: 200, ownerKind: 'user', ms: 42 },
  { type: 'injected', provider: 'github', host: 'api.github.com', status: 200, ownerKind: 'user', ms: 8 },
  { type: 'injected', provider: 'github', host: 'api.github.com', status: 404, ownerKind: 'channel', ms: 120 },
  { type: 'refreshed', provider: 'github', ms: 210 },
  { type: 'refresh_lock_wait', provider: 'github', waitMs: 5, reused: true },
  { type: 'egress_denied', provider: 'github', host: 'evil.example.com', reason: 'host' },
  { type: 'expired', count: 3 },
];
for (const e of demo) metrics.sink(e);

const PORT = process.env.VOUCHR_METRICS_PORT ? Number(process.env.VOUCHR_METRICS_PORT) : 9464;

const server = createServer((req, res) => {
  if (req.method === 'GET' && (req.url ?? '').split('?')[0] === '/metrics') {
    res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' });
    res.end(metrics.render());
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('not found\n');
});

// Loopback only: a metrics port is internal, scraped by a local Prometheus/sidecar, not the network.
server.listen(PORT, '127.0.0.1', () => {
  console.log(`vouchr metrics on http://127.0.0.1:${PORT}/metrics`);
});
