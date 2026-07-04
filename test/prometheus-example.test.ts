import { test } from 'node:test';
import assert from 'node:assert/strict';
import { metricsSink } from '../examples/prometheus/metrics';
import type { VouchrEvent } from '../src/core/injector';

// Offline style of test/observability.test.ts: no DB, no network — just feed a fixed sequence of
// VouchrEvents into metricsSink and assert the rendered exposition text.
test('prometheus example: metricsSink renders the expected counters and histogram buckets', () => {
  const m = metricsSink();
  const events: VouchrEvent[] = [
    { type: 'injected', provider: 'github', host: 'api.github.com', status: 200, ownerKind: 'user', ms: 3 },
    { type: 'injected', provider: 'github', host: 'api.github.com', status: 200, ownerKind: 'user', ms: 40 },
    { type: 'injected', provider: 'github', host: 'api.github.com', status: 500, ownerKind: 'user', ms: 3 },
    { type: 'refreshed', provider: 'github', ms: 100 },
    { type: 'refresh_lock_wait', provider: 'github', waitMs: 7, reused: true },
    { type: 'kms_decrypt', provider: 'github', count: 2 },
    { type: 'egress_denied', provider: 'github', host: 'evil.example.com', reason: 'host' },
    { type: 'egress_error', provider: 'github', host: 'api.github.com', reason: 'fetch_failed' },
    { type: 'resolver_failed', provider: 'aws', source: 'aws-sm' },
    { type: 'connect_prompted', provider: 'github' },
    { type: 'connected', provider: 'github' },
    { type: 'policy_denied', provider: 'github' },
    { type: 'revoked', provider: 'github', ok: true },
    { type: 'expired', count: 5 },
  ];
  for (const e of events) m.sink(e);
  const text = m.render();

  // Counters (labels are already-no-secret VouchrEvent fields).
  assert.match(text, /^vouchr_injected_total\{provider="github",host="api\.github\.com",status="200",owner_kind="user"\} 2$/m);
  assert.match(text, /^vouchr_injected_total\{provider="github",host="api\.github\.com",status="500",owner_kind="user"\} 1$/m);
  assert.match(text, /^vouchr_refreshed_total\{provider="github"\} 1$/m);
  assert.match(text, /^vouchr_refresh_reused_total\{provider="github"\} 1$/m);
  assert.match(text, /^vouchr_kms_decrypt_total\{provider="github"\} 2$/m); // incremented by count
  assert.match(text, /^vouchr_egress_denied_total\{provider="github",host="evil\.example\.com",reason="host"\} 1$/m);
  assert.match(text, /^vouchr_egress_error_total\{provider="github",host="api\.github\.com",reason="fetch_failed"\} 1$/m);
  assert.match(text, /^vouchr_resolver_failed_total\{provider="aws",source="aws-sm"\} 1$/m);
  assert.match(text, /^vouchr_connect_prompted_total\{provider="github"\} 1$/m);
  assert.match(text, /^vouchr_connected_total\{provider="github"\} 1$/m);
  assert.match(text, /^vouchr_policy_denied_total\{provider="github"\} 1$/m);
  assert.match(text, /^vouchr_revoked_total\{provider="github",ok="true"\} 1$/m);
  assert.match(text, /^vouchr_expired_total 5$/m); // no labels, incremented by count

  // Histogram from injected.ms observations 3, 40, 3: le="5" catches the two 3ms, +Inf all three.
  assert.match(text, /^# TYPE vouchr_inject_duration_ms histogram$/m);
  assert.match(text, /^vouchr_inject_duration_ms_bucket\{provider="github",le="5"\} 2$/m);
  assert.match(text, /^vouchr_inject_duration_ms_bucket\{provider="github",le="\+Inf"\} 3$/m);
  assert.match(text, /^vouchr_inject_duration_ms_sum\{provider="github"\} 46$/m);
  assert.match(text, /^vouchr_inject_duration_ms_count\{provider="github"\} 3$/m);
  assert.match(text, /^vouchr_refresh_lock_wait_ms_count\{provider="github"\} 1$/m);

  // Type/help lines present (valid exposition format).
  assert.match(text, /^# TYPE vouchr_injected_total counter$/m);
});
