import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { ReplayGuard } from '../src/adapters/http/identity';
import { DbReplayStore } from '../src/adapters/http/replayStore';

// (a) Replay protection still holds regardless of prune throttling.
test('ReplayGuard: same jti is rejected on reuse, a fresh jti is accepted', () => {
  const g = new ReplayGuard();
  const now = 1_000_000;
  const exp = now + 60_000;
  assert.equal(g.use('a', exp, now), true, 'fresh jti accepted');
  assert.equal(g.use('a', exp, now), false, 'replayed jti rejected');
  assert.equal(g.use('b', exp, now), true, 'a different fresh jti still accepted');
});

// (b) An expired entry is eventually pruned once the clock passes both 60s and the exp.
test('ReplayGuard: expired jti is pruned after 60s so its id is fresh again', () => {
  const g = new ReplayGuard();
  const t0 = 1_000_000;
  assert.equal(g.use('x', t0 + 30_000, t0), true); // recorded, exp = t0+30s
  assert.equal(g.use('x', t0 + 30_000, t0 + 10_000), false, 'still in window: replay rejected');
  // Advance past 60s since the last prune AND past exp → sweep drops 'x', so the id is fresh again.
  const later = t0 + 70_000;
  assert.equal(g.use('x', later + 30_000, later), true, 'expired entry pruned, id reusable');
});

// (c) The prune is throttled: within 60s of the last prune an expired entry persists in the map.
test('ReplayGuard: prune does not run within 60s of the last prune', () => {
  const g = new ReplayGuard();
  const t0 = 1_000_000;
  assert.equal(g.use('y', t0 + 5_000, t0), true); // exp = t0+5s, this call sets lastPrune=t0
  // At t0+10s 'y' is expired, but only 10s have passed since the prune, so it is NOT swept —
  // the entry persists and a same-jti reuse is still rejected as already-seen.
  assert.equal(g.use('y', t0 + 5_000, t0 + 10_000), false, 'entry persists between prunes');
});

// Db path smoke test: end-to-end single-use over Postgres against the baseline broker_jti table.
test('DbReplayStore: single-use works end-to-end on the Postgres path', async (t) => {
  const db = await openTestDb(t);
  const store = new DbReplayStore(db);
  const exp = Date.now() + 60_000;
  assert.equal(await store.use('jti-1', exp), true, 'fresh jti accepted');
  assert.equal(await store.use('jti-1', exp), false, 'replayed jti rejected');
  assert.equal(await store.use('jti-2', exp), true, 'a different fresh jti accepted');
});
