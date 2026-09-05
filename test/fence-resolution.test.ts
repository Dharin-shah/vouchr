import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tombstoneBlocks } from '../src/core/consent';
import { POSTGRES_NOW_US_SQL } from '../src/core/interaction';
import { openTestDb } from './support/pg';

// #290 — lifecycle fences at microsecond resolution. Two invariants pinned here:
//  1. tombstoneBlocks keeps its fail-closed direction (`>=`): a genuine tie still blocks, and ONLY
//     a strictly-older tombstone lets a later issuance proceed (the previously uncovered direction).
//  2. The one shared fence clock is microseconds, not milliseconds, so unrelated sequential
//     operations no longer tie inside a coarser truncation window.

test('tombstoneBlocks: a tie still blocks (fail closed); an older tombstone does not', () => {
  const at = 1_785_600_000_000_000; // a plausible µs-epoch instant; the rule itself is unit-agnostic
  assert.equal(tombstoneBlocks(at, at), true, 'equality must fail closed — a tie blocks');
  assert.equal(tombstoneBlocks(at + 1, at), true, 'a later tombstone blocks');
  assert.equal(tombstoneBlocks(at - 1, at), false, 'a 1µs-older tombstone must NOT block');
  assert.equal(tombstoneBlocks(null, at), false, 'no tombstone never blocks');
  assert.equal(tombstoneBlocks(undefined, at), false, 'no tombstone never blocks');
});

test('the PostgreSQL fence clock ticks in microseconds and sequential reads never tie', async (t) => {
  const db = await openTestDb(t);
  const now = (await db.get<{ n: number }>(`SELECT ${POSTGRES_NOW_US_SQL} AS n`))!.n;
  // Magnitude pins the unit: a 21st-century epoch in MICROseconds is ~1.8e15; in milliseconds it
  // would be ~1.8e12. Still comfortably below 2^53, so JS numbers stay exact.
  assert.ok(Number.isSafeInteger(now), 'fence clock must stay a safe integer');
  assert.ok(now > 1.5e15, `fence clock must be a µs epoch (ms would be ~1.8e12), got ${now}`);
  // Two sequential round trips routinely tie at millisecond resolution — the #290 flake family.
  // At microsecond resolution the round-trip latency alone keeps observations strictly increasing.
  const later = (await db.get<{ n: number }>(`SELECT ${POSTGRES_NOW_US_SQL} AS n`))!.n;
  assert.ok(later > now, 'sequential fence reads must strictly increase at µs resolution');
});
