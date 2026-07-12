import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pgReachable } from './support/pg';

test('test contract: the full suite requires its real PostgreSQL backend', async () => {
  assert.equal(
    process.env.VOUCHR_REQUIRE_POSTGRES,
    '1',
    'the full test command must enable fail-closed PostgreSQL mode',
  );
  assert.equal(
    await pgReachable(),
    true,
    'PostgreSQL is required for npm test but is unreachable; run npm run pg:up or set VOUCHR_TEST_PG_URL',
  );
});
