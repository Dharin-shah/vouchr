import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refSource, UserFacingError } from '../src/adapters/bolt';

test('refSource routes each supported scheme to its source id', () => {
  assert.equal(refSource('arn:aws:secretsmanager:us-east-1:123456789012:secret:x'), 'aws-sm');
  assert.equal(refSource('gcp-sm://projects/p/secrets/s/versions/latest'), 'gcp-sm');
  assert.equal(refSource('azure-kv://my-vault/github-bot'), 'azure-kv');
  assert.equal(refSource('vault://secret/vouchr/github-bot#token'), 'vault');
});

test('refSource throws a UserFacingError on an unknown scheme', () => {
  assert.throws(() => refSource('gopher://nope'), UserFacingError);
});
