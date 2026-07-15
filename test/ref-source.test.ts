import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_SECRET_REFERENCE_BYTES,
  MAX_SECRET_REFERENCE_SCOPE_BYTES,
  normalizeSecretReference,
  SecretReferenceError,
  secretReferenceSource,
} from '../src/core/reference';

const AWS_REF = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/github';
const GCP_REF = 'gcp-sm://projects/p/secrets/s/versions/latest';
const AZURE_REF = 'azure-kv://my-vault/github-bot';
const VAULT_REF = 'vault://secret/vouchr/github-bot#token';

const resolvers = {
  'aws-sm': async () => 'aws',
  'gcp-sm': async () => 'gcp',
  'azure-kv': async () => 'azure',
  vault: async () => 'vault',
};

test('normalizeSecretReference derives one configured source without invoking its resolver', () => {
  let calls = 0;
  const configured = Object.fromEntries(
    Object.keys(resolvers).map((source) => [source, async () => { calls++; return 'secret'; }]),
  );
  for (const [secretRef, source] of [
    [AWS_REF, 'aws-sm'],
    [GCP_REF, 'gcp-sm'],
    [AZURE_REF, 'azure-kv'],
    [VAULT_REF, 'vault'],
  ] as const) {
    assert.deepEqual(normalizeSecretReference({ secretRef }, configured, []), { source, secretRef });
  }
  assert.equal(calls, 0, 'configuration checks presence only; secret resolution remains JIT');
});

test('normalizeSecretReference accepts a matching legacy source and canonical bounded scopes', () => {
  assert.deepEqual(
    normalizeSecretReference(
      { secretRef: AWS_REF, source: 'aws-sm', scopes: 'repo read:user' },
      resolvers,
      ['repo', 'read:user'],
    ),
    { source: 'aws-sm', secretRef: AWS_REF, scopes: 'repo read:user' },
  );

  const prefix = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:';
  const maxRef = prefix + 'x'.repeat(MAX_SECRET_REFERENCE_BYTES - prefix.length);
  const maxScope = 's'.repeat(MAX_SECRET_REFERENCE_SCOPE_BYTES);
  assert.equal(secretReferenceSource(maxRef), 'aws-sm');
  assert.equal(
    normalizeSecretReference({ secretRef: AWS_REF, scopes: maxScope }, resolvers, [maxScope]).scopes?.length,
    MAX_SECRET_REFERENCE_SCOPE_BYTES,
  );
});

test('normalizeSecretReference rejects unsupported, malformed, raw, and oversized values safely', () => {
  const sentinel = 'sk_live_CALLER_SECRET_SENTINEL';
  const prefix = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:';
  const cases: unknown[] = [
    undefined,
    '',
    '   ',
    ` ${AWS_REF}`,
    `${AWS_REF}\n`,
    sentinel,
    'gopher://nope',
    'arn:aws:secretsmanager:missing-fields',
    'gcp-sm://projects/p/secrets/s',
    'gcp-sm://projects/../secrets/s/versions/latest',
    'azure-kv://evil.example#/secret',
    'vault://secret/../admin#token',
    prefix + 'x'.repeat(MAX_SECRET_REFERENCE_BYTES - prefix.length + 1),
  ];

  for (const secretRef of cases) {
    assert.throws(
      () => normalizeSecretReference({ secretRef }, resolvers, []),
      (error: unknown) => {
        assert.ok(error instanceof SecretReferenceError);
        assert.equal(error.code, 'invalid_reference');
        assert.ok(!error.message.includes(sentinel));
        return true;
      },
    );
  }
});

test('normalizeSecretReference rejects source authority, invalid scopes, and missing resolvers', () => {
  assert.throws(
    () => normalizeSecretReference({ secretRef: AWS_REF, source: 'gcp-sm' }, resolvers, []),
    (error: unknown) => error instanceof SecretReferenceError && error.code === 'source_mismatch',
  );

  for (const scopes of [
    '',
    ' repo',
    'repo ',
    'repo  user',
    'repo\nuser',
    'repo repo',
    'ghp_plaintext_token_1234567890',
    's'.repeat(MAX_SECRET_REFERENCE_SCOPE_BYTES + 1),
  ]) {
    assert.throws(
      () => normalizeSecretReference({ secretRef: AWS_REF, scopes }, resolvers, ['repo', 'user']),
      (error: unknown) => error instanceof SecretReferenceError && error.code === 'invalid_scopes',
    );
  }

  assert.throws(
    () => normalizeSecretReference({ secretRef: AWS_REF }, {}, []),
    (error: unknown) => error instanceof SecretReferenceError && error.code === 'resolver_unavailable',
  );
  const inherited = Object.create({ 'aws-sm': async () => 'secret' });
  assert.throws(
    () => normalizeSecretReference({ secretRef: AWS_REF }, inherited, []),
    (error: unknown) => error instanceof SecretReferenceError && error.code === 'resolver_unavailable',
  );
  assert.throws(
    () => normalizeSecretReference({ secretRef: AWS_REF }, { 'aws-sm': 'not-a-function' }, []),
    (error: unknown) => error instanceof SecretReferenceError && error.code === 'resolver_unavailable',
  );
});
