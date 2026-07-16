import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ApprovalPathTooLongError,
  ApprovalRequiredError,
  ConsentRequiredError,
  EgressBlockedError,
  InteractionStateChangedError,
  NoConnectionError,
  PolicyDeniedError,
  RateLimitedError,
  ResolverConfigurationError,
  ResolverFailedError,
  ResponseBlockedError,
  SecretReferenceError,
  SessionApprovalRequiredError,
  TokenEndpointError,
  TOKEN_ENDPOINT_FAILURE_KINDS,
  UpstreamTimeoutError,
  ToolDisabledError,
  UserFacingError,
  VOUCHR_ERROR_CODES,
  VOUCHR_RECOVERY_ACTIONS,
  mapSafeError,
  safeUserMessage,
} from '../src/index';
import {
  ApprovalPathTooLongError as HeadlessApprovalPathTooLongError,
  ApprovalRequiredError as HeadlessApprovalRequiredError,
  ConsentRequiredError as HeadlessConsentRequiredError,
  EgressBlockedError as HeadlessEgressBlockedError,
  InteractionStateChangedError as HeadlessInteractionStateChangedError,
  NoConnectionError as HeadlessNoConnectionError,
  PolicyDeniedError as HeadlessPolicyDeniedError,
  RateLimitedError as HeadlessRateLimitedError,
  ResolverConfigurationError as HeadlessResolverConfigurationError,
  ResolverFailedError as HeadlessResolverFailedError,
  ResponseBlockedError as HeadlessResponseBlockedError,
  SecretReferenceError as HeadlessSecretReferenceError,
  SessionApprovalRequiredError as HeadlessSessionApprovalRequiredError,
  TokenEndpointError as HeadlessTokenEndpointError,
  TOKEN_ENDPOINT_FAILURE_KINDS as HEADLESS_TOKEN_ENDPOINT_FAILURE_KINDS,
  UpstreamTimeoutError as HeadlessUpstreamTimeoutError,
  ToolDisabledError as HeadlessToolDisabledError,
  UserFacingError as HeadlessUserFacingError,
  VOUCHR_ERROR_CODES as HEADLESS_ERROR_CODES,
  VOUCHR_RECOVERY_ACTIONS as HEADLESS_RECOVERY_ACTIONS,
  mapSafeError as headlessMapSafeError,
  safeUserMessage as headlessSafeUserMessage,
} from '../src/headless';
import { OverloadedError } from '../src/core/inflight';

test('typed error classes and mapper are the same exports on root and Bolt-free headless entrypoints', () => {
  const pairs = [
    [ApprovalPathTooLongError, HeadlessApprovalPathTooLongError, 'ApprovalPathTooLongError'],
    [ApprovalRequiredError, HeadlessApprovalRequiredError, 'ApprovalRequiredError'],
    [ConsentRequiredError, HeadlessConsentRequiredError, 'ConsentRequiredError'],
    [EgressBlockedError, HeadlessEgressBlockedError, 'EgressBlockedError'],
    [InteractionStateChangedError, HeadlessInteractionStateChangedError, 'InteractionStateChangedError'],
    [NoConnectionError, HeadlessNoConnectionError, 'NoConnectionError'],
    [PolicyDeniedError, HeadlessPolicyDeniedError, 'PolicyDeniedError'],
    [RateLimitedError, HeadlessRateLimitedError, 'RateLimitedError'],
    [ResolverConfigurationError, HeadlessResolverConfigurationError, 'ResolverConfigurationError'],
    [ResolverFailedError, HeadlessResolverFailedError, 'ResolverFailedError'],
    [ResponseBlockedError, HeadlessResponseBlockedError, 'ResponseBlockedError'],
    [SecretReferenceError, HeadlessSecretReferenceError, 'SecretReferenceError'],
    [SessionApprovalRequiredError, HeadlessSessionApprovalRequiredError, 'SessionApprovalRequiredError'],
    [TokenEndpointError, HeadlessTokenEndpointError, 'TokenEndpointError'],
    [UpstreamTimeoutError, HeadlessUpstreamTimeoutError, 'UpstreamTimeoutError'],
    [ToolDisabledError, HeadlessToolDisabledError, 'ToolDisabledError'],
    [UserFacingError, HeadlessUserFacingError, 'UserFacingError'],
    [mapSafeError, headlessMapSafeError, 'mapSafeError'],
    [safeUserMessage, headlessSafeUserMessage, 'safeUserMessage'],
  ] as const;
  for (const [rootExport, headlessExport, name] of pairs) {
    assert.equal(rootExport, headlessExport, `${name} export drifted`);
  }
  assert.deepEqual(VOUCHR_ERROR_CODES, HEADLESS_ERROR_CODES);
  assert.deepEqual(VOUCHR_RECOVERY_ACTIONS, HEADLESS_RECOVERY_ACTIONS);
  assert.deepEqual(TOKEN_ENDPOINT_FAILURE_KINDS, HEADLESS_TOKEN_ENDPOINT_FAILURE_KINDS);
});

test('mapSafeError returns one exact stable code/recovery/retry contract for typed outcomes', () => {
  const approval = new ApprovalRequiredError(
    'github',
    'self',
    'POST',
    'api.github.com',
    `hmac-sha256:${'a'.repeat(64)}`,
    '00000000-0000-4000-8000-000000000001',
    0,
    true,
  );
  const cases = [
    [new ConsentRequiredError('github'), 'consent_required', 'connect', false, undefined,
      'Consent is required. Complete the private Connect prompt, then retry.'],
    [new SessionApprovalRequiredError('github'), 'session_approval_required', 'request_approval', false, undefined,
      'Thread-scoped session approval is required. Approve the private prompt, then retry.'],
    [approval, 'approval_required', 'request_approval', false, undefined,
      'Human approval is required. Request approval, then retry.'],
    [new ApprovalPathTooLongError(), 'approval_path_too_large', 'fix_configuration', false, undefined,
      'The approval action path is too large. Narrow the endpoint and retry.'],
    [new InteractionStateChangedError('connection', 'credential'), 'interaction_state_changed', 'resolve_again', false, undefined,
      'The connection changed while Vouchr was handling this request. Resolve it again and retry.'],
    [new InteractionStateChangedError('approval', 'authorization'), 'interaction_state_changed', 'resolve_again', false, undefined,
      'Access changed while Vouchr was handling this request. Resolve current access and retry.'],
    [new PolicyDeniedError(), 'policy_denied', 'contact_admin', false, undefined,
      'Provider policy denies this request. Contact an eligible admin.'],
    [new ToolDisabledError(), 'tool_disabled', 'contact_admin', false, undefined,
      'This provider is disabled in the channel. Contact an eligible admin.'],
    [new NoConnectionError('No connection for provider "github"', 'user'), 'not_connected', 'connect', false, undefined,
      'No credential is connected. Connect the provider, then retry.'],
    [new NoConnectionError('No channel credential for provider "github"', 'channel'), 'not_connected', 'fix_configuration', false, undefined,
      'No shared channel credential is configured. Ask an eligible admin to configure it.'],
    [new EgressBlockedError('Egress blocked: host not allowed'), 'egress_blocked', 'fix_configuration', false, undefined,
      'The request was blocked by Vouchr egress policy. Check the provider configuration.'],
    [new ResponseBlockedError('Response blocked: content-type is not allowed', 'content_type'), 'response_blocked', 'fix_configuration', false, undefined,
      'The provider response was blocked by Vouchr response policy. Check the provider configuration.'],
    [new ResolverConfigurationError(), 'resolver_configuration_error', 'fix_configuration', false, undefined,
      'External credential resolution is not configured correctly. Ask an admin to check the resolver and stored reference.'],
    [new ResolverFailedError(), 'resolver_failed', 'retry_later', true, undefined,
      'The external credential resolver is temporarily unavailable. Retry later.'],
    [new UpstreamTimeoutError(), 'upstream_timeout', 'retry_later', false, undefined,
      'The upstream request timed out. Its outcome may be unknown; do not retry automatically.'],
    [new RateLimitedError('github', 60, 1_250), 'rate_limited', 'retry_later', true, 1_250,
      'The request rate limit was reached. Try again in 2s.'],
    [new OverloadedError('provider', 1_000), 'overloaded', 'retry_later', true, 1_000,
      'Vouchr is busy. Try again in 1s.'],
    [new TokenEndpointError('Token endpoint returned HTTP 401', 'credential'), 'token_endpoint_failed', 'connect', false, undefined,
      'The provider rejected this credential. Reconnect it, then retry.'],
    [new TokenEndpointError('Token endpoint returned HTTP 400', 'configuration'), 'token_endpoint_failed', 'fix_configuration', false, undefined,
      'The provider rejected the OAuth client configuration. Ask an admin to check it.'],
    [new TokenEndpointError('Token endpoint returned HTTP 503', 'transient'), 'token_endpoint_failed', 'retry_later', true, undefined,
      'The provider authentication endpoint is temporarily unavailable. Retry later.'],
    [new UserFacingError('Configuration is locked.'), 'user_facing', 'fix_configuration', false, undefined,
      'Configuration is locked.'],
  ] as const;

  for (const [error, code, recovery, retryable, retryAfterMs, message] of cases) {
    const safe = mapSafeError(error);
    assert.equal(safe.code, code);
    assert.equal(safe.message, message);
    assert.equal(safe.recovery, recovery);
    assert.equal(safe.retryable, retryable);
    assert.equal(safe.retryAfterMs, retryAfterMs);
    assert.equal(safeUserMessage(error), safe.message, 'text helper must delegate to the core mapper');
  }
});

test('mapSafeError does not trust arbitrary messages merely because they use an exported error class', () => {
  const secret = 'ghp_known_class_spoof_must_not_render';
  const errors = [
    new ConsentRequiredError(secret),
    new SessionApprovalRequiredError(secret),
    new ApprovalRequiredError(
      secret, 'self', secret, secret, secret,
      '00000000-0000-4000-8000-000000000001', 0, true,
    ),
    new EgressBlockedError(secret),
    new NoConnectionError(secret, 'user'),
    new ResolverConfigurationError(),
    new ResolverFailedError(),
    new ResponseBlockedError(secret, 'content_type'),
    new RateLimitedError(secret, 1, 1_000),
    new TokenEndpointError(secret, false),
  ];
  for (const error of errors) {
    assert.ok(!JSON.stringify(mapSafeError(error)).includes(secret), error.constructor.name);
  }

  // UserFacingError is the deliberate opt-in marker: constructing it explicitly authorizes that
  // Vouchr-authored text for rendering. It is never inferred from a foreign Error.
  assert.equal(mapSafeError(new UserFacingError('Safe fixed refusal.')).message, 'Safe fixed refusal.');
});

test('mapSafeError preserves every SecretReferenceError code and never collapses resolver_failed into it', () => {
  for (const code of ['invalid_reference', 'source_mismatch', 'invalid_scopes', 'resolver_unavailable'] as const) {
    assert.deepEqual(mapSafeError(new SecretReferenceError(code)), {
      code,
      message: new SecretReferenceError(code).message,
      retryable: false,
      recovery: 'fix_configuration',
    });
  }
  assert.equal(mapSafeError(new ResolverFailedError()).code, 'resolver_failed');
  assert.equal(mapSafeError(new ResolverConfigurationError()).code, 'resolver_configuration_error');
});

test('runtime-invalid trusted-class discriminants collapse to fixed internal metadata', () => {
  const sentinel = 'ghp_invalid_recovery_or_kind_must_not_escape';
  const expected = {
    code: 'internal_error',
    message: 'Something went wrong. Ask an admin to check the Vouchr logs.',
    retryable: false,
    recovery: 'contact_admin',
  };
  const invalidRecovery = new UserFacingError('deliberate safe copy', sentinel as any);
  const invalidTokenKind = new TokenEndpointError(sentinel, sentinel as any);
  const invalidInteraction = new InteractionStateChangedError('connection', 'credential');
  (invalidInteraction as any).reason = sentinel;
  for (const error of [invalidRecovery, invalidTokenKind, invalidInteraction]) {
    const mapped = mapSafeError(error);
    assert.deepEqual(mapped, expected);
    assert.ok(!JSON.stringify(mapped).includes(sentinel));
  }
});

test('mapSafeError masks foreign messages, names, non-Errors, and hostile objects with fixed copy', () => {
  const secret = 'ghp_should_never_be_rendered';
  class ForeignProviderError extends Error {}
  const hostile = new Proxy({}, {
    getPrototypeOf() {
      throw new Error(secret);
    },
    get() {
      throw new Error(secret);
    },
  });
  const expected = {
    code: 'internal_error',
    message: 'Something went wrong. Ask an admin to check the Vouchr logs.',
    retryable: false,
    recovery: 'contact_admin',
  };

  for (const error of [new Error(secret), new ForeignProviderError(secret), secret, hostile]) {
    const mapped = mapSafeError(error);
    assert.deepEqual(mapped, expected);
    assert.ok(!JSON.stringify(mapped).includes(secret));
    assert.ok(!mapped.message.includes('ForeignProviderError'));
  }
});

test('published code and recovery registries are closed, duplicate-free contracts', () => {
  assert.equal(new Set(VOUCHR_ERROR_CODES).size, VOUCHR_ERROR_CODES.length);
  assert.equal(new Set(VOUCHR_RECOVERY_ACTIONS).size, VOUCHR_RECOVERY_ACTIONS.length);
  assert.equal(new Set(TOKEN_ENDPOINT_FAILURE_KINDS).size, TOKEN_ENDPOINT_FAILURE_KINDS.length);
  assert.deepEqual(VOUCHR_RECOVERY_ACTIONS, [
    'connect',
    'request_approval',
    'resolve_again',
    'retry_later',
    'fix_configuration',
    'contact_admin',
  ]);
  assert.deepEqual(TOKEN_ENDPOINT_FAILURE_KINDS, ['credential', 'configuration', 'transient']);
});
