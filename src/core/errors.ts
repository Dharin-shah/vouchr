import { ApprovalPathTooLongError, ApprovalRequiredError } from './approval';
import { PolicyDeniedError, ToolDisabledError } from './authz';
import { OverloadedError } from './inflight';
import { UpstreamTimeoutError } from './httpBounds';
import {
  EgressBlockedError,
  NoConnectionError,
  ResolverConfigurationError,
  ResolverFailedError,
  ResponseBlockedError,
} from './injector';
import { RateLimitedError } from './rateLimit';
import {
  InteractionStateChangedError,
  isInteractionKind,
  isInteractionStateReason,
} from './interaction';
import {
  SECRET_REFERENCE_ERROR_CODES,
  SecretReferenceError,
  type SecretReferenceErrorCode,
} from './reference';
import {
  TOKEN_ENDPOINT_FAILURE_KINDS,
  TokenEndpointError,
  type TokenEndpointFailureKind,
} from './tokens';

/** Stable machine codes returned by {@link mapSafeError}. Reference-validation codes retain their
 * existing public values; transports and hosts must branch on these values, never error prose. */
export const VOUCHR_ERROR_CODES = Object.freeze([
  'consent_required',
  'session_approval_required',
  'approval_required',
  'approval_path_too_large',
  'interaction_state_changed',
  'policy_denied',
  'tool_disabled',
  'not_connected',
  'egress_blocked',
  'response_blocked',
  'resolver_configuration_error',
  'resolver_failed',
  'upstream_timeout',
  'rate_limited',
  'overloaded',
  'token_endpoint_failed',
  ...SECRET_REFERENCE_ERROR_CODES,
  'user_facing',
  'internal_error',
] as const);

export type VouchrErrorCode = (typeof VOUCHR_ERROR_CODES)[number];

/** Closed recovery categories for trusted hosts. These describe the next human/operator action;
 * they are not permission to retry a request. Use `retryable` independently. */
export const VOUCHR_RECOVERY_ACTIONS = Object.freeze([
  'connect',
  'request_approval',
  'resolve_again',
  'retry_later',
  'fix_configuration',
  'contact_admin',
] as const);

export type VouchrRecovery = (typeof VOUCHR_RECOVERY_ACTIONS)[number];

/** The transport-neutral, no-secret view of a thrown value. `retryAfterMs`, when present, is a
 * millisecond back-pressure hint; it never authorizes replay of an uncertain or non-idempotent call. */
export interface VouchrSafeError {
  readonly code: VouchrErrorCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly recovery: VouchrRecovery;
  readonly retryAfterMs?: number;
}

export { UpstreamTimeoutError } from './httpBounds';

const USER_FACING_ERRORS = new WeakSet<object>();

/** Thrown by `connect()` after a Connect prompt is posted: stop this turn. */
export class ConsentRequiredError extends Error {
  readonly code = 'consent_required' as const;

  constructor(public provider: string) {
    super(`Consent required for "${provider}". A Connect prompt was posted to the user.`);
    this.name = 'ConsentRequiredError';
  }
}

/** Thrown by `connect()` after a thread-scoped session prompt is posted: stop this turn. */
export class SessionApprovalRequiredError extends Error {
  readonly code = 'session_approval_required' as const;

  constructor(public provider: string) {
    super(`Session approval required for "${provider}": an approval button was posted in the thread.`);
    this.name = 'SessionApprovalRequiredError';
  }
}

/** Marker for deliberate, Vouchr-authored validation/refusal copy. Foreign `Error.message` values
 * never enter this class implicitly; a throw site must explicitly opt in to the text. */
export class UserFacingError extends Error {
  readonly code = 'user_facing' as const;

  constructor(
    message: string,
    public readonly recovery: VouchrRecovery = 'fix_configuration',
  ) {
    super(message);
    this.name = 'UserFacingError';
    USER_FACING_ERRORS.add(this);
  }
}

const INTERNAL_ERROR: VouchrSafeError = Object.freeze({
  code: 'internal_error',
  message: 'Something went wrong. Ask an admin to check the Vouchr logs.',
  retryable: false,
  recovery: 'contact_admin',
});

function safeRetryAfterMs(value: number): number | undefined {
  return Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

function isRecovery(value: unknown): value is VouchrRecovery {
  return typeof value === 'string'
    && (VOUCHR_RECOVERY_ACTIONS as readonly string[]).includes(value);
}

function isTokenEndpointFailureKind(value: unknown): value is TokenEndpointFailureKind {
  return typeof value === 'string'
    && (TOKEN_ENDPOINT_FAILURE_KINDS as readonly string[]).includes(value);
}

function retryLater(code: VouchrErrorCode, message: string, retryAfterMs?: number): VouchrSafeError {
  const safeDelay = retryAfterMs === undefined ? undefined : safeRetryAfterMs(retryAfterMs);
  return {
    code,
    message,
    retryable: true,
    recovery: 'retry_later',
    ...(safeDelay === undefined ? {} : { retryAfterMs: safeDelay }),
  };
}

function retryMessage(prefix: string, retryAfterMs: number | undefined): string {
  const safeDelay = retryAfterMs === undefined ? undefined : safeRetryAfterMs(retryAfterMs);
  return safeDelay === undefined
    ? `${prefix} Retry later.`
    : `${prefix} Try again in ${Math.ceil(safeDelay / 1_000)}s.`;
}

/**
 * Convert any thrown value into the single transport-neutral recovery contract.
 *
 * Only Vouchr-owned typed errors may contribute their message. Unknown errors, non-Error throws,
 * custom providers, resolvers, KMS clients, database drivers, and hostile objects all collapse to
 * fixed copy without reading a foreign `message`, `name`, or `constructor` property.
 */
export function mapSafeError(error: unknown): VouchrSafeError {
  try {
    if (error instanceof ConsentRequiredError) {
      return {
        code: 'consent_required',
        message: 'Consent is required. Complete the private Connect prompt, then retry.',
        retryable: false,
        recovery: 'connect',
      };
    }
    if (error instanceof SessionApprovalRequiredError) {
      return {
        code: 'session_approval_required',
        message: 'Thread-scoped session approval is required. Approve the private prompt, then retry.',
        retryable: false,
        recovery: 'request_approval',
      };
    }
    if (error instanceof ApprovalRequiredError) {
      return {
        code: 'approval_required',
        message: 'Human approval is required. Request approval, then retry.',
        retryable: false,
        recovery: 'request_approval',
      };
    }
    if (error instanceof ApprovalPathTooLongError) {
      return {
        code: 'approval_path_too_large',
        message: 'The approval action path is too large. Narrow the endpoint and retry.',
        retryable: false,
        recovery: 'fix_configuration',
      };
    }
    if (error instanceof InteractionStateChangedError) {
      if (!isInteractionKind(error.interaction) || !isInteractionStateReason(error.reason)) {
        return INTERNAL_ERROR;
      }
      return {
        code: 'interaction_state_changed',
        message: error.reason === 'credential'
          ? 'The connection changed while Vouchr was handling this request. Resolve it again and retry.'
          : 'Access changed while Vouchr was handling this request. Resolve current access and retry.',
        retryable: false,
        recovery: 'resolve_again',
      };
    }
    if (error instanceof PolicyDeniedError) {
      return {
        code: 'policy_denied',
        message: 'Provider policy denies this request. Contact an eligible admin.',
        retryable: false,
        recovery: 'contact_admin',
      };
    }
    if (error instanceof ToolDisabledError) {
      return {
        code: 'tool_disabled',
        message: 'This provider is disabled in the channel. Contact an eligible admin.',
        retryable: false,
        recovery: 'contact_admin',
      };
    }
    if (error instanceof NoConnectionError) {
      const channelOwned = error.owner === 'channel';
      return {
        code: 'not_connected',
        message: channelOwned
          ? 'No shared channel credential is configured. Ask an eligible admin to configure it.'
          : 'No credential is connected. Connect the provider, then retry.',
        retryable: false,
        recovery: channelOwned ? 'fix_configuration' : 'connect',
      };
    }
    if (error instanceof EgressBlockedError) {
      return {
        code: 'egress_blocked',
        message: 'The request was blocked by Vouchr egress policy. Check the provider configuration.',
        retryable: false,
        recovery: 'fix_configuration',
      };
    }
    if (error instanceof ResponseBlockedError) {
      return {
        code: 'response_blocked',
        message: 'The provider response was blocked by Vouchr response policy. Check the provider configuration.',
        retryable: false,
        recovery: 'fix_configuration',
      };
    }
    if (error instanceof ResolverConfigurationError) {
      return {
        code: 'resolver_configuration_error',
        message: 'External credential resolution is not configured correctly. Ask an admin to check the resolver and stored reference.',
        retryable: false,
        recovery: 'fix_configuration',
      };
    }
    if (error instanceof ResolverFailedError) {
      return retryLater(
        'resolver_failed',
        'The external credential resolver is temporarily unavailable. Retry later.',
      );
    }
    if (error instanceof UpstreamTimeoutError) {
      return {
        code: 'upstream_timeout',
        message: 'The upstream request timed out. Its outcome may be unknown; do not retry automatically.',
        retryable: false,
        recovery: 'retry_later',
      };
    }
    if (error instanceof RateLimitedError) {
      return retryLater(
        'rate_limited',
        retryMessage('The request rate limit was reached.', error.retryAfterMs),
        error.retryAfterMs,
      );
    }
    if (error instanceof OverloadedError) {
      return retryLater(
        'overloaded',
        retryMessage('Vouchr is busy.', error.retryAfterMs),
        error.retryAfterMs,
      );
    }
    if (error instanceof TokenEndpointError) {
      if (!isTokenEndpointFailureKind(error.kind)) return INTERNAL_ERROR;
      if (error.kind === 'credential') {
        return {
          code: 'token_endpoint_failed',
          message: 'The provider rejected this credential. Reconnect it, then retry.',
          retryable: false,
          recovery: 'connect',
        };
      }
      if (error.kind === 'configuration') {
        return {
          code: 'token_endpoint_failed',
          message: 'The provider rejected the OAuth client configuration. Ask an admin to check it.',
          retryable: false,
          recovery: 'fix_configuration',
        };
      }
      return retryLater(
          'token_endpoint_failed',
          'The provider authentication endpoint is temporarily unavailable. Retry later.',
      );
    }
    if (error instanceof SecretReferenceError) {
      // Keep the existing SecretReferenceErrorCode values as the machine contract; do not wrap or
      // collapse them into a new umbrella code.
      const code: SecretReferenceErrorCode = error.code;
      if (!(SECRET_REFERENCE_ERROR_CODES as readonly unknown[]).includes(code)) return INTERNAL_ERROR;
      return {
        code,
        message: new SecretReferenceError(code).message,
        retryable: false,
        recovery: 'fix_configuration',
      };
    }
    if (error instanceof UserFacingError && USER_FACING_ERRORS.has(error)) {
      if (typeof error.message !== 'string' || !isRecovery(error.recovery)) return INTERNAL_ERROR;
      return { code: 'user_facing', message: error.message, retryable: false, recovery: error.recovery };
    }
  } catch {
    // `unknown` can be a Proxy whose prototype lookup throws. Mapping must itself be fail-safe and
    // must not inspect a hostile object's properties while trying to render a failure.
  }
  return INTERNAL_ERROR;
}

/** Back-compatible text helper used by the Bolt adapter. All policy lives in mapSafeError. */
export function safeUserMessage(error: unknown): string {
  return mapSafeError(error).message;
}
