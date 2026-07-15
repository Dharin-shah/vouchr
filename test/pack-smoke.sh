#!/usr/bin/env bash
# Packaging smoke test (#123): pack the real tarball, install it into a fresh throwaway
# project, and prove every published entrypoint / bin / type actually resolves — the way the
# pilot integrator's first `npm install` will. Catches a broken `files` glob, an `exports`
# typo, a bad bin shebang, or a type regression that `tsc` on src/ never sees.
#
# Runnable locally (`npm run pack-smoke`) and in CI. Needs network for the consumer install.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> npm pack (runs prepack → build)"
# npm pack prints noise to stdout; capture only the tarball filename it reports last.
( cd "$ROOT" && npm pack --pack-destination "$WORK" >/dev/null )
TGZ="$(ls "$WORK"/vouchr-core-*.tgz)"
[ -f "$TGZ" ] || { echo "FAIL: no tarball produced"; exit 1; }
echo "    packed: $(basename "$TGZ")"
tar -tzf "$TGZ" | grep -x 'package/vision.md' >/dev/null \
  || { echo "FAIL: README's canonical vision.md target is missing from the package"; exit 1; }

echo "==> install into a fresh consumer project"
CONSUMER="$WORK/consumer"
mkdir -p "$CONSUMER"
( cd "$CONSUMER" && npm init -y >/dev/null && npm install "$TGZ" >/dev/null )

echo "==> require() every published entrypoint (CJS exports map)"
( cd "$CONSUMER" && node -e "
  const root = require('@vouchr/core');
  const headless = require('@vouchr/core/headless');
  require('@vouchr/core/broker-server');
  for (const surface of [root, headless]) {
    for (const name of ['loadIdentityConfig', 'mintIdentity', 'verifyIdentity',
      'ConsentRequiredError', 'SessionApprovalRequiredError', 'ApprovalRequiredError',
      'EgressBlockedError', 'NoConnectionError', 'PolicyDeniedError', 'ToolDisabledError',
      'ResolverConfigurationError', 'ResolverFailedError',
      'ResponseBlockedError', 'RateLimitedError', 'SecretReferenceError', 'TokenEndpointError',
      'UpstreamTimeoutError', 'UserFacingError',
      'mapSafeError', 'safeUserMessage']) {
      if (typeof surface[name] !== 'function') throw new Error('missing packed export: ' + name);
    }
    if (!Array.isArray(surface.VOUCHR_ERROR_CODES) || !Array.isArray(surface.VOUCHR_RECOVERY_ACTIONS)
      || !Array.isArray(surface.TOKEN_ENDPOINT_FAILURE_KINDS)) {
      throw new Error('missing packed typed-error registries');
    }
    const errors = [
      new surface.ConsentRequiredError('github'),
      new surface.SessionApprovalRequiredError('github'),
      new surface.ApprovalRequiredError('github', 'self', 'POST', 'api.github.com', '/repos/a/b', 'approval-1'),
      new surface.EgressBlockedError('Egress blocked: host not allowed'),
      new surface.NoConnectionError('No connection for provider "github"', 'user'),
      new surface.PolicyDeniedError(),
      new surface.ToolDisabledError(),
      new surface.ResolverConfigurationError(),
      new surface.ResolverFailedError(),
      new surface.ResponseBlockedError('Response blocked: content-type is not allowed', 'content_type'),
      new surface.RateLimitedError('github', 60, 1000),
      new surface.SecretReferenceError('invalid_reference'),
      new surface.TokenEndpointError('Token endpoint returned HTTP 503', 'transient'),
      new surface.UpstreamTimeoutError(),
      new surface.UserFacingError('Configuration is locked.'),
    ];
    for (const error of errors) {
      if (!(error instanceof surface[error.constructor.name])) {
        throw new Error('packed error lost instanceof identity: ' + error.constructor.name);
      }
      const mapped = surface.mapSafeError(error);
      if (!mapped.code || typeof mapped.retryable !== 'boolean' || !mapped.recovery || typeof mapped.message !== 'string') {
        throw new Error('packed safe mapper returned an incomplete typed result');
      }
    }
    const sentinel = 'ghp_packed_consumer_secret';
    const unknown = surface.mapSafeError(new Error(sentinel));
    if (unknown.code !== 'internal_error' || unknown.recovery !== 'contact_admin' || unknown.retryable
      || JSON.stringify(unknown).includes(sentinel)) {
      throw new Error('packed safe mapper leaked or misclassified a foreign error');
    }
    if (JSON.stringify(surface.mapSafeError(new surface.EgressBlockedError(sentinel))).includes(sentinel)) {
      throw new Error('packed safe mapper trusted a typed constructor message');
    }
    const invalidRecovery = surface.mapSafeError(new surface.UserFacingError('safe fixed copy', sentinel));
    if (invalidRecovery.code !== 'internal_error' || JSON.stringify(invalidRecovery).includes(sentinel)) {
      throw new Error('packed safe mapper accepted an invalid runtime recovery value');
    }
    if ('OverloadedError' in surface) throw new Error('internal overload error leaked into public API');
    for (const name of ['PendingPreviews', 'PREVIEW_VISIBILITIES', 'isPreviewVisibility',
      'previewBlocks', 'previewPostBlocks', 'normalizePreviewContent',
      'PREVIEW_SHARE_ACTION', 'PREVIEW_DISMISS_ACTION']) {
      if (name in surface) throw new Error('removed private-preview export leaked into package: ' + name);
    }
  }
  const identity = headless.loadIdentityConfig({
    VOUCHR_IDENTITY_SECRET: 'packed-consumer-identity-secret-32-bytes!!',
    VOUCHR_DEPLOYMENT_ID: 'packed-consumer',
  });
  const token = headless.mintIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1' }, identity);
  const claims = headless.verifyIdentity(token, identity);
  if (claims.aud !== 'packed-consumer' || !claims.kid) throw new Error('packed bound identity round-trip failed');
  console.log('    all three entrypoints require() cleanly');
" )

echo "==> every bin resolves and prints on --help"
for bin in vouchr vouchr-broker; do
  out="$( cd "$CONSUMER" && npx --no-install "$bin" --help 2>&1 )" || {
    echo "FAIL: $bin --help exited non-zero"; echo "$out"; exit 1;
  }
  [ -n "$out" ] || { echo "FAIL: $bin --help printed nothing"; exit 1; }
  echo "    $bin --help ok"
done

echo "==> a minimal typed consumer compiles against the published types"
cat > "$CONSUMER/consumer.ts" <<'TS'
import { createVouchr, type ConnectContext } from '@vouchr/core';
import {
  createBroker, loadIdentityConfig, mintIdentity, verifyIdentity,
  ConsentRequiredError, SessionApprovalRequiredError, ApprovalRequiredError,
  EgressBlockedError, NoConnectionError, PolicyDeniedError, ToolDisabledError,
  ResolverConfigurationError, ResolverFailedError,
  ResponseBlockedError, RateLimitedError, SecretReferenceError, TokenEndpointError,
  UpstreamTimeoutError, UserFacingError,
  mapSafeError, safeUserMessage, TOKEN_ENDPOINT_FAILURE_KINDS, VOUCHR_ERROR_CODES, VOUCHR_RECOVERY_ACTIONS,
  type BrokerError, type BrokerFetchResponse, type BrokerOptions, type IdentityConfig,
  type SecretReferenceErrorCode, type TokenEndpointFailureKind, type VouchrErrorCode,
  type VouchrRecovery, type VouchrSafeError,
} from '@vouchr/core/headless';

const identity: IdentityConfig = loadIdentityConfig({
  VOUCHR_IDENTITY_SECRET: 'packed-consumer-identity-secret-32-bytes!!',
  VOUCHR_DEPLOYMENT_ID: 'packed-consumer',
});
const identityToken = mintIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1' }, identity);
void verifyIdentity(identityToken, identity);
type HasReplayOverride = 'replayStore' extends keyof BrokerOptions ? true : false;
type HasSkewKnob = 'skewMs' extends keyof IdentityConfig ? true : false;
const noReplayOverride: false = null as unknown as HasReplayOverride;
const noSkewKnob: false = null as unknown as HasSkewKnob;
type HasPreview = 'preview' extends keyof ConnectContext ? true : false;
type HasPreviewConfig = 'setChannelVisibility' extends keyof ConnectContext ? true : false;
const noPreview: false = null as unknown as HasPreview;
const noPreviewConfig: false = null as unknown as HasPreviewConfig;
void noReplayOverride;
void noSkewKnob;
void noPreview;
void noPreviewConfig;
const overload: BrokerError = { error: 'overloaded', scope: 'provider', retryAfterMs: 1000 };
void overload;
const referenceCode: SecretReferenceErrorCode = new SecretReferenceError('invalid_reference').code;
const referenceFailure: BrokerError = { error: 'invalid reference', code: referenceCode };
void referenceFailure;
const documentedErrors = [
  new ConsentRequiredError('github'),
  new SessionApprovalRequiredError('github'),
  new ApprovalRequiredError('github', 'self', 'POST', 'api.github.com', '/repos/a/b', 'approval-1'),
  new EgressBlockedError('Egress blocked: host not allowed'),
  new NoConnectionError('No connection for provider "github"', 'user'),
  new PolicyDeniedError(),
  new ToolDisabledError(),
  new ResolverConfigurationError(),
  new ResolverFailedError(),
  new ResponseBlockedError('Response blocked: content-type is not allowed', 'content_type'),
  new RateLimitedError('github', 60, 1000),
  new SecretReferenceError('invalid_reference'),
  new TokenEndpointError('Token endpoint returned HTTP 503', 'transient'),
  new UpstreamTimeoutError(),
  new UserFacingError('Configuration is locked.'),
];
for (const error of documentedErrors) {
  const safe: VouchrSafeError = mapSafeError(error);
  const code: VouchrErrorCode = safe.code;
  const recovery: VouchrRecovery = safe.recovery;
  void code;
  void recovery;
  void safeUserMessage(error);
}
void VOUCHR_ERROR_CODES;
void VOUCHR_RECOVERY_ACTIONS;
const tokenKind: TokenEndpointFailureKind = TOKEN_ENDPOINT_FAILURE_KINDS[0];
void tokenKind;

// Type-level only — never executed. Proves the type entrypoints resolve and the shapes exist.
export function _smoke(r: BrokerFetchResponse): number {
  void createVouchr;
  void createBroker;
  return r.status;
}
TS
cat > "$CONSUMER/tsconfig.json" <<'JSON'
{
  "compilerOptions": {
    "module": "nodenext",
    "moduleResolution": "nodenext",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true
  },
  "files": ["consumer.ts"]
}
JSON
( cd "$CONSUMER" && npm install -D typescript@5 >/dev/null && npx tsc -p tsconfig.json )
echo "    typed consumer compiles"

echo "==> PASS: package installs, resolves, and type-checks"
