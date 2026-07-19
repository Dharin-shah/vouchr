/**
 * Bolt-free headless entry point (`@vouchr/core/headless`).
 *
 * The root `.` entry re-exports the Bolt adapter, which transitively loads `@slack/bolt` +
 * `@slack/web-api`. A pure-headless consumer who only wants `createBroker` + identity minting should
 * NOT pay for the entire Slack surface. This module re-exports exactly the headless broker surface and
 * imports ONLY from `./core/*`, `./adapters/http/*`, `./adapters/kms`, and `../bin/broker-server`
 * (itself Bolt-free — see broker-server.ts). It must NEVER import `./adapters/bolt`, so its resolved
 * module graph never reaches `@slack/*`. A build-time check (test/headless-boltfree.test.ts) enforces
 * this. The root `./index.ts` remains the Slack-inclusive entry point.
 */

// ── the broker + its request/option types ──
export { createBroker } from './adapters/http/broker';
export type {
  BrokerOptions,
  BrokerServer,
  BrokerFetchRequest,
  BrokerMcpRequest,
  ConnectionHandleRef,
} from './adapters/http/broker';

// ── the ready-to-run headless server (env → wired broker), same core the standalone binary uses ──
export { buildBrokerServer } from '../bin/broker-server';
export type { BuiltBroker } from '../bin/broker-server';

// ── low-level building blocks for the FLEXIBLE direct-construction path: BrokerOptions requires a
// vault/audit/db, so a typed consumer must be able to build them with ONLY `./headless` imports
// (openDb → new Vault → new Audit → createBroker). Direct brokers schedule the returned server's
// safe sweepExpired() facade, which also owns private interaction cleanup. Consent/core
// sweepExpired/TtlPolicy remain available for lower-level lifecycle integrations. All core — no
// @slack in the graph. ──
export { openDb, migrate } from './core/db';
export type { Db, DbOptions } from './core/db';
export { Vault, CredentialLockdownError } from './core/vault';
export type { TtlPolicy } from './core/vault';
// #115 master keys for the direct-construction path: `new Vault(db, loadKeyring())`.
export { loadKeyring } from './core/crypto';
export type { Keyring, MasterKeys, EnvelopeProvider } from './core/crypto';
export { Audit } from './core/audit';
export type { AuditSink, VouchrAuditEvent } from './core/audit';
export { Consent } from './core/consent';
export type { ConsentRequest } from './core/consent';
// Shared typed operational failures + the single safe recovery mapper. These imports are all core,
// so the headless graph stays independent of Bolt/Slack packages.
export {
  ConsentRequiredError,
  SessionApprovalRequiredError,
  UpstreamTimeoutError,
  UserFacingError,
  VOUCHR_ERROR_CODES,
  VOUCHR_RECOVERY_ACTIONS,
  isVouchrErrorCode,
  mapSafeError,
  safeUserMessage,
} from './core/errors';
export type { ConsentPromptState, VouchrErrorCode, VouchrRecovery, VouchrSafeError } from './core/errors';
// The broker maps this typed control-flow error to 403. Interaction stores are not exported: the
// shipped hybrid bridge reaches their safe mutations only through the trusted Bolt
// ConnectContext.recoverBrokerDenial surface; a pure-headless host gets no raw mutation API.
export { ApprovalPathTooLongError, ApprovalRequiredError } from './core/approval';
export { sweepExpired } from './core/sweep';

// ── signed identity minting/verification (the headless auth contract) ──
export {
  signIdentity,
  mintIdentity,
  verifyIdentity,
  ReplayGuard,
  IdentityError,
  MAX_LIFETIME_MS,
  // #212 deployment-bound identity assertions.
  loadIdentityConfig,
  assertStrongIdentitySecret,
  identityKid,
  IDENTITY_SKEW_MS,
  MIN_IDENTITY_SECRET_BYTES,
} from './adapters/http/identity';
export type { IdentityClaims, MintIdentityInput, IdentityConfig, IdentityKey } from './adapters/http/identity';

// ── shared jti replay store (Postgres-backed, cluster-wide single-use) ──
export { DbReplayStore } from './adapters/http/replayStore';

// ── KMS envelope helpers (optional at-rest encryption) ──
export { kmsEnvelope, awsKmsClient } from './adapters/kms';
export type { KmsClientLike } from './adapters/kms';

// ── provider helpers ──
export { github, google, gitlab, notion, databricks, defineProvider, ProviderRegistry } from './core/providers';
export type { Provider, ProviderConfig, DatabricksConfig, RefreshStrategy } from './core/providers';

// ── owner model (user- vs channel-owned credentials) ──
export { userOwner, channelOwner } from './core/owner';
export type { Owner } from './core/owner';

// ── opt-in channel gate ──
export { ChannelConfig, channelIneligibleReason } from './core/channelConfig';
export type { ChannelMode } from './core/channelConfig';

// ── operator authorization surface: Policy scopes the broker to a channel (canary rollout), the tool
// allowlist gates per-channel providers, and Resolvers/EventSink wire the `resolvers`/`onEvent`
// BrokerOptions. All core/adapters-http — no @slack in the graph. ──
export { Policy } from './core/policy';
export type { PolicyRule } from './core/policy';
export { PolicyDeniedError, ToolDisabledError } from './core/authz';
export { ChannelTools } from './core/tools';
export { InteractionStateChangedError } from './core/interaction';
export type { ToolManifestEntry } from './core/tools';
export type { Resolvers, EventSink, VouchrEvent } from './core/injector';
export {
  EgressBlockedError,
  NoConnectionError,
  ResolverConfigurationError,
  ResolverFailedError,
  ResponseBlockedError,
} from './core/injector';
export { SECRET_REFERENCE_ERROR_CODES, SECRET_REFERENCE_SOURCES, SecretReferenceError } from './core/reference';
export type {
  SecretReference,
  SecretReferenceErrorCode,
  SecretReferenceInput,
  SecretReferenceSource,
} from './core/reference';
// Rate limiting at the injection boundary: the broker maps RateLimitedError to 429 + Retry-After;
// the store type lets a scaled deployment plug a shared backend via BrokerOptions.rateLimitStore.
export { RateLimitedError } from './core/rateLimit';
export type { RateLimitStore } from './core/rateLimit';
// #117 credential health: BrokerOptions.onCredentialHealth fires refresh_dead; pass the same hook
// to sweepExpired for expiring_soon/expired. NotificationState is the persistent 24h debounce a
// headless notifier should use (reconnect/delete clear it). All core — no @slack in the graph.
export { NotificationState, HEALTH_NOTIFY_DEBOUNCE_MS } from './core/health';
export type { CredentialHealthEvent, CredentialHealthHook } from './core/health';
export { TOKEN_ENDPOINT_FAILURE_KINDS, TokenEndpointError } from './core/tokens';
export type { TokenEndpointFailureKind } from './core/tokens';

// ── exported wire RESPONSE types (mirror the broker's HTTP responses) ──
export type {
  BrokerConsentState,
  BrokerError,
  BrokerFetchResponse,
  BrokerResolveResponse,
  BrokerStatusResponse,
  BrokerConnectResponse,
  BrokerManifestResponse,
  BrokerChannelManifestResponse,
  BrokerAdminOkResponse,
  BrokerAdminConfigResponse,
  BrokerAuditResponse,
} from './broker-types';
