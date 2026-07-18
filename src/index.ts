export { createVouchr, ConnectContext } from './adapters/bolt';
export type { VouchrOptions } from './adapters/bolt';
export type { ConnectContextDeps } from './adapters/bolt';
// One Bolt-free typed-error contract feeds direct handles, Slack rendering, and the headless broker.
// Unknown/foreign messages never cross this boundary.
export {
  ConsentRequiredError,
  SessionApprovalRequiredError,
  UpstreamTimeoutError,
  UserFacingError,
  VOUCHR_ERROR_CODES,
  VOUCHR_RECOVERY_ACTIONS,
  mapSafeError,
  safeUserMessage,
} from './core/errors';
export type { ConsentPromptState, VouchrErrorCode, VouchrRecovery, VouchrSafeError } from './core/errors';
// Headless HTTP broker (non-Bolt agent runtimes): signed identity + fail-closed read-only egress.
export { createBroker } from './adapters/http/broker';
export type {
  BrokerOptions,
  BrokerServer,
  BrokerFetchRequest,
  BrokerMcpRequest,
  ConnectionHandleRef,
} from './adapters/http/broker';
export {
  signIdentity, mintIdentity, verifyIdentity, ReplayGuard, IdentityError, MAX_LIFETIME_MS,
  // #212 deployment-bound identity: config builder + helpers for minting/verifying bound assertions.
  loadIdentityConfig, assertStrongIdentitySecret, identityKid, IDENTITY_SKEW_MS, MIN_IDENTITY_SECRET_BYTES,
} from './adapters/http/identity';
export type { IdentityClaims, MintIdentityInput, IdentityConfig, IdentityKey } from './adapters/http/identity';
export { DbReplayStore } from './adapters/http/replayStore';
export { kmsEnvelope, awsKmsClient } from './adapters/kms';
export type { KmsClientLike } from './adapters/kms';
export { InteractionStateChangedError } from './core/interaction';
// #113 human-in-the-loop approval for sensitive writes. Typed control-flow errors remain public;
// persisted interaction stores are intentionally internal so
// package consumers cannot bypass the packaged Bolt/broker mutation+lock+audit facades.
export { ApprovalPathTooLongError, ApprovalRequiredError } from './core/approval';
// Low-level building blocks so a headless consumer can direct-construct createBroker end-to-end
// (openDb → new Vault → new Audit) instead of only via the env-driven buildBrokerServer. Also on
// `./headless`. A direct createBroker() result owns safe interaction cleanup through its
// sweepExpired() method; the lower-level core sweepExpired/TtlPolicy remain exported below.
export { openDb, migrate } from './core/db';
export type { Db, DbOptions } from './core/db';
export { Vault } from './core/vault';
export { Audit } from './core/audit';
export { Consent } from './core/consent';
export type { ConsentRequest } from './core/consent';
export { github, google, gitlab, notion, databricks, defineProvider, ProviderRegistry } from './core/providers';
export type { Provider, ProviderConfig, DatabricksConfig, RefreshStrategy } from './core/providers';
export { Policy } from './core/policy';
export type { PolicyRule } from './core/policy';
export { PolicyDeniedError, ToolDisabledError } from './core/authz';
export type { SlackIdentity } from './core/identity';
export {
  ConnectionHandle,
  EgressBlockedError,
  NoConnectionError,
  ResolverConfigurationError,
  ResolverFailedError,
  ResponseBlockedError,
} from './core/injector';
export type { Resolvers, VouchrEvent, EventSink } from './core/injector';
export { SECRET_REFERENCE_ERROR_CODES, SECRET_REFERENCE_SOURCES, SecretReferenceError } from './core/reference';
export type {
  SecretReference,
  SecretReferenceErrorCode,
  SecretReferenceInput,
  SecretReferenceSource,
} from './core/reference';
// Per-(owner, provider) rate limiting at the injection boundary (provider.rateLimit). The error is
// exported so callers can catch/branch on a throttled fetch; the store type so a multi-instance
// deployment can plug a shared backend via VouchrOptions/BrokerOptions.rateLimitStore.
export { RateLimitedError } from './core/rateLimit';
export type { RateLimitStore } from './core/rateLimit';
// #117 credential-health notifications: the hook types for VouchrOptions/BrokerOptions
// `onCredentialHealth`, the persistent per-(owner, provider, type) DM debounce store for custom
// notifiers, and the typed token-endpoint error carrying credential/configuration/transient kind.
export { NotificationState, HEALTH_NOTIFY_DEBOUNCE_MS } from './core/health';
export type { CredentialHealthEvent, CredentialHealthHook } from './core/health';
export { TOKEN_ENDPOINT_FAILURE_KINDS, TokenEndpointError } from './core/tokens';
export type { TokenEndpointFailureKind } from './core/tokens';
export type { VouchrAuditEvent, AuditSink } from './core/audit';
export { userOwner, channelOwner } from './core/owner';
export type { Owner } from './core/owner';
export { DbInstallationStore } from './adapters/installationStore';
// Re-export Bolt's installation types so consumers can wire the store without importing @slack/bolt directly.
export type { Installation, InstallationQuery, InstallationStore } from '@slack/bolt';
export type { ChannelMode } from './core/channelConfig';
export { CHANNEL_MODES, isChannelMode } from './core/channelConfig';
export { ChannelTools } from './core/tools';
export type { ToolManifestEntry } from './core/tools';
// #64 pure Block Kit builders (strings in, Block Kit JSON out — no chat SDK). Exported so a headless
// host can render the SAME connect prompt / credential modal with its OWN client and forward the
// submission to the headless endpoints (/v1/connect, /v1/{admin,user}/reference), instead of
// hand-copying the JSON (which then drifts from the Bolt path).
export {
  connectBlocks,
  configureModal,
  userKeyModal,
  CONFIGURE_CALLBACK,
  USER_KEY_CALLBACK,
  SETUP_KEY_ACTION,
  connectedBlocks,
  consentDeniedBlocks,
  statusBlocks,
  disconnectConfirmBlocks,
  homeView,
  DISCONNECT_ACTION,
  configModal,
  CONFIG_CALLBACK,
} from './adapters/blocks';
export type { Connection, ToolRow, ConfigAdminRow } from './adapters/blocks';
export type { TtlPolicy } from './core/vault';
export type { EnvelopeProvider } from './core/crypto';
// #115 master-key rotation for the direct (non-KMS) path: loadKeyring reads VOUCHR_MASTER_KEY
// and/or VOUCHR_MASTER_KEYS (first entry encrypts, all entries decrypt); every key-taking
// constructor (Vault, DbInstallationStore) accepts a bare Buffer or a Keyring (MasterKeys).
export { loadKeyring } from './core/crypto';
export type { Keyring, MasterKeys } from './core/crypto';
// Lifecycle is driven through the createVouchr() result (vouchr.offboard / vouchr.sweepExpired);
// registerOffboarding() wires the user_change handler. No standalone re-exports: one obvious way.
// Exception: Enterprise Grid / SCIM deprovisioning spans ALL workspaces, which createVouchr's
// single-team offboard can't express, so the cross-team entry point is exported directly.
export { offboardUserEverywhere } from './core/offboard';
// #54 single-user lifecycle helpers, exported so a headless host can drive offboarding / TTL sweep
// in-process (the same core the /v1/disconnect, /v1/admin/offboard routes and broker-server timer use).
export { offboardUser, disconnectProvider } from './core/offboard';
export { sweepExpired } from './core/sweep';
// Exported wire RESPONSE types for the HTTP broker — the request types (BrokerFetchRequest,
// ConnectionHandleRef) were already exported; these give clients the response contract too, so they
// stop hand-typing it. Standalone interfaces (not wired into the handlers). Also on `./headless`.
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
