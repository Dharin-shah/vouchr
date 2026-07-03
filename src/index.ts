export { createVouchr, ConsentRequiredError, SessionApprovalRequiredError, ConnectContext } from './adapters/bolt';
export type { VouchrOptions } from './adapters/bolt';
export type { ConnectContextDeps } from './adapters/bolt';
// Headless HTTP broker (non-Bolt agent runtimes): signed identity + fail-closed read-only egress.
export { createBroker } from './adapters/http/broker';
export type { BrokerOptions, BrokerFetchRequest, ConnectionHandleRef } from './adapters/http/broker';
export { signIdentity, mintIdentity, verifyIdentity, ReplayGuard, IdentityError, MAX_LIFETIME_MS } from './adapters/http/identity';
export type { IdentityClaims, MintIdentityInput, ReplayStore } from './adapters/http/identity';
export { DbReplayStore } from './adapters/http/replayStore';
export { kmsEnvelope, awsKmsClient } from './adapters/kms';
export type { KmsClientLike } from './adapters/kms';
export { SessionGrants } from './core/session';
// Low-level building blocks so a headless consumer can direct-construct createBroker end-to-end
// (openDb → new Vault → new Audit) instead of only via the env-driven buildBrokerServer. Also on
// `./headless`. SessionGrants/sweepExpired/TtlPolicy are already exported below.
export { openDb } from './core/db';
export type { Db, DbOptions } from './core/db';
export { Vault } from './core/vault';
export { Audit } from './core/audit';
export { Consent } from './core/consent';
export { github, google, gitlab, notion, defineProvider, ProviderRegistry } from './core/providers';
export type { Provider, ProviderConfig, RefreshStrategy } from './core/providers';
export { Policy } from './core/policy';
export type { PolicyRule } from './core/policy';
export type { SlackIdentity } from './core/identity';
export { ConnectionHandle } from './core/injector';
export type { Resolvers, VouchrEvent, EventSink } from './core/injector';
export type { VouchrAuditEvent, AuditSink } from './core/audit';
export { userOwner, channelOwner } from './core/owner';
export type { Owner } from './core/owner';
export { DbInstallationStore } from './adapters/installationStore';
// Re-export Bolt's installation types so consumers can wire the store without importing @slack/bolt directly.
export type { Installation, InstallationQuery, InstallationStore } from '@slack/bolt';
export type { ChannelMode } from './core/channelConfig';
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
} from './adapters/blocks';
export type { Connection } from './adapters/blocks';
export type { TtlPolicy } from './core/vault';
export type { EnvelopeProvider } from './core/crypto';
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
} from './broker-types';
