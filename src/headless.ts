/**
 * Bolt-free headless entry point (`@vouchr/core/headless`).
 *
 * The root `.` entry re-exports the Bolt adapter, which transitively loads `@slack/bolt` +
 * `@slack/web-api`. A pure-headless consumer who only wants `createBroker` + identity minting should
 * NOT pay for the entire Slack surface. This module re-exports exactly the headless broker surface and
 * imports ONLY from `./core/*`, `./adapters/http/*`, `./adapters/kms`, and `../bin/broker-server`
 * (itself Bolt-free — see broker-server.ts). It must NEVER import `./adapters/bolt`, so its resolved
 * module graph never reaches `@slack/*`. A build-time check (test/headless-boltfree.test.ts) enforces
 * this. The root `./index.ts` stays unchanged for back-compat.
 */

// ── the broker + its request/option types ──
export { createBroker } from './adapters/http/broker';
export type { BrokerOptions, BrokerFetchRequest, BrokerMcpRequest, ConnectionHandleRef } from './adapters/http/broker';

// ── the ready-to-run headless server (env → wired broker), same core the standalone binary uses ──
export { buildBrokerServer } from '../bin/broker-server';
export type { BuiltBroker } from '../bin/broker-server';

// ── low-level building blocks for the FLEXIBLE direct-construction path: BrokerOptions requires a
// vault/audit/db, so a typed consumer must be able to build them with ONLY `./headless` imports
// (openDb → new Vault → new Audit → createBroker). Consent/SessionGrants/sweepExpired/TtlPolicy are
// the lifecycle bits a headless deploy wires for the TTL sweep. All core — no @slack in the graph. ──
export { openDb } from './core/db';
export type { Db, DbOptions } from './core/db';
export { Vault } from './core/vault';
export type { TtlPolicy } from './core/vault';
// #115 master keys for the direct-construction path: `new Vault(db, loadKeyring())`.
export { loadKeyring } from './core/crypto';
export type { Keyring, MasterKeys, EnvelopeProvider } from './core/crypto';
export { Audit } from './core/audit';
export type { AuditSink, VouchrAuditEvent } from './core/audit';
export { Consent } from './core/consent';
export { SessionGrants } from './core/session';
export { sweepExpired } from './core/sweep';

// ── signed identity minting/verification (the headless auth contract) ──
export {
  signIdentity,
  mintIdentity,
  verifyIdentity,
  ReplayGuard,
  IdentityError,
  MAX_LIFETIME_MS,
} from './adapters/http/identity';
export type { IdentityClaims, MintIdentityInput, ReplayStore } from './adapters/http/identity';

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
// #112 union opt-in: the broker trusts the host's signed actingMemberId, so a headless host that
// resolves acting members itself applies the candidate rule (eligibleUnionMembers) and drives the
// audited join/leave lifecycle with the same core the Bolt surface uses.
export { UnionOptin, eligibleUnionMembers, joinUnion, leaveUnion } from './core/unionOptin';
// Preview visibility (per-channel rendering policy) + the pending-preview claim store, so a headless
// host can honor `visibility` from the manifest and run the same single-use share authorization.
export { PREVIEW_VISIBILITIES, isPreviewVisibility } from './core/channelConfig';
export type { PreviewVisibility } from './core/channelConfig';
export { PendingPreviews } from './core/preview';
export type { PendingPreview } from './core/preview';

// ── operator authorization surface: Policy scopes the broker to a channel (canary rollout), the tool
// allowlist gates per-channel providers, and Resolvers/EventSink wire the `resolvers`/`onEvent`
// BrokerOptions. All core/adapters-http — no @slack in the graph. ──
export { Policy } from './core/policy';
export type { PolicyRule } from './core/policy';
export { ChannelTools } from './core/tools';
export type { ToolManifestEntry } from './core/tools';
export type { Resolvers, EventSink, VouchrEvent } from './core/injector';
// Rate limiting at the injection boundary: the broker maps RateLimitedError to 429 + Retry-After;
// the store type lets a scaled deployment plug a shared backend via BrokerOptions.rateLimitStore.
export { RateLimitedError } from './core/rateLimit';
export type { RateLimitStore } from './core/rateLimit';
// #117 credential health: BrokerOptions.onCredentialHealth fires refresh_dead; pass the same hook
// to sweepExpired for expiring_soon/expired. NotificationState is the persistent 24h debounce a
// headless notifier should use (reconnect/delete clear it). All core — no @slack in the graph.
export { NotificationState, HEALTH_NOTIFY_DEBOUNCE_MS } from './core/health';
export type { CredentialHealthEvent, CredentialHealthHook } from './core/health';
export { TokenEndpointError } from './core/tokens';

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
