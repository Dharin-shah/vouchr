export { createVouchr, ConsentRequiredError, ConnectContext } from './adapters/bolt';
export type { VouchrOptions } from './adapters/bolt';
export { github, google, gitlab, notion, defineProvider, ProviderRegistry } from './core/providers';
export type { Provider, ProviderConfig, RefreshStrategy } from './core/providers';
export { Policy } from './core/policy';
export type { PolicyRule } from './core/policy';
export type { SlackIdentity } from './core/identity';
export { ConnectionHandle } from './core/injector';
export type { Resolvers, VouchrEvent, EventSink } from './core/injector';
export { userOwner, channelOwner } from './core/owner';
export type { Owner } from './core/owner';
export { DbInstallationStore } from './adapters/installationStore';
// Re-export Bolt's installation types so consumers can wire the store without importing @slack/bolt directly.
export type { Installation, InstallationQuery, InstallationStore } from '@slack/bolt';
export type { ChannelMode } from './core/channelConfig';
export { ChannelTools } from './core/tools';
export type { ToolManifestEntry } from './core/tools';
export type { TtlPolicy } from './core/vault';
export type { EnvelopeProvider } from './core/crypto';
// Lifecycle is driven through the createVouchr() result (vouchr.offboard / vouchr.sweepExpired);
// registerOffboarding() wires the user_change handler. No standalone re-exports: one obvious way.
// Exception: Enterprise Grid / SCIM deprovisioning spans ALL workspaces, which createVouchr's
// single-team offboard can't express, so the cross-team entry point is exported directly.
export { offboardUserEverywhere } from './core/offboard';
