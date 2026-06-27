export { createVouchr, ConsentRequiredError, ConnectContext } from './adapters/bolt';
export type { VouchrOptions } from './adapters/bolt';
export { github, google, gitlab, notion, defineProvider, ProviderRegistry } from './core/providers';
export type { Provider, ProviderConfig, RefreshStrategy } from './core/providers';
export { Policy } from './core/policy';
export type { PolicyRule } from './core/policy';
export type { SlackIdentity } from './core/identity';
export { ConnectionHandle } from './core/injector';
export type { Resolvers } from './core/injector';
export { userOwner, channelOwner } from './core/owner';
export type { Owner } from './core/owner';
export type { ChannelMode } from './core/channelConfig';
export type { TtlPolicy } from './core/vault';
// Lifecycle is driven through the createVouchr() result (vouchr.offboard / vouchr.sweepExpired);
// registerOffboarding() wires the user_change handler. No standalone re-exports — one obvious way.
