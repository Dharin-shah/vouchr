/**
 * Wire-contract RESPONSE types for the headless HTTP broker (src/adapters/http/broker.ts).
 *
 * The broker exports its REQUEST types (BrokerFetchRequest, ConnectionHandleRef) but historically no
 * response types, so every headless client hand-typed the JSON it got back. These interfaces mirror the
 * broker's HTTP responses exactly. They are STANDALONE (not wired into the handlers) — the DX win is an
 * exported contract; enforcing them on the handlers is a fine follow-up. Keep them in sync with broker.ts.
 */

import type { ChannelMode } from './core/channelConfig';

/** Coarse per-provider consent state — no secret, existence + state only. */
export type BrokerConsentState = 'connected' | 'needs_consent';

/** Any 4xx/5xx JSON body from the broker: `{ "error": "..." }`. */
export interface BrokerError {
  error: string;
}

/** `POST /v1/fetch` — the brokered upstream response (status + content-type + verbatim body). */
export interface BrokerFetchResponse {
  status: number;
  contentType: string;
  body: string;
}

/** `POST /v1/resolve` — one provider's connection state for the acting user. No secret. */
export interface BrokerResolveResponse {
  connected: boolean;
  consentState: BrokerConsentState;
}

/** `POST /v1/status` — the acting user's connection state across ALL brokered providers. */
export interface BrokerStatusResponse {
  providers: { provider: string; connected: boolean; consentState: BrokerConsentState }[];
}

/** `POST /v1/connect` — an OAuth authorize URL bound to the verified user (state is single-use). */
export interface BrokerConnectResponse {
  authorizeUrl: string;
  state: string;
}

/** `GET /v1/manifest` — each provider's id and whether Vouchr brokers a human credential for it. */
export interface BrokerManifestResponse {
  providers: { provider: string; identity: 'service' | 'acting_human' }[];
}

/** `POST /v1/admin/mode` · `POST /v1/admin/tools` — admin config write acknowledgement. No secret. */
export interface BrokerAdminOkResponse {
  ok: true;
}

/** `GET /v1/admin/config` — the caller's channel's per-provider mode + tool-enabled state (read side
 *  of the admin config write routes). Policy bits only, NO secret. `mode` is null when unconfigured. */
export interface BrokerAdminConfigResponse {
  providers: { provider: string; mode: ChannelMode | null; enabled: boolean }[];
}
