/**
 * Wire-contract RESPONSE types for the headless HTTP broker (src/adapters/http/broker.ts).
 *
 * The broker exports its REQUEST types (BrokerFetchRequest, ConnectionHandleRef) but historically no
 * response types, so every headless client hand-typed the JSON it got back. These interfaces mirror the
 * broker's HTTP responses exactly. They are STANDALONE (not wired into the handlers) — the DX win is an
 * exported contract; enforcing them on the handlers is a fine follow-up. Keep them in sync with broker.ts.
 */

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
