/**
 * Wire-contract RESPONSE types for the headless HTTP broker (src/adapters/http/broker.ts).
 *
 * The broker exports its REQUEST types (BrokerFetchRequest, ConnectionHandleRef) but historically no
 * response types, so every headless client hand-typed the JSON it got back. These interfaces mirror the
 * broker's HTTP responses exactly. They are STANDALONE (not wired into the handlers) — the DX win is an
 * exported contract; enforcing them on the handlers is a fine follow-up. Keep them in sync with broker.ts.
 */

import type { ChannelMode } from './core/channelConfig';
import type { AuditRow } from './core/audit';
import type { ToolManifestEntry } from './core/tools';
import type { VouchrErrorCode, VouchrRecovery } from './core/errors';

/** Coarse per-provider consent state — no secret, existence + state only. */
export type BrokerConsentState = 'connected' | 'needs_consent';

/** Any functional-route 4xx/5xx JSON body: `{ "error": "..." }`. Readiness is the deliberate
 *  exception: `/readyz` returns only `{ ok: false }`, with no diagnostic text. */
export interface BrokerError {
  error: string;
  /** Stable machine-readable classification. Present on typed operational failures; older/general
   * validation routes retain their established prose-only shape. Branch on this, never `error`. */
  code?: VouchrErrorCode;
  /** Whether retrying later can resolve the same condition. This never authorizes an automatic
   * replay of a non-idempotent or unknown-outcome request. */
  retryable?: boolean;
  /** Closed next-action category for trusted recovery UI; never inferred from `error` prose. */
  recovery?: VouchrRecovery;
  /** On a 429 (rate limit) or 503 (in-flight ceiling): the broker's retry hint in milliseconds.
   *  The same value, rounded up to whole seconds, rides the `Retry-After` response header. */
  retryAfterMs?: number;
  /** Present only on an in-flight-overload 503. `global` is the broker-wide admission ceiling;
   *  `provider` is the per-provider ceiling. It never contains a provider id or request value. */
  scope?: 'global' | 'provider';
  /** Present only on `approval_required`; an opaque pending-request handle, not authorization. */
  approvalId?: string;
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
  /** Opaque, authority-free current row generation, returned only when the request explicitly sets
   * `includeCredentialId: true`. Pass it back to `/v1/disconnect` to bind that mutation exactly. */
  credentialId?: string;
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

/** `GET /v1/manifest` — each provider's id and whether Vouchr brokers a human credential for it
 *  (channel-independent). For the channel-scoped manifest, use `POST /v1/manifest`. */
export interface BrokerManifestResponse {
  providers: { provider: string; identity: 'service' | 'acting_human' }[];
}

/** `POST /v1/manifest` — the CHANNEL-SCOPED tool manifest for the verified identity: the same
 *  `ToolManifestEntry` Bolt's `toolManifest()` returns (one core builder feeds both). Provider-output
 *  rendering belongs to the host and is not part of this policy manifest. Policy bits only, NO secret. */
export interface BrokerChannelManifestResponse {
  tools: ToolManifestEntry[];
}

/** `POST /v1/admin/mode` · `POST /v1/admin/tools` — admin config write acknowledgement. No secret. */
export interface BrokerAdminOkResponse {
  ok: true;
}

/** `GET /v1/admin/config` — the caller's channel's per-provider mode + tool-enabled state (read side
 *  of the admin config write routes). Policy bits only, NO secret. `mode` is null when unconfigured
 *  and always null for a service tool, which has no Vouchr-owned credential. */
export interface BrokerAdminConfigResponse {
  providers: { provider: string; mode: ChannelMode | null; enabled: boolean }[];
}

/** `POST /v1/audit` · `POST /v1/admin/audit` — a read-only slice of the audit trail: the caller's own
 *  usage, or (admin) the current channel's. Non-secret columns ONLY — `meta` is never included (the
 *  core read query omits it). Headless analogue of `/vouchr audit` / `/vouchr audit channel`. */
export interface BrokerAuditResponse {
  events: AuditRow[];
}
