import { isOAuthScopeToken } from './providers';
import type { Vault } from './vault';
import type { UserProvisioningIssuance, UserProvisioningResult } from './vault';
import type { Audit } from './audit';
import type { SlackIdentity } from './identity';
import type { ChannelConfig, ChannelMode } from './channelConfig';
import {
  configureChannelCredential,
  type ChannelProvisioningIssuance,
} from './channelCredential';
import { configureUserCredential } from './provisioning';

export const SECRET_REFERENCE_SOURCES = ['aws-sm', 'gcp-sm', 'azure-kv', 'vault'] as const;
export type SecretReferenceSource = (typeof SECRET_REFERENCE_SOURCES)[number];

export interface SecretReferenceInput {
  secretRef?: unknown;
  /** Compatibility-only assertion. The source is always derived from `secretRef`. */
  source?: unknown;
  /** Canonical, space-separated subset of the provider's declared OAuth scopes. */
  scopes?: unknown;
}

export interface SecretReference {
  source: SecretReferenceSource;
  secretRef: string;
  scopes?: string;
}

export const SECRET_REFERENCE_ERROR_CODES = Object.freeze([
  'invalid_reference',
  'source_mismatch',
  'invalid_scopes',
  'resolver_unavailable',
] as const);
export type SecretReferenceErrorCode = (typeof SECRET_REFERENCE_ERROR_CODES)[number];

const ERROR_MESSAGES: Record<SecretReferenceErrorCode, string> = {
  invalid_reference: 'Invalid secret reference. Use a bounded supported external-reference form.',
  source_mismatch: 'Secret source does not match the reference.',
  invalid_scopes: 'Invalid scopes. Use a bounded space-separated subset of the provider scopes.',
  resolver_unavailable: 'Secret reference source is not configured.',
};

/** Fixed, Vouchr-authored validation errors. Messages never contain caller input. */
export class SecretReferenceError extends Error {
  constructor(public readonly code: SecretReferenceErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = 'SecretReferenceError';
  }
}

export const MAX_SECRET_REFERENCE_BYTES = 2 * 1024;
export const MAX_SECRET_REFERENCE_SCOPE_BYTES = 4 * 1024;
export const MAX_SECRET_REFERENCE_SCOPES = 128;

export const AWS_SECRET_REFERENCE =
  /^arn:aws(?:-[a-z0-9-]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$/;
export const GCP_SECRET_REFERENCE =
  /^gcp-sm:\/\/projects\/([A-Za-z0-9_-]+)\/secrets\/([A-Za-z0-9_-]+)\/versions\/([A-Za-z0-9_-]+)$/;
export const AZURE_KEY_VAULT_REFERENCE =
  /^azure-kv:\/\/([A-Za-z0-9-]+)\/([A-Za-z0-9-]+)(?:\/([A-Za-z0-9-]+))?$/;
export const HASHICORP_VAULT_REFERENCE =
  /^vault:\/\/([A-Za-z0-9_-]+)\/([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)#([A-Za-z0-9_.-]+)$/;

function invalidReference(): never {
  throw new SecretReferenceError('invalid_reference');
}

function hasAsciiWhitespaceOrControl(value: string): boolean {
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code <= 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * Validate one supported external-reference shape and derive its resolver source. Resolver
 * availability is checked separately by `normalizeSecretReference()` at every mutation entry point.
 */
export function secretReferenceSource(value: unknown): SecretReferenceSource {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    Buffer.byteLength(value, 'utf8') > MAX_SECRET_REFERENCE_BYTES ||
    hasAsciiWhitespaceOrControl(value)
  ) {
    return invalidReference();
  }

  if (AWS_SECRET_REFERENCE.test(value)) return 'aws-sm';
  if (GCP_SECRET_REFERENCE.test(value)) return 'gcp-sm';
  if (AZURE_KEY_VAULT_REFERENCE.test(value)) return 'azure-kv';

  const vault = HASHICORP_VAULT_REFERENCE.exec(value);
  if (vault) {
    const pathSegments = vault[2].split('/');
    if (pathSegments.every((segment) => segment !== '.' && segment !== '..')) return 'vault';
  }

  return invalidReference();
}

/**
 * Quarantine malformed legacy rows for Vouchr's four advertised source ids at credential use.
 * Unknown ids remain available to trusted low-level callers that provide custom resolvers.
 */
export function assertStoredSecretReference(source: string, secretRef: unknown): void {
  if (!(SECRET_REFERENCE_SOURCES as readonly string[]).includes(source)) return;
  if (secretReferenceSource(secretRef) !== source) {
    throw new SecretReferenceError('source_mismatch');
  }
}

function normalizeScopes(value: unknown, allowedScopes: readonly string[]): string | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    Buffer.byteLength(value, 'utf8') > MAX_SECRET_REFERENCE_SCOPE_BYTES
  ) {
    throw new SecretReferenceError('invalid_scopes');
  }
  const scopes = value.split(' ');
  if (
    scopes.length > MAX_SECRET_REFERENCE_SCOPES ||
    scopes.some((scope) => !isOAuthScopeToken(scope)) ||
    new Set(scopes).size !== scopes.length ||
    scopes.some((scope) => !allowedScopes.includes(scope))
  ) {
    throw new SecretReferenceError('invalid_scopes');
  }
  return value;
}

/**
 * The single mutation-boundary validator for Bolt and headless reference configuration. It derives
 * source server-side, treats a supplied source as a compatibility assertion only, restricts scopes
 * to the provider declaration, and confirms an own configured resolver without invoking it.
 * Nothing caller-controlled is returned on failure.
 */
export function normalizeSecretReference(
  input: SecretReferenceInput,
  resolvers: Readonly<Record<string, unknown>> | undefined,
  allowedScopes: readonly string[],
): SecretReference {
  const secretRef = input.secretRef;
  const source = secretReferenceSource(secretRef);

  if (input.source !== undefined && (typeof input.source !== 'string' || input.source !== source)) {
    throw new SecretReferenceError('source_mismatch');
  }
  if (
    !resolvers ||
    !Object.hasOwn(resolvers, source) ||
    typeof resolvers[source] !== 'function'
  ) {
    throw new SecretReferenceError('resolver_unavailable');
  }

  const scopes = normalizeScopes(input.scopes, allowedScopes);
  return Object.freeze({ source, secretRef: secretRef as string, ...(scopes === undefined ? {} : { scopes }) });
}

/** One user-reference mutation + audit shape, shared by Bolt and headless. */
export async function referenceUserCredential(input: {
  vault: Vault;
  audit: Audit;
  identity: SlackIdentity;
  providerId: string;
  reference: SecretReference;
  issuance: UserProvisioningIssuance;
}): Promise<UserProvisioningResult> {
  return configureUserCredential({
    ...input,
    credential: { kind: 'ref', reference: input.reference },
  });
}

/**
 * One channel-reference authorization/mode/mutation/audit sequence, shared by Bolt and headless.
 * Transport callbacks prove their own trusted facts and map a mode conflict to their surface.
 */
export async function referenceChannelCredential(input: {
  vault: Vault;
  audit: Audit;
  channelConfig: ChannelConfig;
  identity: SlackIdentity;
  channel: string;
  providerId: string;
  reference: SecretReference;
  issuance: ChannelProvisioningIssuance;
  authorize: () => Promise<void>;
  assertEligible: () => Promise<void>;
  modeConflict: (mode: Exclude<ChannelMode, 'shared'>) => never;
}): Promise<boolean> {
  await input.authorize();
  await input.assertEligible();
  return configureChannelCredential({
    vault: input.vault,
    audit: input.audit,
    channelConfig: input.channelConfig,
    identity: input.identity,
    channel: input.channel,
    providerId: input.providerId,
    issuance: input.issuance,
    credential: { kind: 'ref', reference: input.reference },
    modeConflict: input.modeConflict,
  });
}
