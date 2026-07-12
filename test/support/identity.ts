import { createHash } from 'node:crypto';
import {
  IdentityError,
  ReplayGuard,
  IDENTITY_SKEW_MS,
  identityKid,
  mintIdentity as mintBoundIdentity,
  normalizeIdentityConfig,
  signIdentity as signBoundIdentity,
  verifyIdentity as verifyBoundIdentity,
  type IdentityClaims,
  type IdentityConfig,
  type MintIdentityInput,
} from '../../src/adapters/http/identity';

export { IdentityError, ReplayGuard, IDENTITY_SKEW_MS };
export type { IdentityClaims, IdentityConfig, MintIdentityInput };

/**
 * Broker tests used short labels as their historical signing secrets. Derive strong deterministic
 * key material from each label and bind every test broker/token to one deployment, so the production
 * broker path is exercised without weakening its runtime contract for test convenience.
 */
export function identityConfig(label: string): IdentityConfig {
  const secret = createHash('sha256').update(`vouchr-test-identity:${label}`).digest('base64url');
  return normalizeIdentityConfig({
    issuer: 'vouchr-test',
    audience: 'test-deployment',
    keys: [{ kid: identityKid(secret), secret }],
  });
}

/** Match the old test helper signature while emitting a fully deployment-bound assertion. */
export function signIdentity(claims: IdentityClaims, label: string): string {
  const config = identityConfig(label);
  const active = config.keys[0];
  const iat = Math.min(Date.now(), claims.exp - 1);
  return signBoundIdentity({
    ...claims,
    iss: config.issuer,
    aud: config.audience,
    iat,
    kid: active.kid,
  }, active.secret);
}

/** Match the old test helper signature while verifying the same deployment-bound assertion. */
export function verifyIdentity(
  token: string,
  label: string,
  opts: Parameters<typeof verifyBoundIdentity>[2] = {},
): IdentityClaims {
  return verifyBoundIdentity(token, identityConfig(label), opts);
}

/** Match the old test helper signature while using the bound minter. */
export function mintIdentity(input: MintIdentityInput, label: string, ttlMs = 60_000, now = Date.now()): string {
  return mintBoundIdentity(input, identityConfig(label), ttlMs, now);
}
