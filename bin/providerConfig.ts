import { readFileSync } from 'node:fs';
import {
  defineProvider,
  isValidProviderId,
  providerEnvKey,
  assertNoProviderCollisions,
  type Provider,
} from '../src/core/providers';

/**
 * Declarative provider config for the headless broker: an operator declares providers via env/JSON
 * without editing source. DECLARATIVE FIELDS ONLY — a provider that needs function fields (`inject`,
 * `revoke`, `egressValidate`) must be registered in code. Unknown fields are rejected (fail closed).
 * OAuth client id/secret are resolved from per-provider env so secrets live in the secret manager,
 * not the JSON: `VOUCHR_PROVIDER_<ID>_CLIENT_ID` / `_CLIENT_SECRET` (id upper-cased, non-alnum → _).
 */
const ALLOWED = new Set([
  'id', 'credential', 'identity', 'authorizeUrl', 'tokenUrl', 'scopesDefault', 'scopeDescriptions',
  'egressAllow', 'egressPaths', 'egressMethods', 'egressResponse', 'rateLimit', 'refresh', 'pkce',
  'publicClient', 'authorizeParams', 'tokenAuth', 'bodyFormat', 'revokeUrl', 'revokeAuth',
  'mcp', // #65 /v1/mcp opt-in: { paths: string[], allowContentTypes?: string[] }
  'approval', // #113 human-in-the-loop approval: { methods?, paths?, approver: 'self'|'admin', ttlMs? }
]);

function toProvider(entry: any, env: NodeJS.ProcessEnv): Provider {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new Error('provider config: each entry must be a JSON object');
  }
  if (Object.keys(entry).some((key) => !ALLOWED.has(key))) {
    throw new Error('provider config: unknown field; declarative fields only');
  }
  // This early check is required only to derive the credential environment key safely. The same
  // predicate is enforced again by defineProvider, which owns every other normalization and guard.
  if (!isValidProviderId(entry.id)) throw new Error('Provider field "id" must be a conservative identifier of at most 63 characters.');
  const ek = providerEnvKey(entry.id);
  return defineProvider({
    ...entry,
    clientId: env[`VOUCHR_PROVIDER_${ek}_CLIENT_ID`],
    clientSecret: env[`VOUCHR_PROVIDER_${ek}_CLIENT_SECRET`],
  } as Provider);
}

function parseArray(raw: string, label: string): any[] {
  let json: unknown;
  try { json = JSON.parse(raw); } catch { throw new Error(`${label}: invalid JSON`); }
  if (!Array.isArray(json)) throw new Error(`${label}: expected a JSON array of provider objects`);
  return json;
}

/** Load providers from VOUCHR_PROVIDERS_FILE (path) and/or VOUCHR_PROVIDERS (inline JSON). */
export function loadProviders(env: NodeJS.ProcessEnv = process.env): Provider[] {
  const specs: any[] = [];
  if (env.VOUCHR_PROVIDERS_FILE) {
    let raw: string;
    try { raw = readFileSync(env.VOUCHR_PROVIDERS_FILE, 'utf8'); }
    catch { throw new Error('VOUCHR_PROVIDERS_FILE: cannot read the configured provider file'); }
    specs.push(...parseArray(raw, 'VOUCHR_PROVIDERS_FILE'));
  }
  if (env.VOUCHR_PROVIDERS) specs.push(...parseArray(env.VOUCHR_PROVIDERS, 'VOUCHR_PROVIDERS'));

  const providers = specs.map((s) => toProvider(s, env));
  // Duplicate ids + normalized env-key collisions (e.g. "a.b" and "a-b" → shared A_B secret) are
  // rejected by the SAME core guard the registry uses (STR-2/STR-3), so the two paths can't disagree.
  assertNoProviderCollisions(providers);
  return providers;
}
