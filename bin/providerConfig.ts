import { readFileSync } from 'node:fs';
import { defineProvider, type Provider } from '../src/core/providers';

/**
 * Declarative provider config for the headless broker: an operator declares providers via env/JSON
 * without editing source. DECLARATIVE FIELDS ONLY — a provider that needs function fields (`inject`,
 * `revoke`, `egressValidate`) must be registered in code. Unknown fields are rejected (fail closed).
 * OAuth client id/secret are resolved from per-provider env so secrets live in the secret manager,
 * not the JSON: `VOUCHR_PROVIDER_<ID>_CLIENT_ID` / `_CLIENT_SECRET` (id upper-cased, non-alnum → _).
 */
const ALLOWED = new Set([
  'id', 'credential', 'identity', 'authorizeUrl', 'tokenUrl', 'scopesDefault',
  'egressAllow', 'egressPaths', 'egressMethods', 'refresh', 'pkce', 'tokenAuth', 'bodyFormat',
  'mcp', // #65 /v1/mcp opt-in: { paths: string[], allowContentTypes?: string[] }
]);

function envKey(id: string): string {
  return id.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

function assertOneOf(entry: any, field: string, allowed: readonly string[]): void {
  const value = entry[field];
  if (value == null) return;
  if (!allowed.includes(value)) {
    throw new Error(`provider config: "${entry.id}" field "${field}" must be one of: ${allowed.join(', ')}`);
  }
}

function toProvider(entry: any, env: NodeJS.ProcessEnv): Provider {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new Error('provider config: each entry must be a JSON object');
  }
  for (const k of Object.keys(entry)) {
    if (!ALLOWED.has(k)) {
      throw new Error(`provider config: unknown field "${k}" — declarative fields only; register providers needing functions (inject/egressValidate/revoke) in code`);
    }
  }
  if (typeof entry.id !== 'string' || !entry.id.trim()) throw new Error('provider config: "id" is required');
  if (!isStringArray(entry.egressAllow) || entry.egressAllow.length === 0) {
    throw new Error(`provider config: "${entry.id}" needs a non-empty "egressAllow" host list (the egress boundary)`);
  }
  if (entry.credential != null && entry.credential !== 'oauth' && entry.credential !== 'key') {
    throw new Error(`provider config: "${entry.id}" credential must be "oauth" or "key"`);
  }
  assertOneOf(entry, 'identity', ['service', 'acting_human']);
  assertOneOf(entry, 'refresh', ['rotating', 'static', 'none']);
  assertOneOf(entry, 'tokenAuth', ['body', 'basic']);
  assertOneOf(entry, 'bodyFormat', ['form', 'json']);
  if (entry.pkce != null && typeof entry.pkce !== 'boolean') {
    throw new Error(`provider config: "${entry.id}" field "pkce" must be a boolean`);
  }
  const isKey = entry.credential === 'key';
  if (!isKey) {
    if (typeof entry.authorizeUrl !== 'string' || !entry.authorizeUrl) throw new Error(`provider config: OAuth provider "${entry.id}" needs "authorizeUrl"`);
    if (typeof entry.tokenUrl !== 'string' || !entry.tokenUrl) throw new Error(`provider config: OAuth provider "${entry.id}" needs "tokenUrl"`);
  }
  for (const arr of ['scopesDefault', 'egressPaths', 'egressMethods'] as const) {
    if (entry[arr] != null && !isStringArray(entry[arr])) throw new Error(`provider config: "${entry.id}" field "${arr}" must be an array of strings`);
  }
  // #65 /v1/mcp opt-in knob. defineProvider re-validates, but the loader fails with its own
  // config-shaped message like every other field here (fail closed, unknown keys included).
  if (entry.mcp != null) {
    if (typeof entry.mcp !== 'object' || Array.isArray(entry.mcp)) {
      throw new Error(`provider config: "${entry.id}" field "mcp" must be an object like { "paths": ["/mcp"] }`);
    }
    for (const k of Object.keys(entry.mcp)) {
      if (k !== 'paths' && k !== 'allowContentTypes') {
        throw new Error(`provider config: "${entry.id}" field "mcp" has unknown key "${k}" — allowed: paths, allowContentTypes`);
      }
    }
    if (!isStringArray(entry.mcp.paths) || entry.mcp.paths.length === 0 || entry.mcp.paths.some((p: string) => !p.trim())) {
      throw new Error(`provider config: "${entry.id}" field "mcp.paths" must be a non-empty array of non-empty strings`);
    }
    if (entry.mcp.allowContentTypes != null && (!isStringArray(entry.mcp.allowContentTypes) || entry.mcp.allowContentTypes.length === 0 || entry.mcp.allowContentTypes.some((c: string) => !c.trim()))) {
      throw new Error(`provider config: "${entry.id}" field "mcp.allowContentTypes" must be a non-empty array of non-empty strings`);
    }
  }

  const ek = envKey(entry.id);
  // defineProvider throws a clear error if an OAuth provider ends up without client id/secret.
  return defineProvider({
    id: entry.id,
    credential: entry.credential,
    identity: entry.identity,
    authorizeUrl: entry.authorizeUrl ?? '',
    tokenUrl: entry.tokenUrl ?? '',
    scopesDefault: entry.scopesDefault ?? [],
    egressAllow: entry.egressAllow,
    egressPaths: entry.egressPaths,
    egressMethods: entry.egressMethods,
    mcp: entry.mcp,
    refresh: entry.refresh ?? 'none',
    pkce: entry.pkce ?? false,
    tokenAuth: entry.tokenAuth,
    bodyFormat: entry.bodyFormat,
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
    catch (e) { throw new Error(`VOUCHR_PROVIDERS_FILE: cannot read ${env.VOUCHR_PROVIDERS_FILE}: ${(e as Error).message}`); }
    specs.push(...parseArray(raw, `VOUCHR_PROVIDERS_FILE (${env.VOUCHR_PROVIDERS_FILE})`));
  }
  if (env.VOUCHR_PROVIDERS) specs.push(...parseArray(env.VOUCHR_PROVIDERS, 'VOUCHR_PROVIDERS'));

  const providers = specs.map((s) => toProvider(s, env));
  const seen = new Set<string>();
  const seenEnvKey = new Map<string, string>();
  for (const p of providers) {
    if (seen.has(p.id)) throw new Error(`provider config: duplicate provider id "${p.id}"`);
    seen.add(p.id);
    // Two ids that normalize to the same VOUCHR_PROVIDER_<KEY>_CLIENT_SECRET would silently share
    // one secret (e.g. "a.b" and "a-b" → "A_B"). Reject the collision, not just exact id dups.
    const ek = envKey(p.id);
    const clash = seenEnvKey.get(ek);
    if (clash) throw new Error(`provider config: ids "${clash}" and "${p.id}" derive the same client-secret env key VOUCHR_PROVIDER_${ek}_CLIENT_*`);
    seenEnvKey.set(ek, p.id);
  }
  return providers;
}
