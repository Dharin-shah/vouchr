import { readFileSync } from 'node:fs';
import {
  defineProvider,
  isCanonicalPath,
  canonicalMethod,
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

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

/** A plain (non-array, non-null) object — the shape of scopeDescriptions/authorizeParams/egressResponse/rateLimit. */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** A `Record<string, string>` — scopeDescriptions and authorizeParams both require all-string values. */
function isStringRecord(v: unknown): v is Record<string, string> {
  return isPlainObject(v) && Object.values(v).every((x) => typeof x === 'string');
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
  assertOneOf(entry, 'revokeAuth', ['none', 'body']);
  for (const b of ['pkce', 'publicClient'] as const) {
    if (entry[b] != null && typeof entry[b] !== 'boolean') {
      throw new Error(`provider config: "${entry.id}" field "${b}" must be a boolean`);
    }
  }
  // revokeUrl is a plain string here; defineProvider enforces https / no-userinfo / no-port on it
  // (the revoke POST carries the live token + client secret and is not behind the egress gate).
  if (entry.revokeUrl != null && (typeof entry.revokeUrl !== 'string' || !entry.revokeUrl.trim())) {
    throw new Error(`provider config: "${entry.id}" field "revokeUrl" must be a non-empty string`);
  }
  // scopeDescriptions + authorizeParams are Record<string,string>. defineProvider additionally rejects
  // reserved OAuth keys in authorizeParams (state/redirect_uri/…); the loader only shape-checks here.
  for (const rec of ['scopeDescriptions', 'authorizeParams'] as const) {
    if (entry[rec] != null && !isStringRecord(entry[rec])) {
      throw new Error(`provider config: "${entry.id}" field "${rec}" must be an object of string values`);
    }
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

  // #113 approval knob. defineProvider re-validates, but the loader fails with its own
  // config-shaped message like every other field here (fail closed, unknown keys included).
  if (entry.approval != null) {
    if (typeof entry.approval !== 'object' || Array.isArray(entry.approval)) {
      throw new Error(`provider config: "${entry.id}" field "approval" must be an object like { "approver": "admin" }`);
    }
    for (const k of Object.keys(entry.approval)) {
      if (!['methods', 'paths', 'approver', 'ttlMs'].includes(k)) {
        throw new Error(`provider config: "${entry.id}" field "approval" has unknown key "${k}" — allowed: methods, paths, approver, ttlMs`);
      }
    }
    if (entry.approval.approver !== 'self' && entry.approval.approver !== 'admin') {
      throw new Error(`provider config: "${entry.id}" field "approval.approver" must be "self" or "admin"`);
    }
    // Canonical checks up front (SAME rules as defineProvider — isCanonicalPath/canonicalMethod,
    // STR-2), so a fail-open form ('repos', ' /repos', 'POST ') is rejected at config load with a
    // config-shaped message rather than slipping to defineProvider or, worse, to runtime.
    if (entry.approval.methods != null) {
      if (!isStringArray(entry.approval.methods) || entry.approval.methods.length === 0) {
        throw new Error(`provider config: "${entry.id}" field "approval.methods" must be a non-empty array of HTTP method names`);
      }
      if (entry.approval.methods.some((m: string) => canonicalMethod(m) === null)) {
        throw new Error(`provider config: "${entry.id}" field "approval.methods" entries must be bare HTTP method names (e.g. "POST")`);
      }
    }
    if (entry.approval.paths != null) {
      if (!isStringArray(entry.approval.paths) || entry.approval.paths.length === 0) {
        throw new Error(`provider config: "${entry.id}" field "approval.paths" must be a non-empty array of absolute paths`);
      }
      if (entry.approval.paths.some((p: string) => !isCanonicalPath(p))) {
        throw new Error(`provider config: "${entry.id}" field "approval.paths" entries must be absolute paths like "/repos"`);
      }
    }
    const ttl = entry.approval.ttlMs;
    if (ttl != null && !(typeof ttl === 'number' && Number.isFinite(ttl) && ttl > 0)) {
      throw new Error(`provider config: "${entry.id}" field "approval.ttlMs" must be a finite number > 0`);
    }
  }

  // egressResponse (finite response limits) — shape-check with a config-shaped message, unknown keys
  // rejected; defineProvider re-validates deeply (maxBytes finite>0, content-types, header names).
  if (entry.egressResponse != null) {
    if (!isPlainObject(entry.egressResponse)) {
      throw new Error(`provider config: "${entry.id}" field "egressResponse" must be an object like { "maxBytes": 1048576 }`);
    }
    for (const k of Object.keys(entry.egressResponse)) {
      if (!['maxBytes', 'allowContentTypes', 'stripHeaders'].includes(k)) {
        throw new Error(`provider config: "${entry.id}" field "egressResponse" has unknown key "${k}" — allowed: maxBytes, allowContentTypes, stripHeaders`);
      }
    }
    if (entry.egressResponse.maxBytes != null && typeof entry.egressResponse.maxBytes !== 'number') {
      throw new Error(`provider config: "${entry.id}" field "egressResponse.maxBytes" must be a number`);
    }
    for (const arr of ['allowContentTypes', 'stripHeaders'] as const) {
      if (entry.egressResponse[arr] != null && !isStringArray(entry.egressResponse[arr])) {
        throw new Error(`provider config: "${entry.id}" field "egressResponse.${arr}" must be an array of strings`);
      }
    }
  }

  // rateLimit (finite request rate) — shape-check; defineProvider re-validates the finite>0 +
  // effective-capacity>=1 rules that keep the token bucket from bricking or never denying.
  if (entry.rateLimit != null) {
    if (!isPlainObject(entry.rateLimit)) {
      throw new Error(`provider config: "${entry.id}" field "rateLimit" must be an object like { "perMinute": 60 }`);
    }
    for (const k of Object.keys(entry.rateLimit)) {
      if (k !== 'perMinute' && k !== 'burst') {
        throw new Error(`provider config: "${entry.id}" field "rateLimit" has unknown key "${k}" — allowed: perMinute, burst`);
      }
    }
    for (const n of ['perMinute', 'burst'] as const) {
      if (entry.rateLimit[n] != null && typeof entry.rateLimit[n] !== 'number') {
        throw new Error(`provider config: "${entry.id}" field "rateLimit.${n}" must be a number`);
      }
    }
    if (entry.rateLimit.perMinute == null) {
      throw new Error(`provider config: "${entry.id}" field "rateLimit" requires "perMinute"`);
    }
  }

  const ek = providerEnvKey(entry.id);
  // defineProvider throws a clear error if an OAuth provider ends up without client id/secret.
  return defineProvider({
    id: entry.id,
    credential: entry.credential,
    identity: entry.identity,
    authorizeUrl: entry.authorizeUrl ?? '',
    tokenUrl: entry.tokenUrl ?? '',
    scopesDefault: entry.scopesDefault ?? [],
    scopeDescriptions: entry.scopeDescriptions,
    egressAllow: entry.egressAllow,
    egressPaths: entry.egressPaths,
    egressMethods: entry.egressMethods,
    egressResponse: entry.egressResponse,
    rateLimit: entry.rateLimit,
    mcp: entry.mcp,
    approval: entry.approval,
    refresh: entry.refresh ?? 'none',
    pkce: entry.pkce ?? false,
    publicClient: entry.publicClient,
    authorizeParams: entry.authorizeParams,
    tokenAuth: entry.tokenAuth,
    bodyFormat: entry.bodyFormat,
    revokeUrl: entry.revokeUrl,
    revokeAuth: entry.revokeAuth,
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
  // Duplicate ids + normalized env-key collisions (e.g. "a.b" and "a-b" → shared A_B secret) are
  // rejected by the SAME core guard the registry uses (STR-2/STR-3), so the two paths can't disagree.
  assertNoProviderCollisions(providers);
  return providers;
}
