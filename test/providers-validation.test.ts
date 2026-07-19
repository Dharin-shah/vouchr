import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertCallbackUrl,
  buildCallbackUrl,
  defineProvider,
  github,
  gitlab,
  google,
  isLoopbackHost,
  isValidProviderId,
  notion,
  ProviderRegistry,
  type Provider,
} from '../src/core/providers';

const rawBase = (over: Record<string, unknown> = {}): Provider => ({
  id: 'acme',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  refresh: 'none',
  pkce: false,
  clientId: 'id',
  clientSecret: 'sec',
  ...over,
} as Provider);

// A minimal valid confidential OAuth provider; each test overrides the field under test.
const base = (over: Record<string, unknown> = {}) => defineProvider(rawBase(over));

// ---------------------------------------------------------------------------------------------------
// #211 (a) OAuth endpoint URLs are https-validated in defineProvider — not just databricks(). The token
// exchange POSTs the client secret to tokenUrl and is NOT behind the egress https gate, so a http://,
// userinfo-bearing, fragment-carrying, or ported endpoint would leak/downgrade the exchange.
// ---------------------------------------------------------------------------------------------------
test('defineProvider: a non-https tokenUrl is rejected (would leak the client secret in cleartext)', () => {
  assert.throws(() => base({ tokenUrl: 'http://acme.example/token' }), /tokenUrl must use https/);
});

test('defineProvider: a non-https authorizeUrl is rejected (downgrades the single-use state round-trip)', () => {
  assert.throws(() => base({ authorizeUrl: 'http://acme.example/auth' }), /authorizeUrl must use https/);
});

test('defineProvider: userinfo, a fragment, and an explicit port on an OAuth URL are all rejected', () => {
  assert.throws(() => base({ tokenUrl: 'https://user:pass@acme.example/token' }), /tokenUrl must not contain URL credentials/);
  assert.throws(() => base({ tokenUrl: 'https://@acme.example/token' }), /tokenUrl must not contain URL credentials/);
  assert.throws(() => base({ authorizeUrl: 'https://acme.example/auth#frag' }), /authorizeUrl must not contain a URL fragment/);
  assert.throws(() => base({ authorizeUrl: 'https://acme.example/auth#' }), /authorizeUrl must not contain a URL fragment/);
  assert.throws(() => base({ tokenUrl: 'https://acme.example\\token' }), /tokenUrl must be a valid URL/);
  assert.throws(() => base({ tokenUrl: 'https://acme.example:8443/token' }), /tokenUrl must not specify an explicit port/);
  assert.throws(() => base({ tokenUrl: 'https://acme.example:443/token' }), /tokenUrl must not specify an explicit port/);
  assert.throws(() => base({ tokenUrl: 'https://acme.example:/token' }), /tokenUrl.*canonical numeric port/);
  assert.throws(() => base({ tokenUrl: 'http://127.1:5000/token' }), /tokenUrl.*canonical hostname/);
  assert.throws(() => base({ tokenUrl: 'http://2130706433:5000/token' }), /tokenUrl.*canonical hostname/);
});

test('defineProvider: a non-https revokeUrl is rejected (the revoke POST carries the live token)', () => {
  assert.throws(() => base({ revokeUrl: 'http://acme.example/revoke' }), /revokeUrl must use https/);
  assert.doesNotThrow(() => base({ revokeUrl: 'https://acme.example/revoke' }));
});

test('defineProvider: refresh-capable revocation declares access/refresh/both/grant explicitly', () => {
  assert.throws(
    () => base({ refresh: 'rotating', revokeUrl: 'https://acme.example/revoke' }),
    /revokeTarget.*must declare/,
  );
  for (const revokeTarget of ['access', 'refresh', 'both', 'grant'] as const) {
    assert.equal(
      base({ refresh: 'rotating', revokeUrl: 'https://acme.example/revoke', revokeTarget }).revokeTarget,
      revokeTarget,
    );
  }
  assert.throws(() => base({ revokeTarget: 'access' }), /revokeTarget.*requires/);
  assert.throws(
    () => base({ refresh: 'none', revokeUrl: 'https://acme.example/revoke', revokeTarget: 'refresh' }),
    /cannot require a refresh token/,
  );
});

test('defineProvider: loopback OAuth endpoints may use http on an explicit port (the test-only local carve-out)', () => {
  // Mirrors the mock OAuth server used by the integration suite (http://127.0.0.1:<port>).
  assert.doesNotThrow(() => base({ authorizeUrl: 'http://127.0.0.1:5000/a', tokenUrl: 'http://127.0.0.1:5000/t' }));
  // IPv6 loopback (WHATWG brackets the host to [::1]) is exempt on the same terms.
  assert.doesNotThrow(() => base({ authorizeUrl: 'http://[::1]:5000/a', tokenUrl: 'http://[::1]:5000/t' }));
});

test('loopback carve-out is exposed only as a read-only predicate', () => {
  assert.equal(isLoopbackHost('127.0.0.1'), true);
  assert.equal(isLoopbackHost('[::1]'), true);
  assert.equal(isLoopbackHost('attacker.example'), false);
  assert.equal((isLoopbackHost as any).add, undefined, 'callers cannot mutate the canonical host set');
});

test('defineProvider: an unparseable OAuth URL is rejected with a field-named, secret-free error', () => {
  assert.throws(() => base({ tokenUrl: 'not a url' }), /tokenUrl must be a valid URL/);
});

test('defineProvider: a key provider (no OAuth) keeps empty URLs valid', () => {
  assert.doesNotThrow(() =>
    defineProvider({ id: 'k', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [], egressAllow: ['a'], refresh: 'none', pkce: false }),
  );
});

// ---------------------------------------------------------------------------------------------------
// #211 (c) authorizeParams cannot override a Vouchr-owned OAuth parameter (state / redirect_uri / …).
// ---------------------------------------------------------------------------------------------------
test('defineProvider: a reserved authorizeParams key (state) is rejected; a non-reserved one passes', () => {
  assert.throws(() => base({ authorizeParams: { state: 'attacker' } }), /authorizeParams.*Vouchr-owned/);
  assert.throws(() => base({ authorizeParams: { redirect_uri: 'https://evil.example' } }), /authorizeParams.*Vouchr-owned/);
  assert.doesNotThrow(() => base({ authorizeParams: { access_type: 'offline', prompt: 'consent' } }));
});

// ---------------------------------------------------------------------------------------------------
// #211 (g) provider ids are held to a conservative charset/length rule (they flow to env keys, audit,
// and Slack mrkdwn).
// ---------------------------------------------------------------------------------------------------
test('isValidProviderId: accepts boring ids, rejects hostile ones', () => {
  for (const ok of ['github', 'a.b', 'a-b', 'a_b', 'x1', 'A', 'a'.repeat(63)]) {
    assert.equal(isValidProviderId(ok), true, `should accept ${JSON.stringify(ok)}`);
  }
  for (const bad of ['', ' ', 'a b', 'a/b', '../x', '.leading', 'a\nb', 'você', 'a'.repeat(64)]) {
    assert.equal(isValidProviderId(bad), false, `should reject ${JSON.stringify(bad)}`);
  }
});

test('defineProvider: a hostile provider id is rejected before it reaches any sink', () => {
  assert.throws(() => base({ id: 'a/b' }), /invalid/);
  assert.throws(() => base({ id: '../evil' }), /invalid/);
  assert.throws(() => base({ id: '' }), /invalid/);
});

// ---------------------------------------------------------------------------------------------------
// #211 canonicalization: egress hosts/paths/methods are validated + normalized ONCE at definition, so
// the injector compares the normalized value (a mis-cased host / trailing-space method never silently
// fails to match at runtime).
// ---------------------------------------------------------------------------------------------------
test('defineProvider: egressAllow hosts are lower-cased; decorated hosts (scheme/port/path) are rejected', () => {
  assert.deepEqual(base({ egressAllow: ['API.Acme.Example'] }).egressAllow, ['api.acme.example']);
  assert.throws(() => base({ egressAllow: ['api.acme.example:443'] }), /invalid egressAllow host/);
  assert.throws(() => base({ egressAllow: ['https://api.acme.example'] }), /invalid egressAllow host/);
  assert.throws(() => base({ egressAllow: ['api.acme.example/repos'] }), /invalid egressAllow host/);
});

test('defineProvider: a non-canonical egressPaths entry is rejected; egressMethods are normalized', () => {
  assert.throws(() => base({ egressPaths: ['repos'] }), /invalid egressPaths entry/); // no leading slash
  assert.deepEqual(base({ egressMethods: [' get ', 'Post'] }).egressMethods, ['GET', 'POST']);
  assert.throws(() => base({ egressMethods: ['GE T'] }), /invalid egressMethods entry/);
});

// ---------------------------------------------------------------------------------------------------
// #211 (d) the registry rejects duplicate ids AND normalized env-key collisions (previously only the
// env loader did — a code-registered pair slipped through silently).
// ---------------------------------------------------------------------------------------------------
test('ProviderRegistry: a duplicate provider id is rejected, not silently shadowed', () => {
  assert.throws(() => new ProviderRegistry([base(), base()]), /duplicate provider id/);
});

test('ProviderRegistry: two ids that derive the same client-secret env key are rejected', () => {
  const key = (id: string) =>
    defineProvider({ id, credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [], egressAllow: ['a'], refresh: 'none', pkce: false });
  // "a.b" and "a-b" both normalize to VOUCHR_PROVIDER_A_B_CLIENT_* — a silent shared secret.
  assert.throws(() => new ProviderRegistry([key('a.b'), key('a-b')]), /same client-secret env key/);
});

// ---------------------------------------------------------------------------------------------------
// #211 the callback/redirect URL (baseUrl + callbackPath) is https + within the base origin.
// ---------------------------------------------------------------------------------------------------
test('assertCallbackUrl: https within the base origin passes; http / off-origin are rejected', () => {
  assert.doesNotThrow(() => assertCallbackUrl('https://broker.example', 'https://broker.example/oauth/callback'));
  assert.doesNotThrow(() => assertCallbackUrl('http://127.0.0.1:1', 'http://127.0.0.1:1/oauth/callback')); // loopback dev
  assert.throws(() => assertCallbackUrl('http://broker.example', 'http://broker.example/oauth/callback'), /must use https/);
  // An absolute off-origin callbackPath resolves to another host — the code would land there.
  assert.throws(() => assertCallbackUrl('https://broker.example', 'https://evil.example/cb'), /within the baseUrl origin/);
});

test('buildCallbackUrl: returns one canonical route and rejects ambiguous callback forms', () => {
  assert.equal(buildCallbackUrl('https://broker.example', '/oauth/callback'), 'https://broker.example/oauth/callback');
  assert.equal(buildCallbackUrl('http://127.0.0.1:3000', '/oauth/callback'), 'http://127.0.0.1:3000/oauth/callback');
  for (const path of ['', ' ', 'oauth/callback', 'https://evil.example/cb', '//evil.example/cb', '/a/../cb', '/cb?x=1', '/cb#x', '/oauth%20callback', '/oauth%2Fcallback', '/oauth%5ccallback', '/oauth\\callback']) {
    assert.throws(() => buildCallbackUrl('https://broker.example', path), /callbackPath/);
  }
  assert.throws(() => buildCallbackUrl('https://broker.example/base', '/cb'), /baseUrl/);
  assert.throws(() => buildCallbackUrl('https://broker.example/?', '/cb'), /baseUrl/);
});

test('ProviderRegistry: raw programmatic registrations cannot bypass defineProvider', () => {
  assert.throws(
    () => new ProviderRegistry([rawBase({ tokenUrl: 'http://attacker.example/token' })]),
    /tokenUrl must use https/,
  );
  assert.throws(
    () => new ProviderRegistry([rawBase({ egressAllow: undefined })]),
    /egressAllow/,
  );
});

test('ProviderRegistry: registration is an immutable defensive snapshot', () => {
  const original = rawBase();
  const registry = new ProviderRegistry([original]);
  original.tokenUrl = 'http://attacker.example/token';
  original.egressAllow.push('attacker.example');

  const stored = registry.get('acme');
  assert.equal(stored.tokenUrl, 'https://acme.example/token');
  assert.deepEqual(stored.egressAllow, ['api.acme.example']);
  assert.equal(Object.isFrozen(stored), true);
  assert.equal(Object.isFrozen(stored.egressAllow), true);
  assert.throws(() => stored.egressAllow.push('attacker.example'), TypeError);
});

test('ProviderRegistry: provider collection shape and size are bounded', () => {
  assert.doesNotThrow(() => new ProviderRegistry([]));
  assert.throws(() => new ProviderRegistry(null as any), /providers.*bounded array/);
  assert.throws(() => new ProviderRegistry(Array.from({ length: 129 }, (_, i) => rawBase({ id: `p${i}` }))), /providers.*bounded array/);
});

test('defineProvider: validates runtime enums, booleans, functions, and top-level unknown fields', () => {
  for (const [field, value] of [
    ['credential', 'cookie'], ['identity', 'robot'], ['refresh', 'eventually'], ['tokenAuth', 'header'],
    ['bodyFormat', 'xml'], ['revokeAuth', 'header'],
  ]) {
    assert.throws(() => base({ [field]: value }), new RegExp(field));
  }
  assert.throws(() => base({ pkce: 'yes' }), /pkce/);
  assert.throws(() => base({ publicClient: 'yes' }), /publicClient/);
  assert.throws(() => base({ refresh: null }), /refresh/);
  assert.throws(() => base({ inject: 'not-a-function' }), /inject/);
  assert.throws(() => base({ accountProbe: true }), /accountProbe/);
  assert.throws(() => base({ surprise: true }), /unknown field/);
});

test('defineProvider: validates scopes, descriptions, allowlists, and bounded collections', () => {
  assert.throws(() => base({ scopesDefault: 'scope' }), /scopesDefault/);
  assert.throws(() => base({ scopesDefault: null }), /scopesDefault/);
  assert.throws(() => base({ scopesDefault: [''] }), /scopesDefault/);
  assert.throws(() => base({ scopesDefault: [' scope'] }), /scopesDefault.*whitespace/);
  for (const scope of ['read admin', 'read\tadmin', 'read"admin', 'read\\admin']) {
    assert.throws(() => base({ scopesDefault: [scope] }), /one OAuth scope token per item/);
  }
  assert.throws(() => base({ scopesDefault: ['x', 'x'] }), /scopesDefault.*duplicates/);
  assert.throws(() => base({ scopesDefault: Array.from({ length: 49 }, (_, i) => `scope-${i}`) }), /bounded consent surface/);
  assert.throws(() => base({ scopeDescriptions: { x: ' ' } }), /scopeDescriptions/);
  assert.throws(() => base({ scopeDescriptions: { x: 'x'.repeat(513) } }), /scopeDescriptions.*bounded/);
  assert.throws(() => base({ scopeDescriptions: { ' x': 'Description' } }), /scopeDescriptions.*whitespace/);
  assert.throws(() => base({ authorizeParams: { ' prompt': 'consent' } }), /authorizeParams.*whitespace/);
  assert.throws(() => base({ egressAllow: [] }), /egressAllow/);
  assert.throws(() => base({ egressAllow: ['*.example.com'] }), /egressAllow/);
  assert.throws(() => base({ egressAllow: Array.from({ length: 129 }, (_, i) => `h${i}.example`) }), /egressAllow/);
});

test('defineProvider: nested declarative objects reject unknown keys and malformed values', () => {
  assert.throws(() => base({ egressResponse: { maxBytes: 1, typo: true } }), /egressResponse.*unknown key/);
  assert.throws(() => base({ egressResponse: { maxBytes: 1.5 } }), /invalid egressResponse\.maxBytes/);
  assert.throws(() => base({ rateLimit: { perMinute: 10, typo: true } }), /rateLimit.*unknown key/);
  assert.throws(() => base({ mcp: { paths: ['/mcp'], typo: true } }), /mcp.*unknown key/);
  assert.throws(() => base({ mcp: { paths: ['mcp'] } }), /mcp\.paths/);
  assert.throws(() => base({ approval: { approver: 'self', typo: true } }), /approval.*unknown key/);
  assert.throws(() => base({ approval: { approver: 'self', ttlMs: 1.5 } }), /approval\.ttlMs/);
  for (const field of ['egressPaths', 'mcp', 'approval'] as const) {
    const over = field === 'egressPaths'
      ? { egressPaths: ['/api/%2fadmin'] }
      : field === 'mcp'
        ? { mcp: { paths: ['/api/%5cadmin'] } }
        : { approval: { approver: 'self', paths: ['/api/%2Fadmin'] } };
    assert.throws(() => base(over), new RegExp(field));
  }
  for (const field of ['egressPaths', 'mcp', 'approval'] as const) {
    const nested = field === 'egressPaths'
      ? { egressPaths: ['/api/%252e%252e%252fadmin'] }
      : field === 'mcp'
        ? { mcp: { paths: ['/api/%252e%252e%252fadmin'] } }
        : { approval: { approver: 'self', paths: ['/api/%252e%252e%252fadmin'] } };
    assert.throws(() => base(nested), new RegExp(field));
  }
});

test('defineProvider: public-client and standard-revocation combinations fail closed', () => {
  assert.throws(() => base({ publicClient: true, pkce: false, clientSecret: undefined }), /public client.*PKCE/i);
  assert.throws(() => base({ publicClient: true, pkce: true, clientSecret: 'must-not-send' }), /clientSecret/);
  assert.throws(() => base({ publicClient: true, pkce: true, clientSecret: undefined, tokenAuth: 'basic' }), /public client.*Basic/i);
  assert.throws(() => base({ publicClient: true, pkce: true, clientSecret: undefined, revokeUrl: 'https://acme.example/revoke', revokeAuth: 'body' }), /revokeAuth/);
  assert.throws(() => base({ revokeAuth: 'body', revokeUrl: undefined }), /revokeAuth.*revokeUrl/);
  assert.doesNotThrow(() => base({ revokeUrl: 'https://acme.example/revoke', revoke: async () => {} }));
});

test('provider validation errors never reflect untrusted values', () => {
  const sentinel = 'ghp_SECRET_SENTINEL_123';
  for (const make of [
    () => base({ id: sentinel.repeat(4) }),
    () => base({ egressAllow: [sentinel] }),
    () => base({ authorizeParams: { state: sentinel } }),
    () => base({ [sentinel]: true }),
  ]) {
    let message = '';
    try { make(); } catch (error) { message = (error as Error).message; }
    assert.ok(message);
    assert.equal(message.includes(sentinel), false, message);
  }
});

test('built-in credential-bearing probes and GitHub revoke disable redirect following', async () => {
  const providers = [
    github({ clientId: 'id', clientSecret: 'secret' }),
    google({ clientId: 'id', clientSecret: 'secret' }),
    gitlab({ clientId: 'id', clientSecret: 'secret' }),
    notion({ clientId: 'id', clientSecret: 'secret' }),
  ];
  const real = globalThis.fetch;
  const calls: RequestInit[] = [];
  globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    calls.push(init ?? {});
    return new Response(null, { status: 302, headers: { location: 'https://attacker.example/capture' } });
  }) as typeof fetch;
  try {
    for (const provider of providers) assert.equal(await provider.accountProbe?.('live-token'), null);
    await assert.rejects(providers[0].revoke!(providers[0], 'live-token'), /HTTP 302/);
    assert.equal(calls.length, 5);
    assert.ok(calls.every((call) => call.redirect === 'manual'));
  } finally {
    globalThis.fetch = real;
  }
});

test('GitHub revoke encodes the client id as one URL path segment', async () => {
  const provider = github({ clientId: 'id/../?query', clientSecret: 'secret' });
  const real = globalThis.fetch;
  let requested = '';
  globalThis.fetch = (async (url: string | URL | Request) => {
    requested = String(url);
    return new Response(null, { status: 204 });
  }) as typeof fetch;
  try {
    await provider.revoke!(provider, 'live-token');
    assert.equal(requested, 'https://api.github.com/applications/id%2F..%2F%3Fquery/token');
  } finally {
    globalThis.fetch = real;
  }
});
