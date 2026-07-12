import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defineProvider, ProviderRegistry, isValidProviderId, assertCallbackUrl } from '../src/core/providers';

// A minimal valid confidential OAuth provider; each test overrides the field under test.
const base = (over: Record<string, unknown> = {}) =>
  defineProvider({
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
  } as any);

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
  assert.throws(() => base({ authorizeUrl: 'https://acme.example/auth#frag' }), /authorizeUrl must not contain a URL fragment/);
  assert.throws(() => base({ tokenUrl: 'https://acme.example:8443/token' }), /tokenUrl must not specify an explicit port/);
});

test('defineProvider: a non-https revokeUrl is rejected (the revoke POST carries the live token)', () => {
  assert.throws(() => base({ revokeUrl: 'http://acme.example/revoke' }), /revokeUrl must use https/);
  assert.doesNotThrow(() => base({ revokeUrl: 'https://acme.example/revoke' }));
});

test('defineProvider: loopback OAuth endpoints may use http on an explicit port (the test-only local carve-out)', () => {
  // Mirrors the mock OAuth server used by the integration suite (http://127.0.0.1:<port>).
  assert.doesNotThrow(() => base({ authorizeUrl: 'http://127.0.0.1:5000/a', tokenUrl: 'http://127.0.0.1:5000/t' }));
  // IPv6 loopback (WHATWG brackets the host to [::1]) is exempt on the same terms.
  assert.doesNotThrow(() => base({ authorizeUrl: 'http://[::1]:5000/a', tokenUrl: 'http://[::1]:5000/t' }));
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
  assert.throws(() => base({ authorizeParams: { state: 'attacker' } }), /reserved authorizeParams key "state"/);
  assert.throws(() => base({ authorizeParams: { redirect_uri: 'https://evil.example' } }), /reserved authorizeParams key "redirect_uri"/);
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
  assert.throws(() => new ProviderRegistry([base(), base()]), /duplicate provider id "acme"/);
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
