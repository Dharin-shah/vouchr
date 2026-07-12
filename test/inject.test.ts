import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle } from '../src/core/injector';
import { channelOwner } from '../src/core/owner';
import { defineProvider } from '../src/core/providers';

const KEY = randomBytes(32);
const tok = (t: string) => ({ accessToken: t, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

// A non-Bearer provider (x-api-key) injects via the custom hook, NOT Authorization.
test('Provider.inject: custom header instead of Authorization: Bearer', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = channelOwner('T1', 'C1');
  await vault.upsert(owner, 'custommcp', tok('SECRET_KEY'));
  const provider = defineProvider({
    id: 'custommcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
    inject: (h, s) => h.set('x-api-key', s),
  });

  const realFetch = globalThis.fetch;
  let seen: Headers | null = null;
  globalThis.fetch = (async (_u: any, init: any) => {
    seen = new Headers(init.headers);
    return new Response('ok', { status: 200 });
  }) as any;
  try {
    const acting = { enterpriseId: null, teamId: 'T1', userId: 'U' };
    await new ConnectionHandle(provider, owner, acting, vault, new Audit(db)).fetch('https://api.test/x');
    assert.equal(seen!.get('x-api-key'), 'SECRET_KEY'); // secret went to the custom header
    assert.equal(seen!.get('authorization'), null); // and NOT the default Bearer header
  } finally {
    globalThis.fetch = realFetch;
  }
});
