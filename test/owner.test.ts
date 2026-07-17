import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import {
  ConnectionHandle,
  ResolverConfigurationError,
  ResolverFailedError,
  type VouchrEvent,
} from '../src/core/injector';
import { offboardUser } from '../src/core/offboard';
import { Consent } from '../src/core/consent';
import { userOwner, channelOwner } from '../src/core/owner';
import { defineProvider } from '../src/core/providers';
import { mapSafeError, UpstreamTimeoutError } from '../src/core/errors';

const KEY = randomBytes(32);
const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

// T3 + invariant 4: a user cred and a channel cred sharing an id string, and the same channel
// id in another team, are all independently addressable. No lookup satisfies another's.
test('owner isolation: (team,channel) vs (team,user) vs (otherTeam,channel) never cross', async (t) => {
  const vault = new Vault(await openTestDb(t), KEY);
  await vault.upsert(channelOwner('T1', 'X'), 'p', tok('chan-T1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p', tok('user-T1'));
  await vault.upsert(channelOwner('T2', 'X'), 'p', tok('chan-T2'));

  assert.equal((await vault.get(channelOwner('T1', 'X'), 'p'))?.accessToken, 'chan-T1');
  assert.equal((await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p'))?.accessToken, 'user-T1');
  assert.equal((await vault.get(channelOwner('T2', 'X'), 'p'))?.accessToken, 'chan-T2');
  // A channel lookup must never resolve to the same-id user cred or a foreign team's channel.
  assert.notEqual((await vault.get(channelOwner('T1', 'X'), 'p'))?.accessToken, 'user-T1');
  assert.equal(await vault.get(channelOwner('T3', 'X'), 'p'), null); // unknown team → nothing
});

// The AWS-delegate model: a referenced secret lives in an external manager. We persist only a
// non-secret ref; the resolver produces the secret JIT at injection; it is never stored.
test('referenced secret-source: resolved JIT, injected, never persisted', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const owner = channelOwner('T1', 'C_FIN');
  const reference = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/owner-test';
  await vault.reference(owner, 'mcp', { source: 'aws-sm', secretRef: reference });

  // The secret itself appears nowhere in the row. Only the ARN ref does.
  const row = await db.get('SELECT access_token_enc, secret_ref, source FROM connection') as any;
  assert.equal(row.access_token_enc, null);
  assert.equal(row.source, 'aws-sm');
  assert.equal(row.secret_ref, reference);

  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });

  const realFetch = globalThis.fetch;
  let seenAuth: string | null = null;
  let resolvedWith: string | null = null;
  const resolvers = { 'aws-sm': async (ref: string) => { resolvedWith = ref; return 'SECRET_FROM_AWS'; } };
  globalThis.fetch = (async (_u: any, init: any) => {
    seenAuth = new Headers(init.headers).get('authorization');
    return new Response('ok', { status: 200 });
  }) as any;
  try {
    const acting = { enterpriseId: null, teamId: 'T1', userId: 'Uacting' };
    const handle = new ConnectionHandle(provider, owner, acting, vault, audit, resolvers);
    await handle.fetch('https://api.test/thing');
    assert.equal(resolvedWith, reference); // resolver got the ref
    assert.equal(seenAuth, 'Bearer SECRET_FROM_AWS'); // resolved secret injected at the boundary
    // The resolved secret was never written back to the DB.
    const after = await db.get('SELECT access_token_enc FROM connection') as any;
    assert.equal(after.access_token_enc, null);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('referenced secret-source: missing resolver fails closed (no silent skip)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = channelOwner('T1', 'C1');
  await vault.reference(owner, 'mcp', { source: 'aws-sm', secretRef: 'arn:x' });
  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  const handle = new ConnectionHandle(provider, owner, { enterpriseId: null, teamId: 'T1', userId: 'U' }, vault, new Audit(db), {});
  await assert.rejects(
    () => handle.fetch('https://api.test/x'),
    (error: unknown) => error instanceof ResolverConfigurationError
      && error.message === 'External credential resolver is not configured correctly.',
  );
});

test('referenced secret-source: resolver failures never expose resolver text or the reference', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = channelOwner('T1', 'C1');
  const reference = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/error-test';
  const sentinel = 'ghp_RESOLVER_ERROR_SECRET_SENTINEL';
  await vault.reference(owner, 'mcp', { source: 'aws-sm', secretRef: reference });
  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  const handle = new ConnectionHandle(
    provider,
    owner,
    { enterpriseId: null, teamId: 'T1', userId: 'U' },
    vault,
    new Audit(db),
    { 'aws-sm': async () => { throw new Error(`${sentinel}:${reference}`); } },
  );

  await assert.rejects(
    () => handle.fetch('https://api.test/x'),
    (error: unknown) => {
      assert.ok(error instanceof ResolverFailedError);
      assert.equal(error.message, 'External credential resolution failed.');
      assert.ok(!error.message.includes(sentinel));
      assert.ok(!error.message.includes(reference));
      return true;
    },
  );
});

test('referenced secret-source: invalid fulfilled resolver values fail closed before provider egress', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = channelOwner('T1', 'C1');
  const reference = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/invalid-output';
  await vault.reference(owner, 'mcp', { source: 'aws-sm', secretRef: reference });
  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  let providerCalls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => { providerCalls++; return new Response('unexpected'); }) as any;
  try {
    for (const value of [undefined, 42, '', { secret: 'ghp_invalid_resolver_value' }] as const) {
      const events: VouchrEvent[] = [];
      const handle = new ConnectionHandle(
        provider,
        owner,
        { enterpriseId: null, teamId: 'T1', userId: 'U' },
        vault,
        new Audit(db),
        { 'aws-sm': (async () => value) as any },
        new Map(),
        (event) => events.push(event),
      );
      await assert.rejects(
        () => handle.fetch('https://api.test/x'),
        (error: unknown) => error instanceof ResolverConfigurationError
          && error.message === 'External credential resolver is not configured correctly.'
          && !error.message.includes('ghp_invalid_resolver_value'),
      );
      assert.equal(
        events.filter((event) => event.type === 'resolver_failed').length,
        0,
        'invalid fulfilled output is configuration state, not a retryable resolver outage',
      );
    }
    assert.equal(providerCalls, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('referenced secret-source: resolver deadline is retryable failure while explicit caller cancellation propagates', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = channelOwner('T1', 'C1');
  await vault.reference(owner, 'mcp', {
    source: 'aws-sm',
    secretRef: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/hung-resolver',
  });
  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  let providerCalls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => { providerCalls++; return new Response('unexpected'); }) as any;
  const handle = (deadlineMs: number) => new ConnectionHandle(
    provider,
    owner,
    { enterpriseId: null, teamId: 'T1', userId: 'U' },
    vault,
    new Audit(db),
    { 'aws-sm': async () => await new Promise<string>(() => undefined) },
    new Map(),
    () => {},
    () => {},
    null,
    undefined,
    () => {},
    null,
    null,
    false,
    deadlineMs,
  );
  try {
    await assert.rejects(
      () => handle(25).fetch('https://api.test/x'),
      (error: unknown) => error instanceof ResolverFailedError,
    );

    const caller = new AbortController();
    const cancelled = handle(1_000).fetch('https://api.test/x', { signal: caller.signal });
    await new Promise((resolve) => setImmediate(resolve));
    caller.abort();
    await assert.rejects(
      cancelled,
      (error: unknown) => error instanceof Error
        && error.name === 'AbortError'
        && !(error instanceof ResolverFailedError),
    );

    await assert.rejects(
      () => handle(1_000).fetch('https://api.test/x', { signal: AbortSignal.timeout(25) }),
      (error: unknown) => error instanceof Error
        && error.name === 'TimeoutError'
        && !(error instanceof ResolverFailedError),
    );
    assert.equal(providerCalls, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('direct handle maps only its own provider deadline to upstream_timeout', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = channelOwner('T1', 'C1');
  await vault.upsert(owner, 'mcp', tok('provider-token'));
  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  const handle = new ConnectionHandle(
    provider,
    owner,
    { enterpriseId: null, teamId: 'T1', userId: 'U' },
    vault,
    new Audit(db),
    {},
    new Map(),
    () => {},
    () => {},
    null,
    undefined,
    () => {},
    null,
    null,
    false,
    25,
  );
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (_input, init) => {
    await new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
    });
    return new Response('unreachable');
  }) as typeof fetch;
  try {
    await assert.rejects(
      () => handle.fetch('https://api.test/x'),
      (error: unknown) => {
        assert.ok(error instanceof UpstreamTimeoutError);
        assert.deepEqual(mapSafeError(error), {
          code: 'upstream_timeout',
          message: 'The upstream request timed out. Its outcome may be unknown; do not retry automatically.',
          retryable: false,
          recovery: 'retry_later',
        });
        return true;
      },
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

// T5: offboarding a member who linked a shared channel cred must NOT delete the channel's cred,
// and `/vouchr status` (listForUser) must never surface it.
test('offboard leaves channel-owned creds; status never lists them', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const id = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  await vault.upsert(userOwner(id), 'github', tok('mine'));
  await vault.upsert(channelOwner('T1', 'C_FIN'), 'mcp', tok('channel-key'));

  assert.deepEqual((await vault.listForUser(id)).map((c) => c.provider), ['github']); // channel cred not listed
  assert.deepEqual(await offboardUser(vault, audit, consent, id), ['github']);
  assert.equal(await vault.get(userOwner(id), 'github'), null); // user cred gone
  assert.equal((await vault.get(channelOwner('T1', 'C_FIN'), 'mcp'))?.accessToken, 'channel-key'); // channel survives
});

// T9: a shared-channel-cred injection audits the ACTING human, never the channel.
test('audit attribution: shared-cred injection records the acting user, not the channel', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const owner = channelOwner('T1', 'C_FIN');
  await vault.upsert(owner, 'mcp', tok('shared'));
  const provider = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
  try {
    const acting = { enterpriseId: null, teamId: 'T1', userId: 'U_HUMAN' };
    await new ConnectionHandle(provider, owner, acting, vault, audit).fetch('https://api.test/x');
    const row = await db.get(`SELECT user_id FROM audit WHERE action='inject'`) as any;
    assert.equal(row.user_id, 'U_HUMAN'); // the human who acted, not 'C_FIN'
  } finally {
    globalThis.fetch = realFetch;
  }
});
