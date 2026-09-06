/**
 * The write gate on the Bolt path.
 *
 * Finding: `grep -c egressMethods src/adapters/bolt.ts` was 0. The Bolt surface applied NO
 * HTTP-method restriction, so a method-less provider such as `github()` accepted
 * `handle.fetch(url, { method: 'DELETE' })` with the user's full scopes, while the identical call
 * through the broker was a 405. Worse, there was no way to turn that off: `createBroker` has
 * `allowWrites`, `createVouchr` had no equivalent, so a read-only agent could not be locked down at
 * all.
 *
 * `allowWrites` now exists on both. It defaults to TRUE here — writing as the asking user is the
 * point of this surface, and `provider.approval` is how a sensitive write is gated — so the
 * transports still differ by default, deliberately and documented (guides/THREAT-MODEL.md, "Write
 * blast radius differs by transport"). What these tests pin down is that the lockdown works, that it
 * is applied at the one chokepoint every entry point routes through, and that an explicit provider
 * declaration is always honoured.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openTestDb } from './support/pg';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { Policy } from '../src/core/policy';
import { defineProvider, ProviderRegistry, readOnlyEgress, withEgressDefaults, type Provider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';
import { ConnectContext, createVouchr } from '../src/adapters/bolt';

const KEY = Buffer.alloc(32, 7);
const U1: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const SECRET_TOKEN = 'tok-parity-must-never-appear';

/** A provider that declares NO egressMethods — the shape the finding hinged on. */
function methodless(): Provider {
  return defineProvider({
    approval: false,
    id: 'acme',
    authorizeUrl: 'https://acme.example/authorize',
    tokenUrl: 'https://acme.example/token',
    clientId: 'cid',
    clientSecret: 'csec',
    scopesDefault: ['read'],
    egressAllow: ['api.acme.example'],
    refresh: 'none',
    pkce: false,
  });
}

function stubUpstream() {
  const real = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as typeof fetch;
  return { restore: () => { globalThis.fetch = real; } };
}

async function boltVerdict(
  db: Awaited<ReturnType<typeof openTestDb>>,
  vault: Vault,
  provider: Provider,
  method: string,
  allowWrites?: boolean,
): Promise<'allowed' | 'denied'> {
  const deps = {
    identity: U1,
    channel: null, // DM: ungoverned, so the channel tool allowlist is not what decides this test
    client: {} as never,
    registry: new ProviderRegistry([provider]),
    vault,
    audit: new Audit(db),
    consent: new Consent(db),
    policy: new Policy(),
    redirectUri: 'http://x',
  };
  const ctx = new ConnectContext(allowWrites === undefined ? deps : { ...deps, allowWrites });
  const handle = await ctx.connect(provider.id);
  try {
    await handle.fetch('https://api.acme.example/x', { method });
    return 'allowed';
  } catch (e) {
    assert.match(String(e), /is not allowed/, 'denial must be the method gate, not an unrelated error');
    return 'denied';
  }
}

test('allowWrites:false pins a method-less provider to GET/HEAD on the Bolt path', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const provider = methodless();
  await vault.upsert(userOwner(U1), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const up = stubUpstream();
  try {
    assert.equal(await boltVerdict(db, vault, provider, 'GET', false), 'allowed');
    for (const method of ['POST', 'DELETE', 'PUT', 'PATCH']) {
      assert.equal(
        await boltVerdict(db, vault, provider, method, false),
        'denied',
        `${method} must be refused when allowWrites is false`,
      );
    }
  } finally {
    up.restore();
  }
});

test('the default stays permissive, so existing write agents keep working', async (t) => {
  // Documents the deliberate asymmetry rather than leaving it implicit: this is the behaviour the
  // approval feature (provider.approval) is built on top of. If this ever flips, it is a breaking
  // change and this test is where it gets noticed.
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const provider = methodless();
  await vault.upsert(userOwner(U1), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const up = stubUpstream();
  try {
    assert.equal(await boltVerdict(db, vault, provider, 'POST'), 'allowed', 'omitted → permissive');
    assert.equal(await boltVerdict(db, vault, provider, 'POST', true), 'allowed', 'explicit true');
  } finally {
    up.restore();
  }
});

test('an explicit provider egressMethods is honoured whatever allowWrites says', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  // Declares GET+POST: POST is permitted, DELETE never is — the provider's own declaration is the
  // narrower gate and the lockdown flag must not widen it.
  const provider = defineProvider({ ...methodless(), egressMethods: ['GET', 'POST'] } as Provider);
  await vault.upsert(userOwner(U1), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const up = stubUpstream();
  try {
    assert.equal(await boltVerdict(db, vault, provider, 'POST', true), 'allowed');
    assert.equal(await boltVerdict(db, vault, provider, 'DELETE', true), 'denied');
    assert.equal(await boltVerdict(db, vault, provider, 'DELETE', false), 'denied');
  } finally {
    up.restore();
  }
});

test('createVouchr({ allowWrites: false }) reaches the handle the middleware hands to a handler', async (t) => {
  // TEST-2: driven through the PUBLIC API, not by constructing ConnectContext directly. The
  // hand-built tests above all inject `allowWrites` into deps, so they passed while the option was
  // wired into contextFor() (the modal-submit context) and NOT into the middleware's contextDeps —
  // making createVouchr({ allowWrites: false }) a silent no-op on the only path that calls fetch.
  // This test fails against that bug.
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const provider = methodless();
  const vouchr = await createVouchr({
    providers: [provider], baseUrl: 'https://vouchr.test', db, allowWrites: false,
  });
  await vouchr.vault.upsert(userOwner(U1), provider.id, {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  // Run the middleware exactly as Bolt would for a 1:1 DM (ungoverned, so no channel enable needed).
  const context: Record<string, unknown> = {};
  await vouchr.middleware({
    context,
    client: { chat: { postEphemeral: async () => undefined, postMessage: async () => undefined } },
    event: { channel: 'D0PERSONAL', channel_type: 'im', user: 'U1', team: 'T1' },
    next: async () => {},
  } as never);

  const handle = await (context.vouchr as ConnectContext).connect(provider.id);
  const up = stubUpstream();
  try {
    await assert.rejects(
      () => handle.fetch('https://api.acme.example/x', { method: 'DELETE' }),
      /is not allowed/,
      'allowWrites:false must reach the handle the host actually uses',
    );
    assert.equal((await handle.fetch('https://api.acme.example/x')).status, 200, 'GET still works');
  } finally {
    up.restore();
  }
});

test('allowWrites:false narrows a provider that DECLARES writes — not just an undeclared one', async (t) => {
  // The hole this closes: `withEgressDefaults` only supplies a DEFAULT, so a provider declaring its
  // own methods kept them. `databricks()` declares ['GET','POST'], so `allowWrites: false` would
  // have left statement-submission POST open on a deployment that explicitly asked to be read-only —
  // exactly the injected-write the flag exists to stop. readOnlyEgress INTERSECTS instead.
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const provider = defineProvider({ ...methodless(), egressMethods: ['GET', 'POST'] } as Provider);
  await vault.upsert(userOwner(U1), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  const up = stubUpstream();
  try {
    assert.equal(await boltVerdict(db, vault, provider, 'POST', false), 'denied', 'a DECLARED write must be refused under lockdown');
    assert.equal(await boltVerdict(db, vault, provider, 'GET', false), 'allowed', 'reads still work');
    assert.equal(await boltVerdict(db, vault, provider, 'POST', true), 'allowed', 'and the declaration still stands when writes are on');
  } finally {
    up.restore();
  }
});

test('readOnlyEgress intersects rather than replacing, so it can never widen a provider', () => {
  const base = methodless();
  // Undeclared → the read-only floor.
  assert.deepEqual(readOnlyEgress(base).egressMethods, ['GET', 'HEAD']);
  // Declares a write → the write is dropped, the read kept.
  assert.deepEqual(readOnlyEgress({ ...base, egressMethods: ['GET', 'POST'] } as Provider).egressMethods, ['GET']);
  // Declares GET only → must NOT be widened to include HEAD.
  assert.deepEqual(readOnlyEgress({ ...base, egressMethods: ['GET'] } as Provider).egressMethods, ['GET']);
  // Write-only provider → nothing is permitted, which is the right answer for "run this read-only".
  assert.deepEqual(readOnlyEgress({ ...base, egressMethods: ['POST'] } as Provider).egressMethods, []);
});

test('both transports share one rule, so a declared provider is never silently widened', () => {
  // The core helper is the single source of truth both adapters call (STR-2). The broker passes
  // `allowWrites`; Bolt passes `!allowWrites`, because the broker already denies non-GET at its
  // route and this path has no route to deny at. Either way an undeclared provider gets the floor
  // and a declared one keeps its own list.
  const p = methodless();
  assert.deepEqual(withEgressDefaults(p, true).egressMethods, ['GET', 'HEAD'], 'undeclared → floor');
  assert.equal(withEgressDefaults(p, false).egressMethods, undefined, 'not pinned when not asked');
  const declared = { ...p, egressMethods: ['GET', 'POST'] } as Provider;
  assert.deepEqual(
    withEgressDefaults(declared, true).egressMethods, ['GET', 'POST'],
    'an explicit declaration is never overwritten',
  );
});
