/**
 * SEC-1 regression: the objects Vouchr hands to host code must not serialize into the secrets they
 * depend on.
 *
 * TypeScript's `private` is erased at compile time, so `private vault: Vault` is an ordinary own
 * ENUMERABLE property at runtime. Before `hideInternals`, `JSON.stringify(handle)` walked
 * vault → master key, provider → OAuth client secret, and db → connection password, which put the
 * key to the entire credential store into any structured log line, error dump, or agent tool
 * result that serialized the handle. That directly contradicts the product's core claim.
 *
 * These tests assert the property through EVERY enumeration path a logger or host might use, not
 * just `JSON.stringify` — a `toJSON()` shim would pass the first assertion and still leak through
 * an object spread or `Object.entries`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { openTestDb } from './support/pg';
import { WebClient } from '@slack/web-api';
import { ConnectionHandle } from '../src/core/injector';
import { ConnectContext } from '../src/adapters/bolt';
import { Vault } from '../src/core/vault';
import { Consent } from '../src/core/consent';
import { Policy } from '../src/core/policy';
import { defineHidden, hideInternals } from '../src/core/redact';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { Db } from '../src/core/db';
import type { SlackIdentity } from '../src/core/identity';
import type { Audit } from '../src/core/audit';

/** Distinctive, greppable stand-ins: a match anywhere in the output is unambiguous. */
const MASTER_KEY_BYTE = 0xab; // 171 — how a Buffer renders in JSON.stringify
const CLIENT_SECRET = 'CANARY-oauth-client-secret-2f7a';
const DB_PASSWORD = 'CANARY-postgres-password-9c31';
// Deliberately not shaped like a real Slack token: a committed fixture matching a provider's token
// grammar trips secret scanners and violates SEC-1. Detection here only needs a unique string.
const BOT_TOKEN = 'CANARY-slack-bot-token-4e88';

const SECRETS = [CLIENT_SECRET, DB_PASSWORD, BOT_TOKEN];

function fakeDb(): Db {
  // Shaped like the real thing where it matters: the pg Pool carries the connection string, which
  // is where the database password actually lives on a live deployment.
  return {
    pool: { options: { connectionString: `postgres://vouchr:${DB_PASSWORD}@localhost:5432/vouchr` } },
    query: async () => ({ rows: [] }),
  } as unknown as Db;
}

function fakeProvider() {
  return defineProvider({
    id: 'canary',
    authorizeUrl: 'https://example.test/authorize',
    tokenUrl: 'https://example.test/token',
    clientId: 'canary-client-id',
    clientSecret: CLIENT_SECRET,
    scopesDefault: ['read'],
    egressAllow: ['api.example.test'],
    refresh: 'none',
    pkce: false,
  });
}

function fakeIdentity(): SlackIdentity {
  return { teamId: 'T1', userId: 'U1', enterpriseId: null } as SlackIdentity;
}

/** Every way a host or logger might turn an object into text or a plain object. */
function enumerations(o: object): Record<string, string> {
  return {
    'JSON.stringify': JSON.stringify(o) ?? '',
    'util.inspect(depth:null)': inspect(o, { depth: null }),
    'object spread': JSON.stringify({ ...o }) ?? '',
    'Object.entries': JSON.stringify(Object.entries(o)) ?? '',
    'Object.values': JSON.stringify(Object.values(o)) ?? '',
    // How pino/winston-style serializers walk a value.
    'own enumerable keys': Object.keys(o).join(','),
  };
}

function assertNoSecrets(o: object, label: string): void {
  for (const [how, text] of Object.entries(enumerations(o))) {
    for (const secret of SECRETS) {
      assert.ok(
        !text.includes(secret),
        `${label} leaked a secret via ${how}: found ${secret.slice(0, 18)}…`,
      );
    }
    // The master key is a Buffer; JSON renders it as a byte array, inspect as <Buffer ab ab …>.
    assert.ok(
      !/171\s*,\s*171\s*,\s*171/.test(text),
      `${label} leaked master-key bytes via ${how} (JSON Buffer form)`,
    );
    assert.ok(
      !/<Buffer ab ab ab/.test(text),
      `${label} leaked master-key bytes via ${how} (inspect Buffer form)`,
    );
  }
}

test('hideInternals makes every own property non-enumerable but still readable', () => {
  const o = { a: 1, b: 'two' };
  hideInternals(o);
  assert.deepEqual(Object.keys(o), [], 'no own enumerable keys remain');
  assert.equal(JSON.stringify(o), '{}');
  assert.equal(o.a, 1, 'direct reads still work');
  o.a = 5;
  assert.equal(o.a, 5, 'fields stay writable');
  assert.ok(Object.getOwnPropertyNames(o).includes('a'), 'the property still exists');
});

test('Vault does not serialize the master key or the database password', () => {
  const vault = new Vault(fakeDb(), Buffer.alloc(32, MASTER_KEY_BYTE));
  assertNoSecrets(vault, 'Vault');
});

test('ConnectionHandle does not serialize the master key, client secret, or database password', () => {
  const db = fakeDb();
  const vault = new Vault(db, Buffer.alloc(32, MASTER_KEY_BYTE));
  const audit = { record: async () => undefined } as unknown as Audit;
  const handle = new ConnectionHandle(
    fakeProvider(),
    userOwner(fakeIdentity()),
    fakeIdentity(),
    vault,
    audit,
  );
  assertNoSecrets(handle, 'ConnectionHandle');
});

test('a handle nested inside a host error payload still does not leak', () => {
  // The realistic failure: a handler catches, attaches context, and hands the whole thing to a
  // structured logger. The handle must stay opaque one level down, too.
  const vault = new Vault(fakeDb(), Buffer.alloc(32, MASTER_KEY_BYTE));
  const handle = new ConnectionHandle(
    fakeProvider(),
    userOwner(fakeIdentity()),
    fakeIdentity(),
    vault,
    { record: async () => undefined } as unknown as Audit,
  );
  assertNoSecrets({ msg: 'provider call failed', ctx: { handle } }, 'nested handle payload');
});

test('ConnectContext does not serialize the Slack bot token or any credential material', () => {
  // ConnectContext is attached to Bolt's per-request `context.vouchr`, so it is the object a host
  // handler is most likely to dump on error — and it additionally holds a WebClient carrying the
  // Slack bot token. It must not rely on ConnectionHandle's coverage.
  const db = fakeDb();
  const ctx = new ConnectContext({
    identity: fakeIdentity(),
    channel: 'C1',
    client: new WebClient(BOT_TOKEN),
    registry: new ProviderRegistry([fakeProvider()]),
    vault: new Vault(db, Buffer.alloc(32, MASTER_KEY_BYTE)),
    audit: { record: async () => undefined } as unknown as Audit,
    consent: new Consent(db),
    policy: new Policy(),
    redirectUri: 'https://example.test/vouchr/oauth/callback',
  });
  assertNoSecrets(ctx, 'ConnectContext');
});

test('a handle returned from connect() keeps no enumerable own key after its fetch is wrapped', () => {
  // The Bolt adapter wraps `handle.fetch` twice to attach Slack surfaces. A plain assignment would
  // shadow the prototype method with an own ENUMERABLE property, putting the handle back into
  // Object.keys/spread/inspect output after the constructor had already hidden everything.
  const vault = new Vault(fakeDb(), Buffer.alloc(32, MASTER_KEY_BYTE));
  const handle = new ConnectionHandle(
    fakeProvider(), userOwner(fakeIdentity()), fakeIdentity(), vault,
    { record: async () => undefined } as unknown as Audit,
  );
  const original = handle.fetch.bind(handle);
  defineHidden(handle, 'fetch', async (i: string, init: RequestInit = {}) => original(i, init));
  assert.deepEqual(Object.keys(handle), [], 'wrapping must not add an enumerable own key');
  assert.deepEqual(Object.keys({ ...handle }), [], 'nor survive a spread');
  assert.equal(typeof handle.fetch, 'function', 'and the wrapper is still callable');
});

test('the real database handle does not serialize its connection string', async (t) => {
  // createVouchr returns `db` to the host, and PgDb holds the password in `connectionString`.
  // Uses a real handle rather than a fake, because the field being hidden is PgDb's own.
  const db = await openTestDb(t);
  const text = `${JSON.stringify(db) ?? ''}${inspect(db, { depth: null })}${Object.keys(db).join(',')}`;
  assert.ok(!/:\/\/[^@\s"]*:[^@\s"]+@/.test(text), `a password-bearing URL leaked from the Db: ${text.slice(0, 200)}`);
  assert.deepEqual(Object.keys(db), [], 'the Db exposes no enumerable own properties');
});

test('a field declared but assigned only later stays hidden', () => {
  // hideInternals can only hide what exists when the constructor ends. This holds ONLY under
  // `useDefineForClassFields: true` (now pinned in tsconfig.json): with define semantics a declared
  // field is materialised as undefined at construction, so it is hidden then and STAYS hidden when
  // written later. Flip that flag and lazily-assigned fields such as PgDb.refreshPool would reappear
  // in JSON.stringify with the rest of the suite still green — this test is what goes red.
  class Lazy {
    private eager = 'e';
    private lazy?: string; // declared, NOT assigned in the constructor
    constructor() { hideInternals(this); }
    fill(v: string) { this.lazy = v; }
    read() { return `${this.eager}${this.lazy ?? ''}`; }
  }
  const o = new Lazy();
  assert.deepEqual(Object.keys(o), [], 'nothing enumerable after construction');
  o.fill(DB_PASSWORD);
  assert.deepEqual(Object.keys(o), [], 'a lazily-assigned field must not become enumerable');
  assert.ok(!(JSON.stringify(o) ?? '').includes(DB_PASSWORD), 'and must not serialize');
  assert.ok(o.read().includes(DB_PASSWORD), 'while staying readable internally');
});

test('PgDb.refreshPool stays hidden when withRefreshLock assigns it lazily', async (t) => {
  // The REAL lazy-assignment path, not a synthetic stand-in: `private refreshPool?: Pool` is declared
  // but only assigned inside withRefreshLocks. Raised in review as a suspected hole — if that first
  // write created a fresh own property it would be ENUMERABLE, and util.inspect/spread/structured
  // logging could then walk into the Pool's options and out through its password-bearing
  // connectionString. It does not, because a declared class field is materialised at construction
  // (define semantics, pinned via useDefineForClassFields) and hideInternals covers it there; the
  // later write reuses that non-enumerable slot. This test is what fails if that pin is ever removed.
  const db = await openTestDb(t) as unknown as {
    refreshPool?: unknown;
    withRefreshLock: (k: string, fn: () => Promise<void>) => Promise<void>;
  };
  assert.ok(Object.getOwnPropertyNames(db).includes('refreshPool'), 'the field exists at construction');
  assert.deepEqual(Object.keys(db), [], 'nothing enumerable after construction');
  await db.withRefreshLock('no-secret-serialization-probe', async () => {});
  assert.ok(db.refreshPool, 'withRefreshLock really did assign it (otherwise this proves nothing)');
  assert.deepEqual(Object.keys(db), [], 'the lazily-assigned pool must not become enumerable');
  const text = `${JSON.stringify(db) ?? ''}${inspect(db, { depth: null })}${JSON.stringify({ ...db }) ?? ''}`;
  assert.ok(!/:\/\/[^@\s"]*:[^@\s"]+@/.test(text), 'no password-bearing URL may escape via the pool');
});

test('the canaries are actually reachable when NOT hidden (the test can fail)', () => {
  // Guards against the suite passing because the secrets were never wired in. This mirrors the
  // pre-fix structure: a plain holder with enumerable references to the same dependency graph.
  // The raw Buffer is here on purpose: without it the two master-key regexes in assertNoSecrets are
  // never shown to be capable of firing, and a typo in either would make them permanently vacuous.
  const leaky = { provider: fakeProvider(), key: Buffer.alloc(32, MASTER_KEY_BYTE), token: BOT_TOKEN };
  const text = JSON.stringify(leaky) ?? '';
  assert.ok(text.includes(CLIENT_SECRET), 'client secret is reachable without hiding');
  assert.ok(text.includes(BOT_TOKEN), 'bot token is reachable without hiding');
  assert.match(text, /171\s*,\s*171\s*,\s*171/, 'the JSON Buffer form is detectable');
  assert.match(inspect(leaky, { depth: null }), /<Buffer ab ab ab/, 'the inspect Buffer form is detectable');
  assert.throws(
    () => assertNoSecrets(leaky, 'deliberately leaky holder'),
    /leaked a secret/,
    'assertNoSecrets must actually detect a leak',
  );
});
