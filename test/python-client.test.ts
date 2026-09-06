// #278 — the stdlib-only Python example is proven against a REAL broker, not a mock: an in-process
// createBroker (wired as test/broker.test.ts does) serves loopback HTTP, the example CLI runs as a
// genuine `python3` child, and provider egress is stubbed by the same
// test/support/broker-upstream-stub.mjs the two-process bridge test preloads (TEST-3). Identity
// tokens are minted HERE — the TypeScript, trusted-minter side — and handed to the child on stdin,
// one per call, exactly the minter/worker split production keeps.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { openTestDb } from './support/pg';
import { listen } from './support/http';
import { identityConfig, mintIdentity } from './support/identity';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { createBroker } from '../src/adapters/http/broker';

const KEY = randomBytes(32);
const SECRET = 'python-client-secret';
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK';
const CLIENT = path.join(__dirname, '..', 'examples', 'python-client', 'vouchr_client.py');
const STUB = pathToFileURL(path.join(__dirname, 'support', 'broker-upstream-stub.mjs')).href;
// burst 1 at 60/min: one call empties the bucket and it refills one request per second, so a call
// inside that second is a real 429 whose retryAfterMs is under a second — a short, genuine retry.
// A POST needs a human decision (`approval`), which is what the #296 backchannel commands initiate/poll.
const bridge = defineProvider({
  id: 'bridge', authorizeUrl: 'https://bridge.test/auth', tokenUrl: 'https://bridge.test/token',
  scopesDefault: ['x'], egressAllow: ['api.bridge.test'], egressMethods: ['GET', 'POST'],
  approval: { approver: 'self' }, refresh: 'none', pkce: false, clientId: 'id', clientSecret: 'sec',
  rateLimit: { perMinute: 60, burst: 1 },
});
const python = spawnSync('python3', ['--version']).status === 0;

/** Run the example CLI as a real child. Tokens go in on stdin, one per line, as the minter would pipe them. */
function runClient(port: number, args: string[], tokens: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [CLIENT, `http://127.0.0.1:${port}`, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(tokens.map((tok) => `${tok}\n`).join(''));
  });
}

test('#278 python example: stdlib client round-trips a real broker (fetch, one retry, status, typed denial, backchannel)', { skip: python ? false : 'python3 is not on PATH' }, async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'bridge', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const server = createBroker({ providers: [bridge], vault, audit: new Audit(db), db, identitySecret: identityConfig(SECRET), allowWrites: true });
  await listen(t, server);
  const port = (server.address() as any).port;
  const realFetch = globalThis.fetch;
  await import(STUB); // answers api.bridge.test only; any other egress from the broker throws
  t.after(() => { globalThis.fetch = realFetch; });
  const token = (userId = 'U1') => mintIdentity({ teamId: 'T1', userId, channel: 'C1' }, SECRET);

  // 1. Success: the broker injects U1's credential, the stubbed upstream answers, the envelope is intact.
  const t1 = token();
  const ok = await runClient(port, ['fetch', 'bridge', 'GET', '/me'], [t1]);
  assert.equal(ok.code, 0, ok.stderr);
  const fetched = JSON.parse(ok.stdout);
  assert.equal(fetched.status, 200);
  assert.deepEqual(JSON.parse(fetched.body), { ok: true, path: '/me' });

  // 2. Retry once: call 1 emptied U1's one-request bucket, so this call's first attempt is a 429 with a
  //    sub-second retryAfterMs. The client sleeps, mints a FRESH assertion (stdin line 2) and succeeds.
  //    Replaying line 1 would be refused 401 (single-use), so exit 0 plus the logged code proves both halves.
  const retried = await runClient(port, ['fetch', 'bridge', 'GET', '/me'], [token(), token()]);
  assert.equal(retried.code, 0, retried.stderr);
  assert.match(retried.stderr, /rate_limited: retrying once/);
  assert.equal(JSON.parse(retried.stdout).status, 200);

  // 3. Status: no handle, no secret — existence and a coarse consent state only.
  const status = await runClient(port, ['status'], [token()]);
  assert.equal(status.code, 0, status.stderr);
  assert.deepEqual(JSON.parse(status.stdout), { providers: [{ provider: 'bridge', connected: true, consentState: 'connected' }] });

  // 4. Typed denial: U2 never connected → 409 not_connected → VouchrError → exit 1, envelope on stderr.
  const t2 = token('U2');
  const denied = await runClient(port, ['fetch', 'bridge', 'GET', '/me'], [t2]);
  assert.equal(denied.code, 1);
  assert.equal(denied.stdout, '');
  const envelope = JSON.parse(denied.stderr.trim());
  assert.equal(envelope.status, 409);
  assert.equal(envelope.code, 'not_connected');
  assert.equal(envelope.recovery, 'connect');
  assert.equal(envelope.retryable, false);

  // 5. #296 backchannel: initiate a human decision for the POST (nothing executes, no credential read),
  //    then poll it over the header-carried GET. The request spends the same per-provider budget as a
  //    fetch (injector.ts), so it gets a second token in case step 2's bucket has not refilled yet.
  const initiated = await runClient(port, ['authorize', 'bridge', 'POST', '/repos', 'Create the demo repo'], [token(), token()]);
  assert.equal(initiated.code, 0, initiated.stderr);
  const pending = JSON.parse(initiated.stdout);
  assert.equal(pending.status, 'pending');
  const polled = await runClient(port, ['authorization', pending.authorizationId], [token()]);
  assert.equal(polled.code, 0, polled.stderr);
  assert.deepEqual(JSON.parse(polled.stdout), pending);

  // SEC-1: neither the vaulted credential nor an identity token ever reached the child's output.
  const everything = [ok, retried, status, denied, initiated, polled].map((r) => r.stdout + r.stderr).join('');
  assert.ok(!everything.includes(SECRET_TOKEN));
  for (const tok of [t1, t2]) assert.ok(!everything.includes(tok));
});
