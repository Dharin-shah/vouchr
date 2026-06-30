import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { sweepExpired } from '../src/core/sweep';
import { userOwner, channelOwner } from '../src/core/owner';
import { github, defineProvider } from '../src/core/providers';
import { ConnectionHandle } from '../src/core/injector';

// Runs the security-critical invariants against a REAL Postgres (not a mock).
//   npm run pg:up   # start a throwaway postgres:16 in Docker
//   npm test        # this test connects; if no PG is reachable it SKIPS (suite stays green)
//   npm run pg:down
const PG_URL = process.env.VOUCHR_TEST_PG_URL ?? 'postgres://vouchr:vouchr@localhost:5433/vouchr';
const KEY = randomBytes(32);
const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

test('postgres backend: isolation · crypto-at-rest · reference · ttl · consent · config', async (t) => {
  let db;
  try {
    db = await openDb({ databaseUrl: PG_URL });
    await db.exec('TRUNCATE connection, consent_request, channel_config, audit');
  } catch {
    t.skip('Postgres not reachable. Run `npm run pg:up` to exercise the PG backend');
    return;
  }

  try {
    const vault = new Vault(db, KEY);
    const audit = new Audit(db);

    // T3 / owner isolation on the real engine.
    await vault.upsert(channelOwner('T1', 'X'), 'p', tok('chan-T1'));
    await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p', tok('user-T1'));
    await vault.upsert(channelOwner('T2', 'X'), 'p', tok('chan-T2'));
    assert.equal((await vault.get(channelOwner('T1', 'X'), 'p'))?.accessToken, 'chan-T1');
    assert.equal((await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p'))?.accessToken, 'user-T1');
    assert.equal((await vault.get(channelOwner('T2', 'X'), 'p'))?.accessToken, 'chan-T2');
    assert.equal(await vault.get(channelOwner('T3', 'X'), 'p'), null); // unknown team → nothing

    // Ciphertext at rest: BYTEA round-trips and never holds the plaintext.
    const row = (await db.get(
      `SELECT access_token_enc FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      ['T1', 'channel', 'X', 'p'],
    )) as any;
    assert.ok(Buffer.isBuffer(row.access_token_enc));
    assert.ok(!row.access_token_enc.toString('utf8').includes('chan-T1'));

    // Referenced secret: only the ARN pointer is stored, never a secret.
    await vault.reference(channelOwner('T1', 'C_FIN'), 'mcp', { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:r:k' });
    const ref = await vault.get(channelOwner('T1', 'C_FIN'), 'mcp');
    assert.equal(ref?.source, 'aws-sm');
    assert.equal(ref?.secretRef, 'arn:aws:secretsmanager:r:k');
    assert.equal(ref?.accessToken, null);

    // listForUser isolation.
    await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'github', tok('g'));
    const mine = (await vault.listForUser({ enterpriseId: null, teamId: 'T1', userId: 'X' })).map((c) => c.provider).sort();
    assert.deepEqual(mine, ['github', 'p']); // channel creds never listed

    // TTL + sweep on a dedicated idle vault/row.
    const idle = new Vault(db, KEY, { idleMs: 1000 });
    await idle.upsert(userOwner({ enterpriseId: null, teamId: 'T9', userId: 'U' }), 'ttlp', tok('t'));
    await db.run(`UPDATE connection SET last_used_at=? WHERE team_id=? AND provider=?`, [Date.now() - 5000, 'T9', 'ttlp']);
    assert.equal(await idle.get(userOwner({ enterpriseId: null, teamId: 'T9', userId: 'U' }), 'ttlp'), null); // idle-expired
    const swept = await sweepExpired(idle, audit, new Consent(db));
    assert.ok(swept >= 1);

    // Consent single-use round-trip.
    const consent = new Consent(db);
    const id = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
    const { state } = await consent.begin(id, github({ clientId: 'a', clientSecret: 'b' }), 'https://x/cb', 'C1');
    assert.equal((await consent.consume(state))?.identity.userId, 'U1');
    assert.equal(await consent.consume(state), null); // single-use

    // Channel config mode persists.
    const cfg = new ChannelConfig(db);
    await cfg.setMode('T1', 'C_FIN', 'mcp', 'per-user');
    assert.equal(await cfg.getMode('T1', 'C_FIN', 'mcp'), 'per-user');
  } finally {
    await db.close();
  }
});

// A long-lived pod refreshes many times over its lifetime. The dedicated refresh pool's idle-client
// 'error' handler must attach exactly ONCE (at pool creation), not per withRefreshLock call — else
// listeners grow unbounded and pg logs MaxListenersExceededWarning.
test('postgres backend: withRefreshLock registers the pool error listener exactly once', async (t) => {
  let db: Awaited<ReturnType<typeof openDb>> | undefined;
  try {
    db = await openDb({ databaseUrl: PG_URL });
    await db.exec('SELECT 1');
  } catch {
    t.skip('Postgres not reachable. Run `npm run pg:up` to exercise the PG backend');
    return;
  }
  try {
    for (let i = 0; i < 15; i++) {
      await db.withRefreshLock!(`leak-probe:${i % 3}`, async () => i); // distinct + repeated keys
    }
    const pool = (db as any).refreshPool;
    assert.equal(pool.listenerCount('error'), 1, 'refresh-pool error listener must attach exactly once');
  } finally {
    await db.close();
  }
});

// Cross-process refresh coordination: two SEPARATE connections (two "pods", each its own pool and
// own in-process inflight map) refresh the same (owner, provider) at once. The Postgres advisory
// xact lock + re-read-under-lock must collapse this to exactly one provider /token call; the loser
// reuses the winner's rotated token instead of consuming the (now-invalidated) old refresh token.
test('postgres backend: concurrent cross-process refresh => one /token call, loser reuses winner token', async (t) => {
  let dbA: Awaited<ReturnType<typeof openDb>> | undefined;
  let dbB: Awaited<ReturnType<typeof openDb>> | undefined;
  try {
    dbA = await openDb({ databaseUrl: PG_URL });
    await dbA.exec('TRUNCATE connection, audit');
  } catch {
    t.skip('Postgres not reachable. Run `npm run pg:up` to exercise the PG backend');
    return;
  }
  dbB = await openDb({ databaseUrl: PG_URL });

  const realFetch = globalThis.fetch;
  try {
    const provider = defineProvider({
      id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
      scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
      clientId: 'id', clientSecret: 'sec',
    });
    const id = { enterpriseId: null, teamId: 'TL', userId: 'UL' };
    const O = userOwner(id);
    const vaultA = new Vault(dbA, KEY);
    const vaultB = new Vault(dbB, KEY);
    await vaultA.upsert(O, 'acme', { accessToken: 'old', refreshToken: 'r1', scopes: 'x', expiresAt: null, externalAccount: null });

    let tokenCalls = 0;
    let validRefresh = 'r1';
    const leaked: string[] = [];
    globalThis.fetch = (async (url: any, init: any) => {
      if (String(url) === 'https://acme.example/token') {
        tokenCalls++;
        const sent = new URLSearchParams(init.body as string).get('refresh_token');
        // Rotating provider: the previous refresh token is invalid the instant it's used once.
        if (sent !== validRefresh) {
          return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400, headers: { 'content-type': 'application/json' } });
        }
        validRefresh = 'r2';
        await new Promise((r) => setTimeout(r, 60)); // hold the advisory lock long enough to force the loser to wait
        return new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2', expires_in: 3600 }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      const auth = new Headers(init.headers).get('authorization');
      if (auth === 'Bearer old') return new Response('expired', { status: 401 }); // force a refresh
      return new Response(JSON.stringify({ saw: auth }), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as any;

    const sink = (e: any) => leaked.push(JSON.stringify(e));
    const hA = new ConnectionHandle(provider, O, id, vaultA, new Audit(dbA), {}, new Map(), sink);
    const hB = new ConnectionHandle(provider, O, id, vaultB, new Audit(dbB), {}, new Map(), sink);
    const [ra, rb] = await Promise.all([
      hA.fetch('https://api.acme.example/a'),
      hB.fetch('https://api.acme.example/b'),
    ]);

    assert.equal(ra.status, 200);
    assert.equal(rb.status, 200);
    assert.equal(tokenCalls, 1); // cross-process lock collapsed the two refreshes into one
    assert.equal((await ra.json()).saw, 'Bearer new'); // both retried with the winner's rotated token
    assert.equal((await rb.json()).saw, 'Bearer new');
    assert.equal((await vaultA.get(O, 'acme'))?.refreshToken, 'r2'); // winner's rotation persisted
    // No event (including the new refresh_lock_wait) ever carries a secret/token.
    assert.ok(leaked.some((e) => e.includes('refresh_lock_wait')), 'lock-wait metric was emitted');
    for (const e of leaked) {
      assert.ok(!e.includes('new') && !e.includes('r1') && !e.includes('r2'), `event leaked a token: ${e}`);
    }
  } finally {
    globalThis.fetch = realFetch;
    await dbA?.close();
    await dbB?.close();
  }
});
