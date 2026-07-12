import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type { WebClient } from '@slack/web-api';
import { type Db } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ConnectionHandle } from '../src/core/injector';
import { sweepExpired } from '../src/core/sweep';
import { refreshToken, revokeToken, TokenEndpointError } from '../src/core/tokens';
import { NotificationState, type CredentialHealthEvent } from '../src/core/health';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { userOwner, channelOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';
import { healthNotifier, createVouchr } from '../src/adapters/bolt';
import { RECONNECT_ACTION } from '../src/adapters/blocks';

// #117 credential health notifications: refresh_dead fires ONLY on a definitive token-endpoint
// failure (never a transient blip), outside the refresh lock; the sweep fires expiring_soon within
// the 72h TTL window and expired on delete; the default Bolt notifier DMs once per (owner, provider,
// type) per 24h via the persistent notification_state table — the window is CLAIMED atomically
// before the send and released on send failure — and reconnect/delete clear the state (atomically
// with the connection mutation). No token material anywhere (SEC-1).

const KEY = randomBytes(32);
const H = 3_600_000;
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const O1 = userOwner(ID);
const ACCESS = 'ACCESS_SECRET_tok';
const REFRESH = 'REFRESH_SECRET_r1';

const acme = () => defineProvider({
  id: 'acme', authorizeUrl: 'https://acme.example/auth', tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'], egressAllow: ['api.acme.example'], refresh: 'rotating', pkce: true,
  clientId: 'c', clientSecret: 's',
});

/** A handle whose next fetch must refresh first (expiresAt in the past), plus the health events. */
async function deadRefreshSetup(t: TestContext) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const provider = acme();
  await vault.upsert(O1, 'acme', { accessToken: ACCESS, refreshToken: REFRESH, scopes: 'x', expiresAt: Date.now() - 1_000, externalAccount: null });
  const events: CredentialHealthEvent[] = [];
  const handle = new ConnectionHandle(
    provider, O1, ID, vault, audit, {}, new Map(), () => {}, () => {}, null, undefined,
    (e) => events.push(e),
  );
  return { db, vault, audit, handle, events };
}

/** Age a connection row so TTL math is deterministic (upsert always stamps `now`). */
async function ageRow(db: Db, ownerId: string, kind: string, provider: string, createdAt: number, lastUsedAt: number): Promise<void> {
  await db.run(
    `UPDATE connection SET created_at=?, last_used_at=? WHERE team_id='T1' AND owner_kind=? AND owner_id=? AND provider=?`,
    [createdAt, lastUsedAt, kind, ownerId, provider],
  );
}

/** Fake Slack client capturing chat.postMessage payloads. */
function fakeClient(dms: any[], fail?: () => boolean) {
  return {
    chat: {
      postMessage: async (m: any) => {
        if (fail?.()) throw new Error('slack down');
        dms.push(m);
        return { ok: true };
      },
    },
  } as unknown as WebClient;
}

/** The first button URL in a Block Kit blocks array (the Connect button). */
function buttonUrl(blocks: any[]): string | undefined {
  const actions = blocks.find((b) => b.type === 'actions');
  return actions?.elements?.[0]?.url;
}

test('classification: 400/401 and invalid_grant are definitive; 5xx and other OAuth errors are not', async () => {
  const provider = acme();
  let next: () => Response;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => next()) as any;
  try {
    const classify = async (): Promise<TokenEndpointError> => {
      try {
        await refreshToken(provider, 'r1');
        throw new Error('expected a throw');
      } catch (e) {
        assert.ok(e instanceof TokenEndpointError, `expected TokenEndpointError, got ${e}`);
        return e;
      }
    };
    next = () => new Response('nope', { status: 400 }); // bare/unparseable 4xx body → definitive
    assert.equal((await classify()).definitive, true);
    next = () => new Response('nope', { status: 401 });
    assert.equal((await classify()).definitive, true);
    next = () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
    assert.equal((await classify()).definitive, true);
    // invalid_client = the OPERATOR's client secret is broken; no user reconnect fixes it → transient.
    next = () => new Response(JSON.stringify({ error: 'invalid_client' }), { status: 400 });
    assert.equal((await classify()).definitive, false);
    next = () => new Response('nope', { status: 500 });
    assert.equal((await classify()).definitive, false);
    next = () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 200, headers: { 'content-type': 'application/json' } });
    assert.equal((await classify()).definitive, true);
    next = () => new Response(JSON.stringify({ error: 'temporarily_unavailable' }), { status: 200, headers: { 'content-type': 'application/json' } });
    assert.equal((await classify()).definitive, false);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('refresh_dead: a definitive token-endpoint failure fires the hook once, with identity and no token material', async (t) => {
  const { handle, events } = await deadRefreshSetup(t);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })) as any;
  try {
    await assert.rejects(() => handle.fetch('https://api.acme.example/data'), /Token endpoint/);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.deepEqual(events, [{ type: 'refresh_dead', owner: O1, provider: 'acme' }]);
  const s = JSON.stringify(events);
  assert.ok(!s.includes(ACCESS) && !s.includes(REFRESH), 'hook payload must carry no token material');
});

test('refresh_dead: transient failures (5xx, network throw, timeout) never fire the hook', async (t) => {
  for (const boom of [
    async () => new Response('flaky', { status: 500 }),
    async () => { throw new TypeError('fetch failed'); },
    async () => { throw new DOMException('The operation timed out', 'TimeoutError'); },
  ]) {
    const { handle, events } = await deadRefreshSetup(t);
    const realFetch = globalThis.fetch;
    globalThis.fetch = boom as any;
    try {
      await assert.rejects(() => handle.fetch('https://api.acme.example/data'));
    } finally {
      globalThis.fetch = realFetch;
    }
    assert.equal(events.length, 0, 'a transient failure must never look like a dead credential');
  }
});

test('refresh_dead: not fired when the lock section rolls back for a non-endpoint reason', async (t) => {
  const { handle, events } = await deadRefreshSetup(t);
  // The /token call SUCCEEDS; the in-lock store write fails → the section rolls back. The refresh
  // token is NOT dead, so the hook must stay silent (only TokenEndpointError.definitive fires it).
  // Stub the PROTOTYPE, not the instance: on PG withRefreshLock runs fn against a fresh tx-bound
  // Vault, so an instance stub on the outer vault would be bypassed.
  const realUpdate = Vault.prototype.updateTokens;
  (Vault.prototype as any).updateTokens = async () => { throw new Error('db down'); };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ access_token: 'new', refresh_token: 'r2' }), { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    await assert.rejects(() => handle.fetch('https://api.acme.example/data'), /db down/);
  } finally {
    globalThis.fetch = realFetch;
    Vault.prototype.updateTokens = realUpdate;
  }
  assert.equal(events.length, 0);
});

test('an ASYNC, rejecting hook/sink never becomes an unhandled rejection nor affects the refresh flow', async (t) => {
  // `=> void` hook signatures admit async functions (TS void-callback rule); safeEmit must attach
  // a rejection handler or these rejections kill the process. node:test dies on an unhandled
  // rejection, so this test COMPLETING is the proof the handler is attached.
  const setup = await deadRefreshSetup(t);
  let hookFired = 0;
  const handle = new ConnectionHandle(
    acme(), O1, ID, setup.vault, setup.audit, {}, new Map(),
    async () => { throw new Error('async EventSink down'); }, // egress_error fires this during the failed refresh
    () => {}, null, undefined,
    async () => { hookFired++; throw new Error('async health notifier down'); },
  );
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('nope', { status: 401 })) as any;
  try {
    // The flow completes normally: the ORIGINAL refresh error surfaces, not the sink/hook rejections.
    await assert.rejects(() => handle.fetch('https://api.acme.example/data'), /Token endpoint/);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(hookFired, 1);
  await new Promise((r) => setImmediate(r)); // drain microtasks: an unhandled rejection would be fatal here
});

test('refresh_dead: a throwing hook never masks the original refresh error', async (t) => {
  const setup = await deadRefreshSetup(t);
  const handle = new ConnectionHandle(
    acme(), O1, ID, setup.vault, setup.audit, {}, new Map(), () => {}, () => {}, null, undefined,
    () => { throw new Error('bad hook'); },
  );
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('nope', { status: 401 })) as any;
  try {
    await assert.rejects(() => handle.fetch('https://api.acme.example/data'), /Token endpoint/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('default notifier: one DM with a reconnect ACTION button (no expirable URL); debounced across repeats and restarts; reconnect resets', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const registry = new ProviderRegistry([acme()]);
  await vault.upsert(O1, 'acme', { accessToken: ACCESS, refreshToken: REFRESH, scopes: 'x', expiresAt: null, externalAccount: null });
  const dms: any[] = [];
  const deps = { registry, audit, clientFor: async () => fakeClient(dms) };
  const notify = healthNotifier({ ...deps, state: new NotificationState(db) });
  const e: CredentialHealthEvent = { type: 'refresh_dead', owner: O1, provider: 'acme' };

  await notify(e);
  assert.equal(dms.length, 1);
  assert.equal(dms[0].channel, 'U1'); // DM the owner
  assert.match(dms[0].text, /stopped working/);
  // The button is an ACTION, not a baked-in authorize URL: a consent state lives 10 minutes and
  // the DM may be read hours later, so the state is minted on CLICK (see the handler test below).
  const btn = (dms[0].blocks as any[]).find((b) => b.type === 'actions')?.elements?.[0];
  assert.equal(btn?.action_id, RECONNECT_ACTION);
  assert.equal(btn?.value, 'acme');
  assert.equal(btn?.url, undefined);
  // Nothing expirable was minted at send time: no consent row exists until the click.
  assert.equal(Number(((await db.get(`SELECT COUNT(*) AS n FROM consent_request`)) as any).n), 0);

  await notify(e); // same event within 24h → debounced
  assert.equal(dms.length, 1);
  await healthNotifier({ ...deps, state: new NotificationState(db) })(e); // "restart": state persists in the DB
  assert.equal(dms.length, 1);

  // Reconnect (a fresh connection row) clears the state: the next dead refresh may DM again.
  await vault.upsert(O1, 'acme', { accessToken: 'ACCESS_SECRET_tok2', refreshToken: 'r2', scopes: 'x', expiresAt: null, externalAccount: null });
  await notify(e);
  assert.equal(dms.length, 2);

  // Deleting the connection purges its notification_state rows (no orphans).
  await vault.delete(O1, 'acme');
  const left = (await db.all(`SELECT * FROM notification_state WHERE team_id='T1' AND owner_id='U1'`)) as any[];
  assert.equal(left.length, 0);

  // SEC-1: neither the DMs nor the persisted state rows carry token material.
  const persisted = JSON.stringify(await db.all(`SELECT * FROM notification_state`));
  for (const blob of [JSON.stringify(dms), persisted]) {
    assert.ok(!blob.includes(ACCESS) && !blob.includes(REFRESH) && !blob.includes('ACCESS_SECRET_tok2'));
  }
});

test('reconnect button click mints a FRESH single-use state — works no matter how old the DM is; forged values do nothing', async (t) => {
  // Drive the registered RECONNECT_ACTION handler through the real createVouchr wiring.
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const vouchr = await createVouchr({ providers: [acme()], baseUrl: 'https://broker.example', db: await openTestDb(t) });
  const actions: Record<string, (args: any) => Promise<void>> = {};
  vouchr.registerCommands({
    command: () => {}, view: () => {},
    action: (id: string, h: (args: any) => Promise<void>) => { actions[id] = h; },
  });
  const handler = actions[RECONNECT_ACTION];
  assert.ok(handler, 'RECONNECT_ACTION handler must be registered');

  // The DM itself carries NO consent state (verified in the test above), so there is nothing that
  // can expire between send and click — clicking at +6h mints a state that is fresh BY CONSTRUCTION.
  const replies: any[] = [];
  let acked = 0;
  const body = { team: { id: 'T1' }, user: { id: 'U1' }, actions: [{ value: 'acme' }] };
  await handler({ ack: async () => { acked++; }, body, respond: async (m: any) => { replies.push(m); } });
  assert.equal(acked, 1);
  assert.equal(replies.length, 1);
  assert.equal(replies[0].replace_original, true);
  const url = buttonUrl(replies[0].blocks);
  assert.ok(url?.startsWith('https://acme.example/auth?'), `expected an authorize URL, got ${url}`);
  // The minted state is LIVE and single-use, bound to the ACTING user from the verified payload.
  const consent = new Consent(vouchr.db);
  const state = new URL(url!).searchParams.get('state')!;
  const consumed = await consent.consume(state);
  assert.equal(consumed?.identity.userId, 'U1');
  assert.equal(consumed?.channel, null); // DM context: no channel on the consent row
  assert.equal(await consent.consume(state), null); // single-use

  // SEC-3/SEC-4: the button value is forgeable — an unregistered provider is refused before any
  // consent write, and nothing is sent back.
  await handler({ ack: async () => {}, body: { ...body, actions: [{ value: 'ghost' }] }, respond: async (m: any) => { replies.push(m); } });
  assert.equal(replies.length, 1);
  assert.equal(Number(((await vouchr.db.get(`SELECT COUNT(*) AS n FROM consent_request`)) as any).n), 0);
});

test('default notifier: a failed Slack send RELEASES the claim, so the next sweep retries', async (t) => {
  const db = await openTestDb(t);
  const registry = new ProviderRegistry([acme()]);
  const dms: any[] = [];
  let down = true;
  const notify = healthNotifier({
    registry, audit: new Audit(db), state: new NotificationState(db),
    clientFor: async () => fakeClient(dms, () => down),
  });
  const e: CredentialHealthEvent = { type: 'expiring_soon', owner: O1, provider: 'acme', expiresAt: Date.now() + 20 * H };
  await assert.rejects(() => notify(e), /slack down/); // the send failed…
  assert.equal(dms.length, 0);
  // …and the claim was released: no state row survives a failed send.
  assert.equal(Number(((await db.get(`SELECT COUNT(*) AS n FROM notification_state`)) as any).n), 0);
  down = false;
  await notify(e); // the next event re-claims and delivers
  assert.equal(dms.length, 1);
  assert.match(dms[0].text, /expires in ~20h\. Reconnect to keep using it\./);
});

test('claim is atomic: concurrent duplicate events produce exactly one winner and one DM', async (t) => {
  const db = await openTestDb(t);
  const state = new NotificationState(db);
  // Store-level: two racing claims for the same (owner, provider, type) — exactly one wins.
  const [a, b] = await Promise.all([
    state.claim(O1, 'acme', 'refresh_dead'),
    state.claim(O1, 'acme', 'refresh_dead'),
  ]);
  assert.equal([a, b].filter(Boolean).length, 1, 'exactly one concurrent claim must win');
  assert.equal(await state.claim(O1, 'acme', 'refresh_dead'), false); // back-to-back loses too

  // Notifier-level: two concurrent deliveries of the same event → one DM.
  const dms: any[] = [];
  const notify = healthNotifier({
    registry: new ProviderRegistry([acme()]), audit: new Audit(db), state: new NotificationState(db),
    clientFor: async () => fakeClient(dms),
  });
  const e: CredentialHealthEvent = { type: 'expiring_soon', owner: O1, provider: 'acme', expiresAt: Date.now() + 20 * H };
  await Promise.all([notify(e), notify(e)]);
  assert.equal(dms.length, 1);
});

test('sweep: expiring_soon carries the EARLIEST ceiling (idle vs max-age) and only fires inside the 72h window', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY, { idleMs: 80 * H, maxAgeMs: 100 * H });
  const audit = new Audit(db);
  const consent = new Consent(db);
  const now = Date.now();
  // Both dimensions exceed the 72h window (so both warn); idle ceiling now+50h beats max-age
  // now+70h → expiresAt must be the idle one.
  await vault.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await ageRow(db, 'U1', 'user', 'acme', now - 30 * H, now - 30 * H);
  const events: CredentialHealthEvent[] = [];
  await sweepExpired(vault, audit, consent, undefined, (e) => events.push(e));
  assert.equal(events.length, 1);
  assert.equal(events[0].type, 'expiring_soon');
  const drift = Math.abs((events[0].expiresAt ?? 0) - (now - 30 * H + 80 * H));
  assert.ok(drift < 5_000, `expiresAt must be the idle ceiling, off by ${drift}ms`);

  // Outside the window (fresh row, ceilings 200h/300h away) → no events at all.
  const db2 = await openTestDb(t);
  const vault2 = new Vault(db2, KEY, { idleMs: 200 * H, maxAgeMs: 300 * H });
  await vault2.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const events2: CredentialHealthEvent[] = [];
  await sweepExpired(vault2, new Audit(db2), new Consent(db2), undefined, (e) => events2.push(e));
  assert.equal(events2.length, 0);

  // Past the ceiling → 'expired' fires (after the delete), never 'expiring_soon'.
  await vault2.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await ageRow(db2, 'U1', 'user', 'acme', now - 301 * H, now - 301 * H);
  await sweepExpired(vault2, new Audit(db2), new Consent(db2), undefined, (e) => events2.push(e));
  assert.deepEqual(events2.map((e) => e.type), ['expired']);
  assert.equal(await vault2.get(O1, 'acme'), null);
});

test('window guard: a TTL dimension <= the 72h window never warns (no perpetual daily nag); the defaults still do', async (t) => {
  const now = Date.now();
  // idleMs = 48h (an "aggressive" per-user policy) is <= the 72h window: EVERY live connection —
  // used one second ago or one hour from idle death — would permanently sit "inside the window",
  // turning the warning into a daily reconnect nag forever. The dimension must be excluded.
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY, { idleMs: 48 * H });
  await vault.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const events: CredentialHealthEvent[] = [];
  await sweepExpired(vault, new Audit(db), new Consent(db), undefined, (e) => events.push(e)); // used just now
  await ageRow(db, 'U1', 'user', 'acme', now - 47 * H, now - 47 * H); // 1h from idle death
  await sweepExpired(vault, new Audit(db), new Consent(db), undefined, (e) => events.push(e));
  assert.equal(events.length, 0, 'a <=window TTL dimension must never fire expiring_soon');

  // The shipped defaults (idle 7d / max-age 30d) both exceed the window: a fresh connection is
  // silent; a genuinely idle one inside 72h of its idle ceiling still warns, with that ceiling.
  const db2 = await openTestDb(t);
  const vault2 = new Vault(db2, KEY, { idleMs: 7 * 24 * H, maxAgeMs: 30 * 24 * H });
  await vault2.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const events2: CredentialHealthEvent[] = [];
  await sweepExpired(vault2, new Audit(db2), new Consent(db2), undefined, (e) => events2.push(e)); // fresh: silent
  assert.equal(events2.length, 0);
  await ageRow(db2, 'U1', 'user', 'acme', now - 5 * 24 * H, now - 5 * 24 * H); // idle ceiling in 2d
  await sweepExpired(vault2, new Audit(db2), new Consent(db2), undefined, (e) => events2.push(e));
  assert.equal(events2.length, 1);
  assert.equal(events2[0].type, 'expiring_soon');
  const drift = Math.abs((events2[0].expiresAt ?? 0) - (now - 5 * 24 * H + 7 * 24 * H));
  assert.ok(drift < 5_000, `expiresAt must be the idle ceiling, off by ${drift}ms`);

  // Mixed policy: the guard is SELECTION-only, never the reported ceiling. idle 48h (<= window,
  // never selects) + max-age 100h, row created 30h ago and used just now: selected via max-age
  // (~70h out), but the credential actually dies of the idle TTL in ~48h — expiresAt must be
  // lastUsed + 48h, NOT created + 100h ("expires in ~Nh" must not overstate the lifetime).
  const db3 = await openTestDb(t);
  const vault3 = new Vault(db3, KEY, { idleMs: 48 * H, maxAgeMs: 100 * H });
  await vault3.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await ageRow(db3, 'U1', 'user', 'acme', now - 30 * H, now); // created 30h ago, used now
  const events3: CredentialHealthEvent[] = [];
  await sweepExpired(vault3, new Audit(db3), new Consent(db3), undefined, (e) => events3.push(e));
  assert.equal(events3.length, 1);
  assert.equal(events3[0].type, 'expiring_soon');
  const drift3 = Math.abs((events3[0].expiresAt ?? 0) - (now + 48 * H));
  assert.ok(drift3 < 5_000, `expiresAt must be the REAL earliest ceiling (idle), off by ${drift3}ms`);
});

test('sweep 3x in a row still sends ONE expiring-soon DM (persistent debounce through the notifier)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY, { maxAgeMs: 100 * H });
  const audit = new Audit(db);
  const consent = new Consent(db);
  await vault.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await ageRow(db, 'U1', 'user', 'acme', Date.now() - 30 * H, Date.now() - 30 * H);
  const dms: any[] = [];
  const notify = healthNotifier({
    registry: new ProviderRegistry([acme()]), audit, state: new NotificationState(db),
    clientFor: async () => fakeClient(dms),
  });
  // Wire the notifier the way createVouchr does (fire-and-forget), but collect the promises so the
  // test can await delivery deterministically.
  const pending: Promise<void>[] = [];
  const hook = (e: CredentialHealthEvent) => { pending.push(notify(e)); };
  for (let i = 0; i < 3; i++) {
    await sweepExpired(vault, audit, consent, undefined, hook);
    await Promise.all(pending.splice(0));
  }
  assert.equal(dms.length, 1);
  assert.match(dms[0].text, /Your acme connection expires in ~70h\. Reconnect to keep using it\./);
});

test('channel-owned credential: the expiring-soon DM goes to the configuring admin, or is skipped when unknown', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY, { maxAgeMs: 100 * H });
  const audit = new Audit(db);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([acme()]);
  const now = Date.now();
  // C9: configured by UADMIN (an audit 'config' row exists) → DM the admin, mentioning the channel.
  await vault.upsert(channelOwner('T1', 'C9'), 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await ageRow(db, 'C9', 'channel', 'acme', now - 30 * H, now - 30 * H);
  await audit.record('config', { enterpriseId: null, teamId: 'T1', userId: 'UADMIN' }, 'acme', { owner: 'channel', channel: 'C9', mode: 'shared' });
  // C8: nobody ever configured it → skip (never spam the channel), and no state row is written.
  await vault.upsert(channelOwner('T1', 'C8'), 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await ageRow(db, 'C8', 'channel', 'acme', now - 30 * H, now - 30 * H);
  // An unregistered provider never renders or persists anything (SEC-4 gate).
  await vault.upsert(O1, 'ghost', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await ageRow(db, 'U1', 'user', 'ghost', now - 30 * H, now - 30 * H);

  const dms: any[] = [];
  const notify = healthNotifier({
    registry, audit, state: new NotificationState(db),
    clientFor: async () => fakeClient(dms),
  });
  const pending: Promise<void>[] = [];
  await sweepExpired(vault, audit, consent, undefined, (e) => { pending.push(notify(e)); });
  await Promise.all(pending);

  assert.equal(dms.length, 1);
  assert.equal(dms[0].channel, 'UADMIN');
  assert.match(dms[0].text, /shared acme connection in <#C9>.*expires in ~70h/);
  assert.match(dms[0].text, /\/vouchr configure acme/);
  const rows = (await db.all(`SELECT owner_id FROM notification_state`)) as any[];
  assert.deepEqual(rows.map((r) => r.owner_id), ['C9']); // only the delivered DM was marked
});

test('claim window math: 24h per (owner, provider, type), per-type independent; release restores claimability', async (t) => {
  const db = await openTestDb(t);
  const state = new NotificationState(db);
  const now = Date.now();
  assert.equal(await state.claim(O1, 'acme', 'refresh_dead', now - 25 * H), true); // fresh row: wins
  assert.equal(await state.claim(O1, 'acme', 'refresh_dead', now), true); // 25h later: window elapsed, wins
  assert.equal(await state.claim(O1, 'acme', 'refresh_dead', now + 23 * H), false); // inside the window: loses
  assert.equal(await state.claim(O1, 'acme', 'expiring_soon', now), true); // types don't collide
  assert.equal(await state.claim(userOwner({ ...ID, userId: 'U2' }), 'acme', 'refresh_dead', now), true);
  // release (failed send) restores claimability immediately — but only for the exact claimed stamp.
  assert.equal(await state.claim(O1, 'gh2', 'refresh_dead', now), true);
  await state.release(O1, 'gh2', 'refresh_dead', now - 1); // wrong stamp: not ours, no-op
  assert.equal(await state.claim(O1, 'gh2', 'refresh_dead', now + 1), false); // still held
  await state.release(O1, 'gh2', 'refresh_dead', now); // our stamp: released
  assert.equal(await state.claim(O1, 'gh2', 'refresh_dead', now + 1), true);
});

test('transaction isolation: an unrelated concurrent write is isolated from a rolled-back transaction', async (t) => {
  // Postgres runs each pooled connection as its own transaction, so B's autocommit insert can never
  // land inside A's open transaction and can never vanish when A rolls back (the single-connection
  // hazard the old SQLite backend had). Assert the real invariant: A's row is gone, B's SURVIVES.
  const db = await openTestDb(t);
  const a = db.transaction!(async (tx) => {
    await tx.run(`INSERT INTO channel_config (team_id, channel, provider, mode) VALUES ('T','CA','p','shared')`);
    await new Promise((r) => setTimeout(r, 20)); // hold the transaction open across a real concurrent write
    throw new Error('boom');
  }).catch((e: Error) => e);
  const b = db.run(`INSERT INTO channel_config (team_id, channel, provider, mode) VALUES ('T','CB','p','shared')`);
  const [aErr, bResult] = await Promise.all([a, b]);
  assert.match((aErr as Error).message, /boom/);
  assert.equal(bResult.changes, 1); // B committed on its own connection
  const rows = (await db.all(`SELECT channel FROM channel_config ORDER BY channel`)) as any[];
  assert.deepEqual(rows.map((r) => r.channel), ['CB']); // A's row rolled back, B's row survives
});

test('transient token-endpoint and revoke responses cancel their unread bodies (no pinned sockets)', async () => {
  let cancelled = 0;
  const spiedBody = () => new ReadableStream({ cancel() { cancelled++; } });
  const realFetch = globalThis.fetch;
  try {
    // 5xx: classified transient, body never read → must be cancelled before the throw (#172 class).
    globalThis.fetch = (async () => new Response(spiedBody(), { status: 503 })) as any;
    await assert.rejects(() => refreshToken(acme(), 'r1'), /HTTP 503/);
    assert.equal(cancelled, 1);
    // Revoke: only the status is ever read — the body is cancelled on the OK path too.
    globalThis.fetch = (async () => new Response(spiedBody(), { status: 200 })) as any;
    await revokeToken({ ...acme(), revokeUrl: 'https://acme.example/revoke' }, 'tok');
    assert.equal(cancelled, 2);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('vault WRITES are ATOMIC with the notification-state purge; a DELETE survives a purge failure', async (t) => {
  // upsert: hostile db (notification_state dropped) → the INSERT must not survive the failed purge
  // (fail-closed: no new credential lands without its satellites cleared).
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await db.exec(`DROP TABLE notification_state`);
  await assert.rejects(
    vault.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null }),
  ); // the caller sees the failure…
  assert.equal(Number(((await db.get(`SELECT COUNT(*) AS n FROM connection`)) as any).n), 0); // …and nothing half-committed

  // delete is the OPPOSITE contract (GHSA-25m2 review): the credential delete is the
  // security-meaningful action, so a satellite-purge failure must never roll it back or throw.
  const db2 = await openTestDb(t);
  const vault2 = new Vault(db2, KEY);
  await vault2.upsert(O1, 'acme', { accessToken: 'a', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await db2.exec(`DROP TABLE notification_state`);
  assert.equal(await vault2.delete(O1, 'acme'), true); // no throw, truthful result
  assert.equal(Number(((await db2.get(`SELECT COUNT(*) AS n FROM connection`)) as any).n), 0); // delete committed
});
