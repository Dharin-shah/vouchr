import { test } from 'node:test';
import { openTestDb, testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import http from 'node:http';
import { createVouchr, createBroker, ConsentRequiredError, PolicyDeniedError } from '../src';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { Vault, type StoredToken } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Policy } from '../src/core/policy';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import { revokeConnection, selectRevocations } from '../src/core/offboard';
import { EgressBlockedError } from '../src/core/injector';
import { userOwner } from '../src/core/owner';
import { identityConfig, signIdentity } from './support/identity';
import type { SlackIdentity } from '../src/core/identity';

process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');

const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const FRESH: StoredToken = { accessToken: 't0k', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null };
const MASTER = Buffer.from(process.env.VOUCHR_MASTER_KEY!, 'base64');

/** Seed a SYNTHETIC row through the trusted dry_run provenance column (not the account label), the
 *  same path the dry-run callback uses — so the per-request rail and revoke-skip see it as dry-run. */
const seedDry = (v: Vault, id: SlackIdentity, provider: string, extra: Partial<StoredToken> = {}) =>
  v.upsertDryRun(userOwner(id), provider, { ...FRESH, externalAccount: 'dry-run', ...extra });

/** A no-op envelope provider: its mere PRESENCE (not any call) must make dry-run refuse at startup. */
const fakeEnvelope = { wrapDataKey: async (d: Buffer) => d, unwrapDataKey: async (w: Buffer) => w };

// Dummy client credentials: the whole point of dry-run is that no REAL OAuth app exists.
const acme = () => defineProvider({
  id: 'acme',
  authorizeUrl: 'https://acme.example/oauth/authorize',
  tokenUrl: 'https://acme.example/oauth/token',
  scopesDefault: ['read'],
  egressAllow: ['api.acme.example'],
  refresh: 'rotating',
  pkce: true,
  clientId: 'dry',
  clientSecret: 'run',
});

/** Fail-loud network ban: ANY outbound fetch during a dry-run test is a bug. Restore in finally (TEST-3). */
function banNetwork(): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = (async () => {
    throw new Error('network egress attempted in a dry-run test');
  }) as any;
  return () => {
    globalThis.fetch = real;
  };
}

/** Drive the public middleware exactly as Bolt would; returns context.vouchr + the captured posts. */
async function boltContext(vouchr: Awaited<ReturnType<typeof createVouchr>>, posts: any[] = [], userId = 'U1') {
  const client = {
    chat: {
      postEphemeral: async (a: any) => posts.push(a),
      postMessage: async (a: any) => posts.push(a),
    },
  };
  const args: any = { context: {}, client, event: { channel: 'C1', user: userId, team: 'T1' }, next: async () => {} };
  await vouchr.middleware(args);
  return { ctx: args.context.vouchr, posts };
}

/** Express-shaped response capture for driving the mounted OAuth callback (integration.test.ts shape). */
function fakeRes() {
  const r: any = { statusCode: 200, body: '', headers: {} };
  r.status = (c: number) => { r.statusCode = c; return r; };
  r.send = (b: any) => { r.body = b; return r; };
  r.set = (k: any, v?: any) => { if (typeof k === 'object') Object.assign(r.headers, k); else r.headers[k] = v; return r; };
  return r;
}

/** Extract the first error rather than asserting inline, so two modes can be compared field-for-field. */
async function errOf(fn: () => Promise<unknown>): Promise<Error> {
  try {
    await fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a throw');
}

test('dry-run: connect prompt → completeConsent → real gates → synthetic echo, fully offline', async (t) => {
  const restore = banNetwork();
  try {
    const vouchr = await createVouchr({ providers: [acme()], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    const { ctx, posts } = await boltContext(vouchr);

    // The REAL consent machinery posts the prompt; only the authorize URL is replaced by the local
    // instantly-succeeding redirect into the real callback (real single-use state, synthetic code).
    await assert.rejects(() => ctx.connect('acme'), ConsentRequiredError);
    const button = new URL(posts[0].blocks.find((b: any) => b.type === 'actions').elements[0].url);
    assert.equal(button.origin + button.pathname, 'https://app.test/vouchr/oauth/callback');
    assert.equal(button.searchParams.get('code'), 'dry-run');
    assert.ok(button.searchParams.get('state'));

    // Programmatic completion drives the REAL callback path (state consumption, vault write, audit).
    const result = await vouchr.dryRun!.completeConsent('U1', 'acme');
    assert.equal(result.ok, true);
    // The state is single-use: a second completion finds nothing pending.
    await assert.rejects(vouchr.dryRun!.completeConsent(ID, 'acme'), /No pending consent/);

    // The synthetic row carries the TRUSTED provenance column (not just the cosmetic label); the
    // token is random, with no refresh material.
    const cred = await vouchr.vault.get(userOwner(ID), 'acme');
    assert.equal(cred?.dryRun, true); // the system-only column, the sole trust marker
    assert.equal(cred?.externalAccount, 'dry-run'); // cosmetic display label only
    assert.match(cred!.accessToken!, /^[0-9a-f]{64}$/);
    assert.equal(cred?.refreshToken, null);

    // connect() now resolves a handle; fetch passes every real gate, reads the vaulted credential,
    // then returns the echo instead of touching the network (globalThis.fetch would throw).
    const handle = await ctx.connect('acme');
    const res = await handle.fetch('https://api.acme.example/things?x=1', { method: 'GET' });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), {
      dryRun: true,
      method: 'GET',
      url: 'https://api.acme.example/things?x=1',
      wouldInjectAs: 'authorization: Bearer <redacted>',
    });

    // Every audit row written in dry-run carries the meta marker; shapes otherwise match production
    // (the inject row still records host/method/status like a real injection).
    const rows = (await vouchr.db.all(`SELECT action, meta FROM audit`)) as any[];
    assert.ok(rows.some((r) => r.action === 'connect') && rows.some((r) => r.action === 'inject'));
    for (const r of rows) assert.equal(JSON.parse(r.meta).dry_run, true);
    const inject = JSON.parse(rows.find((r) => r.action === 'inject').meta);
    assert.equal(inject.host, 'api.acme.example');
    assert.equal(inject.status, 200);

    // Browser-click surface: a SECOND user's consent, completed through the mounted callback route
    // (exactly what clicking Connect does), returns HTML that never carries a minted token — and
    // neither does any captured Slack post (SEC-1 across every rendered surface).
    let cbHandler: any;
    vouchr.mountRoutes({ get: (_p: string, h: any) => (cbHandler = h) });
    const { ctx: ctx2 } = await boltContext(vouchr, posts, 'U2');
    await assert.rejects(() => ctx2.connect('acme'), ConsentRequiredError);
    const btn2 = new URL(posts.at(-1).blocks.find((b: any) => b.type === 'actions').elements[0].url);
    const res2 = fakeRes();
    await cbHandler({ query: { code: btn2.searchParams.get('code'), state: btn2.searchParams.get('state') } }, res2);
    assert.equal(res2.statusCode, 200);
    const cred2 = await vouchr.vault.get(userOwner({ ...ID, userId: 'U2' }), 'acme');
    assert.equal(cred2?.externalAccount, 'dry-run');
    for (const secret of [cred!.accessToken!, cred2!.accessToken!]) {
      assert.ok(!String(res2.body).includes(secret)); // callback HTML
      assert.ok(!JSON.stringify(posts).includes(secret)); // every Slack post (prompts included)
    }
  } finally {
    restore();
  }
});

test('dry-run: the echo never contains the stored token, and honors a custom inject shape', async (t) => {
  const restore = banNetwork();
  try {
    const KNOWN = randomBytes(24).toString('hex'); // a seeded, known-random secret
    const custom = defineProvider({
      id: 'custom',
      authorizeUrl: 'https://c.example/a',
      tokenUrl: 'https://c.example/t',
      scopesDefault: [],
      egressAllow: ['api.c.example'],
      refresh: 'none',
      pkce: false,
      clientId: 'dry',
      clientSecret: 'run',
      inject: (h, s) => h.set('x-api-key', s),
    });
    const vouchr = await createVouchr({ providers: [custom], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    // Seed directly through the synthetic provenance column, to make the secret's value known.
    await seedDry(vouchr.vault, ID, 'custom', { accessToken: KNOWN });

    const { ctx } = await boltContext(vouchr);
    const res = await (await ctx.connect('custom')).fetch('https://api.c.example/x', { method: 'GET' });
    const raw = await res.text();
    assert.ok(!raw.includes(KNOWN)); // the credential WAS read from the vault but never echoed (SEC-1)
    assert.equal(JSON.parse(raw).wouldInjectAs, 'x-api-key: <redacted>');
    // Nothing persisted carries it either.
    for (const r of (await vouchr.db.all(`SELECT meta, provider, action FROM audit`)) as any[]) {
      assert.ok(!JSON.stringify(r).includes(KNOWN));
    }
  } finally {
    restore();
  }
});

test('dry-run: egress and policy denials are exactly the production error class + message', async (t) => {
  const restore = banNetwork();
  try {
    const denied = () => defineProvider({ ...acme(), id: 'denied' });
    const policy = () => new Policy({ denied: { defaultAllow: false } });

    const prod = await createVouchr({ providers: [acme(), denied()], baseUrl: 'https://app.test', db: await openTestDb(t), policy: policy() });
    await prod.vault.upsert(userOwner(ID), 'acme', FRESH);
    const { ctx: prodCtx } = await boltContext(prod);

    const dry = await createVouchr({ providers: [acme(), denied()], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true, policy: policy() });
    await seedDry(dry.vault, ID, 'acme');
    const { ctx: dryCtx } = await boltContext(dry);

    // Egress denial: same class, same message, thrown BEFORE any secret is read in both modes.
    const pe = await errOf(async () => (await prodCtx.connect('acme')).fetch('https://evil.example/steal'));
    const de = await errOf(async () => (await dryCtx.connect('acme')).fetch('https://evil.example/steal'));
    assert.ok(de instanceof EgressBlockedError);
    assert.equal(de.constructor.name, pe.constructor.name);
    assert.equal(de.message, pe.message);

    // Policy denial at connect(): identical class + message too.
    const pp = await errOf(() => prodCtx.connect('denied'));
    const dp = await errOf(() => dryCtx.connect('denied'));
    assert.ok(dp instanceof PolicyDeniedError);
    assert.equal(dp.constructor.name, pp.constructor.name);
    assert.equal(dp.message, pp.message);
    assert.equal(dp.message, 'Provider policy denies this request.');
  } finally {
    restore();
  }
});

test('dry-run: startup hard-fails against a vault with real credentials; all-dry-run rows pass', async (t) => {
  const dbPath = await testDbUrl(t);
  const mk = (extra: object = {}) =>
    createVouchr({ providers: [acme()], baseUrl: 'https://app.test', databaseUrl: dbPath, ...extra });

  // A production instance stores a real (account-labeled) row.
  const prod = await mk();
  await prod.vault.upsert(userOwner(ID), 'acme', { ...FRESH, externalAccount: 'octocat' });
  await assert.rejects(mk({ dryRun: true }), /refusing dryRun against a vault with real credentials/);

  // MIXED real + dry-run rows still refuse: one real row is enough (dry-run row via the column).
  await seedDry(prod.vault, { ...ID, userId: 'U3' }, 'acme');
  await assert.rejects(mk({ dryRun: true }), /refusing dryRun/);
  await prod.db.close();

  // P1-A: provenance is the dry_run COLUMN, never external_account. A REAL row (production upsert,
  // dry_run=0) whose account label is LITERALLY 'dry-run' must STILL be treated as real and refuse
  // startup — key off the label and this passes (bug); key off the column and it refuses.
  const labelPath = await testDbUrl(t);
  const labelProd = await createVouchr({ providers: [acme()], baseUrl: 'https://app.test', databaseUrl: labelPath });
  await labelProd.vault.upsert(userOwner(ID), 'acme', { ...FRESH, externalAccount: 'dry-run' }); // real
  await labelProd.db.close();
  await assert.rejects(
    createVouchr({ providers: [acme()], baseUrl: 'https://app.test', databaseUrl: labelPath, dryRun: true }),
    /refusing dryRun/,
  );

  // An empty vault, then a vault holding ONLY dry-run rows (a re-run), both pass.
  const cleanPath = await testDbUrl(t);
  const first = await createVouchr({ providers: [acme()], baseUrl: 'https://app.test', databaseUrl: cleanPath, dryRun: true });
  await seedDry(first.vault, ID, 'acme');
  await first.db.close();
  const second = await createVouchr({ providers: [acme()], baseUrl: 'https://app.test', databaseUrl: cleanPath, dryRun: true });
  assert.ok(second.dryRun); // constructed fine, helpers exposed
  await second.db.close();
});

test('dry-run: a non-boolean flag fails closed at construction (SEC-4)', async (t) => {
  await assert.rejects(
    createVouchr({ providers: [acme()], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: 'yes' as any }),
    /createVouchr: dryRun must be a boolean/,
  );
  const db = await openTestDb(t);
  assert.throws(
    () => createBroker({ providers: [acme()], vault: new Vault(db, randomBytes(32)), audit: new Audit(db), db, identitySecret: identityConfig('s'), dryRun: 1 as any }),
    /createBroker: dryRun must be a boolean/,
  );
});

test('dry-run: absent flag → zero behavior change (real authorize URL, real fetch, no markers)', async (t) => {
  const prod = await createVouchr({ providers: [acme()], baseUrl: 'https://app.test', db: await openTestDb(t) });
  assert.equal(prod.dryRun, undefined); // no dry-run surface

  const { ctx, posts } = await boltContext(prod);
  await assert.rejects(() => ctx.connect('acme'), ConsentRequiredError);
  const url = new URL(posts[0].blocks.find((b: any) => b.type === 'actions').elements[0].url);
  assert.equal(url.origin + url.pathname, 'https://acme.example/oauth/authorize'); // the provider's URL

  // The outbound fetch reaches the (stubbed) network edge with the REAL token injected — no echo.
  await prod.vault.upsert(userOwner(ID), 'acme', { ...FRESH, accessToken: 'real-tok' });
  const realFetch = globalThis.fetch;
  let sawAuth: string | null = null;
  globalThis.fetch = (async (_u: any, init: any) => {
    sawAuth = new Headers(init.headers).get('authorization');
    return new Response('{"live":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const res = await (await ctx.connect('acme')).fetch('https://api.acme.example/x');
    assert.deepEqual(await res.json(), { live: true });
    assert.equal(sawAuth, 'Bearer real-tok');
  } finally {
    globalThis.fetch = realFetch;
  }

  const rows = (await prod.db.all(`SELECT meta FROM audit WHERE action='inject'`)) as any[];
  assert.ok(rows.length >= 1);
  for (const r of rows) assert.ok(!('dry_run' in JSON.parse(r.meta)));
});

test('dry-run: a near-expiry credential with a refresh token never hits the token endpoint', async (t) => {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    const vouchr = await createVouchr({ providers: [acme()], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    // A synthetic row INSIDE the 30s refresh window WITH a refresh token — production would POST /token
    // here before the outbound call (acme is refresh:'rotating', so it would also consume the token).
    await seedDry(vouchr.vault, ID, 'acme', { accessToken: 'synthetic-token', refreshToken: 'r1', expiresAt: Date.now() + 10_000 });
    const { ctx } = await boltContext(vouchr);
    const res = await (await ctx.connect('acme')).fetch('https://api.acme.example/x');
    assert.equal((await res.json()).dryRun, true); // still the echo
    assert.equal(calls, 0); // the refresh edge made NO network call
    const after = await vouchr.vault.get(userOwner(ID), 'acme');
    assert.equal(after?.refreshToken, 'r1'); // nothing rotated
    assert.equal(after?.accessToken, 'synthetic-token');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('dry-run: disconnecting a dry-run credential skips the upstream revoke call', async (t) => {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response(null, { status: 200 });
  }) as any;
  try {
    const revocable = defineProvider({
      id: 'rev', authorizeUrl: 'https://acme.example/oauth/authorize', tokenUrl: 'https://acme.example/oauth/token',
      scopesDefault: ['read'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false,
      clientId: 'dry', clientSecret: 'run',
      revokeUrl: 'https://acme.example/oauth/revoke', // production disconnect would POST the token here
    });
    const vouchr = await createVouchr({ providers: [revocable], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    await seedDry(vouchr.vault, ID, 'rev');
    let handler: any;
    vouchr.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
    const out: any[] = [];
    await handler({ command: { team_id: 'T1', user_id: 'U1', text: 'disconnect rev' }, ack: async () => {}, respond: async (m: any) => out.push(m) });
    assert.match(String(out[0]), /Disconnected/);
    assert.equal(calls, 0); // no revoke POST left the process (the synthetic token was never sent)
    assert.equal(await vouchr.vault.get(userOwner(ID), 'rev'), null); // the local delete still happened
    const rev = (await vouchr.db.all(`SELECT meta FROM audit WHERE action='revoke'`)) as any[];
    assert.equal(rev.length, 1);
    assert.equal(JSON.parse(rev[0].meta).dry_run, true);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('dry-run: a real row written AFTER boot is refused per-request, never injected', async (t) => {
  const restore = banNetwork();
  try {
    // Boot against an empty vault (the startup check passes) — then a REAL row lands, e.g. a seeder
    // or a sibling production process sharing the database. Label it literally 'dry-run' (the P1-A
    // adversarial case): the per-request rail must key off the trusted dry_run COLUMN (dry_run=0 →
    // refuse), never the forgeable label — a label-based rail would inject this real token.
    const vouchr = await createVouchr({ providers: [acme()], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    await vouchr.vault.upsert(userOwner(ID), 'acme', { ...FRESH, accessToken: 'real', externalAccount: 'dry-run' });
    assert.equal((await vouchr.vault.get(userOwner(ID), 'acme'))?.dryRun, false); // real despite the label
    const { ctx } = await boltContext(vouchr);
    const handle = await ctx.connect('acme'); // the existence check alone resolves a handle
    await assert.rejects(() => handle.fetch('https://api.acme.example/x'), /refusing dryRun/);
  } finally {
    restore();
  }
});

test('dry-run: provider response constraints never false-deny the synthetic echo', async (t) => {
  const restore = banNetwork();
  try {
    // A production-passing config that would REJECT the echo if the response gate ran on it:
    // csv-only content types and a byte cap far below the echo size.
    const csv = defineProvider({
      id: 'csv', authorizeUrl: 'https://acme.example/oauth/authorize', tokenUrl: 'https://acme.example/oauth/token',
      scopesDefault: ['read'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false,
      clientId: 'dry', clientSecret: 'run',
      egressResponse: { allowContentTypes: ['text/csv'], maxBytes: 16 },
    });
    const vouchr = await createVouchr({ providers: [csv], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    await seedDry(vouchr.vault, ID, 'csv');
    const { ctx } = await boltContext(vouchr);
    const res = await (await ctx.connect('csv')).fetch('https://api.acme.example/report');
    assert.equal((await res.json()).dryRun, true); // no ResponseBlockedError on the synthetic echo
    assert.equal(res.url, 'https://api.acme.example/report'); // the echo carries .url like a fetched Response
  } finally {
    restore();
  }
});

test('P1-A: flag OFF, a REAL credential labelled "dry-run" revokes upstream normally', async (t) => {
  // The core defect: external_account is provider/user data, not provenance. A real account whose
  // label is literally "dry-run" must behave EXACTLY like any other real credential — zero behavior
  // change. Keyed off the label, disconnect would skip the revoke; keyed off the column, it revokes.
  const realFetch = globalThis.fetch;
  let revoked = 0;
  globalThis.fetch = (async (u: any) => {
    if (String(u).includes('/revoke')) revoked++;
    return new Response(null, { status: 200 });
  }) as any;
  try {
    const revocable = defineProvider({
      id: 'rev', authorizeUrl: 'https://acme.example/oauth/authorize', tokenUrl: 'https://acme.example/oauth/token',
      scopesDefault: ['read'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false,
      clientId: 'c', clientSecret: 's', revokeUrl: 'https://acme.example/oauth/revoke',
    });
    // NO dryRun flag — ordinary production wiring.
    const vouchr = await createVouchr({ providers: [revocable], baseUrl: 'https://app.test', db: await openTestDb(t) });
    // A REAL row (production upsert → dry_run=0) whose account label happens to be 'dry-run'.
    await vouchr.vault.upsert(userOwner(ID), 'rev', { ...FRESH, accessToken: 'real-token', externalAccount: 'dry-run' });
    assert.equal((await vouchr.vault.get(userOwner(ID), 'rev'))?.dryRun, false); // real, despite the label
    let handler: any;
    vouchr.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
    await handler({ command: { team_id: 'T1', user_id: 'U1', text: 'disconnect rev' }, ack: async () => {}, respond: async () => {} });
    assert.equal(revoked, 1); // upstream revoke DID happen — the label was not load-bearing
  } finally {
    globalThis.fetch = realFetch;
  }
});

// A revocable provider for the offboard/bulk revoke coverage (a real revokeUrl → a real POST).
const revProvider = () => defineProvider({
  id: 'rev', authorizeUrl: 'https://acme.example/oauth/authorize', tokenUrl: 'https://acme.example/oauth/token',
  scopesDefault: ['read'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false,
  clientId: 'c', clientSecret: 's', revokeUrl: 'https://acme.example/oauth/revoke',
});

/** Count outbound /revoke POSTs; restore in finally (TEST-3). */
function countRevokes(): { restore: () => void; get: () => number } {
  const realFetch = globalThis.fetch;
  let n = 0;
  globalThis.fetch = (async (u: any) => {
    if (String(u).includes('/revoke')) n++;
    return new Response(null, { status: 200 });
  }) as any;
  return { restore: () => { globalThis.fetch = realFetch; }, get: () => n };
}

test('P1-A: offboardUser skips a dry-run cred upstream, but revokes a real "dry-run"-labelled one', async (t) => {
  // Covers offboard.ts offboardUser (sibling of the disconnect path). The revoke-skip keys off the
  // trusted dry_run column: revert it to the label check and the second (flag-OFF) half fails.
  const rev = countRevokes();
  try {
    // dry-run instance: a synthetic cred → offboard must NOT POST the synthetic token upstream.
    const dry = await createVouchr({ providers: [revProvider()], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    await seedDry(dry.vault, ID, 'rev');
    await dry.offboard(ID);
    assert.equal(rev.get(), 0); // synthetic token never left the process

    // flag-OFF instance: a REAL cred whose label is literally 'dry-run' → offboard MUST revoke.
    const prod = await createVouchr({ providers: [revProvider()], baseUrl: 'https://app.test', db: await openTestDb(t) });
    await prod.vault.upsert(userOwner(ID), 'rev', { ...FRESH, accessToken: 'real', externalAccount: 'dry-run' });
    await prod.offboard(ID);
    assert.equal(rev.get(), 1); // real token revoked — the label is not load-bearing
  } finally {
    rev.restore();
  }
});

test('P1-A: bulk revokeConnection skips a dry-run row upstream, but revokes a real "dry-run"-labelled one', async (t) => {
  // Covers offboard.ts revokeConnection (break-glass). selectRevocations carries the dry_run column;
  // the skip keys off row.dryRun. Revert it to the label check and the second (real) half fails.
  const rev = countRevokes();
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const audit = new Audit(db);
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);
  const registry = new ProviderRegistry([revProvider()]);
  const revoke = async () => {
    const [row] = await selectRevocations(db, { provider: 'rev', userId: 'U1' });
    await revokeConnection(vault, audit, consent, sessions, registry, row, 'rev');
  };
  try {
    // A dry-run row (trusted column) → bulk revoke must SKIP the upstream call (synthetic token).
    await vault.upsertDryRun(userOwner(ID), 'rev', { ...FRESH, externalAccount: 'dry-run' });
    await revoke();
    assert.equal(rev.get(), 0);

    // A REAL row labelled 'dry-run' (row deleted by the revoke above, so re-seed) → MUST revoke.
    await vault.upsert(userOwner(ID), 'rev', { ...FRESH, accessToken: 'real', externalAccount: 'dry-run' });
    await revoke();
    assert.equal(rev.get(), 1); // real token revoked — the label is not load-bearing
  } finally {
    rev.restore();
    await db.close();
  }
});

test('P1-B: a concurrent real write is never clobbered by a synthetic consent (atomic)', async (t) => {
  const restore = banNetwork();
  try {
    // The old callback did vault.get() then a separate vault.upsert() — a sibling REAL write between
    // them was clobbered. upsertDryRun is ONE conditional statement (overwrite only an existing
    // dry_run=1 row), so across EVERY interleaving the real row survives. Race the two writes on a
    // SHARED db handle (a sibling "production process") through a barrier, many times.
    const vouchr = await createVouchr({ providers: [acme()], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    const sibling = new Vault(vouchr.db, MASTER); // same db handle = same store, like another process
    const { ctx } = await boltContext(vouchr);

    for (let i = 0; i < 12; i++) {
      await vouchr.vault.delete(userOwner(ID), 'acme'); // reset to empty
      await assert.rejects(() => ctx.connect('acme'), ConsentRequiredError); // records a fresh consent state
      // Barrier: both ops constructed, then released together — arrival order into the FIFO decides
      // the interleaving; the invariant must hold for BOTH orderings.
      const realWrite = sibling.upsert(userOwner(ID), 'acme', { ...FRESH, accessToken: 'real', externalAccount: 'octocat' });
      const synthWrite = vouchr.dryRun!.completeConsent(ID, 'acme').catch(() => undefined); // may refuse if real landed first
      await Promise.all([realWrite, synthWrite]);
      const cred = await vouchr.vault.get(userOwner(ID), 'acme');
      assert.equal(cred?.dryRun, false, `iteration ${i}: real row must survive`);
      assert.equal(cred?.accessToken, 'real', `iteration ${i}: real token intact`);
    }
  } finally {
    restore();
  }
});

test('P2-C: the provider inject hook runs exactly once, with a redacted placeholder', async (t) => {
  const restore = banNetwork();
  try {
    const seen: string[] = [];
    const counting = defineProvider({
      id: 'ct', authorizeUrl: 'https://acme.example/oauth/authorize', tokenUrl: 'https://acme.example/oauth/token',
      scopesDefault: ['read'], egressAllow: ['api.acme.example'], refresh: 'none', pkce: false,
      clientId: 'c', clientSecret: 's',
      inject: (h, secret) => { seen.push(secret); h.set('x-api-key', secret); },
    });
    const vouchr = await createVouchr({ providers: [counting], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true });
    await seedDry(vouchr.vault, ID, 'ct', { accessToken: 'synthetic-secret' });
    const { ctx } = await boltContext(vouchr);
    const res = await (await ctx.connect('ct')).fetch('https://api.acme.example/x');
    assert.equal((await res.json()).wouldInjectAs, 'x-api-key: <redacted>');
    assert.deepEqual(seen, ['<redacted>']); // exactly ONE call, and it NEVER saw the synthetic secret
  } finally {
    restore();
  }
});

test('P2-E: dry-run refuses an external KMS envelope at startup (both factories)', async (t) => {
  // KMS wrap/unwrap are real network calls the fetch-stub tests would miss, so the offline guarantee
  // would be a lie. Refuse fail-closed at construction.
  await assert.rejects(
    createVouchr({ providers: [acme()], baseUrl: 'https://app.test', db: await openTestDb(t), dryRun: true, envelope: fakeEnvelope }),
    /dryRun requires a local master key/,
  );
  const db = await openTestDb(t);
  assert.throws(
    () => createBroker({
      providers: [acme()], vault: new Vault(db, MASTER, {}, fakeEnvelope), audit: new Audit(db), db,
      identitySecret: identityConfig('s'), dryRun: true,
    }),
    /dryRun requires a local master key/,
  );
  await db.close();
});

// ── HTTP broker (TEST-2: through the public wire surface, against the live server) ──────────────

function post(port: number, path: string, body: unknown): Promise<{ status: number; json: any; raw: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ port, path, method: 'POST', headers: { 'content-type': 'application/json' } }, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode!, json: raw ? JSON.parse(raw) : {}, raw });
        } catch {
          resolve({ status: res.statusCode!, json: {}, raw });
        }
      });
    });
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
}

function get(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    http.get({ port, path }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode!, body }));
    }).on('error', reject);
  });
}

const tok = (secret: string) =>
  signIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() }, secret);

test('dry-run broker: /v1/connect → local callback → /v1/fetch echo, fully offline', async (t) => {
  const restore = banNetwork();
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const server = createBroker({
    providers: [acme()], vault, audit: new Audit(db), db,
    identitySecret: identityConfig('shh'), baseUrl: 'https://broker.test', dryRun: true,
  });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    // Mint the consent: the authorize URL points at THIS broker's own callback with a synthetic code.
    const c = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: tok('shh') });
    assert.equal(c.status, 200);
    const authorize = new URL(c.json.authorizeUrl);
    assert.equal(authorize.origin, 'https://broker.test');
    assert.equal(authorize.pathname, '/oauth/callback');
    assert.equal(authorize.searchParams.get('code'), 'dry-run');

    // "Click Connect": GET the callback path on the live broker — instantly succeeds, writes the row.
    const cb = await get(port, authorize.pathname + authorize.search);
    assert.equal(cb.status, 200);
    assert.match(cb.body, /connected/i);
    const cred = await vault.get(userOwner(ID), 'acme');
    assert.equal(cred?.dryRun, true); // trusted provenance column set by the synthetic write
    assert.equal(cred?.externalAccount, 'dry-run'); // cosmetic label

    // /v1/fetch runs identity + policy + egress + the vault read, then returns the echo.
    const f = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: tok('shh'), method: 'GET', path: '/things' });
    assert.equal(f.status, 200);
    const echo = JSON.parse(f.json.body);
    assert.equal(echo.dryRun, true);
    assert.equal(echo.url, 'https://api.acme.example/things');
    assert.match(echo.wouldInjectAs, /<redacted>/);
    assert.ok(!f.raw.includes(cred!.accessToken!)); // the vaulted token never crosses the wire

    // Denial parity on the broker door: a non-allowlisted host maps to the production 403.
    const denied = await post(port, '/v1/fetch', { handle: { provider: 'acme', owner: 'user' }, identityToken: tok('shh'), method: 'GET', path: '/x', host: 'evil.example' });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.error, 'egress blocked');
    assert.equal(denied.json.code, 'egress_blocked');
    assert.equal(denied.json.retryable, false);
    assert.equal(denied.json.recovery, 'fix_configuration');

    // Every audit row (connect, inject, denied) carries the dry_run marker.
    const rows = (await db.all(`SELECT meta FROM audit`)) as any[];
    assert.ok(rows.length >= 3);
    for (const r of rows) assert.equal(JSON.parse(r.meta).dry_run, true);
  } finally {
    server.close();
    await db.close();
    restore();
  }
});

test('dry-run broker: callback refuses a foreign code and never clobbers a real row', async (t) => {
  const restore = banNetwork();
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const server = createBroker({
    providers: [acme()], vault, audit: new Audit(db), db,
    identitySecret: identityConfig('shh'), baseUrl: 'https://broker.test', dryRun: true,
  });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    // (a) A code the local stub didn't mint is a REAL provider redirect: refuse loudly, write nothing.
    const c1 = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: tok('shh') });
    const u1 = new URL(c1.json.authorizeUrl);
    const r1 = await get(port, `${u1.pathname}?code=REAL_PROVIDER_CODE&state=${u1.searchParams.get('state')}`);
    assert.equal(r1.status, 500);
    assert.equal(await vault.get(userOwner(ID), 'acme'), null); // no synthetic row was minted

    // (b) A REAL row written after boot survives a dry-run consent completion untouched.
    await vault.upsert(userOwner(ID), 'acme', { ...FRESH, accessToken: 'real-token', externalAccount: 'octocat' });
    const c2 = await post(port, '/v1/connect', { handle: { provider: 'acme' }, identityToken: tok('shh') });
    const u2 = new URL(c2.json.authorizeUrl);
    const r2 = await get(port, u2.pathname + u2.search); // code=dry-run, valid single-use state
    assert.equal(r2.status, 500);
    const cred = await vault.get(userOwner(ID), 'acme');
    assert.equal(cred?.accessToken, 'real-token'); // not clobbered
    assert.equal(cred?.externalAccount, 'octocat');
  } finally {
    server.close();
    await db.close();
    restore();
  }
});

test('dry-run broker: fails every request closed against a vault with real credentials', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  await vault.upsert(userOwner(ID), 'acme', { ...FRESH, externalAccount: 'octocat' }); // a REAL row
  const server = createBroker({ providers: [acme()], vault, audit: new Audit(db), db, identitySecret: identityConfig('shh'), dryRun: true });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    assert.equal((await get(port, '/healthz')).status, 200); // liveness stays green: the process IS up
    // P2-D: but a refused broker must NOT report ready — readiness awaits the safety check → 503.
    assert.equal((await get(port, '/readyz')).status, 503);
    const r = await post(port, '/v1/status', { identityToken: tok('shh') });
    assert.equal(r.status, 500); // DryRunVaultError: nothing below the probes is served
    assert.deepEqual(r.json, {
      error: 'internal error',
      code: 'internal_error',
      retryable: false,
      recovery: 'contact_admin',
    });
  } finally {
    server.close();
    await db.close();
  }
});
