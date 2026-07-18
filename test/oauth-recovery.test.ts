import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import { ErrorCode as SlackErrorCode, WebClient } from '@slack/web-api';
import {
  createVouchr,
  MAX_PENDING_NOTIFICATION_CLIENT_LOOKUPS,
  PromptFanoutDeadlineError,
  settledWithLimit,
} from '../src/adapters/bolt';
import { Audit } from '../src/core/audit';
import {
  CONSENT_SWEEP_BATCH_SQL,
  Consent,
  MAX_CONSENT_SWEEP_BATCH,
  STATE_RECOVERY_RETENTION_MS,
  STATE_TTL_MS,
} from '../src/core/consent';
import { userOwner } from '../src/core/owner';
import { openDb, type Db } from '../src/core/db';
import { ConsentRequiredError, mapSafeError, UserFacingError } from '../src/core/errors';
import type { SlackIdentity } from '../src/core/identity';
import { handleOAuthCallback } from '../src/core/oauthCallback';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { Vault } from '../src/core/vault';
import { openTestDb, testDbUrl } from './support/pg';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const provider = defineProvider({
  id: 'acme',
  authorizeUrl: 'https://auth.acme.test/authorize',
  tokenUrl: 'https://auth.acme.test/token',
  scopesDefault: ['read'],
  egressAllow: ['api.acme.test'],
  refresh: 'none',
  pkce: true,
  clientId: 'client',
  clientSecret: 'client-secret',
});

function fakeResponse() {
  const response: any = { statusCode: 200, body: '', headers: {} };
  response.status = (status: number) => { response.statusCode = status; return response; };
  response.send = (body: unknown) => { response.body = body; return response; };
  response.set = (name: string | Record<string, string>, value?: string) => {
    if (typeof name === 'string') response.headers[name] = value;
    else Object.assign(response.headers, name);
    return response;
  };
  return response;
}

async function contextFor(vouchr: Awaited<ReturnType<typeof createVouchr>>, client: any) {
  const context: any = {};
  await vouchr.middleware({
    context,
    client,
    event: { channel: 'C1', user: ID.userId, team: ID.teamId },
    next: async () => {},
  });
  return context.vouchr;
}

async function openReplicaPair(t: TestContext) {
  const url = await testDbUrl(t);
  const a = await openDb({ databaseUrl: url });
  const b = await openDb({ databaseUrl: url });
  t.after(async () => {
    await Promise.all([a.close(), b.close()]);
  });
  return { a, b };
}

test('OAuth consent is one owner/provider generation and one delivered prompt across replicas', async (t) => {
  const { a, b } = await openReplicaPair(t);
  const consentA = new Consent(a);
  const consentB = new Consent(b);

  const [first, second] = await Promise.all([
    consentA.begin(ID, provider, 'https://vouchr.test/callback', 'C1'),
    consentB.begin(ID, provider, 'https://vouchr.test/callback', 'C1'),
  ]);
  assert.equal(first.state, second.state);
  assert.equal(
    (await a.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM consent_request WHERE superseded_at IS NULL`,
    ))?.n,
    1,
  );

  const claims = await Promise.all([
    consentA.claimDelivery(first.state),
    consentB.claimDelivery(first.state),
  ]);
  const winner = claims.find((claim) => claim.status === 'claimed');
  assert.ok(winner && winner.status === 'claimed');
  assert.equal(claims.filter((claim) => claim.status === 'claimed').length, 1);
  assert.ok(claims.some((claim) => claim.status === 'in-flight'));
  assert.equal(await consentA.confirmDelivery(first.state, winner.token), true);

  const reused = await consentB.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  assert.equal(reused.state, first.state);
  assert.deepEqual(await consentB.claimDelivery(reused.state), { status: 'delivered' });

  const replacement = await consentB.begin(ID, provider, 'https://vouchr.test/callback', 'C2');
  assert.notEqual(replacement.state, first.state);
  assert.equal((await consentA.consume(first.state)).status, 'superseded');
  assert.equal((await consentA.consume(replacement.state)).status, 'active');
});

test('OAuth delivery cleanup is exact and ambiguous delivery retains its lease', async (t) => {
  const db = await openTestDb(t);
  const consent = new Consent(db);
  const pending = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  const claim = await consent.claimDelivery(pending.state);
  assert.equal(claim.status, 'claimed');
  if (claim.status !== 'claimed') assert.fail('prompt delivery was not claimable');
  assert.deepEqual(await consent.claimDelivery(pending.state), { status: 'in-flight' });

  const replacement = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C2');
  assert.equal(
    await consent.abandonDelivery(pending.state, claim.token),
    false,
    'an old failed sender must not delete a later generation',
  );
  assert.equal(
    (await db.get<{ state: string }>(
      `SELECT state FROM consent_request WHERE superseded_at IS NULL`,
    ))?.state,
    replacement.state,
  );

  const replacementClaim = await consent.claimDelivery(replacement.state);
  assert.equal(replacementClaim.status, 'claimed');
  assert.deepEqual(
    await consent.claimDelivery(replacement.state),
    { status: 'in-flight' },
    'an ambiguous sender retains the short lease and prevents an immediate duplicate',
  );
});

test('fresh setup supersedes a delivered consent minted before an offboard tombstone', async (t) => {
  const db = await openTestDb(t);
  const consent = new Consent(db);
  const old = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  const delivery = await consent.claimDelivery(old.state);
  assert.equal(delivery.status, 'claimed');
  if (delivery.status !== 'claimed') assert.fail('prompt delivery was not claimable');
  assert.equal(await consent.confirmDelivery(old.state, delivery.token), true);

  await consent.markOffboarded(ID);
  await new Promise((resolve) => setTimeout(resolve, 5));
  const fresh = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  assert.notEqual(fresh.state, old.state);
  assert.equal((await consent.consume(old.state)).status, 'superseded');
  assert.equal((await consent.consume(fresh.state)).status, 'active');
});

test('a Slack rejection cannot invalidate an OAuth URL already returned by another adapter', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const headless = await new Consent(db).begin(
    ID,
    provider,
    'https://vouchr.test/vouchr/oauth/callback',
    'C1',
  );
  const vouchr = await createVouchr({ providers: [provider], baseUrl: 'https://vouchr.test', db });
  const client = {
    chat: {
      postEphemeral: async () => {
        throw Object.assign(new Error('rejected'), { code: SlackErrorCode.PlatformError });
      },
      postMessage: async () => {},
    },
  };
  const context = await contextFor(vouchr, client);
  await assert.rejects(() => context.connect('acme'), /Slack rejected/i);
  assert.equal((await new Consent(db).consume(headless.state)).status, 'active');
});

test('a newer OAuth generation fences an older callback paused in token exchange', async (t) => {
  const { a, b } = await openReplicaPair(t);
  const consentA = new Consent(a);
  const consentB = new Consent(b);
  const auditA = new Audit(a);
  const auditB = new Audit(b);
  const registry = new ProviderRegistry([provider]);
  const vaultA = new Vault(a, KEY);
  const vaultB = new Vault(b, KEY);
  const first = await consentA.begin(ID, provider, 'https://vouchr.test/callback', 'C1');

  let exchangeStarted!: () => void;
  let releaseExchange!: () => void;
  const started = new Promise<void>((resolve) => { exchangeStarted = resolve; });
  const release = new Promise<void>((resolve) => { releaseExchange = resolve; });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    exchangeStarted();
    await release;
    return new Response(JSON.stringify({ access_token: 'token-from-provider' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  try {
    const older = handleOAuthCallback(
      { registry, vault: vaultA, audit: auditA, consent: consentA, redirectUri: 'https://vouchr.test/callback' },
      'old-code',
      first.state,
    );
    await started;
    const newer = await consentB.begin(ID, provider, 'https://vouchr.test/callback', 'C2');
    releaseExchange();

    const oldResult = await older;
    assert.equal(oldResult.ok, false);
    assert.equal(!oldResult.ok && oldResult.outcome, 'state_stale');
    assert.equal((await a.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM connection`))?.n, 0);
    assert.equal((await a.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='connect'`))?.n, 0);

    const newResult = await handleOAuthCallback(
      { registry, vault: vaultB, audit: auditB, consent: consentB, redirectUri: 'https://vouchr.test/callback' },
      'new-code',
      newer.state,
    );
    assert.equal(newResult.ok, true);
    assert.equal((await a.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM connection`))?.n, 1);
    assert.equal((await a.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='connect'`))?.n, 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth callback outcomes distinguish attributable recovery without reflecting foreign errors', async (t) => {
  const db = await openTestDb(t);
  const consent = new Consent(db);
  const audit = new Audit(db);
  const vault = new Vault(db, KEY);
  const registry = new ProviderRegistry([provider]);
  const deps = { registry, vault, audit, consent, redirectUri: 'https://vouchr.test/callback' };
  const foreign = 'ghp_RAW_PROVIDER_ERROR_MUST_NOT_ESCAPE';

  const deniedState = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  const denied = await handleOAuthCallback(deps, undefined, deniedState.state, 'access_denied');
  assert.equal(!denied.ok && denied.outcome, 'denied');
  assert.equal(!denied.ok && 'context' in denied && denied.context.identity.userId, ID.userId);
  assert.equal(
    (await handleOAuthCallback(deps, undefined, deniedState.state, 'access_denied')).outcome,
    'state_unavailable',
    'a Slack/provider retry cannot duplicate the attributed denial',
  );

  // Only `access_denied` is a user decision. Any other redirect error value — including a hostile
  // one — is a provider-side failure and must not be audited or messaged as a denial (nor echoed).
  // Closed classification: only server_error / temporarily_unavailable are transient (502 +
  // retry_later). Config/request codes and any unknown value are permanent (500 + fix_configuration)
  // — never "retry unchanged". The raw value is never reflected or persisted for either.
  const transientState = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  const transient = await handleOAuthCallback(deps, undefined, transientState.state, 'temporarily_unavailable');
  assert.equal(!transient.ok && transient.outcome, 'exchange_failed');
  assert.equal(!transient.ok && transient.status, 502);
  assert.equal(!transient.ok && 'recovery' in transient && transient.recovery, 'retry_later');

  const permanentState = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  const permanent = await handleOAuthCallback(deps, undefined, permanentState.state, 'invalid_scope');
  assert.equal(!permanent.ok && permanent.outcome, 'exchange_failed');
  assert.equal(!permanent.ok && permanent.status, 500);
  assert.equal(!permanent.ok && 'recovery' in permanent && permanent.recovery, 'fix_configuration');

  const providerFailedState = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  const providerFailed = await handleOAuthCallback(deps, undefined, providerFailedState.state, foreign);
  assert.equal(!providerFailed.ok && providerFailed.outcome, 'exchange_failed');
  assert.equal(!providerFailed.ok && providerFailed.status, 500, 'an unknown error value defaults to permanent');
  assert.equal(!providerFailed.ok && 'recovery' in providerFailed && providerFailed.recovery, 'fix_configuration');
  assert.ok(!JSON.stringify(providerFailed).includes(foreign));
  const providerFailedAudit = await db.get<{ meta: string }>(
    `SELECT meta FROM audit WHERE action='denied' ORDER BY at DESC LIMIT 1`,
  );
  assert.deepEqual(JSON.parse(providerFailedAudit?.meta ?? '{}'), { reason: 'exchange_failed' });

  const incompleteState = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  const incomplete = await handleOAuthCallback(deps, undefined, incompleteState.state);
  assert.equal(!incomplete.ok && incomplete.outcome, 'incomplete');
  const incompleteAudit = await db.get<{ meta: string }>(
    `SELECT meta FROM audit WHERE action='denied' ORDER BY at DESC LIMIT 1`,
  );
  assert.deepEqual(JSON.parse(incompleteAudit?.meta ?? '{}'), { reason: 'consent_incomplete' });

  const expiredState = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  await db.run(`UPDATE consent_request SET created_at=? WHERE state=?`, [Date.now() - STATE_TTL_MS - 1_000, expiredState.state]);
  assert.equal(await consent.sweepStale(), 0, 'authority expiry must retain bounded recovery context');
  const expired = await handleOAuthCallback(deps, 'code', expiredState.state);
  assert.equal(!expired.ok && expired.outcome, 'state_expired');
  assert.equal((await handleOAuthCallback(deps, 'code', expiredState.state)).outcome, 'state_unavailable');

  const abandoned = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  await db.run(
    `UPDATE consent_request SET created_at=? WHERE state IN (?,?)`,
    [
      Date.now() - STATE_RECOVERY_RETENTION_MS - 1_000,
      expiredState.state,
      abandoned.state,
    ],
  );
  assert.equal(await consent.sweepStale(), 2, 'expired and superseded recovery rows are eventually removed');
  assert.equal((await consent.consume(abandoned.state)).status, 'unavailable');

  const removedState = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  const removed = await handleOAuthCallback(
    { ...deps, registry: new ProviderRegistry([]) },
    'code',
    removedState.state,
  );
  assert.equal(!removed.ok && removed.outcome, 'state_stale');

  assert.equal(
    (await handleOAuthCallback(deps, 'code', 'x'.repeat(100_000))).outcome,
    'state_unavailable',
  );

  const failedState = await consent.begin(ID, provider, deps.redirectUri, 'C1');
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(foreign, { status: 500 })) as typeof fetch;
  try {
    const failed = await handleOAuthCallback(deps, 'code', failedState.state);
    assert.equal(!failed.ok && failed.outcome, 'exchange_failed');
    assert.equal(!failed.ok && failed.recovery, 'retry_later');
    assert.equal(!failed.ok && failed.retryable, false, 'a spent code is never callback-retryable');
    assert.ok(!JSON.stringify(failed).includes(foreign));
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth recovery retention prunes in indexed bounded batches', async (t) => {
  const real = await openTestDb(t);
  const staleAt = Date.now() - STATE_RECOVERY_RETENTION_MS - 60_000;
  await real.exec(
    `INSERT INTO consent_request
       (state,enterprise_id,team_id,user_id,provider,channel,pkce_verifier,created_at,superseded_at)
     SELECT gen_random_uuid()::text,NULL,'T-sweep','U-' || g,'acme',NULL,'verifier',${staleAt},${staleAt}
       FROM generate_series(1, ${MAX_CONSENT_SWEEP_BATCH + 1}) g`,
  );
  const recent = await new Consent(real).begin(
    { enterpriseId: null, teamId: 'T-sweep', userId: 'U-recent' },
    provider,
    'https://vouchr.test/callback',
    null,
  );
  await real.exec(`ANALYZE consent_request`);
  const plan = JSON.stringify((await real.all<Record<string, unknown>>(
    `EXPLAIN (FORMAT JSON) ${CONSENT_SWEEP_BATCH_SQL}`,
    [staleAt + 1, MAX_CONSENT_SWEEP_BATCH],
  ))[0]?.['QUERY PLAN']);
  assert.match(plan, /idx_consent_request_created_at/);
  assert.match(plan, /Index Cond/);

  const batches: number[] = [];
  const recording: Db = {
    get: (sql, params) => real.get(sql, params),
    all: (sql, params) => real.all(sql, params),
    run: async (sql, params) => {
      const result = await real.run(sql, params);
      if (sql === CONSENT_SWEEP_BATCH_SQL) batches.push(result.changes);
      return result;
    },
    exec: (sql) => real.exec(sql),
    close: () => real.close(),
  };
  assert.equal(await new Consent(recording).sweepStale(), MAX_CONSENT_SWEEP_BATCH + 1);
  assert.deepEqual(batches, [MAX_CONSENT_SWEEP_BATCH, 1]);
  assert.equal((await real.get(`SELECT state FROM consent_request WHERE state=?`, [recent.state]))?.state, recent.state);
});

test('audit failure preserves definitive OAuth denial and lifecycle outcomes', async (t) => {
  const db = await openTestDb(t);
  const consent = new Consent(db);
  const registry = new ProviderRegistry([provider]);
  const calls: Array<{ action: string; meta: unknown }> = [];
  const brokenAudit = {
    record: async (action: string, _identity: unknown, _provider: string, meta: unknown) => {
      calls.push({ action, meta });
      throw new Error('audit unavailable');
    },
  } as any;

  const deniedState = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  const denied = await handleOAuthCallback(
    {
      registry,
      vault: new Vault(db, KEY),
      audit: brokenAudit,
      consent,
      redirectUri: 'https://vouchr.test/callback',
    },
    undefined,
    deniedState.state,
    'access_denied',
  );
  assert.equal(!denied.ok && denied.outcome, 'denied');
  assert.equal(!denied.ok && denied.status, 500);
  assert.equal(!denied.ok && denied.recovery, 'contact_admin');
  assert.deepEqual(calls, [{ action: 'denied', meta: { reason: 'consent_denied' } }]);

  calls.length = 0;
  const revokedState = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'provider-token' }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })) as typeof fetch;
  try {
    const revoked = await handleOAuthCallback(
      {
        registry,
        vault: { upsertUser: async () => 'revoked' } as any,
        audit: brokenAudit,
        consent,
        redirectUri: 'https://vouchr.test/callback',
      },
      'code',
      revokedState.state,
    );
    assert.equal(!revoked.ok && revoked.outcome, 'setup_changed');
    assert.equal(!revoked.ok && revoked.status, 500);
    assert.equal(!revoked.ok && revoked.recovery, 'contact_admin');
    assert.deepEqual(calls, [{ action: 'denied', meta: { reason: 'revoked' } }]);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('Bolt deduplicates concurrent and repeated OAuth prompts across replicas', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const { a, b } = await openReplicaPair(t);
  const first = await createVouchr({ providers: [provider], baseUrl: 'https://vouchr.test', db: a });
  const second = await createVouchr({ providers: [provider], baseUrl: 'https://vouchr.test', db: b });
  const posts: any[] = [];
  const client = {
    chat: {
      postEphemeral: async (args: unknown) => { posts.push(args); },
      postMessage: async (args: unknown) => { posts.push(args); },
    },
  };
  const [one, two] = await Promise.all([contextFor(first, client), contextFor(second, client)]);
  const outcomes = await Promise.allSettled([one.connect('acme'), two.connect('acme')]);
  assert.equal(outcomes.every((outcome) => outcome.status === 'rejected'), true);
  assert.ok(outcomes.some(
    (outcome) => outcome.status === 'rejected' && outcome.reason instanceof ConsentRequiredError,
  ));
  assert.ok(outcomes.every(
    (outcome) => outcome.status === 'rejected'
      && (outcome.reason instanceof ConsentRequiredError || outcome.reason instanceof UserFacingError),
  ));
  assert.equal(posts.length, 1);
  assert.equal(
    (await a.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM consent_request WHERE superseded_at IS NULL`))?.n,
    1,
  );

  await assert.rejects(() => one.connect('acme'), ConsentRequiredError);
  assert.equal(posts.length, 1, 'a delivered prompt is reused, not reposted');
});

test('Bolt releases definitely rejected OAuth delivery but retains ambiguous delivery', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({ providers: [provider], baseUrl: 'https://vouchr.test', db });
  const platformSecret = 'xoxb_RAW_SLACK_ERROR_MUST_NOT_ESCAPE';
  const platformClient = {
    chat: {
      postEphemeral: async () => { throw Object.assign(new Error(platformSecret), { code: SlackErrorCode.PlatformError }); },
      postMessage: async () => {},
    },
  };
  const rejected = await contextFor(vouchr, platformClient);
  await assert.rejects(
    () => rejected.connect('acme'),
    (error: unknown) => error instanceof UserFacingError
      && /Slack rejected the connection prompt before delivery/i.test(error.message)
      && !error.message.includes(platformSecret),
  );
  assert.equal((await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM consent_request`))?.n, 1);
  assert.equal(
    (await db.get<{ delivery_token: string | null }>(
      `SELECT delivery_token FROM consent_request WHERE superseded_at IS NULL`,
    ))?.delivery_token,
    null,
  );

  let attempts = 0;
  const transportSecret = 'xoxb_RAW_TRANSPORT_ERROR_MUST_NOT_ESCAPE';
  const ambiguousClient = {
    chat: {
      postEphemeral: async () => {
        attempts++;
        throw Object.assign(new Error(transportSecret), { code: SlackErrorCode.RequestError });
      },
      postMessage: async () => {},
    },
  };
  const ambiguous = await contextFor(vouchr, ambiguousClient);
  await assert.rejects(
    () => ambiguous.connect('acme'),
    (error: unknown) => error instanceof UserFacingError
      && /could not confirm connection-prompt delivery/i.test(error.message)
      && !error.message.includes(transportSecret),
  );
  const retained = await db.get<{ delivery_token: string | null }>(
    `SELECT delivery_token FROM consent_request WHERE superseded_at IS NULL`,
  );
  assert.ok(retained?.delivery_token);
  await assert.rejects(() => ambiguous.connect('acme'), /already being delivered/i);
  assert.equal(attempts, 1);
});

test('Bolt sends one private recovery DM for an attributable callback and none for replay', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const apiCalls: Array<{ method: string; args: any }> = [];
  const prototype = WebClient.prototype as any;
  const realApiCall = prototype.apiCall;
  prototype.apiCall = async (method: string, args: any) => {
    apiCalls.push({ method, args });
    return { ok: true, channel: args.channel, ts: '1.0' };
  };
  try {
    const vouchr = await createVouchr({
      providers: [provider],
      baseUrl: 'https://vouchr.test',
      db,
      botToken: 'xoxb-test',
    });
    const prompts: any[] = [];
    const context = await contextFor(vouchr, {
      chat: {
        postEphemeral: async (args: unknown) => { prompts.push(args); },
        postMessage: async (args: unknown) => { prompts.push(args); },
      },
    });
    await assert.rejects(() => context.connect('acme'), ConsentRequiredError);
    const state = new URL(
      prompts[0].blocks.find((block: any) => block.type === 'actions').elements[0].url,
    ).searchParams.get('state')!;

    let callback: any;
    vouchr.mountRoutes({ get: (_path: string, handler: any) => { callback = handler; } });
    const response = fakeResponse();
    await callback({ query: { state, error: 'access_denied' } }, response);
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(response.statusCode, 400);
    assert.equal(response.body, 'OAuth authorization was denied. Please try again.');
    assert.equal(apiCalls.length, 1);
    assert.equal(apiCalls[0].method, 'chat.postMessage');
    assert.equal(apiCalls[0].args.channel, ID.userId);
    assert.match(JSON.stringify(apiCalls[0].args.blocks), /not authorized|re-run the request/i);

    const replay = fakeResponse();
    await callback({ query: { state, error: 'access_denied' } }, replay);
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(replay.statusCode, 400);
    assert.equal(apiCalls.length, 1, 'a replay must not duplicate the private recovery DM');
  } finally {
    prototype.apiCall = realApiCall;
  }
});

test('a provider-side callback error is not messaged as a user denial and is never echoed', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const apiCalls: Array<{ method: string; args: any }> = [];
  const prototype = WebClient.prototype as any;
  const realApiCall = prototype.apiCall;
  prototype.apiCall = async (method: string, args: any) => {
    apiCalls.push({ method, args });
    return { ok: true };
  };
  const foreign = 'server_error_RAW_PROVIDER_ERROR_MUST_NOT_ESCAPE';
  try {
    const vouchr = await createVouchr({
      providers: [provider],
      baseUrl: 'https://vouchr.test',
      db,
      botToken: 'xoxb-test',
    });
    const pending = await new Consent(db).begin(
      ID,
      provider,
      'https://vouchr.test/vouchr/oauth/callback',
      null,
    );
    let callback: any;
    vouchr.mountRoutes({ get: (_path: string, handler: any) => { callback = handler; } });
    const response = fakeResponse();
    // An unknown, secret-bearing error value classifies as permanent (500 + fix_configuration), not
    // a denial and not transient — and its raw text must never reach the browser or Slack.
    await callback({ query: { state: pending.state, error: foreign } }, response);
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(response.statusCode, 500);
    assert.match(String(response.body), /OAuth configuration/i);
    assert.equal(apiCalls.length, 1);
    const dm = JSON.stringify(apiCalls[0].args.blocks);
    assert.match(dm, /configuration/i);
    assert.doesNotMatch(dm, /not authorized|allowed|temporarily unavailable/i);
    assert.ok(!JSON.stringify([response.body, apiCalls]).includes(foreign));
  } finally {
    prototype.apiCall = realApiCall;
  }
});

test('Bolt callback response does not wait for a non-settling Slack recovery DM', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const pending = await new Consent(db).begin(
    ID,
    provider,
    'https://vouchr.test/vouchr/oauth/callback',
    null,
  );
  const prototype = WebClient.prototype as any;
  const realApiCall = prototype.apiCall;
  prototype.apiCall = async () => new Promise(() => {});
  try {
    const vouchr = await createVouchr({
      providers: [provider],
      baseUrl: 'https://vouchr.test',
      db,
      botToken: 'xoxb-test',
    });
    let callback: any;
    vouchr.mountRoutes({ get: (_path: string, handler: any) => { callback = handler; } });
    const response = fakeResponse();
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        callback({ query: { state: pending.state, error: 'access_denied' } }, response),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('browser callback waited for Slack')), 100);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
    assert.equal(response.statusCode, 400);
    assert.equal(response.body, 'OAuth authorization was denied. Please try again.');
  } finally {
    prototype.apiCall = realApiCall;
  }
});

test('Bolt bounds and deduplicates a non-settling multi-workspace notification lookup', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const secondProvider = defineProvider({
    ...provider,
    id: 'acme-two',
  });
  const consent = new Consent(db);
  const [first, second] = await Promise.all([
    consent.begin(ID, provider, 'https://vouchr.test/vouchr/oauth/callback', null),
    consent.begin(ID, secondProvider, 'https://vouchr.test/vouchr/oauth/callback', null),
  ]);
  let lookups = 0;
  const settleLookups: Array<(installation: object) => void> = [];
  const installationStore = {
    fetchInstallation: async () => {
      lookups++;
      return new Promise((resolve) => settleLookups.push(resolve));
    },
  } as any;
  const vouchr = await createVouchr({
    providers: [provider, secondProvider],
    baseUrl: 'https://vouchr.test',
    db,
    installationStore,
  });
  let callback: any;
  vouchr.mountRoutes({ get: (_path: string, handler: any) => { callback = handler; } });

  await Promise.all([
    callback({ query: { state: first.state, error: 'access_denied' } }, fakeResponse()),
    callback({ query: { state: second.state, error: 'access_denied' } }, fakeResponse()),
  ]);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(lookups, 1, 'one workspace lookup is shared across concurrent callback notices');

  await new Promise((resolve) => setTimeout(resolve, 3_100));
  const afterTimeout = await consent.begin(
    ID,
    provider,
    'https://vouchr.test/vouchr/oauth/callback',
    null,
  );
  await callback(
    { query: { state: afterTimeout.state, error: 'access_denied' } },
    fakeResponse(),
  );
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(
    lookups,
    1,
    'a timed-out CALLER gives up, but the unresolved store lookup keeps its slot — the cap bounds unresolved concurrency, not map size',
  );

  settleLookups[0]!({});
  await new Promise<void>((resolve) => setImmediate(resolve));
  const afterSettlement = await consent.begin(
    ID,
    secondProvider,
    'https://vouchr.test/vouchr/oauth/callback',
    null,
  );
  await callback(
    { query: { state: afterSettlement.state, error: 'access_denied' } },
    fakeResponse(),
  );
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(lookups, 2, 'a settled raw lookup releases the workspace for a later lookup');
  for (const settle of settleLookups.slice(1)) settle({});
});

test('Bolt caps hung notification lookups across distinct workspaces', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const consent = new Consent(db);
  const identities = Array.from(
    { length: MAX_PENDING_NOTIFICATION_CLIENT_LOOKUPS + 8 },
    (_, i): SlackIdentity => ({ enterpriseId: null, teamId: `TW${i}`, userId: `UW${i}` }),
  );
  const requests = await Promise.all(
    identities.map((identity) => consent.begin(
      identity,
      provider,
      'https://vouchr.test/vouchr/oauth/callback',
      null,
    )),
  );
  let lookups = 0;
  const settleLookups: Array<(installation: object) => void> = [];
  const vouchr = await createVouchr({
    providers: [provider],
    baseUrl: 'https://vouchr.test',
    db,
    installationStore: {
      fetchInstallation: async () => {
        lookups++;
        return new Promise((resolve) => settleLookups.push(resolve));
      },
    } as any,
  });
  let callback: any;
  vouchr.mountRoutes({ get: (_path: string, handler: any) => { callback = handler; } });

  await Promise.all(requests.map((request) => callback(
    { query: { state: request.state, error: 'access_denied' } },
    fakeResponse(),
  )));
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(
    lookups,
    MAX_PENDING_NOTIFICATION_CLIENT_LOOKUPS,
    'distinct hung workspaces must stop at the process-wide cap',
  );

  const refusedIdentity: SlackIdentity = { enterpriseId: null, teamId: 'TW-over-cap', userId: 'UW-over-cap' };
  const refused = await consent.begin(
    refusedIdentity,
    provider,
    'https://vouchr.test/vouchr/oauth/callback',
    null,
  );
  await callback({ query: { state: refused.state, error: 'access_denied' } }, fakeResponse());
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(lookups, MAX_PENDING_NOTIFICATION_CLIENT_LOOKUPS);

  settleLookups[0]!({});
  await new Promise<void>((resolve) => setImmediate(resolve));
  const recoveredIdentity: SlackIdentity = { enterpriseId: null, teamId: 'TW-recovered', userId: 'UW-recovered' };
  const recovered = await consent.begin(
    recoveredIdentity,
    provider,
    'https://vouchr.test/vouchr/oauth/callback',
    null,
  );
  await callback({ query: { state: recovered.state, error: 'access_denied' } }, fakeResponse());
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(lookups, MAX_PENDING_NOTIFICATION_CLIENT_LOOKUPS + 1, 'a settled slot admits later work');
  for (const settle of settleLookups.slice(1)) settle({});
});

test('an equal-generation write is fenced (millisecond tie fails closed), no sleeps', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const owner = userOwner(ID);
  const tok = { accessToken: 'first', refreshToken: null, scopes: 'read', expiresAt: null, externalAccount: null };
  assert.equal(await vault.upsertUser(owner, provider.id, tok, await vault.userProvisioningIssuedAt()), 'stored');
  // Read the exact generation the credential committed at, then issue a write AT that same
  // millisecond. Integer-ms clocks make this tie reachable in production; it must fail closed (`>=`),
  // so a stale write can never win the tie and overwrite a causally-newer credential.
  const gen = (await db.get<{ generation_at: number }>(
    `SELECT generation_at FROM connection WHERE team_id=? AND owner_id=? AND provider=?`,
    [owner.teamId, owner.id, provider.id],
  ))!.generation_at;
  const result = await vault.upsertUser(
    owner, provider.id, { ...tok, accessToken: 'tie-write' }, gen,
  );
  assert.equal(result, 'stale', 'a write issued at the exact existing generation must fail closed');
  assert.equal((await vault.get(owner, provider.id))?.accessToken, 'first');
});

test('a direct credential write supersedes an older pending consent so fresh demand never reuses a dead URL', async (t) => {
  const db = await openTestDb(t);
  const consent = new Consent(db);
  const vault = new Vault(db, KEY);
  const owner = userOwner(ID);
  // A pending "Connect" exists...
  const old = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  await new Promise((resolve) => setTimeout(resolve, 2));
  // ...then a credential commits by another path (e.g. a key set, or a broker connect that landed).
  assert.equal(
    await vault.upsertUser(owner, provider.id, {
      accessToken: 'live', refreshToken: null, scopes: 'read', expiresAt: null, externalAccount: null,
    }, await vault.userProvisioningIssuedAt()),
    'stored',
  );
  // The old consent is now superseded (its callback would lose the generation fence), so a fresh
  // connect mints a NEW generation rather than reusing the guaranteed-stale URL.
  assert.equal((await consent.consume(old.state)).status, 'superseded');
  const fresh = await consent.beginFenced(ID, provider, 'https://vouchr.test/callback', 'C1', await vault.userProvisioningIssuedAt());
  assert.ok(fresh);
  assert.notEqual(fresh.state, old.state, 'fresh demand must not reuse the superseded state');
});

test('supersession fails the equal-millisecond consent closed too (matches the >= fence), no sleeps', async (t) => {
  const db = await openTestDb(t);
  const consent = new Consent(db);
  const vault = new Vault(db, KEY);
  const owner = userOwner(ID);
  const pending = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  // Read the consent's exact created_at and write a credential issued at THAT same millisecond. The
  // fence would fail this consent's callback closed (`>=`), so cleanup must supersede it too (`<=`);
  // a strict `<` would leave the equal-time consent reusable as a dead URL.
  const createdAt = (await db.get<{ created_at: number }>(
    `SELECT created_at FROM consent_request WHERE state=?`, [pending.state],
  ))!.created_at;
  assert.equal(
    await vault.upsertUser(owner, provider.id, {
      accessToken: 'live', refreshToken: null, scopes: 'read', expiresAt: null, externalAccount: null,
    }, createdAt),
    'stored',
  );
  assert.equal((await consent.consume(pending.state)).status, 'superseded', 'the equal-time consent must be superseded');
});

test('the approval fan-out honors an overall deadline across many waves (cannot outlive its lease)', async () => {
  const N = 60;
  const items = Array.from({ length: N }, (_, i) => i);
  let started = 0;
  const start = Date.now();
  const results = await settledWithLimit(items, 4, async () => {
    started++;
    await new Promise((r) => setTimeout(r, 100));
  }, 150);
  const elapsed = Date.now() - start;
  // Sequential/uncapped would be (N/4) × 100ms = 1500ms; the deadline caps it near 150ms + one wave.
  assert.ok(elapsed < 500, `fan-out ignored its deadline: ${elapsed}ms for ${N} items`);
  assert.ok(started < N, 'the deadline must stop starting the tail');
  assert.equal(results.length, N, 'every item still has a recorded outcome');
  assert.ok(
    results.some((r) => r.status === 'rejected' && r.reason instanceof PromptFanoutDeadlineError),
    'skipped items are recorded as deadline errors (classified ambiguous → lease retained)',
  );
});

test('re-authorization over a live credential replaces it; a delayed stale callback still loses', async (t) => {
  const db = await openTestDb(t);
  const consent = new Consent(db);
  const audit = new Audit(db);
  const vault = new Vault(db, KEY);
  const registry = new ProviderRegistry([provider]);
  const deps = { registry, vault, audit, consent, redirectUri: 'https://vouchr.test/callback' };
  const owner = userOwner(ID);
  let providerToken = 'token-1';
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: providerToken }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })) as typeof fetch;
  try {
    const first = await consent.begin(ID, provider, deps.redirectUri, 'C1');
    assert.equal((await handleOAuthCallback(deps, 'code-1', first.state)).ok, true);

    // A consent generation minted BEFORE the newest credential write can never overwrite it.
    const stale = await consent.begin(ID, provider, deps.redirectUri, 'C1');
    providerToken = 'token-from-stale-callback';
    await new Promise((resolve) => setTimeout(resolve, 2)); // strictly newer PostgreSQL-ms generation
    const direct = {
      accessToken: 'token-direct', refreshToken: null, scopes: 'read', expiresAt: null, externalAccount: null,
    };
    assert.equal(
      await vault.upsertUser(owner, provider.id, direct, await vault.userProvisioningIssuedAt()),
      'stored',
    );
    const staleResult = await handleOAuthCallback(deps, 'code-2', stale.state);
    assert.equal(!staleResult.ok && staleResult.outcome, 'state_stale');
    assert.equal((await vault.get(owner, provider.id))?.accessToken, 'token-direct');

    // Re-auth while connected (provider-side-dead token, scope change) must not dead-end: a
    // generation minted AFTER the live credential replaces it instead of looping on state_stale.
    await new Promise((resolve) => setTimeout(resolve, 2));
    const reauth = await consent.begin(ID, provider, deps.redirectUri, 'C1');
    providerToken = 'token-2';
    const result = await handleOAuthCallback(deps, 'code-3', reauth.state);
    assert.equal(result.ok, true);
    assert.equal((await vault.get(owner, provider.id))?.accessToken, 'token-2');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('a delivered but possibly-vanished ephemeral prompt is not claimed as freshly posted', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({ providers: [provider], baseUrl: 'https://vouchr.test', db });
  const posts: any[] = [];
  const client = {
    chat: {
      postEphemeral: async (args: unknown) => { posts.push(args); },
      postMessage: async (args: unknown) => { posts.push(args); },
    },
  };
  const context = await contextFor(vouchr, client);
  await assert.rejects(
    () => context.connect('acme'),
    (error: unknown) => error instanceof ConsentRequiredError && /was posted/.test(error.message),
  );
  assert.equal(posts.length, 1);
  await assert.rejects(
    () => context.connect('acme'),
    (error: unknown) => error instanceof ConsentRequiredError
      && /already posted/.test(error.message)
      && /no longer visible/.test(error.message),
    'an ephemeral vanishes on reload; the reuse fence must not claim a fresh post',
  );
  assert.equal(posts.length, 1, 'the live prompt is reused, not reposted');
});

test('a leased prompt post is bounded AND preserves the operator Slack transport', async (t) => {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  const db = await openTestDb(t);
  // A deployment with a non-default Slack endpoint must not be bypassed by the bounded prompt client.
  const vouchr = await createVouchr({
    providers: [provider],
    baseUrl: 'https://vouchr.test',
    db,
    slackClientOptions: { slackApiUrl: 'https://slack-proxy.internal/api/' },
  });
  const posted: Array<{ retries: unknown; rejectRateLimited: unknown; timeout: unknown; apiUrl: unknown }> = [];
  const prototype = WebClient.prototype as any;
  const realApiCall = prototype.apiCall;
  prototype.apiCall = async function (this: any) {
    posted.push({
      retries: this.retryConfig?.retries,
      rejectRateLimited: this.rejectRateLimitedCalls,
      timeout: this.requestConfig?.timeout ?? this.timeout,
      apiUrl: this.slackApiUrl,
    });
    return { ok: true };
  };
  try {
    const context = await contextFor(vouchr, { token: 'xoxb-context', chat: {} });
    await assert.rejects(() => context.connect('acme'), ConsentRequiredError);
    assert.equal(posted.length, 1);
    assert.equal(posted[0].retries, 0, 'a leased prompt post must not queue SDK retries past its lease');
    assert.equal(posted[0].rejectRateLimited, true, 'a 429 must fail the leased post, not park it in the SDK queue');
    assert.equal(posted[0].apiUrl, 'https://slack-proxy.internal/api/', 'the operator transport must survive the bound');
  } finally {
    prototype.apiCall = realApiCall;
  }
});

test('every user-owned issuance shape is generation-fenced: an older key/reference write loses with no audit', async (t) => {
  const { a, b } = await openReplicaPair(t);
  const vaultA = new Vault(a, KEY);
  const vaultB = new Vault(b, KEY);
  const owner = userOwner(ID);
  const audits = await b.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='connect'`);

  // Replica A captures an issuance, then replica B commits a NEWER credential (a rotation) before A
  // writes. A's numeric (direct key/reference) write must lose to the newer generation — the fence
  // is unconditional, not resolver-object-only — and it must NOT emit a connect audit row.
  const staleIssuedAt = await vaultA.userProvisioningIssuedAt();
  await new Promise((resolve) => setTimeout(resolve, 2));
  assert.equal(
    await vaultB.upsertUser(owner, provider.id, {
      accessToken: 'newer', refreshToken: null, scopes: 'read', expiresAt: null, externalAccount: null,
    }, await vaultB.userProvisioningIssuedAt()),
    'stored',
  );
  let audited = false;
  const staleWrite = await vaultA.referenceUser(
    owner, provider.id,
    { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:us-east-1:1:secret:x', scopes: 'read' },
    staleIssuedAt,
    async () => { audited = true; },
  );
  assert.equal(staleWrite, 'stale', 'a numeric issuance older than the live credential must be fenced');
  assert.equal(audited, false, 'a fenced write must not run its audit companion');
  assert.equal((await vaultA.get(owner, provider.id))?.accessToken, 'newer', 'the newer credential survives');
  assert.equal(
    (await b.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='connect'`))?.n,
    audits?.n,
    'no extra connect audit from the fenced write',
  );
});

test("an offboarded user's surviving expired link is account-inactive, not \"ask again\"", async (t) => {
  const db = await openTestDb(t);
  const consent = new Consent(db);
  // Offboarding tolerates a failed consent-row purge, so the row can outlive STATE_TTL_MS with no
  // re-onboarding. Expiry must NOT mask the lifecycle invalidation the user must act on.
  const pending = await consent.begin(ID, provider, 'https://vouchr.test/callback', 'C1');
  await consent.markOffboarded(ID);
  await new Promise((resolve) => setTimeout(resolve, 2));
  await db.run(`UPDATE consent_request SET created_at=? WHERE state=?`, [Date.now() - STATE_TTL_MS - 1_000, pending.state]);
  const claim = await consent.consume(pending.state);
  assert.equal(claim.status, 'invalidated', 'a blocking tombstone wins over expiry');
  assert.equal(claim.status === 'invalidated' && claim.reason, 'offboarded');
});

test('mapSafeError emits fixed copy for a reused (possibly-hidden) Connect prompt', () => {
  const posted = mapSafeError(new ConsentRequiredError('acme', 'posted'));
  const reused = mapSafeError(new ConsentRequiredError('acme', 'reused'));
  assert.equal(posted.recovery, 'connect');
  assert.equal(reused.recovery, 'connect');
  assert.match(posted.message, /Complete the private Connect prompt/);
  assert.match(reused.message, /no longer visible/); // never claims the ephemeral is on screen
  assert.doesNotMatch(reused.message, /Complete the private Connect prompt, then retry/);
});
