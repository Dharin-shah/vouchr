import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { Approvals, ApprovalRequiredError, queryDigest } from '../src/core/approval';
import { approvalNeeded, EgressBlockedError } from '../src/core/injector';
import { defineProvider, github, type Provider } from '../src/core/providers';
import { ChannelConfig } from '../src/core/channelConfig';
import { userOwner, channelOwner } from '../src/core/owner';
import { sweepExpired } from '../src/core/sweep';
import { createVouchr } from '../src/adapters/bolt';
import { APPROVAL_APPROVE_ACTION, APPROVAL_DENY_ACTION } from '../src/adapters/blocks';
import { createBroker } from '../src/adapters/http/broker';
import { signIdentity } from '../src/adapters/http/identity';

// #113 human-in-the-loop approval for sensitive writes: the full state machine (prompt → approve →
// consume → re-prompt; deny; TTL expiry; the double-consume race), gate ordering (egress beats
// approval), the admin/self approver matrices with forged clicks, the broker's 403 shape, the sweep,
// and the no-knob zero-change guarantee. No network: outbound fetch is stubbed (restored in
// finally), Slack is a fake client, and the SQL runs on a throwaway PostgreSQL schema.

const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const BODY_SENTINEL = 'SECRET_BODY_PAYLOAD_never_rendered';
const TOKEN = 'tok_live_secret_value';

const approvalProvider = (over: Partial<Provider> = {}): Provider => defineProvider({
  id: 'acme', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.acme.test'], egressMethods: ['GET', 'POST'],
  approval: { approver: 'self' },
  refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  ...over,
});

/** Stub global fetch (TEST-3), recording outbound calls; ALWAYS restored in finally. */
async function withFetch<T>(fn: (calls: { url: string; init?: RequestInit }[]) => Promise<T>): Promise<T> {
  const real = globalThis.fetch;
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = (async (url: any, init?: any) => {
    calls.push({ url: String(url), init });
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  }) as any;
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = real;
  }
}

/** Fake clock: run `fn` with Date.now() shifted forward by `ms`; ALWAYS restored in finally. */
async function withClockOffset<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  const real = Date.now;
  const base = real();
  Date.now = () => base + ms;
  try {
    return await fn();
  } finally {
    Date.now = real;
  }
}

/** Capture the typed rejection from a fetch that must prompt. */
async function expectApprovalRequired(p: Promise<unknown>): Promise<ApprovalRequiredError> {
  try {
    await p;
  } catch (e) {
    assert.ok(e instanceof ApprovalRequiredError, `expected ApprovalRequiredError, got ${(e as Error)?.name}`);
    return e;
  }
  throw new Error('expected the fetch to throw ApprovalRequiredError');
}

/**
 * Integration harness through the PUBLIC API (TEST-2): a real createVouchr, its real middleware
 * building context.vouchr, and the real registered Approve/Deny action handlers — Slack faked.
 */
async function harness(t: TestContext, o: { provider?: Provider; slackAdmins?: string[]; members?: string[]; sharedChannel?: boolean } = {}) {
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');
  const provider = o.provider ?? approvalProvider();
  const vouchr = await createVouchr({ providers: [provider], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t) });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, h: any) => (actions[id] = h),
  });
  const ephemerals: any[] = [];
  const dms: any[] = [];
  const admins = new Set(o.slackAdmins ?? []);
  const client = {
    users: { info: async ({ user }: any) => ({ user: { is_admin: admins.has(user) } }) },
    conversations: {
      info: async ({ channel }: any) => ({ channel: { id: channel, is_channel: true, creator: 'U_CREATOR' } }),
      members: async () => ({ members: o.members ?? ['U1'] }),
    },
    chat: {
      postEphemeral: async (p: any) => { ephemerals.push(p); return {}; },
      postMessage: async (p: any) => { dms.push(p); return {}; },
    },
  } as any;
  // The real middleware builds context.vouchr from a (fake) verified Slack event: channel C1, thread TH1.
  const args: any = { context: {}, client, event: { channel: 'C1', user: 'U1', team: 'T1', thread_ts: 'TH1' }, next: async () => {} };
  await vouchr.middleware(args);
  const ctx = args.context.vouchr;
  if (o.sharedChannel) {
    // shared: the CHANNEL owns the credential (owner_kind=channel/owner_id=C1); the caller borrows it.
    await new ChannelConfig(vouchr.db).setMode('T1', 'C1', provider.id, 'shared');
    await vouchr.vault.upsert(channelOwner('T1', 'C1'), provider.id, {
      accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  } else {
    await vouchr.vault.upsert(userOwner(ID), provider.id, {
      accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
    });
  }
  const click = (actionId: string, clicker: string, value: string, responds: any[] = []) =>
    actions[actionId]({
      ack: async () => {},
      body: { team: { id: 'T1' }, user: { id: clicker }, channel: { id: 'C1' }, actions: [{ value }] },
      client,
      respond: async (m: any) => { responds.push(m); },
    });
  const auditRows = async () =>
    (await vouchr.db.all(`SELECT action, user_id, actor, meta FROM audit ORDER BY at`)) as any[];
  const approvalRows = async () =>
    (await vouchr.db.all(`SELECT * FROM approval_request`)) as any[];
  return { vouchr, ctx, ephemerals, dms, click, auditRows, approvalRows, provider };
}

// ── predicate ─────────────────────────────────────────────────────────────────────────────────────

test('approvalNeeded: default is every non-read method; explicit methods/paths narrow it', () => {
  const base = { approver: 'self' as const };
  for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) assert.equal(approvalNeeded(base, m, '/x'), true);
  assert.equal(approvalNeeded(base, 'GET', '/x'), false);
  assert.equal(approvalNeeded(base, 'HEAD', '/x'), false);
  // Explicit methods replace the default (case-insensitive), and GET can be opted IN.
  assert.equal(approvalNeeded({ ...base, methods: ['get'] }, 'GET', '/x'), true);
  assert.equal(approvalNeeded({ ...base, methods: ['DELETE'] }, 'POST', '/x'), false);
  // Paths use the same matcher semantics as egressPaths: exact segment or subpath, '/' = all.
  assert.equal(approvalNeeded({ ...base, paths: ['/repos'] }, 'POST', '/repos/r/issues'), true);
  assert.equal(approvalNeeded({ ...base, paths: ['/repos'] }, 'POST', '/user'), false);
});

test('defineProvider: garbage approval knobs are rejected at definition time (SEC-4)', () => {
  const spec = (approval: any) => () => approvalProvider({ approval });
  assert.throws(spec({ approver: 'anyone' }), /approval\.approver/);
  assert.throws(spec({}), /approval\.approver/);
  assert.throws(spec({ approver: 'self', methods: [] }), /approval\.methods/);
  assert.throws(spec({ approver: 'self', paths: [] }), /approval\.paths/);
  assert.throws(spec({ approver: 'self', ttlMs: 0 }), /approval\.ttlMs/);
  assert.throws(spec({ approver: 'self', ttlMs: Number.NaN }), /approval\.ttlMs/);
});

test('defineProvider: non-canonical approval paths/methods are rejected; methods normalize (P2-D fail-open guard)', () => {
  const spec = (approval: any) => () => approvalProvider({ approval });
  // These are non-empty but never match url.pathname / the upper-cased method, so before this guard
  // they'd DISABLE approval silently. Reject them (fail closed).
  assert.throws(spec({ approver: 'self', paths: ['repos'] }), /approval\.paths/); // no leading slash
  assert.throws(spec({ approver: 'self', paths: [' /repos'] }), /approval\.paths/); // leading space
  assert.throws(spec({ approver: 'self', paths: ['/pay ments'] }), /approval\.paths/); // re-encoded on parse
  assert.throws(spec({ approver: 'self', methods: ['PO ST'] }), /approval\.methods/); // internal space
  // A trailing-space / lowercase method is CANONICALIZABLE → normalized (trim + upper) so it actually
  // matches, instead of silently disabling approval.
  const p = approvalProvider({ approval: { approver: 'self', methods: ['post ', 'Delete'] } });
  assert.deepEqual(p.approval!.methods, ['POST', 'DELETE']);
  assert.equal(approvalNeeded(p.approval!, 'POST', '/x'), true);
  assert.equal(approvalNeeded(p.approval!, 'DELETE', '/x'), true);
});

test('P2-C: the approval knob threads through built-in provider configs (github) and enforces', async (t) => {
  const gh = github({ clientId: 'c', clientSecret: 's', approval: { approver: 'self' } });
  assert.deepEqual(gh.approval, { approver: 'self' }, 'ProviderConfig → egressOptions → defineProvider');
  const { ctx } = await harness(t, { provider: gh });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('github');
    await handle.fetch('https://api.github.com/user'); // GET: no approval
    assert.equal(calls.length, 1);
    await expectApprovalRequired(handle.fetch('https://api.github.com/user/repos', { method: 'POST' }));
    assert.equal(calls.length, 1, 'the write was gated, not sent');
  });
});

// ── the full state machine, through the public Bolt API ──────────────────────────────────────────

test('state machine: prompt → approve → consume exactly once → re-prompt', async (t) => {
  const { ctx, ephemerals, click, auditRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');

    // A read passes with no gate (default predicate = non-GET/HEAD only).
    await handle.fetch('https://api.acme.test/user');
    assert.equal(calls.length, 1);

    // A write with no grant: NOTHING reaches the wire, a prompt is posted, the typed error throws.
    const e = await expectApprovalRequired(
      handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL }),
    );
    assert.equal(calls.length, 1, 'the unapproved write never hit the network');
    assert.equal(e.approver, 'self');
    assert.ok(e.approvalId);
    assert.equal(ephemerals.length, 1);
    assert.equal(ephemerals[0].user, 'U1'); // 'self': the acting user gets the prompt
    assert.equal(ephemerals[0].thread_ts, 'TH1');
    const rendered = JSON.stringify(ephemerals[0].blocks);
    assert.match(rendered, /POST/);
    assert.match(rendered, /api\.acme\.test\/repos/);
    // SEC-1: the prompt shows method+host+path, NEVER the body and never the token.
    assert.ok(!rendered.includes(BODY_SENTINEL));
    assert.ok(!rendered.includes(TOKEN));

    // Approve (self = the requester), then the retried fetch consumes the grant and executes.
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 2, 'the approved retry executed exactly once');

    // Single-use: the SAME identical fetch immediately re-prompts (no second free pass).
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL }));
    assert.equal(calls.length, 2);

    // Audit trail: requested → approved → consumed, approver in the actor column (STR-4), and
    // meta carries method+host+path only — never the body, a token, or a query value (SEC-1).
    const rows = await auditRows();
    const actions = rows.map((r) => r.action);
    assert.ok(actions.includes('approval_requested'));
    assert.ok(actions.includes('approved'));
    assert.ok(actions.includes('approval_consumed'));
    const approved = rows.find((r) => r.action === 'approved');
    assert.equal(approved.user_id, 'U1'); // the requester owns the row
    assert.equal(approved.actor, 'U1'); // the approver rides the actor column
    const consumed = rows.find((r) => r.action === 'approval_consumed');
    assert.equal(consumed.actor, 'U1');
    assert.deepEqual(JSON.parse(consumed.meta), { host: 'api.acme.test', method: 'POST', path: '/repos', channel: 'C1' });
    assert.ok(!JSON.stringify(rows).includes(BODY_SENTINEL), 'no body bytes in audit');
    assert.ok(!JSON.stringify(rows).includes(TOKEN), 'no token in audit');
  });
});

test('exact matching: a grant never covers a different method, path, or query', async (t) => {
  // PUT is egress-allowed here so the mismatch reaches the APPROVAL gate (not the egress one).
  const { ctx, click } = await harness(t, { provider: approvalProvider({ egressMethods: ['GET', 'POST', 'PUT'] }) });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    // Approved POST /repos does NOT authorize POST /repos/evil (exact path, not a prefix)…
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos/evil', { method: 'POST' }));
    // …nor PUT /repos (exact method)…
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'PUT' }));
    // …nor POST /repos?x=1 (GHSA-pg84: added query parameters are a DIFFERENT action).
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos?x=1', { method: 'POST' }));
    assert.equal(calls.length, 0, 'nothing reached the wire');
    // The original approved tuple still works (the grant was not burned by the mismatches).
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    assert.equal(res.status, 200);
  });
});

// ── GHSA-pg84: the grant binds the exact (canonical) query parameters ──────────────────────────────

test('queryDigest: byte-exact — ANY textual change (order, duplicates, encoding) is a different action', () => {
  assert.equal(queryDigest(''), '');
  assert.equal(queryDigest('?'), '');
  assert.equal(queryDigest('?a=1&b=2'), queryDigest('?a=1&b=2')); // identical bytes match
  assert.notEqual(queryDigest('?a=1&b=2'), queryDigest('?b=2&a=1')); // reordering re-prompts (fail closed)
  assert.notEqual(queryDigest('?amount=10&amount=1000000'), queryDigest('?amount=1000000&amount=10')); // duplicate order matters upstream
  assert.notEqual(queryDigest('?a=%31'), queryDigest('?a=1')); // different bytes upstream = different action
  assert.notEqual(queryDigest('?a=1'), queryDigest('?a=2')); // changed value
  assert.notEqual(queryDigest('?a=1'), queryDigest('?b=1')); // changed key
  assert.notEqual(queryDigest('?a=1'), queryDigest('?a=1&a=1')); // repeated param is different
  assert.notEqual(queryDigest('?a=1'), ''); // params never collapse to the no-query value
  assert.notEqual(queryDigest('?a=1'), 'pre-v5'); // and can never equal the migration sentinel
});

test('GHSA-pg84: an approval binds the exact query — tampered, reordered, or duplicate-shuffled retries re-prompt', async (t) => {
  const { ctx, click, ephemerals, approvalRows, auditRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const QUERY_SENTINEL = 'alice-PII-payee'; // a query VALUE that must never leave the process
    const e = await expectApprovalRequired(
      handle.fetch(`https://api.acme.test/transfer?to=${QUERY_SENTINEL}&amount=10`, { method: 'POST' }),
    );
    // The human sees only the parameter COUNT (names are as caller-controlled as values, SEC-1)…
    assert.equal(e.queryParamCount, 2);
    const rendered = JSON.stringify(ephemerals[0].blocks);
    assert.match(rendered, /\(2 parameters\)/);
    // …and neither values nor names reach Slack, the error serialization, the store, or audit.
    assert.ok(!rendered.includes(QUERY_SENTINEL), 'no query value in the prompt');
    assert.ok(!rendered.includes('to='), 'no parameter names in the prompt');
    assert.ok(!JSON.stringify({ ...e }).includes(QUERY_SENTINEL), 'no query data on enumerable error properties');
    assert.ok(!JSON.stringify(await approvalRows()).includes(QUERY_SENTINEL), 'no raw query in the approval row');
    assert.ok(!JSON.stringify(await auditRows()).includes(QUERY_SENTINEL), 'no raw query in audit');

    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    // ANY textual change to the query is a different action: re-prompts, grant intact.
    await expectApprovalRequired(
      handle.fetch('https://api.acme.test/transfer?to=attacker&amount=1000000', { method: 'POST' }),
    );
    await expectApprovalRequired( // reordered params — upstream may parse differently, fail closed
      handle.fetch(`https://api.acme.test/transfer?amount=10&to=${QUERY_SENTINEL}`, { method: 'POST' }),
    );
    assert.equal(calls.length, 0, 'no mismatched retry reached the wire');
    // The byte-identical retry consumes the grant exactly once.
    const res = await handle.fetch(`https://api.acme.test/transfer?to=${QUERY_SENTINEL}&amount=10`, { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1, 'the faithful retry executed exactly once');
    assert.ok(!JSON.stringify(await auditRows()).includes(QUERY_SENTINEL), 'consumption audit carries no raw query');
  });
});

test('GHSA-pg84: a secret in a parameter NAME never reaches the prompt or the error serialization', async (t) => {
  const { ctx, ephemerals } = await harness(t);
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    const NAME_SENTINEL = 'ghp_name_sentinel_token'; // a query KEY that must never leave the process
    const e = await expectApprovalRequired(
      handle.fetch(`https://api.acme.test/transfer?${NAME_SENTINEL}=1`, { method: 'POST' }),
    );
    assert.equal(e.queryParamCount, 1);
    assert.ok(!JSON.stringify({ ...e }).includes(NAME_SENTINEL), 'no name on enumerable error properties');
    assert.ok(!e.message.includes(NAME_SENTINEL), 'no name in the error message');
    assert.ok(!JSON.stringify(ephemerals[0].blocks).includes(NAME_SENTINEL), 'no name in the Slack prompt');
  });
});

test('GHSA-pg84: duplicate-key reordering cannot spend a grant (first-wins vs last-wins upstreams)', async (t) => {
  const { ctx, click } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(
      handle.fetch('https://api.acme.test/transfer?amount=10&amount=1000000', { method: 'POST' }),
    );
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    // Same multiset of parameters, different order — a first-wins upstream now reads 1000000.
    await expectApprovalRequired(
      handle.fetch('https://api.acme.test/transfer?amount=1000000&amount=10', { method: 'POST' }),
    );
    assert.equal(calls.length, 0);
    const res = await handle.fetch('https://api.acme.test/transfer?amount=10&amount=1000000', { method: 'POST' });
    assert.equal(res.status, 200); // the exact approved bytes still work
  });
});

test('P1-B: an encoded path separator cannot slip past an approval.paths lock (fail closed)', async (t) => {
  // approval.paths WITHOUT an independent egressPaths: `/payments%2Fsend` does not prefix-match
  // `/payments`, but an upstream that decodes %2F routes it as `/payments/send`. Before the guard it
  // needed NO approval and ran; now it REQUIRES approval. Fail-before (executes, no throw) / pass-after.
  const { ctx, approvalRows } = await harness(t, { provider: approvalProvider({ approval: { approver: 'self', paths: ['/payments'] } }) });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    await expectApprovalRequired(handle.fetch('https://api.acme.test/payments%2Fsend', { method: 'POST' }));
    assert.equal(calls.length, 0, 'the encoded-separator write never reached the wire unconfirmed');
    assert.equal((await approvalRows()).length, 1, 'it minted a pending approval instead of bypassing');
    // A path plainly OUTSIDE the lock still needs no approval (the guard didn't over-fire).
    const res = await handle.fetch('https://api.acme.test/orders', { method: 'POST' });
    assert.equal(res.status, 200);
  });
});

// ── P1-A: grants are bound to the credential OWNER (mode change) and to its lifecycle ──

test('P1-A(a): a grant minted for one credential owner cannot be consumed for another (owner change)', async (t) => {
  // Models a mode/owner change between prompt and retry (e.g. per-user → shared): the grant is keyed
  // to owner A, so a consume that resolves to owner B must MISS (the write would otherwise run against
  // a DIFFERENT credential than was approved). Store-level, deterministic. Fail-before: without the
  // owner clause in consume(), the B-owner consume would wrongly succeed.
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const forOwner = (ownerId: string) => ({
    teamId: 'T1', userId: 'U_CALLER', ownerKind: 'user' as const, ownerId,
    provider: 'acme', method: 'POST', host: 'api.acme.test', path: '/repos', queryHash: '', channel: 'C1', thread: 'TH1',
  });
  const id = await approvals.request(forOwner('U_OWNER_A'));
  assert.ok(await approvals.approve(id, 'U_CALLER', 60_000));
  // Resolution switched to owner B → the grant for A does not match.
  assert.equal(await approvals.consume(forOwner('U_OWNER_B')), null);
  // The grant for the ORIGINAL owner A is still spendable exactly once.
  assert.ok(await approvals.consume(forOwner('U_OWNER_A')));
});

test('P1-A(b): disconnect purges live grants, so a reconnect cannot spend the old approval', async (t) => {
  // Mint + approve a grant, then disconnect (vault.delete — the shared disconnect/offboard/revoke/
  // expiry primitive) and reconnect (vault.upsert). The old grant must be gone. Fail-before: without
  // the vault-side purge the grant survives the delete and, since the reconnect restores the SAME
  // owner, the retry would consume it and run the write with NO fresh human approval.
  const { ctx, vouchr, click, approvalRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    assert.equal((await approvalRows()).filter((r) => r.status === 'granted').length, 1, 'grant is live before disconnect');

    // Disconnect (delete) then reconnect (upsert) the SAME owner+provider.
    await vouchr.vault.delete(userOwner(ID), 'acme');
    assert.equal((await approvalRows()).length, 0, 'disconnect purged the grant');
    await vouchr.vault.upsert(userOwner(ID), 'acme', { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

    // The retry finds no grant → re-prompts (the write is NOT silently executed on the old approval).
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0);
  });
});

test('deny: audited with the approver as actor, requester notified, no grant minted', async (t) => {
  const { ctx, click, auditRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const responds: any[] = [];
    await click(APPROVAL_DENY_ACTION, 'U1', e.approvalId, responds);
    assert.match(responds[0]?.text ?? '', /Denied/);
    // Denied: the retry re-prompts (a fresh request), never executes.
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0);
    const denied = (await auditRows()).find((r) => r.action === 'denied' && r.meta.includes('approval-denied'));
    assert.ok(denied, 'denied audit row written');
    assert.equal(denied.user_id, 'U1'); // attributed to the requester
    assert.equal(denied.actor, 'U1'); // decided by the approver
    assert.deepEqual(JSON.parse(denied.meta), { host: 'api.acme.test', method: 'POST', path: '/repos', channel: 'C1', reason: 'approval-denied' });
  });
});

test('TTL expiry (fake clock): an unspent grant dies after ttlMs and the next fetch re-prompts', async (t) => {
  const { ctx, click } = await harness(t, { provider: approvalProvider({ approval: { approver: 'self', ttlMs: 60_000 } }) });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    // Past the grant TTL the retried fetch finds nothing to consume and prompts again.
    await withClockOffset(61_000, async () => {
      await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    });
    assert.equal(calls.length, 0, 'the expired grant never authorized a call');
  });
});

test('race: two concurrent identical fetches cannot both spend one grant (DELETE…RETURNING)', async (t) => {
  const { ctx, click } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    const results = await Promise.allSettled([
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
      handle.fetch('https://api.acme.test/repos', { method: 'POST' }),
    ]);
    const ok = results.filter((r) => r.status === 'fulfilled');
    const failed = results.filter((r) => r.status === 'rejected') as PromiseRejectedResult[];
    assert.equal(ok.length, 1, 'exactly one retry consumed the grant');
    assert.equal(failed.length, 1);
    assert.ok(failed[0].reason instanceof ApprovalRequiredError, 'the loser re-prompts, never executes');
    assert.equal(calls.length, 1, 'exactly one call reached the wire');
  });
});

test('race: two concurrent store-level consumes yield exactly one winner (consent-consume pattern)', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const key = { teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1', provider: 'acme', method: 'POST', host: 'api.acme.test', path: '/repos', queryHash: '', channel: 'C1', thread: null };
  const id = await approvals.request(key);
  assert.ok(await approvals.approve(id, 'U9', 60_000));
  const [a, b] = await Promise.all([approvals.consume(key), approvals.consume(key)]);
  assert.equal([a, b].filter((r) => r !== null).length, 1);
  // The winner carries the approver for audit attribution.
  assert.equal((a ?? b)!.approvedBy, 'U9');
});

test('concurrent decisions: approve and deny on one pending request — exactly one wins', async (t) => {
  const db = await openTestDb(t);
  const approvals = new Approvals(db);
  const key = { teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1', provider: 'acme', method: 'POST', host: 'api.acme.test', path: '/repos', queryHash: '', channel: null, thread: null };
  const id = await approvals.request(key);
  const [approved, denied] = await Promise.all([approvals.approve(id, 'U9', 60_000), approvals.deny(id)]);
  assert.equal([approved !== false && approved !== null, denied !== null].filter(Boolean).length, 1);
});

// ── gate ordering: approval is an ADDITIONAL gate, never a bypass ─────────────────────────────────

test('ordering: an egress-denied target throws EgressBlockedError and never mints a prompt', async (t) => {
  const { ctx, ephemerals, auditRows, approvalRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    // Host off the allowlist: egress wins.
    await assert.rejects(() => handle.fetch('https://evil.test/x', { method: 'POST' }), EgressBlockedError);
    // Method off egressMethods (GET/POST): egress wins over the approval predicate too.
    await assert.rejects(() => handle.fetch('https://api.acme.test/x', { method: 'DELETE' }), EgressBlockedError);
    assert.equal(calls.length, 0);
    assert.equal(ephemerals.length, 0, 'no approval prompt for an egress-denied request');
    assert.equal((await approvalRows()).length, 0, 'no pending approval row minted');
    assert.ok(!(await auditRows()).some((r) => r.action === 'approval_requested'));
  });
});

// ── approver matrices ─────────────────────────────────────────────────────────────────────────────

test("admin approver: prompts go to eligible admins; forged/ineligible clicks are rejected AND audited; an admin's approval works", async (t) => {
  const { ctx, ephemerals, dms, click, auditRows } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'admin' } }),
    slackAdmins: ['U_ADM'],
    members: ['U1', 'U_ADM', 'U_RANDO'],
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL }));
    assert.equal(e.approver, 'admin');
    // The prompt goes to the one eligible admin — not the requester, not a random member.
    assert.deepEqual(ephemerals.map((p) => p.user), ['U_ADM']);
    assert.ok(!JSON.stringify(ephemerals).includes(BODY_SENTINEL), 'SEC-1: no body in the admin prompt');

    // SEC-3: every interaction field is forgeable — a non-admin click (even the requester's own)
    // is re-checked server-side, rejected, and audited.
    await click(APPROVAL_APPROVE_ACTION, 'U_RANDO', e.approvalId);
    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    const rejected = (await auditRows()).filter((r) => r.action === 'denied' && r.meta.includes('not-approver'));
    assert.equal(rejected.length, 2);
    assert.deepEqual(rejected.map((r) => r.user_id).sort(), ['U1', 'U_RANDO']);
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0, 'no grant existed after the rejected clicks');

    // The real admin approves the SECOND prompt; the retry executes; audit credits the admin.
    const e2 = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U_ADM', e2.approvalId);
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
    const consumed = (await auditRows()).find((r) => r.action === 'approval_consumed');
    assert.equal(consumed.actor, 'U_ADM');
    // The requester was told their request was approved (ephemeral in the channel).
    assert.ok(ephemerals.some((p) => p.user === 'U1' && /approved/i.test(String(p.text))));
    assert.equal(dms.length, 0);
  });
});

test('admin approver: deny notifies the requester ephemerally and audits the admin as actor', async (t) => {
  const { ctx, ephemerals, click, auditRows } = await harness(t, {
    provider: approvalProvider({ approval: { approver: 'admin' } }),
    slackAdmins: ['U_ADM'],
    members: ['U1', 'U_ADM'],
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_DENY_ACTION, 'U_ADM', e.approvalId);
    const denied = (await auditRows()).find((r) => r.action === 'denied' && r.meta.includes('approval-denied'));
    assert.equal(denied.user_id, 'U1');
    assert.equal(denied.actor, 'U_ADM');
    const note = ephemerals.find((p) => p.user === 'U1' && /denied/i.test(String(p.text)));
    assert.ok(note, 'requester was notified of the denial');
    assert.equal(calls.length, 0);
  });
});

test("self approver: another user's click is rejected and audited; nothing is granted", async (t) => {
  const { ctx, click, auditRows } = await harness(t);
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    await click(APPROVAL_APPROVE_ACTION, 'U_EVIL', e.approvalId);
    const denied = (await auditRows()).filter((r) => r.action === 'denied' && r.meta.includes('not-approver'));
    assert.equal(denied.length, 1);
    assert.equal(denied[0].user_id, 'U_EVIL');
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 0);
  });
});

test('forged approval id / cross-team id decides nothing', async (t) => {
  const { ctx, click, approvalRows } = await harness(t);
  await withFetch(async () => {
    const handle = await ctx.connect('acme');
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    const responds: any[] = [];
    await click(APPROVAL_APPROVE_ACTION, 'U1', randomUUID(), responds); // unknown id
    assert.match(responds[0]?.text ?? '', /expired or was already decided/);
    const rows = await approvalRows();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, 'pending', 'the real pending request is untouched');
  });
});

// ── zero behavior change without the knob ─────────────────────────────────────────────────────────

test('providers without the approval knob: writes pass untouched, no approval rows anywhere', async (t) => {
  const { ctx, ephemerals, auditRows, approvalRows } = await harness(t, {
    provider: approvalProvider({ approval: undefined }),
  });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme');
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST', body: BODY_SENTINEL });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
    assert.equal(ephemerals.length, 0);
    assert.equal((await approvalRows()).length, 0);
    assert.ok(!(await auditRows()).some((r) => String(r.action).startsWith('approval')));
  });
});

// ── shared channel-owned credential: the grant binds to owner_kind=channel ────────────────────────

test('shared mode: a write on a channel-owned credential prompts, binds to the channel owner, and consumes once', async (t) => {
  // connect() in shared mode borrows the CHANNEL's credential (owner_kind=channel/owner_id=C1),
  // audited as the acting human. Closes owner-binding coverage for the channel owner kind (the
  // per-user kind is covered above). Approver 'self' = the caller confirms their own action.
  const { ctx, ephemerals, click, approvalRows, auditRows } = await harness(t, { sharedChannel: true });
  await withFetch(async (calls) => {
    const handle = await ctx.connect('acme'); // shared mode → connectChannel, channel-owned cred
    const e = await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(ephemerals[0]?.user, 'U1'); // prompted the acting human

    // The pending grant is bound to the CHANNEL owner, not a user.
    const [pending] = await approvalRows();
    assert.equal(pending.owner_kind, 'channel');
    assert.equal(pending.owner_id, 'C1');
    assert.equal(pending.user_id, 'U1'); // the requester (acting human)

    await click(APPROVAL_APPROVE_ACTION, 'U1', e.approvalId);
    const res = await handle.fetch('https://api.acme.test/repos', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
    // Single-use across the channel owner too.
    await expectApprovalRequired(handle.fetch('https://api.acme.test/repos', { method: 'POST' }));
    assert.equal(calls.length, 1);
    const consumed = (await auditRows()).find((r) => r.action === 'approval_consumed');
    assert.equal(JSON.parse(consumed.meta).channel, 'C1');
  });
});

// ── headless broker: same core enforcement, structured 403 ────────────────────────────────────────

function post(port: number, path: string, body: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let json: any = null;
          try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* leave null */ }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

test('broker: unapproved write → 403 { error: "approval_required", approvalId }; approved retry executes once', async (t) => {
  const SECRET = 'broker-signing-secret';
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const audit = new Audit(db);
  const provider = approvalProvider();
  await vault.upsert(userOwner(ID), 'acme', { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  const server = createBroker({ providers: [provider], vault, audit, db, identitySecret: SECRET, allowWrites: true });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  const tok = () => signIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID() }, SECRET);
  const fetchBody = { handle: { provider: 'acme', owner: 'user' }, method: 'POST', path: '/repos', body: '{}' };
  try {
    await withFetch(async (calls) => {
      const first = await post(port, '/v1/fetch', { ...fetchBody, identityToken: tok() });
      assert.equal(first.status, 403);
      assert.equal(first.json.error, 'approval_required');
      assert.equal(typeof first.json.approvalId, 'string');
      assert.equal(calls.length, 0, 'nothing reached the wire');

      // The approval SURFACE is the Bolt app / the host: the broker only enforces. Approve the
      // pending id out-of-band (same store, same db) and the retried call passes exactly once.
      assert.ok(await new Approvals(db).approve(first.json.approvalId, 'U_ADM', 60_000));
      const retry = await post(port, '/v1/fetch', { ...fetchBody, identityToken: tok() });
      assert.equal(retry.status, 200);
      assert.equal(retry.json.status, 200);
      assert.equal(calls.length, 1);

      // Single-use across doors too: the same call right after re-prompts with a fresh id.
      const again = await post(port, '/v1/fetch', { ...fetchBody, identityToken: tok() });
      assert.equal(again.status, 403);
      assert.equal(again.json.error, 'approval_required');
      assert.notEqual(again.json.approvalId, first.json.approvalId);
    });
  } finally {
    server.close();
  }
});

// ── sweep ─────────────────────────────────────────────────────────────────────────────────────────

test('sweep: expired prompts and unspent grants are deleted and audited (actor: system)', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32));
  const audit = new Audit(db);
  const consent = new Consent(db);
  const approvals = new Approvals(db);
  const key = { teamId: 'T1', userId: 'U1', ownerKind: 'user' as const, ownerId: 'U1', provider: 'acme', method: 'POST', host: 'api.acme.test', path: '/repos', queryHash: '', channel: 'C1', thread: 'TH1' };
  await approvals.request(key); // pending, 10-minute prompt lifetime
  const granted = await approvals.request({ ...key, path: '/other' });
  await approvals.approve(granted, 'U_ADM', 1_000); // grant, 1s TTL
  // A live grant survives the sweep.
  await sweepExpired(vault, audit, consent, undefined, undefined, approvals);
  assert.equal(((await db.all(`SELECT * FROM approval_request`)) as any[]).length, 2);
  // Past both TTLs everything is reclaimed, each expiry audited with the non-human actor.
  await withClockOffset(11 * 60_000, async () => {
    await sweepExpired(vault, audit, consent, undefined, undefined, approvals);
  });
  assert.equal(((await db.all(`SELECT * FROM approval_request`)) as any[]).length, 0);
  const rows = (await db.all(`SELECT action, user_id, actor, meta FROM audit WHERE action='denied'`)) as any[];
  assert.equal(rows.length, 2);
  for (const r of rows) {
    assert.equal(r.user_id, 'U1');
    assert.equal(r.actor, 'system');
    assert.match(r.meta, /approval-expired/);
  }
});
