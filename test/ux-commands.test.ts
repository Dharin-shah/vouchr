import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openTestDb, testDbUrl } from './support/pg';
import { createVouchr } from '../src/adapters/bolt';
import { openDb, type Db } from '../src/core/db';
import { defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { offboardUser } from '../src/core/offboard';

// createVouchr builds the vault keyring from the env at construction (like the other command tests).
process.env.VOUCHR_MASTER_KEY ??= randomBytes(32).toString('base64');

// #194 (Slack commands & rendering slice): the /vouchr command surface must validate before it
// mutates/audits/emits, report outcomes truthfully, never reflect unvalidated input (SEC-1), escape
// validated rendered values (SEC-5), and guide typos to a real `help`. Drives the real command handler.

const ID = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const cred = { accessToken: 'sk-x', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null };

const mcp = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

async function harness(t: TestContext, providers = [mcp]) {
  const db = await openTestDb(t);
  const events: unknown[] = [];
  const vouchr = await createVouchr({ providers, baseUrl: 'https://app.test', db, onEvent: (e) => events.push(e) });
  let handler: any;
  vouchr.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
  const run = async (text: string): Promise<string> => {
    const out: string[] = [];
    await handler({
      command: { team_id: 'T1', user_id: 'U1', channel_id: 'C_FIN', text },
      ack: async () => {}, respond: async (m: any) => out.push(typeof m === 'string' ? m : JSON.stringify(m)), client: {},
    });
    return out[0] ?? '';
  };
  return { vouchr, db, events, run };
}

// These failure-path checks need no live store: createVouchr receives the same Db interface used in
// production, and each case replaces exactly the production dependency it wants to fail. Keeping the
// fixture offline also lets the ack/response contract run without a PostgreSQL availability precondition.
async function failureHarness(providers = [mcp]) {
  const db = {
    get: async () => undefined,
    all: async () => [],
    run: async () => ({ changes: 0 }),
    exec: async () => undefined,
    close: async () => undefined,
  } as Db;
  const vouchr = await createVouchr({
    providers, baseUrl: 'https://app.test', db, isAdmin: async () => true,
  });
  let handler: any;
  vouchr.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
  return { vouchr, handler };
}

test('read dependency failures ack first, respond once, and never disclose the raw error', async (t) => {
  const sentinel = 'ghp_READ_FAILURE_MUST_NOT_REACH_SLACK';
  const cases: {
    name: string;
    text: string;
    expected: string;
    fail: (vouchr: any, dependencyCalled: () => void) => void;
  }[] = [
    {
      name: 'status',
      text: 'status',
      expected: 'Could not load your connected accounts. Try `/vouchr status` again in a moment.',
      fail: (vouchr, called) => { vouchr.vault.listForUser = async () => { called(); throw new Error(sentinel); }; },
    },
    {
      name: 'tools',
      text: 'tools',
      expected: 'Could not load this channel\'s tools. Try `/vouchr tools` again in a moment.',
      fail: (vouchr, called) => { vouchr.db.all = async () => { called(); throw new Error(sentinel); }; },
    },
    {
      name: 'stats',
      text: 'stats',
      expected: 'Could not load this channel\'s usage stats. Try `/vouchr stats` again in a moment.',
      fail: (vouchr, called) => { vouchr.audit.statsByChannel = async () => { called(); throw new Error(sentinel); }; },
    },
    {
      name: 'audit self',
      text: 'audit',
      expected: 'Could not load your credential usage. Try `/vouchr audit` again in a moment.',
      fail: (vouchr, called) => { vouchr.audit.listByOwnerUser = async () => { called(); throw new Error(sentinel); }; },
    },
    {
      name: 'audit channel',
      text: 'audit channel',
      expected: 'Could not load this channel\'s credential usage. Try `/vouchr audit channel` again in a moment.',
      fail: (vouchr, called) => { vouchr.audit.listByChannel = async () => { called(); throw new Error(sentinel); }; },
    },
  ];

  for (const c of cases) {
    await t.test(c.name, async () => {
      const { vouchr, handler } = await failureHarness();
      const order: string[] = [];
      const responses: unknown[] = [];
      c.fail(vouchr, () => order.push('dependency'));

      await handler({
        command: { team_id: 'T1', user_id: 'U1', channel_id: 'C_FIN', text: c.text },
        ack: async () => { order.push('ack'); },
        respond: async (response: unknown) => { order.push('respond'); responses.push(response); },
        client: {},
      });

      assert.equal(order[0], 'ack');
      assert.ok(order.indexOf('dependency') > order.indexOf('ack'), 'dependency ran before acknowledgement');
      assert.equal(responses.length, 1);
      assert.equal(responses[0], c.expected);
      assert.ok(!String(responses[0]).includes(sentinel), 'raw dependency error reached Slack output');
    });
  }
});

test('a rejected Slack response is not caught and retried', async () => {
  const { vouchr, handler } = await failureHarness();
  (vouchr.vault as any).listForUser = async () => { throw new Error('db unavailable'); };
  let responseAttempts = 0;

  await assert.rejects(handler({
    command: { team_id: 'T1', user_id: 'U1', channel_id: 'C_FIN', text: 'status' },
    ack: async () => {},
    respond: async () => {
      responseAttempts++;
      throw new Error('Slack response transport rejected');
    },
    client: {},
  }), /Slack response transport rejected/);
  assert.equal(responseAttempts, 1);
});

test('status preserves its established plain-text contract for an ordinary connection list', async (t) => {
  const { vouchr, run } = await harness(t);
  await vouchr.vault.upsert(userOwner(ID), 'mcp', cred);
  assert.equal(
    await run('status'),
    'Your connected accounts:\n• *mcp* in your DMs\n\nDisconnect with `/vouchr disconnect <provider>`.',
  );
});

test('bare status remains one plain-text response above the page size when the complete text fits', async () => {
  const providers = Array.from({ length: 41 }, (_, i) => defineProvider({
    id: `p-${String(i).padStart(3, '0')}`,
    authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  }));
  const { vouchr, handler } = await failureHarness(providers);
  (vouchr.vault as any).listForUser = async () => providers.map(({ id: provider }) => ({ provider, externalAccount: null }));
  const responses: unknown[] = [];
  await handler({
    command: { team_id: 'T1', user_id: 'U1', channel_id: 'C_FIN', text: 'status' },
    ack: async () => {},
    respond: async (response: unknown) => { responses.push(response); },
    client: {},
  });
  const lines = providers.map(({ id }) => `• *${id}* in your DMs`).join('\n');
  assert.deepEqual(responses, [
    `Your connected accounts:\n${lines}\n\nDisconnect with \`/vouchr disconnect <provider>\`.`,
  ]);
});

test('status paginates current and retired rows into stable, bounded, fully reachable pages', async () => {
  const providers = Array.from({ length: 128 }, (_, i) => defineProvider({
    id: `p-${String(i).padStart(3, '0')}`,
    authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
  }));
  const { vouchr, handler } = await failureHarness(providers);
  const retired = Array.from({ length: 65 }, (_, i) => `retired-${String(i).padStart(3, '0')}`);
  const rows = [
    ...providers.map((provider) => ({ provider: provider.id, externalAccount: '&'.repeat(512) })),
    ...retired.map((provider) => ({ provider, externalAccount: '&'.repeat(512) })),
  ];
  (vouchr.vault as any).listForUser = async () => rows;
  const expected = rows.map((row) => row.provider).sort();
  const seen = new Set<string>();
  const pageSize = 14;
  const totalPages = Math.ceil(expected.length / pageSize);

  for (let page = 1; page <= totalPages; page++) {
    const responses: any[] = [];
    await handler({
      command: { team_id: 'T1', user_id: 'U1', channel_id: 'C_FIN', text: page === 1 ? 'status' : `status ${page}` },
      ack: async () => {},
      respond: async (response: any) => { responses.push(response); },
      client: {},
    });

    assert.equal(responses.length, 1);
    const response = responses[0];
    assert.equal(typeof response.text, 'string');
    assert.ok(response.text.length <= 40_000);
    assert.match(response.text, new RegExp(`Page ${page} of ${totalPages}`));
    assert.ok(Array.isArray(response.blocks));
    assert.ok(response.blocks.length <= 50);
    for (const block of response.blocks) {
      if (block?.type === 'section') assert.ok(block.text.text.length <= 3_000);
    }
    const rendered = JSON.stringify(response.blocks);
    for (const provider of expected.slice((page - 1) * pageSize, page * pageSize)) {
      assert.ok(rendered.includes(`*${provider}*`), `${provider} was omitted from page ${page}`);
      seen.add(provider);
    }
  }
  assert.equal(seen.size, expected.length);
});

test('status rejects invalid page syntax before reading connection state', async () => {
  const { vouchr, handler } = await failureHarness();
  let reads = 0;
  (vouchr.vault as any).listForUser = async () => { reads++; return []; };

  for (const text of ['status 0', 'status -1', 'status nope', 'status 1 extra']) {
    const responses: unknown[] = [];
    await handler({
      command: { team_id: 'T1', user_id: 'U1', channel_id: 'C_FIN', text },
      ack: async () => {},
      respond: async (response: unknown) => { responses.push(response); },
      client: {},
    });
    assert.deepEqual(responses, ['Usage: `/vouchr status [page]`']);
  }
  assert.equal(reads, 0);
});

// `help` lists the retained command surface, including itself, and excludes the removed private
// preview command.
test('help lists the retained commands', async (t) => {
  const { run } = await harness(t);
  const msg = await run('help');
  assert.match(msg, /Vouchr commands/);
  for (const c of ['/vouchr help', '/vouchr status', '/vouchr tools', '/vouchr disconnect', '/vouchr audit', '/vouchr enable', '/vouchr disable', '/vouchr mode', '/vouchr connect-shared', '/vouchr disconnect-shared', '/vouchr stats']) {
    assert.ok(msg.includes(c), `help is missing ${c}`);
  }
  assert.ok(!msg.includes('/vouchr preview'), 'help must not promote the removed private-preview surface');
});

// A typo / unknown subcommand gets an actionable hint, not a silent fall-through to the account list.
test('unknown subcommand guides to help instead of silently showing status', async (t) => {
  const { run } = await harness(t);
  const msg = await run('frobnicate');
  assert.match(msg, /Unknown subcommand/);
  assert.match(msg, /\/vouchr help/);
  assert.doesNotMatch(msg, /connected accounts/);
});

test('removed preview command is an unknown subcommand with no mutation or audit', async (t) => {
  const { run, db } = await harness(t);
  const msg = await run('preview mcp private');
  assert.equal(msg, 'Unknown subcommand. Run `/vouchr help` to see what you can do.');
  assert.equal((await db.all(`SELECT id FROM audit`)).length, 0);
});

// SEC-1: an unknown argument can be a credential pasted in the wrong position. Escaping would stop
// mrkdwn injection but still disclose the value, so every unknown-command/provider response is static.
test('SEC-1: unknown command and provider values are never echoed', async (t) => {
  const { run } = await harness(t);
  const sentinel = 'ghp_SECRET_SENTINEL_MUST_NOT_REACH_SLACK';
  const responses = [
    await run(sentinel),
    await run(`enable ${sentinel}`),
    await run(`disable ${sentinel}`),
    await run(`mode ${sentinel} shared`),
    await run(`preview ${sentinel} public`),
    await run(`connect-shared ${sentinel}`),
    await run(`disconnect ${sentinel}`),
  ];
  for (const msg of responses) {
    assert.ok(!msg.includes(sentinel), 'unvalidated argument reached Slack output');
    assert.match(msg, /Unknown (?:subcommand|provider)/);
  }
});

// SEC-4: an unknown provider is rejected BEFORE disconnectProvider runs, so nothing is deleted, audited,
// or emitted for it. The audit revoke row is the load-bearing check (an unvalidated string must not land there).
test('SEC-4: disconnect of an unknown provider writes no audit revoke row', async (t) => {
  const { run, db, events } = await harness(t);
  const msg = await run('disconnect not-a-provider');
  assert.match(msg, /Unknown provider/);
  const revokes = (await db.all(`SELECT id FROM audit WHERE action='revoke'`)) as any[];
  assert.equal(revokes.length, 0);
  assert.deepEqual(events, []);
});

test('malformed trailing arguments are rejected before disconnect mutates, audits, or emits', async (t) => {
  const { run, db, events, vouchr } = await harness(t);
  await vouchr.vault.upsert(userOwner(ID), 'mcp', cred);
  const msg = await run('disconnect mcp extra');
  assert.match(msg, /Usage: `\/vouchr disconnect/);
  assert.notEqual(await vouchr.vault.get(userOwner(ID), 'mcp'), null);
  assert.equal((await db.all(`SELECT id FROM audit WHERE action='revoke'`)).length, 0);
  assert.deepEqual(events, []);
});

test('every known command rejects unsupported arguments instead of silently widening its action', async (t) => {
  const { run } = await harness(t);
  for (const input of [
    'help extra', 'status extra', 'tools extra', 'stats extra', 'enable mcp extra',
    'disable mcp extra', 'mode mcp shared extra',
    'connect-shared mcp extra', 'audit channel extra', 'audit chanel',
  ]) {
    assert.match(await run(input), /Usage:/, input);
  }
});

// Truthful outcome: nothing connected → say so, never a false "Disconnected".
test('disconnect is truthful when there is nothing to disconnect', async (t) => {
  const { run, db, events } = await harness(t);
  const msg = await run('disconnect mcp');
  assert.match(msg, /no connected \*mcp\* account/);
  assert.doesNotMatch(msg, /^Disconnected/);
  assert.equal(((await db.get(`SELECT COUNT(*) AS n FROM audit WHERE action='revoke'`)) as any).n, 0);
  assert.deepEqual(events, []);
});

// Truthful outcome: a real connection with no upstream revoke due → removed + confirmed.
test('disconnect removes a real connection and confirms it', async (t) => {
  const { run, vouchr } = await harness(t);
  await vouchr.vault.upsert(userOwner(ID), 'mcp', cred);
  const msg = await run('disconnect mcp');
  assert.match(msg, /Disconnected \*mcp\*/);
  assert.doesNotMatch(msg, /could not be confirmed/);
  assert.equal(await vouchr.vault.get(userOwner(ID), 'mcp'), null);
});

test('#194 a delayed slash-command disconnect preserves a fresh post-offboard connection', async (t) => {
  const databaseUrl = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl }),
    openDb({ databaseUrl }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const provider = defineProvider({
    ...mcp,
    revokeUrl: 'https://api.test/revoke',
  });
  const events: unknown[] = [];
  const vouchr = await createVouchr({
    providers: [provider], baseUrl: 'https://app.test', db: dbA,
    onEvent: (event) => events.push(event),
  });
  let handler: any;
  vouchr.registerCommands({
    command: (_name: string, registered: any) => { handler = registered; },
    view: () => undefined,
    action: () => undefined,
  });
  const owner = userOwner(ID);
  await vouchr.vault.upsert(owner, 'mcp', {
    ...cred,
    accessToken: 'OLD_SLACK_TOKEN',
  });

  const originalIssuedAt = vouchr.vault.userProvisioningIssuedAt.bind(vouchr.vault);
  let entered!: () => void;
  let resume!: () => void;
  const atIssuance = new Promise<void>((resolve) => { entered = resolve; });
  const resumed = new Promise<void>((resolve) => { resume = resolve; });
  let pause = true;
  vouchr.vault.userProvisioningIssuedAt = async () => {
    if (pause) {
      pause = false;
      entered();
      await resumed;
    }
    return originalIssuedAt();
  };
  const responses: string[] = [];
  const handling = handler({
    command: { team_id: 'T1', user_id: 'U1', channel_id: 'C_FIN', text: 'disconnect mcp' },
    ack: async () => undefined,
    respond: async (response: unknown) => { responses.push(String(response)); },
    client: {},
  });
  await atIssuance;

  const vaultB = new Vault(dbB, Buffer.from(process.env.VOUCHR_MASTER_KEY!, 'base64'));
  await offboardUser(vaultB, new Audit(dbB), new Consent(dbB), ID);
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(await vaultB.upsert(owner, 'mcp', {
    ...cred,
    accessToken: 'FRESH_SLACK_TOKEN',
  }), true);
  const freshId = await vaultB.liveId(owner, 'mcp');
  assert.ok(freshId);
  const revokesBefore = (await dbB.get<{ n: number }>(
    `SELECT COUNT(*)::int AS n FROM audit WHERE action='revoke' AND provider='mcp'`,
  ))!.n;
  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = (async () => {
    upstreamCalls++;
    return new Response('', { status: 200 });
  }) as any;
  try {
    resume();
    await handling;
    assert.equal(responses.length, 1);
    assert.match(responses[0], /Access changed.*resolve current access and retry/i);
    assert.equal(await vaultB.liveId(owner, 'mcp'), freshId);
    assert.equal((await vaultB.get(owner, 'mcp'))?.accessToken, 'FRESH_SLACK_TOKEN');
    assert.equal(upstreamCalls, 0);
    assert.equal((await dbB.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM audit WHERE action='revoke' AND provider='mcp'`,
    ))!.n, revokesBefore);
    assert.deepEqual(events, []);
  } finally {
    globalThis.fetch = realFetch;
    resume();
  }
});

test('disconnect delete failure returns safe visible recovery and leaves the connection', async (t) => {
  const { run, vouchr } = await harness(t);
  await vouchr.vault.upsert(userOwner(ID), 'mcp', cred);
  const sentinel = 'ghp_DELETE_FAILURE_MUST_NOT_REACH_SLACK';
  (vouchr.vault as any).deleteForRevoke = async () => { throw new Error(sentinel); };
  const msg = await run('disconnect mcp');
  assert.match(msg, /Could not confirm/);
  assert.match(msg, /\/vouchr status/);
  assert.ok(!msg.includes(sentinel));
  assert.notEqual(await vouchr.vault.get(userOwner(ID), 'mcp'), null);
});

test('disconnect post-delete audit failure preserves the committed outcome safely', async (t) => {
  const { run, vouchr, events } = await harness(t);
  await vouchr.vault.upsert(userOwner(ID), 'mcp', cred);
  const sentinel = 'ghp_AUDIT_FAILURE_MUST_NOT_REACH_SLACK';
  (vouchr.audit as any).record = async () => { throw new Error(sentinel); };
  const msg = await run('disconnect mcp');
  assert.match(msg, /Disconnected \*mcp\* locally/);
  assert.match(msg, /could not confirm the audit record/i);
  assert.match(msg, /admin.*logs/i);
  assert.ok(!msg.includes(sentinel));
  assert.equal(await vouchr.vault.get(userOwner(ID), 'mcp'), null);
  assert.deepEqual(events, [{ type: 'revoked', provider: 'mcp', ok: true }]);
});

test('disconnect removes a status-visible retired provider and reports upstream uncertainty', async (t) => {
  const { run, vouchr, db, events } = await harness(t, []);
  await vouchr.vault.upsert(userOwner(ID), 'retired', cred);

  const status = await run('status');
  assert.match(status, /retired/);
  const msg = await run('disconnect retired');
  assert.match(msg, /Disconnected \*retired\* locally/);
  assert.match(msg, /complete revocation could not be confirmed/i);
  assert.match(msg, /revoke or rotate .* directly/i);
  assert.equal(await vouchr.vault.has(userOwner(ID), 'retired'), false);
  assert.equal(((await db.get(`SELECT COUNT(*) AS n FROM audit WHERE action='revoke' AND provider='retired'`)) as any).n, 1);
  assert.deepEqual(events, [{ type: 'revoked', provider: 'retired', ok: false }]);
});

// Truthful outcome: a revocable provider whose upstream revoke FAILS → local removed, but says the
// upstream revoke is unconfirmed rather than claiming a clean success (#194 partial-failure honesty).
test('disconnect reports an unconfirmed upstream revoke truthfully', async (t) => {
  const revocable = defineProvider({
    id: 'rev', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['acme.example'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
    revokeUrl: 'https://acme.example/oauth/revoke',
  });
  const { run, vouchr } = await harness(t, [revocable]);
  await vouchr.vault.upsert(userOwner(ID), 'rev', { ...cred, accessToken: 'TEST_TOKEN' });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error('network down'); }) as any; // upstream revoke fails
  try {
    const msg = await run('disconnect rev');
    assert.match(msg, /Disconnected \*rev\*/);
    assert.match(msg, /could not be confirmed/);
    assert.match(msg, /revoke or rotate .* directly/i);
    assert.equal(await vouchr.vault.get(userOwner(ID), 'rev'), null); // local delete still happened
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('disconnect preserves upstream-revoke guidance when the audit write also fails', async (t) => {
  const revocable = defineProvider({
    id: 'rev', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
    egressAllow: ['acme.example'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
    revokeUrl: 'https://acme.example/oauth/revoke',
  });
  const { run, vouchr, events } = await harness(t, [revocable]);
  await vouchr.vault.upsert(userOwner(ID), 'rev', { ...cred, accessToken: 'sk-live' });
  (vouchr.audit as any).record = async () => { throw new Error('ghp_AUDIT_FAILURE_MUST_NOT_REACH_SLACK'); };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error('ghp_REVOKE_FAILURE_MUST_NOT_REACH_SLACK'); }) as any;
  try {
    const msg = await run('disconnect rev');
    assert.match(msg, /Disconnected \*rev\* locally/);
    assert.match(msg, /complete revocation could not be confirmed/i);
    assert.match(msg, /revoke or rotate .* directly/i);
    assert.doesNotMatch(msg, /ghp_/);
    assert.equal(await vouchr.vault.has(userOwner(ID), 'rev'), false);
    assert.deepEqual(events, [{ type: 'revoked', provider: 'rev', ok: false }]);
  } finally {
    globalThis.fetch = realFetch;
  }
});
