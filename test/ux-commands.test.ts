import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openTestDb } from './support/pg';
import { createVouchr } from '../src/adapters/bolt';
import { defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';

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

// `help` lists the retained command surface, including itself, and does not promote private preview
// state that vision.md/#194 removes from the production product.
test('help lists the retained commands', async (t) => {
  const { run } = await harness(t);
  const msg = await run('help');
  assert.match(msg, /Vouchr commands/);
  for (const c of ['/vouchr help', '/vouchr status', '/vouchr tools', '/vouchr disconnect', '/vouchr audit', '/vouchr enable', '/vouchr disable', '/vouchr mode', '/vouchr configure', '/vouchr stats']) {
    assert.ok(msg.includes(c), `help is missing ${c}`);
  }
  assert.ok(!msg.includes('/vouchr preview'), 'help must not promote the private-preview surface slated for removal');
});

// A typo / unknown subcommand gets an actionable hint, not a silent fall-through to the account list.
test('unknown subcommand guides to help instead of silently showing status', async (t) => {
  const { run } = await harness(t);
  const msg = await run('frobnicate');
  assert.match(msg, /Unknown subcommand/);
  assert.match(msg, /\/vouchr help/);
  assert.doesNotMatch(msg, /connected accounts/);
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
    await run(`configure ${sentinel}`),
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
    'disable mcp extra', 'mode mcp shared extra', 'preview mcp public extra',
    'configure mcp extra', 'audit channel extra', 'audit chanel',
  ]) {
    assert.match(await run(input), /Usage:/, input);
  }
});

// Truthful outcome: nothing connected → say so, never a false "Disconnected".
test('disconnect is truthful when there is nothing to disconnect', async (t) => {
  const { run } = await harness(t);
  const msg = await run('disconnect mcp');
  assert.match(msg, /no connected \*mcp\* account/);
  assert.doesNotMatch(msg, /^Disconnected/);
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

test('disconnect delete failure returns safe visible recovery and leaves the connection', async (t) => {
  const { run, vouchr } = await harness(t);
  await vouchr.vault.upsert(userOwner(ID), 'mcp', cred);
  const sentinel = 'ghp_DELETE_FAILURE_MUST_NOT_REACH_SLACK';
  (vouchr.vault as any).delete = async () => { throw new Error(sentinel); };
  const msg = await run('disconnect mcp');
  assert.match(msg, /Could not confirm/);
  assert.match(msg, /\/vouchr status/);
  assert.ok(!msg.includes(sentinel));
  assert.notEqual(await vouchr.vault.get(userOwner(ID), 'mcp'), null);
});

test('disconnect post-delete audit failure returns safe state-agnostic recovery', async (t) => {
  const { run, vouchr } = await harness(t);
  await vouchr.vault.upsert(userOwner(ID), 'mcp', cred);
  const sentinel = 'ghp_AUDIT_FAILURE_MUST_NOT_REACH_SLACK';
  (vouchr.audit as any).record = async () => { throw new Error(sentinel); };
  const msg = await run('disconnect mcp');
  assert.match(msg, /Could not confirm/);
  assert.match(msg, /\/vouchr status/);
  assert.ok(!msg.includes(sentinel));
  assert.equal(await vouchr.vault.get(userOwner(ID), 'mcp'), null);
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
  await vouchr.vault.upsert(userOwner(ID), 'rev', { ...cred, accessToken: 'sk-live' });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error('network down'); }) as any; // upstream revoke fails
  try {
    const msg = await run('disconnect rev');
    assert.match(msg, /Disconnected \*rev\*/);
    assert.match(msg, /could not be confirmed/);
    assert.match(msg, /Revoke or rotate .* directly/);
    assert.equal(await vouchr.vault.get(userOwner(ID), 'rev'), null); // local delete still happened
  } finally {
    globalThis.fetch = realFetch;
  }
});
