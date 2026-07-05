import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createVouchr } from '../src/adapters/bolt';
import { Audit } from '../src/core/audit';
import { defineProvider } from '../src/core/providers';
import type { SlackIdentity } from '../src/core/identity';

// /vouchr audit — the self-service usage view (#104). Two security requirements under test:
// a non-admin only ever sees rows attributed to their own user id, and meta is never rendered.

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
const id = (userId: string): SlackIdentity => ({ enterpriseId: null, teamId: 'T1', userId });

async function harness(opts: { isAdmin?: boolean } = {}) {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', dbPath: ':memory:',
    ...(opts.isAdmin !== undefined ? { isAdmin: async () => opts.isAdmin! } : {}),
  });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
  const audit = new Audit(lan.db);
  const client = {
    users: { info: async () => ({ user: { is_admin: false } }) },
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator: 'U_SOMEONE' } }) },
  };
  const run = async (text: string, userId = 'U_A') => {
    const out: any[] = [];
    await handler({
      command: { team_id: 'T1', user_id: userId, channel_id: 'C_FIN', trigger_id: 't', text },
      ack: async () => {}, respond: async (m: any) => out.push(m), client,
    });
    return out[0];
  };
  return { lan, audit, run };
}

test('audit: a user sees only their own credential usage, never another user\'s', async () => {
  const { audit, run } = await harness();
  await audit.record('inject', id('U_A'), 'github', { host: 'api.github.com' });
  await audit.record('inject', id('U_B'), 'gitlab', { host: 'gitlab.example' });

  const res = await run('audit', 'U_A');
  const json = JSON.stringify(res);
  assert.match(json, /github/);       // A's own row is shown
  assert.doesNotMatch(json, /gitlab/); // B's row must never leak into A's view
});

test('audit: empty state when the caller has no rows', async () => {
  const { run } = await harness();
  const res = await run('audit', 'U_NEW');
  assert.match(JSON.stringify(res), /Nothing recorded yet/);
});

test('audit: meta contents are never rendered in the Slack view', async () => {
  const { audit, run } = await harness();
  await audit.record('inject', id('U_A'), 'github', { host: 'api.github.com', label: 'TOPSECRETLABEL' });
  const res = await run('audit', 'U_A');
  assert.doesNotMatch(JSON.stringify(res), /TOPSECRETLABEL/);
});

test('audit channel: a non-admin is refused via the admin gate and the denial is audited', async () => {
  const { audit, run } = await harness(); // no isAdmin override, users.info is_admin=false, not the creator
  const res = await run('audit channel', 'U_A');
  assert.match(String(res), /Only a workspace admin/); // plain admin-gate refusal, no blocks
  const denied = await audit.listByOwnerUser(id('U_A'), 20);
  assert.ok(denied.some((r) => r.action === 'denied' && r.provider === 'audit'));
});

test('audit channel: an admin sees only THIS channel\'s rows', async () => {
  const { audit, run } = await harness({ isAdmin: true });
  await audit.record('inject', id('U_A'), 'github', { channel: 'C_FIN' });   // this channel
  await audit.record('inject', id('U_A'), 'stripe', { channel: 'C_OTHER' }); // a different channel

  const res = await run('audit channel', 'U_A');
  const json = JSON.stringify(res);
  assert.match(json, /github/);        // C_FIN row shown
  assert.doesNotMatch(json, /stripe/); // C_OTHER row must not appear
});
