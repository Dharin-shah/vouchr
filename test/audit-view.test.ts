import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
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

async function harness(t: TestContext, opts: { isAdmin?: boolean } = {}) {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t),
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

test('audit: a user sees only their own credential usage, never another user\'s', async (t) => {
  const { audit, run } = await harness(t);
  await audit.record('inject', id('U_A'), 'github', { host: 'api.github.com' });
  await audit.record('inject', id('U_B'), 'gitlab', { host: 'gitlab.example' });

  const res = await run('audit', 'U_A');
  const json = JSON.stringify(res);
  assert.match(json, /github/);       // A's own row is shown
  assert.doesNotMatch(json, /gitlab/); // B's row must never leak into A's view
  assert.match(res.text, /github/);    // screen-reader/top-level fallback carries the actual row
  assert.doesNotMatch(res.text, /gitlab/);
});

test('audit: empty state when the caller has no rows', async (t) => {
  const { run } = await harness(t);
  const res = await run('audit', 'U_NEW');
  assert.match(JSON.stringify(res), /Nothing recorded yet/);
});

test('audit: meta contents are never rendered in the Slack view', async (t) => {
  const { audit, run } = await harness(t);
  await audit.record('inject', id('U_A'), 'github', { host: 'api.github.com', label: 'TOPSECRETLABEL' });
  const res = await run('audit', 'U_A');
  assert.doesNotMatch(JSON.stringify(res), /TOPSECRETLABEL/);
  assert.doesNotMatch(res.text, /TOPSECRETLABEL/);
});

test('audit: a stored value cannot forge a mrkdwn link/mention (escaped in the view)', async (t) => {
  const { audit, run } = await harness(t);
  // Mirrors the real vector: an unvalidated `/vouchr configure <arg>` denial writes attacker text
  // into the provider column. It must render inert, never as a live <…|link> or <@mention>.
  await audit.record('inject', id('U_A'), '<https://evil.com|Re-authorize Vouchr>', { host: 'x' });
  const json = JSON.stringify(await run('audit', 'U_A'));
  assert.doesNotMatch(json, /<https:\/\/evil\.com\|/); // no raw mrkdwn link survives
  assert.match(json, /&lt;https:\/\/evil\.com/);        // present but escaped (inert)
});

test('audit: surfaces the non-caller actor (e.g. an approver) via the actor column', async (t) => {
  const { audit, run } = await harness(t);
  await audit.record('approval_consumed', id('U_A'), 'github', { host: 'x' }, 'U_B'); // U_B approved U_A's action
  assert.match(JSON.stringify(await run('audit', 'U_A')), /by <@U_B>/);
});

test('configure: an unknown (e.g. credential-shaped) provider is rejected before it is ever audited', async (t) => {
  const { audit, run } = await harness(t); // non-admin caller
  const res = await run('connect-shared ghp_looks_like_a_secret_0000', 'U_A');
  assert.match(String(res), /Unknown provider/); // rejected before the admin gate / any record()
  // The bogus value must NOT have been written to the audit provider column (no reflection surface).
  const rows = await audit.listByOwnerUser(id('U_A'), 20);
  assert.equal(rows.length, 0);
});

test('audit channel: a non-admin is refused via the admin gate and the denial is audited', async (t) => {
  const { audit, run } = await harness(t); // no isAdmin override, users.info is_admin=false, not the creator
  const res = await run('audit channel', 'U_A');
  assert.match(String(res), /Only a workspace admin/); // plain admin-gate refusal, no blocks
  const denied = await audit.listByOwnerUser(id('U_A'), 20);
  assert.ok(denied.some((r) => r.action === 'denied' && r.provider === 'audit'));
});

test('audit channel: an admin sees only THIS channel\'s rows', async (t) => {
  const { audit, run } = await harness(t, { isAdmin: true });
  await audit.record('inject', id('U_A'), 'github', { channel: 'C_FIN' });   // this channel
  await audit.record('inject', id('U_A'), 'stripe', { channel: 'C_OTHER' }); // a different channel

  const res = await run('audit channel', 'U_A');
  const json = JSON.stringify(res);
  assert.match(json, /github/);        // C_FIN row shown
  assert.doesNotMatch(json, /stripe/); // C_OTHER row must not appear
});
