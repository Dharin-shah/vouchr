import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Audit } from '../src/core/audit';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { Vault } from '../src/core/vault';
import { userOwner } from '../src/core/owner';
import { ConnectionHandle } from '../src/core/injector';
import { createVouchr } from '../src/adapters/bolt';
import { defineProvider } from '../src/core/providers';

const KEY = randomBytes(32);
const uid = (userId: string) => ({ enterpriseId: null, teamId: 'T1', userId });
const tok = { accessToken: 'sk-secret', refreshToken: null, scopes: '', expiresAt: null, externalAccount: null };

// #107 /vouchr stats — admin per-channel usage analytics. Core query scoping + the command's admin
// gate and enabled-but-idle flag.

const mk = (id: string) => defineProvider({
  id, authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.x'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

const DAY = 24 * 60 * 60 * 1000;

test('statsByChannel: counts injections + distinct actors in-window, scoped to channel + action', async (t) => {
  const db = await openTestDb(t);
  const audit = new Audit(db);
  const now = Date.now();
  const rec = (provider: string, userId: string, channel: string, action: string, at: number) =>
    db.run(`INSERT INTO audit (id, team_id, user_id, provider, action, actor, channel, meta, at) VALUES (?,?,?,?,?,?,?,?,?)`,
      [randomUUID(), 'T1', userId, provider, action, null, channel, '{}', at]);

  await rec('github', 'U1', 'C_FIN', 'inject', now - 1_000); // github: 3 injects, 2 distinct humans
  await rec('github', 'U1', 'C_FIN', 'inject', now - 2_000);
  await rec('github', 'U2', 'C_FIN', 'inject', now - 3_000);
  await rec('gitlab', 'U1', 'C_FIN', 'inject', now - 500);   // gitlab: 1 inject
  await rec('github', 'U9', 'C_FIN', 'inject', now - 40 * DAY); // BEFORE window → excluded
  await rec('github', 'U1', 'C_OTHER', 'inject', now - 100);    // different channel → excluded
  await rec('github', 'U3', 'C_FIN', 'denied', now - 100);      // non-inject action → excluded

  const rows = await audit.statsByChannel('T1', 'C_FIN', now - 30 * DAY);
  const byP = Object.fromEntries(rows.map((r) => [r.provider, r]));
  assert.equal(byP.github.uses, 3);
  assert.equal(byP.github.distinctActors, 2);
  assert.equal(byP.github.lastUsed, now - 1_000); // most recent in-window injection
  assert.equal(byP.gitlab.uses, 1);
  assert.equal(byP.gitlab.distinctActors, 1);
  assert.ok(rows.every((r) => typeof r.uses === 'number' && typeof r.distinctActors === 'number')); // coerced
});

test('statsByChannel attributes REAL per-user usage to the origin channel (the P1 bug)', async (t) => {
  // The prior test seeded audit rows with { channel } set — masking the bug that per-user/session
  // inject audits left channel NULL. This drives a genuine per-user handle.fetch() and asserts the
  // usage is attributed to the channel it happened in (else `/vouchr stats` marks live tools "idle").
  const db = await openTestDb(t);
  const audit = new Audit(db);
  const vault = new Vault(db, KEY);
  await vault.upsert(userOwner(uid('U1')), 'github', tok);
  // Mirrors bolt's per-user construction: a user-owned handle carrying the origin channel (10th arg).
  const handle = new ConnectionHandle(
    mk('github'), userOwner(uid('U1')), uid('U1'), vault, audit, {}, new Map(), () => {}, () => {}, 'C_FIN',
  );
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
  try { await handle.fetch('https://api.x/y'); } finally { globalThis.fetch = realFetch; }

  const rows = await audit.statsByChannel('T1', 'C_FIN', Date.now() - DAY);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].provider, 'github');
  assert.equal(rows[0].uses, 1);           // per-user usage now visible (was structurally 0 / "never used")
  assert.equal(rows[0].distinctActors, 1);
});

async function harness(t: TestContext, opts: { isAdmin?: boolean } = {}) {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [mk('github'), mk('gitlab'), mk('idle')], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t),
    ...(opts.isAdmin !== undefined ? { isAdmin: async () => opts.isAdmin! } : {}),
  });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });
  const audit = new Audit(lan.db);
  const client = { users: { info: async () => ({ user: { is_admin: false } }) },
    conversations: { info: async () => ({ channel: { id: 'C_FIN', is_channel: true, creator: 'U_X' } }) } };
  const run = async (text: string) => {
    const out: any[] = [];
    await handler({ command: { team_id: 'T1', user_id: 'U_A', channel_id: 'C_FIN', trigger_id: 't', text },
      ack: async () => {}, respond: async (m: any) => out.push(m), client });
    return out[0];
  };
  return { lan, audit, run };
}

test('/vouchr stats (admin): shows used providers with counts and flags an enabled-but-idle tool', async (t) => {
  const { lan, audit, run } = await harness(t, { isAdmin: true });
  const tools = new ChannelTools(lan.db);
  for (const p of ['github', 'gitlab', 'idle']) await setChannelToolEnabled(tools, 'T1', 'C_FIN', p, true);
  // github used by 2 people, gitlab by 1; 'idle' is enabled but never used.
  await audit.record('inject', { enterpriseId: null, teamId: 'T1', userId: 'U1' }, 'github', { channel: 'C_FIN' });
  await audit.record('inject', { enterpriseId: null, teamId: 'T1', userId: 'U2' }, 'github', { channel: 'C_FIN' });
  await audit.record('inject', { enterpriseId: null, teamId: 'T1', userId: 'U1' }, 'gitlab', { channel: 'C_FIN' });

  const response = await run('stats');
  const json = JSON.stringify(response);
  assert.match(json, /github.*2 injections · 2 people/);
  assert.match(json, /gitlab.*1 injection ·/);
  assert.match(json, /idle.*never used/);              // idle tool surfaced for pruning
  assert.match(json, /disable <provider>/);            // prune hint present
  assert.match(response.text, /github.*2 injections · 2 people/);
  assert.match(response.text, /idle.*never used/);
  assert.match(response.text, /disable <provider>/);
});

test('/vouchr stats: a non-admin is refused via the admin gate and the denial is audited', async (t) => {
  const { audit, run } = await harness(t); // no isAdmin override; users.info is_admin=false, not creator
  assert.match(String(await run('stats')), /Only a workspace admin/);
  const rows = await audit.listByChannel('T1', 'C_FIN', 20);
  assert.ok(rows.some((r) => r.action === 'denied' && r.provider === 'stats'));
});
