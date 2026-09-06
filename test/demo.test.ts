import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { openDb, type Db } from '../src/core/db';
import { openTestDb, testDbUrl } from './support/pg';
import { defineProvider, github, type Provider } from '../src/core/providers';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { ApprovalRequiredError } from '../src/core/approval';
import { ConsentRequiredError, createVouchr, safeUserMessage } from '../src/adapters/bolt';
import { APPROVAL_APPROVE_ACTION, APPROVAL_DENY_ACTION, CONFIGURE_CALLBACK } from '../src/adapters/blocks';
import { POSTGRES_NOW_US_SQL } from '../src/core/interaction';
import { channelOwner, userOwner } from '../src/core/owner';

// guides/DEMO.md, scenarios (a) to (m) except (j) (the autonomous worker, test/worker-authorization.test.ts)
// plus the #350 edge rows, on the production path with the
// exact Slack copy: a real createVouchr, its middleware, its registered slash command, view, and
// action handlers, a faked Slack client, a stubbed provider egress, and a throwaway PostgreSQL
// schema. The demo app's two providers are registered exactly as examples/demo/app.ts does:
// `github()` with NO approval configuration (the default follows the identity (#359): acting as the
// person, the requester confirms each write; acting as the channel, another member approves) and a
// key provider for the channel's shared token with a thread grant.

const TEAM = 'T1';
const CHANNEL = 'C_DEMO';
const ALEX = 'U_ALEX';
const SAM = 'U_SAM';
const JO = 'U_JO';
const TOKEN = 'gho_alex_secret_never_rendered';
const TEAM_TOKEN = 'ghp_team_secret_never_rendered';
const id = (userId: string) => ({ enterpriseId: null, teamId: TEAM, userId });

const githubTeam = (): Provider => defineProvider({
  id: 'github-team',
  credential: 'key',
  authorizeUrl: '',
  tokenUrl: '',
  scopesDefault: [],
  egressAllow: ['api.github.com'],
  refresh: 'none',
  pkce: false,
  approval: { grant: 'thread', ttlMs: 30 * 60 * 1000 },
});

/** Stub provider egress; every call is recorded, none leaves the process. */
async function withFetch<T>(fn: (calls: { url: string; init?: RequestInit }[]) => Promise<T>): Promise<T> {
  const real = globalThis.fetch;
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = (async (url: any, init?: any) => {
    calls.push({ url: String(url), init });
    return new Response('{"login":"alex","public_repos":3,"html_url":"https://github.com/alex/vouchr-demo/issues/1","user":{"login":"alex"}}', {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  }) as any;
  try { return await fn(calls); } finally { globalThis.fetch = real; }
}

const texts = (blocks: any[]): unknown[] => blocks.map((b) => b.type === 'actions'
  ? { type: 'actions', buttons: b.elements.map((e: any) => e.text.text) }
  : { type: b.text.type, text: b.text.text });

async function demo(t: TestContext, o: { db?: Db; members?: string[]; channelInfo?: Record<string, unknown> } = {}) {
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');
  const db = o.db ?? await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [github({ clientId: 'c', clientSecret: 's' }), githubTeam()],
    baseUrl: 'https://vouchr.test',
    db,
  });
  let command: any;
  const views: Record<string, any> = {};
  const actions: Record<string, any> = {};
  vouchr.registerCommands({
    command: (_n: string, h: any) => { command = h; },
    view: (name: string, h: any) => { views[name] = h; },
    action: (name: string, h: any) => { actions[name] = h; },
  });
  const members = o.members ?? [ALEX, SAM];
  const ephemerals: any[] = [];
  const messages: any[] = [];
  const modals: any[] = [];
  const client = {
    conversations: {
      info: async ({ channel }: any) => ({ channel: { id: channel, is_channel: !channel.startsWith('D'), is_im: channel.startsWith('D'), creator: SAM, ...o.channelInfo } }),
      members: async () => ({ members }),
    },
    chat: {
      postEphemeral: async (p: any) => { ephemerals.push(p); return {}; },
      postMessage: async (p: any) => { messages.push(p); return {}; },
      update: async () => ({}),
    },
    views: {
      open: async () => ({ view: { id: 'V_LOADING' } }),
      update: async (p: any) => { modals.push(p); return {}; },
    },
  } as any;
  /** `context.vouchr` for a mention in `channel`, in `thread`, by `user`, as the real middleware builds it. */
  const context = async (user: string, channel = CHANNEL, thread = 'TH1', channelType?: string) => {
    const args: any = {
      context: {}, client, next: async () => {},
      event: { user, team: TEAM, channel, thread_ts: thread, ...(channelType ? { channel_type: channelType } : {}) },
    };
    await vouchr.middleware(args);
    return args.context.vouchr;
  };
  const slash = async (user: string, text: string, channel = CHANNEL): Promise<any> => {
    let out: any;
    await command({
      command: { team_id: TEAM, user_id: user, channel_id: channel, trigger_id: 'trig', text },
      ack: async () => {}, respond: async (m: any) => { out = m; }, client,
    });
    return out;
  };
  const click = async (action: string, user: string, value: string, location = { channel: CHANNEL, thread: 'TH1' }) => {
    const responds: any[] = [];
    await actions[action]({
      ack: async () => {},
      body: {
        team: { id: TEAM }, user: { id: user }, channel: { id: location.channel },
        container: { channel_id: location.channel, thread_ts: location.thread }, actions: [{ value }],
      },
      client, respond: async (m: any) => { responds.push(m); },
    });
    return responds;
  };
  const audit = async () => (await db.all(`SELECT action, user_id, actor, channel, meta FROM audit ORDER BY at`)) as any[];
  const approvalRequired = async (p: Promise<unknown>): Promise<ApprovalRequiredError> => {
    try { await p; } catch (e) { assert.ok(e instanceof ApprovalRequiredError, `expected ApprovalRequiredError, got ${String(e)}`); return e; }
    throw new Error('expected the write to wait for approval');
  };
  return { vouchr, db, client, context, slash, click, audit, approvalRequired, ephemerals, messages, modals, views };
}

const APPROVE_GITHUB_BLOCKS = (reason?: string, link?: string) => [
  { type: 'mrkdwn', text: ':lock: *Approve this github action?*\nThe agent wants to run an action as you on github.' },
  { type: 'plain_text', text: 'POST api.github.com/repos/alex/vouchr-demo/issues' },
  ...(reason ? [{ type: 'plain_text', text: `Reason: ${reason}` }] : []),
  ...(link ? [{ type: 'mrkdwn', text: `Link: <${link}>` }] : []),
  { type: 'mrkdwn', text: `This covers one call, once, within 5 minutes. This prompt expires in 10 minutes if unused. The request body is not shown or inspected.${reason || link ? ' The reason and link are the agent’s own claim, not verified by Vouchr.' : ''}` },
  { type: 'actions', buttons: ['Approve', 'Deny'] },
];

test('(a) deny by default, (b) a member enables, (c) the connect prompt, (d) a read runs as Alex', async (t) => {
  const d = await demo(t);
  // (a) The channel starts closed.
  const alex = await d.context(ALEX);
  await assert.rejects(alex.connect('github'), (e: unknown) => {
    assert.equal(safeUserMessage(e), 'This provider is disabled in the channel. Any member can run `/vouchr enable` there.');
    return true;
  });
  assert.deepEqual((await d.audit()).map((r) => [r.action, JSON.parse(r.meta).reason]), [['denied', 'tool-disabled']]);

  // (b) Sam opens it; Jo, who is not in the channel, cannot.
  assert.equal(await d.slash(JO, 'enable github'), 'Only a current member of this channel can change channel tools. If you are one, make sure Vouchr is in the channel and try again.');
  assert.equal(await d.slash(SAM, 'enable github'), `Enabled *github* in <#${CHANNEL}>.`);

  // (c) The first ask posts the private Connect prompt with the two scopes and one button.
  await assert.rejects((await d.context(ALEX)).connect('github'), ConsentRequiredError);
  assert.equal(d.ephemerals.length, 1);
  assert.equal(d.ephemerals[0].user, ALEX);
  const connect = d.ephemerals[0].blocks;
  assert.match(connect[0].text.text, /^:link: \*Connect your github account\*\nI need to act as you on github for this\./);
  assert.match(connect[1].text.text, /Connecting grants the agent, acting as you:\n• Read your profile\n• Read and write your repositories/);
  assert.equal(connect.at(-1).elements[0].text.text, 'Connect github');
  // The browser sign-in is covered in test/browser-identity.test.ts; here the callback's write is seeded.
  await d.vouchr.vault.upsert(userOwner(id(ALEX)), 'github', { accessToken: TOKEN, refreshToken: null, scopes: 'read:user repo', expiresAt: null, externalAccount: 'alex' });
  assert.equal(await d.slash(ALEX, 'status'), 'Your connected accounts:\n• *github* (alex) in your DMs\n\nDisconnect with `/vouchr disconnect <provider>`.');

  // (d) A read runs as Alex: no prompt, no token in the reply path, one inject audit row for the channel.
  await withFetch(async (calls) => {
    const gh = await (await d.context(ALEX)).connect('github');
    const me: any = await (await gh.fetch('https://api.github.com/user')).json();
    assert.equal(`You are *${me.login}* on GitHub, ${me.public_repos} public repos.`, 'You are *alex* on GitHub, 3 public repos.');
    assert.equal(new Headers(calls[0].init?.headers).get('authorization'), `Bearer ${TOKEN}`);
  });
  const inject = (await d.audit()).find((r) => r.action === 'inject');
  assert.equal(inject.user_id, ALEX);
  assert.equal(inject.channel, CHANNEL);
  assert.ok(!JSON.stringify(await d.audit()).includes(TOKEN));
});

test('(e) a write as Alex waits for Alex with no approval configuration, (f) deny, and re-asking while pending', async (t) => {
  const d = await demo(t);
  await d.slash(SAM, 'enable github');
  await d.vouchr.vault.upsert(userOwner(id(ALEX)), 'github', { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'alex' });
  await withFetch(async (calls) => {
    const alex = await d.context(ALEX);
    const gh = await alex.connect('github');
    const write = (init: Record<string, unknown> = {}) => gh.fetch('https://api.github.com/repos/alex/vouchr-demo/issues', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ title: 'Demo issue' }), ...init,
    });

    // Nothing is sent. The agent acts as Alex, so Alex gets one private prompt, in the thread, that
    // says what and why (#359). The channel sees nothing.
    const first = await d.approvalRequired(write());
    assert.equal(first.approver, 'self');
    assert.equal(safeUserMessage(first), 'Human approval is required. Approve the prompt Vouchr posted to you, then retry.');
    assert.equal(calls.length, 0);
    assert.equal(d.messages.length, 0, 'no channel message for a personal write');
    assert.equal(d.ephemerals.length, 1);
    assert.equal(d.ephemerals[0].channel, CHANNEL);
    assert.equal(d.ephemerals[0].user, ALEX);
    assert.equal(d.ephemerals[0].thread_ts, 'TH1');
    assert.deepEqual(texts(d.ephemerals[0].blocks), APPROVE_GITHUB_BLOCKS());
    assert.ok(!JSON.stringify(d.ephemerals[0]).includes('Demo issue'), 'the request body is never rendered');

    // Re-asking while the prompt is pending: one private line, no second prompt.
    const again = await d.approvalRequired(write());
    assert.equal(again.approvalId, first.approvalId);
    assert.equal(d.ephemerals.length, 2);
    assert.equal(d.ephemerals[1].text, 'Still waiting for you to decide the github action above.');

    // Sam cannot approve for Alex: the credential is Alex's own; the prompt stays.
    assert.deepEqual(await d.click(APPROVAL_APPROVE_ACTION, SAM, first.approvalId), [
      { replace_original: false, response_type: 'ephemeral', text: 'You are not eligible to decide this approval; only the requester can.' },
    ]);
    // The host waits for the decision (#363). Alex approves: the prompt is replaced, the wait
    // resolves, the same write runs once with no new mention, and the next write asks again.
    const waiting = alex.waitForApproval(first.approvalId);
    assert.deepEqual(await d.click(APPROVAL_APPROVE_ACTION, ALEX, first.approvalId), [
      { replace_original: true, response_type: 'ephemeral', text: '✅ Approved the *github* action. This covers one call, once, within 5 minutes. The agent will continue.' },
    ]);
    assert.equal(await waiting, 'approved');
    assert.equal((await write()).status, 200);
    assert.equal(calls.length, 1);
    assert.equal(d.ephemerals.length, 2, 'the continued write posted no new prompt');
    const second = await d.approvalRequired(write({ reason: 'Filing the demo issue Alex asked for', link: 'https://github.com/alex/vouchr-demo' }));
    assert.notEqual(second.approvalId, first.approvalId);
    assert.deepEqual(texts(d.ephemerals.at(-1).blocks), APPROVE_GITHUB_BLOCKS('Filing the demo issue Alex asked for', 'https://github.com/alex/vouchr-demo'));
    assert.deepEqual(
      (await d.audit()).filter((r) => r.action === 'approval_requested').map((r) => JSON.parse(r.meta).reason),
      [undefined, 'Filing the demo issue Alex asked for'],
      'the reason rides the audit row under one fixed key',
    );

    // (f) Deny: nothing is sent, and asking again is a new decision.
    assert.deepEqual(await d.click(APPROVAL_DENY_ACTION, ALEX, second.approvalId), [
      { replace_original: true, response_type: 'ephemeral', text: '🚫 Denied the *github* action. Nothing was sent.' },
    ]);
    assert.equal(calls.length, 1);
    const third = await d.approvalRequired(write());
    assert.notEqual(third.approvalId, second.approvalId);
    assert.equal(d.messages.length, 0, 'the channel never saw a personal write');
  });
  assert.deepEqual(
    (await d.audit()).map((r) => `${r.action}${r.actor ? `:${r.actor}` : ''}${JSON.parse(r.meta).reason ? `(${JSON.parse(r.meta).reason})` : ''}`),
    [
      'config', 'approval_requested', 'denied(not-approver)', `approved:${ALEX}`, `approval_consumed:${ALEX}`, 'inject',
      'approval_requested(Filing the demo issue Alex asked for)', `denied:${ALEX}(approval-denied)`, 'approval_requested',
    ],
  );
});

test('(g) a shared credential the channel owns, (h) one approval covers the thread until the TTL', async (t) => {
  const d = await demo(t);
  await d.slash(SAM, 'enable github-team');
  // Edge: the channel identity with no credential connected yet is one message naming connect-shared.
  assert.equal(
    await d.slash(SAM, 'identity github-team channel'),
    `In <#${CHANNEL}> the agent now acts as the channel for *github-team*. Connect its account with \`/vouchr connect-shared github-team\`.`,
  );
  await assert.rejects((await d.context(ALEX)).connect('github-team'), (e: unknown) => {
    assert.equal(safeUserMessage(e), 'No shared channel credential is configured. Any member can run `/vouchr connect-shared` there.');
    return true;
  });

  // (g) Sam connects the team token through the private modal.
  assert.equal(await d.slash(SAM, 'connect-shared github-team'), undefined);
  const form = d.modals.at(-1).view;
  assert.equal(form.title.text, 'Channel credential');
  assert.equal(form.blocks[0].text.text, 'Set the *github-team* credential for this channel. Only you can see what you type here. It is never posted to the channel.');
  await d.views[CONFIGURE_CALLBACK]({
    ack: async () => {},
    body: { team: { id: TEAM }, user: { id: SAM } },
    view: { id: 'V_FORM', private_metadata: form.private_metadata, state: { values: { raw: { v: { value: TEAM_TOKEN } }, ref: { v: { value: '' } } } } },
    client: d.client,
  });
  assert.equal(d.modals.at(-1).view.title.text, 'Credential saved');
  assert.equal(d.modals.at(-1).view.blocks[0].text.text, `Saved the *github-team* credential for <#${CHANNEL}>.`);
  assert.equal(await new ChannelConfig(d.db).getIdentity(TEAM, CHANNEL, 'github-team'), 'channel');
  assert.ok(!JSON.stringify([d.modals, d.messages, d.ephemerals, await d.audit()]).includes(TEAM_TOKEN));

  await withFetch(async (calls) => {
    const write = async (path: string, thread = 'TH1') => (await (await d.context(ALEX, CHANNEL, thread)).connect('github-team'))
      .fetch(`https://api.github.com${path}`, { method: 'POST', body: '{}' });
    const first = await d.approvalRequired(write('/repos/alex/vouchr-demo/issues'));
    assert.equal(first.grant, 'thread');
    // The credential belongs to the channel, so with no approver configured a teammate decides (#359).
    assert.equal(first.approver, 'member');
    assert.equal(safeUserMessage(first), 'Waiting for another channel member to approve the prompt; retry after they do.');
    assert.equal(d.ephemerals.length, 0, 'the team prompt is a channel message, not a private one');
    assert.deepEqual(texts(d.messages[0].blocks), [
      { type: 'mrkdwn', text: `:lock: *Approve this github-team action?*\nThe agent wants to run an action on github-team for <@${ALEX}>. Another member of this channel must approve it.` },
      { type: 'plain_text', text: 'POST api.github.com/repos/alex/vouchr-demo/issues' },
      { type: 'mrkdwn', text: 'This covers every github-team call that needs approval in this thread for 30 minutes. This prompt expires in 10 minutes if unused. The request body is not shown or inspected.' },
      { type: 'actions', buttons: ['Approve', 'Deny'] },
    ]);
    // Alex cannot approve Alex's use of the team credential; the prompt stays for a teammate.
    assert.deepEqual(await d.click(APPROVAL_APPROVE_ACTION, ALEX, first.approvalId), [
      { replace_original: false, response_type: 'ephemeral', text: 'You are not eligible to decide this approval; another channel member must.' },
    ]);
    assert.deepEqual(await d.click(APPROVAL_APPROVE_ACTION, SAM, first.approvalId), [
      { replace_original: true, response_type: 'ephemeral', text: '✅ Approved the *github-team* action. This covers every github-team call that needs approval in this thread for 30 minutes. The agent will continue.' },
    ]);
    assert.equal(d.ephemerals.at(-1).text, `✅ <@${SAM}> approved your *github-team* action. The agent will continue.`);
    // (h) The same thread proceeds, call after call, with the channel's token and the requester audited.
    assert.equal((await write('/repos/alex/vouchr-demo/issues')).status, 200);
    assert.equal((await write('/repos/alex/vouchr-demo/issues/1/comments')).status, 200);
    assert.equal(calls.length, 2);
    assert.equal(new Headers(calls[0].init?.headers).get('authorization'), `Bearer ${TEAM_TOKEN}`);
    assert.equal(d.messages.length, 1, 'no second prompt in the approved thread');
    // Another thread asks again.
    await d.approvalRequired(write('/repos/alex/vouchr-demo/issues', 'TH2'));
    assert.equal(d.messages.length, 2);
    assert.equal(d.messages[1].thread_ts, 'TH2');
    // After the TTL the approved thread asks again too.
    await d.db.run(`UPDATE approval_request SET expires_at=${POSTGRES_NOW_US_SQL}-1 WHERE id=?`, [first.approvalId]);
    await d.approvalRequired(write('/repos/alex/vouchr-demo/issues'));
    assert.equal(d.messages.length, 3);
    assert.equal(calls.length, 2);
  });
  const consumed = (await d.audit()).filter((r) => r.action === 'approval_consumed');
  assert.equal(consumed.length, 2);
  assert.ok(consumed.every((r) => r.user_id === ALEX && r.actor === SAM && JSON.parse(r.meta).grant === 'thread'));

  // Back to each person: the channel token is deleted with the flip.
  assert.equal(await d.slash(SAM, 'disconnect-shared github-team'), `Removed the shared *github-team* account in <#${CHANNEL}>. The agent now acts as each person there.`);
  assert.equal(await new ChannelConfig(d.db).getIdentity(TEAM, CHANNEL, 'github-team'), 'person');
});

test('(i) an outsider, two approvers at once, (k) offboarding fences a pending prompt', async (t) => {
  const d = await demo(t, { members: [ALEX, SAM, 'U_SAM2'] });
  await d.slash(SAM, 'enable github');
  await d.slash(SAM, 'enable github-team');
  await d.slash(SAM, 'identity github-team channel');
  await d.vouchr.vault.upsert(channelOwner(TEAM, CHANNEL), 'github-team', { accessToken: TEAM_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
  await d.vouchr.vault.upsert(userOwner(id(ALEX)), 'github', { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'alex' });
  await withFetch(async () => {
    // (i) The team credential: a teammate decides, so an outsider and the requester are refused.
    const team = await (await d.context(ALEX)).connect('github-team');
    const teamWrite = () => team.fetch('https://api.github.com/repos/alex/vouchr-demo/issues', { method: 'POST', body: '{}' });
    const pending = await d.approvalRequired(teamWrite());
    assert.equal(pending.approver, 'member');
    // Jo is not a member: refused and audited, the prompt stays.
    assert.deepEqual(await d.click(APPROVAL_APPROVE_ACTION, JO, pending.approvalId), [
      { replace_original: false, response_type: 'ephemeral', text: 'You are not eligible to decide this approval; another channel member must.' },
    ]);
    assert.equal(JSON.parse((await d.audit()).at(-1).meta).reason, 'not-approver');
    // Two approvers at once: one decision, one fixed receipt for the other.
    const [a, b] = await Promise.all([
      d.click(APPROVAL_APPROVE_ACTION, SAM, pending.approvalId),
      d.click(APPROVAL_APPROVE_ACTION, 'U_SAM2', pending.approvalId),
    ]);
    const outcomes = [a[0].text, b[0].text].sort();
    assert.deepEqual(outcomes, [
      'This approval expired or was already decided. Ask the agent again.',
      '✅ Approved the *github-team* action. This covers every github-team call that needs approval in this thread for 30 minutes. The agent will continue.',
    ]);
    assert.equal((await d.audit()).filter((r) => r.action === 'approved').length, 1);
    assert.equal((await teamWrite()).status, 200);

    // (k) Alex asks as Alex, is deactivated, and a click grants nothing: offboarding removed the
    // pending request with the credential, so the leftover prompt answers as stale.
    const gh = await (await d.context(ALEX)).connect('github');
    const write = () => gh.fetch('https://api.github.com/repos/alex/vouchr-demo/issues', { method: 'POST', body: '{}' });
    const stranded = await d.approvalRequired(write());
    assert.equal(stranded.approver, 'self');
    await d.vouchr.offboard(id(ALEX));
    assert.deepEqual(await d.click(APPROVAL_APPROVE_ACTION, SAM, stranded.approvalId), [
      { replace_original: true, response_type: 'ephemeral', text: 'This approval expired or was already decided. Ask the agent again.' },
    ]);
    assert.equal((await d.db.all(`SELECT 1 FROM approval_request`)).length, 0);
    assert.equal(await d.vouchr.vault.get(userOwner(id(ALEX)), 'github'), null, 'offboarding removed the credential');
  });
});

test('edge: a direct message needs no enable, the approver becomes the person, and the channel identity is not offered', async (t) => {
  const d = await demo(t);
  await d.vouchr.vault.upsert(userOwner(id(ALEX)), 'github', { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'alex' });
  await withFetch(async (calls) => {
    const gh = await (await d.context(ALEX, 'D_ALEX', 'TH1', 'im')).connect('github');
    const pending = await d.approvalRequired(gh.fetch('https://api.github.com/repos/alex/vouchr-demo/issues', { method: 'POST', body: '{}' }));
    assert.equal(pending.approver, 'self');
    assert.equal(d.ephemerals[0].channel, 'D_ALEX');
    assert.deepEqual(texts(d.ephemerals[0].blocks)[0], { type: 'mrkdwn', text: ':lock: *Approve this github action?*\nThe agent wants to run an action as you on github.' });
    assert.deepEqual(await d.click(APPROVAL_APPROVE_ACTION, ALEX, pending.approvalId, { channel: 'D_ALEX', thread: 'TH1' }), [
      { replace_original: true, response_type: 'ephemeral', text: '✅ Approved the *github* action. This covers one call, once, within 5 minutes. The agent will continue.' },
    ]);
    assert.equal((await gh.fetch('https://api.github.com/repos/alex/vouchr-demo/issues', { method: 'POST', body: '{}' })).status, 200);
    assert.equal(calls.length, 1);
  });
  // No channel governs a DM, so the channel identity is not offered there.
  assert.equal(
    await d.slash(ALEX, 'identity github channel', 'D_ALEX'),
    'Channel credentials are not allowed in DMs or group DMs. Use your own connection here, or configure in an internal channel.',
  );
});

test('(l) Slack Connect is refused everywhere with one message', async (t) => {
  const d = await demo(t, { channelInfo: { is_ext_shared: true } });
  const refusal = /^Channel credentials are not allowed in externally shared channels\./;
  await d.slash(SAM, 'connect-shared github-team'); // the modal opened by the command carries the refusal
  assert.equal(d.modals.at(-1).view.title.text, 'Setup unavailable');
  assert.match(d.modals.at(-1).view.blocks[0].text.text, refusal);
  assert.match(await d.slash(SAM, 'identity github-team channel'), refusal);
  assert.match(await d.slash(SAM, 'enable github'), refusal, 'governance writes are refused there too');
  // A provider enabled before the channel became shared: a write as Alex still prompts Alex privately
  // (the credential and the decision are Alex's own); a teammate prompt there is refused
  // (test/approval.test.ts, "member approver: no prompt is posted into an externally shared channel").
  await setChannelToolEnabled(new ChannelTools(d.db), TEAM, CHANNEL, 'github', true);
  await d.vouchr.vault.upsert(userOwner(id(ALEX)), 'github', { accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: 'alex' });
  await withFetch(async (calls) => {
    const gh = await (await d.context(ALEX)).connect('github');
    const pending = await d.approvalRequired(gh.fetch('https://api.github.com/repos/alex/vouchr-demo/issues', { method: 'POST', body: '{}' }));
    assert.equal(pending.approver, 'self');
    assert.deepEqual(d.ephemerals.map((e) => e.user), [ALEX]);
    assert.equal(d.messages.length, 0, 'no channel message lands in a Slack Connect channel');
    assert.equal(calls.length, 0);
  });
});

test('(m) the operator CLI lists who the agent acts as per channel', async (t) => {
  const url = await testDbUrl(t);
  const db = await openDb({ databaseUrl: url });
  t.after(() => db.close());
  const d = await demo(t, { db });
  await d.slash(SAM, 'enable github-team');
  await d.slash(SAM, 'identity github-team channel');
  const res = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'channels', '--team', TEAM], {
    encoding: 'utf8', env: { ...process.env, VOUCHR_DATABASE_URL: url },
  });
  assert.equal(res.status, 0, res.stderr);
  const [header, , ...rows] = res.stdout.trim().split('\n');
  assert.deepEqual(header.split(/\s+/), ['team', 'channel', 'provider', 'identity', 'enabled']);
  assert.deepEqual(rows.map((r) => r.split(/\s+/)), [
    [TEAM, CHANNEL, 'github', 'person', 'no'],
    [TEAM, CHANNEL, 'github-team', 'channel', 'yes'],
  ]);
});
