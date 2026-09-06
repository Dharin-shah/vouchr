// #347: a private Connect prompt replaces itself in Slack when clicked, and a stale one offers a
// fresh link in place. Every test drives the production handlers createVouchr registers.
import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import {
  CONNECT_PROMPT_OPENING_TEXT,
  CONNECT_PROMPT_STALE_TEXT,
  OAUTH_CONNECT_ACTION,
  OAUTH_RENEW_ACTION,
} from '../src/adapters/blocks';
import { createVouchr } from '../src/adapters/bolt';
import { BrowserIdentityVerifier } from '../src/adapters/slackVerify';
import { Audit } from '../src/core/audit';
import { Consent, isConsentState, STATE_TTL_US } from '../src/core/consent';
import { openDb, type Db } from '../src/core/db';
import { ConsentRequiredError } from '../src/core/errors';
import type { SlackIdentity } from '../src/core/identity';
import { POSTGRES_NOW_US_SQL } from '../src/core/interaction';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { openTestDb, testDbUrl } from './support/pg';
import { TEST_SLACK_OIDC } from './support/slackOidc';

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
const REDIRECT = 'https://vouchr.test/vouchr/oauth/callback';

const count = async (db: Db, sql: string): Promise<number> =>
  (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n ${sql}`))?.n ?? -1;
const expire = (db: Db, state: string) => db.run(
  `UPDATE consent_request SET created_at=${POSTGRES_NOW_US_SQL}-? WHERE state=?`,
  [STATE_TTL_US + 1_000_000, state],
);
const actionsOf = (blocks: any[]) => blocks.find((b: any) => b.type === 'actions').elements[0];

/** One Bolt instance with its registered action handlers captured, exactly as `install()` wires them. */
async function harness(t: TestContext, db: Db) {
  process.env.VOUCHR_MASTER_KEY = KEY.toString('base64');
  t.after(() => { delete process.env.VOUCHR_MASTER_KEY; });
  const vouchr = await createVouchr({ providers: [provider], baseUrl: 'https://vouchr.test', db });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, handler: any) => { actions[id] = handler; },
  });
  const posts: any[] = [];
  const client = {
    chat: {
      postEphemeral: async (a: any) => { posts.push(a); return {}; },
      postMessage: async (a: any) => { posts.push(a); return {}; },
    },
  };
  /** Post the private prompt through the middleware + connect(), as an agent turn does. Channels
   *  are deny-by-default, so opt the provider in (as a member's `/vouchr enable` would) first. */
  const prompt = async (channel = 'C1', user = ID.userId) => {
    await setChannelToolEnabled(new ChannelTools(db), ID.teamId, channel, provider.id, true);
    const context: any = {};
    await vouchr.middleware({ context, client, event: { channel, user, team: ID.teamId }, next: async () => {} });
    await assert.rejects(() => context.vouchr.connect(provider.id), ConsentRequiredError);
    const button = actionsOf(posts.at(-1).blocks);
    assert.equal(button.action_id, OAUTH_CONNECT_ACTION);
    assert.equal(button.value, new URL(button.url).searchParams.get('state'));
    return button.value as string;
  };
  /** Click a registered action with a Slack-signed-shaped payload; returns what `respond` received. */
  const click = async (
    actionId: string,
    value: unknown,
    user = ID.userId,
    /** Replaces the default recording `respond` (a test can make the response_url write fail). */
    respond?: (payload: any) => Promise<void>,
  ) => {
    const responses: any[] = [];
    await actions[actionId]({
      ack: async () => {},
      body: {
        team: { id: ID.teamId },
        user: { id: user },
        channel: { id: 'C1' },
        container: { channel_id: 'C1', is_ephemeral: true },
        actions: [value === undefined ? {} : { value }],
      },
      client,
      respond: respond ?? (async (payload: any) => { responses.push(payload); }),
    });
    return responses;
  };
  return { vouchr, posts, prompt, click };
}

test('a Connect click on a live in-channel prompt replaces the ephemeral and does not spend the state', async (t) => {
  const db = await openTestDb(t);
  const h = await harness(t, db);
  const state = await h.prompt();

  const responses = await h.click(OAUTH_CONNECT_ACTION, state);
  assert.deepEqual(responses, [
    { replace_original: true, response_type: 'ephemeral', text: CONNECT_PROMPT_OPENING_TEXT },
  ]);
  assert.ok(await new Consent(db).activeRow(state), 'the click must not spend, supersede, or expire the state');
  assert.equal(h.posts.length, 1, 'the replacement rides the response_url, not a new post');

  // A channel-less prompt is a durable DM message (postMessage) and the user's only retry surface
  // after a cancelled Slack sign-in, so its live click stays the bare ack.
  const dm = await new Consent(db).begin({ ...ID, userId: 'U2' }, provider, REDIRECT, null);
  assert.deepEqual(await h.click(OAUTH_CONNECT_ACTION, dm.state, 'U2'), []);
  assert.ok(await new Consent(db).activeRow(dm.state));

  // Every Vouchr-rendered button carries its state; a click without one is a tampered payload and
  // gets the fixed stale copy, never a silent ack.
  assert.deepEqual(await h.click(OAUTH_CONNECT_ACTION, undefined), [
    { replace_original: true, response_type: 'ephemeral', text: CONNECT_PROMPT_STALE_TEXT },
  ]);
  assert.equal(await count(db, 'FROM audit'), 0);
});

test('a failed response_url write is ambiguous: the fallback is a DM, never a second write that could overwrite the installed prompt', async (t) => {
  const db = await openTestDb(t);
  const h = await harness(t, db);
  const state = await h.prompt();
  await expire(db, state);
  h.posts.length = 0;

  // The replacement write throws after Slack may already have accepted it.
  let writes = 0;
  const responses = await h.click(OAUTH_CONNECT_ACTION, state, ID.userId, async () => {
    writes++;
    throw new Error('socket hang up');
  });
  assert.deepEqual(responses, [], 'nothing else rides the response_url');
  assert.equal(writes, 1, 'exactly one response_url write; no replace_original retry');
  assert.deepEqual(h.posts, [{ channel: ID.userId, text: CONNECT_PROMPT_STALE_TEXT }], 'the actor hears the outcome in a DM');

  // The same rule for "Send a new link": once the fresh prompt has been written through the
  // response_url, a failure reports through a DM instead of clobbering it.
  const fresh = await h.prompt();
  await expire(db, fresh);
  h.posts.length = 0;
  const renew = await h.click(OAUTH_RENEW_ACTION, fresh, ID.userId, async () => { throw new Error('socket hang up'); });
  assert.deepEqual(renew, []);
  assert.equal(h.posts.length, 1, 'one DM, no second response_url write');
  assert.equal(h.posts[0].channel, ID.userId);
  assert.doesNotMatch(String(h.posts[0].text), /socket hang up/, 'foreign error text never reaches Slack');
});

test('a Connect click on an expired, superseded, or spent prompt replaces it with the expiry copy and a Send a new link button', async (t) => {
  const db = await openTestDb(t);
  const h = await harness(t, db);
  const consent = new Consent(db);

  const expectRenewPrompt = async (state: string) => {
    const responses = await h.click(OAUTH_CONNECT_ACTION, state);
    assert.equal(responses.length, 1);
    const { replace_original, response_type, blocks, text } = responses[0];
    assert.equal(replace_original, true);
    assert.equal(response_type, 'ephemeral');
    assert.match(text, /no longer current/);
    assert.match(JSON.stringify(blocks), /Connect your acme account/);
    assert.deepEqual(
      { action_id: actionsOf(blocks).action_id, value: actionsOf(blocks).value },
      { action_id: OAUTH_RENEW_ACTION, value: state },
    );
  };

  const expired = await h.prompt();
  await expire(db, expired);
  await expectRenewPrompt(expired);
  assert.equal(
    (await db.get<{ consumed_at: number | null }>('SELECT consumed_at FROM consent_request WHERE state=?', [expired]))?.consumed_at,
    null,
    'the click reads the row; it never consumes it',
  );

  const superseded = await h.prompt('C2');
  const newest = await h.prompt('C3'); // a different context supersedes the C2 generation
  assert.notEqual(newest, superseded);
  await expectRenewPrompt(superseded);

  assert.equal((await consent.consume(newest)).status, 'active');
  await expectRenewPrompt(newest);
  assert.equal(await count(db, 'FROM audit'), 0);
});

test('Send a new link mints exactly one new request across two Bolt replicas clicking at once and replaces once', async (t) => {
  const url = await testDbUrl(t);
  const a = await openDb({ databaseUrl: url });
  const b = await openDb({ databaseUrl: url });
  t.after(async () => { await Promise.all([a.close(), b.close()]); });
  const first = await harness(t, a);
  const second = await harness(t, b);

  const old = await first.prompt();
  await expire(a, old);
  const [one, two] = await Promise.all([
    first.click(OAUTH_RENEW_ACTION, old),
    second.click(OAUTH_RENEW_ACTION, old),
  ]);
  const replacements = [...one, ...two].filter((r) => r.replace_original === true);
  assert.equal(replacements.length, 1, 'exactly one replica replaces the prompt');
  assert.equal([...one, ...two].length, 1, 'the loser stays quiet rather than clobbering the winner');
  const button = actionsOf(replacements[0].blocks);
  assert.equal(button.action_id, OAUTH_CONNECT_ACTION);
  assert.ok(isConsentState(button.value) && button.value !== old, 'a fresh generation');
  assert.equal(new URL(button.url).searchParams.get('state'), button.value);
  assert.match(replacements[0].text, /Connect your acme account/);

  const live = await a.all<{ state: string; delivered_at: number | null }>(
    'SELECT state, delivered_at FROM consent_request WHERE superseded_at IS NULL',
  );
  assert.deepEqual(live.map((r) => r.state), [button.value]);
  assert.ok(live[0].delivered_at != null, 'delivered through the lease, then confirmed');
  assert.equal(await count(a, 'FROM consent_request WHERE superseded_at IS NOT NULL'), 1);
  assert.equal(first.posts.length + second.posts.length, 1, 'no chat.post: the new prompt rode the response_url');

  // The old button clicked again finds the live generation already delivered: nothing to redo.
  assert.deepEqual(await first.click(OAUTH_RENEW_ACTION, old), []);
  assert.equal(await count(a, 'FROM consent_request'), 2);
  assert.equal(await count(a, 'FROM audit'), 0);
});

test('a tampered or foreign Connect click is refused with the stale copy, spends nothing, and audits nothing', async (t) => {
  const db = await openTestDb(t);
  const h = await harness(t, db);
  const foreign = await h.prompt('C1', 'U2'); // another user's live prompt
  const before = await count(db, 'FROM consent_request');
  const stale = [{ replace_original: true, response_type: 'ephemeral', text: CONNECT_PROMPT_STALE_TEXT }];

  for (const value of [randomBytes(32).toString('base64url'), 'not-a-state', '', 42, foreign]) {
    assert.deepEqual(await h.click(OAUTH_CONNECT_ACTION, value), stale, `connect ${String(value)}`);
    assert.deepEqual(await h.click(OAUTH_RENEW_ACTION, value), stale, `renew ${String(value)}`);
  }
  assert.ok(await new Consent(db).activeRow(foreign), "another user's click never touches the owner's state");
  assert.equal(await count(db, 'FROM consent_request'), before, 'no generation minted for a refused click');
  assert.equal(await count(db, 'FROM audit'), 0);
  assert.equal(h.posts.length, 1);
});

test('the browser verify hop keeps its fixed stale copy and says the Slack prompt now offers a new link', async (t) => {
  const db = await openTestDb(t);
  const verifier = new BrowserIdentityVerifier({
    consent: new Consent(db),
    registry: new ProviderRegistry([provider]),
    redirectUri: REDIRECT,
    oidcRedirectUri: 'https://vouchr.test/vouchr/oauth/slack',
    audit: new Audit(db),
    oidc: TEST_SLACK_OIDC,
  });
  const r = await verifier.begin(randomBytes(32).toString('base64url'));
  assert.deepEqual(r, {
    ok: false,
    status: 400,
    error: `${CONNECT_PROMPT_STALE_TEXT} The prompt in Slack now offers a new link.`,
  });
  assert.equal(CONNECT_PROMPT_STALE_TEXT, 'This connection request is no longer current. Ask the agent for a new connection prompt.');
});
