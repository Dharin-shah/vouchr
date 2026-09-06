import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { ConnectContext, createVouchr } from '../src/adapters/bolt';
import { CONFIGURE_CALLBACK } from '../src/adapters/blocks';
import { WebClient } from '@slack/web-api';

const KEY = randomBytes(32);
const ID = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };
const SECRET = 'sk-super-secret-value-9999';

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});

// Mirrors channel.test.ts's ctx() but exposes the governance knobs. `slack.members` shapes the
// mocked conversations.members LIVE (mutate it between calls): a member-id list, or 'throw' to fail
// the membership read. Configuration is member-gated (#322) and reads the same fake.
async function ctx(t: TestContext, opts: {
  requireMembership?: boolean;
  members?: string[] | 'throw';
  clientToken?: string;
  slackClientOptions?: any;
} = {}) {
  const { requireMembership = false, clientToken, slackClientOptions } = opts;
  const slack = { members: opts.members ?? [ID.userId] };
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const client = {
    ...(clientToken ? { token: clientToken } : {}),
    conversations: {
      info: async () => ({ channel: { id: 'C_FIN', is_channel: true } }),
      members: async () => {
        if (slack.members === 'throw') throw new Error('channel_not_found');
        return { members: slack.members };
      },
    },
  } as any;
  const c = new ConnectContext({
    identity: ID, channel: 'C_FIN', client, registry: new ProviderRegistry([provider]), vault, audit,
    consent: new Consent(db), policy: new Policy(), redirectUri: 'http://x',
    channelConfig: new ChannelConfig(db), requireMembership, slackClientOptions,
  });
  return { c, db, vault, audit, slack };
}

const auditRows = async (db: any) => await db.all('SELECT action, meta FROM audit') as any[];

// requireChannelMembership ON: a configured shared cred is refused for a non-member, audited
// 'not-member', and allowed for a member. (A member configures it; the roster then changes.)
test('requireChannelMembership: non-member refused + audited, member allowed', async (t) => {
  const deny = await ctx(t, { requireMembership: true });
  await deny.c.setChannelSecret('mcp', SECRET);
  deny.slack.members = ['U_OTHER']; // the actor left (or was removed) after configuring
  await assert.rejects(() => deny.c.connectChannel('mcp'), /member of this channel/);
  assert.ok((await auditRows(deny.db)).some((r) => r.action === 'denied' && r.meta.includes('not-member')));

  const ok = await ctx(t, { requireMembership: true, members: [ID.userId] });
  await ok.c.setChannelSecret('mcp', SECRET);
  assert.ok(await ok.c.connectChannel('mcp')); // member → handle
});

// requireChannelMembership OFF (default): membership is never checked at USE, a non-member still gets
// the shared cred, exactly as before this feature. (Configuration itself is always member-gated.)
test('requireChannelMembership: off → membership not checked at use', async (t) => {
  const { c, slack } = await ctx(t, { requireMembership: false });
  await c.setChannelSecret('mcp', SECRET);
  slack.members = 'throw';
  assert.ok(await c.connectChannel('mcp')); // would throw if membership were consulted
});

// Fail-closed: when membership can't be verified (conversations.members throws), refuse.
test('requireChannelMembership: membership check errors → refused', async (t) => {
  const { c, db, slack } = await ctx(t, { requireMembership: true });
  await c.setChannelSecret('mcp', SECRET);
  slack.members = 'throw';
  await assert.rejects(() => c.connectChannel('mcp'), /member of this channel/);
  assert.ok((await auditRows(db)).some((r) => r.action === 'denied' && r.meta.includes('not-member')));
});

test('requireChannelMembership: token-bearing clients use the bounded zero-retry transport', async (t) => {
  const seen: any[] = [];
  const prototype = WebClient.prototype as any;
  const realApiCall = prototype.apiCall;
  prototype.apiCall = async function (this: any, method: string) {
    seen.push({
      method,
      retries: this.retryConfig?.retries,
      rejectRateLimited: this.rejectRateLimitedCalls,
      apiUrl: this.slackApiUrl,
    });
    return { ok: true, members: [ID.userId] };
  };
  try {
    const { c } = await ctx(t, {
      requireMembership: true,
      clientToken: 'xoxb-membership-test',
      slackClientOptions: { slackApiUrl: 'https://slack-proxy.internal/api/' },
    });
    await c.setChannelSecret('mcp', SECRET); // the member gate reads membership through the same bound
    assert.ok(await c.connectChannel('mcp'));
    const bounded = {
      method: 'conversations.members',
      retries: 0,
      rejectRateLimited: true,
      apiUrl: 'https://slack-proxy.internal/api/',
    };
    assert.deepEqual(seen, [bounded, bounded]);
  } finally {
    prototype.apiCall = realApiCall;
  }
});

test('/vouchr commands pass the member gate for a current channel member', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const lan = await createVouchr({
    providers: [provider],
    baseUrl: 'http://127.0.0.1:1',
    db: await openTestDb(t),
  });
  let handler: any;
  lan.registerCommands({ command: (_n: string, h: any) => (handler = h), view: () => undefined, action: () => undefined });

  const out: string[] = [];
  let opened: any = null;
  let hydrated: any = null;
  const client = {
    // enable/connect-shared now assert channel eligibility at the mutation (like mode always did),
    // so the fake must serve conversations.info for an ordinary eligible channel, and the member
    // gate (#322) reads conversations.members.
    conversations: {
      info: async () => ({ channel: { id: 'C_FIN', is_channel: true } }),
      members: async () => ({ members: [ID.userId] }),
    },
    views: {
      open: async (a: any) => {
        opened = a;
        return { view: { id: 'V_LOADING' } };
      },
      update: async ({ view }: any) => { hydrated = view; },
    },
    chat: { postMessage: async () => ({}) },
  };
  const base = { team_id: 'T1', user_id: 'U_ADMIN', channel_id: 'C_FIN', trigger_id: 'trig' };

  await handler({
    command: { ...base, text: 'enable mcp' },
    ack: async () => {},
    respond: async (m: string) => out.push(m),
    client,
  });
  assert.match(out[0], /Enabled/);
  const row = await lan.db.get('SELECT enabled FROM channel_tool WHERE team_id=? AND channel=? AND provider=?', ['T1', 'C_FIN', 'mcp']) as any;
  assert.equal(row.enabled, 1);

  const enableAuditCount = Number((await lan.db.get(
    "SELECT COUNT(*) AS n FROM audit WHERE action='config' AND provider='mcp'",
  ) as any).n);
  await handler({
    command: { ...base, text: 'enable mcp' },
    ack: async () => {},
    respond: async (m: string) => out.push(m),
    client,
  });
  assert.match(out[1], /\*mcp\* is already enabled .*— nothing changed\./);
  assert.equal(Number((await lan.db.get(
    "SELECT COUNT(*) AS n FROM audit WHERE action='config' AND provider='mcp'",
  ) as any).n), enableAuditCount, 'truthful no-op feedback must not mask an audit write');

  await handler({
    command: { ...base, text: 'connect-shared mcp' },
    ack: async () => {},
    respond: async (m: string) => out.push(m),
    client,
  });
  assert.equal(opened?.trigger_id, 'trig');
  assert.equal(opened?.view?.callback_id, undefined);
  assert.equal(hydrated?.callback_id, CONFIGURE_CALLBACK);

  await handler({
    command: { ...base, text: 'disable mcp' },
    ack: async () => {},
    respond: async (m: string) => out.push(m),
    client,
  });
  assert.match(out.at(-1) ?? '', /Disabled/);
  const disableAuditCount = Number((await lan.db.get(
    "SELECT COUNT(*) AS n FROM audit WHERE action='config' AND provider='mcp'",
  ) as any).n);
  await handler({
    command: { ...base, text: 'disable mcp' },
    ack: async () => {},
    respond: async (m: string) => out.push(m),
    client,
  });
  assert.match(out.at(-1) ?? '', /\*mcp\* is already disabled .*— nothing changed\./);
  assert.equal(Number((await lan.db.get(
    "SELECT COUNT(*) AS n FROM audit WHERE action='config' AND provider='mcp'",
  ) as any).n), disableAuditCount, 'a repeated disable must remain mutation- and audit-free');
});
