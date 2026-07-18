import { test } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  safeUserMessage,
  createVouchr,
  ConsentRequiredError,
  SessionApprovalRequiredError,
} from '../src/adapters/bolt';
import { EgressBlockedError, NoConnectionError, ResolverFailedError, ResponseBlockedError } from '../src/core/injector';
import { SecretReferenceError } from '../src/core/reference';
import { defineProvider } from '../src/core/providers';
import { USER_KEY_CALLBACK, CONFIGURE_CALLBACK, SETUP_KEY_ACTION } from '../src/adapters/blocks';
import { ChannelProvisioningRequests, UserProvisioningRequests } from '../src/core/provisioning';
import { purgePendingForProvider } from '../src/core/offboard';
import { countingDb } from './support/counting-db';
import { channelOwner } from '../src/core/owner';

// A key provider that brokers (non-service) — enough to exercise the /vouchr command + channel modal.
const acme = () => defineProvider({
  id: 'acme', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false,
  inject: (h: any, s: string) => h.set('x-api-key', s),
});

const SECRET = 'secret ghp_abc1234567890abcdef';

async function issueChannelRequest(
  db: any,
  vouchr: Awaited<ReturnType<typeof createVouchr>>,
  channel = 'C1',
  provider = 'acme',
): Promise<string> {
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const requests = new ChannelProvisioningRequests(db, vouchr.vault);
  const requestId = await requests.issue(
    identity,
    channel,
    provider,
    await vouchr.vault.userProvisioningIssuedAt(),
  );
  assert.ok(requestId);
  return requestId;
}

function channelSetupSurface(vouchr: Awaited<ReturnType<typeof createVouchr>>) {
  let command: any;
  let submit: any;
  vouchr.registerCommands({
    command: (_name: string, handler: any) => { command = handler; },
    view: (id: string, handler: any) => { if (id === CONFIGURE_CALLBACK) submit = handler; },
    action: () => undefined,
  });
  return {
    open: (client: any, respond: (value: any) => Promise<void> = async () => undefined) => command({
      command: {
        team_id: 'T1',
        user_id: 'U1',
        channel_id: 'C1',
        trigger_id: 'TRIGGER',
        text: 'configure acme',
      },
      ack: async () => undefined,
      respond,
      client,
    }),
    submit: (client: any, privateMetadata: string, ack: (value?: any) => Promise<void>) => submit({
      ack,
      body: { team: { id: 'T1' }, user: { id: 'U1' } },
      view: {
        id: 'V_CHANNEL',
        private_metadata: privateMetadata,
        state: {
          values: {
            raw: { v: { value: 'synthetic-channel-key' } },
            ref: { v: { value: '' } },
          },
        },
      },
      client,
    }),
  };
}

// Unit: an unexpected/foreign error is reduced to its CLASS NAME — the raw message (which may carry
// a leaked token) is never returned.
test('safeUserMessage: masks an unexpected error with fixed copy', () => {
  const msg = safeUserMessage(new Error(SECRET));
  assert.ok(!msg.includes('ghp_abc'), 'token must not survive');
  assert.equal(msg, 'Something went wrong. Ask an admin to check the Vouchr logs.');
});

// A custom-named error (e.g. thrown by a provider.inject / KMS extension) exposes neither its name
// nor message; both are foreign and can be attacker-controlled.
test('safeUserMessage: masks a custom error class and its secret message', () => {
  class ProviderInjectError extends Error {}
  const msg = safeUserMessage(new ProviderInjectError(SECRET));
  assert.ok(!msg.includes('ghp_abc'));
  assert.ok(!msg.includes('ProviderInjectError'));
  assert.equal(msg, 'Something went wrong. Ask an admin to check the Vouchr logs.');
});

// Typed errors map to Vouchr-owned fixed copy; constructor text is not a trust boundary.
test("safeUserMessage: Vouchr's typed errors use the core mapper's fixed safe copy", () => {
  assert.equal(
    safeUserMessage(new ConsentRequiredError('github', 'posted')),
    'Consent is required. Complete the private Connect prompt, then retry.',
  );
  assert.match(
    safeUserMessage(new ConsentRequiredError('github', 'reused')),
    /no longer visible/,
  );
  assert.equal(
    safeUserMessage(new SessionApprovalRequiredError('github')),
    'Thread-scoped session approval is required. Approve the private prompt, then retry.',
  );
  assert.equal(
    safeUserMessage(new EgressBlockedError('Egress blocked: host not allowed')),
    'The request was blocked by Vouchr egress policy. Check the provider configuration.',
  );
  assert.equal(
    safeUserMessage(new ResponseBlockedError('Response blocked: content-type is not allowed for provider "github"', 'content_type')),
    'The provider response was blocked by Vouchr response policy. Check the provider configuration.',
  );
  assert.equal(
    safeUserMessage(new NoConnectionError('No connection for github')),
    'No credential is connected. Connect the provider, then retry.',
  );
  assert.equal(
    safeUserMessage(new ResolverFailedError()),
    'The external credential resolver is temporarily unavailable. Retry later.',
  );
  const reference = new SecretReferenceError('invalid_reference');
  assert.equal(safeUserMessage(reference), reference.message);
});

// Non-Error values don't crash and don't echo their content.
test('safeUserMessage: handles a non-Error throw', () => {
  const msg = safeUserMessage('ghp_rawstring');
  assert.ok(!msg.includes('ghp_rawstring'));
  assert.match(msg, /Something went wrong/);
});

// Integration: the modal-submit path. A KMS envelope that throws AFTER touching the secret (the exact
// "extension can throw with the token" case) must NOT leak into the ephemeral modal error.
test('modal submit: a throwing KMS envelope never leaks the secret to the user', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  let acknowledged = false;
  const provider = defineProvider({
    id: 'customdb', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false,
    inject: (h, s) => h.set('x-api-key', s),
  });
  class KmsWrapError extends Error {}
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [provider],
    baseUrl: 'http://127.0.0.1:1',
    db,
    // wrapDataKey runs inside vault.upsert, after the raw secret is in hand — a realistic leak vector.
    envelope: {
      wrapDataKey: async () => {
        assert.equal(acknowledged, true, 'Slack must be acknowledged before KMS work starts');
        throw new KmsWrapError(`kms failed for ${SECRET}`);
      },
      unwrapDataKey: async (b) => b,
    },
  });
  let viewHandler: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: (id: string, h: any) => { if (id === USER_KEY_CALLBACK) viewHandler = h; },
    action: () => undefined,
  });

  let ackValue: any = 'unset';
  const dms: string[] = [];
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(
    { enterpriseId: null, teamId: 'T1', userId: 'U1' },
    'customdb',
  );
  assert.ok(requestId);
  await viewHandler({
    ack: async (value?: any) => { acknowledged = true; ackValue = value; },
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      private_metadata: JSON.stringify({ channel: '', provider: 'customdb', requestId }),
      state: { values: { raw: { v: { value: 'my-real-key' } }, ref: { v: { value: '' } } } },
    },
    client: { chat: { postMessage: async ({ text }: any) => { dms.push(text); return {}; } } },
  });

  assert.equal(ackValue.response_action, 'update');
  assert.match(JSON.stringify(ackValue.view), /If no result appears here/);
  assert.equal(dms.length, 1);
  const shown = JSON.stringify(dms);
  assert.ok(!shown.includes('ghp_abc'), 'secret must not reach the modal error');
  assert.match(dms[0], /could not confirm whether your \*customdb\* credential was saved/i);
  assert.match(dms[0], /check current connection status/i);
  assert.doesNotMatch(dms[0], /Could not save|try again|Something went wrong/);
  assert.doesNotMatch(dms[0], /KmsWrapError/);
});

test('modal submit reports a post-commit throw as unknown outcome, never definite save failure', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let submit: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: (id: string, handler: any) => { if (id === USER_KEY_CALLBACK) submit = handler; },
    action: () => undefined,
  });
  const realUpsert = vouchr.vault.upsertUser.bind(vouchr.vault);
  vouchr.vault.upsertUser = (async (...args: Parameters<typeof realUpsert>) => {
    const result = await realUpsert(...args);
    if (result === 'stored') throw new Error('commit acknowledgement was lost');
    return result;
  }) as typeof vouchr.vault.upsertUser;
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(
    { enterpriseId: null, teamId: 'T1', userId: 'U1' },
    'acme',
  );
  assert.ok(requestId);
  const dms: string[] = [];
  await submit({
    ack: async () => undefined,
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      private_metadata: JSON.stringify({ channel: '', provider: 'acme', requestId }),
      state: { values: { raw: { v: { value: 'synthetic-key' } }, ref: { v: { value: '' } } } },
    },
    client: { chat: { postMessage: async ({ text }: any) => { dms.push(text); } } },
  });

  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM connection`)).n, 1);
  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`)).n, 1);
  assert.equal(dms.length, 1);
  assert.match(dms[0], /could not confirm whether your \*acme\* credential was saved/i);
  assert.match(dms[0], /check current connection status/i);
  assert.doesNotMatch(dms[0], /Could not save|try again/);
});

test('raw-only credential modal targets generic validation errors at its rendered raw block', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const provider = defineProvider({
    id: 'customdb', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false,
  });
  const vouchr = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t),
  });
  let submit: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: (id: string, h: any) => { if (id === USER_KEY_CALLBACK) submit = h; },
    action: () => undefined,
  });

  for (const entry of [
    { body: { team: { id: 'T1' }, user: { id: 'U1' } }, metadata: '{' },
    { body: {}, metadata: JSON.stringify({ provider: 'customdb' }) },
  ]) {
    let acked: any = null;
    await submit({
      ack: async (value: any) => { acked = value; },
      body: entry.body,
      view: {
        private_metadata: entry.metadata,
        state: { values: { raw: { v: { value: 'synthetic-key' } } } },
      },
      client: {},
    });
    assert.equal(acked.response_action, 'errors');
    assert.equal(typeof acked.errors.raw, 'string');
    assert.equal(acked.errors.ref, undefined);
  }
});

test('stale key-setup action returns fixed private recovery instead of disappearing', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const provider = defineProvider({
    id: 'customdb', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false,
  });
  const vouchr = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t),
  });
  let setup: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, h: any) => { if (id === SETUP_KEY_ACTION) setup = h; },
  });
  let acked = false;
  const dms: string[] = [];
  await setup({
    ack: async () => { acked = true; },
    body: {
      team: { id: 'T1' }, user: { id: 'U1' }, trigger_id: 'old-trigger',
      actions: [{ value: 'removed-provider' }],
    },
    client: {
      views: { open: async () => { throw new Error('must not open'); } },
      chat: { postMessage: async ({ text }: any) => { dms.push(text); } },
    },
  });
  assert.equal(acked, true);
  assert.deepEqual(dms, ['This credential setup button is no longer valid. Ask the agent to request setup again.']);
});

test('key-setup open rejection reports unknown Slack acceptance, not definite failure', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let setup: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, handler: any) => { if (id === SETUP_KEY_ACTION) setup = handler; },
  });
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(
    { enterpriseId: null, teamId: 'T1', userId: 'U1' },
    'acme',
  );
  assert.ok(requestId);
  let acked = false;
  const dms: string[] = [];
  await setup({
    ack: async () => { acked = true; },
    body: {
      team: { id: 'T1' }, user: { id: 'U1' }, trigger_id: 'fresh-trigger',
      actions: [{ value: requestId }],
    },
    client: {
      views: { open: async () => { throw new Error('timeout after send'); } },
      chat: { postMessage: async ({ text }: any) => { dms.push(text); } },
    },
  });
  assert.equal(acked, true);
  assert.equal(dms.length, 1);
  assert.match(dms[0], /could not confirm whether credential setup opened/i);
  assert.match(dms[0], /If a setup window appeared/);
  assert.doesNotMatch(dms[0], /could not open credential setup/i);
});

test('a setup prompt issued before offboarding cannot open a modal afterward', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let setup: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, handler: any) => { if (id === SETUP_KEY_ACTION) setup = handler; },
  });
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(identity, 'acme');
  assert.ok(requestId);
  await vouchr.offboard(identity);

  const opened: any[] = [];
  const updated: any[] = [];
  const dms: string[] = [];
  await setup({
    ack: async () => undefined,
    body: {
      team: { id: 'T1' }, user: { id: 'U1' }, trigger_id: 'late-click',
      actions: [{ value: requestId }],
    },
    client: {
      views: {
        open: async (input: any) => { opened.push(input); return { view: { id: 'V_LOADING' } }; },
        update: async (input: any) => { updated.push(input); },
      },
      chat: { postMessage: async ({ text }: any) => { dms.push(text); } },
    },
  });

  assert.equal(opened.length, 1, 'the expiring trigger is consumed before stale-state reads');
  assert.doesNotMatch(JSON.stringify(opened[0]), /acme|vouchr_user_key|private_metadata/);
  assert.equal(updated.length, 1);
  assert.match(JSON.stringify(updated[0]), /Setup unavailable/);
  assert.doesNotMatch(JSON.stringify(updated[0]), /vouchr_user_key|private_metadata/);
  assert.deepEqual(dms, []);
  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM user_provisioning_request`)).n, 0);
});

test('key setup consumes the trigger before a slow provisioning lookup, then hydrates the same modal', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let setup: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, handler: any) => { if (id === SETUP_KEY_ACTION) setup = handler; },
  });
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(identity, 'acme');
  assert.ok(requestId);

  const realGet = db.get.bind(db);
  let lookupStarted!: () => void;
  let releaseLookup!: () => void;
  const lookup = new Promise<void>((resolve) => { lookupStarted = resolve; });
  const release = new Promise<void>((resolve) => { releaseLookup = resolve; });
  let held = false;
  db.get = (async (sql: string, params?: any[]) => {
    if (!held && sql.includes('FROM user_provisioning_request')) {
      held = true;
      lookupStarted();
      await release;
    }
    return realGet(sql, params);
  }) as typeof db.get;

  const events: string[] = [];
  const handling = setup({
    ack: async () => { events.push('ack'); },
    body: {
      team: { id: identity.teamId }, user: { id: identity.userId }, trigger_id: 'fresh-trigger',
      actions: [{ value: requestId }],
    },
    client: {
      views: {
        open: async (input: any) => {
          events.push('open');
          assert.doesNotMatch(JSON.stringify(input.view), /acme|vouchr_user_key|private_metadata/);
          assert.match(JSON.stringify(input.view), /close this window.*ask the agent/i);
          return { view: { id: 'V_LOADING' } };
        },
        update: async (input: any) => {
          events.push('update');
          assert.equal(input.view_id, 'V_LOADING');
          assert.equal(JSON.parse(input.view.private_metadata).requestId, requestId);
        },
      },
      chat: { postMessage: async () => undefined },
    },
  });
  await lookup;
  assert.deepEqual(events, ['ack', 'open']);
  releaseLookup();
  await handling;
  assert.deepEqual(events, ['ack', 'open', 'update']);
});

test('key setup reports transient lookup failure as unconfirmed rather than stale', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let setup: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, handler: any) => { if (id === SETUP_KEY_ACTION) setup = handler; },
  });
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(identity, 'acme');
  assert.ok(requestId);
  const realGet = db.get.bind(db);
  db.get = (async (sql: string, params?: any[]) => {
    if (sql.includes('FROM user_provisioning_request')) throw new Error('database unavailable');
    return realGet(sql, params);
  }) as typeof db.get;

  const updates: any[] = [];
  await setup({
    ack: async () => undefined,
    body: {
      team: { id: identity.teamId }, user: { id: identity.userId }, trigger_id: 'fresh-trigger',
      actions: [{ value: requestId }],
    },
    client: {
      views: {
        open: async () => ({ view: { id: 'V_LOADING' } }),
        update: async ({ view }: any) => { updates.push(view); },
      },
      chat: { postMessage: async () => undefined },
    },
  });

  assert.match(JSON.stringify(updates), /Setup not confirmed/);
  assert.match(JSON.stringify(updates), /could not confirm whether credential setup is available/i);
  assert.doesNotMatch(JSON.stringify(updates), /no longer valid/);
});

test('key setup hydration failure keeps crash-safe modal guidance and sends an unconfirmed receipt', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let setup: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, handler: any) => { if (id === SETUP_KEY_ACTION) setup = handler; },
  });
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(identity, 'acme');
  assert.ok(requestId);

  let loading: any;
  const dms: string[] = [];
  await setup({
    ack: async () => undefined,
    body: {
      team: { id: identity.teamId }, user: { id: identity.userId }, trigger_id: 'fresh-trigger',
      actions: [{ value: requestId }],
    },
    client: {
      views: {
        open: async ({ view }: any) => { loading = view; return { view: { id: 'V_LOADING' } }; },
        update: async () => { throw new Error('Slack unavailable'); },
      },
      chat: { postMessage: async ({ text }: any) => { dms.push(text); } },
    },
  });

  assert.match(JSON.stringify(loading), /close this window.*ask the agent/i);
  assert.match(dms.join('\n'), /could not confirm whether credential setup is available/i);
  assert.doesNotMatch(dms.join('\n'), /no longer valid/);
});

test('user credential modal consumes one opaque request and duplicate submit cannot write or audit twice', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let setup: any;
  let submit: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: (id: string, handler: any) => { if (id === USER_KEY_CALLBACK) submit = handler; },
    action: (id: string, handler: any) => { if (id === SETUP_KEY_ACTION) setup = handler; },
  });

  const order: string[] = [];
  let hydrated: any;
  const receipts: any[] = [];
  const client = {
    views: {
      open: async () => { order.push('open'); return { view: { id: 'V_LOADING' } }; },
      update: async ({ view }: any) => {
        if (typeof view.private_metadata === 'string') hydrated = view;
        else receipts.push(view);
        return {};
      },
    },
    chat: { postMessage: async () => ({}) },
  };
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(
    { enterpriseId: null, teamId: 'T1', userId: 'U1' },
    'acme',
  );
  assert.ok(requestId);
  await setup({
    ack: async () => { order.push('ack'); },
    body: {
      team: { id: 'T1' }, user: { id: 'U1' }, trigger_id: 'fresh-trigger',
      actions: [{ value: requestId }],
    },
    client,
  });
  assert.deepEqual(order, ['ack', 'open'], 'the setup click is acknowledged before request lookup/open');
  const metadata = JSON.parse(hydrated.private_metadata);
  const privateMetadata = hydrated.private_metadata;
  assert.match(metadata.requestId, /^[0-9a-f-]{36}$/i);
  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM user_provisioning_request`)).n, 1);

  const submission = () => submit({
    ack: async () => undefined,
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      id: 'V1',
      private_metadata: privateMetadata,
      state: { values: { raw: { v: { value: 'synthetic-key' } }, ref: { v: { value: '' } } } },
    },
    client,
  });
  await submission();
  await submission();

  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM connection`)).n, 1);
  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`)).n, 1);
  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM user_provisioning_request`)).n, 0);
  assert.match(JSON.stringify(receipts), /Credential saved/);
  assert.match(JSON.stringify(receipts), /Review current status/);
  assert.match(JSON.stringify(receipts), /may already be saved/);
  assert.doesNotMatch(JSON.stringify(receipts), /Save not confirmed|Could not save/);
});

test('pre-offboard user credential modal intent is stale and creates no credential or config audit', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let setup: any;
  let submit: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: (id: string, handler: any) => { if (id === USER_KEY_CALLBACK) submit = handler; },
    action: (id: string, handler: any) => { if (id === SETUP_KEY_ACTION) setup = handler; },
  });
  let hydrated: any;
  const outcomes: any[] = [];
  const client = {
    views: {
      open: async () => ({ view: { id: 'V_LOADING' } }),
      update: async ({ view }: any) => { hydrated ??= view; outcomes.push(view); },
    },
    chat: { postMessage: async () => ({}) },
  };
  const requestId = await new UserProvisioningRequests(db, vouchr.vault).issue(
    { enterpriseId: null, teamId: 'T1', userId: 'U1' },
    'acme',
  );
  assert.ok(requestId);
  await setup({
    ack: async () => undefined,
    body: {
      team: { id: 'T1' }, user: { id: 'U1' }, trigger_id: 'fresh-trigger',
      actions: [{ value: requestId }],
    },
    client,
  });
  await vouchr.offboard({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  await submit({
    ack: async () => undefined,
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      id: 'V1',
      private_metadata: hydrated.private_metadata,
      state: { values: { raw: { v: { value: 'synthetic-key' } }, ref: { v: { value: '' } } } },
    },
    client,
  });

  assert.match(JSON.stringify(outcomes), /Review current status/);
  assert.match(JSON.stringify(outcomes), /setup request is no longer active/i);
  assert.doesNotMatch(JSON.stringify(outcomes), /Credential saved|Could not save/);
  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM connection`)).n, 0);
  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='config'`)).n, 0);
  assert.equal((await db.get<any>(`SELECT COUNT(*)::int AS n FROM user_provisioning_request`)).n, 0);
});

test('modal reference submits share the core validator and reject whitespace before state or audit', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const provider = acme();
  const reference = ' arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/modal';
  const vouchr = await createVouchr({
    providers: [provider], baseUrl: 'http://127.0.0.1:1', db,
    resolvers: { 'aws-sm': async () => SECRET },
  });
  const views: Record<string, any> = {};
  vouchr.registerCommands({
    command: () => undefined,
    view: (id: string, handler: any) => { views[id] = handler; },
    action: () => undefined,
  });
  const outcomes: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: { update: async ({ view }: any) => { outcomes.push(view); } },
    chat: { postMessage: async () => ({}) },
  };

  let userAck: any = null;
  await views[USER_KEY_CALLBACK]({
    ack: async (value: any) => { userAck = value; },
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      private_metadata: JSON.stringify({ provider: 'acme' }),
      state: { values: { raw: { v: { value: '' } }, ref: { v: { value: reference } } } },
    },
    client,
  });
  assert.equal(userAck.response_action, 'errors');
  assert.equal(userAck.errors.ref, 'Invalid secret reference. Use a bounded supported external-reference form.');
  assert.ok(!JSON.stringify(userAck).includes(reference));

  const requestId = await issueChannelRequest(db, vouchr);
  let channelAck: any = null;
  await views[CONFIGURE_CALLBACK]({
    ack: async (value: any) => { channelAck = value; },
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      id: 'V_CHANNEL',
      private_metadata: JSON.stringify({ requestId }),
      state: { values: { raw: { v: { value: '' } }, ref: { v: { value: reference } } } },
    },
    client,
  });
  assert.equal(channelAck.response_action, 'update');
  assert.match(
    JSON.stringify(outcomes),
    /Invalid secret reference\. Use a bounded supported external-reference form\./,
  );
  assert.ok(!JSON.stringify(outcomes).includes(reference));

  assert.equal((await db.get<any>('SELECT COUNT(*) n FROM connection')).n, 0);
  assert.equal((await db.get<any>('SELECT COUNT(*) n FROM channel_config')).n, 0);
  assert.equal((await db.get<any>('SELECT COUNT(*) n FROM audit')).n, 0);
});

test('channel modal received before break-glass cannot save after a stalled acknowledgement', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  let submit: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: (id: string, handler: any) => { if (id === CONFIGURE_CALLBACK) submit = handler; },
    action: () => undefined,
  });

  let ackStarted!: () => void;
  let releaseAck!: () => void;
  const atAck = new Promise<void>((resolve) => { ackStarted = resolve; });
  const resumeAck = new Promise<void>((resolve) => { releaseAck = resolve; });
  const outcomes: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: { update: async ({ view }: any) => { outcomes.push(view); } },
    chat: { postMessage: async () => ({}) },
  };
  const requestId = await issueChannelRequest(db, vouchr);
  const handling = submit({
    ack: async () => {
      ackStarted();
      await resumeAck;
    },
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      id: 'V1',
      private_metadata: JSON.stringify({ requestId }),
      state: { values: { raw: { v: { value: 'synthetic-key' } }, ref: { v: { value: '' } } } },
    },
    client,
  });
  await atAck;
  try {
    await purgePendingForProvider(
      db,
      { provider: 'acme', teamId: 'T1', channel: 'C1' },
      { providerRegistered: true },
    );
  } finally {
    releaseAck();
  }
  await handling;

  assert.match(JSON.stringify(outcomes), /Review current status/);
  assert.match(JSON.stringify(outcomes), /setup request is no longer active/i);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM connection')).n, 0);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_config')).n, 0);
  assert.equal((await db.get<any>("SELECT COUNT(*)::int AS n FROM audit WHERE action='config'")).n, 0);
});

test('channel modal opened before break-glass cannot recreate authority afterward', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  const surface = channelSetupSurface(vouchr);
  let opened: any;
  let hydrated: any;
  const updates: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: {
      open: async (value: any) => {
        opened = value;
        return { view: { id: 'V_LOADING' } };
      },
      update: async (value: any) => {
        updates.push(value.view);
        if (value.view?.callback_id === CONFIGURE_CALLBACK) hydrated = value.view;
      },
    },
    chat: { postMessage: async () => ({}) },
  };

  await surface.open(client);
  assert.equal(opened.view.callback_id, undefined);
  assert.equal(opened.view.private_metadata, undefined);
  assert.deepEqual(Object.keys(JSON.parse(hydrated.private_metadata)), ['requestId']);

  await purgePendingForProvider(
    db,
    { provider: 'acme', teamId: 'T1', channel: 'C1' },
    { providerRegistered: true },
  );
  let acked: any;
  await surface.submit(client, hydrated.private_metadata, async (value) => { acked = value; });

  assert.equal(acked.response_action, 'update');
  assert.match(JSON.stringify(updates), /Review current status/);
  assert.match(JSON.stringify(updates), /setup request is no longer active/i);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM connection')).n, 0);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_config')).n, 0);
  assert.equal((await db.get<any>("SELECT COUNT(*)::int AS n FROM audit WHERE action='config'")).n, 0);
});

test('channel credential modal consumes one request and a duplicate submit cannot rotate or audit twice', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  const surface = channelSetupSurface(vouchr);
  let hydrated: any;
  const receipts: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: {
      open: async () => ({ view: { id: 'V_LOADING' } }),
      update: async ({ view }: any) => {
        receipts.push(view);
        if (view?.callback_id === CONFIGURE_CALLBACK) hydrated = view;
      },
    },
    chat: { postMessage: async () => ({}) },
  };
  await surface.open(client);
  const metadata = hydrated.private_metadata;

  await surface.submit(client, metadata, async () => undefined);
  const first = await db.get<any>(
    `SELECT id FROM connection WHERE team_id='T1' AND owner_kind='channel'
       AND owner_id='C1' AND provider='acme'`,
  );
  assert.ok(first?.id);
  await surface.submit(client, metadata, async () => undefined);
  const second = await db.get<any>(
    `SELECT id FROM connection WHERE team_id='T1' AND owner_kind='channel'
       AND owner_id='C1' AND provider='acme'`,
  );

  assert.equal(second?.id, first.id);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM connection')).n, 1);
  assert.equal((await db.get<any>("SELECT COUNT(*)::int AS n FROM audit WHERE action='config'")).n, 1);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n, 0);
  assert.match(JSON.stringify(receipts), /Credential saved/);
  assert.match(JSON.stringify(receipts), /Review current status/);
  assert.doesNotMatch(JSON.stringify(receipts), /Save not confirmed/);
});

test('channel setup open rejection performs no gates or ticket write and reports unknown acceptance', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const base = await openTestDb(t);
  const counted = countingDb(base);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db: counted.db,
  });
  const surface = channelSetupSurface(vouchr);
  let userReads = 0;
  let channelReads = 0;
  const dms: string[] = [];
  const client = {
    users: { info: async () => { userReads++; return { user: { is_admin: true } }; } },
    conversations: { info: async () => { channelReads++; return { channel: { id: 'C1' } }; } },
    views: { open: async () => { throw new Error('accepted_then_disconnected'); } },
    chat: { postMessage: async ({ text }: any) => { dms.push(text); return {}; } },
  };
  counted.reset();
  await surface.open(client);

  assert.deepEqual(counted.counts, { get: 0, all: 0 });
  assert.equal(userReads, 0);
  assert.equal(channelReads, 0);
  assert.match(dms.join('\n'), /could not confirm whether channel credential setup opened/i);
  assert.doesNotMatch(dms.join('\n'), /couldn't open|did not open/i);
  assert.equal((await base.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n, 0);
  assert.equal((await base.get<any>('SELECT COUNT(*)::int AS n FROM audit')).n, 0);
});

test('a channel mutation while the loading view opens fences the older setup receipt', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  const surface = channelSetupSurface(vouchr);
  let openStarted!: () => void;
  let releaseOpen!: () => void;
  const atOpen = new Promise<void>((resolve) => { openStarted = resolve; });
  const resumeOpen = new Promise<void>((resolve) => { releaseOpen = resolve; });
  let hydrated = false;
  const updates: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: {
      open: async () => {
        openStarted();
        await resumeOpen;
        return { view: { id: 'V_LOADING' } };
      },
      update: async ({ view }: any) => {
        updates.push(view);
        if (view?.callback_id === CONFIGURE_CALLBACK) hydrated = true;
      },
    },
    chat: { postMessage: async () => ({}) },
  };

  const opening = surface.open(client);
  await atOpen;
  await vouchr.vault.upsert(channelOwner('T1', 'C1'), 'acme', {
    accessToken: 'NEWER_DURING_OPEN',
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: null,
  });
  releaseOpen();
  await opening;

  assert.equal(hydrated, false);
  assert.match(JSON.stringify(updates), /Review current status/);
  assert.equal((await vouchr.vault.get(channelOwner('T1', 'C1'), 'acme'))?.accessToken, 'NEWER_DURING_OPEN');
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n, 0);
});

test('channel setup opens its loading view before slow gates and preserves the original receipt fence', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  const surface = channelSetupSurface(vouchr);
  let gateStarted!: () => void;
  let releaseGate!: () => void;
  const atGate = new Promise<void>((resolve) => { gateStarted = resolve; });
  const resumeGate = new Promise<void>((resolve) => { releaseGate = resolve; });
  const order: string[] = [];
  let hydrated = false;
  const updates: any[] = [];
  const client = {
    users: {
      info: async () => {
        order.push('admin');
        gateStarted();
        await resumeGate;
        return { user: { is_admin: true } };
      },
    },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: {
      open: async () => {
        order.push('open');
        return { view: { id: 'V_LOADING' } };
      },
      update: async ({ view }: any) => {
        updates.push(view);
        if (view?.callback_id === CONFIGURE_CALLBACK) hydrated = true;
      },
    },
    chat: { postMessage: async () => ({}) },
  };
  const opening = surface.open(client);
  await atGate;
  assert.deepEqual(order, ['open', 'admin']);
  await purgePendingForProvider(
    db,
    { provider: 'acme', teamId: 'T1', channel: 'C1' },
    { providerRegistered: true },
  );
  releaseGate();
  await opening;

  assert.equal(hydrated, false);
  assert.match(JSON.stringify(updates), /Review current status/);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n, 0);
});

test('channel setup reserves before slow admin checks so a sibling write invalidates it', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  const surface = channelSetupSurface(vouchr);
  let gateStarted!: () => void;
  let releaseGate!: () => void;
  const atGate = new Promise<void>((resolve) => { gateStarted = resolve; });
  const resumeGate = new Promise<void>((resolve) => { releaseGate = resolve; });
  let hydrated = false;
  const updates: any[] = [];
  const client = {
    users: {
      info: async () => {
        gateStarted();
        await resumeGate;
        return { user: { is_admin: true } };
      },
    },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: {
      open: async () => ({ view: { id: 'V_LOADING' } }),
      update: async ({ view }: any) => {
        updates.push(view);
        if (view?.callback_id === CONFIGURE_CALLBACK) hydrated = true;
      },
    },
    chat: { postMessage: async () => ({}) },
  };

  const opening = surface.open(client);
  await atGate;
  assert.equal(
    (await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n,
    1,
  );
  await vouchr.vault.upsert(channelOwner('T1', 'C1'), 'acme', {
    accessToken: 'NEWER_CHANNEL_KEY',
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: null,
  });
  releaseGate();
  await opening;

  assert.equal(hydrated, false);
  assert.match(JSON.stringify(updates), /Review current status/);
  assert.equal((await vouchr.vault.get(channelOwner('T1', 'C1'), 'acme'))?.accessToken, 'NEWER_CHANNEL_KEY');
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n, 0);
  assert.equal((await db.get<any>("SELECT COUNT(*)::int AS n FROM audit WHERE action='config'")).n, 0);
});

test('a refused concurrent opener cannot invalidate an already-hydrated setup form', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  const surface = channelSetupSurface(vouchr);
  let firstForm: any;
  const firstClient = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: {
      open: async () => ({ view: { id: 'V_FIRST' } }),
      update: async ({ view }: any) => {
        if (view?.callback_id === CONFIGURE_CALLBACK) firstForm = view;
      },
    },
    chat: { postMessage: async () => ({}) },
  };
  await surface.open(firstClient);
  assert.ok(firstForm);

  const secondOutcomes: any[] = [];
  const secondClient = {
    users: { info: async () => ({ user: { is_admin: false } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: {
      open: async () => ({ view: { id: 'V_SECOND' } }),
      update: async ({ view }: any) => { secondOutcomes.push(view); },
    },
    chat: { postMessage: async () => ({}) },
  };
  await surface.open(secondClient);
  assert.match(JSON.stringify(secondOutcomes), /Setup unavailable/);
  assert.equal(
    (await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n,
    1,
  );

  await surface.submit(firstClient, firstForm.private_metadata, async () => undefined);
  assert.equal((await vouchr.vault.get(channelOwner('T1', 'C1'), 'acme'))?.accessToken, 'synthetic-channel-key');
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n, 0);
  assert.equal((await db.get<any>("SELECT COUNT(*)::int AS n FROM audit WHERE action='config'")).n, 1);
  assert.equal((await db.get<any>("SELECT COUNT(*)::int AS n FROM audit WHERE action='denied'")).n, 1);
});

test('channel setup request, credential, and config audit roll back together on audit failure', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const db = await openTestDb(t);
  const vouchr = await createVouchr({
    providers: [acme()], baseUrl: 'http://127.0.0.1:1', db,
  });
  const surface = channelSetupSurface(vouchr);
  let hydrated: any;
  const outcomes: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    views: {
      open: async () => ({ view: { id: 'V_LOADING' } }),
      update: async ({ view }: any) => {
        outcomes.push(view);
        if (view?.callback_id === CONFIGURE_CALLBACK) hydrated = view;
      },
    },
    chat: { postMessage: async () => ({}) },
  };
  await surface.open(client);
  const metadata = hydrated.private_metadata;
  const originalRecord = vouchr.audit.record.bind(vouchr.audit);
  let failConfig = true;
  (vouchr.audit as any).record = async (action: string, ...args: any[]) => {
    if (action === 'config' && failConfig) {
      failConfig = false;
      throw new Error('audit unavailable');
    }
    return (originalRecord as any)(action, ...args);
  };

  await surface.submit(client, metadata, async () => undefined);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM connection')).n, 0);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_config')).n, 0);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n, 1);

  (vouchr.audit as any).record = originalRecord;
  await surface.submit(client, metadata, async () => undefined);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM connection')).n, 1);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_config')).n, 1);
  assert.equal((await db.get<any>("SELECT COUNT(*)::int AS n FROM audit WHERE action='config'")).n, 1);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM channel_provisioning_request')).n, 0);
  assert.match(JSON.stringify(outcomes), /Save not confirmed/);
  assert.match(JSON.stringify(outcomes), /Credential saved/);
});

// Regression (#97 issue #132): the deliberate admin-denial for `/vouchr mode` is thrown as a plain
// refusal, NOT one of the 4 whitelisted classes. It must still reach the user verbatim — before the
// UserFacingError marker it collapsed to "Something went wrong (Error)...".
test('command: a non-admin /vouchr mode gets the real admin-denied message, not the generic mask', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const vouchr = await createVouchr({ providers: [acme()], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t) });
  let cmd: any;
  vouchr.registerCommands({
    command: (_n: string, h: any) => { cmd = h; },
    view: () => undefined,
    action: () => undefined,
  });
  const nonAdmin = { users: { info: async () => ({ user: { is_admin: false, is_owner: false } }) } };
  let said = '';
  await cmd({
    command: { team_id: 'T1', user_id: 'U1', channel_id: 'C1', text: 'mode acme per-user', trigger_id: 'x' },
    ack: async () => {}, respond: async (m: any) => { said = m; }, client: nonAdmin,
  });
  assert.equal(said, 'Only a workspace admin can configure channel credentials.');
});

// Regression: a mode-locked channel rejecting a STATIC key after Slack has acknowledged the modal.
// The safe refusal moves to the private recovery DM and must survive masking.
test('modal submit: a mode-locked channel keeps the real "static keys are not allowed" message', async (t) => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const vouchr = await createVouchr({ providers: [acme()], baseUrl: 'http://127.0.0.1:1', db: await openTestDb(t) });
  let cmd: any, configureView: any;
  vouchr.registerCommands({
    command: (_n: string, h: any) => { cmd = h; },
    view: (id: string, h: any) => { if (id === CONFIGURE_CALLBACK) configureView = h; },
    action: () => undefined,
  });
  // Admin + a normal (eligible) channel: both mutations pass the admin gate + eligibility check.
  const dms: string[] = [];
  const admin = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: {} }) },
    chat: { postMessage: async ({ text }: any) => { dms.push(text); return {}; } },
  };
  // 1) Admin locks the channel to per-user.
  await cmd({
    command: { team_id: 'T1', user_id: 'U1', channel_id: 'C1', text: 'mode acme per-user', trigger_id: 'x' },
    ack: async () => {}, respond: async () => {}, client: admin,
  });
  const requestId = await issueChannelRequest(vouchr.db, vouchr);
  // 2) Admin then tries to save a STATIC key → refused by the mode lock; message must reach the modal.
  let acked = false;
  await configureView({
    ack: async () => { acked = true; },
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      private_metadata: JSON.stringify({ requestId }),
      state: { values: { raw: { v: { value: 'my-real-key' } }, ref: { v: { value: '' } } } },
    },
    client: admin,
  });
  assert.equal(acked, true);
  assert.equal(dms.length, 1);
  assert.match(dms[0], /Channel is set to per-user for "acme"; static keys are not allowed\./);
});

// Regression: the ConsentRequiredError path is unaffected — its user-facing message is preserved
// (it is one of Vouchr's own classes), so the connect prompt still reads normally, not the generic form.
test('regression: ConsentRequiredError still shows its own connect-prompt message', () => {
  const e = new ConsentRequiredError('github', 'posted');
  assert.equal(safeUserMessage(e), 'Consent is required. Complete the private Connect prompt, then retry.');
  assert.match(safeUserMessage(e), /Connect prompt/);
});
