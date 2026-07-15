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

// A key provider that brokers (non-service) — enough to exercise the /vouchr command + channel modal.
const acme = () => defineProvider({
  id: 'acme', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false,
  inject: (h: any, s: string) => h.set('x-api-key', s),
});

const SECRET = 'secret ghp_abc1234567890abcdef';

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
    safeUserMessage(new ConsentRequiredError('github')),
    'Consent is required. Complete the private Connect prompt, then retry.',
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
  const vouchr = await createVouchr({
    providers: [provider],
    baseUrl: 'http://127.0.0.1:1',
    db: await openTestDb(t),
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
  await viewHandler({
    ack: async (value?: any) => { acknowledged = true; ackValue = value; },
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      private_metadata: JSON.stringify({ channel: '', provider: 'customdb' }),
      state: { values: { raw: { v: { value: 'my-real-key' } }, ref: { v: { value: '' } } } },
    },
    client: { chat: { postMessage: async ({ text }: any) => { dms.push(text); return {}; } } },
  });

  assert.equal(ackValue.response_action, 'update');
  assert.match(JSON.stringify(ackValue.view), /If no result appears here/);
  assert.equal(dms.length, 1);
  const shown = JSON.stringify(dms);
  assert.ok(!shown.includes('ghp_abc'), 'secret must not reach the modal error');
  assert.match(dms[0], /Could not save your \*customdb\* credential/);
  assert.match(dms[0], /Something went wrong\. Ask an admin to check the Vouchr logs\./);
  assert.doesNotMatch(dms[0], /KmsWrapError/);
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
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: { info: async () => ({ channel: { id: 'C1', is_channel: true } }) },
    chat: { postMessage: async () => ({}) },
  };

  for (const [callback, channel] of [[CONFIGURE_CALLBACK, 'C1'], [USER_KEY_CALLBACK, '']] as const) {
    let acked: any = null;
    await views[callback]({
      ack: async (value: any) => { acked = value; },
      body: { team: { id: 'T1' }, user: { id: 'U1' } },
      view: {
        private_metadata: JSON.stringify({ channel, provider: 'acme' }),
        state: { values: { raw: { v: { value: '' } }, ref: { v: { value: reference } } } },
      },
      client,
    });
    assert.equal(acked.response_action, 'errors');
    assert.equal(acked.errors.ref, 'Invalid secret reference. Use a bounded supported external-reference form.');
    assert.ok(!JSON.stringify(acked).includes(reference));
  }

  assert.equal((await db.get<any>('SELECT COUNT(*) n FROM connection')).n, 0);
  assert.equal((await db.get<any>('SELECT COUNT(*) n FROM channel_config')).n, 0);
  assert.equal((await db.get<any>('SELECT COUNT(*) n FROM audit')).n, 0);
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
  // 2) Admin then tries to save a STATIC key → refused by the mode lock; message must reach the modal.
  let acked = false;
  await configureView({
    ack: async () => { acked = true; },
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      private_metadata: JSON.stringify({ channel: 'C1', provider: 'acme' }),
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
  const e = new ConsentRequiredError('github');
  assert.equal(safeUserMessage(e), 'Consent is required. Complete the private Connect prompt, then retry.');
  assert.match(safeUserMessage(e), /Connect prompt/);
});
