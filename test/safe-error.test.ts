import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  safeUserMessage,
  createVouchr,
  ConsentRequiredError,
  SessionApprovalRequiredError,
} from '../src/adapters/bolt';
import { EgressBlockedError, NoConnectionError } from '../src/core/injector';
import { defineProvider } from '../src/core/providers';
import { USER_KEY_CALLBACK } from '../src/adapters/blocks';

const SECRET = 'secret ghp_abc1234567890abcdef';

// Unit: an unexpected/foreign error is reduced to its CLASS NAME — the raw message (which may carry
// a leaked token) is never returned.
test('safeUserMessage: masks an unexpected error, keeps only the class name', () => {
  const msg = safeUserMessage(new Error(SECRET));
  assert.ok(!msg.includes('ghp_abc'), 'token must not survive');
  assert.match(msg, /Something went wrong \(Error\)\. Ask an admin to check the Vouchr logs\./);
});

// A custom-named error (e.g. thrown by a provider.inject / KMS extension) still masks the message but
// surfaces its class name for triage.
test('safeUserMessage: shows a custom error class name, not its secret message', () => {
  class ProviderInjectError extends Error {}
  const msg = safeUserMessage(new ProviderInjectError(SECRET));
  assert.ok(!msg.includes('ghp_abc'));
  assert.match(msg, /Something went wrong \(ProviderInjectError\)\./);
});

// Vouchr's OWN error classes are deliberately user-facing and secret-free → their message passes through.
test("safeUserMessage: Vouchr's own error classes keep their message", () => {
  for (const e of [
    new ConsentRequiredError('github'),
    new SessionApprovalRequiredError('github'),
    new EgressBlockedError('Egress blocked: host not allowed'),
    new NoConnectionError('No connection for github'),
  ]) {
    assert.equal(safeUserMessage(e), (e as Error).message);
  }
});

// Non-Error values don't crash and don't echo their content.
test('safeUserMessage: handles a non-Error throw', () => {
  const msg = safeUserMessage('ghp_rawstring');
  assert.ok(!msg.includes('ghp_rawstring'));
  assert.match(msg, /Something went wrong/);
});

// Integration: the modal-submit path. A KMS envelope that throws AFTER touching the secret (the exact
// "extension can throw with the token" case) must NOT leak into the ephemeral modal error.
test('modal submit: a throwing KMS envelope never leaks the secret to the user', async () => {
  process.env.VOUCHR_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
  const provider = defineProvider({
    id: 'customdb', credential: 'key', authorizeUrl: '', tokenUrl: '', scopesDefault: [],
    egressAllow: ['api.test'], refresh: 'none', pkce: false,
    inject: (h, s) => h.set('x-api-key', s),
  });
  class KmsWrapError extends Error {}
  const vouchr = await createVouchr({
    providers: [provider],
    baseUrl: 'http://127.0.0.1:1',
    dbPath: ':memory:',
    // wrapDataKey runs inside vault.upsert, after the raw secret is in hand — a realistic leak vector.
    envelope: {
      wrapDataKey: async () => { throw new KmsWrapError(`kms failed for ${SECRET}`); },
      unwrapDataKey: async (b) => b,
    },
  });
  let viewHandler: any;
  vouchr.registerCommands({
    command: () => undefined,
    view: (id: string, h: any) => { if (id === USER_KEY_CALLBACK) viewHandler = h; },
    action: () => undefined,
  });

  let acked: any = null;
  await viewHandler({
    ack: async (a: any) => { acked = a; },
    body: { team: { id: 'T1' }, user: { id: 'U1' } },
    view: {
      private_metadata: JSON.stringify({ channel: '', provider: 'customdb' }),
      state: { values: { raw: { v: { value: 'my-real-key' } }, ref: { v: { value: '' } } } },
    },
    client: { chat: { postMessage: async () => ({}) } },
  });

  const shown = JSON.stringify(acked);
  assert.ok(!shown.includes('ghp_abc'), 'secret must not reach the modal error');
  assert.match(acked.errors.raw, /Something went wrong \(KmsWrapError\)\./);
});

// Regression: the ConsentRequiredError path is unaffected — its user-facing message is preserved
// (it is one of Vouchr's own classes), so the connect prompt still reads normally, not the generic form.
test('regression: ConsentRequiredError still shows its own connect-prompt message', () => {
  const e = new ConsentRequiredError('github');
  assert.equal(safeUserMessage(e), e.message);
  assert.match(safeUserMessage(e), /Connect prompt was posted/);
});
