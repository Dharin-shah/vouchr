import { Consent, type ConsentRequest } from '../../src/core/consent';
import type { Db } from '../../src/core/db';

// #340: the Slack OIDC credentials every `createVouchr` / `createBroker` requires. `createVouchr`
// reads them from env (the production path the examples use); `createBroker` takes them as an
// option. `test/support/pg` imports this module, so every database-backed test file has the env
// pair set before its first construction. Tests that prove fail-closed boot delete the pair and
// restore it in `finally`.
export const TEST_SLACK_OIDC = { clientId: 'slack-app-cid', clientSecret: 'slack-app-csec' };
process.env.VOUCHR_SLACK_CLIENT_ID ??= TEST_SLACK_OIDC.clientId;
process.env.VOUCHR_SLACK_CLIENT_SECRET ??= TEST_SLACK_OIDC.clientSecret;

/** The two required `createBroker` options a test does not otherwise care about. Spread FIRST so an
 *  explicit value in the call wins. */
export const BROKER_REQUIRED = { baseUrl: 'https://broker.example', slackOidc: TEST_SLACK_OIDC };

/** Stamp a live consent as Slack-verified with the production method hop 2 calls on a matching
 *  id_token, so a test of post-hop callback behavior reaches the callback without driving the hop
 *  (test/browser-identity.test.ts covers the hop itself end to end). Throws if the state is not live. */
export async function verifyConsent(db: Db | Consent, state: string): Promise<void> {
  const consent = db instanceof Consent ? db : new Consent(db);
  if (!(await consent.markSlackVerified(state))) throw new Error('consent state is not live; nothing to stamp');
}

/** `consent.begin(...)` followed by {@link verifyConsent}: a minted prompt whose bearer already
 *  passed the Slack hop, the precondition of every post-hop callback test. */
export async function beginVerified(consent: Consent, ...args: Parameters<Consent['begin']>): Promise<ConsentRequest> {
  const pending = await consent.begin(...args);
  await verifyConsent(consent, pending.state);
  return pending;
}
