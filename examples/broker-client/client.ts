/**
 * Reference integration for the headless broker, split across the TWO roles a production deployment
 * keeps in SEPARATE processes:
 *
 *   1. the TRUSTED MINTER — your Slack-facing service. It verified the Slack event signature, holds
 *      VOUCHR_IDENTITY_SECRET, and mints one short-lived assertion per request (`mintIdentity`).
 *   2. the AGENT WORKER — the process running model/tool code. It receives only that assertion and
 *      calls the broker (`fetchThroughBroker` below). It never sees the signing key, and never sees
 *      the credential: the broker injects it.
 *
 * !! The `main` block at the bottom runs BOTH roles in one process. That is LOCAL DEVELOPMENT ONLY.
 * The identity signing key is the broker's trust root: anything holding it can mint
 * `{ userId: <any human>, channel: <any channel> }` and use every credential the deployment serves. Minting
 * inside the agent runtime therefore collapses the trust boundary — one prompt injection that can
 * read the process environment owns the workspace. In production, keep the key in the minter and
 * pass only `identityToken` over the wire. See guides/THREAT-MODEL.md, "Headless broker: leaked
 * identity signing key".
 *
 * Run against a local broker. First provision T1/U1 through a Bolt control plane sharing this
 * database, or through the broker's validated `/v1/user/reference` route with a configured external
 * secret resolver. The control plane and broker must share the SAME database and master key:
 *
 *   export VOUCHR_MASTER_KEY=$(openssl rand -base64 32)
 *   export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
 *   export VOUCHR_IDENTITY_SECRET=$(openssl rand -base64 32)   # >= 32 bytes, not the master key
 *   export VOUCHR_DEPLOYMENT_ID=local-dev                       # binds assertions to this deployment
 *   export VOUCHR_BASE_URL=https://broker.example              # public origin; the connect/verify/callback routes mount here
 *   export VOUCHR_SLACK_CLIENT_ID=... VOUCHR_SLACK_CLIENT_SECRET=...   # the Slack app's OIDC credentials (#302)
 *
 *   # terminal A — after provisioning T1/U1, start the broker:
 *   VOUCHR_PROVIDERS='[{"id":"github","credential":"key","egressAllow":["api.github.com"]}]' npm run broker
 *
 *   # terminal B — call through the broker as that user:
 *   BROKER_URL=http://localhost:3000 node --import tsx examples/broker-client/client.ts
 *
 * See guides/DEPLOYMENT.md for the two supported provisioning paths.
 */
import {
  mintIdentity,
  loadIdentityConfig,
  type SlackConversationType,
} from '../../src'; // published package: from '@vouchr/core'

/** Minter-side input: the acting human, from a signature-verified Slack event. Never worker input. */
export interface Acting {
  teamId: string;
  userId: string;
  channel: string;
  /** Slack conversation type from a verified event or authenticated API lookup; never from the model/worker. */
  channelType: SlackConversationType;
  threadTs?: string;
}

export interface BrokerCall {
  provider: string;
  method: string;
  path: string;
  host?: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string;
}

/**
 * WORKER SIDE — no signing key here. POST one request through the broker with an `identityToken` the
 * trusted minter produced for exactly this call: assertions are single-use and short-lived, so ask
 * the minter again for every request and every retry rather than caching one. `brokerToken` is the
 * optional coarse perimeter bearer if your broker sets one. Returns the broker's JSON response.
 */
export async function fetchThroughBroker(
  brokerUrl: string,
  identityToken: string,
  call: BrokerCall,
  brokerToken?: string,
): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${brokerUrl}/v1/fetch`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(brokerToken ? { authorization: `Bearer ${brokerToken}` } : {}),
    },
    body: JSON.stringify({
      handle: { provider: call.provider, owner: 'user' }, // owner is the verified token, never this
      identityToken,
      method: call.method,
      path: call.path,
      host: call.host,
      query: call.query,
      headers: call.headers,
      body: call.body,
    }),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

if (require.main === module) {
  const brokerUrl = process.env.BROKER_URL ?? 'http://localhost:3000';

  // ---- TRUSTED MINTER SIDE — a SEPARATE service in production; in-process here is local dev only.
  // Build the SAME deployment-bound config the broker uses (#212): reads VOUCHR_IDENTITY_SECRET +
  // VOUCHR_DEPLOYMENT_ID from env, so the minted token's issuer/audience/kid match what the broker
  // expects. A mismatch (or a bare-secret token against a config-mode broker) is rejected.
  const identity = loadIdentityConfig(process.env);
  // In the real minter these come from a signature-verified Slack event or authenticated Slack API
  // lookup, never user input. Carry channel_type too: an MPIM uses a G… id, and the signed 'mpim'
  // value tells the broker it is a personal group DM rather than a governed private channel.
  const acting: Acting = { teamId: 'T1', userId: 'U1', channel: 'C1', channelType: 'channel' };
  const identityToken = mintIdentity(acting, identity); // fresh jti + short exp, one per call

  // ---- WORKER SIDE — receives the assertion over the wire; the signing key never crosses here.
  fetchThroughBroker(brokerUrl, identityToken, {
    provider: 'github',
    method: 'GET',
    path: '/user',
    host: 'api.github.com',
  })
    .then((r) => console.log(`broker responded ${r.status}:`, r.body))
    .catch((e) => console.error('broker call failed:', e.message));
}
