/**
 * Caller-side integration for the headless broker: mint a per-request identity token and call
 * /v1/fetch. This is the code that runs in YOUR agent/runtime — the thing that already knows which
 * human is acting. The broker verifies the token and injects the real credential; your agent never
 * sees it.
 *
 * Run against a local broker. First provision T1/U1 through a Bolt control plane sharing this
 * database, or through the broker's validated `/v1/user/reference` route with a configured external
 * secret resolver. The control plane and broker must share the SAME database and master key:
 *
 *   export VOUCHR_MASTER_KEY=$(openssl rand -base64 32)
 *   export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
 *   export VOUCHR_IDENTITY_SECRET=$(openssl rand -base64 32)   # >= 32 bytes, not the master key
 *   export VOUCHR_DEPLOYMENT_ID=local-dev                       # binds assertions to this deployment
 *
 *   # terminal A — after provisioning T1/U1, start the broker:
 *   VOUCHR_PROVIDERS='[{"id":"github","credential":"key","egressAllow":["api.github.com"]}]' npm run broker
 *
 *   # terminal B — call through the broker as that user:
 *   BROKER_URL=http://localhost:3000 node --import tsx examples/broker-client/client.ts
 *
 * See guides/DEPLOYMENT.md for the two supported provisioning paths.
 */
import { mintIdentity, loadIdentityConfig, type IdentityConfig } from '../../src'; // published package: from '@vouchr/core'

export interface Acting {
  teamId: string;
  userId: string;
  channel: string;
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
 * Mint a fresh token for `acting` and POST one request through the broker. `identity` is the
 * deployment-bound `IdentityConfig` built from `loadIdentityConfig(process.env)`, so the assertion is
 * bound to one issuer/audience and signed with the active key. Your trusted minter and every broker
 * replica must share the same verification key set. `brokerToken` is the optional coarse perimeter
 * bearer if your broker sets one. Returns the broker's JSON response.
 */
export async function fetchThroughBroker(
  brokerUrl: string,
  identity: IdentityConfig,
  acting: Acting,
  call: BrokerCall,
  brokerToken?: string,
): Promise<{ status: number; body: unknown }> {
  const identityToken = mintIdentity(acting, identity); // fresh jti + short exp, per call

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
  // Build the SAME deployment-bound config the broker uses (#212): reads VOUCHR_IDENTITY_SECRET +
  // VOUCHR_DEPLOYMENT_ID from env, so the minted token's issuer/audience/kid match what the broker
  // expects. A mismatch (or a bare-secret token against a config-mode broker) is rejected.
  const identity = loadIdentityConfig(process.env);
  // In a real agent these come from the event you already authenticated, not from user input.
  const acting: Acting = { teamId: 'T1', userId: 'U1', channel: 'C1' };

  fetchThroughBroker(brokerUrl, identity, acting, {
    provider: 'github',
    method: 'GET',
    path: '/user',
    host: 'api.github.com',
  })
    .then((r) => console.log(`broker responded ${r.status}:`, r.body))
    .catch((e) => console.error('broker call failed:', e.message));
}
