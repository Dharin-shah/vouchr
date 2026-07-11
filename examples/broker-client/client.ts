/**
 * Caller-side integration for the headless broker: mint a per-request identity token and call
 * /v1/fetch. This is the code that runs in YOUR agent/runtime — the thing that already knows which
 * human is acting. The broker verifies the token and injects the real credential; your agent never
 * sees it.
 *
 * Run against a local broker. The seed and the broker must share the SAME PostgreSQL database AND
 * master key (a random key per process wouldn't decrypt what the seed wrote):
 *
 *   export VOUCHR_MASTER_KEY=$(openssl rand -base64 32)
 *   export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
 *   export VOUCHR_IDENTITY_SECRET=dev-secret
 *
 *   # terminal A — seed a credential for user T1/U1, then start the broker:
 *   VOUCHR_SEED_ACCESS_TOKEN=ghp_xxx node --import tsx bin/broker-seed.ts key \
 *       --provider github --team T1 --user U1
 *   VOUCHR_PROVIDERS='[{"id":"github","credential":"key","egressAllow":["api.github.com"]}]' npm run broker
 *
 *   # terminal B — call through the broker as that user:
 *   BROKER_URL=http://localhost:3000 node --import tsx examples/broker-client/client.ts
 *
 * See `npm run seed` in guides/DEPLOYMENT.md for reference vs key modes.
 */
import { mintIdentity } from '../../src'; // published package: from '@vouchr/core'

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
 * Mint a fresh token for `acting` and POST one request through the broker. `secret` is the shared
 * HS256 identity secret (VOUCHR_IDENTITY_SECRET); `brokerToken` is the optional coarse perimeter
 * bearer if your broker sets one. Returns the broker's JSON response.
 */
export async function fetchThroughBroker(
  brokerUrl: string,
  secret: string,
  acting: Acting,
  call: BrokerCall,
  brokerToken?: string,
): Promise<{ status: number; body: unknown }> {
  const identityToken = mintIdentity(acting, secret); // fresh jti + short exp, per call

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
  const secret = process.env.VOUCHR_IDENTITY_SECRET ?? 'dev-secret';
  // In a real agent these come from the event you already authenticated, not from user input.
  const acting: Acting = { teamId: 'T1', userId: 'U1', channel: 'C1' };

  fetchThroughBroker(brokerUrl, secret, acting, {
    provider: 'github',
    method: 'GET',
    path: '/user',
    host: 'api.github.com',
  })
    .then((r) => console.log(`broker responded ${r.status}:`, r.body))
    .catch((e) => console.error('broker call failed:', e.message));
}
