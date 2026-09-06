/**
 * The autonomous worker for guides/DEMO.md, scenario (j). No human asks and the worker has no
 * account: the job runs as the app's bot user, asks the channel over the broker's backchannel, a
 * member authorizes the write with their own `github` account, and the worker polls, then runs the
 * write once as that member.
 *
 * LOCAL DEVELOPMENT ONLY: minting next to the worker collapses the trust boundary. In production the
 * minter is a separate service (see examples/broker-client/client.ts) and it alone sets `worker`.
 *
 *   BROKER_URL=http://localhost:3001 DEMO_TEAM=T... DEMO_BOT_USER=U... DEMO_CHANNEL=C... \
 *   DEMO_REPO=owner/name node --import tsx examples/demo/worker.ts
 */
import { loadIdentityConfig, mintIdentity } from '../../src';

const env = (k: string): string => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} is required`);
  return v;
};
const broker = process.env.BROKER_URL ?? 'http://localhost:3001';
const identity = loadIdentityConfig(process.env);
// The same claims on every call: the grant is bound to them. `group` is Slack's type for a private
// channel. `worker: true` says no human drives this token; a channel member authorizes as themselves.
const claims = {
  teamId: env('DEMO_TEAM'),
  userId: env('DEMO_BOT_USER'),
  channel: env('DEMO_CHANNEL'),
  channelType: 'group' as const,
  channelEligible: true,
  worker: true,
};
const handle = { provider: 'github', owner: 'user' };
const title = process.env.DEMO_TITLE ?? 'TICKET-42: release checklist';
const action = { method: 'POST', path: `/repos/${env('DEMO_REPO')}/issues` };

async function post(route: string, body: object): Promise<{ status: number; json: any }> {
  const res = await fetch(`${broker}${route}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ handle, identityToken: mintIdentity(claims, identity), ...body }),
  });
  return { status: res.status, json: await res.json() };
}

(async () => {
  const created = await post('/v1/authorization', { ...action, reason: `${title}: open the release checklist issue`, link: 'https://tracker.example/TICKET-42' });
  console.log('authorization', created.status, created.json);
  let status = created.json.status;
  while (status === 'pending') {
    await new Promise((r) => setTimeout(r, 5000));
    const res = await fetch(`${broker}/v1/authorization/${created.json.authorizationId}`, {
      headers: { 'x-vouchr-identity': mintIdentity(claims, identity) },
    });
    status = (await res.json()).status;
    console.log('poll', status);
  }
  if (status !== 'approved') return;
  const done = await post('/v1/fetch', {
    ...action,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ title }),
  });
  const upstream = done.json.status === undefined ? done.json : { status: done.json.status, url: JSON.parse(done.json.body || '{}').html_url };
  console.log('fetch', done.status, upstream);
})();
