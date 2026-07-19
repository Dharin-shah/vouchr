// #194 — the two-process proof for the hybrid recovery bridge: a REAL packaged broker
// (bin/broker-server.ts, spawned as its own process, env-configured like production) and an
// in-process Bolt control plane (createVouchr) share ONE PostgreSQL schema. The "worker" is this
// test calling the broker over HTTP with deployment-bound single-use identity assertions; every
// broker denial is relayed to ConnectContext.recoverBrokerDenial from the verified Slack context,
// and every retry mints a FRESH assertion. Covers connect, session, and approval recovery
// end-to-end: deny → private prompt → human acts → retry succeeds → replay/single-use hold.
//
// Provider egress from the broker child is stubbed by test/support/broker-upstream-stub.mjs
// (`--import` preload) — the process-boundary analog of the suite's withFetch stub (TEST-3).
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { testDbUrl } from './support/pg';
import { openDb } from '../src/core/db';
import { ChannelConfig } from '../src/core/channelConfig';
import { loadIdentityConfig, mintIdentity, type MintIdentityInput } from '../src/adapters/http/identity';
import { ConnectContext, createVouchr } from '../src/adapters/bolt';
import { APPROVAL_APPROVE_ACTION, APPROVE_SESSION_ACTION, SETUP_KEY_ACTION } from '../src/adapters/blocks';

const IDENTITY_SECRET = 'bridge-e2e-identity-secret-at-least-32-bytes!!';
const DEPLOYMENT_ID = 'bridge-e2e-deployment';
const idConfig = () => loadIdentityConfig({
  VOUCHR_IDENTITY_SECRET: IDENTITY_SECRET,
  VOUCHR_DEPLOYMENT_ID: DEPLOYMENT_ID,
} as any);
const USER_KEY = 'sk-user-key-material';

/** One fresh single-use deployment-bound assertion per broker call — never reused. */
const assertionFor = (input: Omit<MintIdentityInput, 'exp' | 'jti'>): string =>
  mintIdentity(input as MintIdentityInput, idConfig());

const PROVIDERS = [
  { id: 'ghlite', credential: 'key', egressAllow: ['api.bridge.test'] },
  {
    id: 'writer', credential: 'key', egressAllow: ['api.bridge.test'],
    egressMethods: ['GET', 'POST'], approval: { approver: 'self' },
  },
];

function request(port: number, method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolvePromise, reject) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: '127.0.0.1', port, path, method,
        headers: data ? { 'content-type': 'application/json', 'content-length': data.length } : {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let json: any = null;
          try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* leave null */ }
          resolvePromise({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

/** Spawn the packaged broker as a separate process over the shared schema; resolve its bound port
 * from the readiness log line, then confirm liveness over HTTP. */
async function spawnBroker(t: TestContext, databaseUrl: string): Promise<{ port: number; child: ChildProcess }> {
  const stub = pathToFileURL(resolve('test/support/broker-upstream-stub.mjs')).href;
  const child = spawn(
    process.execPath,
    ['--import', 'tsx', '--import', stub, 'bin/broker-server.ts'],
    {
      env: {
        ...process.env,
        VOUCHR_DATABASE_URL: databaseUrl,
        VOUCHR_MASTER_KEY: process.env.VOUCHR_MASTER_KEY!,
        VOUCHR_IDENTITY_SECRET: IDENTITY_SECRET,
        VOUCHR_DEPLOYMENT_ID: DEPLOYMENT_ID,
        VOUCHR_PROVIDERS: JSON.stringify(PROVIDERS),
        VOUCHR_ALLOW_WRITES: '1',
        VOUCHR_CHANNEL_MODES: '1',
        VOUCHR_PORT: '0',
        VOUCHR_SWEEP_INTERVAL_MS: '0',
        VOUCHR_PG_POOL_MAX: '2',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  t.after(async () => {
    if (child.exitCode === null && !child.killed) {
      child.kill('SIGTERM');
      await Promise.race([once(child, 'exit'), new Promise((r) => setTimeout(r, 5_000))]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
  });
  let stdout = '';
  let stderr = '';
  child.stderr!.on('data', (c) => { stderr += c; });
  const port = await new Promise<number>((resolvePort, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`broker did not become ready\nstdout: ${stdout}\nstderr: ${stderr}`)),
      30_000,
    );
    child.stdout!.on('data', (c) => {
      stdout += c;
      const m = /\[vouchr\] broker listening port=(\d+)/.exec(stdout);
      if (m) { clearTimeout(timer); resolvePort(Number(m[1])); }
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`broker exited before ready (code ${code})\nstdout: ${stdout}\nstderr: ${stderr}`));
    });
  });
  assert.notEqual(port, 0, 'the readiness line reports the OS-assigned port, not the literal 0');
  const health = await request(port, 'GET', '/healthz');
  assert.equal(health.status, 200);
  return { port, child };
}

test('two-process bridge: broker denials recover through Bolt for connect, session, and approval', async (t) => {
  const databaseUrl = await testDbUrl(t);
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');

  // ── The trusted Slack control plane: a real createVouchr on the SAME schema, Slack faked. ──────
  const db = await openDb({ databaseUrl });
  t.after(() => db.close());
  const vouchr = await createVouchr({
    providers: PROVIDERS.map((p) => ({
      ...p, authorizeUrl: '', tokenUrl: '', scopesDefault: [], refresh: 'none' as const, pkce: false,
    })) as any,
    baseUrl: 'http://127.0.0.1:1',
    db,
  });
  const actions: Record<string, any> = {};
  vouchr.registerCommands({
    command: () => undefined,
    view: () => undefined,
    action: (id: string, h: any) => { actions[id] = h; },
  });
  const ephemerals: any[] = [];
  const dms: any[] = [];
  const client = {
    users: { info: async ({ user }: any) => ({ user: { is_admin: user === 'U1' } }) },
    conversations: {
      info: async ({ channel }: any) => ({ channel: { id: channel, is_channel: true, creator: 'U1' } }),
      members: async () => ({ members: ['U1'] }),
    },
    chat: {
      postEphemeral: async (p: any) => { ephemerals.push(p); return {}; },
      postMessage: async (p: any) => { dms.push(p); return {}; },
    },
  } as any;
  const context = async (over: { channel?: string; thread?: string } = {}): Promise<ConnectContext> => {
    const args: any = {
      context: {},
      client,
      event: {
        team: 'T1', user: 'U1',
        channel: over.channel ?? 'C1',
        ...(over.thread ? { thread_ts: over.thread } : {}),
      },
      next: async () => {},
    };
    await vouchr.middleware(args);
    return args.context.vouchr as ConnectContext;
  };
  const click = async (actionId: string, value: string, where: { channel: string; thread?: string }) => {
    await actions[actionId]({
      ack: async () => {},
      body: {
        team: { id: 'T1' },
        user: { id: 'U1' },
        channel: { id: where.channel },
        container: { channel_id: where.channel, ...(where.thread ? { thread_ts: where.thread } : {}) },
        actions: [{ value }],
      },
      client,
      respond: async () => {},
    });
  };

  // ── The packaged broker: a genuinely separate process over the same PostgreSQL. ────────────────
  const { port } = await spawnBroker(t, databaseUrl);
  const fetchVia = (over: {
    provider?: string; method?: string; path?: string; body?: string;
    channel?: string; thread?: string; token?: string;
  } = {}) => request(port, 'POST', '/v1/fetch', {
    handle: { provider: over.provider ?? 'ghlite', owner: 'user' },
    method: over.method ?? 'GET',
    path: over.path ?? '/me',
    ...(over.body === undefined ? {} : { body: over.body }),
    identityToken: over.token ?? assertionFor({
      teamId: 'T1', userId: 'U1',
      channel: over.channel ?? 'C1',
      ...(over.thread ? { threadTs: over.thread } : {}),
    }),
  });

  // ════ 1. Connect recovery: not_connected → private key-setup flow → retry succeeds. ════════════
  const notConnected = await fetchVia();
  assert.equal(notConnected.status, 409);
  assert.equal(notConnected.json.code, 'not_connected');
  assert.equal(notConnected.json.recovery, 'connect');

  const connectRecovery = await (await context()).recoverBrokerDenial('ghlite', notConnected.json);
  assert.deepEqual(connectRecovery, { status: 'connect_prompted', provider: 'ghlite', promptState: 'posted' });
  assert.equal(ephemerals.length, 1);
  assert.ok(JSON.stringify(ephemerals[0].blocks).includes(SETUP_KEY_ACTION), 'private key-setup prompt');

  // The human completes setup through the public self-service API (the modal's shared mutation).
  await (await context()).setUserSecret('ghlite', USER_KEY);
  const afterConnect = await fetchVia();
  assert.equal(afterConnect.status, 200, 'fresh assertion + stored credential clears the denial');
  assert.equal(afterConnect.json.status, 200);

  // Single-use assertions: replaying an already-spent token is refused at the broker.
  const spent = assertionFor({ teamId: 'T1', userId: 'U1', channel: 'C1' });
  assert.equal((await fetchVia({ token: spent })).status, 200);
  assert.equal((await fetchVia({ token: spent })).status, 401, 'jti replay refused cluster-wide');

  // ════ 2. Session recovery: session_approval_required → in-thread prompt → click → retry. ═══════
  // An admin sets the channel mode through the public Bolt surface (audited, shared PG row).
  await (await context({ channel: 'C2' })).setChannelMode('ghlite', 'session');
  const needsSession = await fetchVia({ channel: 'C2', thread: 'TH2' });
  assert.equal(needsSession.status, 403);
  assert.equal(needsSession.json.code, 'session_approval_required');
  assert.equal(needsSession.json.recovery, 'request_approval');

  const sessionDenial = needsSession.json;
  const sessionRecovery = await (await context({ channel: 'C2', thread: 'TH2' })).recoverBrokerDenial('ghlite', sessionDenial);
  assert.deepEqual(sessionRecovery, { status: 'session_prompted', provider: 'ghlite' });
  const sessionPrompts = ephemerals.filter((p) => JSON.stringify(p.blocks ?? '').includes(APPROVE_SESSION_ACTION));
  assert.equal(sessionPrompts.length, 1);
  assert.equal(sessionPrompts[0].thread_ts, 'TH2', 'prompt is thread-scoped');

  // A repeated relay (broker denies again while the human decides) converges without a re-post.
  const relayAgain = await (await context({ channel: 'C2', thread: 'TH2' })).recoverBrokerDenial('ghlite', sessionDenial);
  assert.deepEqual(relayAgain, { status: 'session_prompted', provider: 'ghlite' });
  assert.equal(
    ephemerals.filter((p) => JSON.stringify(p.blocks ?? '').includes(APPROVE_SESSION_ACTION)).length,
    1,
    'no duplicate session prompt',
  );

  const sessionRequest = await db.get<any>('SELECT id FROM session_request WHERE channel=?', ['C2']);
  await click(APPROVE_SESSION_ACTION, sessionRequest.id, { channel: 'C2', thread: 'TH2' });
  const afterGrant = await fetchVia({ channel: 'C2', thread: 'TH2' });
  assert.equal(afterGrant.status, 200, 'the thread grant admits the retried call');

  // The grant is thread-scoped: the same user in another thread is denied again.
  const otherThread = await fetchVia({ channel: 'C2', thread: 'TH9' });
  assert.equal(otherThread.status, 403);
  assert.equal(otherThread.json.code, 'session_approval_required');

  // ════ 3. Approval recovery: approval_required → decision surface → approve → single-use. ═══════
  await (await context()).setUserSecret('writer', USER_KEY);
  const writeBody = { provider: 'writer', method: 'POST', path: '/repos', body: '{}', channel: 'C1', thread: 'TH1' };
  const needsApproval = await fetchVia(writeBody);
  assert.equal(needsApproval.status, 403);
  assert.equal(needsApproval.json.code, 'approval_required');
  assert.equal(typeof needsApproval.json.approvalId, 'string');

  const approvalRecovery = await (await context({ thread: 'TH1' })).recoverBrokerDenial('writer', needsApproval.json);
  assert.deepEqual(approvalRecovery, { status: 'approval_prompted', provider: 'writer', approver: 'self' });
  const approvalPrompts = ephemerals.filter((p) => JSON.stringify(p.blocks ?? '').includes(APPROVAL_APPROVE_ACTION));
  assert.equal(approvalPrompts.length, 1);
  assert.equal(approvalPrompts[0].user, 'U1', 'self approval goes to the requester');

  await click(APPROVAL_APPROVE_ACTION, needsApproval.json.approvalId, { channel: 'C1', thread: 'TH1' });
  const approvedRetry = await fetchVia(writeBody);
  assert.equal(approvedRetry.status, 200, 'one live grant admits exactly one retried write');

  // Single-use: the identical write immediately re-prompts with a FRESH pending id.
  const reprompt = await fetchVia(writeBody);
  assert.equal(reprompt.status, 403);
  assert.equal(reprompt.json.code, 'approval_required');
  assert.notEqual(reprompt.json.approvalId, needsApproval.json.approvalId);

  // ════ No credential material ever reached a Slack surface (SEC-1). ═════════════════════════════
  const everything = JSON.stringify([ephemerals, dms]);
  assert.ok(!everything.includes(USER_KEY));
  assert.ok(!everything.includes(IDENTITY_SECRET));

  // The channel-mode fact both processes used is the same shared row (one PostgreSQL, no copies).
  assert.equal(await new ChannelConfig(db).getMode('T1', 'C2', 'ghlite'), 'session');
});
