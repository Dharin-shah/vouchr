import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import * as root from '../src/index';
import * as headless from '../src/headless';
import { createVouchr } from '../src/adapters/bolt';
import { defineProvider } from '../src/core/providers';
import { openTestDb } from './support/pg';

const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x.test/a', tokenUrl: 'https://x.test/t',
  scopesDefault: [], egressAllow: ['api.test'], refresh: 'none', pkce: false,
  clientId: 'c', clientSecret: 's',
});

const REMOVED_EXPORTS = [
  'PendingPreviews',
  'PREVIEW_VISIBILITIES',
  'isPreviewVisibility',
  'previewBlocks',
  'previewPostBlocks',
  'normalizePreviewContent',
  'PREVIEW_SHARE_ACTION',
  'PREVIEW_DISMISS_ACTION',
] as const;

test('private-preview runtime exports are removed from root and headless entrypoints', () => {
  for (const name of REMOVED_EXPORTS) {
    assert.equal(name in (root as Record<string, unknown>), false, `${name} leaked from the root entrypoint`);
    assert.equal(name in (headless as Record<string, unknown>), false, `${name} leaked from the headless entrypoint`);
  }
});

test('Bolt removes preview state/API but safely expires controls issued before the cutover', async (t: TestContext) => {
  process.env.VOUCHR_MASTER_KEY = randomBytes(32).toString('base64');
  const lan = await createVouchr({
    providers: [provider],
    baseUrl: 'http://127.0.0.1:1',
    db: await openTestDb(t),
  });
  let command: any;
  const actions: Record<string, unknown> = {};
  lan.registerCommands({
    command: (_name: string, handler: any) => { command = handler; },
    view: () => undefined,
    action: (id: string, handler: unknown) => { actions[id] = handler; },
  });

  for (const id of ['vouchr_preview_share', 'vouchr_preview_dismiss']) {
    assert.equal(typeof actions[id], 'function', `${id} needs a state-free stale-control tombstone`);
    const sequence: string[] = [];
    const responses: unknown[] = [];
    await (actions[id] as (args: unknown) => Promise<void>)({
      ack: async () => { sequence.push('ack'); },
      respond: async (message: unknown) => { sequence.push('respond'); responses.push(message); },
      body: { message: { text: 'provider-response-sentinel' } },
      client: { chat: { postMessage: async () => assert.fail('a retired control must never share content') } },
    });
    assert.deepEqual(sequence, ['ack', 'respond'], 'the stale interaction must be acknowledged first');
    assert.deepEqual(responses, [{
      replace_original: true,
      text: 'This preview expired because private previews were removed. Ask the agent again.',
    }]);
    assert.doesNotMatch(JSON.stringify(responses), /provider-response-sentinel/);
  }

  const args: any = {
    client: {},
    event: { channel: 'C_FIN', user: 'U1', team: 'T1', thread_ts: '111.222' },
    body: { team_id: 'T1', user_id: 'U1' },
    context: {},
    next: async () => undefined,
  };
  await lan.middleware(args);
  const context = args.context.vouchr as Record<string, unknown>;
  assert.equal('preview' in context, false);
  assert.equal('setChannelVisibility' in context, false);
  assert.equal('previews' in context, false, 'no process-memory provider-response store may be allocated');

  const manifest = await (context.toolManifest as () => Promise<Record<string, unknown>[]>).call(context);
  assert.deepEqual(manifest, [{ provider: 'mcp', mode: null, enabled: true, identity: 'acting_human' }]);
  assert.equal(Object.hasOwn(manifest[0], 'visibility'), false);

  const responses: string[] = [];
  await command({
    command: { team_id: 'T1', user_id: 'U1', channel_id: 'C_FIN', text: 'preview mcp private' },
    ack: async () => undefined,
    respond: async (message: string) => { responses.push(message); },
    client: {},
  });
  assert.deepEqual(responses, ['Unknown subcommand. Run `/vouchr help` to see what you can do.']);
  assert.equal((await lan.db.all(`SELECT id FROM audit`)).length, 0);
});
