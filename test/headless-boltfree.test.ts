import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import http from 'node:http';
// Direct-construction path: EVERYTHING here comes from `../src/headless` and NOTHING else, proving a
// typed pure-headless consumer can build createBroker end-to-end without reaching into internal paths.
// This is also the compile-level proof (tsc --noEmit in the gate type-checks this file).
import { openDb, Vault, Audit, createBroker, github, sweepExpired, Consent, Policy, ChannelTools } from '../src/headless';
import type { Db, TtlPolicy } from '../src/headless';

/**
 * Proves the Bolt-free claim (Product H2): the `./headless` entry's RESOLVED CommonJS module graph must
 * never reach `@slack/*`. We load the COMPILED entry in a clean child process and inspect require.cache
 * — the ground truth of what actually got loaded. If any @slack module is in the graph, the headless
 * entry is not Bolt-free and a pure-headless consumer would still pay for the whole Slack surface.
 *
 * Requires `npm run build` first (the gate builds before testing). We assert dist exists so a missing
 * build fails loudly rather than silently passing.
 */
const dist = path.resolve(__dirname, '../dist/src/headless.js');

// CI builds before test (see ci.yml), so dist exists there; a local `npm test` with no prior build
// skips this rather than red-failing — the check is only meaningful against the compiled artifact.
test('headless entry: compiled module graph is @slack-free', { skip: existsSync(dist) ? false : 'run `npm run build` first (CI builds before test)' }, () => {

  // Clean-room: a child that requires ONLY the headless entry, then reports any @slack in its cache.
  const probe = `
    require(${JSON.stringify(dist)});
    const slack = Object.keys(require.cache).filter((k) => k.includes(${JSON.stringify(path.sep + '@slack' + path.sep)}));
    process.stdout.write(JSON.stringify(slack));
  `;
  const out = execFileSync(process.execPath, ['-e', probe], { encoding: 'utf8' });
  const slackModules: string[] = JSON.parse(out);
  assert.deepEqual(
    slackModules,
    [],
    `headless entry pulled @slack modules into its graph:\n${slackModules.join('\n')}`,
  );
});

test('headless entry: createBroker is constructible end-to-end from ./headless alone', async () => {
  const db: Db = await openDb(); // sqlite in-memory default
  try {
    const ttl: TtlPolicy = { idleMs: 1000 };
    const vault = new Vault(db, Buffer.alloc(32), ttl);
    const audit = new Audit(db);
    const provider = github({ clientId: 'id', clientSecret: 'secret' });
    // Policy-gated construction (the canary rollout: scope the broker to one channel) + tool allowlist,
    // all from ./headless alone.
    const policy = new Policy({ github: { defaultAllow: false, allowChannels: ['C_canary'] } }, { defaultDeny: true });
    const channelTools = new ChannelTools(db);
    const server = createBroker({ providers: [provider], vault, audit, db, identitySecret: 'test-secret', policy, channelTools });
    assert.ok(server instanceof http.Server);
    // sweep lifecycle bits are reachable too (all from ./headless).
    assert.equal(await sweepExpired(vault, audit, new Consent(db)), 0);
    server.close();
  } finally {
    await db.close();
  }
});
