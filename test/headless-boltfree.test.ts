import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

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

test('headless entry: compiled module graph is @slack-free', () => {
  assert.ok(existsSync(dist), `build first: ${dist} not found (run "npm run build")`);

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
