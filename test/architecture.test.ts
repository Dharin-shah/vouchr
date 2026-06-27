import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { channelIneligibleReason } from '../src/core/channelConfig';

// The broker core must stay transport-agnostic: no Slack/Bolt or adapter imports. That boundary is
// what lets a future sidecar + thin clients reuse the SAME core (and its security logic) instead of
// re-implementing it per language. Slack-specific pieces (e.g. the InstallationStore) live in
// src/adapters/. This test fails the moment something couples core to the transport.
test('core is transport-agnostic (no @slack or adapter imports)', () => {
  const coreDir = join(process.cwd(), 'src', 'core');
  const offenders: string[] = [];
  for (const f of readdirSync(coreDir).filter((f) => f.endsWith('.ts'))) {
    const src = readFileSync(join(coreDir, f), 'utf8');
    if (/from ['"]@slack\//.test(src) || /require\(['"]@slack\//.test(src)) offenders.push(`core/${f}: @slack import`);
    if (/from ['"]\.\.\/adapters\//.test(src)) offenders.push(`core/${f}: adapters import`);
  }
  assert.deepEqual(offenders, [], `core must not depend on the transport layer:\n${offenders.join('\n')}`);
});

// The channel-eligibility RULE is core so every adapter enforces it identically.
test('channelIneligibleReason: classifies channel classes, fails closed on unknown', () => {
  assert.equal(channelIneligibleReason({}), null); // a normal channel is eligible
  assert.equal(channelIneligibleReason(null), 'Could not verify the channel type; channel credentials are refused.');
  assert.match(channelIneligibleReason({ is_ext_shared: true })!, /externally shared/);
  assert.match(channelIneligibleReason({ is_shared: true })!, /externally shared/);
  assert.match(channelIneligibleReason({ is_pending_ext_shared: true })!, /externally shared/);
  assert.match(channelIneligibleReason({ is_im: true })!, /DMs/);
  assert.match(channelIneligibleReason({ is_mpim: true })!, /DMs/);
  assert.match(channelIneligibleReason({ is_archived: true })!, /archived/);
});
