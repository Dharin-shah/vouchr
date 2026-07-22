import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { channelIneligibleReason } from '../src/core/channelConfig';
import {
  connectBlocks, configureModal, userKeyModal,
  CONFIGURE_CALLBACK, USER_KEY_CALLBACK, SETUP_KEY_ACTION,
} from '../src';

// The broker core must stay transport-agnostic: no Slack/Bolt or adapter imports. That boundary is
// what lets the packaged broker + thin clients reuse the SAME core (and its security logic) instead of
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

// Import-based checks miss Slack KNOWLEDGE that carries no @slack import: a function that pages
// `conversations.members` or reads `is_admin`/`is_owner` off a users.info response is just as coupled
// to Slack as an import is. Assert core references none of those Slack-semantic tokens, so the boundary
// is structural (what core knows), not merely which packages it imports.
//
// Token note: we match `conversations.members` (the paging API the moved membership helpers called),
// NOT a bare `conversations.` — core deliberately keeps the channel-eligibility RULE + the ChannelInfo
// field subset (see channelConfig.ts), whose doc comment mentions `conversations.info`. That RULE is
// meant to live in core; only the Slack API-CALLING logic (members paging, admin-flag reads) is banned.
test('core is Slack-semantics-free (no conversations.members / is_admin / is_owner)', () => {
  const coreDir = join(process.cwd(), 'src', 'core');
  const forbidden = ['conversations.members', '.is_admin', '.is_owner'];
  const offenders: string[] = [];
  for (const f of readdirSync(coreDir).filter((f) => f.endsWith('.ts'))) {
    const src = readFileSync(join(coreDir, f), 'utf8');
    for (const token of forbidden) {
      if (src.includes(token)) offenders.push(`core/${f}: references "${token}"`);
    }
  }
  assert.deepEqual(offenders, [], `core must not contain Slack-semantic logic:\n${offenders.join('\n')}`);
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

// #64: the pure Block Kit builders are importable from the package root so a headless host reuses the
// modal SHAPE with its own client instead of hand-copying (and drifting from) the Bolt JSON.
test('#64 block builders + callback ids are exported from the package root as usable Block Kit', () => {
  // Modals carry the callback_id a host's view-submission handler routes on.
  assert.equal((configureModal('jira', 'C1') as any).callback_id, CONFIGURE_CALLBACK);
  assert.equal((userKeyModal('jira') as any).callback_id, USER_KEY_CALLBACK);
  assert.equal((configureModal('jira', 'C1') as any).type, 'modal');
  // The connect prompt is a block array with a link button to the authorize URL.
  const blocks = connectBlocks('jira', 'https://issuer.example/authorize?x=1');
  assert.ok(Array.isArray(blocks) && blocks.length > 0);
  assert.ok(JSON.stringify(blocks).includes('https://issuer.example/authorize?x=1'));
  assert.equal(typeof SETUP_KEY_ACTION, 'string');
});

// #241: the production KMS template is a supported wiring artifact, not illustrative pseudocode.
// Keep one envelope-backed store on both sides of Bolt's installation contract so a future example
// cleanup cannot silently leave Slack installation tokens on the direct-key path.
test('#241 Postgres+KMS template wires one envelope-backed installation store into Bolt and Vouchr', () => {
  const source = readFileSync(join(process.cwd(), 'examples', 'postgres-kms', 'app.ts'), 'utf8');
  assert.match(source, /const envelope = kmsEnvelope\(kmsKeyId, await awsKmsClient\(/);
  assert.match(source, /new DbInstallationStore\(db, key, envelope\)/);
  assert.match(source, /new ExpressReceiver\(\{[\s\S]*?installationStore,[\s\S]*?\}\)/);
  assert.match(source, /createVouchr\(\{[\s\S]*?envelope,[\s\S]*?installationStore,[\s\S]*?\}\)/);
  assert.doesNotMatch(source, /new App\(\{\s*token:/, 'multi-workspace template must not bypass the installation store');
  assert.doesNotMatch(source, /KMS envelope provider is not configured/, 'production template must not ship a placeholder provider');
});

// #2/#5 doc-drift guard: two governance facts changed and the docs must not regress to the inverse.
// (1) The `/vouchr configure` slash command was REMOVED (renamed to `connect-shared`), so it must not
//     appear in user-facing docs or the Slack manifest (CHANGELOG records the rename and is exempt).
// (2) Channels are deny-by-default; the ChannelTools contract doc must say so, not the old open-by-default.
test('#5 docs do not regress to the removed `configure` command or the open-by-default default', () => {
  const root = process.cwd();
  const docFiles = [
    'README.md', 'QUICKSTART.md',
    'guides/HYBRID.md', 'guides/DEPLOYMENT.md', 'guides/HEADLESS.md',
    'examples/slack-manifest.yml', 'examples/dry-run/README.md',
  ];
  const offenders: string[] = [];
  for (const rel of docFiles) {
    const text = readFileSync(join(root, rel), 'utf8');
    // The removed slash command as an invocation (`vouchr configure`). Not "configure the channel",
    // `configureModal`, or `HOME_CONFIGURE_ACTION` — those are not the command surface.
    text.split('\n').forEach((line, i) => {
      if (/\bvouchr\s+configure\b/i.test(line)) offenders.push(`${rel}:${i + 1} references the removed \`vouchr configure\` command`);
    });
  }
  assert.deepEqual(offenders, [], `docs still reference the removed configure command:\n${offenders.join('\n')}`);

  // Positive guard: the ChannelTools contract documents deny-by-default (the inverse of the old text).
  const tools = readFileSync(join(root, 'src', 'core', 'tools.ts'), 'utf8');
  assert.match(tools, /deny-by-default/i, 'ChannelTools JSDoc must document deny-by-default');
  assert.doesNotMatch(
    tools,
    /rowless[^.]*enable[sd]?\s+every\s+provider|treats\s+every\s+provider\s+as\s+enabled/i,
    'ChannelTools JSDoc must not state the old open-by-default behavior',
  );
});
