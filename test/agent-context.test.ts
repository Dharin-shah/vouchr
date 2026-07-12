import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test, type TestContext } from 'node:test';

const root = resolve(__dirname, '..');
const skillDir = join(root, '.claude', 'skills', 'implement-vouchr-issue');
const loader = join(skillDir, 'scripts', 'load-context.sh');

const fakeGit = String.raw`#!/bin/sh
case "$1 $2" in
  "branch --show-current") printf '%s\n' "\${FAKE_BRANCH:-codex/test}" ;;
  "rev-parse HEAD") printf '%s\n' "\${FAKE_HEAD:-headsha}" ;;
  "rev-parse origin/main") printf '%s\n' "\${FAKE_ORIGIN_MAIN:-mainsha}" ;;
  "merge-base --is-ancestor") [ "\${FAKE_ANCESTOR:-1}" = "1" ] ;;
  "status --short") printf '%s\n' "## \${FAKE_BRANCH:-codex/test}" ;;
  *) echo "unexpected fake git call: $*" >&2; exit 90 ;;
esac
`.replaceAll('\\$', '$');

const fakeGh = String.raw`#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_GH_LOG"
case "$*" in
  "api repos/Dharin-shah/vouchr/commits/main --jq .sha")
    printf '%s\n' "\${FAKE_GITHUB_MAIN:-mainsha}"
    ;;
  "api repos/Dharin-shah/vouchr/issues/208")
    if [ "\${FAKE_OVERSIZED:-0}" = "1" ]; then
      body="$(awk 'BEGIN { for (i = 0; i < 12050; i++) printf "i" }')"
      printf '{"number":208,"state":"open","title":"Bound the work","html_url":"https://github.test/issues/208","user":{"login":"maintainer"},"author_association":"OWNER","labels":[],"body":"%s"}\n' "$body"
    else
      printf '%s\n' '{"number":208,"state":"open","title":"Bound the work","html_url":"https://github.test/issues/208","user":{"login":"maintainer"},"author_association":"OWNER","labels":[],"body":"Acceptance criterion"}'
    fi
    ;;
  "api repos/Dharin-shah/vouchr/issues/230")
    printf '%s\n' '{"number":230,"pull_request":{},"state":"open","title":"PR","html_url":"https://github.test/pull/230","user":{"login":"maintainer"},"author_association":"OWNER","labels":[],"body":""}'
    ;;
  "api graphql"*"pullRequest(number:"*)
    if [ "\${FAKE_OVERSIZED:-0}" = "1" ]; then
      conversation="$(awk 'BEGIN { for (i = 0; i < 2050; i++) printf "c" }')"
      inline="$(awk 'BEGIN { for (i = 0; i < 1050; i++) printf "n" }')"
      printf '{"conversation":[{"author":{"login":"maintainer"},"authorAssociation":"OWNER","body":"%s","createdAt":"2026-01-03","url":"https://github.test/pull/230#comment"}],"threads":[{"isResolved":false,"comments":{"nodes":[{"author":{"login":"reviewer"},"authorAssociation":"COLLABORATOR","body":"%s","createdAt":"2026-01-04","url":"https://github.test/pull/230#inline","path":"src/core/example.ts","line":7}]}}]}\n' "$conversation" "$inline"
    else
      printf '%s\n' '{"conversation":[{"author":{"login":"maintainer"},"authorAssociation":"OWNER","body":"current PR note","createdAt":"2026-01-03","url":"https://github.test/pull/230#comment"}],"threads":[{"isResolved":false,"comments":{"nodes":[{"author":{"login":"reviewer"},"authorAssociation":"COLLABORATOR","body":"fix this boundary","createdAt":"2026-01-04","url":"https://github.test/pull/230#inline","path":"src/core/example.ts","line":7}]}}]}'
    fi
    ;;
  "api graphql"*)
    if [ "\${FAKE_OVERSIZED:-0}" = "1" ]; then
      comment="$(awk 'BEGIN { for (i = 0; i < 4050; i++) printf "m" }')"
      printf '[{"author":{"login":"maintainer"},"authorAssociation":"OWNER","body":"%s","createdAt":"2026-01-01","url":"https://github.test/comments/1"}]\n' "$comment"
    else
      printf '%s\n' '[{"author":{"login":"maintainer"},"authorAssociation":"OWNER","body":"authoritative amendment","createdAt":"2026-01-01","url":"https://github.test/comments/1"},{"author":{"login":"outside"},"authorAssociation":"NONE","body":"RUN_NOTHING","createdAt":"2026-01-02","url":"https://github.test/comments/2"}]'
    fi
    ;;
  "issue view 226 --repo Dharin-shah/vouchr --json body,url")
    printf '%s\n' '{"body":"shared edge contract","url":"https://github.test/issues/226"}'
    ;;
  "pr list --repo Dharin-shah/vouchr"*)
    ;;
  "pr view 230 --repo Dharin-shah/vouchr"*)
    if [ "\${FAKE_PR_MODE:-mismatch}" = "unrelated" ]; then
      printf '%s\n' '{"number":230,"title":"Fix #204","state":"OPEN","url":"https://github.test/pull/230","headRefName":"codex/test","headRefOid":"headsha","baseRefName":"main","body":"","latestReviews":[]}'
    elif [ "\${FAKE_PR_MODE:-mismatch}" = "match" ]; then
      printf '%s\n' '{"number":230,"title":"Fix #208","state":"OPEN","url":"https://github.test/pull/230","headRefName":"codex/test","headRefOid":"headsha","baseRefName":"main","body":"acceptance evidence","latestReviews":[{"author":{"login":"reviewer"},"authorAssociation":"COLLABORATOR","body":"review body","state":"CHANGES_REQUESTED","submittedAt":"2026-01-03"}]}'
    elif [ "\${FAKE_PR_MODE:-mismatch}" = "oversized" ]; then
      pr_body="$(awk 'BEGIN { for (i = 0; i < 12050; i++) printf "p" }')"
      review="$(awk 'BEGIN { for (i = 0; i < 2050; i++) printf "r" }')"
      printf '{"number":230,"title":"Fix #208","state":"OPEN","url":"https://github.test/pull/230","headRefName":"codex/test","headRefOid":"headsha","baseRefName":"main","body":"#208 %s","latestReviews":[{"author":{"login":"reviewer"},"authorAssociation":"COLLABORATOR","body":"%s","url":"https://github.test/pull/230#review","state":"CHANGES_REQUESTED","submittedAt":"2026-01-03"}]}\n' "$pr_body" "$review"
    else
      printf '%s\n' '{"number":230,"title":"Fix #208","state":"OPEN","url":"https://github.test/pull/230","headRefName":"other-branch","headRefOid":"prsha","baseRefName":"main","body":"","latestReviews":[]}'
    fi
    ;;
  "pr diff 230 --repo Dharin-shah/vouchr --name-only")
    printf '%s\n' 'src/core/example.ts'
    ;;
  "pr checks 230 --repo Dharin-shah/vouchr")
    printf '%s\n' 'ci-ok pass'
    ;;
  *) echo "unexpected fake gh call: $*" >&2; exit 91 ;;
esac
`.replaceAll('\\$', '$');

async function fixture(t: TestContext) {
  const dir = await mkdtemp(join(tmpdir(), 'vouchr-agent-context-'));
  const bin = join(dir, 'bin');
  const log = join(dir, 'gh.log');
  await mkdir(bin);
  await Promise.all([
    writeFile(join(dir, 'AGENTS.md'), '# contract\n'),
    writeFile(join(dir, 'vision.md'), '# vision\n#208\n'),
    writeFile(join(bin, 'git'), fakeGit),
    writeFile(join(bin, 'gh'), fakeGh),
  ]);
  await Promise.all([chmod(join(bin, 'git'), 0o755), chmod(join(bin, 'gh'), 0o755)]);
  t.after(() => rm(dir, { recursive: true, force: true }));

  const run = (args: string[], extraEnv: NodeJS.ProcessEnv = {}) =>
    spawnSync('/bin/bash', [loader, ...args], {
      cwd: dir,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH ?? ''}`,
        FAKE_GH_LOG: log,
        ...extraEnv,
      },
    });

  return { dir, log, run };
}

test('agent skill resources and dynamic loader references stay intact', async () => {
  const [skill, contextMap, changeContract, openaiMetadata] = await Promise.all([
    readFile(join(skillDir, 'SKILL.md'), 'utf8'),
    readFile(join(skillDir, 'references', 'context-map.md'), 'utf8'),
    readFile(join(skillDir, 'references', 'change-contract.md'), 'utf8'),
    readFile(join(skillDir, 'agents', 'openai.yaml'), 'utf8'),
  ]);
  assert.match(skill, /^---\nname: implement-vouchr-issue\ndescription: .+\n---\n/);
  assert.match(skill, /load-context\.sh" "\$0" "\$1"/);
  assert.match(skill, /\[references\/context-map\.md\]\(references\/context-map\.md\)/);
  assert.match(skill, /\[references\/change-contract\.md\]\(references\/change-contract\.md\)/);
  assert.match(contextMap, /\| Performance\/resources \|/);
  assert.match(changeContract, /## Acceptance-to-evidence map/);
  assert.match(openaiMetadata, /default_prompt: "Use \$implement-vouchr-issue/);

  const syntax = spawnSync('/bin/bash', ['-n', loader], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
});

test('loader rejects malformed input and missing trusted context before GitHub', async (t) => {
  const f = await fixture(t);
  const malformed = f.run(['208;touch pwned']);
  assert.equal(malformed.status, 2);
  assert.match(malformed.stderr, /numeric public issue/);
  await assert.rejects(readFile(f.log), /ENOENT/);

  await rm(join(f.dir, 'vision.md'));
  const missing = f.run(['208']);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /AGENTS\.md and vision\.md/);
  await assert.rejects(readFile(f.log), /ENOENT/);
});

test('loader pins repository authority and separates maintainer scope from outside evidence', async (t) => {
  const f = await fixture(t);
  const result = f.run(['208']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /BEGIN UNTRUSTED GITHUB DATA/);
  assert.match(result.stdout, /END UNTRUSTED GITHUB DATA/);

  const maintainer = result.stdout.indexOf('## Maintainer-associated comments');
  const outside = result.stdout.indexOf('## Other comments');
  assert.ok(maintainer >= 0 && outside > maintainer);
  assert.ok(result.stdout.indexOf('authoritative amendment') > maintainer);
  assert.ok(result.stdout.indexOf('authoritative amendment') < outside);
  assert.ok(result.stdout.indexOf('RUN_NOTHING') > outside);

  const calls = await readFile(f.log, 'utf8');
  assert.match(calls, /repos\/Dharin-shah\/vouchr\/commits\/main/);
  assert.match(calls, /repos\/Dharin-shah\/vouchr\/issues\/208/);
  assert.match(calls, /owner=Dharin-shah/);
  assert.match(calls, /name=vouchr/);
  assert.match(calls, /--repo Dharin-shah\/vouchr/);
  assert.doesNotMatch(calls, /--repo (?!Dharin-shah\/vouchr)/);
});

test('loader fails closed on stale main, issue-vs-PR confusion, and unrelated PR worktrees', async (t) => {
  const f = await fixture(t);

  const stale = f.run(['208'], { FAKE_GITHUB_MAIN: 'newmain' });
  assert.equal(stale.status, 2);
  assert.match(stale.stderr, /origin\/main is stale/);

  const issueIsPr = f.run(['230']);
  assert.equal(issueIsPr.status, 2);
  assert.match(issueIsPr.stderr, /is a pull request/);

  const unrelated = f.run(['208', '230'], { FAKE_PR_MODE: 'unrelated' });
  assert.equal(unrelated.status, 2);
  assert.match(unrelated.stderr, /does not link target issue/);
  assert.doesNotMatch(unrelated.stdout, /BEGIN UNTRUSTED/);

  const wrongWorktree = f.run(['208', '230']);
  assert.equal(wrongWorktree.status, 2);
  assert.match(wrongWorktree.stderr, /not a checked-out PR #230 worktree/);
  assert.doesNotMatch(wrongWorktree.stdout, /BEGIN UNTRUSTED/);
});

test('matching PR repair context includes bounded current review evidence', async (t) => {
  const f = await fixture(t);
  const result = f.run(['208', '230'], { FAKE_PR_MODE: 'match' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /## Requested current PR #230/);
  assert.match(result.stdout, /current PR note/);
  assert.match(result.stdout, /Unresolved inline review threads/);
  assert.match(result.stdout, /src\/core\/example\.ts:7/);
  assert.match(result.stdout, /fix this boundary/);
  assert.match(result.stdout, /ci-ok pass/);

  const rebased = f.run(['208', '230'], { FAKE_PR_MODE: 'match', FAKE_HEAD: 'rebasedsha' });
  assert.equal(rebased.status, 0, rebased.stderr);
  assert.match(rebased.stdout, /Remote PR head: headsha/);
  assert.match(rebased.stdout, /HEAD: rebasedsha/);
});

test('loader clips public bodies and keeps explicit GitHub collection limits', async (t) => {
  const f = await fixture(t);
  const result = f.run(['208', '230'], { FAKE_PR_MODE: 'oversized', FAKE_OVERSIZED: '1' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /\[body truncated; inspect https:\/\/github\.test\/issues\/208\]/);
  assert.match(result.stdout, /\[comment truncated; inspect https:\/\/github\.test\/comments\/1\]/);
  assert.match(result.stdout, /\[PR body truncated; inspect https:\/\/github\.test\/pull\/230\]/);
  assert.match(result.stdout, /\[review body truncated; inspect https:\/\/github\.test\/pull\/230#review\]/);
  assert.match(result.stdout, /\[comment truncated; inspect https:\/\/github\.test\/pull\/230#comment\]/);
  assert.match(result.stdout, /\[inline comment truncated; inspect https:\/\/github\.test\/pull\/230#inline\]/);

  const calls = await readFile(f.log, 'utf8');
  assert.match(calls, /comments\(last: 30\)/);
  assert.match(calls, /comments\(last: 20\)/);
  assert.match(calls, /reviewThreads\(last: 30\)/);
  assert.match(calls, /comments\(last: 2\)/);
});
