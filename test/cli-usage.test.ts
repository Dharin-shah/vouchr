import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

// Usage parsing for the CLI commands routed through `node:util.parseArgs` (strict). NOTE `rekey` and
// `migrate` are among them and both MUTATE — they are here because their flags are parsed before any
// store opens, not because they are read-only. The genuinely destructive commands (`revoke`,
// `prune`) keep the stricter hand-written parser, which additionally rejects duplicate and empty
// flag values; parseArgs is last-writer-wins on duplicates. Every case here
// must be decided BEFORE the database opens, so this file needs no Postgres and no keys: the child is
// spawned with the store/key env stripped, and a parse regression would surface as the generic
// runtime failure (exit 1) instead of the usage rejection (exit 2).
// The destructive commands' own parser is covered by cli-revoke.test.ts.

const env = { ...process.env };
delete env.VOUCHR_DATABASE_URL;
delete env.VOUCHR_MASTER_KEY;
delete env.VOUCHR_MASTER_KEYS;

const run = (args: string[]) =>
  spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', ...args], { env, encoding: 'utf8' });

const REJECTED: [label: string, args: string[]][] = [
  // A value flag left without a value must NOT swallow the next flag: `--db --dry-run` silently
  // becoming `db='--dry-run'` would turn a rehearsal into a live re-encryption of every ciphertext.
  ['rekey --db swallowing --dry-run', ['rekey', '--db', '--dry-run']],
  ['rekey --dry-run given a value', ['rekey', '--dry-run=true']],
  ['unknown flag', ['doctor', '--bogus']],
  ['unexpected positional', ['inventory', 'extra']],
  ['value flag with no value at all', ['inventory', '--team', 'T1', '--db']],
  ['short flag', ['channels', '-t']],
];

test('non-destructive commands reject malformed usage before touching the store', () => {
  for (const [label, args] of REJECTED) {
    const res = run(args);
    assert.equal(res.status, 2, `${label}: expected usage exit 2, got ${res.status}\n${res.stderr}`);
    assert.match(res.stderr, /invalid usage/, `${label}: expected a usage error`);
  }
});

test('a usage error never echoes the offending argument (SEC-1)', () => {
  // Deliberately NOT shaped like a real Slack/GitHub token: a committed fixture that matches a
  // provider's token grammar trips secret scanners and violates SEC-1 ("no credential in committed
  // test fixtures"). What is under test is that the CLI never echoes an ARGUMENT, whatever it looks
  // like, so an obviously-synthetic sentinel proves exactly as much.
  const secret = 'SYNTHETIC-CREDENTIAL-VALUE-DO-NOT-ECHO-0123456789';
  for (const args of [['doctor', `--${secret}`], ['inventory', secret], ['inventory', '--team', 'T1', '--db', `--${secret}`]]) {
    const res = run(args);
    assert.equal(res.status, 2, `expected usage exit 2, got ${res.status}\n${res.stderr}`);
    assert.equal(res.stdout.includes(secret), false, 'stdout echoed the argument');
    assert.equal(res.stderr.includes(secret), false, 'stderr echoed the argument');
  }
});

test('--version prints the package version and nothing else', () => {
  for (const flag of ['--version', '-v']) {
    const res = run([flag]);
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout.trim(), require('../package.json').version);
  }
});

test('help lists only the commands the CLI implements', () => {
  const res = run(['help']);
  assert.equal(res.status, 0, res.stderr);
  for (const cmd of ['migrate', 'inventory', 'channels', 'revoke', 'doctor', 'rekey', 'prune']) {
    assert.match(res.stdout, new RegExp(`^ {2}${cmd}\\b`, 'm'), `help should document ${cmd}`);
  }
  // `health` was a reachability probe, not a broker command; it is gone and must not be advertised
  // (it also forced a third copy of the provider list — STR-2).
  assert.equal(res.stdout.includes('health'), false, 'help still advertises the removed health command');
  assert.equal(run(['health']).status, 2, 'health must be an unknown command');
});
