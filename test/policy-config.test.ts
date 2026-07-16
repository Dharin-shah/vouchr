import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadPolicy } from '../bin/policyConfig';

const providers = [
  { id: 'github' },
  { id: 'notion' },
  { id: 'unruled' },
  { id: 'constructor' },
];

function inline(document: unknown) {
  const loaded = loadPolicy(providers, { VOUCHR_POLICY: JSON.stringify(document) });
  assert.ok(loaded);
  return loaded;
}

function thrownMessage(env: NodeJS.ProcessEnv): string {
  try {
    loadPolicy(providers, env);
  } catch (error) {
    assert.ok(error instanceof Error);
    return error.message;
  }
  assert.fail('expected policy configuration to be rejected');
}

test('#236 loadPolicy: absent config preserves the historical no-policy path', () => {
  assert.equal(loadPolicy(providers, {}), undefined);
});

test('#236 loadPolicy: inline JSON and a mounted JSON file produce identical policy decisions', () => {
  const raw = JSON.stringify({
    defaultDeny: true,
    rules: {
      github: {
        defaultAllow: false,
        allowChannels: ['C_ALLOW', 'C_BOTH'],
        denyChannels: ['C_DENY', 'C_BOTH'],
      },
      notion: { defaultAllow: true, denyChannels: ['C_BLOCK'] },
    },
  });
  const dir = mkdtempSync(join(tmpdir(), 'vouchr-policy-'));
  const file = join(dir, 'policy.json');
  writeFileSync(file, raw, 'utf8');

  const fromInline = loadPolicy(providers, { VOUCHR_POLICY: raw });
  const fromFile = loadPolicy(providers, { VOUCHR_POLICY_FILE: file });
  assert.ok(fromInline);
  assert.ok(fromFile);
  assert.deepEqual(
    { defaultDeny: fromInline.defaultDeny, ruleCount: fromInline.ruleCount },
    { defaultDeny: true, ruleCount: 2 },
  );
  assert.deepEqual(
    { defaultDeny: fromFile.defaultDeny, ruleCount: fromFile.ruleCount },
    { defaultDeny: true, ruleCount: 2 },
  );

  const decisions: Array<[provider: string, channel: string | null, allowed: boolean]> = [
    ['github', 'C_ALLOW', true],
    ['github', 'C_DENY', false],
    ['github', 'C_OTHER', false],
    ['github', 'C_BOTH', false], // an explicit deny wins over an explicit allow
    ['github', null, false],
    ['notion', 'C_OPEN', true],
    ['notion', 'C_BLOCK', false],
    ['unruled', 'C_OPEN', false],
  ];
  for (const [provider, channel, allowed] of decisions) {
    assert.equal(fromInline.policy.check(provider, channel), allowed, `inline ${provider}/${channel}`);
    assert.equal(fromFile.policy.check(provider, channel), allowed, `file ${provider}/${channel}`);
  }
});

test('#236 loadPolicy: inline and file sources are mutually exclusive, including empty values', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vouchr-policy-conflict-'));
  const file = join(dir, 'policy.json');
  writeFileSync(file, '{}', 'utf8');

  assert.throws(
    () => loadPolicy(providers, { VOUCHR_POLICY: '{}', VOUCHR_POLICY_FILE: file }),
    /VOUCHR_POLICY.*VOUCHR_POLICY_FILE|VOUCHR_POLICY_FILE.*VOUCHR_POLICY/,
  );
  assert.throws(
    () => loadPolicy(providers, { VOUCHR_POLICY: '', VOUCHR_POLICY_FILE: file }),
    /VOUCHR_POLICY.*VOUCHR_POLICY_FILE|VOUCHR_POLICY_FILE.*VOUCHR_POLICY/,
  );
});

test('#236 loadPolicy: malformed JSON and non-object roots fail closed', () => {
  for (const raw of ['', '   ', '{', 'null', '[]', 'true', '42']) {
    assert.throws(
      () => loadPolicy(providers, { VOUCHR_POLICY: raw }),
      /VOUCHR_POLICY/,
      `must reject ${JSON.stringify(raw)}`,
    );
  }
  assert.throws(
    () => loadPolicy(providers, { VOUCHR_POLICY_FILE: '' }),
    /VOUCHR_POLICY_FILE/,
    'an explicitly empty file path is invalid config, not an absent source',
  );
});

test('#236 loadPolicy: optional fields distinguish absence from explicit null or wrong types', () => {
  for (const defaultDeny of [null, 0, 'false', [], {}]) {
    assert.throws(
      () => inline({ defaultDeny }),
      /defaultDeny/,
      `must reject defaultDeny=${JSON.stringify(defaultDeny)}`,
    );
  }
  for (const rules of [null, false, 'none', [], 7]) {
    assert.throws(
      () => inline({ rules }),
      /rules/,
      `must reject rules=${JSON.stringify(rules)}`,
    );
  }
});

test('#236 loadPolicy: unknown top-level and rule fields fail closed', () => {
  assert.throws(() => inline({ defaultDeny: false, rules: {}, typo: true }), /unknown/i);
  assert.throws(
    () => inline({ rules: { github: { defaultAllow: true, allowChannel: ['C1'] } } }),
    /unknown/i,
  );
});

test('#236 loadPolicy: each rule requires a boolean defaultAllow', () => {
  for (const rule of [
    {},
    { defaultAllow: null },
    { defaultAllow: 0 },
    { defaultAllow: 'true' },
    { defaultAllow: [] },
  ]) {
    assert.throws(
      () => inline({ rules: { github: rule } }),
      /defaultAllow/,
      `must reject ${JSON.stringify(rule)}`,
    );
  }
  assert.throws(() => inline({ rules: { github: null } }), /rule/i);
  assert.throws(() => inline({ rules: { github: [] } }), /rule/i);
});

test('#236 loadPolicy: channel lists must be arrays of strings; empty lists remain valid', () => {
  for (const [field, value] of [
    ['allowChannels', 'C1'],
    ['allowChannels', [1]],
    ['allowChannels', ['C1', null]],
    ['denyChannels', {}],
    ['denyChannels', ['C1', false]],
  ] as const) {
    assert.throws(
      () => inline({ rules: { github: { defaultAllow: true, [field]: value } } }),
      /Channels|channel/i,
      `must reject ${field}=${JSON.stringify(value)}`,
    );
  }

  const loaded = inline({
    rules: { github: { defaultAllow: false, allowChannels: [], denyChannels: [] } },
  });
  assert.equal(loaded.ruleCount, 1);
  assert.equal(loaded.policy.check('github', 'C1'), false);
});

test('#236 loadPolicy: rule provider ids must exactly match configured providers', () => {
  assert.throws(
    () => inline({ rules: { Github: { defaultAllow: true } } }),
    /provider/i,
    'provider membership is case-sensitive',
  );
  assert.throws(
    () => inline({ rules: { unconfigured: { defaultAllow: true } } }),
    /provider/i,
  );
});

test('#236 loadPolicy: default-deny with missing or empty rules is a valid deny-all policy', () => {
  for (const document of [{ defaultDeny: true }, { defaultDeny: true, rules: {} }]) {
    const loaded = inline(document);
    assert.equal(loaded.defaultDeny, true);
    assert.equal(loaded.ruleCount, 0);
    for (const provider of providers) {
      assert.equal(loaded.policy.check(provider.id, 'C1'), false);
      assert.equal(loaded.policy.check(provider.id, null), false);
    }
  }
});

test('#236 loadPolicy: an unruled provider named constructor uses the real no-rule fallback', () => {
  const loaded = inline({
    rules: { github: { defaultAllow: false, allowChannels: ['C_ALLOWED'] } },
  });
  assert.equal(loaded.defaultDeny, false);
  assert.equal(loaded.policy.check('constructor', 'C_ANY'), true);
});

test('#236 loadPolicy: errors never reflect hostile keys, provider ids, channels, JSON, or paths', () => {
  const sentinel = 'SENSITIVE_POLICY_SENTINEL_7f49';
  const dir = mkdtempSync(join(tmpdir(), 'vouchr-policy-redaction-'));
  const invalidFile = join(dir, `${sentinel}.json`);
  writeFileSync(invalidFile, `{${sentinel}`, 'utf8');
  const missingFile = join(dir, `${sentinel}-missing.json`);

  const environments: NodeJS.ProcessEnv[] = [
    { VOUCHR_POLICY: JSON.stringify({ [sentinel]: true }) },
    { VOUCHR_POLICY: JSON.stringify({ rules: { [sentinel]: { defaultAllow: true } } }) },
    {
      VOUCHR_POLICY: JSON.stringify({
        rules: { github: { defaultAllow: true, [sentinel]: true } },
      }),
    },
    {
      VOUCHR_POLICY: JSON.stringify({
        rules: { github: { defaultAllow: true, allowChannels: [sentinel, 7] } },
      }),
    },
    { VOUCHR_POLICY: `{"rules":${sentinel}` },
    { VOUCHR_POLICY_FILE: invalidFile },
    { VOUCHR_POLICY_FILE: missingFile },
  ];

  for (const env of environments) {
    const message = thrownMessage(env);
    assert.equal(message.includes(sentinel), false, message);
    assert.equal(message.includes(invalidFile), false, message);
    assert.equal(message.includes(missingFile), false, message);
  }
});
