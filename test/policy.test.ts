import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Policy } from '../src/core/policy';

test('policy: default allow-all mode unchanged', () => {
  const p = new Policy({
    payments: { defaultAllow: false, allowChannels: ['C_FIN'] },
    github: { defaultAllow: true, denyChannels: ['C_PUBLIC'] },
  });
  assert.equal(p.check('unknown', 'C1'), true); // no rule => allow
  assert.equal(p.check('github', 'C_PUBLIC'), false); // denyChannels blocks
  assert.equal(p.check('github', 'C1'), true);
  assert.equal(p.check('payments', 'C1'), false); // defaultAllow:false gates
  assert.equal(p.check('payments', 'C_FIN'), true); // allowChannels permits
  assert.equal(new Policy().check('anything', 'C1'), true); // no-arg ctor allows
});

test('policy: default-deny mode denies unruled providers but honors explicit rules', () => {
  const p = new Policy(
    {
      payments: { defaultAllow: false, allowChannels: ['C_FIN'] },
      github: { defaultAllow: true, denyChannels: ['C_PUBLIC'] },
    },
    { defaultDeny: true },
  );
  assert.equal(p.check('unknown', 'C1'), false); // no rule => denied
  assert.equal(p.check('github', 'C1'), true); // defaultAllow:true allows
  assert.equal(p.check('github', 'C_PUBLIC'), false); // denyChannels blocks
  assert.equal(p.check('payments', 'C1'), false); // allowChannels gates
  assert.equal(p.check('payments', 'C_FIN'), true);
});

test('policy: inherited object keys use the documented no-rule fallback unless explicitly configured', () => {
  for (const provider of ['constructor', 'toString']) {
    assert.equal(new Policy().check(provider, 'C1'), true);
    assert.equal(new Policy({}, { defaultDeny: true }).check(provider, 'C1'), false);
  }

  const configured = new Policy({ constructor: { defaultAllow: false, allowChannels: ['C_ALLOWED'] } });
  assert.equal(configured.check('constructor', 'C_ALLOWED'), true);
  assert.equal(configured.check('constructor', 'C_OTHER'), false);
});
