import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Static validation of the reference Kubernetes manifest (#216, #258). No YAML dependency: the
// checks are string/structural so a security control silently dropped from either pod template
// (the migrate Job OR the Deployment) fails CI instead of only being caught at `kubectl apply`.
const manifest = readFileSync(join(process.cwd(), 'deploy', 'k8s.yaml'), 'utf8');
const docs = manifest.split(/^---$/m);
const kindOf = (doc: string): string => doc.match(/^kind:\s*(\w+)/m)?.[1] ?? '';
const podTemplates = docs.filter((d) => kindOf(d) === 'Job' || kindOf(d) === 'Deployment');

test('the manifest has exactly two workload pod templates (migrate Job + broker Deployment)', () => {
  assert.deepEqual(podTemplates.map(kindOf).sort(), ['Deployment', 'Job']);
});

test('both pod templates run non-root with RuntimeDefault seccomp', () => {
  for (const doc of podTemplates) {
    assert.match(doc, /runAsNonRoot:\s*true/, `${kindOf(doc)} pod must set runAsNonRoot: true`);
    assert.match(doc, /seccompProfile:\s*\{\s*type:\s*RuntimeDefault\s*\}/, `${kindOf(doc)} pod must set RuntimeDefault seccomp`);
  }
});

test('no pod pins a numeric UID/GID — the platform selects an arbitrary non-root identity (#216)', () => {
  // The image supplies a numeric non-root default (Dockerfile USER 1000:1000); pinning runAsUser
  // here would break Restricted platforms that allocate a namespace UID range.
  assert.doesNotMatch(manifest, /runAsUser:/);
  assert.doesNotMatch(manifest, /runAsGroup:/);
});

test('both containers carry the Restricted container-level controls', () => {
  for (const doc of podTemplates) {
    assert.match(doc, /allowPrivilegeEscalation:\s*false/, `${kindOf(doc)} container must set allowPrivilegeEscalation: false`);
    assert.match(doc, /readOnlyRootFilesystem:\s*true/, `${kindOf(doc)} container must set readOnlyRootFilesystem: true`);
    assert.match(doc, /capabilities:\s*\{\s*drop:\s*\["ALL"\]\s*\}/, `${kindOf(doc)} container must drop ALL capabilities`);
  }
});

test('both containers bound CPU and memory in requests AND limits', () => {
  // A request only affects scheduling; a limit is the hard ceiling. Require both dimensions on both.
  for (const doc of podTemplates) {
    const requests = doc.match(/requests:\s*\{([^}]*)\}/)?.[1] ?? '';
    const limits = doc.match(/limits:\s*\{([^}]*)\}/)?.[1] ?? '';
    assert.match(requests, /cpu:/, `${kindOf(doc)} must request cpu`);
    assert.match(requests, /memory:/, `${kindOf(doc)} must request memory`);
    assert.match(limits, /cpu:/, `${kindOf(doc)} must set a cpu LIMIT (a request is not a ceiling)`);
    assert.match(limits, /memory:/, `${kindOf(doc)} must set a memory limit`);
  }
});
