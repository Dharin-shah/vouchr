import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connectedHtml } from '../src/core/landing';

const ID = { enterpriseId: null, teamId: 'T0WORKSPACE', userId: 'U0FORWARD' };

test('connectedHtml: shows the provider account and granted scopes', () => {
  const html = connectedHtml('github', 'octocat', 'repo read:user', ID);
  assert.match(html, /github connected as octocat/);
  assert.match(html, /repo read:user/); // granted scopes surfaced where the user actually lands
  // No scopes → no "with:" clause (a provider that doesn't echo scope and has none requested).
  assert.doesNotMatch(connectedHtml('github', 'octocat', undefined, ID), /with: <code>/);
  // The old, false "acting as you" copy must be gone: it lies to a forwarded-link completer.
  assert.doesNotMatch(html, /acting as you/);
});

test('connectedHtml: names the bound Slack identity so a forwarded link is detectable', () => {
  const html = connectedHtml('github', 'octocat', 'repo', ID);
  assert.match(html, /U0FORWARD/); // whoever completes the OAuth sees which Slack user it empowers
  assert.match(html, /T0WORKSPACE/);
  assert.match(html, /not you/i);
  // The concrete provider account is the human-recognizable anchor (not only opaque U/T ids).
  assert.match(html, /your github account \(octocat\) to someone else/i);
});

test('connectedHtml: escapes every provider- and user-controlled value (no XSS)', () => {
  const html = connectedHtml(
    'github',
    '</h2><script>alert(1)</script>',
    'repo"><img src=x onerror=alert(1)>',
    { enterpriseId: null, teamId: 'T', userId: '<script>u</script>' },
  );
  assert.doesNotMatch(html, /<script/i); // no raw <script> from account or user id
  assert.doesNotMatch(html, /<img/i); // no raw <img> from the scope string
  assert.match(html, /&lt;script&gt;/); // present but escaped (inert)
});
