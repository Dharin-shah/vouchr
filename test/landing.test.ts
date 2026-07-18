import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connectedHtml } from '../src/adapters/landing';

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

test('connectedHtml: the bound identity is human-recognizable (deep link), not only raw ids', () => {
  const html = connectedHtml('github', 'octocat', 'repo', ID);
  assert.match(html, /U0FORWARD/); // the id is present...
  assert.match(html, /T0WORKSPACE/);
  // ...but the completer also gets a clickable slack:// profile link to see WHO it actually is,
  // rather than being asked to recognize an opaque U…/T… id.
  assert.match(html, /href="slack:\/\/user\?team=T0WORKSPACE&amp;id=U0FORWARD"/);
  assert.match(html, /not you/i);
});

test('connectedHtml: the disclosure holds when the provider account is null', () => {
  // account can be null (no probe / provider returns none); the copy must not depend on it.
  const html = connectedHtml('github', null, undefined, ID);
  assert.match(html, /connected this github account to someone else/i);
  assert.match(html, /href="slack:\/\/user/); // the recognizable anchor is still the deep link
  assert.doesNotMatch(html, /\(\)/); // no empty "( )" where the account name would be
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
