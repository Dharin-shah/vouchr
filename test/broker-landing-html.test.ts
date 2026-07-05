import { test } from 'node:test';
import assert from 'node:assert/strict';
import { landingHtml } from '../src/adapters/http/broker';

// #52 reflected-XSS guard: landingHtml() now escapes its title/body internally, so the OAuth callback
// page can't reflect a provider-/attacker-influenced value (account, error, provider) as live markup.
test('landingHtml escapes markup in both title and body (no reflected XSS)', () => {
  const html = landingHtml('</h2><script>alert(1)</script>', '<img src=x onerror=alert(1)>');
  assert.doesNotMatch(html, /<script/i);       // no raw <script> from the title
  assert.doesNotMatch(html, /<img\s/i);         // no raw <img> from the body
  assert.match(html, /&lt;script&gt;/);         // title markup present but inert
  assert.match(html, /&lt;img/);                // body markup present but inert
});

test('landingHtml leaves ordinary text (and the ✅ emoji) intact', () => {
  const html = landingHtml('✅ github connected as octocat', 'You can close this tab and return to your app.');
  assert.match(html, /✅ github connected as octocat/);
  assert.match(html, /You can close this tab/);
});
