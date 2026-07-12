import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  connectBlocks,
  connectedBlocks,
  connectedDmText,
  connectedHtml,
  consentDeniedBlocks,
  statusBlocks,
  disconnectConfirmBlocks,
  homeView,
  DISCONNECT_ACTION,
} from '../src/adapters/blocks';

// Block Kit is untyped here (unknown[]); cast to any for structural probing.
const j = (b: unknown) => JSON.stringify(b);

test('connectedBlocks: interpolates provider + channel and shows how to disconnect', () => {
  const b = connectedBlocks('github', { channel: 'C123', scope: 'repo' }) as any[];
  assert.ok(Array.isArray(b));
  assert.equal(b[0].type, 'section');
  assert.match(b[0].text.text, /github connected/i);
  assert.match(j(b), /<#C123>/); // channel mention
  assert.match(j(b), /repo/); // scope
  assert.match(j(b), /\/vouchr disconnect github/);
});

test('connectedBlocks: null channel renders a DM scope', () => {
  const b = connectedBlocks('github', { channel: null }) as any[];
  assert.match(j(b), /your DMs/);
});

test('connectedBlocks: shows the connected account and granted scope', () => {
  const b = connectedBlocks('github', { channel: 'C123', scope: 'repo read:user', account: 'octocat' }) as any[];
  assert.match(j(b), /Connected as \*octocat\*/);
  assert.match(j(b), /repo read:user/); // granted scope from the token response
});

test('connectedBlocks: escapes provider-controlled markup in account + scope (SEC-5, #176)', () => {
  // accountProbe and the token-response scope string are provider-controlled: a hostile value like
  // `<!channel>` or `<https://evil|click>` must render inert, never as a live mention/link.
  const b = connectedBlocks('<https://evil|gh>', {
    channel: 'C123',
    scope: '<https://evil|scopes>',
    account: '<!channel> <https://evil|click>',
  }) as any[];
  const s = j(b);
  assert.ok(!s.includes('<!channel>')); // no live @channel broadcast
  assert.ok(!s.includes('<https://evil|click>')); // no forged link from the account label
  assert.ok(!s.includes('<https://evil|scopes>')); // nor from the scope string
  assert.ok(!s.includes('<https://evil|gh>')); // provider id escaped too (defense in depth)
  assert.match(s, /&lt;!channel&gt;/); // present, but escaped (inert)
});

test('connectedDmText: the post-OAuth confirmation DM escapes the account label (SEC-5, #176)', () => {
  // This is the exact string bolt's callback route DMs to the connecting user; the DM path has no
  // offline seam (real WebClient), so the renderer is the testable escape site.
  const t = connectedDmText('github', '<!channel> <https://evil|click>');
  assert.ok(!t.includes('<!channel>'));
  assert.ok(!t.includes('<https://evil|click>'));
  assert.match(t, /&lt;!channel&gt;/); // escaped, inert
  assert.equal(connectedDmText('github', null), '✅ github connected.'); // no-account shape unchanged
});

test('connectedHtml: the live post-connect page shows account + granted scopes', () => {
  const html = connectedHtml('github', 'octocat', 'repo read:user');
  assert.match(html, /github connected as octocat/);
  assert.match(html, /repo read:user/); // granted scopes surfaced where the user actually lands
  // No scopes → no granted line (e.g. a provider that doesn't echo scope and has none requested).
  assert.doesNotMatch(connectedHtml('github', 'octocat', ''), /acting as you/);
});

test('connectedHtml: escapes provider-controlled markup (no XSS on the callback page)', () => {
  const html = connectedHtml('github', '</h2><script>alert(1)</script>', 'repo"><img src=x onerror=alert(1)>');
  assert.doesNotMatch(html, /<script/i); // no raw <script> tag can form from the account
  assert.doesNotMatch(html, /<img/i); // nor a raw <img> from the scope string (its `<` is escaped)
  assert.match(html, /&lt;script&gt;/); // the account markup is present, but escaped (inert)
  assert.match(html, /&lt;img/); // and so is the scope markup
});

test('connectBlocks: no scopes renders exactly the intro + button (no scope block)', () => {
  const b = connectBlocks('github', 'https://auth') as any[];
  assert.equal(b.length, 2); // intro section + actions
  assert.doesNotMatch(j(b), /Connecting grants/);
});

test('connectBlocks: escapes the provider id in mrkdwn (SEC-5, #178)', () => {
  // The provider id is registry-validated, but SEC-5 takes no exception — every mrkdwn renderer
  // escapes it, so a `<…|link>`-shaped id must render inert. Scope the assertion to the mrkdwn
  // sections: the button's `plain_text` is rendered literally by Slack (safe, and MUST stay raw —
  // escaping it would surface literal `&lt;` to the user).
  const b = connectBlocks('<https://evil|gh>', 'https://auth') as any[];
  const mrkdwn = b.filter((x: any) => x.text?.type === 'mrkdwn').map((x: any) => x.text.text).join('\n');
  assert.ok(!mrkdwn.includes('<https://evil|gh>')); // no forged link in the mrkdwn body
  assert.match(mrkdwn, /&lt;https/); // present, but escaped
});

test('connectBlocks: renders human-language scope descriptions when passed', () => {
  const b = connectBlocks('github', 'https://auth', {
    list: ['read:user', 'repo'],
    describe: { 'read:user': 'Read your profile', repo: 'Read and write your repositories' },
  }) as any[];
  assert.match(j(b), /Connecting grants the agent, acting as you/);
  assert.match(j(b), /Read your profile/);
  assert.match(j(b), /Read and write your repositories/);
});

test('connectBlocks: an unknown scope falls back to its raw string, never dropped', () => {
  const b = connectBlocks('acme', 'https://auth', {
    list: ['known', 'mystery:scope'],
    describe: { known: 'A known thing' },
  }) as any[];
  assert.match(j(b), /A known thing/);
  assert.match(j(b), /mystery:scope/); // raw fallback, not hidden
});

test('connectBlocks: scope descriptions and fallback ids are inert mrkdwn, and blanks cannot hide a scope', () => {
  const b = connectBlocks('acme', 'https://auth', {
    list: ['known', '<!channel> <@U123>'],
    describe: { known: '   ' },
  }) as any[];
  const mrkdwn = b.filter((x: any) => x.text?.type === 'mrkdwn').map((x: any) => x.text.text).join('\n');

  assert.match(mrkdwn, /• known/); // blank description falls back to the real scope id
  assert.ok(!mrkdwn.includes('<!channel>'));
  assert.ok(!mrkdwn.includes('<@U123>'));
  assert.match(mrkdwn, /&lt;!channel&gt; &lt;@U123&gt;/); // present and truthful, but inert
});

test('connectBlocks: large valid scope copy is split into Slack-compliant sections without hiding scopes', () => {
  const first = '&'.repeat(512);
  const second = '<'.repeat(512);
  const b = connectBlocks('acme', 'https://auth', {
    list: ['first', 'second'],
    describe: { first, second },
  }) as any[];
  const scopeSections = b.filter((x: any) => x.text?.type === 'mrkdwn' && /granted|Connecting grants/.test(x.text.text));
  assert.equal(scopeSections.length, 2);
  assert.ok(scopeSections.every((x: any) => x.text.text.length <= 3000));
  const rendered = scopeSections.map((x: any) => x.text.text).join('\n');
  assert.match(rendered, /&amp;/);
  assert.match(rendered, /&lt;/);
});

test('connectBlocks: a direct caller cannot construct an oversized Slack section', () => {
  assert.throws(
    () => connectBlocks('acme', 'https://auth', { list: ['x'], describe: { x: '&'.repeat(600) } }),
    /scope copy exceeds the Slack section limit/,
  );
});

test('consentDeniedBlocks: states provider, default reason, and next step', () => {
  const b = consentDeniedBlocks('stripe') as any[];
  assert.equal(b[0].type, 'section');
  assert.match(b[0].text.text, /stripe not authorized/i);
  assert.match(j(b), /nothing was sent/i);
  assert.match(j(b), /\/vouchr connect stripe/);
});

test('consentDeniedBlocks: uses a supplied reason', () => {
  const b = consentDeniedBlocks('stripe', 'You clicked deny.') as any[];
  assert.match(j(b), /You clicked deny\./);
});

test('statusBlocks: empty state prompts to connect', () => {
  const b = statusBlocks([]) as any[];
  assert.equal(b.length, 1);
  assert.match(b[0].text.text, /no connections/i);
});

test('statusBlocks: lists each connection with channel + mode', () => {
  const b = statusBlocks([
    { provider: 'github', channel: 'C1', mode: 'shared' },
    { provider: 'stripe', channel: null, mode: 'per-user' },
  ]) as any[];
  assert.equal(b[0].type, 'header');
  const list = b[1].text.text as string;
  assert.match(list, /github/);
  assert.match(list, /<#C1>/);
  assert.match(list, /shared/);
  assert.match(list, /your DMs/);
  assert.match(list, /per-user/);
});

test('disconnectConfirmBlocks: destructive button carries provider in value', () => {
  const b = disconnectConfirmBlocks('github') as any[];
  const actions = b.find((x) => x.type === 'actions');
  assert.ok(actions);
  const btn = actions.elements[0];
  assert.equal(btn.type, 'button');
  assert.equal(btn.action_id, DISCONNECT_ACTION);
  assert.equal(btn.value, 'github');
  assert.equal(btn.style, 'danger');
});

test('homeView: returns a home view listing connections and available providers', () => {
  const v = homeView({
    connections: [{ provider: 'github', channel: 'C1', mode: 'shared' }],
    providers: ['github', 'stripe'],
  }) as any;
  assert.equal(v.type, 'home');
  assert.ok(Array.isArray(v.blocks));
  const s = j(v.blocks);
  assert.match(s, /github/); // connected
  assert.match(s, /stripe/); // available (not connected)
  // github is already connected, so it should not appear under "Available providers"
  const avail = v.blocks.find((x: any) => x.type === 'section' && /Available providers/.test(x.text?.text ?? ''));
  assert.ok(avail);
  assert.doesNotMatch(avail.text.text, /github/);
});

test('homeView: empty connections still renders a valid home view', () => {
  const v = homeView({ connections: [], providers: ['github'] }) as any;
  assert.equal(v.type, 'home');
  assert.match(j(v.blocks), /None yet/i);
});
