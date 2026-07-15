import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  auditBlocks,
  blocksFallbackText,
  configModal,
  configureModal,
  connectBlocks,
  connectedBlocks,
  connectedDmText,
  connectedHtml,
  connectionLine,
  consentDeniedBlocks,
  statusBlocks,
  disconnectConfirmBlocks,
  homeView,
  keySetupBlocks,
  sessionApprovalBlocks,
  statsBlocks,
  userKeyModal,
  DISCONNECT_ACTION,
} from '../src/adapters/blocks';

// Block Kit is untyped here (unknown[]); cast to any for structural probing.
const j = (b: unknown) => JSON.stringify(b);

const mrkdwnTexts = (value: unknown): string[] => {
  const out: string[] = [];
  const visit = (item: unknown): void => {
    if (Array.isArray(item)) {
      for (const child of item) visit(child);
      return;
    }
    if (!item || typeof item !== 'object') return;
    const object = item as Record<string, unknown>;
    if (object.type === 'mrkdwn' && typeof object.text === 'string') out.push(object.text);
    for (const child of Object.values(object)) visit(child);
  };
  visit(value);
  return out;
};

const sectionTexts = (blocks: unknown[]): string[] =>
  (blocks as any[])
    .filter((block) => block.type === 'section' && block.text?.type === 'mrkdwn')
    .map((block) => block.text.text as string);

const assertPackedRows = (blocks: unknown[], providers: string[]): void => {
  const sections = sectionTexts(blocks);
  assert.ok(sections.length > 0);
  assert.ok(sections.every((text) => text.length <= 3000));
  const rows = sections.flatMap((text) => text.split('\n')).filter((line) => line.startsWith('• '));
  assert.equal(rows.length, providers.length);
  providers.forEach((provider, index) => {
    assert.ok(rows[index].includes(provider), `row ${index} lost or reordered`);
  });
};

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

test('credential and session renderers escape mrkdwn but preserve literal interaction data', () => {
  const provider = '<!channel> & <https://evil.example|click>';
  const escaped = '&lt;!channel&gt; &amp; &lt;https://evil.example|click&gt;';
  const configure = configureModal(provider, 'C1') as any;
  const userKey = userKeyModal(provider) as any;
  const keySetup = keySetupBlocks(provider) as any[];
  const session = sessionApprovalBlocks(provider, 'TH1') as any[];

  for (const [name, rendered] of [
    ['configureModal', configure],
    ['userKeyModal', userKey],
    ['keySetupBlocks', keySetup],
    ['sessionApprovalBlocks', session],
  ] as const) {
    const mrkdwn = mrkdwnTexts(rendered).join('\n');
    assert.ok(!mrkdwn.includes(provider), `${name} rendered live provider mrkdwn`);
    assert.ok(mrkdwn.includes(escaped), `${name} dropped or altered the escaped provider`);
  }

  // Modal routing data and interactive controls are not mrkdwn: keep the exact literal provider so
  // escaping cannot change which registry entry a valid submission/click targets.
  assert.equal(JSON.parse(configure.private_metadata).provider, provider);
  assert.equal(JSON.parse(userKey.private_metadata).provider, provider);
  const keyButton = keySetup.find((block) => block.type === 'actions').elements[0];
  assert.equal(keyButton.text.text, `Set up ${provider}`);
  assert.equal(keyButton.value, provider);
  const sessionButton = session.find((block) => block.type === 'actions').elements[0];
  assert.equal(sessionButton.text.text, `Allow ${provider} here`);
  assert.deepEqual(JSON.parse(sessionButton.value), { provider, thread: 'TH1' });
});

test('credential modals advertise only reference sources available in their process', () => {
  const compatibleDefault = configureModal('acme', 'C1') as any;
  assert.equal(compatibleDefault.blocks.some((block: any) => block.block_id === 'ref'), true);

  const rawOnly = configureModal('acme', 'C1', []) as any;
  assert.equal(rawOnly.blocks.some((block: any) => block.block_id === 'ref'), false);
  assert.equal(rawOnly.blocks.find((block: any) => block.block_id === 'raw').label.text, 'Paste a key directly');

  const gcp = userKeyModal('acme', ['gcp-sm']) as any;
  const gcpRef = gcp.blocks.find((block: any) => block.block_id === 'ref');
  assert.match(gcpRef.hint.text, /GCP Secret Manager/);
  assert.ok(!gcpRef.hint.text.includes('AWS'));
  assert.equal(gcpRef.element.placeholder.text, 'gcp-sm://projects/…/versions/latest');

  const multi = configureModal('acme', 'C1', ['azure-kv', 'vault']) as any;
  const multiRef = multi.blocks.find((block: any) => block.block_id === 'ref');
  assert.match(multiRef.hint.text, /Azure Key Vault/);
  assert.match(multiRef.hint.text, /HashiCorp Vault/);
  assert.equal(multiRef.element.placeholder.text, 'Paste a supported reference');
});

test('auditBlocks escapes a caller-supplied heading when the empty state renders it as mrkdwn', () => {
  const text = sectionTexts(auditBlocks([], '<!channel> & usage'))[0];
  assert.doesNotMatch(text, /<!channel>/);
  assert.match(text, /&lt;!channel&gt; &amp; usage/);
});

test('consentDeniedBlocks: states provider, default reason, and next step', () => {
  const b = consentDeniedBlocks('stripe') as any[];
  assert.equal(b[0].type, 'section');
  assert.match(b[0].text.text, /stripe not authorized/i);
  assert.match(j(b), /nothing was sent/i);
  assert.match(j(b), /re-run the request/i); // truthful recovery (on-demand), not a phantom command
  assert.doesNotMatch(j(b), /\/vouchr connect/); // #194: never advertise a command that doesn't exist
});

test('consentDeniedBlocks: never renders an arbitrary supplied reason', () => {
  const sentinel = 'ghp_RAW_PROVIDER_ERROR_MUST_NOT_REACH_SLACK';
  const b = consentDeniedBlocks('stripe', `Provider failed: ${sentinel} <!channel>`) as any[];
  const rendered = j(b);
  assert.ok(!rendered.includes(sentinel));
  assert.doesNotMatch(rendered, /Provider failed|<!channel>/);
  assert.match(rendered, /haven't allowed stripe/);
});

test('consentDeniedBlocks: escapes provider in mrkdwn', () => {
  const rendered = j(consentDeniedBlocks('<!channel>'));
  assert.doesNotMatch(rendered, /<!channel>/);
  assert.match(rendered, /&lt;!channel&gt;/);
});

test('statusBlocks: empty state explains on-demand connection without a phantom command', () => {
  const b = statusBlocks([]) as any[];
  assert.equal(b.length, 1);
  assert.match(b[0].text.text, /no connections/i);
  assert.match(b[0].text.text, /on demand/i);
  assert.doesNotMatch(b[0].text.text, /\/vouchr connect/); // #194: no guidance for a command that doesn't exist
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

test('connectionLine preserves a maximum account label losslessly while escaping mrkdwn', () => {
  const account = '&'.repeat(512);
  const line = connectionLine({ provider: 'mcp', channel: null, account });
  assert.ok(line.includes('&amp;'.repeat(512)));
  assert.doesNotMatch(line, /…/);
});

test('shared row packer accepts 3000 chars, splits 3001 losslessly, and rejects one oversized row', () => {
  const connectionWithLength = (length: number, provider: string) => {
    const fixed = connectionLine({ provider, channel: null }).length - provider.length;
    const connection = { provider: provider + 'x'.repeat(length - fixed - provider.length), channel: null };
    assert.equal(connectionLine(connection).length, length);
    return connection;
  };

  const atLimit = connectionWithLength(3000, 'a');
  assert.deepEqual(sectionTexts(statusBlocks([atLimit])), [connectionLine(atLimit)]);
  assert.throws(() => statusBlocks([connectionWithLength(3001, 'b')]), /Slack section limit/);

  const first = connectionWithLength(1500, 'c');
  const secondAtLimit = connectionWithLength(1499, 'd');
  const exactly = sectionTexts(statusBlocks([first, secondAtLimit]));
  assert.equal(exactly.length, 1);
  assert.equal(exactly[0].length, 3000); // 1500 + newline + 1499

  const secondOver = connectionWithLength(1500, 'e');
  const split = sectionTexts(statusBlocks([first, secondOver]));
  assert.deepEqual(split, [connectionLine(first), connectionLine(secondOver)]);
});

test('max registry tables stay section-bounded and preserve all rows in order', () => {
  const providers = Array.from({ length: 128 }, (_, index) => {
    const prefix = `p${String(index).padStart(3, '0')}`;
    return prefix + 'x'.repeat(63 - prefix.length);
  });

  assertPackedRows(statsBlocks(providers, [], 30), providers);
  const statusProviders = providers.slice(0, 14);
  const status = statusBlocks(statusProviders.map((provider) => ({
    provider,
    channel: null,
    mode: 'per-user',
    account: '&'.repeat(512), // supported stored-label maximum; escaping expands this fivefold
  })), { page: 1, totalPages: 10 });
  assertPackedRows(status, statusProviders);
  assert.ok(status.length <= 50);

  const modal = configModal({
    channel: 'C1',
    connections: [],
    tools: providers.map((provider) => ({ provider, enabled: true, mode: 'per-user' })),
  }) as any;
  assertPackedRows(modal.blocks, providers);
  assert.ok(modal.blocks.length <= 100);

  // Audit's production callers request at most 20 rows; that caller bound still needs lossless
  // section packing when conservative maximum provider ids make the joined table exceed 3000.
  const auditProviders = providers.slice(0, 20);
  assertPackedRows(auditBlocks(auditProviders.map((provider, index) => ({
    provider,
    action: 'approval_consumed',
    actor: `U${index}`,
    channel: `C${index}`,
    at: 1_750_000_000_000 + index,
  })), 'Your credential usage'), auditProviders);
});

test('configModal rejects an over-block view before Slack can truncate or reject it', () => {
  const providers = Array.from({ length: 128 }, (_, index) => `p${index}`);
  assert.throws(() => configModal({
    channel: 'C1',
    connections: [],
    tools: providers.map((provider) => ({ provider, enabled: true, mode: 'per-user' })),
    admin: providers.map((provider) => ({ provider, enabled: true, mode: 'per-user', visibility: 'public' })),
  }), /Slack modal block limit/);
});

test('configModal enforces Slack private_metadata independently of the block count', () => {
  const providers = Array.from({ length: 28 }, (_, index) => {
    const prefix = `p${String(index).padStart(2, '0')}`;
    return prefix + 'x'.repeat(63 - prefix.length);
  });
  const build = (ids: string[]) => configModal({
    channel: 'C1',
    connections: [],
    tools: ids.map((provider) => ({ provider, enabled: true, mode: 'per-user' })),
    admin: ids.map((provider) => ({ provider, enabled: true, mode: 'per-user', visibility: 'public' })),
  }) as any;

  const withinLimit = build(providers.slice(0, 27));
  assert.ok(withinLimit.blocks.length <= 100);
  assert.ok(withinLimit.private_metadata.length <= 3_000);
  assert.throws(() => build(providers), /Slack modal private_metadata limit/);
});

test('configModal bounds connection buttons and points every omitted row to paged status', () => {
  const connections = Array.from({ length: 25 }, (_, i) => ({
    provider: `retired-${String(i).padStart(2, '0')}`,
    channel: null,
  }));
  const modal = configModal({ channel: 'C1', connections, tools: [] }) as any;
  const disconnects = modal.blocks.filter((block: any) => block.accessory?.action_id === DISCONNECT_ACTION);
  assert.equal(disconnects.length, 10);
  assert.match(JSON.stringify(modal.blocks), /\+15 more/);
  assert.ok(JSON.stringify(modal.blocks).includes('`/vouchr status`'));
  assert.ok(modal.blocks.length <= 100);
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

test('disconnectConfirmBlocks: provider is inert in mrkdwn but literal in plain_text/value', () => {
  const provider = '<@U123>';
  const b = disconnectConfirmBlocks(provider) as any[];
  const section = b.find((x) => x.type === 'section');
  const button = b.find((x) => x.type === 'actions').elements[0];
  assert.doesNotMatch(section.text.text, /<@U123>/);
  assert.match(section.text.text, /&lt;@U123&gt;/);
  assert.equal(button.text.text, `Disconnect ${provider}`);
  assert.equal(button.value, provider);
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

test('blocksFallbackText includes visible copy only and safely promotes plain_text into mrkdwn', () => {
  const hidden = 'HIDDEN_URL_VALUE_METADATA_OR_INPUT';
  const fallback = blocksFallbackText([
    { type: 'header', text: { type: 'plain_text', text: '<Header &>' }, private_metadata: hidden },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: '*Body* &lt;safe&gt;' },
      fields: [{ type: 'mrkdwn', text: 'Field copy' }],
      accessory: {
        type: 'button', text: { type: 'plain_text', text: '<Open>' }, url: hidden, value: hidden,
      },
    },
    { type: 'context', elements: [{ type: 'mrkdwn', text: 'Context copy' }] },
    {
      type: 'actions',
      elements: [
        { type: 'button', text: { type: 'plain_text', text: '<Approve>' }, url: hidden, value: hidden },
        { type: 'button', text: { type: 'plain_text', text: 'Deny & close' }, value: hidden },
      ],
    },
    {
      type: 'input',
      label: { type: 'plain_text', text: hidden },
      element: { type: 'plain_text_input', action_id: hidden, initial_value: hidden },
    },
  ]);

  assert.equal(fallback, [
    '&lt;Header &amp;&gt;',
    '*Body* &lt;safe&gt;',
    'Field copy',
    '&lt;Open&gt;',
    'Context copy',
    '&lt;Approve&gt;',
    'Deny &amp; close',
  ].join('\n'));
  assert.ok(!fallback.includes(hidden));
});

test('blocksFallbackText accepts exactly 40000 chars and rejects truncation-prone output', () => {
  const blocksForLength = (length: number): unknown[] => {
    const full = Array.from({ length: 13 }, () => 'x'.repeat(3000));
    const tail = 'x'.repeat(length - full.join('\n').length - 1);
    return [...full, tail].map((text) => ({ type: 'section', text: { type: 'mrkdwn', text } }));
  };

  assert.equal(blocksFallbackText(blocksForLength(40_000)).length, 40_000);
  assert.throws(() => blocksFallbackText(blocksForLength(40_001)), /top-level message limit/);
  assert.throws(() => blocksFallbackText([{ type: 'divider' }]), /no visible block copy/);
});
