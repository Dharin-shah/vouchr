import Anthropic from '@anthropic-ai/sdk';
import { betaTool } from '@anthropic-ai/sdk/helpers/beta/json-schema';
import { App, ExpressReceiver } from '@slack/bolt';
import {
  ConsentRequiredError,
  createVouchr,
  defineProvider,
  github,
  google,
  notion,
  safeUserMessage,
  type Provider,
} from '../../src';

/**
 * One agent, many providers, N humans — each acting as themselves.
 *
 * A discussion happens in a Slack thread. People ask the agent to do things that live in different
 * systems: file this question on the PR, put it on my calendar, add it to the meeting notes. The
 * agent picks the provider from the request; Vouchr decides whose credential that becomes.
 *
 * Three properties this shows, none of which a screenshot can fake:
 *
 *  1. The agent holds no credential of its own. Vouchr resolves one from the VERIFIED Slack
 *     identity on the event, so Alice's comment is authored by Alice because Alice asked — not
 *     because the model said so. There is no user-id argument to get wrong.
 *  2. The provider list is the CHANNEL's, not the code's. `toolManifest()` returns what an admin
 *     enabled here, and that becomes the model's tool enum. Channels are deny-by-default, so an
 *     agent in a channel where nothing is enabled can reach nothing.
 *  3. The model chooses the URL. That is the generic-HTTP-tool shape prompt injection loves, and
 *     it is safe only because the egress gates run before the credential is read. When the model
 *     picks a host or method the provider never declared, the request is refused and the user is
 *     told — see the `EgressBlockedError` path below, which is a demo beat, not an edge case.
 */

const anthropic = new Anthropic(); // ANTHROPIC_API_KEY

/** Register whichever providers this deployment has OAuth credentials for. */
function configuredProviders(): Provider[] {
  const out: Provider[] = [];
  if (process.env.GITHUB_CLIENT_ID) {
    // Writes are narrowed at the provider, not in the agent: the model may POST a comment and
    // nothing else. `DELETE /repos/{owner}/{repo}` is refused even though the user's token allows it.
    out.push(defineProvider({
      ...github({ scopes: ['read:user', 'public_repo'] }),
      egressMethods: ['GET', 'POST'],
      egressPaths: ['/repos', '/user'],
    }));
  }
  if (process.env.GOOGLE_CLIENT_ID) {
    out.push(defineProvider({
      ...google({ scopes: ['openid', 'email', 'https://www.googleapis.com/auth/calendar.events'] }),
      egressMethods: ['GET', 'POST'],
      egressPaths: ['/calendar/v3'],
    }));
  }
  if (process.env.NOTION_CLIENT_ID) {
    out.push(defineProvider({
      ...notion(),
      egressMethods: ['GET', 'POST', 'PATCH'],
      egressPaths: ['/v1/pages', '/v1/blocks', '/v1/search'],
    }));
  }
  if (!out.length) throw new Error('Configure at least one provider — see the README.');
  return out;
}

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

app.event('app_mention', async ({ context, event, client, say }) => {
  const thread = (event as { thread_ts?: string }).thread_ts ?? event.ts;
  const vouchr = context.vouchr;

  // The channel's tool manifest IS the model's tool surface. `acting_human` entries are the ones
  // Vouchr brokers; a `service` tool is the host's own to wire up, so it is not offered here.
  const manifest = await vouchr.toolManifest();
  const usable = manifest.filter((t) => t.enabled && t.identity === 'acting_human').map((t) => t.provider);
  if (!usable.length) {
    await say({ thread_ts: thread, text: 'No providers are enabled in this channel yet — an admin can run `/vouchr enable <provider>`.' });
    return;
  }

  // One tool, provider chosen from the manifest. The model decides which system the request means.
  const callProvider = betaTool({
    name: 'call_provider',
    description:
      'Make one HTTPS request to a connected provider AS the person who asked. Choose the provider '
      + 'that owns the thing being asked for. The credential is attached by Vouchr; you never see it '
      + 'and must not ask for it. Requests outside a provider\'s allowed hosts, paths, or methods are '
      + 'refused — if that happens, say so rather than retrying a different way.',
    inputSchema: {
      type: 'object',
      properties: {
        provider: { type: 'string', enum: usable, description: 'Which connected provider to act on.' },
        method: { type: 'string', enum: ['GET', 'POST', 'PATCH'], description: 'HTTP method.' },
        url: { type: 'string', description: 'Absolute https URL of the provider API endpoint.' },
        body: { type: 'string', description: 'JSON request body, omitted for GET.' },
      },
      required: ['provider', 'method', 'url'],
      additionalProperties: false,
    },
    run: async ({ provider, method, url, body }) => {
      // connect() resolves the credential for the ACTING human and re-checks mode, policy, channel
      // tools and session state. It throws ConsentRequiredError if this person has not connected —
      // which is per-person: one participant connecting does nothing for the others.
      const handle = await vouchr.connect(provider);
      const res = await handle.fetch(url, {
        method,
        ...(body ? { headers: { 'content-type': 'application/json' }, body } : {}),
      });
      const text = await res.text();
      // Return the status too: the model needs to know a 4xx happened rather than assume success.
      return `HTTP ${res.status}\n${text.slice(0, 4000)}`;
    },
  });

  try {
    const replies = await client.conversations.replies({ channel: event.channel, ts: thread });
    const transcript = (replies.messages ?? [])
      .map((m) => `${m.user ?? 'unknown'}: ${m.text ?? ''}`)
      .join('\n');

    const final = await anthropic.beta.messages.toolRunner({
      model: 'claude-opus-5',
      // Thinking is on by default on this model and shares the budget with the reply — leave room.
      max_tokens: 8192,
      output_config: { effort: 'low' },
      tools: [callProvider],
      system:
        `You act on behalf of <@${event.user}> in a Slack thread. Available providers: ${usable.join(', ')}.\n`
        + 'Pick the provider that owns what they asked for and make the smallest request that does it. '
        + 'Then reply in one or two sentences saying what you did and, where the provider tells you, '
        + 'under which account. If a request is refused, say plainly what was refused and stop — do not '
        + 'try another host or method to get around it.',
      messages: [{ role: 'user', content: `Thread:\n${transcript}\n\nDo what they just asked.` }],
    });

    const reply = final.content
      .filter((b): b is Anthropic.Beta.BetaTextBlock => b.type === 'text')
      .map((b) => b.text).join('').trim();
    await say({ thread_ts: thread, text: reply || 'Done.' });
  } catch (e) {
    // Vouchr already posted this person a private Connect prompt; nobody else in the thread is
    // affected, and the next person to ask gets their own.
    if (e instanceof ConsentRequiredError) return;
    // Everything else — including an egress refusal — becomes fixed, leak-safe copy.
    await say({ thread_ts: thread, text: safeUserMessage(e) });
  }
});

(async () => {
  for (const v of ['PUBLIC_URL', 'ANTHROPIC_API_KEY']) {
    if (!process.env[v]) throw new Error(`${v} is required — see examples/multi-provider-agent/README.md`);
  }
  const providers = configuredProviders();
  const vouchr = await createVouchr({
    providers,
    baseUrl: process.env.PUBLIC_URL!,
    // The second of the two write opt-ins. Without it every provider above is intersected down to
    // GET/HEAD regardless of what it declares, and the agent becomes read-only.
    allowWrites: true,
  });
  vouchr.install(app, receiver);

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ multi-provider agent on :${port} (${providers.map((p) => p.id).join(', ')})`);
  console.log(`   Callback at ${process.env.PUBLIC_URL}/vouchr/oauth/callback`);
})();
