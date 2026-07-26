import Anthropic from '@anthropic-ai/sdk';
import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, defineProvider, github, ConsentRequiredError, safeUserMessage } from '../../src';

/**
 * Thread → GitHub, as the person who asked.
 *
 * A design discussion happens in a Slack thread. Each participant asks the agent to file their own
 * open question on a PR. Three people ask, three GitHub comments appear — authored by three
 * different GitHub accounts, each the real human who spoke.
 *
 * That is the whole point, and it is the part a screenshot cannot fake: the agent has no GitHub
 * token of its own and cannot act for anyone who has not connected. Vouchr resolves the credential
 * from the VERIFIED Slack identity on the event, so Alice's comment is authored by Alice because
 * Alice asked — not because the agent was told she did.
 *
 * The model reads the thread and drafts the comment. It never sees a token: `gh.fetch` attaches the
 * credential inside Vouchr at the outbound HTTP boundary.
 */

// The write path needs BOTH opt-ins. Neither alone is enough:
//   1. this provider declares the methods and paths it accepts, and
//   2. `allowWrites: true` on createVouchr below.
// So a prompt-injected `DELETE /repos/owner/repo` is refused before the credential is read, even
// though the agent legitimately holds a token that could do it.
const githubComments = defineProvider({
  ...github({ scopes: ['read:user', 'public_repo'] }),
  egressMethods: ['GET', 'POST'],
  egressPaths: ['/repos', '/user'],
});

const REPO = process.env.GITHUB_REPO!;        // "owner/name"
const ISSUE = process.env.GITHUB_ISSUE!;      // issue or PR number
const anthropic = new Anthropic();            // reads ANTHROPIC_API_KEY

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

/** Ask the model for THIS person's open question, from the thread they are standing in. */
async function draftComment(transcript: string, speaker: string): Promise<string> {
  const message = await anthropic.messages.create({
    model: 'claude-opus-5',
    // Thinking is on by default on this model and shares the budget with the reply, so leave
    // headroom even though the output itself is short.
    max_tokens: 4096,
    output_config: { effort: 'low' },
    system:
      'You extract one open question from a Slack design discussion and rewrite it as a GitHub '
      + 'comment. Output only the comment body: one or two sentences, no preamble, no greeting, no '
      + 'sign-off, no markdown headers. Write it in the first person, as the speaker. If the '
      + 'speaker asked nothing answerable, output exactly: NONE',
    messages: [{
      role: 'user',
      content: `Thread:\n${transcript}\n\nWrite ${speaker}'s open question as a GitHub comment.`,
    }],
  });
  return message.content
    .filter((b): b is Anthropic.TextBlock => b.type === 'text')
    .map((b) => b.text)
    .join('')
    .trim();
}

app.event('app_mention', async ({ context, event, client, say }) => {
  const thread = (event as { thread_ts?: string }).thread_ts ?? event.ts;
  try {
    // 1. The credential Vouchr resolves belongs to whoever sent THIS event. There is no user id
    //    argument to get wrong, and nothing the model says can change whose account is used.
    const gh = await context.vouchr.connect('github');

    // 2. Reading the thread is the host's job, with the host's own bot token — not Vouchr's.
    const replies = await client.conversations.replies({ channel: event.channel, ts: thread });
    const transcript = (replies.messages ?? [])
      .map((m) => `${m.user ?? 'unknown'}: ${m.text ?? ''}`)
      .join('\n');

    const body = await draftComment(transcript, event.user ?? 'the speaker');
    if (body === 'NONE' || !body) {
      await say({ thread_ts: thread, text: "I couldn't find an open question from you in this thread." });
      return;
    }

    // 3. The write. The model drafted `body`; it never held the token that posts it.
    const res = await gh.fetch(`https://api.github.com/repos/${REPO}/issues/${ISSUE}/comments`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ body }),
    });
    if (!res.ok) {
      await say({ thread_ts: thread, text: `GitHub rejected that (${res.status}).` });
      return;
    }
    const comment = await res.json() as { html_url: string; user: { login: string } };

    // The payoff line: GitHub itself reports who authored it.
    await say({
      thread_ts: thread,
      text: `Filed as *${comment.user.login}* on ${REPO}#${ISSUE} — ${comment.html_url}`,
    });
  } catch (e) {
    // ConsentRequiredError means Vouchr already posted a private Connect prompt to this user.
    // Whoever has not connected yet simply connects; nobody else in the thread is affected.
    if (e instanceof ConsentRequiredError) return;
    await say({ thread_ts: thread, text: safeUserMessage(e) });
  }
});

(async () => {
  for (const v of ['GITHUB_REPO', 'GITHUB_ISSUE', 'PUBLIC_URL', 'ANTHROPIC_API_KEY']) {
    if (!process.env[v]) throw new Error(`${v} is required — see examples/thread-to-github/README.md`);
  }
  const vouchr = await createVouchr({
    providers: [githubComments],
    baseUrl: process.env.PUBLIC_URL!,
    // The second opt-in. Without it every provider is intersected down to GET/HEAD and the POST
    // above is refused — which is the right default for an agent that only needs to read.
    allowWrites: true,
  });
  vouchr.install(app, receiver);

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ thread → ${REPO}#${ISSUE} on :${port}. Callback at ${process.env.PUBLIC_URL}/vouchr/oauth/callback`);
})();
