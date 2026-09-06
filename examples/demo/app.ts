import { App, ExpressReceiver } from '@slack/bolt';
import {
  ApprovalRequiredError,
  ConsentRequiredError,
  createVouchr,
  defineProvider,
  github,
  safeUserMessage,
} from '../../src';

// The demo app behind guides/DEMO.md: examples/bolt-github plus one write and one shared credential.
// `github()` needs no approval config: reads go through, every write waits for another member.

// The channel's shared credential: a GitHub token pasted once with `/vouchr connect-shared github-team`.
// No OAuth. The default injection is `Authorization: Bearer <key>`, which GitHub accepts for a token.
// One approval covers every write in the approving thread for 30 minutes.
const githubTeam = defineProvider({
  id: 'github-team',
  credential: 'key',
  authorizeUrl: '',
  tokenUrl: '',
  scopesDefault: [],
  egressAllow: ['api.github.com'],
  refresh: 'none',
  pkce: false,
  approval: { grant: 'thread', ttlMs: 30 * 60 * 1000 },
});

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

// Two mentions:
//   @vouchr who am I                                   -> GET /user as the person who asked
//   @vouchr open an issue titled X in repo owner/name  -> POST /repos/owner/name/issues as them (approval)
//   @vouchr open a team issue titled X in repo owner/name -> the same write with the channel's credential
app.event('app_mention', async ({ context, event, client }) => {
  const text = event.text.replace(/<@[^>]+>/g, '').trim();
  const reply = async (t: string): Promise<void> => {
    await client.chat.postMessage({ channel: event.channel, thread_ts: (event as { thread_ts?: string }).thread_ts ?? event.ts, text: t });
  };
  try {
    const issue = /open an? (team )?issue titled (.+?) in repo (\S+\/\S+)/i.exec(text);
    if (issue) {
      const [, team, title, repo] = issue;
      const gh = await context.vouchr.connect(team ? 'github-team' : 'github');
      const res = await gh.fetch(`https://api.github.com/repos/${repo}/issues`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ title }),
        // Shown on the Approve/Deny prompt and kept in the audit row, as the agent's own claim.
        reason: `Open an issue titled "${title}" in ${repo}, asked for in Slack`,
        link: `https://github.com/${repo}`,
      });
      const body: any = await res.json();
      if (!res.ok) return reply(`GitHub said ${res.status}: ${body.message ?? 'no message'}.`);
      return reply(`Opened ${body.html_url} as *${body.user.login}*.`);
    }
    const gh = await context.vouchr.connect('github');
    const me: any = await (await gh.fetch('https://api.github.com/user')).json();
    await reply(`You are *${me.login}* on GitHub, ${me.public_repos} public repos.`);
  } catch (e) {
    // Vouchr already posted the Connect prompt or the Approve/Deny prompt.
    if (e instanceof ConsentRequiredError || e instanceof ApprovalRequiredError) return;
    if (event.user) await client.chat.postEphemeral({ channel: event.channel, user: event.user, text: safeUserMessage(e) });
    throw e;
  }
});

(async () => {
  // Same wiring as examples/bolt-github. `install` also delivers the headless worker's prompts (guides/DEMO.md, scenario j).
  const vouchr = await createVouchr({ providers: [github(), githubTeam], baseUrl: process.env.PUBLIC_URL! });
  vouchr.install(app, receiver);
  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ Vouchr demo on :${port}. Callback at ${process.env.PUBLIC_URL}/vouchr/oauth/callback`);
})();
