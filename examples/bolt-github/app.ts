import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github, ConsentRequiredError } from '../../src';

// 1. Bolt with an ExpressReceiver so we can mount the OAuth callback route.
const receiver = new ExpressReceiver({
  signingSecret: process.env.SLACK_SIGNING_SECRET!,
});
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

// 3. An agent action that needs to act AS the user on GitHub.
app.event('app_mention', async ({ context, event, client }) => {
  try {
    const gh = await (context as any).vouchr.connect('github');
    // The token is injected at the HTTP boundary — this code never sees it.
    const res = await gh.fetch('https://api.github.com/user');
    const me: any = await res.json();
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: event.ts,
      text: `You are *${me.login}* on GitHub — ${me.public_repos} public repos.`,
    });
  } catch (e) {
    if (e instanceof ConsentRequiredError) return; // Connect prompt already posted.
    throw e;
  }
});

(async () => {
  // 2. Vouchr: one provider (GitHub), public callback origin (e.g. an ngrok URL).
  //    Defaults to SQLite (VOUCHR_DB); set VOUCHR_DATABASE_URL for Postgres.
  const vouchr = await createVouchr({
    providers: [github()],
    baseUrl: process.env.PUBLIC_URL!,
  });
  app.use(vouchr.middleware);
  vouchr.mountRoutes(receiver.router);
  vouchr.registerCommands(app); // /vouchr status | disconnect | configure  (register the slash command in your Slack app)
  vouchr.registerOffboarding(app); // auto-revoke a user's connections when Slack deactivates them
  setInterval(() => vouchr.sweepExpired(), 60 * 60 * 1000); // hourly TTL sweep of idle/old connections

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ Vouchr GitHub demo on :${port} — callback at ${process.env.PUBLIC_URL}/vouchr/oauth/callback`);
})();
