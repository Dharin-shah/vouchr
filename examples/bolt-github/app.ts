import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github, ConsentRequiredError } from '../../src';

// 1. Bolt with an ExpressReceiver so Vouchr can mount the OAuth callback route.
const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

// 2. An agent action that needs to act AS the user on GitHub.
app.event('app_mention', async ({ context, event, client }) => {
  try {
    const gh = await context.vouchr.connect('github');
    // The token is injected at the HTTP boundary. This code never sees it.
    const res = await gh.fetch('https://api.github.com/user');
    const me: any = await res.json();
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: event.ts,
      text: `You are *${me.login}* on GitHub, ${me.public_repos} public repos.`,
    });
  } catch (e) {
    if (e instanceof ConsentRequiredError) return; // Connect prompt already posted.
    throw e;
  }
});

(async () => {
  // 3. Vouchr in one call: middleware + OAuth callback + /vouchr command + offboarding + TTL sweep.
  //    Requires a PostgreSQL connection string in VOUCHR_DATABASE_URL. Run `npm run cli -- migrate`
  //    once against it first — the runtime connects DML-only and never creates tables.
  // Least privilege: this demo only reads /user, so request read:user ONLY — not the broad `repo`
  // scope github() defaults to. The Connect prompt then shows just "Read your profile".
  const vouchr = await createVouchr({ providers: [github({ scopes: ['read:user'] })], baseUrl: process.env.PUBLIC_URL! });
  vouchr.install(app, receiver);

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ Vouchr GitHub demo on :${port}. Callback at ${process.env.PUBLIC_URL}/vouchr/oauth/callback`);
})();
