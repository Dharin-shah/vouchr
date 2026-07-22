import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, google, ConsentRequiredError } from '../../src';

// 1. Bolt with an ExpressReceiver so we can mount the OAuth callback route.
const receiver = new ExpressReceiver({
  signingSecret: process.env.SLACK_SIGNING_SECRET!,
});
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

// 2. An agent action that needs to act AS the user on a Google API.
app.event('app_mention', async ({ context, event, client }) => {
  try {
    const g = await context.vouchr.connect('google');
    // Token injected at the HTTP boundary. This code never sees it. The host
    // (www.googleapis.com) is on the built-in google() egress allowlist.
    const res = await g.fetch('https://www.googleapis.com/oauth2/v3/userinfo');
    const me: any = await res.json();
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: event.ts,
      text: `You are *${me.name ?? me.email}* (${me.email}) on Google.`,
    });
  } catch (e) {
    if (e instanceof ConsentRequiredError) return; // Connect prompt already posted.
    throw e;
  }
});

(async () => {
  // 3. Vouchr: one provider (Google), public callback origin (e.g. an ngrok URL).
  //    google() uses PKCE and asks for a refresh token (access_type=offline +
  //    prompt=consent), so connections survive past the ~1h access-token lifetime.
  //    Vouchr refreshes them on demand (refresh: 'rotating').
  const vouchr = await createVouchr({
    providers: [google()],
    baseUrl: process.env.PUBLIC_URL!,
  });
  app.use(vouchr.middleware);
  vouchr.mountRoutes(receiver.router);
  vouchr.registerCommands(app); // /vouchr, status, tools, disconnect, and connect-shared
  vouchr.registerOffboarding(app);
  setInterval(() => vouchr.sweepExpired(), 60 * 60 * 1000);

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ Vouchr Google demo on :${port}, callback at ${process.env.PUBLIC_URL}/vouchr/oauth/callback`);
})();
