import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, defineProvider, ConsentRequiredError } from '../../src';

// A per-user KEY provider: there is no OAuth dance. Each user pastes their own
// API key into a private self-service modal; Vouchr stores it (encrypted) and
// injects it on outbound requests. authorizeUrl/tokenUrl/scopes are unused for
// `credential: 'key'`, but the Provider shape still requires the fields.
const internal = defineProvider({
  id: 'internal',
  credential: 'key',
  authorizeUrl: '',
  tokenUrl: '',
  scopesDefault: [],
  egressAllow: ['api.internal.example'],
  // Non-Bearer auth: attach the key as a custom header instead of Authorization.
  inject: (headers, key) => headers.set('x-api-key', key),
  refresh: 'none',
  pkce: false,
});

const receiver = new ExpressReceiver({
  signingSecret: process.env.SLACK_SIGNING_SECRET!,
});
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

// Agent action that calls the internal API as the mentioning user.
app.event('app_mention', async ({ context, event, client }) => {
  try {
    // First time a user hits this, connect() posts an ephemeral "set up your key"
    // button (wired by registerCommands) and throws — no OAuth, no admin needed.
    const api = await context.vouchr.connect('internal');
    const res = await api.fetch('https://api.internal.example/v1/me');
    const me: any = await res.json();
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: event.ts,
      text: `Internal API says you are *${me.name ?? me.id}*.`,
    });
  } catch (e) {
    if (e instanceof ConsentRequiredError) return; // Key-setup prompt already posted.
    throw e;
  }
});

(async () => {
  const vouchr = await createVouchr({
    providers: [internal],
    baseUrl: process.env.PUBLIC_URL!,
  });
  app.use(vouchr.middleware);
  vouchr.mountRoutes(receiver.router);
  // registerCommands wires the "set up your key" button + private key modal that
  // connect() triggers for key providers (and /vouchr status | disconnect).
  vouchr.registerCommands(app);
  vouchr.registerOffboarding(app);
  setInterval(() => vouchr.sweepExpired(), 60 * 60 * 1000);

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ Vouchr internal-key demo on :${port}`);
})();
