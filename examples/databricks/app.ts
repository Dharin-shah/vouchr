import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, databricks, ConsentRequiredError } from '../../src';

// Per-user Databricks (OAuth U2M): the agent runs SQL AS the connected human, so Unity Catalog
// masks / row filters / grants apply per person automatically. Vouchr's egress lock keeps the
// injected token pinned to the SQL Statement Execution API — the agent cannot reach jobs, secrets,
// DBFS, or workspace admin with it.

const WAREHOUSE_ID = process.env.DATABRICKS_WAREHOUSE_ID!;

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

app.event('app_mention', async ({ context, event, client }) => {
  try {
    const dbx = await context.vouchr.connect('databricks');
    // POST submits the statement. The token is injected at the HTTP boundary; this code never sees
    // it. `${host}/api/2.0/sql/statements` is the ONLY path this credential may reach by default.
    const res = await dbx.fetch(`${process.env.DATABRICKS_HOST}/api/2.0/sql/statements`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        warehouse_id: WAREHOUSE_ID,
        statement: 'SELECT current_user() AS me',
        wait_timeout: '30s',
      }),
    });
    const out: any = await res.json();
    const me = out?.result?.data_array?.[0]?.[0] ?? '(query ran)';
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: event.ts,
      text: `Ran as *${me}* — Unity Catalog governance applied to your identity, not a shared bot.`,
    });
  } catch (e) {
    if (e instanceof ConsentRequiredError) return; // Connect prompt already posted.
    throw e;
  }
});

(async () => {
  const vouchr = await createVouchr({
    // Public client (no secret) shown here; pass `clientSecret` for a confidential OAuth app.
    // POST is required to submit a statement, so writes must be enabled for this path.
    providers: [databricks({ host: process.env.DATABRICKS_HOST!, clientId: process.env.DATABRICKS_CLIENT_ID! })],
    baseUrl: process.env.PUBLIC_URL!,
  });
  app.use(vouchr.middleware);
  vouchr.mountRoutes(receiver.router);
  vouchr.registerCommands(app);
  vouchr.registerOffboarding(app);
  setInterval(() => vouchr.sweepExpired(), 60 * 60 * 1000);

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ Vouchr Databricks demo on :${port}, callback at ${process.env.PUBLIC_URL}/vouchr/oauth/callback`);
})();
