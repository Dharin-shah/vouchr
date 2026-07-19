import { App, ExpressReceiver } from '@slack/bolt';
import {
  awsKmsClient,
  ConsentRequiredError,
  createVouchr,
  DbInstallationStore,
  github,
  google,
  kmsEnvelope,
} from '../../src';
import { openDb } from '../../src/core/db';
import { loadKeyring } from '../../src/core/crypto';

// ─────────────────────────────────────────────────────────────────────────────
// PRODUCTION TEMPLATE. Install @aws-sdk/client-kms, set the env vars, deploy.
// ─────────────────────────────────────────────────────────────────────────────

(async () => {
  // Run `vouchr migrate` once (schema-owner role) before starting — the runtime connects with a
  // DML-only role and never creates tables (it fails closed on an unmigrated database).
  //
  // Open ONE pool and share it: the installation store and Vouchr both use this `db`, so the
  // deployment opens a single Postgres pool instead of two. We own its lifecycle, so we close it on
  // shutdown (an injected `db` is the caller's to close — createVouchr won't close what it didn't open).
  const kmsKeyId = process.env.VOUCHR_KMS_KEY_ID;
  if (!kmsKeyId) throw new Error('VOUCHR_KMS_KEY_ID is required');
  const region = process.env.AWS_REGION;
  const envelope = kmsEnvelope(kmsKeyId, await awsKmsClient(region ? { region } : {}));
  const key = loadKeyring();
  const db = await openDb({ databaseUrl: process.env.VOUCHR_DATABASE_URL });
  // Pass the SAME envelope to the installation store as to createVouchr below, so multi-workspace
  // Slack bot tokens get the same KMS envelope (per-secret DEK + external KEK) as Vault credentials
  // (#241). Omit it and installation tokens would stay direct-master-encrypted under a configured KMS.
  const installationStore = new DbInstallationStore(db, key, envelope);

  // This is a real multi-workspace OAuth receiver: Bolt writes every Slack installation through the
  // envelope-backed store above, and reads the correct workspace bot token from that same store.
  // Installer options belong on ExpressReceiver when using a custom receiver.
  const receiver = new ExpressReceiver({
    signingSecret: process.env.SLACK_SIGNING_SECRET!,
    clientId: process.env.SLACK_CLIENT_ID!,
    clientSecret: process.env.SLACK_CLIENT_SECRET!,
    stateSecret: process.env.SLACK_STATE_SECRET!,
    scopes: ['app_mentions:read', 'chat:write', 'commands', 'users:read', 'channels:read', 'groups:read'],
    installationStore,
  });
  const app = new App({ receiver });

  const vouchr = await createVouchr({
    providers: [github(), google()],
    baseUrl: process.env.PUBLIC_URL!,
    db,                                           // share one pool (Postgres → stateless, multi-instance)
    envelope,                                     // at-rest secrets wrapped by KMS
    installationStore,                            // multi-workspace token source
  });
  app.use(vouchr.middleware);
  app.event('app_mention', async ({ context, event, client }) => {
    try {
      const gh = await context.vouchr.connect('github');
      const me: any = await (await gh.fetch('https://api.github.com/user')).json();
      await client.chat.postMessage({ channel: event.channel, thread_ts: event.ts, text: `Hi *${me.login}*.` });
    } catch (e) {
      if (e instanceof ConsentRequiredError) return; // Connect prompt already posted.
      throw e;
    }
  });
  vouchr.mountRoutes(receiver.router);
  vouchr.registerCommands(app);
  vouchr.registerOffboarding(app);
  setInterval(() => vouchr.sweepExpired(), 60 * 60 * 1000);

  // We opened the shared pool, so we close it on shutdown (createVouchr won't — the db is injected).
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    process.once(sig, () => { void db.close().finally(() => process.exit(0)); });
  }

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`⚡ Vouchr (Postgres + KMS) on :${port}`);
})();
