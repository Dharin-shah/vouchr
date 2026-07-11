import { App, ExpressReceiver } from '@slack/bolt';
import { createVouchr, github, google, DbInstallationStore, ConsentRequiredError, type EnvelopeProvider } from '../../src';
import { openDb } from '../../src/core/db';
import { loadKeyring } from '../../src/core/crypto';

// ─────────────────────────────────────────────────────────────────────────────
// PRODUCTION TEMPLATE. Fill in the KMS calls below, set the env vars, deploy.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Envelope encryption with AWS KMS. Each stored secret gets a fresh data key (DEK)
 * that Vouchr wraps with your KMS key (the KEK) and stores alongside the ciphertext.
 *
 * This template typechecks WITHOUT pulling in @aws-sdk/client-kms.
 * Replace the two bodies with the real calls (sketched below) before use.
 *
 *   import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';
 *   const kms = new KMSClient({});                 // region/creds from the default chain
 *   const KEY_ID = process.env.VOUCHR_KMS_KEY_ID!;
 *   const kmsEnvelope: EnvelopeProvider = {
 *     async wrapDataKey(dek) {
 *       const r = await kms.send(new EncryptCommand({ KeyId: KEY_ID, Plaintext: dek }));
 *       return Buffer.from(r.CiphertextBlob!);
 *     },
 *     async unwrapDataKey(wrapped) {
 *       const r = await kms.send(new DecryptCommand({ KeyId: KEY_ID, CiphertextBlob: wrapped }));
 *       return Buffer.from(r.Plaintext!);     // never log the DEK
 *     },
 *   };
 *
 * (KMS's GenerateDataKey, which mints the DEK and returns both forms in one call, is
 * the alternative if you let KMS create the DEK instead of Vouchr's seal().)
 */
const kmsEnvelope: EnvelopeProvider = {
  async wrapDataKey(_dek) {
    throw new Error('KMS envelope provider is not configured: implement wrapDataKey with EncryptCommand.');
  },
  async unwrapDataKey(_wrapped) {
    throw new Error('KMS envelope provider is not configured: implement unwrapDataKey with DecryptCommand.');
  },
};

const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

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

(async () => {
  // Run `vouchr migrate` once (schema-owner role) before starting — the runtime connects with a
  // DML-only role and never creates tables (it fails closed on an unmigrated database).
  //
  // Open ONE pool and share it: the installation store and Vouchr both use this `db`, so the
  // deployment opens a single Postgres pool instead of two. We own its lifecycle, so we close it on
  // shutdown (an injected `db` is the caller's to close — createVouchr won't close what it didn't open).
  const key = loadKeyring();
  const db = await openDb({ databaseUrl: process.env.VOUCHR_DATABASE_URL });
  const installationStore = new DbInstallationStore(db, key);

  const vouchr = await createVouchr({
    providers: [github(), google()],
    baseUrl: process.env.PUBLIC_URL!,
    db,                                           // share one pool (Postgres → stateless, multi-instance)
    envelope: kmsEnvelope,                        // at-rest secrets wrapped by KMS
    installationStore,                            // multi-workspace token source
  });
  app.use(vouchr.middleware);
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
