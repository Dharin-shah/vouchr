import { createVouchr, github } from '../../src';
import { gcpSecretManager } from './resolver';

// Wire the GCP Secret Manager resolver into Vouchr. The 'gcp-sm' source id matches
// what bolt's refSource() assigns to a `gcp-sm://` reference.
//
// An admin then runs, from inside the channel they want to configure:
//
//   /vouchr configure github
//
// and pastes a reference into the private modal, e.g.
//
//   gcp-sm://projects/my-project/secrets/github-bot/versions/latest
//
// Vouchr stores only that reference. When an agent acts on GitHub, the injector calls
// the resolver above JIT to fetch the live secret. Vouchr never persists it.
(async () => {
  const vouchr = await createVouchr({
    providers: [github()],
    baseUrl: process.env.PUBLIC_URL!,
    resolvers: gcpSecretManager(),
  });

  console.log('Vouchr ready with GCP Secret Manager resolver.', vouchr != null);
})();
