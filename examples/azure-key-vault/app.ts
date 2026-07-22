import { createVouchr, github } from '../../src';
import { azureKeyVault } from './resolver';

// Wire the Azure Key Vault resolver into Vouchr. Its 'azure-kv' key matches the source Vouchr
// derives from a supported Azure reference; configuration checks presence without resolving.
//
// An admin then runs, from inside the channel they want to configure:
//
//   /vouchr connect-shared github
//
// and pastes a reference into the private modal, e.g.
//
//   azure-kv://my-vault/github-bot
//
// Vouchr stores only that reference. When an agent acts on GitHub, the injector calls
// the resolver above JIT to fetch the live secret. Vouchr never persists it.
(async () => {
  const vouchr = await createVouchr({
    providers: [github()],
    baseUrl: process.env.PUBLIC_URL!,
    resolvers: azureKeyVault(),
  });

  console.log('Vouchr ready with Azure Key Vault resolver.', vouchr != null);
})();
