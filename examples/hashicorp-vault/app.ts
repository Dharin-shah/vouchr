import { createVouchr, github } from '../../src';
import { hashicorpVault } from './resolver';

// Wire the HashiCorp Vault resolver into Vouchr. Its 'vault' key matches the source Vouchr derives
// from a supported Vault reference; configuration checks presence without resolving. VAULT_ADDR
// and VAULT_TOKEN come from the environment.
//
// An admin then runs, from inside the channel they want to configure:
//
//   /vouchr configure github
//
// and pastes a reference into the private modal, e.g.
//
//   vault://secret/vouchr/github-bot#token
//
// Vouchr stores only that reference. When an agent acts on GitHub, the injector calls
// the resolver above JIT to read the live secret. Vouchr never persists it.
(async () => {
  const vouchr = await createVouchr({
    providers: [github()],
    baseUrl: process.env.PUBLIC_URL!,
    resolvers: hashicorpVault(),
  });

  console.log('Vouchr ready with HashiCorp Vault resolver.', vouchr != null);
})();
