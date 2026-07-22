# Azure Key Vault resolver

A Vouchr resolver that points a credential at an **Azure Key Vault secret** instead of
storing a raw secret. Vouchr keeps only the non-secret reference; the injector calls the
resolver **just-in-time** to fetch the live value, hands it to the outbound request, and
never persists or caches it. Rotation stays entirely in Key Vault.

Zero dependencies: the resolver uses the global `fetch` only — no Azure SDK.

## Usage

```ts
import { createVouchr, github } from '@vouchr/core';
import { azureKeyVault } from './resolver';

const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  resolvers: azureKeyVault(),
});
```

Then an admin, from inside the channel to configure, runs:

```
/vouchr connect-shared github
```

and pastes a reference into the private modal:

```
azure-kv://my-vault/github-bot
```

Vouchr validates the supported reference form, derives the `'azure-kv'` source id, and confirms this
resolver is configured before saving it. The resolver itself is not invoked until credential use.

## Reference format

```
azure-kv://<vault-name>/<secret-name>[/<version>]
```

Omit the version to get the current one. A malformed reference fails closed (the resolver
throws before any network call).

## Authentication

The resolver uses the **ambient Managed Identity** via the Azure **Instance Metadata
Service** (IMDS): it GETs a token from `169.254.169.254` (header `Metadata: true`,
`resource=https://vault.azure.net`), then calls the vault with that bearer. There are **no
static credentials in code**.

## Least-privilege access

Grant the Managed Identity only **Get** on secrets, scoped to the specific vault (via a
Key Vault access policy or the `Key Vault Secrets User` RBAC role on that vault). No list
or management permissions are needed.

## Rotation

Rotation stays in the secret manager; Vouchr stores only the reference (recommended
production posture). Rotate the secret in Key Vault — omit the version in the reference and
the next call picks up the current value automatically.
