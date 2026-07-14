# HashiCorp Vault resolver

A Vouchr resolver that points a credential at a **HashiCorp Vault KV v2 field** instead of
storing a raw secret. Vouchr keeps only the non-secret reference; the injector calls the
resolver **just-in-time** to read the live value, hands it to the outbound request, and
never persists or caches it. Rotation stays entirely in Vault.

Zero dependencies: the resolver uses the global `fetch` only — no Vault SDK.

## Usage

```ts
import { createVouchr, github } from '@vouchr/core';
import { hashicorpVault } from './resolver';

const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  resolvers: hashicorpVault(),
});
```

Then an admin, from inside the channel to configure, runs:

```
/vouchr configure github
```

and pastes a reference into the private modal:

```
vault://secret/vouchr/github-bot#token
```

Vouchr validates the supported reference form, derives the `'vault'` source id, and confirms this
resolver is configured before saving it. The resolver itself is not invoked until credential use.

## Reference format

```
vault://<mount>/<path>#<field>
```

`<mount>` is the KV v2 mount (e.g. `secret`), `<path>` the secret path, and `<field>` the
key within the secret. A malformed reference fails closed (the resolver throws before any
network call).

## Authentication

Config comes from the environment:

- `VAULT_ADDR` — the Vault server address (e.g. `https://vault.internal:8200`).
- `VAULT_TOKEN` — the token used as the `X-Vault-Token` header.

Both are overridable via `hashicorpVault({ addr, token })` for tests. There are **no
static credentials in code** — supply the token from your platform's secret injection
(e.g. an AppRole/Kubernetes-auth sidecar that writes `VAULT_TOKEN`).

## Least-privilege policy

Grant the token a policy with only `read` on the specific paths Vouchr may resolve:

```hcl
path "secret/data/vouchr/*" {
  capabilities = ["read"]
}
```

## Rotation

Rotation stays in the secret manager; Vouchr stores only the reference (recommended
production posture). Rotate the secret in Vault — the next call reads the current value
automatically.
