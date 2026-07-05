# GCP Secret Manager resolver

A Vouchr resolver that points a credential at a **GCP Secret Manager secret version**
instead of storing a raw secret. Vouchr keeps only the non-secret reference; the injector
calls the resolver **just-in-time** to fetch the live payload, hands it to the outbound
request, and never persists or caches it. Rotation stays entirely in GCP SM.

Zero dependencies: the resolver uses the global `fetch` only — no Google SDK.

## Usage

```ts
import { createVouchr, github } from '@vouchr/core';
import { gcpSecretManager } from './resolver';

const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  resolvers: gcpSecretManager(),
});
```

Then an admin, from inside the channel to configure, runs:

```
/vouchr configure github
```

and pastes a reference into the private modal:

```
gcp-sm://projects/my-project/secrets/github-bot/versions/latest
```

Vouchr's `refSource()` maps any `gcp-sm://` reference to the `'gcp-sm'` source id, which
this resolver handles.

## Reference format

```
gcp-sm://projects/<project>/secrets/<secret>/versions/<version|latest>
```

A malformed reference fails closed (the resolver throws before any network call).

## Authentication

The resolver uses the **ambient service account** via the GCE/GKE **metadata server**:
it GETs a token from `metadata.google.internal` (header `Metadata-Flavor: Google`), then
calls Secret Manager with that bearer. There are **no static credentials in code**.

## Least-privilege IAM

Grant the service account only `roles/secretmanager.secretAccessor`, scoped to the
specific secrets Vouchr may resolve (bind the role at the secret resource level, not the
project). No broader Secret Manager permissions are needed.

## Rotation

Rotation stays in the secret manager; Vouchr stores only the reference (recommended
production posture). Rotate the secret in GCP SM — point the reference at `versions/latest`
and the next call picks up the new version automatically.
