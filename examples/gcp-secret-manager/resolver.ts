// GCP Secret Manager resolver for Vouchr.
//
// Resolves a secret JIT: when the injector needs the credential it calls this
// resolver with the reference the admin configured, fetches the live secret payload
// from GCP Secret Manager, and hands it straight to the outbound request. Vouchr
// stores only the non-secret reference and never caches the value here. Rotation
// stays entirely in GCP SM, so a rotated secret is picked up on the next call.
//
// Auth uses the ambient service account via the GCE/GKE metadata server. There are
// no static credentials in code. Zero dependencies — global `fetch` only.
//
// Reference format: gcp-sm://projects/<project>/secrets/<secret>/versions/<version|latest>
import type { Resolvers } from '../../src';
import { GCP_SECRET_REFERENCE } from '../../src/core/reference';

export function gcpSecretManager(opts: { fetch?: typeof fetch } = {}): Resolvers {
  const f = opts.fetch ?? fetch;

  return {
    'gcp-sm': async (ref: string): Promise<string> => {
      const m = GCP_SECRET_REFERENCE.exec(ref);
      if (!m) throw new Error('Malformed GCP Secret Manager reference.');
      const [, project, secret, version] = m;

      // Ambient service-account access token from the metadata server.
      const tokenRes = await f(
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        { headers: { 'Metadata-Flavor': 'Google' } },
      );
      if (!tokenRes.ok) throw new Error(`GCP metadata token request failed (${tokenRes.status}).`);
      const { access_token } = (await tokenRes.json()) as { access_token?: string };
      if (!access_token) throw new Error('GCP metadata server returned no access_token.');

      const url = `https://secretmanager.googleapis.com/v1/projects/${project}/secrets/${secret}/versions/${version}:access`;
      const res = await f(url, { headers: { Authorization: `Bearer ${access_token}` } });
      if (!res.ok) throw new Error(`GCP Secret Manager access failed (${res.status}).`);
      const body = (await res.json()) as { payload?: { data?: string } };
      const data = body.payload?.data;
      if (!data) throw new Error('GCP Secret Manager returned no payload.');
      // Fail closed on an empty decoded value too — base64 like "=" is truthy but decodes to "".
      const value = Buffer.from(data, 'base64').toString('utf8');
      if (!value) throw new Error('GCP Secret Manager returned an empty value.');
      return value;
    },
  };
}
