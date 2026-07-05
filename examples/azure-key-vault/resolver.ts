// Azure Key Vault resolver for Vouchr.
//
// Resolves a secret JIT: when the injector needs the credential it calls this
// resolver with the reference the admin configured, fetches the live secret value
// from Azure Key Vault, and hands it straight to the outbound request. Vouchr stores
// only the non-secret reference and never caches the value here. Rotation stays
// entirely in Key Vault, so a rotated secret is picked up on the next call.
//
// Auth uses the ambient Managed Identity via the Azure IMDS endpoint. There are no
// static credentials in code. Zero dependencies — global `fetch` only.
//
// Reference format: azure-kv://<vault-name>/<secret-name>[/<version>]
import type { Resolvers } from '../../src';

// Vault + secret + version are restricted to Azure's real naming charset (alphanumeric + hyphen).
// This is SECURITY-CRITICAL, not cosmetic: `vault` is interpolated into the request AUTHORITY, and a
// looser class like [^/]+ would let a reference such as `azure-kv://evil.com#/x` (`#`/`?`/`\` terminate
// the authority in WHATWG URL parsing) redirect the fetch host and exfiltrate the Managed Identity token.
const REF = /^azure-kv:\/\/([a-zA-Z0-9-]+)\/([a-zA-Z0-9-]+)(?:\/([a-zA-Z0-9-]+))?$/;

export function azureKeyVault(opts: { fetch?: typeof fetch } = {}): Resolvers {
  const f = opts.fetch ?? fetch;

  return {
    'azure-kv': async (ref: string): Promise<string> => {
      const m = REF.exec(ref);
      if (!m) throw new Error(`Malformed Azure Key Vault reference: "${ref}".`);
      const [, vault, secret, version] = m;

      // Ambient Managed Identity token from the Azure Instance Metadata Service.
      const tokenRes = await f(
        'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net',
        { headers: { Metadata: 'true' } },
      );
      if (!tokenRes.ok) throw new Error(`Azure IMDS token request failed (${tokenRes.status}).`);
      const { access_token } = (await tokenRes.json()) as { access_token?: string };
      if (!access_token) throw new Error('Azure IMDS returned no access_token.');

      const path = version ? `${secret}/${version}` : secret;
      const url = `https://${vault}.vault.azure.net/secrets/${path}?api-version=7.4`;
      const res = await f(url, { headers: { Authorization: `Bearer ${access_token}` } });
      // Error names the reference (non-secret) only, never any secret material.
      if (!res.ok) throw new Error(`Azure Key Vault access failed for "${ref}" (${res.status}).`);
      const body = (await res.json()) as { value?: string };
      if (!body.value) throw new Error(`Azure Key Vault returned no value for "${ref}".`);
      return body.value;
    },
  };
}
