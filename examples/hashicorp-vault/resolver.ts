// HashiCorp Vault (KV v2) resolver for Vouchr.
//
// Resolves a secret JIT: when the injector needs the credential it calls this
// resolver with the reference the admin configured, reads the live value from Vault's
// KV v2 engine, and hands it straight to the outbound request. Vouchr stores only the
// non-secret reference and never caches the value here. Rotation stays entirely in
// Vault, so a rotated secret is picked up on the next call.
//
// Config comes from the environment (VAULT_ADDR, VAULT_TOKEN); both are overridable via
// opts for tests. Zero dependencies — global `fetch` only.
//
// Reference format: vault://<mount>/<path>#<field>
import type { Resolvers } from '../../src';

const REF = /^vault:\/\/([^/]+)\/(.+)#([^#]+)$/;

export function hashicorpVault(
  opts: { fetch?: typeof fetch; addr?: string; token?: string } = {},
): Resolvers {
  const f = opts.fetch ?? fetch;
  const addr = opts.addr ?? process.env.VAULT_ADDR;
  const token = opts.token ?? process.env.VAULT_TOKEN;

  return {
    vault: async (ref: string): Promise<string> => {
      if (!addr || !token) throw new Error('VAULT_ADDR and VAULT_TOKEN must be set.');
      const m = REF.exec(ref);
      if (!m) throw new Error(`Malformed Vault reference: "${ref}".`);
      const [, mount, path, field] = m;

      const url = `${addr}/v1/${mount}/data/${path}`;
      const res = await f(url, { headers: { 'X-Vault-Token': token } });
      // Error names the reference (non-secret) only, never any secret material.
      if (!res.ok) throw new Error(`Vault read failed for "${ref}" (${res.status}).`);
      const body = (await res.json()) as { data?: { data?: Record<string, string> } };
      const value = body.data?.data?.[field];
      if (!value) throw new Error(`Vault returned no value for field "${field}" of "${ref}".`);
      return value;
    },
  };
}
