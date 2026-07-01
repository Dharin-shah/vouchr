import type { EnvelopeProvider } from '../core/crypto';

/**
 * The minimal KMS surface the envelope needs: wrap (encrypt) and unwrap (decrypt) a data key under a
 * KEK. Injectable so the envelope is testable with a fake and carries NO hard cloud-SDK dependency.
 */
export interface KmsClientLike {
  encrypt(keyId: string, plaintext: Buffer): Promise<Buffer>;
  decrypt(ciphertext: Buffer): Promise<Buffer>;
}

/**
 * Build an {@link EnvelopeProvider} from a KMS client. Vouchr generates a fresh random DEK per secret
 * and calls `wrapDataKey`; this wraps the DEK with the KEK (KMS Encrypt) and unwraps it on read (KMS
 * Decrypt). Supply this to `new Vault(db, key, ttl, envelope)` / the broker entrypoint in production.
 */
export function kmsEnvelope(keyId: string, client: KmsClientLike): EnvelopeProvider {
  return {
    wrapDataKey: (dek) => client.encrypt(keyId, dek),
    unwrapDataKey: (wrapped) => client.decrypt(wrapped),
  };
}

/**
 * Lazily construct an AWS-KMS-backed {@link KmsClientLike}. `@aws-sdk/client-kms` is an OPTIONAL
 * dependency, imported only here and only when KMS is configured — the minimal SQLite self-hoster
 * never installs it. Credentials come from the SDK's default provider chain, so IRSA / workload
 * identity "just works" with zero AWS code in `src/core`. Install `@aws-sdk/client-kms` in the image
 * when running with `VOUCHR_KMS_KEY_ID`.
 */
export async function awsKmsClient(opts: { region?: string } = {}): Promise<KmsClientLike> {
  const specifier = '@aws-sdk/client-kms'; // non-literal so this stays a runtime-optional import
  const mod: any = await import(specifier);
  const client = new mod.KMSClient(opts.region ? { region: opts.region } : {});
  return {
    encrypt: async (keyId, plaintext) => {
      const out = await client.send(new mod.EncryptCommand({ KeyId: keyId, Plaintext: plaintext }));
      return Buffer.from(out.CiphertextBlob);
    },
    decrypt: async (ciphertext) => {
      const out = await client.send(new mod.DecryptCommand({ CiphertextBlob: ciphertext }));
      return Buffer.from(out.Plaintext);
    },
  };
}
