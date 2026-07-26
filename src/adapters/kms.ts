import type { EnvelopeProvider } from '../core/crypto';

/**
 * The minimal KMS surface the envelope needs: wrap (encrypt) and unwrap (decrypt) a data key under a
 * KEK. Injectable so the envelope is testable with a fake and carries NO hard cloud-SDK dependency.
 */
export interface KmsClientLike {
  encrypt(keyId: string, plaintext: Buffer, signal?: AbortSignal): Promise<Buffer>;
  /** Takes the SAME `keyId` as `encrypt` so the unwrap can be pinned to the configured KEK rather
   *  than trusting the key the ciphertext blob names — see `awsKmsClient`. */
  decrypt(keyId: string, ciphertext: Buffer, signal?: AbortSignal): Promise<Buffer>;
}

/**
 * Build an {@link EnvelopeProvider} from a KMS client. Vouchr generates a fresh random DEK per secret
 * and calls `wrapDataKey`; this wraps the DEK with the KEK (KMS Encrypt) and unwraps it on read (KMS
 * Decrypt). Supply this to `new Vault(db, key, ttl, envelope)` / the broker entrypoint in production.
 */
export function kmsEnvelope(keyId: string, client: KmsClientLike): EnvelopeProvider {
  return {
    wrapDataKey: (dek, signal) => client.encrypt(keyId, dek, signal),
    // The same `keyId` on both sides (STR-2): one configured KEK, so an unwrap cannot be satisfied
    // by a different key the blob happens to name.
    unwrapDataKey: (wrapped, signal) => client.decrypt(keyId, wrapped, signal),
  };
}

/**
 * Lazily construct an AWS-KMS-backed {@link KmsClientLike}. `@aws-sdk/client-kms` is an OPTIONAL
 * dependency, imported only here and only when KMS is configured — a minimal self-hoster using
 * plain at-rest encryption never installs it. Credentials come from the SDK's default provider chain, so IRSA / workload
 * identity "just works" with zero AWS code in `src/core`. Install `@aws-sdk/client-kms` in the image
 * when running with `VOUCHR_KMS_KEY_ID`.
 */
export async function awsKmsClient(opts: { region?: string } = {}): Promise<KmsClientLike> {
  const specifier = '@aws-sdk/client-kms'; // non-literal so this stays a runtime-optional import
  const mod: any = await import(specifier);
  const client = new mod.KMSClient(opts.region ? { region: opts.region } : {});
  return {
    encrypt: async (keyId, plaintext, signal) => {
      const out = await client.send(
        new mod.EncryptCommand({ KeyId: keyId, Plaintext: plaintext }),
        signal ? { abortSignal: signal } : undefined,
      );
      return Buffer.from(out.CiphertextBlob);
    },
    // `KeyId` is REQUIRED on Decrypt, not optional politeness. Without it KMS decrypts under
    // whatever key the ciphertext blob names, so if this deployment's IAM role can decrypt under any
    // other key, an attacker who can swap the stored wrapped-DEK for one they created gets it
    // unwrapped and the credential decrypts under a key they control. Pinning it makes KMS reject
    // any blob not wrapped by the configured KEK.
    decrypt: async (keyId, ciphertext, signal) => {
      const out = await client.send(
        new mod.DecryptCommand({ KeyId: keyId, CiphertextBlob: ciphertext }),
        signal ? { abortSignal: signal } : undefined,
      );
      return Buffer.from(out.Plaintext);
    },
  };
}
