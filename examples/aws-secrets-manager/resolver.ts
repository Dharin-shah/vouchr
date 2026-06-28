// AWS Secrets Manager resolver for Vouchr.
//
// Resolves a secret JIT: when the injector needs the credential it calls this
// resolver with the ARN the admin configured, fetches the live SecretString from
// AWS Secrets Manager, and hands it straight to the outbound request. The secret
// is never stored by Vouchr (only the non-secret ARN is) and never cached here.
// Rotation stays entirely in AWS SM, so a rotated secret is picked up on the next call.
//
// Auth uses the ambient IAM role (task role / instance profile / EKS IRSA). No
// static credentials in code. Grant the role secretsmanager:GetSecretValue on the
// specific secret ARNs (see README).
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import type { Resolvers } from '../../src';

export function awsSecretsManager(): Resolvers {
  // One client; the SDK resolves region/credentials from the ambient environment.
  const client = new SecretsManagerClient({});

  return {
    'aws-sm': async (arn: string): Promise<string> => {
      const out = await client.send(new GetSecretValueCommand({ SecretId: arn }));

      if (out.SecretString != null) return out.SecretString;

      // Binary secrets come back base64-encoded; decode to the raw string value.
      if (out.SecretBinary != null) {
        return Buffer.from(out.SecretBinary as Uint8Array).toString('utf8');
      }

      // Error names the ARN (non-secret) only, never any secret material.
      throw new Error(`AWS Secrets Manager returned no value for "${arn}".`);
    },
  };
}
