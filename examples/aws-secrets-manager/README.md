# AWS Secrets Manager resolver

A Vouchr resolver that points a credential at an **AWS Secrets Manager ARN** instead
of storing a raw secret. Vouchr keeps only the non-secret ARN; the injector calls the
resolver **just-in-time** to fetch the live `SecretString`, hands it to the outbound
request, and never persists or caches it. Rotation stays entirely in AWS SM.

## Usage

```ts
import { createVouchr, github } from '@vouchr/core';
import { awsSecretsManager } from './resolver';

const vouchr = await createVouchr({
  providers: [github()],
  baseUrl: process.env.PUBLIC_URL!,
  resolvers: awsSecretsManager(),
});
```

Then an admin, from inside the channel to configure, runs:

```
/vouchr configure github
```

and pastes an ARN into the private modal:

```
arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/github-bot-AbCdEf
```

Vouchr validates the bounded ARN form, derives the `'aws-sm'` source id, and confirms this resolver is
configured before saving the reference. The resolver itself is not invoked until credential use.

## Authentication

The resolver uses the **ambient IAM role** (ECS/Fargate task role, EC2 instance
profile, or EKS IRSA). There are **no static credentials in code**. Region and
credentials are resolved by the AWS SDK's default provider chain. The resolver forwards Vouchr's
optional `AbortSignal` to the SDK request so a caller disconnect or deadline cancels underlying AWS
work as well as Vouchr's wait.

## Least-privilege IAM policy

Grant only `secretsmanager:GetSecretValue`, scoped to the specific secret ARNs Vouchr
may resolve:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/github-bot-*"
      ]
    }
  ]
}
```

(If your secrets use a customer-managed KMS key, also grant `kms:Decrypt` on that key.)

## Dependencies

The only extra dependency is [`@aws-sdk/client-secrets-manager`](https://www.npmjs.com/package/@aws-sdk/client-secrets-manager).
