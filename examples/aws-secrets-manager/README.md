# AWS Secrets Manager resolver

A Vouchr resolver that points a credential at an **AWS Secrets Manager ARN** instead
of storing a raw secret. Vouchr keeps only the non-secret ARN; the injector calls the
resolver **just-in-time** to fetch the live `SecretString`, hands it to the outbound
request, and never persists or caches it. Rotation stays entirely in AWS SM.

## Usage

```ts
import { createVouchr, github } from 'vouchr';
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

Vouchr's `refSource()` maps any `arn:aws:secretsmanager:` reference to the `'aws-sm'`
source id, which this resolver handles.

## Authentication

The resolver uses the **ambient IAM role** (ECS/Fargate task role, EC2 instance
profile, or EKS IRSA). There are **no static credentials in code**. Region and
credentials are resolved by the AWS SDK's default provider chain.

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
