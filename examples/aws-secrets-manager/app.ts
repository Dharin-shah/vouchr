import { createVouchr, github } from '../../src';
import { awsSecretsManager } from './resolver';

// Wire the AWS Secrets Manager resolver into Vouchr. The 'aws-sm' source id matches
// what bolt's refSource() assigns to an `arn:aws:secretsmanager:` reference.
//
// An admin then runs, from inside the channel they want to configure:
//
//   /vouchr configure github
//
// and pastes an ARN into the private modal, e.g.
//
//   arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/github-bot-AbCdEf
//
// Vouchr stores only that ARN. When an agent acts on GitHub, the injector calls the
// resolver above JIT to fetch the live secret — Vouchr never persists it.
(async () => {
  const vouchr = await createVouchr({
    providers: [github()],
    baseUrl: process.env.PUBLIC_URL!,
    resolvers: awsSecretsManager(),
  });

  console.log('Vouchr ready with AWS Secrets Manager resolver.', vouchr != null);
})();
