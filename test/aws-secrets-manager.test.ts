import assert from 'node:assert/strict';
import test from 'node:test';
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { awsSecretsManager } from '../examples/aws-secrets-manager/resolver';

test('#209 AWS Secrets Manager resolver propagates caller cancellation to the SDK request', async () => {
  const originalSend = SecretsManagerClient.prototype.send;
  const controller = new AbortController();
  let seenCommand: unknown;
  let seenSignal: AbortSignal | undefined;

  SecretsManagerClient.prototype.send = (async (command: unknown, options?: { abortSignal?: AbortSignal }) => {
    seenCommand = command;
    seenSignal = options?.abortSignal;
    return { SecretString: 'synthetic-test-secret' };
  }) as typeof SecretsManagerClient.prototype.send;

  try {
    const resolver = awsSecretsManager()['aws-sm'];
    assert.ok(resolver);
    assert.equal(await resolver('arn:aws:secretsmanager:us-east-1:123456789012:secret:test', controller.signal), 'synthetic-test-secret');
    assert.ok(seenCommand instanceof GetSecretValueCommand);
    assert.equal(seenSignal, controller.signal);
  } finally {
    SecretsManagerClient.prototype.send = originalSend;
  }
});
