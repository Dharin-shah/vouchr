import { test } from 'node:test';
import assert from 'node:assert/strict';
import { azureKeyVault } from '../examples/azure-key-vault/resolver';

const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body }) as unknown as Response;
const fail = (status: number) => ({ ok: false, status, json: async () => ({}) }) as unknown as Response;

const REF = 'azure-kv://my-vault/github-bot';

test('azure resolver returns the secret value', async () => {
  const secret = 'ghp_supersecret';
  const fetch = (async (url: string) =>
    String(url).includes('169.254.169.254')
      ? ok({ access_token: 'meta-token' })
      : ok({ value: secret })) as unknown as typeof globalThis.fetch;

  const value = await azureKeyVault({ fetch })['azure-kv'](REF);
  assert.equal(value, secret);
});

test('azure resolver throws on a malformed reference', async () => {
  const fetch = (async () => { throw new Error('should not be called'); }) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => azureKeyVault({ fetch })['azure-kv']('azure-kv://only-vault'), /Malformed/);
});

test('azure resolver throws (never resolves empty) on a failed access', async () => {
  const fetch = (async (url: string) =>
    String(url).includes('169.254.169.254') ? ok({ access_token: 't' }) : fail(404)) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => azureKeyVault({ fetch })['azure-kv'](REF), /failed/);
});

test('azure resolver throws when value is missing (no empty-string success)', async () => {
  const fetch = (async (url: string) =>
    String(url).includes('169.254.169.254') ? ok({ access_token: 't' }) : ok({})) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => azureKeyVault({ fetch })['azure-kv'](REF), /no value/);
});
