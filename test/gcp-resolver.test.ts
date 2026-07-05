import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gcpSecretManager } from '../examples/gcp-secret-manager/resolver';

const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body }) as unknown as Response;
const fail = (status: number) => ({ ok: false, status, json: async () => ({}) }) as unknown as Response;

const REF = 'gcp-sm://projects/p/secrets/s/versions/latest';

test('gcp resolver returns the decoded secret value', async () => {
  const secret = 'ghp_supersecret';
  const fetch = (async (url: string) =>
    String(url).includes('metadata.google.internal')
      ? ok({ access_token: 'meta-token' })
      : ok({ payload: { data: Buffer.from(secret).toString('base64') } })) as unknown as typeof globalThis.fetch;

  const value = await gcpSecretManager({ fetch })['gcp-sm'](REF);
  assert.equal(value, secret);
});

test('gcp resolver throws on a malformed reference', async () => {
  const fetch = (async () => { throw new Error('should not be called'); }) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => gcpSecretManager({ fetch })['gcp-sm']('gcp-sm://nope'), /Malformed/);
});

test('gcp resolver throws (never resolves empty) on a failed access', async () => {
  const fetch = (async (url: string) =>
    String(url).includes('metadata.google.internal') ? ok({ access_token: 't' }) : fail(403)) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => gcpSecretManager({ fetch })['gcp-sm'](REF), /failed/);
});

test('gcp resolver throws when the payload is missing (no empty-string success)', async () => {
  const fetch = (async (url: string) =>
    String(url).includes('metadata.google.internal') ? ok({ access_token: 't' }) : ok({ payload: {} })) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => gcpSecretManager({ fetch })['gcp-sm'](REF), /no payload/);
});
