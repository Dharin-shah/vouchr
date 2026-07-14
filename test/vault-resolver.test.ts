import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashicorpVault } from '../examples/hashicorp-vault/resolver';

const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body }) as unknown as Response;
const fail = (status: number) => ({ ok: false, status, json: async () => ({}) }) as unknown as Response;

const OPTS = { addr: 'https://vault.internal:8200', token: 'root' };
const REF = 'vault://secret/vouchr/github-bot#token';

test('vault resolver returns the field value', async () => {
  const secret = 'ghp_supersecret';
  const fetch = (async () => ok({ data: { data: { token: secret } } })) as unknown as typeof globalThis.fetch;
  const value = await hashicorpVault({ ...OPTS, fetch }).vault(REF);
  assert.equal(value, secret);
});

test('vault resolver throws on a malformed reference', async () => {
  let calls = 0;
  const fetch = (async () => { calls++; throw new Error('should not be called'); }) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => hashicorpVault({ ...OPTS, fetch }).vault('vault://secret/no-field'), /Malformed/);
  await assert.rejects(
    () => hashicorpVault({ ...OPTS, fetch }).vault('vault://secret/foo/../../../other/data/target#password'),
    /Malformed/,
  );
  assert.equal(calls, 0);
});

test('vault resolver throws (never resolves empty) on a failed read', async () => {
  const fetch = (async () => fail(403)) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => hashicorpVault({ ...OPTS, fetch }).vault(REF), /read failed/);
});

test('vault resolver throws when the field is missing (no empty-string success)', async () => {
  const fetch = (async () => ok({ data: { data: { other: 'x' } } })) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => hashicorpVault({ ...OPTS, fetch }).vault(REF), /no value/);
});

test('vault resolver throws when addr/token are unset', async () => {
  delete process.env.VAULT_ADDR;
  delete process.env.VAULT_TOKEN;
  const fetch = (async () => { throw new Error('should not be called'); }) as unknown as typeof globalThis.fetch;
  await assert.rejects(() => hashicorpVault({ fetch }).vault(REF), /VAULT_ADDR and VAULT_TOKEN/);
});
