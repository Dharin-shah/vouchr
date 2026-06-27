import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/core/db';
import { Audit } from '../src/core/audit';
import type { SlackIdentity } from '../src/core/identity';

const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };

async function lastMeta(db: any): Promise<any> {
  const row = await db.get('SELECT meta FROM audit ORDER BY at DESC LIMIT 1') as any;
  return JSON.parse(row.meta);
}

test('audit: redacts credential-shaped values, keeps legitimate metadata intact', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const audit = new Audit(db);
  const blob = 'A'.repeat(60); // 60-char high-entropy base64 blob

  const meta = {
    token: 'xoxb-123456789012-abcdefghijklmnop',
    gh: 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    auth: 'Bearer abcdef0123456789',
    secret: blob,
    // legitimate fields that must survive untouched
    host: 'api.github.com',
    status: 200,
    channel: 'C0123ABC',
    provider: 'github',
    ok: true,
  };

  await audit.record('connect', ID, 'github', meta);
  const stored = await lastMeta(db);

  assert.equal(stored.token, '[redacted]');
  assert.equal(stored.gh, '[redacted]');
  assert.equal(stored.auth, '[redacted]');
  assert.equal(stored.secret, '[redacted]');

  assert.equal(stored.host, 'api.github.com');
  assert.equal(stored.status, 200);
  assert.equal(stored.channel, 'C0123ABC');
  assert.equal(stored.provider, 'github');
  assert.equal(stored.ok, true);

  // The caller's original object must not be mutated.
  assert.equal(meta.token, 'xoxb-123456789012-abcdefghijklmnop');
  assert.equal(meta.secret, blob);
});

test('audit: redaction walks nested objects and arrays', async () => {
  const db = await openDb({ dbPath: ':memory:' });
  const audit = new Audit(db);

  const meta = {
    nested: { leaked: 'ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', safe: 'ok' },
    list: ['C0123ABC', 'AKIAIOSFODNN7EXAMPLE', 200],
  };

  await audit.record('config', ID, 'github', meta);
  const stored = await lastMeta(db);

  assert.equal(stored.nested.leaked, '[redacted]');
  assert.equal(stored.nested.safe, 'ok');
  assert.deepEqual(stored.list, ['C0123ABC', '[redacted]', 200]);
});
