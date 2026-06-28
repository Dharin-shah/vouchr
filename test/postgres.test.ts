import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { sweepExpired } from '../src/core/sweep';
import { userOwner, channelOwner } from '../src/core/owner';
import { github } from '../src/core/providers';

// Runs the security-critical invariants against a REAL Postgres (not a mock).
//   npm run pg:up   # start a throwaway postgres:16 in Docker
//   npm test        # this test connects; if no PG is reachable it SKIPS (suite stays green)
//   npm run pg:down
const PG_URL = process.env.VOUCHR_TEST_PG_URL ?? 'postgres://vouchr:vouchr@localhost:5433/vouchr';
const KEY = randomBytes(32);
const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

test('postgres backend: isolation · crypto-at-rest · reference · ttl · consent · config', async (t) => {
  let db;
  try {
    db = await openDb({ databaseUrl: PG_URL });
    await db.exec('TRUNCATE connection, consent_request, channel_config, audit');
  } catch {
    t.skip('Postgres not reachable. Run `npm run pg:up` to exercise the PG backend');
    return;
  }

  try {
    const vault = new Vault(db, KEY);
    const audit = new Audit(db);

    // T3 / owner isolation on the real engine.
    await vault.upsert(channelOwner('T1', 'X'), 'p', tok('chan-T1'));
    await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p', tok('user-T1'));
    await vault.upsert(channelOwner('T2', 'X'), 'p', tok('chan-T2'));
    assert.equal((await vault.get(channelOwner('T1', 'X'), 'p'))?.accessToken, 'chan-T1');
    assert.equal((await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'p'))?.accessToken, 'user-T1');
    assert.equal((await vault.get(channelOwner('T2', 'X'), 'p'))?.accessToken, 'chan-T2');
    assert.equal(await vault.get(channelOwner('T3', 'X'), 'p'), null); // unknown team → nothing

    // Ciphertext at rest: BYTEA round-trips and never holds the plaintext.
    const row = (await db.get(
      `SELECT access_token_enc FROM connection WHERE team_id=? AND owner_kind=? AND owner_id=? AND provider=?`,
      ['T1', 'channel', 'X', 'p'],
    )) as any;
    assert.ok(Buffer.isBuffer(row.access_token_enc));
    assert.ok(!row.access_token_enc.toString('utf8').includes('chan-T1'));

    // Referenced secret: only the ARN pointer is stored, never a secret.
    await vault.reference(channelOwner('T1', 'C_FIN'), 'mcp', { source: 'aws-sm', secretRef: 'arn:aws:secretsmanager:r:k' });
    const ref = await vault.get(channelOwner('T1', 'C_FIN'), 'mcp');
    assert.equal(ref?.source, 'aws-sm');
    assert.equal(ref?.secretRef, 'arn:aws:secretsmanager:r:k');
    assert.equal(ref?.accessToken, null);

    // listForUser isolation.
    await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'X' }), 'github', tok('g'));
    const mine = (await vault.listForUser({ enterpriseId: null, teamId: 'T1', userId: 'X' })).map((c) => c.provider).sort();
    assert.deepEqual(mine, ['github', 'p']); // channel creds never listed

    // TTL + sweep on a dedicated idle vault/row.
    const idle = new Vault(db, KEY, { idleMs: 1000 });
    await idle.upsert(userOwner({ enterpriseId: null, teamId: 'T9', userId: 'U' }), 'ttlp', tok('t'));
    await db.run(`UPDATE connection SET last_used_at=? WHERE team_id=? AND provider=?`, [Date.now() - 5000, 'T9', 'ttlp']);
    assert.equal(await idle.get(userOwner({ enterpriseId: null, teamId: 'T9', userId: 'U' }), 'ttlp'), null); // idle-expired
    const swept = await sweepExpired(idle, audit, new Consent(db));
    assert.ok(swept >= 1);

    // Consent single-use round-trip.
    const consent = new Consent(db);
    const id = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
    const { state } = await consent.begin(id, github({ clientId: 'a', clientSecret: 'b' }), 'https://x/cb', 'C1');
    assert.equal((await consent.consume(state))?.identity.userId, 'U1');
    assert.equal(await consent.consume(state), null); // single-use

    // Channel config mode persists.
    const cfg = new ChannelConfig(db);
    await cfg.setMode('T1', 'C_FIN', 'mcp', 'per-user');
    assert.equal(await cfg.getMode('T1', 'C_FIN', 'mcp'), 'per-user');
  } finally {
    await db.close();
  }
});
