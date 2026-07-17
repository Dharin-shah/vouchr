import { randomBytes, randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createBroker } from '../src/headless';
import {
  approvalActionFingerprint,
  Approvals,
  type ApprovalKey,
} from '../src/core/approval';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import type { Db } from '../src/core/db';
import type { CredentialHealthEvent } from '../src/core/health';
import type { VouchrEvent } from '../src/core/injector';
import { userOwner } from '../src/core/owner';
import {
  ChannelProvisioningRequests,
  UserProvisioningRequests,
} from '../src/core/provisioning';
import { defineProvider } from '../src/core/providers';
import { SessionGrants } from '../src/core/session';
import { Vault } from '../src/core/vault';
import { identityConfig } from './support/identity';
import { openTestDb } from './support/pg';

const provider = defineProvider({
  id: 'acme',
  authorizeUrl: 'https://acme.test/oauth/authorize',
  tokenUrl: 'https://acme.test/oauth/token',
  scopesDefault: [],
  egressAllow: ['api.acme.test'],
  refresh: 'none',
  pkce: false,
  clientId: 'client',
  clientSecret: 'secret',
});

const identity = (userId: string) => ({
  enterpriseId: null,
  teamId: 'T1',
  userId,
});

async function rowCount(db: Db, table: string): Promise<number> {
  const row = await db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM ${table}`);
  return Number(row?.count ?? 0);
}

test('BrokerServer.sweepExpired owns every lifecycle family and preserves canonical outcomes', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, randomBytes(32), { idleMs: 60_000 });
  const audit = new Audit(db);
  const events: VouchrEvent[] = [];
  const healthEvents: CredentialHealthEvent[] = [];
  const server = createBroker({
    providers: [provider],
    vault,
    audit,
    db,
    identitySecret: identityConfig('lifecycle'),
    onEvent: (event) => { events.push(event); },
    onCredentialHealth: (event) => { healthEvents.push(event); },
  });

  const expiredIdentity = identity('U_EXPIRED');
  await vault.upsert(userOwner(expiredIdentity), 'acme', {
    accessToken: 'expired-test-token',
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: null,
  });
  await db.run(
    `UPDATE connection SET created_at=0, last_used_at=0
     WHERE team_id=? AND owner_kind='user' AND owner_id=? AND provider=?`,
    ['T1', expiredIdentity.userId, 'acme'],
  );

  await new Consent(db).begin(
    identity('U_CONSENT'),
    provider,
    'https://vouchr.test/oauth/callback',
    null,
  );

  const approvalKey: ApprovalKey = {
    teamId: 'T1',
    userId: 'U_APPROVAL',
    ownerKind: 'user',
    ownerId: 'U_APPROVAL',
    credentialId: randomUUID(),
    provider: 'acme',
    method: 'POST',
    origin: 'https://api.acme.test',
    host: 'api.acme.test',
    path: '/dangerous-action',
    queryHash: '',
    channel: null,
    thread: null,
  };
  await new Approvals(db).request(approvalKey);

  const sessions = new SessionGrants(db);
  await sessions.request(
    identity('U_SESSION_REQUEST'),
    'C_SESSION',
    'TH_REQUEST',
    'acme',
    randomUUID(),
  );
  await sessions.grant(
    identity('U_SESSION_GRANT'),
    'C_SESSION',
    'TH_GRANT',
    'acme',
    60_000,
    randomUUID(),
  );

  assert.ok(await new UserProvisioningRequests(db, vault).issue(
    identity('U_USER_SETUP'),
    'acme',
  ));
  const channelProvisioning = new ChannelProvisioningRequests(db, vault);
  assert.ok(await channelProvisioning.issue(
    identity('U_CHANNEL_SETUP'),
    'C_SETUP',
    'acme',
    await vault.userProvisioningIssuedAt(),
  ));

  await db.run(`UPDATE consent_request SET created_at=0`);
  await db.run(`UPDATE approval_request SET expires_at=0`);
  await db.run(`UPDATE session_request SET expires_at=0`);
  await db.run(`UPDATE session_grant SET expires_at=0`);
  await db.run(`UPDATE user_provisioning_request SET expires_at=0`);
  await db.run(`UPDATE channel_provisioning_request SET expires_at=0`);

  for (const table of [
    'connection',
    'consent_request',
    'approval_request',
    'session_request',
    'session_grant',
    'user_provisioning_request',
    'channel_provisioning_request',
  ]) {
    assert.equal(await rowCount(db, table), 1, `${table} fixture must reach the public sweep`);
  }
  assert.equal(await rowCount(db, 'audit'), 0);

  assert.equal(await server.sweepExpired(), 1, 'the compatible count is expired credentials only');

  for (const table of [
    'connection',
    'consent_request',
    'approval_request',
    'session_request',
    'session_grant',
    'user_provisioning_request',
    'channel_provisioning_request',
  ]) {
    assert.equal(await rowCount(db, table), 0, `${table} must be reclaimed by the broker facade`);
  }

  assert.deepEqual(events, [{ type: 'expired', count: 1 }]);
  assert.deepEqual(healthEvents, [{
    type: 'expired',
    owner: { teamId: 'T1', kind: 'user', id: 'U_EXPIRED' },
    provider: 'acme',
  }]);

  const rows = await db.all<{
    action: string;
    actor: string | null;
    user_id: string;
    provider: string;
    meta: string;
  }>(`SELECT action, actor, user_id, provider, meta FROM audit ORDER BY action`);
  assert.equal(rows.length, 2);

  const denied = rows.find((row) => row.action === 'denied');
  assert.equal(denied?.actor, 'system');
  assert.equal(denied?.user_id, 'U_APPROVAL');
  assert.equal(denied?.provider, 'acme');
  assert.deepEqual(JSON.parse(denied?.meta ?? '{}'), {
    host: 'api.acme.test',
    method: 'POST',
    actionFingerprint: approvalActionFingerprint(approvalKey),
    reason: 'approval-expired',
  });
  assert.ok(!String(denied?.meta).includes(approvalKey.path), 'raw approval paths stay out of audit');

  const revoke = rows.find((row) => row.action === 'revoke');
  assert.equal(revoke?.actor, null);
  assert.equal(revoke?.user_id, 'U_EXPIRED');
  assert.equal(revoke?.provider, 'acme');
  assert.deepEqual(JSON.parse(revoke?.meta ?? '{}'), {
    reason: 'expired',
    owner_kind: 'user',
  });

  server.close();
});
