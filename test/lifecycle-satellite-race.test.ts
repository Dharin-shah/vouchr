import { randomBytes, randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Approvals, type ApprovalKey } from '../src/core/approval';
import { Audit } from '../src/core/audit';
import { openDb, type Db } from '../src/core/db';
import { NotificationState } from '../src/core/health';
import type { SlackIdentity } from '../src/core/identity';
import { userOwner } from '../src/core/owner';
import { SessionGrants } from '../src/core/session';
import { sweepLifecycle } from '../src/core/sweep';
import { Vault } from '../src/core/vault';
import { testDbUrl } from './support/pg';

const IDENTITY: SlackIdentity = {
  enterpriseId: null,
  teamId: 'T1',
  userId: 'U1',
};
const PROVIDER = 'acme';

interface Deferred {
  promise: Promise<void>;
  resolve: () => void;
}

function deferred(): Deferred {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

async function within<T>(promise: Promise<T>, message: string, ms = 8_000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Pause the coordinator after its expired-row snapshot has crossed the database boundary, but
 * before deleteExpired can re-check the row. A second pool can then land a real reconnect and its
 * generation-bound satellites in the exact stale-snapshot window. */
function pauseAfterExpiredSnapshot(db: Db, captured: Deferred, release: Deferred): Db {
  let paused = false;
  return new Proxy(db, {
    get(target, property) {
      if (property === 'all') {
        return async <T = any>(sql: string, params: any[] = []): Promise<T[]> => {
          const rows = await target.all<T>(sql, params);
          if (
            !paused &&
            sql.includes('SELECT team_id, owner_kind, owner_id, provider FROM connection WHERE')
          ) {
            paused = true;
            captured.resolve();
            await release.promise;
          }
          return rows;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

async function count(db: Db, table: string): Promise<number> {
  const row = await db.get<{ count: number }>(`SELECT COUNT(*)::int AS count FROM ${table}`);
  return row?.count ?? 0;
}

test('lifecycle stale snapshot cannot purge a reconnect generation or its fresh satellites', async (t) => {
  const url = await testDbUrl(t);
  const [sweepRaw, writerDb] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => {
    await Promise.all([sweepRaw.close(), writerDb.close()]);
  });

  const snapshotCaptured = deferred();
  const releaseSnapshot = deferred();
  t.after(releaseSnapshot.resolve);
  const sweepDb = pauseAfterExpiredSnapshot(sweepRaw, snapshotCaptured, releaseSnapshot);
  const key = randomBytes(32);
  const sweepVault = new Vault(sweepDb, key, { idleMs: 60_000 });
  const writerVault = new Vault(writerDb, key, { idleMs: 60_000 });
  const owner = userOwner(IDENTITY);
  const token = (suffix: string) => ({
    accessToken: `synthetic-lifecycle-${suffix}`,
    refreshToken: null,
    scopes: '',
    expiresAt: null,
    externalAccount: null,
  });

  assert.equal(await sweepVault.upsert(owner, PROVIDER, token('stale')), true);
  await sweepRaw.run(
    `UPDATE connection SET created_at=0, last_used_at=0
      WHERE team_id=? AND owner_kind='user' AND owner_id=? AND provider=?`,
    [IDENTITY.teamId, IDENTITY.userId, PROVIDER],
  );

  const sweeping = sweepLifecycle({
    db: sweepDb,
    vault: sweepVault,
    audit: new Audit(sweepDb),
  });
  await within(
    snapshotCaptured.promise,
    'lifecycle sweep did not expose the expired-row snapshot barrier',
  );

  let setupFailure: unknown;
  let freshCredentialId: string | null = null;
  try {
    assert.equal(await writerVault.upsert(owner, PROVIDER, token('fresh')), true);
    freshCredentialId = await writerVault.liveId(owner, PROVIDER);
    assert.ok(freshCredentialId, 'the second handle must commit a fresh credential generation');

    const approvalKey: ApprovalKey = {
      teamId: IDENTITY.teamId,
      userId: IDENTITY.userId,
      ownerKind: 'user',
      ownerId: IDENTITY.userId,
      credentialId: freshCredentialId,
      provider: PROVIDER,
      method: 'POST',
      origin: 'https://api.acme.test',
      host: 'api.acme.test',
      path: '/fresh-action',
      queryHash: '',
      channel: 'C_APPROVAL',
      thread: 'TH_APPROVAL',
    };
    await new Approvals(writerDb).request(approvalKey);

    const sessions = new SessionGrants(writerDb);
    await sessions.request(
      IDENTITY,
      'C_SESSION',
      'TH_REQUEST',
      PROVIDER,
      freshCredentialId,
    );
    await sessions.grant(
      IDENTITY,
      'C_SESSION',
      'TH_GRANT',
      PROVIDER,
      60_000,
      freshCredentialId,
    );

    const now = Date.now();
    await writerDb.run(
      `INSERT INTO user_provisioning_request
        (id, team_id, user_id, provider, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
      [randomUUID(), IDENTITY.teamId, IDENTITY.userId, PROVIDER, now, now + 60_000],
    );
    assert.equal(
      await new NotificationState(writerDb).claim(owner, PROVIDER, 'expiring_soon', now),
      true,
    );

    for (const table of [
      'connection',
      'approval_request',
      'session_request',
      'session_grant',
      'user_provisioning_request',
      'notification_state',
    ]) {
      assert.equal(await count(writerDb, table), 1, `${table} must exist before releasing the stale sweep`);
    }
  } catch (error) {
    setupFailure = error;
  } finally {
    releaseSnapshot.resolve();
  }

  const swept = await within(sweeping, 'lifecycle sweep did not settle after reconnect');
  if (setupFailure) throw setupFailure;
  assert.equal(swept, 0, 'the stale snapshot must not count the replacement generation as deleted');
  assert.equal(await writerVault.liveId(owner, PROVIDER), freshCredentialId);

  for (const table of [
    'connection',
    'approval_request',
    'session_request',
    'session_grant',
    'user_provisioning_request',
    'notification_state',
  ]) {
    assert.equal(await count(writerDb, table), 1, `${table} must survive the stale lifecycle sweep`);
  }
  assert.equal(
    await count(writerDb, 'audit'),
    0,
    'a skipped stale delete must not publish an expiry audit',
  );
});
