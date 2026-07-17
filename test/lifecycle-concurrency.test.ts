import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import { Audit } from '../src/core/audit';
import { openDb, type Db } from '../src/core/db';
import { dryRunAudit } from '../src/core/dryRun';
import type { SlackIdentity } from '../src/core/identity';
import { purgeChannelInteractionState } from '../src/core/interaction';
import { channelOwner, userOwner } from '../src/core/owner';
import { UserProvisioningRequests } from '../src/core/provisioning';
import { sweepLifecycle } from '../src/core/sweep';
import { Vault } from '../src/core/vault';
import { testDbUrl } from './support/pg';

const KEY = randomBytes(32);
const ID: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const PROVIDER = 'acme';
const DRY_TOKEN = {
  accessToken: 'synthetic-lifecycle-concurrency-token',
  refreshToken: null,
  scopes: '',
  expiresAt: null,
  externalAccount: null,
};

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function within<T>(promise: Promise<T>, ms = 8_000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('lifecycle concurrency test timed out')), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function postgresCode(error: unknown): string | null {
  try {
    return error && typeof error === 'object' && typeof (error as { code?: unknown }).code === 'string'
      ? (error as { code: string }).code
      : null;
  } catch {
    return null;
  }
}

function assertRetryableSweepOutcome(result: PromiseSettledResult<number>): void {
  if (result.status === 'fulfilled') return;
  const code = postgresCode(result.reason);
  assert.notEqual(code, '40P01', 'the lifecycle sweep must never enter PostgreSQL deadlock recovery');
  assert.equal(code, '55P03', 'a contended NOWAIT sweep may only fail as lock_not_available');
}

interface TransactionContext {
  ordinal: number;
  pid: number;
}

/** Decorate only transaction-bound handles. Nested `transaction()` calls stay on the same client,
 * matching PgClientDb, while the hook can pause/observe the lifecycle coordinator's table lock. */
function observeTransactions(
  db: Db,
  hooks: {
    onStart?: (context: TransactionContext) => void;
    exec?: (
      context: TransactionContext,
      sql: string,
      run: () => Promise<void>,
    ) => Promise<void>;
  },
): Db {
  if (!db.transaction) throw new Error('transaction observer requires PostgreSQL transactions');
  let ordinal = 0;
  return new Proxy(db, {
    get(target, property) {
      if (property === 'transaction') {
        return async <T>(fn: (tx: Db) => Promise<T>): Promise<T> => target.transaction!(async (tx) => {
          const current = ++ordinal;
          const row = await tx.get<{ pid: number }>(`SELECT pg_backend_pid() AS pid`);
          if (!Number.isSafeInteger(row?.pid)) throw new Error('could not observe PostgreSQL transaction');
          const context = { ordinal: current, pid: row!.pid };
          hooks.onStart?.(context);
          let wrapped!: Db;
          wrapped = new Proxy(tx, {
            get(txTarget, txProperty) {
              if (txProperty === 'transaction') {
                return async <U>(nested: (nestedTx: Db) => Promise<U>): Promise<U> => nested(wrapped);
              }
              if (txProperty === 'exec' && hooks.exec) {
                return (sql: string) => hooks.exec!(context, sql, () => tx.exec(sql));
              }
              const value = Reflect.get(txTarget, txProperty, txTarget);
              return typeof value === 'function' ? value.bind(txTarget) : value;
            },
          });
          return fn(wrapped);
        });
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

async function waitForRelationLock(
  observer: Db,
  pid: number,
  relations: readonly string[],
): Promise<void> {
  for (let attempt = 0; attempt < 250; attempt++) {
    const rows = await observer.all<{ relname: string; mode: string; granted: boolean }>(
      `SELECT c.relname, l.mode, l.granted
         FROM pg_locks l
         JOIN pg_class c ON c.oid=l.relation
        WHERE l.pid=? AND c.relname::text = ANY(?::text[])`,
      [pid, relations],
    );
    if (rows.length > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('timed out waiting for lifecycle relation lock');
}

async function databases(t: TestContext): Promise<{
  vaultDb: Db;
  sweepDb: Db;
  observerDb: Db;
}> {
  const url = await testDbUrl(t);
  const [vaultDb, sweepDb, observerDb] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => {
    await Promise.all([vaultDb.close(), sweepDb.close(), observerDb.close()]);
  });
  return { vaultDb, sweepDb, observerDb };
}

test('concurrent dry-run lifecycle sweeps never deadlock while upgrading their table locks', async (t) => {
  const { vaultDb, sweepDb, observerDb } = await databases(t);
  const vault = new Vault(vaultDb, KEY, { idleMs: 60_000 });
  const audit = dryRunAudit(new Audit(vaultDb));
  const owner = userOwner(ID);
  assert.equal(await vault.upsertDryRun(owner, PROVIDER, DRY_TOKEN), true);
  await vaultDb.run(
    `UPDATE connection SET created_at=0, last_used_at=0
      WHERE team_id=? AND owner_kind='user' AND owner_id=? AND provider=?`,
    [ID.teamId, ID.userId, PROVIDER],
  );

  const firstLocked = deferred<void>();
  const releaseFirst = deferred<void>();
  const secondStarted = deferred<number>();
  const observed = observeTransactions(sweepDb, {
    onStart: ({ ordinal, pid }) => {
      if (ordinal === 2) secondStarted.resolve(pid);
    },
    exec: async ({ ordinal }, sql, run) => {
      await run();
      if (ordinal === 1 && /^LOCK TABLE\b/.test(sql.trim())) {
        firstLocked.resolve();
        await releaseFirst.promise;
      }
    },
  });
  const sweep = () => sweepLifecycle({ db: observed, vault, audit, dryRun: true });

  const first = Promise.allSettled([sweep()]).then(([result]) => result);
  await firstLocked.promise;
  const second = Promise.allSettled([sweep()]).then(([result]) => result);
  const secondPid = await secondStarted.promise;
  // Under the buggy SHARE mode this observes the second granted SHARE lock before both DELETEs try
  // to upgrade. Under a self-exclusive/NOWAIT fix it observes either a waiter or prompt rejection.
  await Promise.race([
    waitForRelationLock(observerDb, secondPid, ['connection']),
    second.then(() => undefined),
  ]);
  releaseFirst.resolve();

  const outcomes = await within(Promise.all([first, second]));
  for (const outcome of outcomes) assertRetryableSweepOutcome(outcome);
  for (const outcome of outcomes) {
    if (outcome.status === 'rejected') {
      assert.equal(await sweepLifecycle({ db: sweepDb, vault, audit, dryRun: true }), 0);
    }
  }
  assert.equal(await vault.has(owner, PROVIDER), false);
  assert.equal(
    (await vaultDb.get<{ count: number }>(`SELECT COUNT(*)::int AS count FROM audit WHERE action='revoke'`))?.count,
    1,
    'one delete winner writes one expiry audit',
  );
});

test('provisioning-ticket consume and dry-run sweep settle without deadlock or partial mutation', async (t) => {
  const { vaultDb, sweepDb, observerDb } = await databases(t);
  const vault = new Vault(vaultDb, KEY, { idleMs: 60_000 });
  const audit = dryRunAudit(new Audit(vaultDb));
  const requests = new UserProvisioningRequests(vaultDb, vault);
  const requestId = await requests.issue(ID, PROVIDER);
  assert.ok(requestId);
  const consume = requests.issuance(requestId, ID, PROVIDER);
  if (typeof consume !== 'function') throw new Error('provisioning request must resolve inside the transaction');
  const requestDeleted = deferred<void>();
  const releaseWriter = deferred<void>();
  const issuance = async (tx: Db) => {
    const resolved = await consume(tx);
    requestDeleted.resolve();
    await releaseWriter.promise;
    return resolved;
  };

  const writer = Promise.allSettled([
    vault.upsertDryRunUser(
      userOwner(ID),
      PROVIDER,
      DRY_TOKEN,
      issuance,
      (tx) => audit.record(
        'config',
        ID,
        PROVIDER,
        { owner: 'user', kind: 'secret' },
        undefined,
        tx,
      ),
    ),
  ]).then(([result]) => result);
  await requestDeleted.promise;

  const sweepStarted = deferred<number>();
  const observed = observeTransactions(sweepDb, {
    onStart: ({ pid }) => sweepStarted.resolve(pid),
  });
  const sweep = Promise.allSettled([
    sweepLifecycle({ db: observed, vault, audit, dryRun: true }),
  ]).then(([result]) => result);
  const sweepPid = await sweepStarted.promise;
  // Current lock order holds connection while waiting for the writer's provisioning-table lock.
  // A safe implementation may instead reject NOWAIT or wait without holding a conflicting prefix.
  await Promise.race([
    waitForRelationLock(observerDb, sweepPid, ['connection', 'user_provisioning_request']),
    sweep.then(() => undefined),
  ]);
  releaseWriter.resolve();

  const [writerOutcome, sweepOutcome] = await within(Promise.all([writer, sweep]));
  assert.equal(writerOutcome.status, 'fulfilled', 'the ticket consume must not become the deadlock victim');
  if (writerOutcome.status === 'fulfilled') assert.equal(writerOutcome.value, 'stored');
  assertRetryableSweepOutcome(sweepOutcome);
  if (sweepOutcome.status === 'rejected') {
    assert.equal(await sweepLifecycle({ db: sweepDb, vault, audit, dryRun: true }), 0);
  }

  assert.equal(await vault.has(userOwner(ID), PROVIDER), true, 'the synthetic credential commits once');
  assert.equal(
    (await vaultDb.get<{ count: number }>(
      `SELECT COUNT(*)::int AS count FROM user_provisioning_request WHERE id=?`,
      [requestId],
    ))?.count,
    0,
    'the single-use ticket commits consumed with its credential',
  );
  assert.equal(
    (await vaultDb.get<{ count: number }>(`SELECT COUNT(*)::int AS count FROM audit WHERE action='config'`))?.count,
    1,
    'the credential and its audit companion commit together',
  );
  assert.equal(
    (await vaultDb.get<{ count: number }>(`SELECT COUNT(*)::int AS count FROM audit WHERE action='revoke'`))?.count,
    0,
    'a contended sweep cannot publish a rolled-back expiry',
  );
});

test('channel-governance tombstone purge cannot deadlock a dry-run channel-expiry sweep', async (t) => {
  const { vaultDb, sweepDb, observerDb } = await databases(t);
  const vault = new Vault(vaultDb, KEY, { idleMs: 60_000 });
  const audit = dryRunAudit(new Audit(vaultDb));
  const owner = channelOwner(ID.teamId, 'C_GOVERNANCE');
  assert.equal(await vault.upsertDryRun(owner, PROVIDER, DRY_TOKEN), true);
  await vaultDb.run(
    `UPDATE connection SET created_at=0, last_used_at=0
      WHERE team_id=? AND owner_kind='channel' AND owner_id=? AND provider=?`,
    [ID.teamId, owner.id, PROVIDER],
  );

  if (!vaultDb.transaction) throw new Error('governance race requires PostgreSQL transactions');
  const tombstoneHeld = deferred<void>();
  const releaseGovernance = deferred<void>();
  const governance = Promise.allSettled([
    vaultDb.transaction(async (tx) => {
      const wrapped = new Proxy(tx, {
        get(target, property) {
          if (property === 'run') {
            return async (sql: string, params?: any[]) => {
              const result = await tx.run(sql, params);
              if (/INSERT INTO channel_interaction_tombstone\b/.test(sql)) {
                tombstoneHeld.resolve();
                await releaseGovernance.promise;
              }
              return result;
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      await purgeChannelInteractionState(wrapped, ID.teamId, owner.id, PROVIDER);
    }),
  ]).then(([result]) => result);
  await tombstoneHeld.promise;

  const sweepStarted = deferred<number>();
  const observed = observeTransactions(sweepDb, {
    onStart: ({ pid }) => sweepStarted.resolve(pid),
  });
  const sweep = Promise.allSettled([
    sweepLifecycle({ db: observed, vault, audit, dryRun: true }),
  ]).then(([result]) => result);
  const sweepPid = await sweepStarted.promise;
  await Promise.race([
    waitForRelationLock(
      observerDb,
      sweepPid,
      ['connection', 'session_request', 'channel_interaction_tombstone'],
    ),
    sweep.then(() => undefined),
  ]);
  releaseGovernance.resolve();

  const [governanceOutcome, sweepOutcome] = await within(Promise.all([governance, sweep]));
  assert.equal(
    governanceOutcome.status,
    'fulfilled',
    'the governance mutation must not become a lifecycle deadlock victim',
  );
  assertRetryableSweepOutcome(sweepOutcome);
  if (sweepOutcome.status === 'rejected') {
    assert.equal(
      await sweepLifecycle({ db: sweepDb, vault, audit, dryRun: true }),
      1,
      'a contended sweep retries after the governance transaction commits',
    );
  }

  assert.equal(await vault.has(owner, PROVIDER), false);
  assert.equal(
    (await vaultDb.get<{ count: number }>(`SELECT COUNT(*)::int AS count FROM audit WHERE action='revoke'`))?.count,
    1,
    'the successful retry deletes and audits the channel credential exactly once',
  );
});
