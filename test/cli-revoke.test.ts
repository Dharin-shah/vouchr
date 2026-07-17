import { test, type TestContext } from 'node:test';
import { openTestDb, testDbUrl } from './support/pg';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import {
  ChannelProvisioningRequests,
  issueUserProvisioningRequest,
  UserProvisioningRequests,
} from '../src/core/provisioning';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { selectRevocations, revokeConnection, countPendingForProvider, purgePendingForProvider } from '../src/core/offboard';
import { userOwner, channelOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';
import { ChannelConfig } from '../src/core/channelConfig';
import { configureChannelCredential } from '../src/core/channelCredential';

const KEY = randomBytes(32);

// Google-like: form body `token=<token>`, has a revoke endpoint.
const revocable = defineProvider({
  id: 'revocable',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  refresh: 'rotating',
  pkce: true,
  revokeUrl: 'https://acme.example/revoke',
  clientId: 'id',
  clientSecret: 'sec',
});

// No revoke endpoint (Notion-style): an upstream revoke is a no-op → reported SKIPPED, never success.
const norevoke = defineProvider({
  id: 'norevoke', authorizeUrl: 'https://no.example/a', tokenUrl: 'https://no.example/t',
  scopesDefault: [], egressAllow: ['api.no.example'], refresh: 'none', pkce: false, clientId: 'id', clientSecret: 'sec',
});

const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });

/** Seed 3 connections across 2 teams: T1 user U1, T1 channel C1, T2 user U2 — all for `revocable`. */
async function seed(t: TestContext) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable', tok('TOK_U1'));
  await vault.upsert(channelOwner('T1', 'C1'), 'revocable', tok('TOK_C1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T2', userId: 'U2' }), 'revocable', tok('TOK_U2'));
  return { db, vault, audit: new Audit(db), consent: new Consent(db), sessions: new SessionGrants(db), registry: new ProviderRegistry([revocable]) };
}

test('dry-run (selectRevocations) matches without mutating; filters compose', async (t) => {
  const { db, vault } = await seed(t);
  assert.equal((await selectRevocations(db, { provider: 'revocable' })).length, 3);
  assert.equal((await selectRevocations(db, { provider: 'revocable', teamId: 'T1' })).length, 2);
  assert.equal((await selectRevocations(db, { provider: 'revocable', userId: 'U1' })).length, 1);
  assert.equal((await selectRevocations(db, { provider: 'revocable', channel: 'C1' })).length, 1);
  assert.equal((await selectRevocations(db, { provider: 'other' })).length, 0);
  // Nothing was deleted by selecting.
  assert.ok(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'));
  assert.equal((await db.get('SELECT COUNT(*) AS n FROM connection') as any).n, 3);
});

test('--team T1 revokes only T1 rows, calls upstream revoke, writes audit; T2 untouched', async (t) => {
  const { db, vault, audit, consent, sessions, registry } = await seed(t);
  const realFetch = globalThis.fetch;
  const revokedTokens: string[] = [];
  globalThis.fetch = (async (_url: any, init: any) => {
    revokedTokens.push(new URLSearchParams(init.body).get('token')!);
    return new Response('', { status: 200 });
  }) as any;
  try {
    const rows = await selectRevocations(db, { provider: 'revocable', teamId: 'T1' });
    for (const r of rows) {
      const out = await revokeConnection(vault, audit, consent, sessions, registry, r, 'revocable');
      assert.equal(out.removed, true);
      assert.equal(out.upstreamOk, true);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
  // Only the two T1 rows are gone; the T2 user row survives (filters compose).
  assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'), null);
  assert.equal(await vault.get(channelOwner('T1', 'C1'), 'revocable'), null);
  assert.ok(await vault.get(userOwner({ enterpriseId: null, teamId: 'T2', userId: 'U2' }), 'revocable'));
  // Both live tokens hit the upstream revoke endpoint.
  assert.deepEqual(revokedTokens.sort(), ['TOK_C1', 'TOK_U1']);
  // One audit 'revoke' row per revoked connection, no token material in meta.
  const rows = (await db.all('SELECT meta FROM audit WHERE action=?', ['revoke'])) as any[];
  assert.equal(rows.length, 2);
  for (const r of rows) assert.ok(!r.meta.includes('TOK_'));
});

test('failing upstream revoke still deletes locally and reports upstreamOk=false', async (t) => {
  const { db, vault, audit, consent, sessions, registry } = await seed(t);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('nope', { status: 500 })) as any;
  try {
    const [row] = await selectRevocations(db, { provider: 'revocable', userId: 'U1' });
    const out = await revokeConnection(vault, audit, consent, sessions, registry, row, 'revocable');
    assert.equal(out.removed, true); // local delete is the security-meaningful action
    assert.equal(out.upstreamOk, false); // best-effort revoke failed, but did not fail the delete
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'), null);
  assert.equal(JSON.parse((await db.get('SELECT meta FROM audit WHERE action=?', ['revoke']) as any).meta).ok, false);
});

test('local delete is guaranteed even with a wrong key and no registry (break-glass invariant)', async (t) => {
  // P1: if the master key / provider registry are unavailable, the CLI still constructs a Vault with a
  // throwaway key and no registry. revokeConnection must delete locally regardless — the token read
  // fails to decrypt (swallowed) and upstream revoke is skipped, but the credential is gone.
  const { db, audit, consent, sessions } = await seed(t);
  const wrongKeyVault = new Vault(db, randomBytes(32)); // a DIFFERENT key than the data was sealed with
  const [row] = await selectRevocations(db, { provider: 'revocable', userId: 'U1' });
  const out = await revokeConnection(wrongKeyVault, audit, consent, sessions, undefined, row, 'revocable');
  assert.equal(out.removed, true); // deleted despite being unable to decrypt the token
  assert.equal(out.upstreamOk, true); // no registry → upstream revoke skipped, not failed
  assert.equal(await wrongKeyVault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'), null);
});

test('pending consent, sessions, and key setup with NO connection are counted and purged for the scope', async (t) => {
  // P2: pending authority without a live connection must still be cleared, or it can recreate
  // access after the break-glass run.
  const { db } = await seed(t);
  const id: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U_ORPHAN' }; // no connection row
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);
  await consent.begin(id, revocable, 'https://broker.example/cb', 'C9');
  const orphanGeneration = '00000000-0000-4000-8000-000000000001';
  await sessions.request(id, 'C9', 'THREAD', 'revocable', orphanGeneration);
  await sessions.grant(id, 'C9', 'THREAD', 'revocable', 60_000, orphanGeneration);
  const vault = new Vault(db, KEY);
  assert.ok(await new UserProvisioningRequests(db, vault).issue(id, 'revocable'));
  assert.ok(await new ChannelProvisioningRequests(db, vault).issue(
    id,
    'C9',
    'revocable',
    await vault.userProvisioningIssuedAt(),
  ));
  // A different provider's pending state must survive the scoped purge.
  await consent.begin(id, { ...revocable, id: 'other' } as any, 'https://broker.example/cb', 'C9');

  assert.deepEqual(await countPendingForProvider(db, { provider: 'revocable' }), {
    consents: 1,
    requests: 1,
    grants: 1,
    provisioning: 1,
    channelProvisioning: 1,
  });
  const purged = await purgePendingForProvider(db, { provider: 'revocable' });
  assert.deepEqual(purged, {
    consents: 1,
    requests: 1,
    grants: 1,
    provisioning: 1,
    channelProvisioning: 1,
  });
  assert.deepEqual(await countPendingForProvider(db, { provider: 'revocable' }), {
    consents: 0,
    requests: 0,
    grants: 0,
    provisioning: 0,
    channelProvisioning: 0,
  });
  assert.deepEqual(await countPendingForProvider(db, { provider: 'other' }), {
    consents: 1,
    requests: 0,
    grants: 0,
    provisioning: 0,
    channelProvisioning: 0,
  }); // untouched
});

test('pending purge respects the team/user scope', async (t) => {
  const { db } = await seed(t);
  const consent = new Consent(db);
  await consent.begin({ enterpriseId: null, teamId: 'T1', userId: 'U1' }, revocable, 'https://x/cb', null);
  await consent.begin({ enterpriseId: null, teamId: 'T2', userId: 'U2' }, revocable, 'https://x/cb', null);
  const provisioning = new UserProvisioningRequests(db, new Vault(db, KEY));
  assert.ok(await provisioning.issue({ enterpriseId: null, teamId: 'T1', userId: 'U_SETUP_1' }, 'revocable'));
  assert.ok(await provisioning.issue({ enterpriseId: null, teamId: 'T2', userId: 'U_SETUP_2' }, 'revocable'));
  const purged = await purgePendingForProvider(db, { provider: 'revocable', teamId: 'T1' });
  assert.equal(purged.consents, 1); // only T1
  assert.equal(purged.provisioning, 1); // only T1
  assert.deepEqual(await countPendingForProvider(db, { provider: 'revocable', teamId: 'T2' }), {
    consents: 1,
    requests: 0,
    grants: 0,
    provisioning: 1,
    channelProvisioning: 0,
  });
});

test('--channel treats a consent channel as origin, not shared-credential ownership', async (t) => {
  const { db } = await seed(t);
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U_ORIGIN' };
  await new Consent(db).begin(identity, revocable, 'https://x/cb', 'C1');
  const vault = new Vault(db, KEY);
  const channelRequests = new ChannelProvisioningRequests(db, vault);
  assert.ok(await channelRequests.issue(
    identity,
    'C1',
    'revocable',
    await vault.userProvisioningIssuedAt(),
  ));

  assert.deepEqual(await countPendingForProvider(db, {
    provider: 'revocable', channel: 'C1',
  }), {
    consents: 0,
    requests: 0,
    grants: 0,
    provisioning: 0,
    channelProvisioning: 1,
  });
  assert.deepEqual(await purgePendingForProvider(db, {
    provider: 'revocable', channel: 'C1',
  }), {
    consents: 0,
    requests: 0,
    grants: 0,
    provisioning: 0,
    channelProvisioning: 1,
  });
  assert.equal(
    (await db.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM consent_request WHERE user_id=? AND provider=?`,
      [identity.userId, 'revocable'],
    ))?.n,
    1,
    'a channel-owner revoke must not consume a user consent merely because it originated there',
  );
});

test('--user does not treat the admin actor as owner of a channel setup request', async (t) => {
  const { db } = await seed(t);
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };
  const vault = new Vault(db, KEY);
  const requests = new ChannelProvisioningRequests(db, vault);
  assert.ok(await requests.issue(
    identity,
    'C_SHARED',
    'revocable',
    await vault.userProvisioningIssuedAt(),
  ));

  assert.deepEqual(
    await purgePendingForProvider(db, { provider: 'revocable', userId: identity.userId }),
    {
      consents: 0,
      requests: 0,
      grants: 0,
      provisioning: 0,
      channelProvisioning: 0,
    },
  );
  assert.equal(
    (await db.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM channel_provisioning_request WHERE user_id=?`,
      [identity.userId],
    ))?.n,
    1,
  );
});

test('a retired provider represented only by a channel setup request remains revocable', async (t) => {
  const { db } = await seed(t);
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };
  const vault = new Vault(db, KEY);
  assert.ok(await new ChannelProvisioningRequests(db, vault).issue(
    identity,
    'C_RETIRED',
    'retired-channel',
    await vault.userProvisioningIssuedAt(),
  ));
  const purged = await purgePendingForProvider(db, {
    provider: 'retired-channel',
    channel: 'C_RETIRED',
  });
  assert.equal(purged.channelProvisioning, 1);
});

test('scoped revoke fences an invisible pre-insert user setup without blocking a sibling or fresh setup', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const vaultA = new Vault(dbA, KEY);
  const blocked = { enterpriseId: null, teamId: 'T1', userId: 'U_BLOCKED' };
  const sibling = { enterpriseId: null, teamId: 'T1', userId: 'U_SIBLING' };
  const siblingIssuedAt = await vaultA.userProvisioningIssuedAt();
  const realLock = vaultA.withCredentialLock.bind(vaultA);
  let entered!: () => void;
  let release!: () => void;
  const beforeLock = new Promise<void>((resolve) => { entered = resolve; });
  const resume = new Promise<void>((resolve) => { release = resolve; });
  vaultA.withCredentialLock = (async (...args: Parameters<Vault['withCredentialLock']>) => {
    entered();
    await resume;
    return realLock(...args);
  }) as Vault['withCredentialLock'];

  const oldSetup = issueUserProvisioningRequest(vaultA, blocked, 'revocable');
  await beforeLock;
  await purgePendingForProvider(
    dbB,
    { provider: 'revocable', userId: blocked.userId },
    { providerRegistered: true },
  );
  release();
  assert.equal(await oldSetup, null);

  assert.ok(
    await issueUserProvisioningRequest(vaultA, sibling, 'revocable', siblingIssuedAt),
    'a user-scoped marker must not invalidate a sibling user in the same team',
  );
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.ok(
    await issueUserProvisioningRequest(vaultA, blocked, 'revocable'),
    'a genuinely new setup after the marker remains possible',
  );
  const marker = await dbA.get<Record<string, unknown>>(
    `SELECT provider, scope_kind, scope_key, created_at
       FROM provisioning_revocation_tombstone`,
  );
  assert.equal(marker?.scope_kind, 'user');
  assert.doesNotMatch(JSON.stringify(marker), /U_BLOCKED|U_SIBLING/);
});

test('a marker-only retired provider remains recognized so a later revoke refreshes its fence', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U_RETIRED' };
  const filter = { provider: 'retired-provider', userId: identity.userId };
  await purgePendingForProvider(dbB, filter, { providerRegistered: true });
  await new Promise((resolve) => setTimeout(resolve, 5));

  const vault = new Vault(dbA, KEY);
  const issuedAt = await vault.userProvisioningIssuedAt();
  const realLock = vault.withCredentialLock.bind(vault);
  let entered!: () => void;
  let release!: () => void;
  const beforeLock = new Promise<void>((resolve) => { entered = resolve; });
  const resume = new Promise<void>((resolve) => { release = resolve; });
  vault.withCredentialLock = (async (...args: Parameters<Vault['withCredentialLock']>) => {
    entered();
    await resume;
    return realLock(...args);
  }) as Vault['withCredentialLock'];
  const delayed = issueUserProvisioningRequest(
    vault,
    identity,
    filter.provider,
    issuedAt,
  );
  await beforeLock;
  // No registry entry or live/pending row remains. The validated first marker is the only durable
  // recognition, and must authorize refreshing this exact fence rather than rejecting the run.
  await purgePendingForProvider(dbB, filter);
  release();
  assert.equal(await delayed, null);
  assert.equal(
    (await dbA.get<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM user_provisioning_request WHERE provider=?`,
      [filter.provider],
    ))?.n,
    0,
  );
});

test('a failed break-glass fence leaves pending authority intact and never reports a purge', async (t) => {
  const db = await openTestDb(t);
  const identity: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  await new Consent(db).begin(identity, revocable, 'https://broker.example/callback', 'C1');
  const failingDb = {
    get: db.get.bind(db),
    all: db.all.bind(db),
    run: db.run.bind(db),
    withRefreshLock: async () => {
      throw new Error('provisioning fence unavailable');
    },
  } as any;

  await assert.rejects(
    purgePendingForProvider(
      failingDb,
      { provider: 'revocable', teamId: identity.teamId, userId: identity.userId },
      { providerRegistered: true },
    ),
    /provisioning fence unavailable/,
  );
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM consent_request')).n, 1);
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone')).n, 0);
});

test('channel-scoped revoke fences a delayed shared write without blocking a sibling channel', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'ADMIN' };
  const vaultA = new Vault(dbA, KEY);
  const issuedAt = await vaultA.userProvisioningIssuedAt();
  const realLock = vaultA.withCredentialLock.bind(vaultA);
  let entered!: () => void;
  let release!: () => void;
  const beforeLock = new Promise<void>((resolve) => { entered = resolve; });
  const resume = new Promise<void>((resolve) => { release = resolve; });
  vaultA.withCredentialLock = (async (...args: Parameters<Vault['withCredentialLock']>) => {
    entered();
    await resume;
    return realLock(...args);
  }) as Vault['withCredentialLock'];
  const modeConflict = (mode: 'per-user' | 'session'): never => {
    throw new Error(`unexpected mode ${mode}`);
  };
  const delayed = configureChannelCredential({
    vault: vaultA,
    audit: new Audit(dbA),
    channelConfig: new ChannelConfig(dbA),
    identity,
    channel: 'C_BLOCKED',
    providerId: 'revocable',
    issuance: issuedAt,
    credential: { kind: 'secret', token: tok('DELAYED_CHANNEL_TOKEN') },
    modeConflict,
  });
  await beforeLock;
  await purgePendingForProvider(
    dbB,
    { provider: 'revocable', channel: 'C_BLOCKED' },
    { providerRegistered: true },
  );
  release();
  assert.equal(await delayed, false);
  assert.equal(await vaultA.has(channelOwner('T1', 'C_BLOCKED'), 'revocable'), false);

  assert.equal(await configureChannelCredential({
    vault: vaultA,
    audit: new Audit(dbA),
    channelConfig: new ChannelConfig(dbA),
    identity,
    channel: 'C_SIBLING',
    providerId: 'revocable',
    issuance: issuedAt,
    credential: { kind: 'secret', token: tok('SIBLING_CHANNEL_TOKEN') },
    modeConflict,
  }), true);
  assert.equal(await vaultA.has(channelOwner('T1', 'C_SIBLING'), 'revocable'), true);
});

for (const kind of ['vault', 'dry-run', 'reference'] as const) {
  test(`exported Vault ${kind} channel write cannot cross a confirmed scoped revoke`, async (t) => {
    const url = await testDbUrl(t);
    const [dbA, dbB] = await Promise.all([
      openDb({ databaseUrl: url }),
      openDb({ databaseUrl: url }),
    ]);
    t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
    const channel = `C_LOW_${kind.replace('-', '_')}`;
    const owner = channelOwner('T1', channel);
    const vault = new Vault(dbA, KEY);
    const realLock = vault.withCredentialLock.bind(vault);
    let entered!: () => void;
    let release!: () => void;
    const beforeLock = new Promise<void>((resolve) => { entered = resolve; });
    const resume = new Promise<void>((resolve) => { release = resolve; });
    vault.withCredentialLock = (async (...args: Parameters<Vault['withCredentialLock']>) => {
      entered();
      await resume;
      return realLock(...args);
    }) as Vault['withCredentialLock'];

    const writing = kind === 'vault'
      ? vault.upsert(owner, 'revocable', tok('LOW_LEVEL_TOKEN'))
      : kind === 'dry-run'
        ? vault.upsertDryRun(owner, 'revocable', tok('LOW_LEVEL_DRY_TOKEN'))
        : vault.reference(owner, 'revocable', {
            source: 'aws-sm',
            secretRef: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:vouchr/low-level',
          });
    await beforeLock;
    await purgePendingForProvider(
      dbB,
      { provider: 'revocable', channel },
      { providerRegistered: true },
    );
    release();
    if (kind === 'reference') {
      await assert.rejects(writing, /channel credential provisioning was refused/);
    } else {
      assert.equal(await writing, false);
    }
    assert.equal(await vault.has(owner, 'revocable'), false);
  });
}

test('pending key purge waits for a consumed in-flight ticket so the CLI rescan catches its credential', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const identity: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U_RACE' };
  const owner = userOwner(identity);
  const vaultA = new Vault(dbA, KEY);
  const requests = new UserProvisioningRequests(dbA, vaultA);
  const requestId = await requests.issue(identity, 'revocable');
  assert.ok(requestId);

  let writeEntered!: () => void;
  let releaseWrite!: () => void;
  const entered = new Promise<void>((resolve) => { writeEntered = resolve; });
  const release = new Promise<void>((resolve) => { releaseWrite = resolve; });
  const writing = vaultA.upsertUser(
    owner,
    'revocable',
    tok('RACE_TOKEN'),
    requests.issuance(requestId, identity, 'revocable'),
    async () => {
      writeEntered();
      await release;
    },
  );
  await entered;

  let purgeSettled = false;
  const purging = purgePendingForProvider(dbB, {
    provider: 'revocable', teamId: identity.teamId, userId: identity.userId,
  }).then((result) => { purgeSettled = true; return result; });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(purgeSettled, false, 'purge must wait on the writer\'s canonical credential lock');
  releaseWrite();
  assert.equal(await writing, 'stored');
  const purged = await purging;
  assert.equal(purged.provisioning, 0, 'the winning writer consumed the ticket in its transaction');

  const settled = await selectRevocations(dbB, {
    provider: 'revocable', teamId: identity.teamId, userId: identity.userId,
  });
  assert.equal(settled.length, 1, 'the required post-purge rescan sees the settled credential');
  const vaultB = new Vault(dbB, KEY);
  await revokeConnection(
    vaultB,
    new Audit(dbB),
    new Consent(dbB),
    new SessionGrants(dbB),
    undefined,
    settled[0],
    'revocable',
  );
  assert.equal(await vaultB.has(owner, 'revocable'), false);
});

test('pending channel-key purge waits for a consumed ticket so the CLI rescan catches its credential', async (t) => {
  const url = await testDbUrl(t);
  const [dbA, dbB] = await Promise.all([
    openDb({ databaseUrl: url }),
    openDb({ databaseUrl: url }),
  ]);
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const identity: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U_ADMIN' };
  const channel = 'C_RACE';
  const owner = channelOwner(identity.teamId, channel);
  const vaultA = new Vault(dbA, KEY);
  const requests = new ChannelProvisioningRequests(dbA, vaultA);
  const requestId = await requests.issue(
    identity,
    channel,
    'revocable',
    await vaultA.userProvisioningIssuedAt(),
  );
  assert.ok(requestId);

  let writeEntered!: () => void;
  let releaseWrite!: () => void;
  const entered = new Promise<void>((resolve) => { writeEntered = resolve; });
  const release = new Promise<void>((resolve) => { releaseWrite = resolve; });
  const audit = new Audit(dbA);
  const originalRecord = audit.record.bind(audit);
  (audit as any).record = async (...args: any[]) => {
    writeEntered();
    await release;
    return (originalRecord as any)(...args);
  };
  const writing = configureChannelCredential({
    vault: vaultA,
    audit,
    channelConfig: new ChannelConfig(dbA),
    identity,
    channel,
    providerId: 'revocable',
    issuance: requests.issuance(requestId, identity, channel, 'revocable'),
    credential: { kind: 'secret', token: tok('CHANNEL_RACE_TOKEN') },
    modeConflict: (mode) => { throw new Error(`unexpected mode ${mode}`); },
  });
  await entered;

  let purgeSettled = false;
  const purging = purgePendingForProvider(dbB, {
    provider: 'revocable', teamId: identity.teamId, channel,
  }).then((result) => { purgeSettled = true; return result; });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(purgeSettled, false, 'purge must wait on the channel credential lock');
  releaseWrite();
  assert.equal(await writing, true);
  const purged = await purging;
  assert.equal(
    purged.channelProvisioning,
    0,
    'the winning writer consumed the channel ticket in its transaction',
  );

  const settled = await selectRevocations(dbB, {
    provider: 'revocable', teamId: identity.teamId, channel,
  });
  assert.equal(settled.length, 1, 'the required post-purge rescan sees the settled channel credential');
  assert.equal(await new Vault(dbB, KEY).has(owner, 'revocable'), true);
});

test('revoking a user connection clears that user+provider session grants and pending consent', async (t) => {
  const { db, vault, audit, consent, sessions, registry } = await seed(t);
  const id: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  const credentialId = await vault.liveId(userOwner(id), 'revocable');
  assert.ok(credentialId);
  await sessions.grant(id, 'C9', 'THREAD', 'revocable', 60_000, credentialId);
  await consent.begin(id, revocable, 'https://broker.example/cb', 'C9');
  assert.equal(await sessions.isGranted(id, 'C9', 'THREAD', 'revocable', credentialId), true);
  assert.equal((await db.get('SELECT COUNT(*) AS n FROM consent_request') as any).n, 1);

  const [row] = await selectRevocations(db, { provider: 'revocable', userId: 'U1' });
  await revokeConnection(vault, audit, consent, sessions, registry, row, 'revocable');

  assert.equal(await sessions.isGranted(id, 'C9', 'THREAD', 'revocable', credentialId), false); // grant cleared
  assert.equal((await db.get('SELECT COUNT(*) AS n FROM consent_request') as any).n, 0); // consent cleared
});

test('a provider with no revoke endpoint reports upstream SKIPPED, not success', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'norevoke', tok('TOK'));
  const realFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = (async () => { called = true; return new Response('', { status: 200 }); }) as any;
  try {
    const [row] = await selectRevocations(db, { provider: 'norevoke', userId: 'U1' });
    const out = await revokeConnection(vault, new Audit(db), new Consent(db), new SessionGrants(db), new ProviderRegistry([norevoke]), row, 'norevoke');
    assert.equal(out.removed, true);
    assert.equal(out.upstreamAttempted, false); // no revoke endpoint → not attempted
    assert.equal(called, false); // fetch never called
  } finally {
    globalThis.fetch = realFetch;
  }
  // The audit meta records the skip, not ok:true (a skip must not read as a success).
  const meta = JSON.parse((await db.get('SELECT meta FROM audit WHERE action=?', ['revoke']) as any).meta);
  assert.equal(meta.ok, undefined);
  assert.equal(meta.upstream, 'skipped');
});

test('revokeConnection swallows a post-delete audit failure (bulk sweep never strands rows)', async (t) => {
  const { db, vault, consent, sessions, registry } = await seed(t);
  const throwingAudit = { record: async () => { throw new Error('db down'); } } as any;
  const [row] = await selectRevocations(db, { provider: 'revocable', userId: 'U1' });
  // Must NOT throw — the local delete already happened and the loop must continue for the other rows.
  const out = await revokeConnection(vault, throwingAudit, consent, sessions, registry, row, 'revocable');
  assert.equal(out.removed, true);
  assert.equal(await vault.get(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'revocable'), null);
});

test('CLI refuses an empty --team scope instead of widening to every team', async (t) => {
  // The `--team --yes` typo leaves --team empty; the CLI must refuse rather than revoke all teams.
  const _dir = mkdtempSync(path.join(os.tmpdir(), 'vouchr-revoke-'));
  const dbPath = await testDbUrl(t);
  const keyB64 = randomBytes(32).toString('base64');
  const db = await openDb({ databaseUrl: dbPath });
  const vault = new Vault(db, Buffer.from(keyB64, 'base64'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'gh', tok('X1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T2', userId: 'U2' }), 'gh', tok('X2'));
  await db.close();

  const res = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'revoke', '--provider', 'gh', '--team', '--yes'], {
    env: { ...process.env, VOUCHR_DATABASE_URL: dbPath, VOUCHR_MASTER_KEY: keyB64 }, encoding: 'utf8',
  });
  assert.equal(res.status, 2); // refused with the usage exit code
  assert.match(res.stderr, /--team requires a value/); // strict parse: --yes can't be --team's value
  const db2 = await openDb({ databaseUrl: dbPath });
  const n = (await db2.get('SELECT COUNT(*) AS n FROM connection')) as any;
  await db2.close();
  assert.equal(n.n, 2); // BOTH teams' connections survive — nothing was revoked
});

test('CLI revoke rejects an unknown/typo scope flag instead of widening the blast radius', async (t) => {
  // `--teem T1` (typo) must be REJECTED, not silently dropped to leave an all-teams --yes revoke.
  const dbPath = await testDbUrl(t);
  const keyB64 = randomBytes(32).toString('base64');
  const db = await openDb({ databaseUrl: dbPath });
  const vault = new Vault(db, Buffer.from(keyB64, 'base64'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'gh', tok('X1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T2', userId: 'U2' }), 'gh', tok('X2'));
  await db.close();

  const res = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'revoke', '--provider', 'gh', '--teem', 'T1', '--yes'], {
    env: { ...process.env, VOUCHR_DATABASE_URL: dbPath, VOUCHR_MASTER_KEY: keyB64 }, encoding: 'utf8',
  });
  assert.equal(res.status, 2);
  assert.match(res.stderr, /unknown flag/);
  assert.doesNotMatch(res.stderr, /teem/); // SEC-1: the unknown flag name is not echoed back
  const db2 = await openDb({ databaseUrl: dbPath });
  const n = (await db2.get('SELECT COUNT(*) AS n FROM connection')) as any;
  await db2.close();
  assert.equal(n.n, 2); // nothing revoked — the typo did not widen to all teams
});

test('CLI revoke rejects an EMPTY scope (--team=) instead of treating it as "all teams"', async (t) => {
  const dbPath = await testDbUrl(t);
  const keyB64 = randomBytes(32).toString('base64');
  const db = await openDb({ databaseUrl: dbPath });
  const vault = new Vault(db, Buffer.from(keyB64, 'base64'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'gh', tok('X1'));
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T2', userId: 'U2' }), 'gh', tok('X2'));
  await db.close();

  for (const scope of ['--team=', '--user=', '--channel=']) {
    const res = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'revoke', '--provider', 'gh', scope, '--yes'], {
      env: { ...process.env, VOUCHR_DATABASE_URL: dbPath, VOUCHR_MASTER_KEY: keyB64 }, encoding: 'utf8',
    });
    assert.equal(res.status, 2, `${scope} must be refused`);
    assert.match(res.stderr, /requires a non-empty value/);
    const db2 = await openDb({ databaseUrl: dbPath });
    const n = (await db2.get('SELECT COUNT(*) AS n FROM connection')) as any;
    await db2.close();
    assert.equal(n.n, 2, `${scope} must delete nothing`); // both teams survive
  }
});

test('CLI revoke validates provider and mutually exclusive owner scopes before fencing', async (t) => {
  const dbPath = await testDbUrl(t);
  const keyB64 = randomBytes(32).toString('base64');
  const env = {
    ...process.env,
    VOUCHR_DATABASE_URL: dbPath,
    VOUCHR_MASTER_KEY: keyB64,
    VOUCHR_PROVIDERS: '[]',
  };
  for (const entry of [
    { args: ['--provider', 'bad/id', '--yes'], error: /valid provider id/ },
    {
      args: ['--provider', 'revocable', '--user', 'U1', '--channel', 'C1', '--yes'],
      error: /mutually exclusive/,
    },
  ]) {
    const res = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'revoke', ...entry.args], {
      env,
      encoding: 'utf8',
    });
    assert.equal(res.status, 2);
    assert.match(res.stderr, entry.error);
  }
  const db = await openDb({ databaseUrl: dbPath });
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone')).n, 0);
  await db.close();
});

test('CLI actual revoke refuses a valid unknown provider without persisting its id', async (t) => {
  const dbPath = await testDbUrl(t);
  const keyB64 = randomBytes(32).toString('base64');
  const res = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'bin/vouchr.ts', 'revoke', '--provider', 'retired-typo', '--yes'],
    {
      env: {
        ...process.env,
        VOUCHR_DATABASE_URL: dbPath,
        VOUCHR_MASTER_KEY: keyB64,
        VOUCHR_PROVIDERS: '[]',
      },
      encoding: 'utf8',
    },
  );
  assert.equal(res.status, 1);
  assert.match(res.stderr, /command failed/);
  const db = await openDb({ databaseUrl: dbPath });
  assert.equal((await db.get<any>('SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone')).n, 0);
  await db.close();
});

test('CLI dry-run writes no provisioning fence', async (t) => {
  const dbPath = await testDbUrl(t);
  const keyB64 = randomBytes(32).toString('base64');
  const db = await openDb({ databaseUrl: dbPath });
  const vault = new Vault(db, Buffer.from(keyB64, 'base64'));
  await vault.upsert(
    userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }),
    'revocable',
    tok('DRY_RUN_PROOF_TOKEN'),
  );
  await db.close();

  const res = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'bin/vouchr.ts', 'revoke', '--provider', 'revocable', '--dry-run'],
    {
      env: { ...process.env, VOUCHR_DATABASE_URL: dbPath, VOUCHR_MASTER_KEY: keyB64 },
      encoding: 'utf8',
    },
  );
  assert.equal(res.status, 0);
  const after = await openDb({ databaseUrl: dbPath });
  assert.equal((await after.get<any>('SELECT COUNT(*)::int AS n FROM connection')).n, 1);
  assert.equal((await after.get<any>('SELECT COUNT(*)::int AS n FROM provisioning_revocation_tombstone')).n, 0);
  await after.close();
});

test('CLI revoke does not echo a token-shaped positional or unknown-flag secret (SEC-1)', async (t) => {
  const dbPath = await testDbUrl(t);
  const keyB64 = randomBytes(32).toString('base64');
  const secret = 'ghp_TOPSECRETtokenBBBBBBBBBBBBBBBBBBBB';
  const env = { ...process.env, VOUCHR_DATABASE_URL: dbPath, VOUCHR_MASTER_KEY: keyB64 };
  for (const args of [['revoke', secret, '--yes'], ['revoke', `--${secret}`, '--yes']]) {
    const res = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', ...args], { env, encoding: 'utf8' });
    assert.notEqual(res.status, 0);
    assert.doesNotMatch(res.stderr + res.stdout, /ghp_TOPSECRET/, `must not echo the secret in ${args.join(' ')}`);
  }

  // Recognized flag values are untrusted too; a token pasted as --provider must not be reflected in
  // the scope summary even though parsing succeeds and the dry-run safely matches zero rows.
  const recognized = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', 'revoke', '--provider', secret, '--dry-run'], { env, encoding: 'utf8' });
  assert.equal(recognized.status, 0);
  assert.doesNotMatch(recognized.stderr + recognized.stdout, /ghp_TOPSECRET/);

  // The command itself is untrusted argv too. A credential pasted in that position must get a
  // useful but static usage error, never be reflected back into terminal logs.
  const unknownCommand = spawnSync(process.execPath, ['--import', 'tsx', 'bin/vouchr.ts', secret], {
    env, encoding: 'utf8',
  });
  assert.equal(unknownCommand.status, 2);
  assert.match(unknownCommand.stderr, /Unknown command/);
  assert.doesNotMatch(unknownCommand.stderr + unknownCommand.stdout, /ghp_TOPSECRET/);
});
