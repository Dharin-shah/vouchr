import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { openTestDb, testDbUrl } from './support/pg';
import { openDb, type Db } from '../src/core/db';
import { boundedEnvelopeProvider } from '../src/core/crypto';
import { Vault, CredentialLockdownError, REVOKE_DECRYPT_TIMEOUT_MS } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { userOwner, channelOwner } from '../src/core/owner';
import {
  revokeAllCredentials,
  revokeConnection,
  enumerateStoredProviders,
  RESURRECTION_TABLES,
  selectRevocations,
  type RevokeAllDeps,
} from '../src/core/offboard';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';

const KEY = randomBytes(32);

// Upstream-revoke behavior is selected by the revoke host: ok.example → 200, fail.example → 400,
// slow.example → hangs (the caller's deadline fires). Each provider is otherwise a normal OAuth2.
const mk = (id: string, revokeHost?: string, oauthTimeoutMs?: number) =>
  defineProvider({
    id,
    authorizeUrl: 'https://auth.example/a',
    tokenUrl: 'https://auth.example/t',
    scopesDefault: ['x'],
    egressAllow: ['api.example'],
    refresh: revokeHost ? 'rotating' : 'none',
    pkce: false,
    clientId: 'id',
    clientSecret: 'sec',
    ...(revokeHost ? { revokeUrl: `https://${revokeHost}/revoke` } : {}),
    ...(revokeHost ? { revokeTarget: 'both' as const } : {}),
    ...(oauthTimeoutMs ? { oauthTimeoutMs } : {}),
  });

const revokOk = mk('revok_ok', 'ok.example');
const revokFail = mk('revok_fail', 'fail.example');
const revokSlow = mk('revok_slow', 'slow.example', 60);
const norevoke = mk('norevoke'); // no revoke endpoint
// `retired` is intentionally NOT registered — it exists only in stored rows.
const REGISTRY = new ProviderRegistry([revokOk, revokFail, revokSlow, norevoke]);

const tok = (accessToken: string, refreshToken: string | null = null) => ({
  accessToken,
  refreshToken,
  scopes: '',
  expiresAt: null,
  externalAccount: null,
});
const U = (n: string) => userOwner({ enterpriseId: null, teamId: 'T1', userId: n });

/** Stub global.fetch for the upstream revoke POSTs; restore in finally (TEST-3). Never inspects the
 *  token — only the host selects the response, mirroring real revoke endpoints. */
async function withFetch<T>(fn: (calls: { url: string; token: string | null }[]) => Promise<T>): Promise<T> {
  const calls: { url: string; token: string | null }[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: any, init?: any) => {
    const url = String(typeof input === 'string' ? input : input.url);
    calls.push({ url, token: new URLSearchParams(String(init?.body ?? '')).get('token') });
    if (url.includes('ok.example')) return new Response(null, { status: 200 });
    if (url.includes('fail.example')) return new Response(null, { status: 400 });
    if (url.includes('slow.example')) {
      // Hang until the caller aborts (its revoke deadline), then reject like a cancelled fetch.
      return await new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = real;
  }
}

async function count(db: Db, table: string): Promise<number> {
  const r = (await db.get(`SELECT COUNT(*) AS n FROM ${table}`)) as { n: number } | undefined;
  return Number(r?.n ?? 0);
}

/** Seed the full inventory the acceptance criteria call for: registered + unregistered providers,
 *  user + channel owners, vault + external-reference + dry-run + undecryptable connection rows, and
 *  every resurrection table + Slack installation rows. Returns the vault keyed by KEY. */
async function seed(t: TestContext): Promise<{ db: Db; vault: Vault }> {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  // Connections (one per upstream category).
  await vault.upsert(U('U1'), 'revok_ok', tok('AAA', 'RAAA'));    // → revoked (access + refresh)
  await vault.upsert(channelOwner('T1', 'C1'), 'revok_ok', tok('AAA')); // → revoked (channel owner)
  await vault.upsert(U('U2'), 'revok_fail', tok('BBB'));          // → revoke_failed (400)
  await vault.upsert(U('U3'), 'revok_slow', tok('CCC'));          // → revoke_failed (timeout)
  await vault.upsert(U('U4'), 'norevoke', tok('DDD'));            // → unsupported (no endpoint)
  await vault.upsert(U('U5'), 'retired', tok('EEE'));             // → unsupported (unregistered)
  await vault.reference(U('U6'), 'revok_ok', { source: 'aws-secrets-manager', secretRef: 'arn:x' }); // → external_reference
  await vault.upsertDryRun(U('U7'), 'revok_ok', tok('FFF'));      // → synthetic (dry-run)
  // Real envelope/KMS row, but the returned break-glass Vault intentionally has no envelope client:
  // local deletion must still complete and upstream must report undecryptable.
  const envelope = { wrapDataKey: async (d: Buffer) => d, unwrapDataKey: async (d: Buffer) => d };
  await new Vault(db, KEY, {}, envelope).upsert(U('U8'), 'revok_ok', tok('KMS_ACCESS', 'KMS_REFRESH'));
  // Compromised-DB metadata can itself be credential-shaped. Global reporting/audit must aggregate
  // unregistered values and use system identity rather than copying either value to an output sink.
  await db.run(
    `INSERT INTO connection (id, team_id, owner_kind, owner_id, provider, source, access_token_enc, scopes, created_at, updated_at)
     VALUES (?, 'T1', 'user', ?, ?, 'vault', ?, '', ?, ?)`,
    [randomUUID(), 'github_pat_OWNER_SECRET', 'ghp_DB_METADATA_SECRET', randomBytes(48), Date.now(), Date.now()],
  );

  // Resurrection paths — raw inserts with the minimal valid columns; exact counts matter.
  const now = Date.now();
  const later = now + 600_000;
  await db.run(`INSERT INTO consent_request (state, team_id, user_id, provider, pkce_verifier, created_at) VALUES (?, 'T1', 'U1', 'revok_ok', 'v', ?)`, [randomUUID(), now]);
  await db.run(`INSERT INTO consent_request (state, team_id, user_id, provider, pkce_verifier, created_at) VALUES (?, 'T1', 'U9', 'gone_provider', 'v', ?)`, [randomUUID(), now]); // pending for a provider with NO connection
  await db.run(`INSERT INTO session_request (id, team_id, channel, thread, user_id, provider, credential_id, created_at, expires_at) VALUES (?, 'T1', 'C1', 'th', 'U1', 'revok_ok', ?, ?, ?)`, [randomUUID(), randomUUID(), now, later]);
  await db.run(`INSERT INTO session_grant (team_id, channel, thread, user_id, provider, credential_id, created_at, expires_at) VALUES ('T1', 'C1', 'th', 'U1', 'revok_ok', ?, ?, ?)`, [randomUUID(), now, later]);
  await db.run(
    `INSERT INTO approval_request (id, action_key, team_id, user_id, owner_kind, owner_id, credential_id, provider, method, origin, host, path, channel, thread, governable_channel, status, created_at, expires_at)
     VALUES (?, 'k', 'T1', 'U1', 'user', 'U1', ?, 'revok_ok', 'POST', 'https://api.ok.example', 'api.ok.example', '/x', 'C1', 'th', 'C1', 'pending', ?, ?)`,
    [randomUUID(), randomUUID(), now, later],
  );
  await db.run(`INSERT INTO user_provisioning_request (id, team_id, user_id, provider, created_at, expires_at) VALUES (?, 'T1', 'U1', 'revok_ok', ?, ?)`, [randomUUID(), now, later]);
  await db.run(`INSERT INTO channel_provisioning_request (id, team_id, channel, user_id, provider, created_at, expires_at) VALUES (?, 'T1', 'C1', 'U1', 'revok_ok', ?, ?)`, [randomUUID(), now, later]);
  await db.run(`INSERT INTO notification_state (team_id, owner_kind, owner_id, provider, type, last_notified_at) VALUES ('T1', 'user', 'U1', 'revok_ok', 'expiring', ?)`, [now]);
  // Slack installation credentials (ciphertext columns; never printed).
  await db.run(`INSERT INTO installation (id, team_id, data, updated_at) VALUES (?, 'T1', ?, ?)`, [randomUUID(), randomBytes(32), now]);
  await db.run(`INSERT INTO installation (id, team_id, data, updated_at) VALUES (?, 'T2', ?, ?)`, [randomUUID(), randomBytes(32), now]);
  return { db, vault };
}

function deps(db: Db, vault: Vault, registry: ProviderRegistry | undefined = REGISTRY): RevokeAllDeps {
  return { vault, audit: new Audit(db), registry };
}

/** Every secret-bearing string that must never appear in the report/logs. */
const SECRETS = [
  'AAA', 'RAAA', 'BBB', 'CCC', 'DDD', 'EEE', 'FFF', 'KMS_ACCESS', 'KMS_REFRESH', 'arn:x',
  'github_pat_OWNER_SECRET', 'ghp_DB_METADATA_SECRET',
];
const assertNoSecrets = (blob: string) => {
  for (const s of SECRETS) assert.ok(!blob.includes(s), `report leaked secret ${s}`);
};

test('enumerateStoredProviders returns every stored provider incl. unregistered', async (t) => {
  const { db } = await seed(t);
  const providers = await enumerateStoredProviders(db);
  for (const p of ['revok_ok', 'revok_fail', 'revok_slow', 'norevoke', 'retired', 'gone_provider']) {
    assert.ok(providers.includes(p), `missing provider ${p}`);
  }
});

test('dry-run mutates nothing and emits no secret', async (t) => {
  const { db, vault } = await seed(t);
  const before = await snapshotCounts(db);
  const report = await withFetch((calls) =>
    revokeAllCredentials(db, deps(db, vault), { execute: false }).then((r) => {
      assert.equal(calls.length, 0, 'dry-run must make no upstream call');
      return r;
    }),
  );
  assert.equal(report.executed, false);
  assert.deepEqual(await snapshotCounts(db), before, 'dry-run must not delete a single row');
  assert.equal(report.matched.connections, 10);
  assert.equal(report.matched.installations, 2);
  assert.deepEqual(report.cleared, {
    connections: 0, consents: 0, sessionRequests: 0, sessionGrants: 0, approvals: 0,
    userProvisioning: 0, channelProvisioning: 0, notifications: 0, installations: 0,
  }, 'dry-run must never describe matched rows as cleared');
  assert.deepEqual(report.remaining, {
    credentials: 10,
    authorizations: 8,
    installations: 2,
  }, 'dry-run remaining counts describe the rows that still exist');
  // Metadata-only preview cannot predict the upstream OUTCOME — every revocable vault row counts as
  // "would attempt": U1, C1, U2, U3, U8 = 5. The execute path splits these into revoked/failed/undecryptable.
  assert.equal(report.upstream.would_attempt, 5);
  assert.equal(report.upstreamAttempted, 0, 'dry-run makes no real provider call');
  assert.equal(report.upstream.revoked, 0);
  assert.equal(report.upstream.external_reference, 1);
  assert.equal(report.upstream.unsupported, 3);
  assert.equal(report.upstream.synthetic, 1);
  assert.equal(report.unregistered.providers, 3, 'retired + auth-only gone provider + hostile metadata provider');
  assert.equal(report.unregistered.connections, 2, 'retired + hostile metadata connection');
  assert.equal(report.unregistered.attempted, 0);
  assert.ok(report.byProvider.every((provider) => provider.attempted === 0));
  assertNoSecrets(JSON.stringify(report));
});

test('execute removes every local artifact and reports upstream categories distinctly', async (t) => {
  const { db, vault } = await seed(t);
  const { report, calls } = await withFetch(async (calls) => ({
    report: await revokeAllCredentials(db, deps(db, vault), { execute: true }),
    calls,
  }));

  // Distinct upstream buckets (success ≠ failure ≠ unsupported ≠ undecryptable ≠ external ≠ synthetic).
  assert.equal(report.upstream.revoked, 2, 'ok.example user + channel');
  assert.equal(report.upstream.revoke_failed, 2, '400 + timeout');
  assert.equal(report.upstream.unsupported, 3, 'norevoke + retired + hostile unregistered row');
  assert.equal(report.upstream.undecryptable, 1, 'KMS envelope row without the envelope client');
  assert.equal(report.upstream.external_reference, 1);
  assert.equal(report.upstream.synthetic, 1);
  assert.equal(report.upstreamAttempted, 4, 'two successes + HTTP failure + timeout made real calls');
  assert.equal(report.byProvider.find((p) => p.provider === 'revok_ok')?.attempted, 2);
  assert.equal(report.byProvider.find((p) => p.provider === 'revok_fail')?.attempted, 1);
  assert.equal(report.byProvider.find((p) => p.provider === 'revok_slow')?.attempted, 1);
  assert.equal(report.unregistered.attempted, 0);
  assert.ok(calls.some((call) => call.token === 'RAAA'), 'the provider-declared refresh authority is revoked');

  // Local invalidation is COMPLETE across every credential + resurrection table.
  assert.equal(report.ok, true);
  assert.deepEqual(report.remaining, { credentials: 0, authorizations: 0, installations: 0 });
  assert.equal(await count(db, 'connection'), 0);
  assert.equal(await count(db, 'installation'), 0);
  for (const table of RESURRECTION_TABLES) assert.equal(await count(db, table), 0, `${table} not cleared`);
  assertNoSecrets(JSON.stringify(report));
  const audits = (await db.all('SELECT team_id, user_id, provider, actor, meta FROM audit')) as any[];
  assertNoSecrets(JSON.stringify(audits));
  assert.ok(audits.length > 0);
  for (const row of audits) {
    assert.equal(row.team_id, 'system', 'deployment revoke must not copy stored owner metadata');
    assert.equal(row.user_id, 'system', 'deployment revoke must not copy stored owner metadata');
    assert.equal(row.actor, 'system');
    assert.ok(
      ['revok_ok', 'revok_fail', 'revok_slow', 'norevoke', 'unregistered'].includes(row.provider),
      'audit provider must come from the trusted registry or the fixed unregistered bucket',
    );
    assert.equal(JSON.parse(row.meta).owner, 'deployment');
  }
});

test('partial both-token revoke is reported as undecryptable, not a provider HTTP failure', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(U('U1'), 'revok_ok', tok('READABLE_ACCESS', 'REFRESH_THAT_WILL_BE_CORRUPTED'));
  await db.run(
    `UPDATE connection SET refresh_token_enc=?
     WHERE team_id='T1' AND owner_kind='user' AND owner_id='U1' AND provider='revok_ok'`,
    [randomBytes(48)],
  );

  const { report, calls } = await withFetch(async (calls) => ({
    report: await revokeAllCredentials(db, deps(db, vault), { execute: true }),
    calls,
  }));
  assert.equal(report.upstreamAttempted, 1, 'the readable access token was still attempted');
  assert.equal(report.upstream.undecryptable, 1, 'the unreadable required refresh token is the recovery action');
  assert.equal(report.upstream.revoke_failed, 0, 'a successful HTTP call is not mislabeled as endpoint failure');
  assert.deepEqual(calls.map((call) => call.token), ['READABLE_ACCESS']);
  assert.equal(report.ok, true, 'local invalidation remains complete');
});

test('execute completes even with the master key unavailable and a broken registry', async (t) => {
  const { db } = await seed(t);
  // Wrong key (nothing decrypts) AND no registry (no upstream at all) — the local wipe must still finish.
  const brokenVault = new Vault(db, randomBytes(32));
  const report = await withFetch((calls) =>
    revokeAllCredentials(db, deps(db, brokenVault, undefined), { execute: true }).then((r) => {
      assert.equal(calls.length, 0, 'no registry ⇒ no upstream revoke attempted');
      return r;
    }),
  );
  assert.equal(report.ok, true, 'local deletion must not depend on decryptability/registry');
  assert.equal(await count(db, 'connection'), 0);
  assert.equal(await count(db, 'installation'), 0);
});

test('a hung envelope read is bounded after the local credential delete commits', async (t) => {
  const db = await openTestDb(t);
  const identityEnvelope = {
    wrapDataKey: async (dataKey: Buffer) => dataKey,
    unwrapDataKey: async (wrapped: Buffer) => wrapped,
  };
  await new Vault(db, KEY, {}, identityEnvelope).upsert(
    U('U1'),
    'revok_ok',
    tok('ENVELOPE_ACCESS', 'ENVELOPE_REFRESH'),
  );

  let started!: () => void;
  const unwrapStarted = new Promise<void>((resolve) => { started = resolve; });
  let aborts = 0;
  const hangingEnvelope = {
    wrapDataKey: async (dataKey: Buffer) => dataKey,
    unwrapDataKey: async (_wrapped: Buffer, signal?: AbortSignal) => {
      started();
      return new Promise<Buffer>((_resolve, reject) => {
        signal?.addEventListener('abort', () => {
          aborts++;
          reject(signal.reason);
        }, { once: true });
      });
    },
  };
  // Pre-bound above the emergency deadline so this regression proves the outer break-glass
  // cancellation reaches the underlying provider, rather than passing on the normal 2s bound.
  const vault = new Vault(db, KEY, {}, boundedEnvelopeProvider(hangingEnvelope, {
    timeoutMs: REVOKE_DECRYPT_TIMEOUT_MS * 2,
    maxUnresolved: 2,
  }));
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const claimedPromise = vault.deleteForRevoke(U('U1'), 'revok_ok', true);
  await unwrapStarted;
  assert.equal(await count(db, 'connection'), 0, 'local deletion commits before any KMS wait');
  t.mock.timers.tick(REVOKE_DECRYPT_TIMEOUT_MS);
  const claimed = await claimedPromise;
  assert.equal(claimed.removed, true);
  assert.equal(claimed.accessUnreadable, true);
  assert.equal(claimed.refreshUnreadable, true);
  assert.equal(aborts, 2, 'both KMS unwraps receive cancellation at the deadline');
  t.mock.timers.reset();
});

test('a provider without upstream revoke deletes locally without decrypting its token', async (t) => {
  const db = await openTestDb(t);
  const identityEnvelope = {
    wrapDataKey: async (dataKey: Buffer) => dataKey,
    unwrapDataKey: async (wrapped: Buffer) => wrapped,
  };
  await new Vault(db, KEY, {}, identityEnvelope).upsert(U('U1'), 'norevoke', tok('NO_REVOKE_TOKEN'));

  let unwraps = 0;
  const vault = new Vault(db, KEY, {}, {
    wrapDataKey: async (dataKey: Buffer) => dataKey,
    unwrapDataKey: async () => {
      unwraps++;
      throw new Error('should not decrypt');
    },
  });
  const report = await withFetch((calls) =>
    revokeAllCredentials(db, deps(db, vault), { execute: true }).then((result) => {
      assert.equal(calls.length, 0);
      return result;
    }),
  );

  assert.equal(unwraps, 0, 'no revoke capability means no secret access is necessary');
  assert.equal(report.upstream.unsupported, 1);
  assert.equal(report.removedLocal, 1);
  assert.equal(await count(db, 'connection'), 0);
});

test('a revoke loser reports no token disposition when the row is already gone', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  await vault.upsert(U('U1'), 'revok_ok', tok('ONE_TIME_TOKEN'));
  const [row] = await selectRevocations(db, { provider: 'revok_ok' });
  assert.ok(row);
  const audit = new Audit(db);
  const consent = new Consent(db);
  const sessions = new SessionGrants(db);

  await withFetch(async () => {
    const winner = await revokeConnection(vault, audit, consent, sessions, REGISTRY, row, 'revok_ok');
    assert.equal(winner.removed, true);
    const loser = await revokeConnection(vault, audit, consent, sessions, REGISTRY, row, 'revok_ok');
    assert.equal(loser.removed, false);
    assert.equal(loser.upstreamAttempted, false);
    assert.equal(loser.upstreamUnreadable, false);
    assert.equal(loser.upstreamMissing, false, 'no token was read, so its presence is unknown');
  });
});

test('second run is safe and reports zero remaining (idempotent)', async (t) => {
  const { db, vault } = await seed(t);
  await withFetch(() => revokeAllCredentials(db, deps(db, vault), { execute: true }));
  const second = await withFetch(() => revokeAllCredentials(db, deps(db, vault), { execute: true }));
  assert.equal(second.ok, true);
  assert.equal(second.matched.connections, 0);
  assert.equal(second.removedLocal, 0);
  assert.deepEqual(second.remaining, { credentials: 0, authorizations: 0, installations: 0 });
});

test('a failed local delete is reported non-zero with safe counts only', async (t) => {
  const { db, vault } = await seed(t);
  // Wrap the Db so DELETE FROM installation always throws — the sweep must surface it, not hide it.
  const flaky: Db = new Proxy(db, {
    get(target, prop, receiver) {
      if (prop === 'run') {
        return (sql: string, params?: unknown[]) =>
          /DELETE FROM installation/.test(sql)
            ? Promise.reject(new Error('boom'))
            : (target.run as any)(sql, params);
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  const report = await withFetch(() => revokeAllCredentials(flaky, deps(flaky, vault), { execute: true }));
  assert.equal(report.ok, false, 'a stranded installation row must fail the run');
  assert.equal(report.cleared.installations, -1, 'the failed table is marked, not silently zero');
  assert.ok(report.remaining.installations >= 1);
  assertNoSecrets(JSON.stringify(report));
});

test('lockdown denies serving and minting on two independent connections (containment)', async (t) => {
  // Two independent pools to the SAME schema stand in for two replicas, both locked down (#239).
  const url = await testDbUrl(t);
  const db1 = await openDb({ databaseUrl: url });
  const db2 = await openDb({ databaseUrl: url });
  t.after(async () => { await db1.close(); await db2.close(); });

  // Seed a real credential through a NON-lockdown vault so there is something to (fail to) serve.
  await new Vault(db1, KEY).upsert(U('U1'), 'revok_ok', tok('AAA'));

  const locked1 = new Vault(db1, KEY, {}, undefined, true);
  const locked2 = new Vault(db2, KEY, {}, undefined, true);
  for (const v of [locked1, locked2]) {
    await assert.rejects(() => v.get(U('U1'), 'revok_ok'), CredentialLockdownError, 'injection must be denied');
    await assert.rejects(() => v.upsert(U('Unew'), 'revok_ok', tok('ZZZ')), CredentialLockdownError, 'callback/reconnect mint must be denied');
    await assert.rejects(
      () => v.reference(U('Uref'), 'revok_ok', { source: 'aws-secrets-manager', secretRef: 'arn:y' }),
      CredentialLockdownError,
      'credential/reference setup must be denied',
    );
  }
  let wraps = 0;
  const lockedEnvelope = new Vault(db1, KEY, {}, {
    wrapDataKey: async (d) => { wraps++; return d; },
    unwrapDataKey: async (d) => d,
  }, true);
  await assert.rejects(
    () => lockedEnvelope.upsert(U('Ukms'), 'revok_ok', tok('MUST_NOT_REACH_KMS')),
    CredentialLockdownError,
  );
  assert.equal(wraps, 0, 'lockdown must refuse before envelope/KMS work touches the secret');
  // Nothing was resurrected on either connection while locked down.
  assert.equal(await count(db2, 'connection'), 1, 'no new credential row was minted under lockdown');

  // Break-glass deletion and metadata reads stay OPEN under lockdown.
  assert.equal(await locked1.has(U('U1'), 'revok_ok'), true, 'metadata reads stay available in lockdown');
  const claimed = await locked1.deleteForRevoke(U('U1'), 'revok_ok', false);
  assert.equal(claimed.removed, true, 'break-glass delete must work in lockdown');
});

test('schema has no secret-bearing table that revoke --all silently omits', async (t) => {
  const { db } = await seed(t);
  // Enumerate every table the migration creates, from the canonical DDL.
  const ddl = readFileSync(join(process.cwd(), 'src', 'core', 'db.ts'), 'utf8');
  const tables = [...ddl.matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map((m) => m[1]);
  const deleted = new Set<string>(['connection', 'installation', ...RESURRECTION_TABLES]);
  // Tables a global revoke deliberately KEEPS, each with the reason it is not a credential/authz row.
  const kept = new Set<string>([
    'meta', // schema version
    'audit', // incident evidence
    'broker_jti', // single-use identity replay guard (deleting it would ALLOW replay)
    'channel_config', 'channel_tool', // channel policy (mode/enabled), not a credential
    'channel_interaction_tombstone', 'user_offboard_scope_tombstone',
    'provisioning_revocation_tombstone', 'offboard_tombstone', // anti-resurrection fences — must survive
  ]);
  for (const table of tables) {
    assert.ok(
      deleted.has(table) || kept.has(table),
      `table "${table}" is neither wiped by revoke --all nor in the documented keep-list — classify it (#239)`,
    );
    // Every table that actually exists must be countable (proves the names are real, not typos).
    await count(db, table);
  }
});

/** Row counts for every table revoke --all touches, for the dry-run no-mutation assertion. */
async function snapshotCounts(db: Db): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const table of ['connection', 'installation', ...RESURRECTION_TABLES]) out[table] = await count(db, table);
  return out;
}
