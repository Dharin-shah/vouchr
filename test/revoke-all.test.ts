import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { openTestDb, testDbUrl } from './support/pg';
import { openDb, type Db } from '../src/core/db';
import { Vault, CredentialLockdownError } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { SessionGrants } from '../src/core/session';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { userOwner, channelOwner } from '../src/core/owner';
import {
  revokeAllCredentials,
  enumerateStoredProviders,
  RESURRECTION_TABLES,
  type RevokeAllDeps,
} from '../src/core/offboard';

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
    refresh: 'none',
    pkce: false,
    clientId: 'id',
    clientSecret: 'sec',
    ...(revokeHost ? { revokeUrl: `https://${revokeHost}/revoke` } : {}),
    ...(oauthTimeoutMs ? { oauthTimeoutMs } : {}),
  });

const revokOk = mk('revok_ok', 'ok.example');
const revokFail = mk('revok_fail', 'fail.example');
const revokSlow = mk('revok_slow', 'slow.example', 60);
const norevoke = mk('norevoke'); // no revoke endpoint
// `retired` is intentionally NOT registered — it exists only in stored rows.
const REGISTRY = new ProviderRegistry([revokOk, revokFail, revokSlow, norevoke]);

const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
const U = (n: string) => userOwner({ enterpriseId: null, teamId: 'T1', userId: n });

/** Stub global.fetch for the upstream revoke POSTs; restore in finally (TEST-3). Never inspects the
 *  token — only the host selects the response, mirroring real revoke endpoints. */
async function withFetch<T>(fn: (calls: string[]) => Promise<T>): Promise<T> {
  const calls: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: any, init?: any) => {
    const url = String(typeof input === 'string' ? input : input.url);
    calls.push(url);
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
  await vault.upsert(U('U1'), 'revok_ok', tok('AAA'));            // → revoked (200)
  await vault.upsert(channelOwner('T1', 'C1'), 'revok_ok', tok('AAA')); // → revoked (channel owner)
  await vault.upsert(U('U2'), 'revok_fail', tok('BBB'));          // → revoke_failed (400)
  await vault.upsert(U('U3'), 'revok_slow', tok('CCC'));          // → revoke_failed (timeout)
  await vault.upsert(U('U4'), 'norevoke', tok('DDD'));            // → unsupported (no endpoint)
  await vault.upsert(U('U5'), 'retired', tok('EEE'));             // → unsupported (unregistered)
  await vault.reference(U('U6'), 'revok_ok', { source: 'aws-secrets-manager', secretRef: 'arn:x' }); // → external_reference
  await vault.upsertDryRun(U('U7'), 'revok_ok', tok('FFF'));      // → synthetic (dry-run)
  // Undecryptable: raw row whose ciphertext will not open under KEY (garbage bytes).
  await db.run(
    `INSERT INTO connection (id, team_id, owner_kind, owner_id, provider, source, access_token_enc, scopes, created_at, updated_at)
     VALUES (?, 'T1', 'user', 'U8', 'revok_ok', 'vault', ?, '', ?, ?)`,
    [randomUUID(), randomBytes(48), Date.now(), Date.now()],
  );

  // Resurrection paths — raw inserts with the minimal valid columns; exact counts matter.
  const now = Date.now();
  const later = now + 600_000;
  await db.run(`INSERT INTO consent_request (state, team_id, user_id, provider, pkce_verifier, created_at) VALUES (?, 'T1', 'U1', 'revok_ok', 'v', ?)`, [randomUUID(), now]);
  await db.run(`INSERT INTO consent_request (state, team_id, user_id, provider, pkce_verifier, created_at) VALUES (?, 'T1', 'U9', 'gone_provider', 'v', ?)`, [randomUUID(), now]); // pending for a provider with NO connection
  await db.run(`INSERT INTO session_request (id, team_id, channel, thread, user_id, provider, credential_id, created_at, expires_at) VALUES (?, 'T1', 'C1', 'th', 'U1', 'revok_ok', ?, ?, ?)`, [randomUUID(), randomUUID(), now, later]);
  await db.run(`INSERT INTO session_grant (team_id, channel, thread, user_id, provider, credential_id, created_at, expires_at) VALUES ('T1', 'C1', 'th', 'U1', 'revok_ok', ?, ?, ?)`, [randomUUID(), now, later]);
  await db.run(
    `INSERT INTO approval_request (id, action_key, team_id, user_id, owner_kind, owner_id, credential_id, provider, method, origin, host, path, channel, thread, status, created_at, expires_at)
     VALUES (?, 'k', 'T1', 'U1', 'user', 'U1', ?, 'revok_ok', 'POST', 'https://api.ok.example', 'api.ok.example', '/x', 'C1', 'th', 'pending', ?, ?)`,
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
  return { vault, audit: new Audit(db), consent: new Consent(db), sessions: new SessionGrants(db), registry };
}

/** Every secret-bearing string that must never appear in the report/logs. */
const SECRETS = ['AAA', 'BBB', 'CCC', 'DDD', 'EEE', 'FFF', 'arn:x'];
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
  assert.equal(report.connections, 9);
  assert.equal(report.installations, 2);
  // Metadata-only preview cannot predict the upstream OUTCOME — every revocable vault row counts as
  // "would attempt": U1, C1, U2, U3, U8 = 5. The execute path splits these into revoked/failed/undecryptable.
  assert.equal(report.upstream.revoked, 5);
  assert.equal(report.upstream.external_reference, 1);
  assert.equal(report.upstream.unsupported, 2);
  assert.equal(report.upstream.synthetic, 1);
  assertNoSecrets(JSON.stringify(report));
});

test('execute removes every local artifact and reports upstream categories distinctly', async (t) => {
  const { db, vault } = await seed(t);
  const report = await withFetch(() => revokeAllCredentials(db, deps(db, vault), { execute: true }));

  // Distinct upstream buckets (success ≠ failure ≠ unsupported ≠ undecryptable ≠ external ≠ synthetic).
  assert.equal(report.upstream.revoked, 2, 'ok.example user + channel');
  assert.equal(report.upstream.revoke_failed, 2, '400 + timeout');
  assert.equal(report.upstream.unsupported, 2, 'norevoke + retired');
  assert.equal(report.upstream.undecryptable, 1);
  assert.equal(report.upstream.external_reference, 1);
  assert.equal(report.upstream.synthetic, 1);

  // Local invalidation is COMPLETE across every credential + resurrection table.
  assert.equal(report.ok, true);
  assert.deepEqual(report.remaining, { credentials: 0, authorizations: 0, installations: 0 });
  assert.equal(await count(db, 'connection'), 0);
  assert.equal(await count(db, 'installation'), 0);
  for (const table of RESURRECTION_TABLES) assert.equal(await count(db, table), 0, `${table} not cleared`);
  assertNoSecrets(JSON.stringify(report));
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

test('second run is safe and reports zero remaining (idempotent)', async (t) => {
  const { db, vault } = await seed(t);
  await withFetch(() => revokeAllCredentials(db, deps(db, vault), { execute: true }));
  const second = await withFetch(() => revokeAllCredentials(db, deps(db, vault), { execute: true }));
  assert.equal(second.ok, true);
  assert.equal(second.connections, 0);
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
