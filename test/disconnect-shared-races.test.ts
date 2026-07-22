import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig, writeChannelMode, type ChannelMode } from '../src/core/channelConfig';
import { channelOwner } from '../src/core/owner';
import { defineProvider, ProviderRegistry } from '../src/core/providers';
import { disconnectChannelShared, configureChannelCredential, setChannelCredentialMode } from '../src/core/channelCredential';
import { offboardUser } from '../src/core/offboard';
import { testDbUrl, pgReachable } from './support/pg';

// The three P1 disconnect-shared races, exercised through the ACTUAL transaction + advisory-lock
// interleavings on two independent connections to one PostgreSQL (not synthesized final states). Each
// pauses the OTHER writer inside its locked transaction (via ChannelConfig's beforeModeWrite hook, the
// same primitive postgres.test.ts uses) so disconnect-shared genuinely contends for the credential lock.
const SKIP = 'Postgres not reachable. Run `npm run pg:up` to exercise the PG backend';
const KEY = randomBytes(32);
const tok = (accessToken: string) => ({ accessToken, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null });
const provider = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
const registry = new ProviderRegistry([provider]);
const conflict = (mode: 'per-user' | 'session'): never => { throw new Error(`mode conflict: ${mode}`); };

/** A pausable ChannelConfig: the returned `arm(provider, mode)` gate resolves `entered` the moment that
 *  exact mode write begins inside its transaction, then blocks it until `release()`. Mirrors postgres.test.ts. */
function pausableConfig(db: any) {
  let hook: ((p: string, m: ChannelMode) => Promise<void>) | undefined;
  const config = new ChannelConfig(db, async (p, m) => hook?.(p, m));
  const arm = (targetProvider: string, targetMode: ChannelMode) => {
    let entered!: () => void; let release!: () => void;
    const enteredP = new Promise<void>((r) => { entered = r; });
    const gate = new Promise<void>((r) => { release = r; });
    hook = async (p, m) => { if (p === targetProvider && m === targetMode) { entered(); await gate; } };
    return { enteredP, release: () => release() };
  };
  return { config, arm };
}

// Race 1 — disconnect-shared vs a concurrent shared→session. The OLD (non-atomic) code read the mode
// OUTSIDE the lock, so a session set between the read and the per-user write was silently clobbered.
// Here session wins the lock first; disconnect must block, then read the CURRENT session inside the lock
// and refuse (not-shared) rather than overwrite it to per-user.
test('race: disconnect-shared blocks on an in-flight shared→session and never clobbers it', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const identity = { enterpriseId: null, teamId: 'TR1', userId: 'UA' };
  const channel = 'CR1';
  const vaultA = new Vault(dbA, KEY); const vaultB = new Vault(dbB, KEY);
  const auditA = new Audit(dbA); const auditB = new Audit(dbB);
  await writeChannelMode(new ChannelConfig(dbB), identity.teamId, channel, 'mcp', 'shared');
  await vaultB.upsert(channelOwner(identity.teamId, channel), 'mcp', tok('shared-sk'));

  // Replica B moves the channel to session, pausing INSIDE the lock before the session mode row commits.
  const { config: cfgB, arm } = pausableConfig(dbB);
  const gate = arm('mcp', 'session');
  const bSession = setChannelCredentialMode({
    vault: vaultB, audit: auditB, channelConfig: cfgB, identity, channel, providerId: 'mcp',
    mode: 'session', issuance: await vaultB.userProvisioningIssuedAt(),
  });
  await gate.enteredP; // B holds the credential lock with session written (uncommitted)

  // Replica A's disconnect-shared must WAIT for B's lock rather than act on the stale 'shared' snapshot.
  const cfgA = new ChannelConfig(dbA);
  let aSettled = false;
  const aDisc = disconnectChannelShared({
    vault: vaultA, audit: auditA, channelConfig: cfgA, registry, identity, channel, providerId: 'mcp',
    issuance: await vaultA.userProvisioningIssuedAt(),
  }).finally(() => { aSettled = true; });
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(aSettled, false, 'disconnect must wait for the in-flight session transaction');

  gate.release(); // B commits session (deleting the shared credential, writing session)
  await bSession;
  const outcome = await aDisc; // A now reads the CURRENT mode (session) under the lock
  assert.equal(outcome.status, 'not-shared', 'disconnect refuses instead of clobbering the session');
  assert.equal(await cfgA.getMode(identity.teamId, channel, 'mcp'), 'session', 'the session mode is preserved');
  assert.equal(await vaultA.get(channelOwner(identity.teamId, channel), 'mcp'), null, 'the shared credential is gone (B removed it)');
});

// Race 2 — disconnect-shared vs a replacement credential. A delayed command must not delete a credential
// re-configured AFTER it was authorized. The setup wins the lock first (writing a NEWER generation); the
// delayed disconnect blocks, then the current-generation fence (>= issuance) leaves the replacement intact.
test('race: a delayed disconnect-shared does not delete a replacement credential configured under the lock', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const identity = { enterpriseId: null, teamId: 'TR2', userId: 'UA' };
  const channel = 'CR2';
  const vaultA = new Vault(dbA, KEY); const vaultB = new Vault(dbB, KEY);
  const auditA = new Audit(dbA); const auditB = new Audit(dbB);
  await writeChannelMode(new ChannelConfig(dbB), identity.teamId, channel, 'mcp', 'shared');
  await vaultB.upsert(channelOwner(identity.teamId, channel), 'mcp', tok('cred-1'));

  // A's command is authorized NOW, before the replacement exists.
  const disconnectIssuance = await vaultA.userProvisioningIssuedAt();

  // Replica B re-configures the shared credential (a NEWER generation), pausing inside the lock.
  const { config: cfgB, arm } = pausableConfig(dbB);
  const gate = arm('mcp', 'shared');
  const bSetup = configureChannelCredential({
    vault: vaultB, audit: auditB, channelConfig: cfgB, identity, channel, providerId: 'mcp',
    credential: { kind: 'secret', token: tok('cred-2') }, modeConflict: conflict,
    issuance: await vaultB.userProvisioningIssuedAt(),
  });
  await gate.enteredP; // B holds the lock; cred-2 (generation > disconnectIssuance) is written

  let aSettled = false;
  const aDisc = disconnectChannelShared({
    vault: vaultA, audit: auditA, channelConfig: new ChannelConfig(dbA), registry, identity, channel,
    providerId: 'mcp', issuance: disconnectIssuance,
  }).finally(() => { aSettled = true; });
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(aSettled, false, 'disconnect must wait for the in-flight setup transaction');

  gate.release();
  assert.equal(await bSetup, true, 'the replacement credential is stored');
  const outcome = await aDisc;
  assert.equal(outcome.status, 'stale', 'the delayed disconnect is stale against the newer generation');
  assert.equal(await new ChannelConfig(dbA).getMode(identity.teamId, channel, 'mcp'), 'shared', 'the mode stays shared');
  assert.ok(await vaultA.get(channelOwner(identity.teamId, channel), 'mcp'), 'the replacement credential survives');
});

// Race 3 — disconnect-shared vs actor offboarding, across two replicas. The OLD code deleted the
// credential BEFORE the actor fence; the fix checks the offboard tombstone before any mutation. Replica B
// offboards the acting admin; replica A's disconnect (authorized before the offboard) must then observe
// the committed tombstone and refuse — the credential is untouched, no upstream revoke, no revoke audit.
test('race: an offboarded actor cannot delete the shared credential before the stale receipt is rejected', async (t) => {
  if (!(await pgReachable())) return t.skip(SKIP);
  const url = await testDbUrl(t);
  const dbA = await openDb({ databaseUrl: url });
  const dbB = await openDb({ databaseUrl: url });
  t.after(async () => { await Promise.all([dbA.close(), dbB.close()]); });
  const identity = { enterpriseId: null, teamId: 'TR3', userId: 'UA' };
  const channel = 'CR3';
  const vaultA = new Vault(dbA, KEY); const vaultB = new Vault(dbB, KEY);
  const auditA = new Audit(dbA); const auditB = new Audit(dbB);
  await writeChannelMode(new ChannelConfig(dbB), identity.teamId, channel, 'mcp', 'shared');
  await vaultB.upsert(channelOwner(identity.teamId, channel), 'mcp', tok('shared-sk'));

  // A's disconnect is authorized before the actor is offboarded.
  const disconnectIssuance = await vaultA.userProvisioningIssuedAt();
  // Replica B offboards the acting admin — the tombstone commits at-or-after A's receipt.
  await offboardUser(vaultB, auditB, new Consent(dbB), identity);

  const outcome = await disconnectChannelShared({
    vault: vaultA, audit: auditA, channelConfig: new ChannelConfig(dbA), registry, identity, channel,
    providerId: 'mcp', issuance: disconnectIssuance,
  });
  assert.equal(outcome.status, 'stale', 'the offboarded actor receipt is rejected before any mutation');
  assert.equal(await new ChannelConfig(dbA).getMode(identity.teamId, channel, 'mcp'), 'shared', 'the mode is untouched');
  assert.ok(await vaultA.get(channelOwner(identity.teamId, channel), 'mcp'), 'the shared credential is intact (never deleted)');
  assert.equal(((await dbA.all("SELECT 1 FROM audit WHERE action='revoke'")) as any[]).length, 0, 'no revoke was attempted or audited');
});
