import type { Audit } from './audit';
import { writeChannelMode, type ChannelConfig, type ChannelMode } from './channelConfig';
import {
  latestProvisioningRevocationTombstone,
  latestUserOffboardTombstone,
  tombstoneBlocks,
  withProvisioningRevocationLock,
  withUserInteractionFence,
  withUserOffboardLock,
} from './consent';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import { latestChannelInteractionTombstone, purgeChannelInteractionState } from './interaction';
import { channelOwner } from './owner';
import type { ProviderRegistry } from './providers';
import type { SecretReference } from './reference';
import { revokeProviderCredential } from './tokens';
import {
  prepareVaultCredentialWrite,
  type PreparedVaultCredentialWrite,
  type StoredToken,
  type Vault,
} from './vault';

type ChannelCredential =
  | { kind: 'secret'; token: StoredToken }
  | { kind: 'ref'; reference: SecretReference };

/** A direct server-trusted issuance time, or a single-use request consume performed inside the
 * final credential transaction. Keeping the resolver transaction-bound makes duplicate Slack
 * submits and audit failures atomic with the channel credential write. */
export type ChannelProvisioningIssuance = number | ((tx: Db) => Promise<number | null>);

interface ChannelCredentialMutation {
  vault: Vault;
  audit: Audit;
  channelConfig: ChannelConfig;
  identity: SlackIdentity;
  channel: string;
  providerId: string;
}

/**
 * Store one shared credential, its mode, and its audit row behind the owner/provider lifecycle
 * lock. The lock makes setup mutually exclusive with mode changes across replicas; the transaction
 * makes the row, mode, satellite cleanup, and audit one committed outcome.
 */
export async function configureChannelCredential(
  input: ChannelCredentialMutation & {
    credential: ChannelCredential;
    modeConflict: (mode: Exclude<ChannelMode, 'shared'>) => never;
    /** Server-trusted intent time, resolved at most once inside the final write transaction. */
    issuance: ChannelProvisioningIssuance;
  },
): Promise<boolean> {
  const owner = channelOwner(input.identity.teamId, input.channel);
  const preparedSecret: PreparedVaultCredentialWrite | null = input.credential.kind === 'secret'
    ? await prepareVaultCredentialWrite(input.vault, input.credential.token)
    : null;
  return input.vault.withCredentialLock(owner, input.providerId, async (locked, tx) =>
    withProvisioningRevocationLock(tx, owner, input.providerId, (revocationTx) =>
      withUserOffboardLock(revocationTx, input.identity, async (fencedTx) => {
      const issuedAt = typeof input.issuance === 'number'
        ? input.issuance
        : await input.issuance(fencedTx);
      if (issuedAt === null) return false;
      if (!Number.isSafeInteger(issuedAt)) throw new Error('invalid channel provisioning issuance');
      // One transaction-bound pg client: sequence these reads rather than issuing concurrent
      // client.query calls (deprecated in pg 8 and removed in pg 9).
      const revokedAt = await latestProvisioningRevocationTombstone(
        fencedTx,
        owner,
        input.providerId,
      );
      const offboardedAt = await latestUserOffboardTombstone(fencedTx, input.identity);
      const changedAt = await latestChannelInteractionTombstone(
        fencedTx,
        owner.teamId,
        input.channel,
        input.providerId,
      );
      if (
        tombstoneBlocks(revokedAt, issuedAt) ||
        tombstoneBlocks(offboardedAt, issuedAt) ||
        tombstoneBlocks(changedAt, issuedAt)
      ) return false;
      const mode = await input.channelConfig.getMode(
        owner.teamId,
        input.channel,
        input.providerId,
        fencedTx,
      );
      if (mode != null && mode !== 'shared') input.modeConflict(mode);

      if (input.credential.kind === 'secret') {
        await preparedSecret!(fencedTx, owner, input.providerId);
      } else {
        await locked.reference(owner, input.providerId, input.credential.reference);
      }
      await writeChannelMode(
        input.channelConfig,
        owner.teamId,
        input.channel,
        input.providerId,
        'shared',
        fencedTx,
      );
      await purgeChannelInteractionState(
        fencedTx,
        owner.teamId,
        input.channel,
        input.providerId,
      );
      await input.audit.record('config', input.identity, input.providerId, {
        owner: 'channel',
        channel: input.channel,
        mode: 'shared',
        kind: input.credential.kind,
        ...(input.credential.kind === 'ref' ? { source: input.credential.reference.source } : {}),
      }, undefined, fencedTx);
      return true;
    })));
}

/**
 * Change one channel credential mode behind the same lifecycle lock used by setup. Moving to a
 * user-owned mode deletes any shared credential in the locked transaction, preventing a dormant
 * credential from surviving or being reactivated by a later shared flip.
 */
export async function setChannelCredentialMode(
  input: ChannelCredentialMutation & { mode: ChannelMode; issuance: number },
): Promise<boolean> {
  const owner = channelOwner(input.identity.teamId, input.channel);
  return input.vault.withCredentialLock(owner, input.providerId, async (locked, tx) => {
    const fenced = await withUserInteractionFence(
      tx,
      input.identity,
      input.issuance,
      async (fencedTx) => {
        const previous = await input.channelConfig.getMode(
          owner.teamId,
          input.channel,
          input.providerId,
          fencedTx,
        );
        if (input.mode !== 'shared') await locked.delete(owner, input.providerId);
        await writeChannelMode(
          input.channelConfig,
          owner.teamId,
          input.channel,
          input.providerId,
          input.mode,
          fencedTx,
        );
        if (previous !== input.mode) {
          await purgeChannelInteractionState(
            fencedTx,
            owner.teamId,
            input.channel,
            input.providerId,
          );
        }
        await input.audit.record('config', input.identity, input.providerId, {
          owner: 'channel', channel: input.channel, mode: input.mode,
        }, undefined, fencedTx);
      },
    );
    return fenced.status === 'current';
  });
}

/** The truthful outcome of {@link disconnectChannelShared}. `removed` deleted a shared credential and
 *  returned the channel to per-user; `missing` found `shared` mode but no stored credential (e.g. a
 *  prior break-glass revoke deleted the row but left the mode) and still returned it to per-user;
 *  `not-shared` did nothing because the channel was not in `shared` mode (never downgrading a
 *  session/per-user channel); `stale` lost to a concurrent lifecycle change (a newer credential
 *  generation, or the acting admin being offboarded) and mutated nothing. `ok=false` on `removed`
 *  means upstream revocation debt may remain (the provider token could still be live). `audited=false`
 *  means the destructive work committed but its durable `revoke` audit row could not be written — the
 *  caller renders that separately and never discards the committed outcome (matches personal disconnect). */
export type DisconnectSharedOutcome = {
  status: 'removed' | 'missing' | 'not-shared' | 'stale';
  ok: boolean;
  attempted: boolean;
  audited: boolean;
};

/**
 * Remove a channel's SHARED credential: the dedicated counterpart to configureChannelCredential.
 * Unlike a generic mode reset it:
 *  - only acts when the channel is actually in `shared` mode, so a `per-user`/`session` channel is
 *    never mutated (a session channel keeps its thread-approval requirement — no access widening);
 *  - deletes the shared credential through the SAME claim→decode→revoke primitive the personal
 *    disconnect uses, so revocable provider authority is actually revoked upstream, not just dropped
 *    locally; and
 *  - reports a truthful outcome (`not-shared`/`missing`/`stale`/`removed` with `ok`/`attempted`).
 *
 * Every decision and mutation — the actor/receipt fence, the shared-mode check, the current-generation
 * validation, the exact-row claim-delete, the mode flip, the satellite purge, and the local audit —
 * happens in ONE locked, fenced transaction, mirroring configureChannelCredential's lock stack
 * (credential → provisioning-revocation → actor-offboard). Only the best-effort upstream revoke (a
 * network call that must not run inside the DB transaction) happens after commit, against the token
 * material claimed by the delete. Doing the claim-delete inside the same locked transaction as the
 * mode read is what prevents a concurrent shared→session change from being clobbered, a newer shared
 * credential from being deleted by a delayed command, and an offboarded actor from deleting before
 * its stale issuance is rejected.
 */
export async function disconnectChannelShared(input: {
  vault: Vault;
  audit: Audit;
  channelConfig: ChannelConfig;
  registry?: ProviderRegistry;
  identity: SlackIdentity;
  channel: string;
  providerId: string;
  issuance: number;
}): Promise<DisconnectSharedOutcome> {
  const owner = channelOwner(input.identity.teamId, input.channel);
  const provider = input.registry?.has(input.providerId) ? input.registry.get(input.providerId) : null;
  const registered = provider != null;

  type Claimed = Awaited<ReturnType<Vault['claimGenerationForRevoke']>>;
  const decided = await input.vault.withCredentialLock(owner, input.providerId, async (_locked, tx) =>
    withProvisioningRevocationLock(tx, owner, input.providerId, (revocationTx) =>
      withUserOffboardLock(revocationTx, input.identity, async (fencedTx): Promise<
        { status: 'not-shared' | 'stale' | 'missing' } | { status: 'removed'; claimed: Claimed }
      > => {
        // Actor/receipt fence: an actor offboarded at or after this request's issuance is rejected
        // BEFORE any mutation — a stale authorization must never delete a credential (finding #1).
        // A provisioning-revocation tombstone deliberately does NOT block here: unlike setup, a
        // durable break-glass marker must not permanently wedge the recovery path into `stale`.
        const offboardedAt = await latestUserOffboardTombstone(fencedTx, input.identity);
        if (tombstoneBlocks(offboardedAt, input.issuance)) return { status: 'stale' };

        // Shared-mode check INSIDE the lock: a session/per-user channel is never touched, and a
        // concurrent shared→session change is either already visible here (⇒ not-shared) or blocked
        // on the credential lock until we commit (⇒ it applies on top, never silently clobbered).
        const mode = await input.channelConfig.getMode(owner.teamId, input.channel, input.providerId, fencedTx);
        if (mode !== 'shared') return { status: 'not-shared' };

        // Current-generation validation: only a credential generation strictly OLDER than this
        // request's issuance is deletable. Timestamp equality FAILS CLOSED (`>=`): both are integer
        // PostgreSQL milliseconds, so a replacement credential re-configured in the SAME millisecond as
        // the command's issuance must be treated as newer and left intact — never deleted by the
        // delayed command (finding #1). This matches the write-side newest-generation fence
        // (withUserProvisioningFence): a legitimate replacement always arrives on a strictly-later receipt.
        const existing = await fencedTx.get<{ id: string; generation_at: number }>(
          `SELECT id, generation_at FROM connection
             WHERE team_id=? AND owner_kind='channel' AND owner_id=? AND provider=?`,
          [owner.teamId, owner.id, input.providerId],
        );
        if (existing && existing.generation_at >= input.issuance) return { status: 'stale' };

        // Return the channel to per-user + purge satellites + audit the mode change — always, once we
        // are committed to acting on a shared channel. The purge advances the channel-interaction
        // tombstone, which fences any stalled setup request from recreating the credential.
        const flipAndAudit = async () => {
          await writeChannelMode(input.channelConfig, owner.teamId, input.channel, input.providerId, 'per-user', fencedTx);
          await purgeChannelInteractionState(fencedTx, owner.teamId, input.channel, input.providerId);
          await input.audit.record('config', input.identity, input.providerId, {
            owner: 'channel', channel: input.channel, mode: 'per-user',
          }, undefined, fencedTx);
        };

        // `missing`: shared mode with no stored credential (a prior break-glass revoke left the mode).
        // Still recover the channel to per-user, but there is nothing to delete or revoke.
        if (!existing) {
          await flipAndAudit();
          return { status: 'missing' };
        }

        // Exact-row claim-delete (+ satellite purge) in this same transaction, decoded for the
        // post-commit upstream revoke. Unregistered providers pass decrypt=false (ciphertext untouched).
        const claimed = await input.vault.claimGenerationForRevoke(fencedTx, owner, input.providerId, existing.id, registered);
        await flipAndAudit();
        return { status: 'removed', claimed };
      })));

  if (decided.status !== 'removed') {
    // Nothing was deleted, so no `revoke` audit is due; any mode-flip audit already committed inside
    // the transaction above (it cannot fail post-commit), so these are audited by construction.
    if (decided.status === 'not-shared') return { status: 'not-shared', ok: true, attempted: false, audited: true };
    if (decided.status === 'stale') return { status: 'stale', ok: false, attempted: false, audited: true };
    return { status: 'missing', ok: true, attempted: false, audited: true };
  }

  // Post-commit best-effort upstream revoke, mirroring the personal disconnect's truth table exactly
  // (removeUserConnection): `ok` starts true when there is no revocation debt to leave behind (nothing
  // removed, a registered provider whose revoke will run, or a synthetic dry-run row) and only goes
  // false if a DUE revoke fails or could not run. `!registered` (unknown revoke contract) is debt.
  const claimed = decided.claimed;
  let ok = !claimed.removed || registered || claimed.dryRun;
  let attempted = false;
  if (provider && claimed.removed && !claimed.dryRun && (provider.revoke || provider.revokeUrl)) {
    const upstream = await revokeProviderCredential(provider, claimed);
    attempted = upstream.attempted;
    if (!upstream.ok) ok = false;
  }
  // Durable revoke-outcome audit (STR-4: same 'revoke' action as the personal disconnect). This runs
  // AFTER the destructive transaction and the upstream attempt committed, so an audit-store failure
  // must NOT reject the whole operation and hide the committed result: catch it and report
  // audited:false (the caller renders it separately). ALWAYS record `ok` (adding upstream:'skipped'
  // when no call was made) so a successful non-revocable removal is distinguishable from unresolved
  // upstream debt — matching disconnectProviderAtGeneration's revoke meta.
  let audited = true;
  try {
    await input.audit.record('revoke', input.identity, input.providerId, {
      owner: 'channel', channel: input.channel, ok, ...(attempted ? {} : { upstream: 'skipped' }),
    });
  } catch {
    audited = false;
  }
  return { status: 'removed', ok, attempted, audited };
}
