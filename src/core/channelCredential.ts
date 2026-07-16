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
import type { SecretReference } from './reference';
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
