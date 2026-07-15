import type { Audit } from './audit';
import type { ChannelConfig, ChannelMode } from './channelConfig';
import type { SlackIdentity } from './identity';
import { channelOwner } from './owner';
import type { SecretReference } from './reference';
import type { StoredToken, Vault } from './vault';

type ChannelCredential =
  | { kind: 'secret'; token: StoredToken }
  | { kind: 'ref'; reference: SecretReference };

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
  },
): Promise<void> {
  const owner = channelOwner(input.identity.teamId, input.channel);
  await input.vault.withCredentialLock(owner, input.providerId, async (locked, tx) => {
    const mode = await input.channelConfig.getMode(owner.teamId, input.channel, input.providerId, tx);
    if (mode != null && mode !== 'shared') input.modeConflict(mode);

    if (input.credential.kind === 'secret') {
      await locked.upsert(owner, input.providerId, input.credential.token);
    } else {
      await locked.reference(owner, input.providerId, input.credential.reference);
    }
    await input.channelConfig.setMode(owner.teamId, input.channel, input.providerId, 'shared', tx);
    await input.audit.record('config', input.identity, input.providerId, {
      owner: 'channel',
      channel: input.channel,
      mode: 'shared',
      kind: input.credential.kind,
      ...(input.credential.kind === 'ref' ? { source: input.credential.reference.source } : {}),
    }, undefined, tx);
  });
}

/**
 * Change one channel credential mode behind the same lifecycle lock used by setup. Moving to a
 * user-owned mode deletes any shared credential in the locked transaction, preventing a dormant
 * credential from surviving or being reactivated by a later shared flip.
 */
export async function setChannelCredentialMode(
  input: ChannelCredentialMutation & { mode: ChannelMode },
): Promise<void> {
  const owner = channelOwner(input.identity.teamId, input.channel);
  await input.vault.withCredentialLock(owner, input.providerId, async (locked, tx) => {
    if (input.mode !== 'shared') await locked.delete(owner, input.providerId);
    await input.channelConfig.setMode(owner.teamId, input.channel, input.providerId, input.mode, tx);
    await input.audit.record('config', input.identity, input.providerId, {
      owner: 'channel', channel: input.channel, mode: input.mode,
    }, undefined, tx);
  });
}
