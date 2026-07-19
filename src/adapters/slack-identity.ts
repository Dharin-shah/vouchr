// Slack-semantic identity helpers. These KNOW Slack's payload shapes and Web API (Bolt bodies,
// users.info is_admin/is_owner, conversations.members) so they live in the adapter layer, not in
// transport-agnostic core. Core keeps only the SlackIdentity TYPE (the vault key), imported here.
import type { SlackIdentity } from '../core/identity';

/**
 * Resolve the acting Slack user from a Bolt middleware args object. Prefers the
 * `actor` (the user who triggered THIS request) over the app installer, then
 * falls back across the shapes different event/command/action payloads use.
 */
export function resolveIdentity(args: {
  context?: any;
  body?: any;
  payload?: any;
  event?: any;
}): SlackIdentity | null {
  const { context = {}, body = {}, event = {} } = args;

  const teamId = context.teamId ?? body.team_id ?? body.team?.id ?? event.team ?? null;
  const userId =
    context.actorUserId ?? // Bolt actor-token resolution: the triggering user
    body.user_id ??
    body.user?.id ??
    event.user ??
    null;
  const enterpriseId =
    context.enterpriseId ?? body.enterprise_id ?? body.enterprise?.id ?? null;

  if (!teamId || !userId) return null;
  return { enterpriseId, teamId, userId };
}

/**
 * Whether `userId` is a Slack workspace admin/owner, the gate for channel-credential
 * config (invariant 7). Fail-closed: any API error or missing flag → not admin.
 */
export async function isSlackAdmin(
  client: { users: { info: (a: { user: string }) => Promise<any> } },
  userId: string,
): Promise<boolean> {
  try {
    const res = await client.users.info({ user: userId });
    return Boolean(res?.user?.is_admin || res?.user?.is_owner);
  } catch {
    return false;
  }
}

/**
 * Whether `userId` created `channel`, the portable "channel owner" notion (public channels have no
 * admin boolean). Alongside `isSlackAdmin`, this widens who may CONFIGURE channel credentials to the
 * channel creator, not just workspace admins. Fail-closed: no channel, any API error, or a missing
 * creator → not a channel admin.
 * Caveats: for a PRIVATE channel the bot must be a member for conversations.info to return it, else
 * this fails closed and only the workspace-admin path applies. `creator` is immutable and can point
 * at a since-deactivated user.
 */
export async function isChannelAdmin(
  client: { conversations: { info: (a: { channel: string }) => Promise<any> } },
  channel: string,
  userId: string,
): Promise<boolean> {
  if (!channel) return false;
  try {
    const res = await client.conversations.info({ channel });
    return res?.channel?.creator === userId;
  } catch {
    return false;
  }
}

interface ChannelMemberPaginationBounds {
  maxMembers: number;
  maxPages: number;
  continue: () => boolean;
}

type ConversationsMembersClient = {
  conversations: {
    members: (a: { channel: string; cursor?: string; limit?: number }) => Promise<any>;
  };
};

/** One finite, cursor-validated traversal shared by membership checks and complete audience reads.
 * `true` means the visitor found its target, `false` means the complete list was read, and `null`
 * means Slack could not prove a result within the caller's deadline/work cap. */
async function scanChannelMembers(
  client: ConversationsMembersClient,
  channel: string,
  bounds: ChannelMemberPaginationBounds,
  visit: (member: string) => boolean,
): Promise<boolean | null> {
  if (
    !Number.isSafeInteger(bounds.maxMembers) || bounds.maxMembers < 1
    || !Number.isSafeInteger(bounds.maxPages) || bounds.maxPages < 1
  ) return null;
  const members = new Set<string>();
  const cursors = new Set<string>();
  let scannedEntries = 0;
  let scannedPages = 0;
  try {
    let cursor: string | undefined;
    do {
      scannedPages += 1;
      if (scannedPages > bounds.maxPages || !bounds.continue()) return null;
      const res = await client.conversations.members({ channel, cursor, limit: 1000 });
      if (
        !bounds.continue()
        || !Array.isArray(res?.members)
        || res.members.length > 1000
      ) return null;
      for (const member of res.members) {
        scannedEntries += 1;
        if (scannedEntries > bounds.maxMembers || !bounds.continue()) return null;
        if (typeof member !== 'string' || member.length === 0 || member.length > 255) return null;
        if (members.has(member)) continue;
        members.add(member);
        if (visit(member)) return true;
      }
      const next = res?.response_metadata?.next_cursor;
      if (next == null || next === '') cursor = undefined;
      else {
        if (typeof next !== 'string' || next.length > 1024 || cursors.has(next)) return null;
        cursors.add(next);
        cursor = next;
      }
    } while (cursor);
    return false;
  } catch {
    return null;
  }
}

/**
 * Whether `userId` is a member of `channel`, the gate for using a SHARED channel credential when
 * `requireChannelMembership` is on. Fail-closed: any API error or incomplete/bounded traversal
 * → not a member, so a non-member can never borrow the channel's cred.
 */
export async function isChannelMember(
  client: {
    conversations: {
      members: (a: { channel: string; cursor?: string; limit?: number }) => Promise<any>;
    };
  },
  channel: string,
  userId: string,
  bounds: ChannelMemberPaginationBounds,
): Promise<boolean> {
  return (await scanChannelMembers(client, channel, bounds, (member) => member === userId)) === true;
}

/**
 * The user ids of every member of `channel`, paged from conversations.members. Used to find the
 * channel's eligible approvers (#113). `null` means the complete current set could not be proven
 * because an API read failed, the caller's overall deadline elapsed, or the configured work cap was
 * exceeded; an empty array means the complete set was read and contained no members.
 */
export async function listChannelMembers(
  client: {
    conversations: {
      members: (a: { channel: string; cursor?: string; limit?: number }) => Promise<any>;
    };
  },
  channel: string,
  bounds: ChannelMemberPaginationBounds,
): Promise<string[] | null> {
  const out = new Set<string>();
  const complete = await scanChannelMembers(client, channel, bounds, (member) => {
    out.add(member);
    return false;
  });
  if (complete === null) return null;
  return [...out];
}
