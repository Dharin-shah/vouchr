// Slack-semantic identity helpers. These KNOW Slack's payload shapes and Web API (Bolt bodies,
// conversations.members) so they live in the adapter layer, not in transport-agnostic core. Core keeps only the SlackIdentity TYPE (the vault key), imported here.
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
