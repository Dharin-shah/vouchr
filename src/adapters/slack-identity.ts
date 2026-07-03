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

/**
 * Whether `userId` is a member of `channel`, the gate for using a SHARED channel credential when
 * `requireChannelMembership` is on. Fail-closed: any API error (or a member list we can't read)
 * → not a member, so a non-member can never borrow the channel's cred. Pages conversations.members
 * (Slack returns at most 1000/page) until the user is seen or the cursor runs out; a missing/empty
 * page is treated as "not found", not "allow".
 */
export async function isChannelMember(
  client: {
    conversations: {
      members: (a: { channel: string; cursor?: string; limit?: number }) => Promise<any>;
    };
  },
  channel: string,
  userId: string,
): Promise<boolean> {
  try {
    let cursor: string | undefined;
    do {
      const res = await client.conversations.members({ channel, cursor, limit: 1000 });
      if (Array.isArray(res?.members) && res.members.includes(userId)) return true;
      cursor = res?.response_metadata?.next_cursor || undefined;
    } while (cursor);
    return false;
  } catch {
    return false;
  }
}

/**
 * The user ids of every member of `channel`, paged from conversations.members. Used by the 'union'
 * channel mode to find a member who has connected a provider. Fail-closed: any API error yields an
 * empty list (no member resolves → the caller falls back to prompting the asker), so a read we can't
 * complete never silently borrows a credential.
 */
export async function listChannelMembers(
  client: {
    conversations: {
      members: (a: { channel: string; cursor?: string; limit?: number }) => Promise<any>;
    };
  },
  channel: string,
): Promise<string[]> {
  const out: string[] = [];
  try {
    let cursor: string | undefined;
    do {
      const res = await client.conversations.members({ channel, cursor, limit: 1000 });
      if (Array.isArray(res?.members)) out.push(...res.members);
      cursor = res?.response_metadata?.next_cursor || undefined;
    } while (cursor);
  } catch {
    return [];
  }
  return out;
}
