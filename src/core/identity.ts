/** Slack's native identity tuple: the key everything in the vault hangs off. */
export interface SlackIdentity {
  enterpriseId: string | null;
  teamId: string;
  userId: string;
}

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
