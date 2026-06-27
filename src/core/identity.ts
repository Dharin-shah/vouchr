/** Slack's native identity tuple — the key everything in the vault hangs off. */
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
 * Whether `userId` is a Slack workspace admin/owner — the gate for channel-credential
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
