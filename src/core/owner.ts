import type { SlackIdentity } from './identity';

/**
 * The principal that OWNS a credential — a Slack user or a Slack channel.
 * Distinct from the ACTING identity (the human who triggered a request), which is
 * always used for audit attribution even when a shared channel credential is used.
 */
// enterpriseId is a stored attribute only — it is NOT part of the isolation key
// (team_id is globally unique across Slack). It lets enterprise-scoped queries
// (e.g. offboardUserEverywhere with an enterprise filter) match user-owned rows.
export type Owner = { teamId: string; kind: 'user' | 'channel'; id: string; enterpriseId?: string | null };

export const userOwner = (i: SlackIdentity): Owner => ({
  teamId: i.teamId,
  kind: 'user',
  id: i.userId,
  enterpriseId: i.enterpriseId ?? null,
});

/** teamId MUST be the authenticated user's team — never derived from the channel id. */
export const channelOwner = (teamId: string, channelId: string, enterpriseId: string | null = null): Owner => ({
  teamId,
  kind: 'channel',
  id: channelId,
  enterpriseId,
});
