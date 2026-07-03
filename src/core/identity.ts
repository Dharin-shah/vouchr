/**
 * Slack's native identity tuple: the key everything in the vault hangs off. This TYPE stays in
 * transport-agnostic core (broker.ts and others key on it); the Slack-semantic helpers that parse
 * Bolt payloads / call the Web API to PRODUCE it live in src/adapters/slack-identity.ts.
 */
export interface SlackIdentity {
  enterpriseId: string | null;
  teamId: string;
  userId: string;
}
