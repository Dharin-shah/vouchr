import { defineProvider, github, type ToolManifestEntry } from '../src';

// ─────────────────────────────────────────────────────────────────────────────
// A per-channel tool manifest mixing the TWO kinds of "tool in a channel", which
// need different mechanisms (see README → "When to use Vouchr vs a service-to-
// service MCP"). The boundary is whose identity the tool acts as:
//
//   • acting_human  → acts AS the human, with their credential + consent → Vouchr
//   • service       → acts AS the agent itself, with the host's service auth → NOT
//                     Vouchr (there is no human credential to broker)
//
// Both live in one manifest so the host sees the whole tool set in one place, but
// only the acting_human entries route through `context.vouchr.connect(...)`.
// ─────────────────────────────────────────────────────────────────────────────

// A Vouchr-brokered, per-human provider. `identity` defaults to 'acting_human'.
const jira = defineProvider({
  id: 'jira',
  authorizeUrl: 'https://auth.atlassian.com/authorize',
  tokenUrl: 'https://auth.atlassian.com/oauth/token',
  scopesDefault: ['read:jira-work', 'write:jira-work'],
  egressAllow: ['api.atlassian.com'],
  refresh: 'rotating',
  pkce: true,
  clientId: process.env.JIRA_CLIENT_ID ?? '',
  clientSecret: process.env.JIRA_CLIENT_SECRET ?? '',
});

// A team-owned "payments" MCP the agent calls AS ITSELF. It's marked `identity:
// 'service'` so Vouchr stays out of its path: `connect('payments')` refuses with
// no consent flow, and the host wires the service auth (its own egress + service
// token, namespaced per channel). No `clientId`/`clientSecret`: Vouchr never
// brokers it, so it needs no OAuth client here.
const payments = defineProvider({
  id: 'payments',
  identity: 'service',
  credential: 'key',
  authorizeUrl: '',
  tokenUrl: '',
  scopesDefault: [],
  egressAllow: ['payments.internal'],
  refresh: 'none',
  pkce: false,
});

export const providers = [github(), jira, payments];

// What `context.vouchr.toolManifest()` returns for a channel where Jira is set to
// 'union' (any connected member) — the shape an agent reads before planning. The
// host filters on `identity` to decide who runs the tool:
//
//   entry.identity === 'acting_human'  → await context.vouchr.connect(entry.provider)
//   entry.identity === 'service'       → host's own service-to-service call
export const exampleManifest: ToolManifestEntry[] = [
  { provider: 'github', mode: 'per-user', enabled: true, identity: 'acting_human' },
  { provider: 'jira', mode: 'union', enabled: true, identity: 'acting_human' },
  { provider: 'payments', mode: null, enabled: true, identity: 'service' },
];

// Route each tool by its identity: Vouchr brokers the humans, the host runs services.
export async function dispatch(
  entry: ToolManifestEntry,
  vouchr: { connect: (id: string) => Promise<unknown> },
  callService: (id: string) => Promise<unknown>,
): Promise<unknown> {
  return entry.identity === 'acting_human'
    ? vouchr.connect(entry.provider) // resolves the human's credential + consent (+ union across members)
    : callService(entry.provider); // service-to-service: Vouchr is deliberately not in this path
}
