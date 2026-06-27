import { App, ExpressReceiver } from '@slack/bolt';
import {
  createVouchr,
  github,
  defineProvider,
  Policy,
  ConsentRequiredError,
  type Provider,
  type ConnectContext,
  type ConnectionHandle,
} from '../../src';

// ─────────────────────────────────────────────────────────────────────────────
// Vouchr as the credential/policy layer in front of "tools".
//
// The pattern: an agent in Slack wants to call a tool. The tool handler holds NO
// secret. It asks Vouchr for a handle (`context.vouchr.connect(provider)`) and
// calls the provider through `handle.fetch(...)`, so the credential is injected at
// the egress boundary and never reaches the model or the tool's own code. A
// per-channel `Policy` decides which tools/providers are usable in the current
// channel BEFORE the tool runs — that same policy shapes the tool manifest the
// agent is even allowed to see.
//
// This is NOT a full MCP runtime. Tools are modeled as a small typed map and a
// dispatcher. Where a real MCP server plugs in is called out below.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * An internal/first-party API exposed as a Vouchr provider. It's a `key` provider
 * (a user/admin pastes a static key into a private modal — no OAuth), and its
 * egress allowlist pins the one host its key may ever be sent to. The key is
 * attached as `x-api-key` at the fetch boundary, not by the tool.
 *
 * ponytail: a local provider modeled inside the example — the built-in providers
 * (github/google/gitlab/notion) are OAuth SaaS; an internal API is the realistic
 * second tool, so it's defined here rather than invented in src.
 */
const internalApi = (): Provider =>
  defineProvider({
    id: 'internal-api',
    credential: 'key',
    authorizeUrl: '', // unused for key providers
    tokenUrl: '', // unused for key providers
    scopesDefault: [],
    egressAllow: ['api.internal.example.com'],
    inject: (headers, secret) => headers.set('x-api-key', secret),
    refresh: 'none',
    pkce: false,
  });

// ── The tool registry. In a real MCP server this is the ListTools manifest. ──────
//
// A tool declares which Vouchr provider it needs and a `run(handle)` that talks to
// the provider ONLY through the injected handle. It never sees, stores, or logs a
// token — it gets a `ConnectionHandle` and calls `.fetch(...)`.
interface Tool {
  name: string;
  /** Vouchr provider whose credential this tool needs. */
  provider: string;
  /** Human/agent-facing description (the MCP tool schema would carry this). */
  description: string;
  run(handle: ConnectionHandle): Promise<string>;
}

const TOOLS: Record<string, Tool> = {
  'github.whoami': {
    name: 'github.whoami',
    provider: 'github',
    description: "Return the acting user's GitHub login and public repo count.",
    run: async (handle) => {
      // The bearer is injected inside fetch(), after the egress allowlist check.
      const res = await handle.fetch('https://api.github.com/user');
      const me = (await res.json()) as { login?: string; public_repos?: number };
      return `GitHub: ${me.login ?? 'unknown'} (${me.public_repos ?? 0} public repos)`;
    },
  },
  'internal.openTickets': {
    name: 'internal.openTickets',
    provider: 'internal-api',
    description: 'Count open tickets from the internal ticketing API.',
    run: async (handle) => {
      const res = await handle.fetch('https://api.internal.example.com/tickets?state=open');
      const body = (await res.json()) as { count?: number };
      return `Open tickets: ${body.count ?? 0}`;
    },
  },
};

// ── Per-channel policy. Decides the visible manifest AND gates execution. ─────────
//
// github is usable everywhere; the internal-api tool only in the ops channel. A
// real deployment would source channel ids from config; here OPS_CHANNEL_ID is env.
const OPS_CHANNEL = process.env.OPS_CHANNEL_ID ?? 'C0OPS000';

const policy = new Policy({
  github: { defaultAllow: true },
  'internal-api': { defaultAllow: false, allowChannels: [OPS_CHANNEL] },
});

/**
 * The tool manifest for a channel = tools whose provider policy allows here. This
 * is what an MCP ListTools should return: the agent never even sees a tool it
 * cannot run in the current channel.
 */
function manifestFor(channel: string | null): Tool[] {
  return Object.values(TOOLS).filter((tool) => policy.check(tool.provider, channel));
}

/**
 * Dispatch a tool call. In a real MCP server this is the CallTool handler.
 *
 *   1. Policy gate BEFORE anything runs — defense even if a hidden tool is named.
 *   2. Ask Vouchr for a leak-safe handle. connect() re-checks the same policy and,
 *      if the acting user hasn't connected, posts a Connect prompt and throws
 *      ConsentRequiredError (stop this turn). The credential never enters this code.
 *   3. Run the tool with the handle; it calls the provider via handle.fetch(...),
 *      which injects the secret at egress and audits as the acting human.
 */
async function dispatch(
  vouchr: ConnectContext,
  channel: string | null,
  toolName: string,
): Promise<string> {
  const tool = TOOLS[toolName];
  if (!tool) throw new Error(`Unknown tool "${toolName}".`);

  if (!policy.check(tool.provider, channel)) {
    throw new Error(`Tool "${toolName}" is not available in this channel.`);
  }

  const handle = await vouchr.connect(tool.provider);
  return tool.run(handle);
}

/** Pick a tool name out of the mention text (the agent/LLM would choose this). */
function parseToolName(text: string | undefined): string | null {
  return Object.keys(TOOLS).find((name) => text?.includes(name)) ?? null;
}

// ── Slack wiring. The app_mention handler is the stand-in for the MCP client. ─────
const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET! });
const app = new App({ token: process.env.SLACK_BOT_TOKEN, receiver });

app.event('app_mention', async ({ context, event, client }) => {
  const channel = event.channel;
  const requested = parseToolName(event.text);
  try {
    const text = requested
      ? await dispatch(context.vouchr, channel, requested)
      : `Tools available here: ${manifestFor(channel).map((t) => t.name).join(', ') || '(none)'}`;
    await client.chat.postMessage({ channel, thread_ts: event.ts, text });
  } catch (e) {
    if (e instanceof ConsentRequiredError) return; // Connect prompt already posted to the user.
    // Policy denials and tool errors are safe to surface — they never carry a secret.
    await client.chat.postMessage({ channel, thread_ts: event.ts, text: (e as Error).message });
  }
});

(async () => {
  const vouchr = await createVouchr({
    providers: [github(), internalApi()],
    baseUrl: process.env.PUBLIC_URL!,
    policy, // the SAME policy object that builds the manifest also gates connect()
  });
  app.use(vouchr.middleware);
  vouchr.mountRoutes(receiver.router);
  vouchr.registerCommands(app); // /vouchr status | disconnect | configure

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.start(port);
  console.log(`Vouchr MCP-gateway demo on :${port} — mention the bot with a tool name.`);
})();
