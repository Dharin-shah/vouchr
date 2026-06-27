# MCP gateway with Vouchr

A minimal illustration of Vouchr as the **credential and policy layer in front of
tools** — the seam where an MCP gateway belongs. The point: a tool call routes
through Vouchr so the secret stays in the broker, leaves only to an allowlisted
host, and is attributed to the human who triggered it.

## Why route MCP/tool calls through Vouchr

- **Secrets stay in the broker.** The tool handler holds no token. It asks Vouchr
  for a `ConnectionHandle` (`context.vouchr.connect(provider)`) and calls the
  provider via `handle.fetch(...)`. The credential is injected at the HTTP egress
  boundary, inside `fetch`, so it never reaches the model, the tool's own code, or
  the conversation transcript.
- **Egress allowlist.** Each provider pins the hostnames its credential may be sent
  to. A tool can't be tricked into shipping the GitHub token (or an internal key)
  to an attacker-controlled URL — the handle refuses any host off the allowlist,
  and requires https.
- **Channel policy decides the visible tool manifest.** The same `Policy` that gates
  execution also builds the per-channel manifest (`manifestFor`): the agent only
  ever sees tools it can actually run here. In this example the internal-API tool is
  visible only in the ops channel; GitHub is allowed everywhere. The policy is
  checked **before** the tool runs (and `connect()` re-checks it — defense in depth).
- **Acting-human audit.** Even when a shared channel credential is used, Vouchr
  records the inject against the human who triggered the call, not the credential's
  owner. A shared token never launders away who acted.

## How this maps to a real MCP gateway

| This example | Real MCP gateway |
|---|---|
| `TOOLS` map | the tool registry / schemas |
| `manifestFor(channel)` | `ListTools` (policy-filtered manifest) |
| `dispatch(...)` | `CallTool` handler |
| `app_mention` handler | the MCP client transport |
| `handle.fetch(...)` | unchanged — the egress injection point |

Drop a real MCP server in where `dispatch` and `manifestFor` live: serve the
policy-filtered manifest from `ListTools`, and have `CallTool` policy-check, call
`vouchr.connect(provider)`, then run the tool with the handle. The Vouchr calls
don't change.

## What's illustrative vs production

- **Illustrative:** tools are a typed map, not a real MCP runtime; the "agent"
  picks a tool by substring match in the mention text; `internal-api` and its host
  (`api.internal.example.com`) are placeholders; channel ids come from env.
- **Real / reused as-is:** `createVouchr`, the `Policy` gate, `connect()`,
  `handle.fetch()` egress allowlist + injection + acting-human audit, and the
  `ConsentRequiredError` flow (Vouchr posts an in-Slack Connect prompt when the
  user hasn't authorized the provider yet) are the actual library behavior.

## Run

Same setup as the other examples — Slack signing secret, bot token, a public
callback origin (`PUBLIC_URL`), GitHub OAuth client env, and `OPS_CHANNEL_ID` for
the internal tool's allowed channel. Mention the bot with a tool name (e.g.
`@bot github.whoami`) or with none to list the channel's manifest.
