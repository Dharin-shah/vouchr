# One agent, many providers, N humans — each acting as themselves

A discussion happens in a Slack thread. People ask the agent for things that live in different
systems: *file this question on the PR*, *put it on my calendar*, *add it to the meeting notes*. The
agent picks the provider from the request. Vouchr decides **whose** credential that becomes.

Nothing here is provider-specific. The agent doesn't know it's talking to GitHub — it's given the
list of providers a channel member enabled **in this channel** and picks from it.

## The three things this demonstrates

**1. The agent holds no credential of its own.** Vouchr resolves one from the *verified Slack
identity on the event*. There is no user-id argument to get wrong and nothing the model can say that
changes whose account is used. Alice's comment is authored by Alice because Alice asked.

**2. The provider list is the channel's, not the code's.** `toolManifest()` returns what a channel member
enabled here, and that list becomes the model's tool enum:

```ts
const manifest = await vouchr.toolManifest();
const usable = manifest.filter((t) => t.enabled && t.identity === 'acting_human').map((t) => t.provider);
// → the `provider` enum the model chooses from
```

Channels are deny-by-default, so an agent in a channel where nothing is enabled can reach nothing.
Turning a provider on is `/vouchr enable <provider>` — no redeploy, no code change.

**3. The model chooses the URL — and that's safe.** This is deliberately the generic-HTTP-tool shape
prompt injection loves. It's safe because the egress gates run **before the credential is attached**:
a host, path, or method the provider never declared is refused, the refused request reads no
credential and opens no connection, and nothing is sent. Each provider declares its own bounds:

```ts
defineProvider({ ...github(...), egressMethods: ['GET', 'POST'], egressPaths: ['/repos', '/user'] })
```

So the model may POST a comment and nothing else. `DELETE /repos/{owner}/{repo}` is refused even
though the user's own token would happily perform it.

## Writes need two opt-ins

Both, or the agent is read-only:

```ts
defineProvider({ ...github(...), egressMethods: ['GET', 'POST'], … })  // 1. provider declares
createVouchr({ providers, allowWrites: true, … })                      // 2. deployment enables
```

Try it: delete `allowWrites: true` and ask again. Every provider is intersected down to GET/HEAD
regardless of what it declares, and the write is refused before the credential is attached.

## Setup

Start from the [QUICKSTART](../../QUICKSTART.md) Slack app.

**One extra bot scope.** This example reads the thread it was mentioned in
(`conversations.replies`), which `examples/slack-manifest.yml` does not grant — add
`channels:history` (and `groups:history` for private channels) to the manifest's bot scopes and
reinstall the app, or the first mention fails with `missing_scope`. It's deliberately not in the
shared manifest: reading channel history is a broad grant, and only this example needs it.

Then configure **at least one** provider — the agent registers whichever ones it finds credentials
for:

| Provider | Env | Enables |
| --- | --- | --- |
| GitHub | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | comment on issues and PRs |
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | create calendar events |
| Notion | `NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET` | append to pages |

```bash
export ANTHROPIC_API_KEY=sk-ant-...
node --import tsx examples/multi-provider-agent/app.ts
```

Plus the usual `SLACK_SIGNING_SECRET`, `SLACK_BOT_TOKEN`, `PUBLIC_URL`, `VOUCHR_DATABASE_URL`,
`VOUCHR_MASTER_KEY`.

Configure two providers if you can — watching the model pick between them from plain English is most
of the point.

## Running it

1. Enable what you want available: `/vouchr enable github`, `/vouchr enable google`. (Deny-by-default:
   until you do, the agent will say so.)
2. Have **two or three people** hold a short discussion in one thread.
3. Each of them, in that thread: `@your-bot file my open question on PR 17` — or *"put a 30-minute
   follow-up on my calendar tomorrow"*, which routes to a different provider entirely.
4. First time for each person: a private Connect prompt, they authorize, they ask again. Per-person —
   one participant connecting does nothing for anyone else.
5. Each gets a reply naming the account it acted as.

Then open the PR (or the calendars). Different authors, different accounts.

## Recording it

The multi-user shot is the story. Film with **two real Slack accounts** — not one renamed. 60–75s:

1. The thread, mid-discussion. (5s)
2. Person A asks → Connect prompt → authorize → it lands. (25s)
3. **Person B asks in the same thread → lands under a different account.** (20s)
4. Cut to the PR: two comments, two authors, two avatars. (10s)
5. Cut to the terminal: `grep` the logs for the token, find nothing. (10s)

Beat 3 is the one no competitor screenshot reproduces. Beat 5 only reads as *proof* because of beat 3
— without a second user it's just OAuth with extra steps.

**Optional beat 6, if you want the guardrail on camera:** ask the agent to **edit an existing
comment**. That's a `PATCH`, which this GitHub config doesn't declare, so the method gate refuses it
without reading the credential or opening a connection.

Pick that ask deliberately. *"Delete the repo"* films worse: the tool's `method` enum is
`GET | POST | PATCH`, so the model can't emit `DELETE` at all and simply declines — on camera that's
indistinguishable from a model being agreeable, which is the thing this beat exists to contrast
against. `PATCH` is a request the model *will* make and the gate *will* stop. (A URL on a host
outside `egressAllow` works equally well, via the host gate.)

Split-screen Slack and the terminal throughout so beat 5 needs no cut. Captions, not voiceover — it
gets watched muted.

## What this does not do

Vouchr binds **who** the request acts as and **where** it may go. It does not verify that the request
the model composed is a faithful reading of what the human wanted — the model picked the endpoint and
wrote the body. For writes where that matters, show the user what's about to happen before it does;
see [#294](https://github.com/Dharin-shah/vouchr/issues/294) for that discussion.

**This example specifically feeds the model the whole thread, and that crosses participants.** The
prompt is every message from everyone in it, while the credential is the *mentioning* user's — so
Bob can write something in the thread that steers what the model does with Alice's token when Alice
mentions the bot. The egress gates still bound it to what Alice's own provider config allows (here:
comment or open an issue in a public repo, not delete one), but the blast radius is Alice's account,
not Bob's. Narrow the transcript, or scope writes tighter, before pointing this at a channel where
that matters.

Provider responses also come back to your process. What reaches the model or the transcript after
that is the host's call, not Vouchr's.
