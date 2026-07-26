# Thread → GitHub, as the person who asked

A design discussion happens in a Slack thread. Each participant asks the agent to file their own open
question on a PR. Three people ask, three GitHub comments appear — **authored by three different
GitHub accounts**, each the real human who spoke.

That last part is the whole demo, and it is the part a screenshot cannot fake. The agent holds no
GitHub token of its own and cannot act for anyone who has not connected. Vouchr resolves the
credential from the *verified Slack identity on the event*, so Alice's comment is authored by Alice
because Alice asked — not because the agent was told she did.

The model reads the thread and drafts the comment. It never sees a token: `gh.fetch` attaches the
credential inside Vouchr, at the outbound HTTP boundary.

## What this shows that the basic example doesn't

| | [`bolt-github`](../bolt-github) | this example |
| --- | --- | --- |
| Identity | one user reads their own profile | **N users each write as themselves** |
| Direction | read (`GET /user`) | **write** (`POST /repos/…/comments`) |
| Gates exercised | consent, egress host | consent, egress host + **path + method**, `allowWrites` |
| Model involved | no | yes — drafts the comment, never holds the token |

## Writes need two opt-ins

This example is the reason both exist. `app.ts` sets:

```ts
// 1. the provider declares what it accepts
defineProvider({ ...github(...), egressMethods: ['GET', 'POST'], egressPaths: ['/repos', '/user'] })

// 2. the deployment enables writes at all
createVouchr({ ..., allowWrites: true })
```

Neither alone is enough. Drop either one and the `POST` is refused **before the credential is read** —
so a prompt-injected `DELETE /repos/owner/repo` is refused too, even though the user's token could
genuinely perform it. Try it: delete `allowWrites: true` and ask again.

## Setup

You need the [QUICKSTART](../../QUICKSTART.md) Slack app and GitHub OAuth app first — this example
uses the same two. Then:

```bash
export GITHUB_REPO=owner/name          # the repo to comment on
export GITHUB_ISSUE=17                 # issue or PR number
export ANTHROPIC_API_KEY=sk-ant-...    # drafts the comment
node --import tsx examples/thread-to-github/app.ts
```

Plus the usual `SLACK_SIGNING_SECRET`, `SLACK_BOT_TOKEN`, `PUBLIC_URL`, `VOUCHR_DATABASE_URL`,
`VOUCHR_MASTER_KEY`, `GITHUB_CLIENT_ID`, and `GITHUB_CLIENT_SECRET`.

The GitHub OAuth consent asks for `public_repo` because commenting is a write. For a private repo,
change the scope to `repo` — and note the connect prompt will say so, which is the point.

## Running the demo

1. In a channel, `/vouchr enable github` once (channels are deny-by-default).
2. Have **two or three people** hold a short design discussion in one thread.
3. Each of them, in that thread: `@your-bot file my open question`.
4. First time for each person: a private Connect prompt appears, they authorize, they ask again.
5. Each gets back: `Filed as *their-github-login* on owner/name#17 — <link>`.

Open the PR. The comments are authored by different GitHub accounts.

## Recording it

The multi-user shot is the story, so film it with **two real Slack accounts** — not one account
renamed. Suggested cut, 60–75 seconds:

1. The thread, mid-discussion. (5s)
2. Person A asks → Connect prompt → authorize → comment lands. (25s)
3. **Person B asks in the same thread → their comment lands under a different GitHub account.** (20s)
4. Cut to the PR: two comments, two authors, two avatars. (10s)
5. Cut to the terminal: `grep` the logs for the token, find nothing. (10s)

Beat 3 is the one no competitor screenshot can reproduce. Beat 5 only lands as proof *because* of
beat 3 — without the second user it is just OAuth.

Split-screen Slack and the terminal throughout so beat 5 needs no cut. Captions, not voiceover —
it gets watched muted.

## What this does not do

The agent posts the comment the model drafted. Vouchr binds **who** the request acts as and **where**
it may go; it does not verify that the comment text is a faithful summary of the thread. If the
drafted text matters, show it to the user before posting — see
[issue #294](https://github.com/Dharin-shah/vouchr/issues/294) for the approval-UX discussion.
