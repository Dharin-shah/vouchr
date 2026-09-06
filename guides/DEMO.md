# Demo run-through

A script for one recorded session: the maintainer, two or three friends, one Slack workspace, every
product scenario. Each scenario says who does what, the exact copy Slack shows (quoted from the
code, with the file it comes from), what the audit shows afterwards, and what to capture.

The app is [`examples/demo/app.ts`](../examples/demo/app.ts): the quickstart app plus one shared
credential. Slack copy is rendered by `src/adapters/blocks.ts` and `src/adapters/bolt.ts`; refusal
copy is in `src/core/errors.ts` and `src/core/channelConfig.ts`. `<#C…>` is Slack's channel link,
`<@U…>` a user mention. Every scenario below also runs in `test/demo.test.ts` on the production
path, asserting this copy.

## 1. Cast and props

| Who | Role | Needs |
| --- | --- | --- |
| Alex | the requester: connects GitHub, asks the agent for reads and writes | a GitHub account |
| Sam | the teammate: enables providers, approves and denies | nothing |
| Jo | the outsider: not in `#demo-team` | nothing |
| You | workspace admin, laptop, tunnel, screen recorder | everything below |

- A throwaway Slack workspace. You are its admin. Alex, Sam, and Jo are members.
- A private channel `#demo-team` with you, Alex, Sam, and the bot. Jo is not in it.
- A public channel `#demo-public` with the bot. Jo can join it.
- A GitHub OAuth app (quickstart step 5), a throwaway repo Alex can write to (`alex/vouchr-demo`
  below), and a personal access token that can open issues in it: the shared credential in (g).
- Local PostgreSQL and a tunnel to port 3000.

### Pre-flight checklist

Follow [QUICKSTART.md](../QUICKSTART.md) steps 2 to 8 once, with these differences: run
`npm run example:demo` instead of `npm run example:github`, and invite the bot to both channels.

1. Tunnel up: `ngrok http 3000 --domain <your-name>.ngrok-free.app` or
   `cloudflared tunnel --url http://localhost:3000`. The `https://` URL is `PUBLIC_URL`.
2. Slack app created from `examples/slack-manifest.bootstrap.yml` with the redirect URL
   `https://<tunnel host>/vouchr/oauth/slack`. Installed to the workspace.
3. GitHub OAuth app with callback `PUBLIC_URL/vouchr/oauth/callback`.
4. `.env` filled in. Every variable the demo app reads:

   ```dotenv
   VOUCHR_MASTER_KEY=            # openssl rand -base64 32
   VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
   SLACK_BOT_TOKEN=xoxb-...      # Install App page
   SLACK_SIGNING_SECRET=...      # Basic Information
   VOUCHR_SLACK_CLIENT_ID=...    # Basic Information, App Credentials
   VOUCHR_SLACK_CLIENT_SECRET=...
   PUBLIC_URL=https://<tunnel host>
   PORT=3000
   GITHUB_CLIENT_ID=...
   GITHUB_CLIENT_SECRET=...
   ```

   The Slack client id and secret are required. Every Connect link passes through a Slack sign-in
   check that proves the browser belongs to the person who asked.
5. Schema and app:

   ```bash
   VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr npm run cli -- migrate
   # prints: OK schema migrated to version 3
   npm run example:demo
   # prints: ⚡ Vouchr demo on :3000. Callback at https://<tunnel host>/vouchr/oauth/callback
   ```
6. The three request URLs in the Slack app set to `PUBLIC_URL/slack/events` (quickstart step 8).
7. `/invite @vouchr` in `#demo-team` and `#demo-public`.
8. Note three ids for scenario (j): `curl -s -H "Authorization: Bearer $SLACK_BOT_TOKEN" https://slack.com/api/auth.test`
   prints `team_id` and the bot's `user_id`; the channel id is at the bottom of the `#demo-team`
   details pane.

### Two-minute smoke test (before the friends arrive)

1. `npm run example:dry-run` passes (`# pass 1`).
2. `VOUCHR_DATABASE_URL=... VOUCHR_MASTER_KEY=... npm run cli -- doctor` prints
   `PASS master key: 32 bytes` and `PASS db reachable`.
3. In `#demo-team`, as yourself: `@vouchr who am I`. Expect the private refusal from scenario (a).
   Then `/vouchr enable github`, mention again, click **Connect github**, sign in, authorize, mention
   again. Expect `You are *<your login>* on GitHub, N public repos.` If that works, run
   `/vouchr disconnect github` and `/vouchr disable github` so the recording starts clean.

Record one take per scenario with the app's terminal beside Slack. Screenshots are listed per scenario.

## 2. Which app

None of the shipped examples has both a read and a governed write, so
[`examples/demo/app.ts`](../examples/demo/app.ts) adds them on top of `examples/bolt-github`:

- `github()` with no approval configuration at all. The agent acts as the person, so by default the
  requester confirms each write (every method except GET and HEAD) privately; reads go through.
- `github-team`, a key provider in the style of `examples/internal-api-key`, for the channel's
  shared token, with `approval: { grant: 'thread', ttlMs: 30 * 60 * 1000 }`: the credential is the
  channel's, so by default a teammate approves, and one approval covers every write in the approving
  thread for thirty minutes. The default injection is
  `Authorization: Bearer <key>`.
- `@vouchr who am I` runs `GET /user`. Any other text does the same.
- `@vouchr open an issue titled <title> in repo <owner>/<name>` runs `POST /repos/<owner>/<name>/issues`
  as the person who asked, with a `reason` and `link` on the call.
- `@vouchr open a team issue titled <title> in repo <owner>/<name>` does the same write with the
  channel's `github-team` credential.
- Replies come in a thread under the mention. `examples/demo/worker.ts` is the headless job for (j):
  it runs as the app's bot user with no credential of its own, and a member authorizes each write
  with their own `github` account.

Nobody picks a mode. Who the agent acts as is one setting per channel per provider, `person` (the
default) or `channel`, and `connect-shared` sets it for you.

## 3. Scenarios

Run them in order; each leaves the state the next one expects.

### (a) Deny by default

Alex, in `#demo-team`: `@vouchr who am I`.

Expected, private to Alex (`src/core/errors.ts`):

> This provider is disabled in the channel. Any member can run `/vouchr enable` there.

Audit: a `denied` row with `reason: 'tool-disabled'` in `meta` (`src/adapters/bolt.ts`). `/vouchr audit`
shows `:information_source: *Your credential usage*` then `Nothing recorded yet.`

Shots: the refusal.

### (b) A member enables the provider

Sam, in `#demo-team`: `/vouchr enable github`.

Expected (`src/adapters/bolt.ts`): `Enabled *github* in <#demo-team>.`

On the laptop `VOUCHR_DATABASE_URL=... npm run cli -- channels` shows the row with identity `person`
and enabled `yes`. Audit: a `config` row. Shots: the reply and the `channels` output.

### (c) Alex connects

Alex, in `#demo-team`: `@vouchr who am I`.

Expected, private to Alex (`src/adapters/blocks.ts`, `connectBlocks`):

> :link: *Connect your github account*
> I need to act as you on github for this. Your token is stored encrypted on this server and is never shown to the agent or posted in Slack. This link expires in 10 minutes.
> Connecting grants the agent, acting as you:
> • Read your profile
> • Read and write your repositories

with a **Connect github** button. Alex clicks it. The browser goes to Slack's sign-in page first
(Slack's own screen), then to GitHub's authorize screen, then lands on Vouchr's page
(`src/adapters/landing.ts`). Back in Slack, Alex gets a DM and a private note in the channel, both
`✅ github connected as alex.` (`src/adapters/blocks.ts`, `connectedDmText`). The prompt itself was
replaced on click with `Opening the sign-in page. If it says the request is no longer current, mention me again.`

If a prompt is left for more than ten minutes, clicking it replaces it with
`This connection prompt is no longer current. Get a new link to continue.` and a **Send a new link**
button (`connectExpiredBlocks`). Clicking that swaps in a fresh Connect prompt in place.

`/vouchr status` from Alex prints `Your connected accounts:` then `• *github* (alex) in your DMs`.
Audit: a `connect` row. `vouchr inventory` shows one row, `owner_kind` user.

Shots: the Connect prompt, the Slack sign-in page, the GitHub consent screen, the landing page, the DM.

### (d) A read runs as Alex

Alex: `@vouchr who am I`.

Expected, in a thread: `You are *alex* on GitHub, N public repos.`

The terminal shows no token. `/vouchr audit` from Alex shows `• *github* · inject · <#demo-team> · <time>`.

Shots: the reply and the terminal side by side.

### (e) A write as Alex waits for Alex

Alex: `@vouchr open an issue titled Demo issue in repo alex/vouchr-demo`.

Nothing is sent. The agent acts as Alex with Alex's own token, so Alex gets one private prompt, in
the thread (`src/adapters/blocks.ts`, `approvalBlocks`). The channel sees nothing:

> :lock: *Approve this github action?*
> The agent wants to run an action as you on github.
> POST api.github.com/repos/alex/vouchr-demo/issues
> Reason: Open an issue titled "Demo issue" in alex/vouchr-demo, asked for in Slack
> Link: https://github.com/alex/vouchr-demo
> This covers one call, once, within 5 minutes. This prompt expires in 10 minutes if unused. The request body is not shown or inspected. The reason and link are the agent's own claim, not verified by Vouchr.

with **Approve** and **Deny** buttons. The reason and link are what the demo app passes on the
call; an agent that gives none gets the same prompt without those two lines.

Alex repeats the same mention while the prompt is up. Nothing new is posted; Alex gets one private
line: `Still waiting for you to decide the github action above.`

Alex clicks **Approve**. The prompt is replaced by:

> ✅ Approved the *github* action. This covers one call, once, within 5 minutes. Have the agent retry now.

Alex repeats the exact same mention. Reply: `Opened https://github.com/alex/vouchr-demo/issues/1 as *alex*.`

Alex repeats it once more. A new approval prompt appears. Approvals are single use
(`test/demo.test.ts`, "(e) a write as Alex waits for Alex").

Why Alex and not a teammate: the credential is Alex's and the request is Alex's, so Alex is already
the human in the loop; a second person would add a step without adding a check. The teammate gate is
the team credential's, scenario (g). To make a personal provider wait for a teammate anyway, set
`approval: { approver: 'member' }` on it.

Audit, in order: `approval_requested` (with the reason under `meta.reason`), `approved` with Alex as
`actor`, `approval_consumed` with Alex as `actor`, `inject`.

Shots: the prompt, the approved message, the issue on GitHub, the second prompt.

### (f) Deny

Alex clicks **Deny** on the prompt left over from (e). The prompt is replaced by:

> 🚫 Denied the *github* action. Nothing was sent.

The denial is kept in the table with `status = 'denied'` for ten minutes so a headless poller can
read it. It does not block: if Alex asks again, a new prompt appears.

Audit: `denied` with `reason: 'approval-denied'`. Shots: the denied message.

### (g) A shared credential the channel owns

Sam: `/vouchr enable github-team`, then `/vouchr connect-shared github-team`. A modal titled
**Channel credential** opens (`src/adapters/blocks.ts`, `configureModal`):

> Set the *github-team* credential for this channel. Only you can see what you type here. It is never posted to the channel.

Sam pastes the team token into **Paste a key directly** and saves. A modal titled **Credential saved**
says `Saved the *github-team* credential for <#demo-team>.` From now on the agent acts as the channel
for `github-team` there; `/vouchr tools` shows `• *github-team*: enabled (acts as channel)`.

If Sam had set the identity first (`/vouchr identity github-team channel`, reply
`In <#demo-team> the agent now acts as the channel for *github-team*. Connect its account with
\`/vouchr connect-shared github-team\`.`) and Alex asked before the token was connected, Alex would
see one line: `No shared channel credential is configured. Any member can run \`/vouchr connect-shared\` there.`

Alex: `@vouchr open a team issue titled Team issue in repo alex/vouchr-demo`. The credential is the
channel's, so this time the channel gets one message, in the thread, and a teammate decides:

> :lock: *Approve this github-team action?*
> The agent wants to run an action on github-team for <@alex>. Another member of this channel must approve it.
> POST api.github.com/repos/alex/vouchr-demo/issues
> Reason: Open an issue titled "Team issue" in alex/vouchr-demo, asked for in Slack
> Link: https://github.com/alex/vouchr-demo
> This covers every github-team call that needs approval in this thread for 30 minutes. This prompt expires in 10 minutes if unused. The request body is not shown or inspected. The reason and link are the agent's own claim, not verified by Vouchr.

Alex repeats the mention while the prompt is up: one private line,
`Still waiting for another member of this channel to approve the github-team action.`

Alex clicks **Approve**. Private reply, the prompt stays (`src/adapters/bolt.ts`):

> You are not eligible to decide this approval; another channel member must.

Sam approves: `✅ Approved the *github-team* action. This covers every github-team call that needs approval in this thread for 30 minutes. Have the agent retry now.`
Alex gets a private note: `✅ <@sam> approved your *github-team* action. Ask the agent to retry.`
Alex repeats the mention: `Opened https://github.com/alex/vouchr-demo/issues/2 as *<token owner>*.`

Audit: `denied` with `reason: 'not-approver'` for Alex's click, `approved` and `approval_consumed`
with Sam as `actor`. `/vouchr audit channel` shows `by <@sam>` on the approval rows.

Audit: `config` for the credential, then the approval rows with `grant: 'thread'` in `meta`.
Sam denying instead reads `🚫 Denied the *github-team* action. Nothing was sent.` and Alex gets
`🚫 <@sam> denied your *github-team* action. Nothing was sent.` `vouchr inventory` now has a second row with `owner_kind` channel and `owner_id` the channel id.

Sam, in `#demo-team`: `/vouchr` with no arguments opens the **Vouchr** settings modal
(`src/adapters/blocks.ts`, `configModal`). Under **Channel settings** the enabled providers come first,
each with a select labelled `github-team: who does the agent act as here?` showing the current value,
`Each member, as themselves` or `This channel, with one shared credential`, and the
**Enabled in this channel** checkbox. Disabled providers follow with only the checkbox, labelled
`<provider>: enable to configure`. Saving without touching anything writes nothing.

Shots: the credential modal (blur the field), the saved message, the settings modal with the
`github-team` line, the prompt, the issue opened by the token owner.

### (h) One approval covers the thread

Alex, in the same thread: `@vouchr open a team issue titled Second team issue in repo alex/vouchr-demo`.
No prompt. Reply: `Opened https://github.com/alex/vouchr-demo/issues/3 as *<token owner>*.`

Alex, in a different thread: the same mention. The prompt is back; the grant is bound to the thread
it was approved in. After thirty minutes the first thread asks again too
(`test/demo.test.ts`, "(h) one approval covers the thread until the TTL").

Reset for the rest of the session: nothing to do. To show the switch back, Sam runs
`/vouchr disconnect-shared github-team`: `Removed the shared *github-team* account in <#demo-team>. The agent now acts as each person there.`

Shots: the second issue with no prompt, the prompt in the other thread.

### (i) Jo, the outsider

Jo is not in `#demo-team`. Slack itself keeps the channel and every prompt in it out of Jo's sight,
so there is nothing for Jo to click. Screenshot Jo's sidebar without the channel.

The server-side gate is the same in every channel: only a current member may enable, set who the
agent acts as, connect a shared credential, or approve the team credential's use, and the requester
may never approve their own use of it (`test/demo.test.ts`, "(i) an outsider"). The refusal copy for a non-member on the
configure commands is (`src/adapters/bolt.ts`):

> Only a current member of this channel can change channel tools. If you are one, make sure Vouchr is in the channel and try again.

The public-channel tradeoff, from [THREAT-MODEL.md](./THREAT-MODEL.md):

> in a public channel every member can configure and approve, so teams should govern agents from channels whose membership they control.

Show it: Jo joins `#demo-public` and runs `/vouchr enable github`. Reply:
`Enabled *github* in <#demo-public>.` Anyone in the workspace can join a public channel, so anyone
can do this there. Then Jo runs `/vouchr disable github` and leaves.

Shots: Jo's sidebar, the enable reply in the public channel.

### (j) An autonomous worker

A job with no human requester asks the channel over the broker, and a member authorizes the write
with their own `github` account. No team credential: the shared `github-team` credential from (g) is
not involved, and nothing is connected for the bot. The broker is a second process on the same
database. In a second terminal:

```bash
export VOUCHR_MASTER_KEY=<same as .env>
export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
export VOUCHR_SLACK_CLIENT_ID=<same as .env> VOUCHR_SLACK_CLIENT_SECRET=<same as .env>
export VOUCHR_IDENTITY_SECRET=$(openssl rand -base64 32)
export VOUCHR_DEPLOYMENT_ID=demo
export VOUCHR_BASE_URL=http://localhost:3001     # the broker's connect routes are not used here
export VOUCHR_PORT=3001 VOUCHR_ALLOW_WRITES=1
export VOUCHR_PROVIDER_GITHUB_CLIENT_ID=$GITHUB_CLIENT_ID VOUCHR_PROVIDER_GITHUB_CLIENT_SECRET=$GITHUB_CLIENT_SECRET
export VOUCHR_PROVIDERS='[{"id":"github","authorizeUrl":"https://github.com/login/oauth/authorize","tokenUrl":"https://github.com/login/oauth/access_token","scopesDefault":["repo"],"egressAllow":["api.github.com"],"refresh":"none","pkce":false}]'
npm run broker
```

In a third terminal, with the same `VOUCHR_IDENTITY_SECRET` and `VOUCHR_DEPLOYMENT_ID` exported:

```bash
DEMO_TEAM=T... DEMO_BOT_USER=U... DEMO_CHANNEL=C... DEMO_REPO=alex/vouchr-demo \
  node --import tsx examples/demo/worker.ts
```

The worker mints an identity for the bot user with `worker: true`, bound to `#demo-team`, calls
`POST /v1/authorization` with a `reason` and a `link`, prints
`authorization 200 { authorizationId: '…', status: 'pending', expiresAt: … }`, then `poll pending`
every five seconds. Within fifteen seconds the Slack app posts one message to `#demo-team`:

> :lock: *Authorize this github action?*
> The worker <@vouchr> wants to run an action on github and has no account of its own. A member of this channel can authorize it with their own account; the call then runs as that member, once.
> POST api.github.com/repos/alex/vouchr-demo/issues
> Reason: TICKET-42: open the release checklist issue
> Link: https://tracker.example/TICKET-42
> This covers one call, once, within 5 minutes. ...
> [Authorize with your account] [Deny]

Jo, who never connected GitHub, clicks first: a private Connect prompt appears for Jo in the channel,
with `Connect your *github* account first. Vouchr sent you a private Connect prompt in this channel;
once connected, click *Authorize with your account* again. The request stays open for 10 minutes if
nobody authorizes it.` The request stays pending. Sam clicks:
`✅ Authorized the *github* action with your account. It runs as you, once. Further *github* actions
this worker takes in this channel will ask you privately, each time, until 30 minutes pass without
one. The worker can retry now.` The worker prints `poll approved`, sends `POST /v1/fetch` with the
same claims, and prints `fetch 200 { status: 201, url: 'https://github.com/alex/vouchr-demo/issues/4' }`.
The issue is opened by Sam's GitHub account.

Run the worker again with a different title: the request is minted for Sam and Sam alone gets a
private prompt (`The worker <@vouchr> wants to run another action on github in this thread, where you
authorized it with your account. It runs as you, once, if you approve.`), with a plain *Approve*
button. Sam's `/vouchr disconnect github` ends that: the next run asks the channel again.

Audit: `approval_requested` and `approval_consumed` carry the bot's user id as `user_id`;
`approval_consumed` carries Sam in `actor` and in `meta.owner`, plus the thread and the reason
(`test/worker-authorization.test.ts`).

Shots: the worker terminal, the channel message naming the bot, Jo's Connect line, Sam's receipt, the issue.

### (k) Offboarding

You, as workspace admin: deactivate Alex (Slack admin, Manage members, Deactivate account). Slack
sends `user_change` with `deleted: true`; the app removes Alex's own connections and revokes the
GitHub token upstream (`src/adapters/bolt.ts`, `src/core/offboard.ts`).

Show: `vouchr inventory` no longer lists Alex's `github` row. The channel's `github-team` row
stays: it belongs to the channel. `psql -d vouchr -c "select action, provider, meta from audit order by at desc limit 3"`
shows a `revoke` row with `"reason":"offboarded"`.

The fence: if Alex asked for a write just before being deactivated, the request went with the
credential. Any click on the leftover prompt, say Sam's, answers (`src/adapters/bolt.ts`):

> This approval expired or was already decided. Ask the agent again.

Nothing is granted (`test/demo.test.ts`, "(k) offboarding fences a pending prompt").

The SCIM example (`examples/scim`) does the same from a directory event but ships no runnable
endpoint, so it is not recorded. Reactivate Alex afterwards.

Shots: the inventory before and after, Sam's refusal.

### (l) Slack Connect

Vouchr refuses channel credentials in externally shared channels, with one message everywhere
(`src/core/channelConfig.ts`, `channelIneligibleReason`):

> Channel credentials are not allowed in externally shared channels.

Showing it needs a second workspace and a Slack Connect channel. If you have one, run
`/vouchr connect-shared github-team` there and screenshot the refusal in the modal; `/vouchr identity`
and `/vouchr enable` answer the same line, and a write that needs a teammate's approval is refused
with it instead of posting a prompt. A write as Alex with Alex's own token still prompts Alex
privately there: nothing of it reaches the channel (`test/demo.test.ts`, "(l) Slack Connect").
Otherwise say so on camera.

### (m) The operator CLI

On the laptop, with `VOUCHR_DATABASE_URL` and `VOUCHR_MASTER_KEY` exported. See [CLI.md](./CLI.md).

```bash
npm run cli -- inventory                                  # every live credential, no secrets
npm run cli -- channels --team T...                       # provider, identity, enabled per channel
npm run cli -- revoke --provider github-team --channel C... # dry run
npm run cli -- revoke --provider github-team --channel C... --yes
npm run cli -- doctor
```

`channels` prints `team  channel  provider  identity  enabled` with `person` or `channel` per row.
The dry run ends with `No changes made. Re-run with --yes to revoke.` The real run prints
`Revoked 1 locally; 0 matching connection(s) remain.` and an `Upstream revoke:` line with attempted,
failed, unresolved, and skipped counts. `doctor` prints `PASS`/`FAIL`/`INFO` lines. Shots: each output.

## 4. Talk track

Vouchr is a self-hosted identity broker for agents: per-person credentials injected at egress,
human-in-the-loop approvals, and an audit trail for every call. The agent acts as the person who
asked, with that person's own access, or as the channel with a credential the team owns. Writes wait
for a human by default: acting as you, you confirm each one; acting as the channel, a teammate
approves. Every prompt says who asked, what, and why.
Every action is on record: who, what, where, and who approved.

Here is the order. A channel starts closed: the agent is refused. Sam opens it. Alex connects once,
through Slack sign-in and GitHub consent. A read runs as Alex. A write stops: Alex sees the
provider, the method, the path, and the agent's reason, confirms, the write runs once, and the next
one asks again. Alex denies one. Then a shared team token the channel owns: the team sees who asked
and what, Alex cannot approve Alex, Sam approves, and one approval covers a whole thread. Jo is outside and sees nothing; a
public channel is the tradeoff. A worker with no human asks the same channel the same way. Alex
leaves and the credential goes with them. The CLI shows every live credential and can revoke any of
them.

## 5. Reset in five minutes

1. Stop the app, the broker, and the worker.
2. `dropdb vouchr && createdb -O vouchr vouchr`, then the `migrate` command from the checklist.
   This clears connections, channel identities, approvals, and the audit table.
3. GitHub: Alex opens Settings, Applications, Authorized OAuth Apps, and revokes `Vouchr demo`, so
   the consent screen appears again on camera.
4. Slack: nothing to clear. The bot token in `.env` stays valid and the app stores no installation
   of its own in this setup. Reactivate Alex if (k) ran.
5. `npm run example:demo`, then the two-minute smoke test.
