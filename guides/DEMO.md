# Demo run-through

A script for one recorded session: the maintainer, two or three friends, one Slack workspace, every
product scenario. Each scenario says who does what, the exact copy Slack shows (quoted from the
code, with the file it comes from), what the audit shows afterwards, and what to capture.

The app is [`examples/demo/app.ts`](../examples/demo/app.ts): the quickstart app plus one write
that waits for a teammate and one shared credential. Slack copy is rendered by
`src/adapters/blocks.ts` and `src/adapters/bolt.ts`; refusal copy is in `src/core/errors.ts` and
`src/core/channelConfig.ts`. `<#C…>` is Slack's channel link, `<@U…>` a user mention.

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
  below), and a personal access token that can open issues in it: the shared credential in (h).
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
   # prints: OK schema migrated to version 1
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

- `github` with `approval: { approver: 'member', methods: ['POST', 'PUT', 'PATCH', 'DELETE'], paths: ['/repos/'] }`.
- `github-team`, a key provider in the style of `examples/internal-api-key`, for the channel's
  shared token. Same approval rule. The default injection is `Authorization: Bearer <key>`.
- `@vouchr who am I` runs `GET /user`. Any other text does the same.
- `@vouchr open an issue titled <title> in repo <owner>/<name>` runs `POST /repos/<owner>/<name>/issues`
  as the person who asked.
- `@vouchr open a team issue titled <title> in repo <owner>/<name>` does the same write with the
  channel's `github-team` credential.
- Replies come in a thread under the mention. `examples/demo/worker.ts` is the headless job for (j).

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

On the laptop `VOUCHR_DATABASE_URL=... npm run cli -- channels` shows the row with enabled `yes`.
Audit: a `config` row. Shots: the reply and the `channels` output.

### (c) Alex connects

Alex, in `#demo-team`: `@vouchr who am I`.

Expected, private to Alex (`src/adapters/blocks.ts`, `connectBlocks`):

> :link: *Connect your github account*
> I need to act as you on github for this. Your token is stored encrypted on this server and is never shown to the agent or posted in Slack.
> Connecting grants the agent, acting as you:
> • Read your profile
> • Read and write your repositories

with a **Connect github** button. Alex clicks it. The browser goes to Slack's sign-in page first
(Slack's own screen), then to GitHub's authorize screen, then lands on Vouchr's page
(`src/adapters/landing.ts`):

> ✅ github connected as alex
> This connection is now linked to this Slack user (`U…` in workspace `T…`). The agent will act as that Slack user with: `<granted scopes>`.
> You can close this tab.

Back in Slack, Alex gets a DM and a private note in the channel, both
`✅ github connected as alex.` (`src/adapters/blocks.ts`, `connectedDmText`).

`/vouchr status` from Alex lists the github connection with the account name. Audit: a `connect` row. `vouchr inventory` shows one row, `owner_kind` user.

Shots: the Connect prompt, the Slack sign-in page, the GitHub consent screen, the landing page, the DM.

### (d) A read runs as Alex

Alex: `@vouchr who am I`.

Expected, in a thread: `You are *alex* on GitHub, N public repos.`

The terminal shows no token. `/vouchr audit` from Alex shows `• *github* · inject · <#demo-team> · <time>`.

Shots: the reply and the terminal side by side.

### (e) A write waits for the team

Alex: `@vouchr open an issue titled Demo issue in repo alex/vouchr-demo`.

Nothing is sent. The channel gets one message (`src/adapters/blocks.ts`, `approvalBlocks`):

> :lock: *Approve this github action?*
> The agent wants to run an action on github for <@alex>. Another member of this channel must approve it.
> POST api.github.com
> Action fingerprint: <hash>
> The fingerprint binds the exact owner, method, endpoint, and query string — once — and expires if unused. The raw path and request body are not displayed or inspected.

with **Approve** and **Deny** buttons.

Alex clicks **Approve**. Private reply, the prompt stays (`src/adapters/bolt.ts`):

> You are not eligible to decide this approval.

Sam clicks **Approve**. The prompt is replaced by:

> ✅ Approved the *github* action. The approval is single-use and expires in 300s — have the agent retry now.

Alex gets a private note: `✅ <@sam> approved your *github* action — ask the agent to retry.`

Alex repeats the exact same mention. Reply: `Opened https://github.com/alex/vouchr-demo/issues/1 as *alex*.`

Alex repeats it once more. A new approval prompt appears. Approvals are single use
(`test/approval.test.ts`, "state machine: prompt → approve → consume exactly once → re-prompt").

Audit, in order: `approval_requested`, `denied` with `reason: 'not-approver'` for Alex's click,
`approved` with Sam as `actor`, `approval_consumed` with Sam as `actor`, `inject`.
`/vouchr audit channel` shows the same rows with `by <@sam>` on the approval rows.

Shots: the prompt, Alex's refusal, the approved message, the issue on GitHub, the second prompt.

### (f) Deny

Sam clicks **Deny** on the prompt left over from (e). The prompt is replaced by:

> 🚫 Denied the *github* action. Nothing was sent.

Alex gets `🚫 <@sam> denied your *github* action. Nothing was sent.`

The denial is kept in the table with `status = 'denied'` for ten minutes so a headless poller can
read it. It does not block: if Alex asks again, a new prompt appears
(`test/approval.test.ts`, "member approver: deny is retained (#296), ...").

Audit: `denied` with `reason: 'approval-denied'`. Shots: the denied message, Alex's note.

### (g) Session mode in a thread

Sam: `/vouchr mode github session`. Reply: `Set *github* to *session* in <#demo-team>.`

Alex, at the top level of the channel: `@vouchr who am I`. Private reply (`src/adapters/bolt.ts`):

> "github" needs a thread-scoped session; ask me inside a thread.

Alex replies in any thread: `@vouchr who am I`. Private prompt in the thread
(`src/adapters/blocks.ts`, `sessionApprovalBlocks`):

> :lock: *Allow github in this thread?*
> The agent will be able to act as you on github only inside this thread, until the session expires. This approval does not apply to any other thread or channel.

with an **Allow github here** button. Alex clicks it: `Approved *github* for this thread. Ask the agent again.`

Alex mentions again in the thread: the read runs. Alex mentions in a different thread: the prompt
appears again (`test/session.test.ts`, "after granting the thread, the same thread proceeds but other threads do not").

The time limit is eight hours by default, set with `sessionTtlMs` on `createVouchr`. It is not shown
in Slack. To show expiry on camera, add `sessionTtlMs: 2 * 60 * 1000` to `createVouchr` in
`examples/demo/app.ts`, restart, and mention again after two minutes: the prompt is back.

Reset: Sam runs `/vouchr mode github per-user`.

Audit: `session` rows with `event: 'request'` and `event: 'grant'` in `meta`.
Shots: the top-level refusal, the thread prompt, the approved reply.

### (h) A shared credential

Sam: `/vouchr mode github-team shared`. Reply: `Set *github-team* to *shared* in <#demo-team>.`

Sam: `/vouchr connect-shared github-team`. A modal titled **Channel credential** opens
(`src/adapters/blocks.ts`, `configureModal`):

> Set the *github-team* credential for this channel. Only you can see what you type here. It is never posted to the channel.

Sam pastes the team token into **Paste a key directly** and saves. A modal titled **Credential saved**
says `Saved the *github-team* credential for <#demo-team>.`

Alex: `@vouchr open a team issue titled Team issue in repo alex/vouchr-demo`. The approval prompt
appears as in (e), for `github-team`. Sam approves. Alex repeats the mention:
`Opened https://github.com/alex/vouchr-demo/issues/2 as *<token owner>*.`

Audit: `config` for the credential, then the approval rows. `/vouchr audit channel` lists them.
`vouchr inventory` now has a second row with `owner_kind` channel and `owner_id` the channel id.

Shots: the modal (blur the field), the saved message, the prompt, the issue opened by the token owner.

### (i) Jo, the outsider

Jo is not in `#demo-team`. Slack itself keeps the channel and every prompt in it out of Jo's sight,
so there is nothing for Jo to click. Screenshot Jo's sidebar without the channel.

The server-side gate is the same in every channel: only a current member may enable, set a mode,
connect a shared credential, or approve, and the requester may never approve their own request
(`test/channel-member.test.ts`, `test/approval.test.ts`). The refusal copy for a non-member on the
configure commands is (`src/adapters/bolt.ts`):

> Only a current member of this channel can change channel tools. If you are one, make sure Vouchr is in the channel and try again.

The public-channel tradeoff, from [THREAT-MODEL.md](./THREAT-MODEL.md):

> in a public channel every member can configure and approve, so teams should govern agents from channels whose membership they control.

Show it: Jo joins `#demo-public` and runs `/vouchr enable github`. Reply:
`Enabled *github* in <#demo-public>.` Anyone in the workspace can join a public channel, so anyone
can do this there. Then Jo runs `/vouchr disable github` and leaves.

Shots: Jo's sidebar, the enable reply in the public channel.

### (j) An autonomous worker

A job with no human requester asks the channel for approval over the broker and runs the write with
the `github-team` credential from (h). The broker is a second process on the same database. In a
second terminal:

```bash
export VOUCHR_MASTER_KEY=<same as .env>
export VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
export VOUCHR_SLACK_CLIENT_ID=<same as .env> VOUCHR_SLACK_CLIENT_SECRET=<same as .env>
export VOUCHR_IDENTITY_SECRET=$(openssl rand -base64 32)
export VOUCHR_DEPLOYMENT_ID=demo
export VOUCHR_BASE_URL=http://localhost:3001     # the broker's connect routes are not used here
export VOUCHR_PORT=3001 VOUCHR_ALLOW_WRITES=1
export VOUCHR_PROVIDERS='[{"id":"github-team","credential":"key","egressAllow":["api.github.com"],"approval":{"approver":"member","methods":["POST","PUT","PATCH","DELETE"],"paths":["/repos/"]}}]'
npm run broker
```

In a third terminal, with the same `VOUCHR_IDENTITY_SECRET` and `VOUCHR_DEPLOYMENT_ID` exported:

```bash
DEMO_TEAM=T... DEMO_BOT_USER=U... DEMO_CHANNEL=C... DEMO_REPO=alex/vouchr-demo \
  node --import tsx examples/demo/worker.ts
```

The worker mints an identity for the bot user bound to `#demo-team`, calls `POST /v1/authorization`,
prints `authorization 200 { authorizationId: '…', status: 'pending', expiresAt: … }`, then
`poll pending` every five seconds. Within fifteen seconds the Slack app delivers the prompt to `#demo-team`:

> :lock: *Approve this github-team action?*
> The agent wants to run an action on github-team for <@vouchr>. Another member of this channel must approve it.
> POST api.github.com
> Action fingerprint: <hash>
> Agent's statement: TICKET-42: open the release checklist issue

Sam approves. The worker prints `poll approved`, sends `POST /v1/fetch` with the same claims, and
prints `fetch 200 { status: 201, url: 'https://github.com/alex/vouchr-demo/issues/3' }`.

Audit: `approval_requested` and `approval_consumed` carry the bot's user id as `user_id`;
`approval_consumed` carries Sam in `actor` (`test/authorization.test.ts`, "autonomous worker").

Shots: the worker terminal, the prompt naming the bot, the fetch line, the issue.

### (k) Offboarding

You, as workspace admin: deactivate Alex (Slack admin, Manage members, Deactivate account). Slack
sends `user_change` with `deleted: true`; the app removes Alex's own connections and revokes the
GitHub token upstream (`src/adapters/bolt.ts`, `src/core/offboard.ts`).

Show: `vouchr inventory` no longer lists Alex's `github` row. The channel's `github-team` row
stays: it belongs to the channel. `psql -d vouchr -c "select action, provider, meta from audit order by at desc limit 3"`
shows a `revoke` row with `"reason":"offboarded"`.

The fence: if Alex asked for a write just before being deactivated, the prompt is still in the
channel. Sam clicks **Approve**. Reply (`src/adapters/bolt.ts`):

> This approval is no longer valid because provider or channel access changed. Ask the agent again.

Nothing is granted (`test/approval.test.ts`, the offboard fence tests around "no longer valid").

The SCIM example (`examples/scim`) does the same from a directory event but ships no runnable
endpoint, so it is not recorded. Reactivate Alex afterwards.

Shots: the inventory before and after, Sam's refusal.

### (l) Slack Connect

Vouchr refuses channel credentials in externally shared channels
(`src/core/channelConfig.ts`, `channelIneligibleReason`):

> Channel credentials are not allowed in externally shared channels.

Showing it needs a second workspace and a Slack Connect channel. If you have one, run
`/vouchr connect-shared github-team` there and screenshot the refusal. Otherwise say so on camera
and point at `test/approval.test.ts`: "member approver: no prompt is posted into an externally
shared (Slack Connect) channel" and "member approver: a Slack Connect conversion after the prompt
invalidates it; a foreign-org member cannot approve".

### (m) The operator CLI

On the laptop, with `VOUCHR_DATABASE_URL` and `VOUCHR_MASTER_KEY` exported. See [CLI.md](./CLI.md).

```bash
npm run cli -- inventory                                  # every live credential, no secrets
npm run cli -- channels --team T...                       # provider, mode, enabled per channel
npm run cli -- revoke --provider github-team --channel C... # dry run
npm run cli -- revoke --provider github-team --channel C... --yes
npm run cli -- doctor
```

The dry run ends with `No changes made. Re-run with --yes to revoke.` The real run prints
`Revoked 1 locally; 0 matching connection(s) remain.` and an `Upstream revoke:` line with attempted,
failed, unresolved, and skipped counts. `doctor` prints `PASS`/`FAIL`/`INFO` lines. Shots: each output.

## 4. Talk track

Vouchr is a self-hosted identity broker for agents: per-user credentials injected at egress,
human-in-the-loop approvals scoped to the team's channel, and an audit trail for every call. The
agent acts as the person who asked, with that person's own access. Sensitive steps wait for the
team: the channel that owns the credential approves. Every action is on record: who, what, where,
and who approved.

Here is the order. A channel starts closed: the agent is refused. Sam opens it. Alex connects once,
through Slack sign-in and GitHub consent. A read runs as Alex. A write stops: the team sees who
asked, what provider, what method, what host. Alex cannot approve Alex. Sam approves, the write runs
once, and the next one asks again. Sam denies one. Then session mode: a thread, a time limit. Then
a shared team token that any member can approve. Jo is outside and sees nothing; a public channel
is the tradeoff. A worker with no human asks the same channel the same way. Alex leaves and the
credential goes with them. The CLI shows every live credential and can revoke any of them.

## 5. Reset in five minutes

1. Stop the app, the broker, and the worker.
2. `dropdb vouchr && createdb -O vouchr vouchr`, then the `migrate` command from the checklist.
   This clears connections, channel modes, approvals, sessions, and the audit table.
3. GitHub: Alex opens Settings, Applications, Authorized OAuth Apps, and revokes `Vouchr demo`, so
   the consent screen appears again on camera.
4. Slack: nothing to clear. The bot token in `.env` stays valid and the app stores no installation
   of its own in this setup. Reactivate Alex if (k) ran. Remove `sessionTtlMs` if you added it.
5. `npm run example:demo`, then the two-minute smoke test.
