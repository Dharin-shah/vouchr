# Quickstart

This guide takes you from nothing to a Slack bot that acts as you on GitHub. You connect your
account once through a private prompt in Slack. The bot then answers `You are *yourlogin*, N public
repos`. The GitHub token never touches the bot code, the Slack transcript, or the logs.

Plan on about ten minutes to set up the Slack and GitHub apps, then a few minutes to run.

> New to the project? Do the [sanity check](#1-sanity-check-no-accounts-needed) first. It proves
> the core works with no Slack or OAuth setup.

## What you need

| Thing | Why | Cost |
| --- | --- | --- |
| **Node 22 or newer** | runtime (`nvm install 22`) | free |
| **PostgreSQL** | the only datastore Vouchr uses | free (Docker or Homebrew) |
| **A public HTTPS tunnel** | Slack and GitHub call back to your laptop | free (ngrok or cloudflared) |
| **A throwaway Slack workspace** | you must be a workspace admin to install the app | free |
| **A GitHub account** | the provider this guide connects | free |

> Use a new, throwaway Slack workspace, not your company's. You get admin rights and no risk of
> pinging colleagues while you test.

## 0. Clone the repo

```bash
git clone https://github.com/Dharin-shah/vouchr.git
cd vouchr
```

Every command below runs from this directory.

## 1. Sanity check (no accounts needed)

This runs the real consent, policy, egress, vault, and audit code with every network edge stubbed.
It needs a local PostgreSQL. `npm run pg:up` starts a throwaway `postgres:16-alpine` in Docker on
`localhost:5432` with database, user, and password all set to `vouchr`.

```bash
npm install
npm run pg:up            # Docker; skip if you already have Postgres on :5432 (see step 2)
npm run example:dry-run
```

If the tests pass, the core works. Now wire up the real Slack demo.

## 2. PostgreSQL

If you have Docker, step 1's `npm run pg:up` is all you need. It is the container the rest of this
guide assumes. `npm run pg:down` removes it along with everything in it.

Prefer Homebrew on macOS?

```bash
brew install postgresql@16 && brew services start postgresql@16
createuser -s vouchr 2>/dev/null; createdb -O vouchr vouchr 2>/dev/null
psql -d vouchr -c "ALTER USER vouchr PASSWORD 'vouchr';"
```

Either way your connection string is:

```
postgres://vouchr:vouchr@localhost:5432/vouchr
```

## 3. Start the tunnel first

Slack and GitHub both call back to your laptop, so you need a public HTTPS URL. Start the tunnel
before you create the apps, because the URL goes into three places.

ngrok. A [free static domain](https://dashboard.ngrok.com/domains) keeps the URL stable across
restarts, so you do not have to edit three configs again:

```bash
ngrok http 3000 --domain your-name.ngrok-free.app     # or plain: ngrok http 3000
```

cloudflared, no signup needed for a quick tunnel:

```bash
cloudflared tunnel --url http://localhost:3000
```

Copy the `https://` URL it prints. This guide calls it `PUBLIC_URL` from here on.

> ngrok's free tier shows an interstitial page that can break Slack's URL verification and the OAuth
> redirect. A static ngrok domain or a cloudflared tunnel avoids it.

## 4. Create a Slack workspace and app

Use the bootstrap manifest.

1. New workspace: go to <https://slack.com/get-started> and choose *Create a workspace*. Name it
   (for example "Vouchr Demo"), skip inviting people, and create a channel like `#demo`.
2. New app from a manifest: go to <https://api.slack.com/apps>, click **Create New App**, choose
   **From a manifest**, and pick your new workspace.
3. Paste the contents of
   [`examples/slack-manifest.bootstrap.yml`](./examples/slack-manifest.bootstrap.yml), not
   `slack-manifest.yml`. Replace `YOUR_PUBLIC_URL` in the one redirect URL with your tunnel host
   from step 3 (host only, no `https://`, no trailing slash). The bootstrap file carries no request
   URLs on purpose. Slack checks a request URL the moment you submit the manifest, and your app
   cannot answer until it runs with the signing secret this step gives you. You add the URLs in
   [step 8](#8-finish-the-slack-app-the-three-urls), against a live server.
4. Click **Create**. On the app's **Install App** page, click **Install to Workspace**, then
   **Allow**.
5. Copy four values:
   - **Install App** page, **Bot User OAuth Token** (`xoxb-...`). This is `SLACK_BOT_TOKEN`.
   - **Basic Information**, **Signing Secret**. This is `SLACK_SIGNING_SECRET`.
   - **Basic Information**, **Client ID** and **Client Secret**. These are
     `VOUCHR_SLACK_CLIENT_ID` and `VOUCHR_SLACK_CLIENT_SECRET`. Vouchr uses them to check, on every
     Connect link, that the browser is signed in to Slack as the person who asked.

The manifest already sets up the `/vouchr` command, the `app_mention`, `app_home_opened`, and
`user_change` events, the App Home tab, the Slack sign-in redirect URL
(`PUBLIC_URL/vouchr/oauth/slack`), and the minimal bot scopes. The only things left to do by hand
are the three URLs in step 8.

## 5. Create a GitHub OAuth App

1. Go to <https://github.com/settings/developers>, open **OAuth Apps**, and click **New OAuth App**.
2. Fill in:
   - **Application name:** `Vouchr demo`
   - **Homepage URL:** your `PUBLIC_URL`
   - **Authorization callback URL:** `PUBLIC_URL/vouchr/oauth/callback`. This must be exact. It is
     the Vouchr callback path, not `/slack/events`.
3. Click **Register application**. Copy the **Client ID** (`GITHUB_CLIENT_ID`). Click
   **Generate a new client secret** and copy it (`GITHUB_CLIENT_SECRET`).

> GitHub OAuth apps do not declare scopes up front. Vouchr requests them when it sends you to
> authorize, so the consent screen shows exactly what the demo asks for.

## 6. Configure `.env`

```bash
cp .env.example .env
```

Fill in these. Leave `VOUCHR_IDENTITY_SECRET` and `VOUCHR_DEPLOYMENT_ID` blank. They are only for
the headless broker, which this demo does not use.

```dotenv
VOUCHR_MASTER_KEY=            # openssl rand -base64 32
VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr

SLACK_BOT_TOKEN=xoxb-...      # from step 4
SLACK_SIGNING_SECRET=...      # from step 4
VOUCHR_SLACK_CLIENT_ID=...    # from step 4
VOUCHR_SLACK_CLIENT_SECRET=...  # from step 4

PUBLIC_URL=https://your-tunnel-host   # from step 3, no trailing slash
PORT=3000

GITHUB_CLIENT_ID=...          # from step 5
GITHUB_CLIENT_SECRET=...      # from step 5
```

You can generate the master key in one line:

```bash
printf 'VOUCHR_MASTER_KEY=%s\n' "$(openssl rand -base64 32)" >> .env
```

## 7. Migrate the database and start the bot

The CLI does not read `.env`, so pass the database URL on the command line.

```bash
npm install
# Creates the schema once. The running app never creates tables.
VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr npm run cli -- migrate
npm run example:github
```

You should see:

```
⚡ Vouchr GitHub demo on :3000. Callback at https://your-tunnel-host/vouchr/oauth/callback
```

Keep this terminal visible. It shows that the token never appears in your logs.

## 8. Finish the Slack app (the three URLs)

Now that the tunnel and the app are running, Slack can verify a URL the moment you save it. All
three URLs are the same one. An `ExpressReceiver` serves events, interactivity, and commands on a
single path: `PUBLIC_URL/slack/events` (your tunnel URL from step 3, for example
`https://your-name.ngrok-free.app/slack/events`).

Back on <https://api.slack.com/apps>, open your app:

1. **Event Subscriptions**: turn **Enable Events** on, paste the URL into **Request URL**, wait for
   the green **Verified**, then **Save Changes**. The three bot events are already listed from the
   manifest.
2. **Interactivity & Shortcuts**: turn it on, paste the same URL, then **Save Changes**. The Connect
   button and every modal depend on this.
3. **Slash Commands**: open `/vouchr`, click **Edit**, paste the same URL, then **Save**.

If Slack asks you to reinstall the app afterwards, do it. The bot token does not change.
[`examples/slack-manifest.yml`](./examples/slack-manifest.yml) shows what the finished app looks like.

## 9. Try it

In your Slack workspace, in the `#demo` channel:

1. Invite the bot to the channel once: `/invite @vouchr`.
2. Enable GitHub in the channel once. Channels are deny-by-default, so any member of the channel
   runs `/vouchr enable github` in `#demo`. Without it the first mention gets a private
   *"This provider is disabled in the channel. Any member can run `/vouchr enable` there."* A
   direct message needs no enable. DMs are personal, not governed.
3. Mention the bot: `@vouchr who am I on github?` (any text works, the mention is the trigger).
   Vouchr posts a private *"Connect your GitHub account"* message with a **Connect** button. Only
   you can see it. It is an ephemeral message, not a channel post.
4. Click **Connect**. Your browser first passes through a Slack sign-in check (Slack confirms you
   are the person who asked, then sends you on), then opens GitHub's authorize screen. Click
   **Authorize**. You land on a plain *"github connected"* page that names the Slack user it is
   linked to. Back in Slack the prompt has replaced itself with a one-line note. A prompt is valid
   for ten minutes; clicking an older one replaces it with a **Send a new link** button, so you
   never have to mention the bot again just to get a fresh link.
5. Mention the bot again: `@vouchr who am I on github?` The in-thread reply is
   **`You are *yourlogin* on GitHub, N public repos.`**
6. This is the point of Vouchr. The bot code ran `gh.fetch('https://api.github.com/user')` and never
   saw the token. Look at the terminal: there is no token in the logs. You can also run
   `/vouchr status` to see the managed connection, and `/vouchr disconnect github` to revoke it.
7. Writes ask by default. Any call other than GET or HEAD posts an Approve/Deny prompt before the
   call goes out: to you privately when the agent acts as you, to the channel for a teammate when it
   acts as the channel. Reads go straight through.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Slack says "Your URL didn't respond" when saving a Request URL | Slack calls the URL as you save it, so the app must already be up. Check that `npm run example:github` is running and that the tunnel forwards to `:3000`. If you hit this while *creating* the app, you pasted `slack-manifest.yml`. Create the app from `slack-manifest.bootstrap.yml` (step 4) and add the URLs in step 8 instead. Avoid ngrok's interstitial page (use a static domain or cloudflared). |
| GitHub `redirect_uri mismatch` | The callback must be exactly `PUBLIC_URL/vouchr/oauth/callback`: same scheme and host, no trailing slash. |
| Slack shows an error before GitHub opens | The app's OAuth redirect URL must be exactly `PUBLIC_URL/vouchr/oauth/slack`, and `VOUCHR_SLACK_CLIENT_ID` / `VOUCHR_SLACK_CLIENT_SECRET` must be that app's credentials. |
| Bot ignores your `@mention` | Run `/invite @vouchr` in the channel. Confirm the `app_mention` event is in the manifest and the process is running. |
| Boot fails on the database | Run the migrate command from step 7 first. Check that `VOUCHR_DATABASE_URL` points at a reachable Postgres. Vouchr fails closed if it is unset or not a `postgres://` URL. |
| `role "vouchr" does not exist` | Create the role and database (step 2, Homebrew) or point the URL at an existing one. |
| Connect prompt never returns, or the callback returns 404 | `PUBLIC_URL` in `.env` must match the tunnel and the GitHub callback exactly, and the tunnel must forward to `:3000`. |

Next: the [deployment guide](./guides/DEPLOYMENT.md) covers Slack scopes, KMS envelope encryption,
Kubernetes, and the production runbooks. The [security model](./SECURITY.md) and
[threat model](./guides/THREAT-MODEL.md) cover what Vouchr does and does not protect against.
