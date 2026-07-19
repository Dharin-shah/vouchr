# Quickstart — Vouchr in ~5 minutes (with a demo script for recording)

This takes you from **nothing** to a working Slack bot that acts as *you* on GitHub — connecting
your account once through a private OAuth prompt, then answering `You are *yourlogin*, N public
repos` — with the GitHub token **never** touching the bot code, the Slack transcript, or the logs.

It doubles as a **video script**: the [Record the demo](#7-record-the-demo-the-money-shot) section
is the exact on-screen sequence.

> New to the project? Do the [30-second sanity check](#0-30-second-sanity-check-no-accounts-needed)
> first — it proves the core works with zero Slack/OAuth setup.

---

## What you'll need (~10 min of account setup, one-time)

| Thing | Why | Cost |
| --- | --- | --- |
| **Node ≥ 22** | runtime (`nvm install 22`) | free |
| **PostgreSQL** | the only datastore Vouchr uses | free (Docker or Homebrew) |
| **A public HTTPS tunnel** | Slack + GitHub call back to your laptop | free (ngrok / cloudflared) |
| **A throwaway Slack workspace** | you need to be admin to install the app | free |
| **A GitHub account** | the provider we connect in the demo | free |

> **Use a brand-new, throwaway Slack workspace — not your company's.** You want admin rights and no
> risk of pinging colleagues while you test.

---

## 0. 30-second sanity check (no accounts needed)

Confirms the real consent → policy → egress → vault → audit machinery works, with every network edge
stubbed. Only needs local PostgreSQL.

```bash
npm install
VOUCHR_TEST_PG_URL=postgres://vouchr:vouchr@localhost:5432/vouchr npm run example:dry-run
```

Green ⇒ the core is sound; now wire up the real Slack demo below.

---

## 1. PostgreSQL

**Option A — Docker (portable):**

```bash
docker run --name vouchr-pg -e POSTGRES_USER=vouchr -e POSTGRES_PASSWORD=vouchr \
  -e POSTGRES_DB=vouchr -p 5432:5432 -d postgres:16
```

**Option B — Homebrew (macOS):**

```bash
brew install postgresql@16 && brew services start postgresql@16
createuser -s vouchr 2>/dev/null; createdb -O vouchr vouchr 2>/dev/null
psql -d vouchr -c "ALTER USER vouchr PASSWORD 'vouchr';"
```

Either way your connection string is:

```
postgres://vouchr:vouchr@localhost:5432/vouchr
```

---

## 2. Start the tunnel FIRST (everything below bakes its URL in)

Slack and GitHub both call back to your laptop, so you need a public HTTPS URL. Start it **before**
creating the apps, because the URL goes into three places.

**ngrok** (use a [free static domain](https://dashboard.ngrok.com/domains) so the URL survives
restarts — this saves you re-editing three configs between recording takes):

```bash
ngrok http 3000 --domain your-name.ngrok-free.app     # or plain: ngrok http 3000
```

**cloudflared** (no signup for a quick tunnel):

```bash
cloudflared tunnel --url http://localhost:3000
```

Copy the `https://…` URL it prints. Call it **`PUBLIC_URL`** from here on.

> ⚠️ ngrok's free **interstitial page** can break Slack's URL verification and the OAuth redirect.
> A static ngrok domain or a cloudflared tunnel avoids it.

---

## 3. Create a Slack workspace + app

1. **New workspace:** go to <https://slack.com/get-started> → *Create a workspace*. Name it (e.g.
   "Vouchr Demo"), skip inviting people, and create a channel like `#demo`.
2. **New app from the manifest:** <https://api.slack.com/apps> → **Create New App** → **From a
   manifest** → pick your new workspace.
3. Paste the contents of [`examples/slack-manifest.yml`](./examples/slack-manifest.yml), then
   **replace every `YOUR_PUBLIC_URL`** with your tunnel host (the part after `https://`). There are
   three: the slash command URL, the event `request_url`, and the interactivity `request_url` — all
   `https://YOUR_PUBLIC_URL/slack/events`.
4. **Create** → on the app's **Install App** page, **Install to Workspace** → **Allow**.
5. Grab two secrets:
   - **Install App** page → **Bot User OAuth Token** (`xoxb-…`) → this is `SLACK_BOT_TOKEN`.
   - **Basic Information** → **Signing Secret** → this is `SLACK_SIGNING_SECRET`.

The manifest already wires the `/vouchr` command, the `app_mention` / `app_home_opened` /
`user_change` events, interactivity (the Connect button + modals), and the minimal bot scopes —
you don't configure any of that by hand.

---

## 4. Create a GitHub OAuth App

1. <https://github.com/settings/developers> → **OAuth Apps** → **New OAuth App**.
2. Fill in:
   - **Application name:** `Vouchr demo`
   - **Homepage URL:** your `PUBLIC_URL`
   - **Authorization callback URL:** `PUBLIC_URL/vouchr/oauth/callback` **(exact — this is the
     Vouchr callback path, not `/slack/events`)**
3. **Register application** → copy the **Client ID** (`GITHUB_CLIENT_ID`) → **Generate a new client
   secret** → copy it (`GITHUB_CLIENT_SECRET`).

> GitHub OAuth apps don't pre-declare scopes; Vouchr requests them at authorize time, so the consent
> screen will show exactly what the demo asks for.

---

## 5. Configure `.env`

```bash
cp .env.example .env
```

Fill in these (leave `VOUCHR_IDENTITY_SECRET` / `VOUCHR_DEPLOYMENT_ID` blank — those are only for the
headless broker, which this Bolt demo doesn't use):

```dotenv
VOUCHR_MASTER_KEY=            # openssl rand -base64 32
VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr

SLACK_BOT_TOKEN=xoxb-...      # from step 3
SLACK_SIGNING_SECRET=...      # from step 3

PUBLIC_URL=https://your-tunnel-host   # from step 2, NO trailing slash
PORT=3000

GITHUB_CLIENT_ID=...          # from step 4
GITHUB_CLIENT_SECRET=...      # from step 4
```

Generate the master key inline if you like:

```bash
printf 'VOUCHR_MASTER_KEY=%s\n' "$(openssl rand -base64 32)" >> .env
```

---

## 6. Migrate the database and start the bot

```bash
npm install
npm run cli -- migrate          # creates the schema once (runtime is DML-only, never creates tables)
npm run example:github
```

You should see:

```
⚡ Vouchr GitHub demo on :3000. Callback at https://your-tunnel-host/vouchr/oauth/callback
```

Keep this terminal visible in the recording — it proves the token never appears in your logs.

---

## 7. Record the demo (the money shot)

In your Slack workspace, `#demo` channel:

1. **Invite the bot to the channel** once: `/invite @vouchr`.
2. **Mention it:** `@vouchr who am I on github?` (any text works — the mention is the trigger).
   → Vouchr posts a **private** *"Connect your GitHub account"* message with a **Connect** button.
   *Narrate: only you can see this — it's an ephemeral, not a channel post.*
3. **Click Connect** → your browser opens GitHub's authorize screen → **Authorize** → you land on a
   plain *"You're connected"* page.
4. **Mention it again:** `@vouchr who am I on github?`
   → In-thread reply: **`You are *yourlogin* on GitHub, N public repos.`**
5. **Land the point** (this is the whole pitch): the bot code just ran
   `gh.fetch('https://api.github.com/user')` — it **never saw the token**. Cut to the terminal to
   show there's no token in the logs. Optionally run `/vouchr status` to show the managed connection,
   and `/vouchr disconnect github` to show one-click revocation.

**Recording tips**
- Pre-connect once to shake out setup bugs, then `/vouchr disconnect github` right before you hit
  record so you capture the *first-connect* flow cleanly.
- Split-screen Slack + the terminal — the "no token in logs" reveal is the strongest visual.
- A static tunnel domain keeps the callback URL stable across takes.

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Slack "Your URL didn't respond" when saving the manifest | The app must be **running on :3000 through the tunnel** before Slack verifies. Start `npm run example:github` and the tunnel first, then create/verify the app. Avoid ngrok's interstitial (static domain / cloudflared). |
| GitHub `redirect_uri mismatch` | The callback must be **exactly** `PUBLIC_URL/vouchr/oauth/callback`, same scheme/host, no trailing slash. |
| Bot ignores your `@mention` | `/invite @vouchr` into the channel; confirm the `app_mention` event is in the manifest and the process is running. |
| Boot fails on the database | Run `npm run cli -- migrate` first; check `VOUCHR_DATABASE_URL` points at a reachable Postgres (Vouchr fails closed if it's unset or non-`postgres://`). |
| `role "vouchr" does not exist` | Create the role/db (step 1 Option B) or point the URL at an existing one. |
| Connect prompt never returns / callback 404 | `PUBLIC_URL` in `.env` must match the tunnel and the GitHub callback exactly, and the tunnel must forward to `:3000`. |

---

Next: the [deployment guide](./guides/DEPLOYMENT.md) covers Slack scopes, KMS envelope encryption,
Kubernetes, and the production runbooks. The [security model](./SECURITY.md) and
[threat model](./guides/THREAT-MODEL.md) cover what Vouchr does — and does not — protect against.
