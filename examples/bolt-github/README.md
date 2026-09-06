# GitHub as the user (the flagship demo)

A ~35-line Bolt app that answers an `@vouchr who am I on github?` mention with the mentioning
user's **own** GitHub identity. The handler calls `gh.fetch('https://api.github.com/user')` and
never sees the token — Vouchr injects it at the HTTP boundary.

It requests `read:user` only, not the broad `repo` scope `github()` defaults to, so the Connect
prompt shows just "Read your profile".

## Setup

[QUICKSTART.md](../../QUICKSTART.md) is the full zero-to-running walkthrough: Slack workspace + app
(from [`slack-manifest.bootstrap.yml`](../slack-manifest.bootstrap.yml)), a GitHub OAuth app with
callback `${PUBLIC_URL}/vouchr/oauth/callback`, PostgreSQL, and the tunnel. Then, with `.env` filled
in:

```bash
VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr npm run cli -- migrate   # once; the running app never creates tables, and the CLI does not read .env
npm run example:github
```

## What you should see

Invite the bot (`/invite @vouchr`), then enable the provider once — channels are deny-by-default:
`/vouchr enable github`. Mention it and Vouchr posts a **private** Connect prompt; after the browser
OAuth, mention it again and the bot replies in-thread:

```
You are *yourlogin* on GitHub, 42 public repos.
```

No token appears in the channel, the thread, or the terminal. `/vouchr status` lists the connection
and `/vouchr disconnect github` revokes it.

## Env

```
SLACK_SIGNING_SECRET=...
SLACK_BOT_TOKEN=xoxb-...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
PUBLIC_URL=https://abc.ngrok.io
VOUCHR_DATABASE_URL=postgres://vouchr:vouchr@localhost:5432/vouchr
VOUCHR_MASTER_KEY=$(openssl rand -base64 32)
```
