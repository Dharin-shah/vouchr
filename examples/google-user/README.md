# Google as the user

The agent acts **as the mentioning user** on a Google API. When a user hasn't
connected yet, `connect('google')` posts an ephemeral Connect button and throws
`ConsentRequiredError`; after they finish the browser OAuth, the next mention
works.

```ts
const vouchr = await createVouchr({
  providers: [google()],
  baseUrl: process.env.PUBLIC_URL!,
});
```

## OAuth setup

Create an OAuth client in the [Google Cloud console](https://console.cloud.google.com/apis/credentials)
and set:

- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- Authorized redirect URI: `${PUBLIC_URL}/vouchr/oauth/callback`

The built-in `google()` provider already requests `openid email
https://www.googleapis.com/auth/userinfo.profile`. To call other Google APIs,
pass the scopes you need (the OAuth consent screen must list them):

```ts
google({ scopes: ['openid', 'email', 'https://www.googleapis.com/auth/gmail.readonly'] })
```

Egress for `google()` is allowlisted to `www.googleapis.com`,
`gmail.googleapis.com`, and `people.googleapis.com`. A `fetch` to any other host
is blocked at the injection boundary.

## Refresh tokens

`google()` sets `access_type=offline` + `prompt=consent` and `refresh:
'rotating'`, so Google issues a refresh token and Vouchr renews the short-lived
access token on demand (and on a 401). It also uses **PKCE** on the authorize +
token exchange. Nothing to configure: it just keeps working past the ~1h access
token expiry.

## Env

```
SLACK_SIGNING_SECRET=...
SLACK_BOT_TOKEN=xoxb-...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
PUBLIC_URL=https://abc.ngrok.io
VOUCHR_MASTER_KEY=$(openssl rand -base64 32)
```
