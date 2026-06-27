# Internal API via a per-user key

Not every backend speaks OAuth. A **key provider** lets each user supply their
own static API key for an internal service; Vouchr stores it encrypted and
injects it at the HTTP boundary so the agent (and the LLM) never sees it.

```ts
const internal = defineProvider({
  id: 'internal',
  credential: 'key',                 // no OAuth — user pastes a key
  authorizeUrl: '', tokenUrl: '',    // unused for key providers
  scopesDefault: [],
  egressAllow: ['api.internal.example'],
  inject: (h, k) => h.set('x-api-key', k),  // non-Bearer header
  refresh: 'none',
  pkce: false,
});
```

## Flow

1. A user @-mentions the bot. The handler calls `connect('internal')`.
2. They have no key yet, so Vouchr posts an **ephemeral "set up your key" button**
   (wired by `registerCommands`) and throws `ConsentRequiredError` — the handler
   stops this turn.
3. The user clicks the button and pastes their key into a **private modal**. The
   key never appears in the channel, the audit log, or any error string.
4. On the next mention, `connect('internal')` returns a handle and the agent
   calls the internal API with the key injected as `x-api-key`.

Users can also paste an **external secret-manager reference** instead of a raw
key in the same modal (resolved just-in-time via a `resolvers` entry — see
`../aws-secrets-manager`).

## Env

```
SLACK_SIGNING_SECRET=...
SLACK_BOT_TOKEN=xoxb-...
PUBLIC_URL=https://abc.ngrok.io
VOUCHR_MASTER_KEY=$(openssl rand -base64 32)
```

`PUBLIC_URL` is still needed for the mounted callback route even though key
providers don't use OAuth.
