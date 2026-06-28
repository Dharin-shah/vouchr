# Vouchr Sidecar (reference implementation)

A minimal localhost HTTP **sidecar** that owns the Vouchr vault and exposes the credential broker
over a tiny HTTP contract, so agents written in **any language** (Python, Go, Rust, …) reuse the
exact same security (egress allowlist, https-only, encrypted vault, refresh-on-401, audit) without
re-implementing any of it.

This works because the Vouchr core is **transport-agnostic** (enforced by
`test/architecture.test.ts`): the core has no knowledge of Slack or Bolt. The Bolt adapter is one
front-end; this sidecar is another. Both drive the same `ConnectionHandle` over the same vault DB.

> This is a **minimal reference implementation**. It is intentionally placed under
> `examples/` so it is typechecked against the real `src/` exports. See
> [What a production sidecar adds](#what-a-production-sidecar-would-add).

## Why proxy instead of returning the token

**The sidecar never returns the credential.** `/proxy` builds a
`ConnectionHandle` for the owner+provider and calls `handle.fetch(url, init)` *inside* the sidecar.
The token is injected at the sidecar's egress and the caller gets back only the **provider's
response** (status + headers + body). This is the same leak-safe guarantee as the embedded handle:
the secret never crosses the vault boundary, so neither the calling app nor any LLM in the loop can
exfiltrate it. The egress allowlist and https-only checks live in `ConnectionHandle.fetch`, so they
apply here unchanged. A denied host never even reaches the vault read.

Returning the raw token to the caller would throw all of that away: the moment a token is in the
caller's process (or an LLM's context), it can leak. Proxying keeps the blast radius inside the
sidecar.

## Trust model (the honest boundary)

The sidecar is a **localhost component**. It authenticates the caller with a single shared bearer
token (`VOUCHR_SIDECAR_TOKEN`, constant-time compared). That proves "you are the app I trust",
nothing finer. The sidecar then **trusts the authenticated caller to assert the verified Slack
identity** in `owner`. The sidecar does **not** verify Slack itself; the caller is responsible for
having verified the Slack interaction before it ever calls `/proxy`.

This is the honest boundary: a localhost sidecar with a shared secret is a single trust domain with
its caller. If you need per-caller identity or to not trust the caller's `owner` assertion, that's a
production hardening (below), not something this reference pretends to do.

The `owner` (who OWNS the credential) and `acting` (the human who triggered the request, for audit)
are kept separate, exactly as in the core. For a **user** owner, `acting` defaults to the owner. For
a **channel** (shared) owner, the caller MUST supply `acting.userId` so a shared credential never
launders away who acted.

## Connect / consent stays in the Slack app

OAuth connect and consent are **not** in the sidecar and are not faked here. They need a browser and
a verified Slack interaction, which the embedded Bolt adapter owns. Connect once via Slack; the
credential lands in the shared vault DB; the sidecar then serves the **use path** (proxying calls
with the already-stored credential), which is the part other-language agents actually need.

## Running

```bash
# Same env the Slack app uses (so they share one vault DB):
export VOUCHR_MASTER_KEY=$(openssl rand -base64 32)   # must match the app's key
export VOUCHR_DB=vouchr.db                              # or VOUCHR_DATABASE_URL=postgres://...
export VOUCHR_SIDECAR_TOKEN=$(openssl rand -hex 32)    # shared bearer for trusted callers
# Provider OAuth client envs the app already sets, e.g. GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
# (built-ins without configured client env are simply not registered).

npx tsx examples/sidecar/server.ts            # listens on http://127.0.0.1:8787
npx tsx examples/sidecar/server.ts --selftest # runs the pure request-parsing self-check
```

## HTTP contract

All endpoints are `POST`, JSON in / JSON out, and require `Authorization: Bearer $VOUCHR_SIDECAR_TOKEN`.
Missing/wrong bearer → `401`. Bad input → `400`. Egress/no-connection/unknown-provider → `400` with
an `{ "error": "..." }` body.

`owner` is always `{ "teamId": string, "kind": "user" | "channel", "id": string }`.

### `POST /proxy`

Proxy an outbound provider call. The credential is injected at egress and is **never** in the response.

Request:
```json
{
  "owner":   { "teamId": "T123", "kind": "user", "id": "U123" },
  "provider": "github",
  "request": {
    "url": "https://api.github.com/user",
    "method": "GET",
    "headers": { "accept": "application/vnd.github+json" },
    "body": null
  },
  "acting": { "userId": "U123", "enterpriseId": null }
}
```
`acting` is optional for a user owner (defaults to the owner); required for a channel owner.

Response (the provider's own reply):
```json
{ "status": 200, "headers": { "content-type": "application/json" }, "body": "{\"login\":\"octocat\"}" }
```

### `POST /status`

List the owner's connected providers (no secrets). User owners only. The core `Vault` exposes
`listForUser()` and this reference does not invent SQL for channel listing.

Request: `{ "owner": { "teamId": "T123", "kind": "user", "id": "U123" } }`

Response:
```json
{ "providers": [ { "provider": "github", "externalAccount": "octocat" } ] }
```

### `POST /disconnect`

Delete the stored credential. Upstream OAuth revocation stays in the Slack app.

Request: `{ "owner": { ... }, "provider": "github" }` → Response: `{ "ok": true }`

## How a Python / Go client implements the same contract

There is no SDK to port. It's three POSTs. Any language replicates `examples/sidecar/client.ts`:

```python
import requests
class Sidecar:
    def __init__(self, base, token): self.base, self.h = base, {"authorization": f"Bearer {token}"}
    def proxy(self, owner, provider, request, acting=None):
        r = requests.post(f"{self.base}/proxy",
                          json={"owner": owner, "provider": provider, "request": request, "acting": acting},
                          headers=self.h)
        r.raise_for_status(); return r.json()   # {status, headers, body}, never a token
```

```go
body, _ := json.Marshal(map[string]any{"owner": owner, "provider": provider, "request": req})
httpReq, _ := http.NewRequest("POST", base+"/proxy", bytes.NewReader(body))
httpReq.Header.Set("authorization", "Bearer "+token)
// resp JSON: {status, headers, body}, the provider's reply, no credential
```

The contract is the seam: get the same broker guarantees by speaking HTTP, in any language.

## What a production sidecar would add

This reference deliberately stops at "correct and clear". A hardened sidecar would add:

- **Transport security beyond a shared bearer**: a Unix domain socket with filesystem permissions,
  or mTLS, instead of a loopback TCP port + shared token.
- **Per-caller identity**: distinct caller credentials (so you can attribute and revoke per caller)
  rather than one shared bearer for all trusted callers.
- **Request signing** of the `owner`/`acting` assertion, so the sidecar doesn't blindly trust the
  caller's identity claim.
- **Rate limiting / quotas** per caller and per owner+provider.
- **Body size limits, request timeouts, and binary-safe body handling** (this reference reads the
  provider body as text).
- **Channel-owner status** (needs a core `Vault` method to list channel-owned connections).
