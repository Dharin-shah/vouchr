# Python client (stdlib only)

`vouchr_client.py` is the worker half of [`examples/broker-client/client.ts`](../broker-client/client.ts)
in Python: it calls the packaged `vouchr-broker` over the HTTP contract in
[`guides/HEADLESS.md`](../../guides/HEADLESS.md) using only the standard library (`urllib`, `json`).
Nothing to install, nothing published.

What it is **not**: a minter. The identity signing key stays in your trusted Slack-facing service,
which mints one short-lived, single-use `identityToken` per broker call
([HYBRID.md section 4](../../guides/HYBRID.md#4-mint-identity-only-from-verified-slack-facts)).
The client takes a `mint` callable and asks it once per request and once per retry; the CLI reads
one token per line from stdin. A Python worker never needs the signing scheme, so it is deliberately
not reimplemented here.

## Run it

Start the broker as `examples/broker-client/client.ts` describes (same `VOUCHR_IDENTITY_SECRET`,
`VOUCHR_DEPLOYMENT_ID`, `VOUCHR_MASTER_KEY`, `VOUCHR_DATABASE_URL`, and Slack OIDC pair as the
control plane, plus `VOUCHR_BASE_URL`). Mint a
token on the TypeScript side and pipe it in:

```sh
# LOCAL DEVELOPMENT ONLY: minting next to the worker collapses the trust boundary (see client.ts).
mint() { node --import tsx -e "const { loadIdentityConfig, mintIdentity } = require('./src');
  console.log(mintIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1' }, loadIdentityConfig(process.env)))"; }

mint | python3 examples/python-client/vouchr_client.py http://localhost:3000 status
mint | python3 examples/python-client/vouchr_client.py http://localhost:3000 fetch github GET /user api.github.com
```

As a library:

```python
from vouchr_client import Vouchr, VouchrError

client = Vouchr("http://broker.internal:3000", mint=ask_the_trusted_minter)
try:
    r = client.fetch({"provider": "github", "owner": "user"}, "GET", "/user", host="api.github.com")
    print(r["status"], r["body"])
except VouchrError as e:
    if e.code == "not_connected":  # relay e.body to the Slack control plane's recoverBrokerDenial
        ...
```

## Errors

Every broker denial raises `VouchrError` with `status`, `code`, `retryable`, `recovery`,
`retry_after_ms`, `approval_id`, and the raw `body`. Branch on `code`; the meanings are in
HEADLESS.md's typed error table. Codes a worker sees: `not_connected`, `consent_required`,
`approval_required`, `approval_path_too_large`,
`interaction_state_changed`, `policy_denied`, `tool_disabled`, `egress_blocked`, `response_blocked`,
`resolver_configuration_error`, `resolver_failed`, `rate_limited`, `overloaded`,
`token_endpoint_failed`, `upstream_timeout`, `internal_error`, and the `invalid_reference` family.
`code` is `None` on prose-only validation errors (400/401/404/405). A retryable denial that carries
`retryAfterMs` (`rate_limited`, `overloaded`) is retried once with a fresh token after that delay;
nothing else is replayed automatically.

The `authorize` and `authorization` commands are the #296 backchannel: `POST /v1/authorization`
initiates a human decision for one exact action without executing it, and `GET /v1/authorization/{id}`
polls it (`pending`, `approved`, `denied`, `expired`; a spent or swept id is 404). See HEADLESS.md,
"Backchannel authorization for background agents".

Proven by `test/python-client.test.ts` against a real in-process broker (skipped when `python3` is
not on PATH).
