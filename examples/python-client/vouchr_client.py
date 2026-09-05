"""Stdlib-only client for the Vouchr headless broker (guides/HEADLESS.md). Worker side ONLY.

It never holds the identity signing key. `mint` is a callable returning a fresh single-use
`identityToken` from your trusted Slack-facing minter (guides/HYBRID.md, section 4). The broker
consumes every assertion it verifies, so the client asks `mint` once per call and once per retry,
exactly like examples/broker-client/client.ts. Tokens are never logged or printed.

    python3 vouchr_client.py BROKER_URL status
    python3 vouchr_client.py BROKER_URL fetch PROVIDER METHOD PATH [HOST]
    python3 vouchr_client.py BROKER_URL authorize PROVIDER METHOD PATH "statement"   # #296 backchannel
    python3 vouchr_client.py BROKER_URL authorization ID                             # #296 poll

The CLI reads one identity token per line from stdin (pipe them from the minter) and honours
VOUCHR_BROKER_TOKEN (optional perimeter bearer). JSON on stdout; a denial's envelope on stderr, exit 1.
"""
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request

log = logging.getLogger("vouchr")


class VouchrError(Exception):
    """A broker denial: the typed `{error, code, retryable, recovery, retryAfterMs}` envelope.

    Branch on `code` (None on prose-only validation errors), never on `error` prose. `recovery` is one
    of connect | request_approval | resolve_again | retry_later | fix_configuration | contact_admin.
    `retryable` never authorizes replaying an uncertain write."""

    def __init__(self, status, body):
        super().__init__("%s %s" % (status, body.get("code") or body.get("error")))
        self.status, self.body = status, body
        self.code = body.get("code")
        self.retryable = body.get("retryable", False)
        self.recovery = body.get("recovery")
        self.retry_after_ms = body.get("retryAfterMs")
        self.approval_id = body.get("approvalId")  # only on approval_required


class Vouchr:
    def __init__(self, broker_url, mint, broker_token=None):
        self.url, self.mint, self.broker_token = broker_url.rstrip("/"), mint, broker_token

    def fetch(self, handle, method, path, host=None, query=None, headers=None, body=None):
        """POST /v1/fetch -> {status, contentType, body}: the provider's response, credential injected."""
        return self._post("/v1/fetch", handle=handle, method=method, path=path, host=host,
                          query=query, headers=headers, body=body)

    def status(self):
        """POST /v1/status -> {providers: [{provider, connected, consentState}]} for the acting user."""
        return self._post("/v1/status")

    def request_authorization(self, handle, method, path, binding_message, host=None, query=None):
        """POST /v1/authorization (#296) -> {authorizationId, status, expiresAt}. Nothing executes."""
        return self._post("/v1/authorization", handle=handle, method=method, path=path, host=host,
                          query=query, bindingMessage=binding_message)

    def authorization(self, authorization_id):
        """GET /v1/authorization/{id} (#296) -> pending | approved | denied | expired; 404 is terminal."""
        return self._call("/v1/authorization/" + urllib.request.quote(authorization_id, safe=""))

    def _post(self, route, **fields):
        return self._call(route, {k: v for k, v in fields.items() if v is not None})

    def _call(self, route, body=None):
        # GET: token in `x-vouchr-identity`; POST: `identityToken` in the JSON body. Retry ONCE on a retry
        # hint (429 / 503): both refuse before any credential read or provider call, so the replay is safe.
        for attempt in (0, 1):
            token = self.mint()
            hdrs = {"content-type": "application/json"}
            if self.broker_token:
                hdrs["authorization"] = "Bearer " + self.broker_token
            if body is None:
                hdrs["x-vouchr-identity"], data = token, None
            else:
                data = json.dumps(dict(body, identityToken=token)).encode()
            req = urllib.request.Request(self.url + route, data=data, headers=hdrs,
                                         method="GET" if data is None else "POST")
            try:
                with urllib.request.urlopen(req) as res:
                    return json.load(res)
            except urllib.error.HTTPError as e:
                try:
                    err = VouchrError(e.code, json.load(e))
                except ValueError:
                    err = VouchrError(e.code, {"error": e.reason})
                if attempt or not (err.retryable and err.retry_after_ms):
                    raise err
                log.warning("%s: retrying once in %d ms", err.code, err.retry_after_ms)
                time.sleep(err.retry_after_ms / 1000)


if __name__ == "__main__":
    argv = sys.argv[1:]
    if len(argv) < 2:
        sys.exit(__doc__)
    client = Vouchr(argv[0], lambda: sys.stdin.readline().strip(), os.environ.get("VOUCHR_BROKER_TOKEN"))
    cmd, args = argv[1], argv[2:]
    handle = {"provider": args[0], "owner": "user"} if args else None  # owner is the verified token, never this
    try:
        if cmd == "status":
            out = client.status()
        elif cmd == "fetch":
            out = client.fetch(handle, args[1], args[2], *args[3:4])
        elif cmd == "authorize":
            out = client.request_authorization(handle, args[1], args[2], args[3])
        elif cmd == "authorization":
            out = client.authorization(args[0])
        else:
            sys.exit(__doc__)
    except IndexError:
        sys.exit(__doc__)
    except VouchrError as e:
        print(json.dumps(dict(e.body, status=e.status)), file=sys.stderr)
        sys.exit(1)
    print(json.dumps(out))
