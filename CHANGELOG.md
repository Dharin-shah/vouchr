# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/). Pre-1.0: minor versions may carry breaking changes.

## [0.1.0]

First hardened cut. Not yet published; not yet run in production.

### Added

- `examples/slack-manifest.yml` — ready-to-import Slack app manifest (scopes, events,
  interactivity, the `/vouchr` command).
- `context.vouchr` is now typed via a `@slack/bolt` module augmentation (no `as any`).
- Continuous integration: typecheck + test (including a real Postgres backend) on push and PR.

### Fixed

- **Postgres pool resilience.** The connection pool now has an `error` listener (an idle-client
  error no longer crashes the process) and connection/statement timeouts (a slow or down database
  fails fast instead of hanging the request).
- **User-key modal submit** now awaits the write — a storage failure surfaces inline instead of
  becoming an unhandled rejection, and the success DM no longer fires before the write lands.
- **Token refresh is single-flight** per owner+provider — concurrent calls share one refresh, so a
  rotating refresh token can no longer brick a connection.
- **OAuth callback** has an error boundary; an async failure returns a 500 instead of hanging the browser.
- **Egress requires https** (loopback exempt) so a bearer token is never sent over cleartext.
- SQLite `busy_timeout`; atomic single-use consent (`DELETE … RETURNING`); post-call bookkeeping is
  best-effort so it can't discard an already-successful response.

### Changed

- Node ≥ 20.6 (the example uses `--env-file`).
- Removed dead code (`idKey`) and merged the two duplicated modal-submit handlers into one.
