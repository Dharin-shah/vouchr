# Context map

Always load the target issue and comments, #226, the relevant `vision.md` sections,
`AGENTS.md`, the current diff/status, and existing tests for changed behavior. Then select
every applicable row below.

| Surface | Load before design | Mandatory questions |
| --- | --- | --- |
| PostgreSQL/schema | `src/core/db.ts`, every caller of changed SQL, migration/readiness commands, `test/support/pg.ts`, deployment docs | Is runtime DML-only? What locks/transactions/order decide races? Are hard limits enforced in core? Does the test explain/execute production SQL? |
| Lifecycle/state | consent, callback, vault, offboard, refresh, sweep, session, audit, relevant schema | What is the full mutation timeline? Where can retry, callback, expiry, reconnect, deletion, or offboard race? What commits before success? |
| CLI/destructive | parser and command in `bin/`, core mutation, all scope filters, CLI/deployment docs, subprocess tests | Are unknown, positional, missing, empty, valued-boolean, duplicate, conflicting, case-conflicting, oversized and boundary forms rejected? Can a typo widen scope? Is confirmation exact and tested via resulting DB state? |
| Slack/UX | Bolt handlers, block builders, authz/core mutation, safe errors, matching Slack tests, #194 | Does `ack()` precede I/O? Are payloads forged/stale/retried? Is feedback private, renderable, escaped, accessible, truthful, and actionable? |
| Broker/identity | HTTP router, broker types/client, signer/verifier/replay store, golden wire fixtures, #212 | Are issuer/audience/deployment/time/jti bound at every route? Are bodies/deadlines/resources bounded and errors stable? |
| Provider/OAuth/egress | provider definitions/loaders, callback/tokens, injector, policy, redirects, SECURITY/threat model, #211 | Are all definition paths normalized identically? Is HTTPS/host/path/method/query/redirect checked before secret read? Are encoded and duplicate forms fail-closed? |
| Public/package API | `src/index.ts`, `src/headless.ts`, options/types, package exports, README, CHANGELOG, pack smoke | Can callers bypass an adapter guard? Is behavior/export compatibility intentional? Does the packed artifact prove the contract? |
| Performance/resources | complete production operation, pool/client ownership, cancellation/shutdown, representative generator, exact operator docs, #208/#209 | What is the hard work/memory/time/concurrency bound at every callable layer? What distribution and complete path are measured? Record P50/P95/P99 as requested, buffers/WAL/pool impact, overload and concurrent work. |
| Documentation/operations | CLI `help`, README/guides/examples, env/config, image/workflows/runbooks | Does every named symbol exist? Does every command/SQL example run? Are role, archive, backup, failure, and residual-risk claims precise? |
| Removal/simplification | `vision.md` non-goals, all references/exports/schema/docs/tests for removed feature | Is the dead path actually deleted? Did the change accidentally add compatibility, scaffolding, a second datastore, or a one-use abstraction? |

For issue families, also load:

- #192: consent/callback/vault/offboard/refresh/sweep barrier timelines.
- #194: every retained Slack/browser/API recovery surface.
- #208/#209: exact SQL/network paths, public bounds, cancellation, pools, WAL/memory/latency.
- #211: every provider registration/configuration and OAuth/egress path.
- #212: minter/verifier/replay/schema/rotation and two-replica behavior.
- #216/#217/#223/#225: the exact image, package, workflow, configuration, artifact identity,
  branch rules, staging proof, and assessment evidence.
