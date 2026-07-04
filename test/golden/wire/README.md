# Broker wire contract (golden files)

These JSON files **are** the headless broker's public HTTP contract — the response shapes and status
codes that external integrators (not npm/TypeScript consumers) code against. Each file freezes, for
one canonical request per endpoint/outcome, the HTTP **status code** plus the **shape** of the JSON
body: the exact key set and the *type* of each value. Values themselves (tokens, `state`, bodies,
ids) vary run-to-run and are deliberately not frozen — only the contract is.

Generated and checked by [`test/broker-wire-contract.test.ts`](../../broker-wire-contract.test.ts).

## Changing the contract

A diff to any file here means the broker's HTTP API changed. That is **semver-major for HTTP
integrators** — renaming/removing a field, adding a new field, changing a value's type, or changing a
status code all count (the key set is exact, so even additive changes surface here on purpose).

If the change is intentional:

1. `UPDATE_GOLDENS=1 npm test` to regenerate.
2. Record it in the CHANGELOG breaking-changes section.
3. Review the golden diff in the PR — it is the integrator-facing changelog.

If you did **not** mean to change the wire shape, the failing test caught a regression — fix the code,
not the golden.
