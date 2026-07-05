# Contributing to Vouchr

Thanks for helping. Vouchr is a security-sensitive credential broker, so the bar is
correctness and simplicity over feature volume.

**Before you start, read [`AGENTS.md`](./AGENTS.md)**: it is the canonical contribution
contract for both humans and AI agents — numbered SEC/STR/TEST/PROC rules, the layout,
dev setup, testing expectations, and the exact PR sign-off template. The PROC rules
(title style, "checks pass" statement, sign-off, agent canary) are enforced by the
`pr-lint` CI job, so a PR that skips them fails before review.

## Quick start

```bash
nvm use            # Node ≥ 22 (CI runs 22 and 24)
npm install
npm run typecheck  # must be clean
npm test           # unit + integration, fully offline
```

## Ground rules

- One concern per PR; keep the diff focused and match surrounding style.
- Non-trivial logic ships with a runnable test (`node:test`); flows get an integration test.
  CI reports per-file `src/**` coverage (`npm run test:coverage`) on the Node 22 leg — new code
  should keep it moving up, never down. (Visibility today; a failing floor lands once the baseline
  is established, and only ever ratchets upward.)
- Never weaken the security invariants: tokens stay out of logs, messages, the audit
  table, and tool schemas; keep the egress allowlist and single-use OAuth `state`.
- If the correct approach isn't feasible, raise it in the PR instead of faking it.

## Sign-off

Every PR description ends with a sign-off line (see AGENTS.md → Pull requests). Human
authors who reviewed the change sign with their name; automated agents whose operator has
not certified a review use the `🤖 automated-agent` sign-off so maintainers can triage.

## Reporting security issues

Don't open a public issue for vulnerabilities. See `SECURITY.md` if present, otherwise
contact the maintainers privately.

By contributing you agree your contributions are licensed under Apache-2.0.

## Releasing

The package is published to npm as `@vouchr/core` by `.github/workflows/release.yml`,
which runs only on a `v*` tag and requires the tag to match `package.json`'s version.
To cut a release:

1. Bump `version` in `package.json` (SemVer; pre-1.0 minors may carry breaking changes).
2. Add a `## [x.y.z]` heading to `CHANGELOG.md` describing the changes.
3. Confirm `npm run typecheck` and `npm test` are green, including the Postgres path
   (`npm run pg:up` then `npm test`).
4. Tag the release and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z` — the
   release workflow publishes to npm (with provenance) and pushes the GHCR broker image.
