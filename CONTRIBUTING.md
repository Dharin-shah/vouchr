# Contributing to Vouchr

Thanks for helping. Vouchr is a security-sensitive credential broker, so the bar is
correctness and simplicity over feature volume.

**Before you start, read [`AGENTS.md`](./AGENTS.md)**: it's written for both humans and
AI agents and covers the working principles (never fake it; build the correct general
structure; simplest thing that works; security is never simplified away), the layout, dev
setup, and testing expectations.

## Quick start

```bash
nvm use            # Node ≥ 20.6 (developed on 22)
npm install
npm run typecheck  # must be clean
npm test           # unit + integration, fully offline
```

## Ground rules

- One concern per PR; keep the diff focused and match surrounding style.
- Non-trivial logic ships with a runnable test (`node:test`); flows get an integration test.
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

Pre-1.0 and private: the package is **not published to npm**, so there is no publish step.
Releases are just tags. To cut one:

1. Bump `version` in `package.json` (SemVer; pre-1.0 minors may carry breaking changes).
2. Add a `## [x.y.z]` heading to `CHANGELOG.md` describing the changes.
3. Confirm `npm run typecheck` and `npm test` are green, including the Postgres path
   (`npm run pg:up` then `npm test`).
4. Tag the release: `git tag vX.Y.Z`.
