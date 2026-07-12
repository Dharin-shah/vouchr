# Vouchr — guide for coding agents

@AGENTS.md

AGENTS.md (imported above) is the canonical contract: SEC/STR/TEST/REV/PROC rules, exact
commands, and the PR template. Everything below is workflow guidance on top of it.

## Workflow

- Every PR targets `main`. Never base a PR on another PR's branch.
- Do feature work in a dedicated git worktree, not by switching branches in the main
  checkout: `git worktree add ../vouchr-worktrees/<branch> -b <branch> origin/main`.
- Reviews follow `AGENTS.md` section **Review rules (REV)**, including the deterministic
  guardrail or non-duplicate issue disposition before approval.
- Before opening a PR, walk the Pre-PR checklist at the bottom of AGENTS.md and copy the
  sign-off template from AGENTS.md § Pull requests verbatim.

## Greenfield: no deployed databases

- Vouchr is **greenfield** — no deployed databases, no live users, no backwards-compat burden.
- The DB schema is created fresh on first open, so **don't write data migrations or upgrade/
  compatibility layers** for a change: just change `schema()` in `src/core/db.ts` directly and
  keep it simple. Removing a table means deleting its `CREATE TABLE`, not migrating rows out of it.
- `SCHEMA_VERSION` and the `guardSchemaVersion` downgrade fence stay (they protect a future
  deploy), but you never need a per-feature migration test for greenfield changes.

## Fast orientation

- Start at `src/index.ts` (the public API) and `src/adapters/bolt.ts` (the Slack surface).
- Security-critical flows: `src/core/injector.ts` (token injection at the HTTP boundary),
  `src/core/oauthCallback.ts` (single-use `state`), `src/core/vault.ts` (encrypted storage).
- Run one test file while iterating: `node --import tsx --test test/<file>.test.ts`.
