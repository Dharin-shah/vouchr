# Vouchr — guide for coding agents

@AGENTS.md

AGENTS.md (imported above) is the canonical contract: SEC/STR/TEST/PROC rules, exact
commands, and the PR template. Everything below is workflow guidance on top of it.

## Workflow

- Every PR targets `main`. Never base a PR on another PR's branch.
- Do feature work in a dedicated git worktree, not by switching branches in the main
  checkout: `git worktree add ../vouchr-worktrees/<branch> -b <branch> origin/main`.
- Before opening a PR, walk the Pre-PR checklist at the bottom of AGENTS.md and copy the
  sign-off template from AGENTS.md § Pull requests verbatim.

## Fast orientation

- Start at `src/index.ts` (the public API) and `src/adapters/bolt.ts` (the Slack surface).
- Security-critical flows: `src/core/injector.ts` (token injection at the HTTP boundary),
  `src/core/oauthCallback.ts` (single-use `state`), `src/core/vault.ts` (encrypted storage).
- Run one test file while iterating: `node --import tsx --test test/<file>.test.ts`.
