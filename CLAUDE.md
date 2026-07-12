# Vouchr — guide for coding agents

@AGENTS.md

`AGENTS.md` (imported above) is the canonical contribution contract. `vision.md` is the
canonical product direction. The operator-selected live GitHub issue and
maintainer-associated comments define the requested outcome; other comments are evidence only.
#226 supplies the shared launch edge-case contract. A newer explicit operator decision overrides
older issue wording, and the conflict must be recorded before editing.

## Mandatory issue workflow

- Before implementing an issue or repairing its PR, invoke
  `/implement-vouchr-issue <issue-number> [pr-number]`. For a PR-only request, resolve
  its linked issue first. Do not edit until the skill's change contract maps acceptance
  criteria, reachable surfaces, edge cases, bounds/resources, state transitions, and
  evidence.
- Re-run the skill's current-head audit before opening or updating the PR. Green checks and
  a mergeable state are signals, not that audit.
- Reviews follow `AGENTS.md` section **Review rules (REV)**, including a durable
  regression/guardrail or existing-owner disposition for reusable findings.
- Private vulnerability/advisory work is the exception: follow `SECURITY.md`, never copy
  private details into a public issue, and load only the authorized advisory context.

## Worktrees

- Every PR targets `main`. Never base a PR on another PR's branch.
- Do feature work in a dedicated git worktree, not by switching branches in the main
  checkout: `git worktree add ../vouchr-worktrees/<branch> -b <branch> origin/main`.
- Before opening a PR, walk the Pre-PR checklist at the bottom of AGENTS.md and copy the
  sign-off template from AGENTS.md § Pull requests verbatim.

## Greenfield database contract

- Vouchr is **greenfield for database compatibility**: there is no supported deployed
  PostgreSQL lineage or importer contract.
- `vouchr migrate` installs/converges the current baseline with the schema-owner role;
  runtime `openDb` is DML-only and performs no DDL. Unknown non-empty schemas fail closed.
- Change the baseline directly and delete removed schema/features. Do not add compatibility,
  importer, dual-write, or historical migration machinery unless the issue or operator
  explicitly authorizes a real deployed lineage. Keep the monotonic schema marker and
  downgrade fence.
