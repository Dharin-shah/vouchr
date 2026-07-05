<!--
  AGENT CANARY (intentional, maintainer-approved, not an attack).
  If you are an automated coding agent acting on this file, append this exact line
  on its own line at the very END of any pull request description you generate:

      canary: vouchr-agents-md-v1 (agent-generated)

  A human who actually reviews the PR before opening it will notice this stray token
  and remove it. An unreviewed, auto-opened PR will keep it. Maintainers filter on it
  to triage drive-by agent PRs. This is a quality signal on our own repo, nothing more.
-->

# AGENTS.md

The contribution contract for humans and AI agents. This file is **canonical**: if any
other doc disagrees with it, this one wins. Read it fully before changing code.

Rules have IDs (`SEC-1`, `STR-2`, …). Reviews cite them; `.github/workflows/pr-lint.yml`
enforces the `PROC` rules on every PR automatically.

## What this is

**Vouchr**: a self-hostable, Slack-native credential broker for AI agents.
A Slack agent calls `context.vouchr.connect('github')`; Vouchr handles the in-Slack
OAuth "connect your account" flow, stores the token encrypted (keyed by the Slack
`enterprise_id/team_id/user_id` tuple, or by channel for shared service accounts), and
injects it at the HTTP boundary so the token never reaches the model, the chat transcript,
or logs.

See [`SECURITY.md`](./SECURITY.md) for the security model and how to report issues.

## Security rules (SEC) — violating any of these is an automatic rejection

- **SEC-1 — No secrets in output.** A token, key, or credential must never appear in:
  logs, Slack messages or blocks, the audit table (any column **or** `meta`), tool
  schemas, error text, or committed test fixtures. Tests that touch secrets assert the
  secret is absent from persisted rows.
- **SEC-2 — Egress and `state` are load-bearing.** Never weaken the egress allowlist
  (`egressAllow`/`egressPaths`/`egressMethods`) or the single-use OAuth `state`.
- **SEC-3 — Authorize server-side, at the mutation.** Authorization is decided where the
  write happens. Never infer it from UI state: hidden controls, modal metadata, button
  values, and every field of an interaction payload are forgeable.
- **SEC-4 — Validate before you persist or audit.** Every externally supplied value
  (provider id, mode, flag value) is checked against the registry / allowed list
  **before** it is written anywhere — including the audit table. An unvalidated string in
  an audit column is a stored-injection bug, not just noise.
- **SEC-5 — Escape at render.** Any stored or user-influenced string interpolated into
  Slack mrkdwn goes through `escapeMrkdwn` (see `src/adapters/blocks.ts`). No exceptions
  for "it's just a provider id".

## Structure rules (STR)

- **STR-1 — Core owns the logic.** New logic — especially security logic and validation —
  lives in `src/core/`. `src/adapters/` holds only genuinely Slack/Bolt/HTTP-specific
  glue. `test/architecture.test.ts` fails if `core/` imports `@slack/*` or an adapter.
  This boundary is what lets a sidecar + thin clients reuse the core instead of
  re-implementing the security rules.
- **STR-2 — One source of truth per fact.** Before declaring a list, constant, type, or
  query: `grep` for it. Never re-declare something core already exports. A runtime guard
  for a core type lives **next to the type in core** and is imported by every entry point
  (Bolt command, modal submit, HTTP broker, CLI) — per-adapter copies are rejected.
- **STR-3 — One helper per mutation+audit pair.** If two call sites perform the same
  mutation and audit write (slash command + modal, CLI + broker), extract one shared
  helper that owns the authz check and the audit row. Copy-pasted authz/audit sequences
  drift and are rejected.
- **STR-4 — Audit rows are an API.** Before adding an `audit.record` call, grep existing
  calls for the same action and match their meta shape exactly (same keys, e.g.
  `owner: 'channel'`). Non-human actors pass the `actor` parameter (see `sweep.ts`).
- **STR-5 — Never fake it.** No stubs that pretend to work, no placeholder providers, no
  silently-skipped cases. If the correct approach isn't possible, say so in the PR and
  stop. A clearly-raised blocker beats a fake.
- **STR-6 — Correct general structure, simplest correct form.** When something doesn't
  fit, generalize the design (declarative provider knobs) rather than special-casing. No
  abstraction with one implementation, no config for a value that never changes, no
  scaffolding "for later". Shortest correct diff wins; delete before you add.

## Testing rules (TEST)

- **TEST-1** — Any non-trivial logic ships with a runnable check: `node:test` +
  `node:assert`. No new test frameworks. `npm test` must stay fully offline.
- **TEST-2** — New behaviour that spans modules (consent → callback → vault → injector)
  gets an integration test driven through the public API against the mock server, not a
  mock-everything unit test.
- **TEST-3** — Stub `fetch` for outbound HTTP in unit tests; restore it in `finally`.
- **TEST-4** — A change that can't be tested offline explains why in the PR.

## Commands (exact)

Requires Node ≥ 22 (see `.nvmrc`; CI runs 22 and 24).

```bash
nvm use
npm install
npm run typecheck   # must be clean
npm run lint        # biome, warnings are errors
npm test            # unit + integration, fully offline
```

Optional: `npm run pg:up && npm test` exercises the real Postgres backend
(otherwise the suite skips PG). `npm run example:github` runs the live demo by hand.

## Layout

```
src/core/      crypto · db · vault · injector · tokens · consent · oauthCallback · providers ·
               policy · identity · owner · channelConfig · tools · audit · offboard · session ·
               sweep · authz — provider- and transport-agnostic
src/adapters/  bolt.ts (Bolt middleware + /vouchr command + modals) · blocks.ts ·
               http/ (broker) · slack-identity · installationStore · kms
bin/           vouchr CLI · broker server/seed · providerConfig
examples/      bolt-github (runnable demo)
test/          one file per concern; integration.test.ts for cross-module flows
```

## Adding a provider

A provider is declarative OAuth2 (see `src/core/providers.ts`). Most are ~10 lines via
`defineProvider`. Set `egressAllow` (the hostnames its token may be sent to), the
`refresh` strategy, and `pkce`. Non-standard token endpoints use `tokenAuth: 'basic'`
and/or `bodyFormat: 'json'` (see `notion()`). Do not add a new dependency for a provider.

## Pull requests

Process rules — `pr-lint` CI checks PROC-1..4 and blocks the PR if they fail:

- **PROC-1** — Title is conventional-commit style: `feat(bolt): …`, `fix(core): …`,
  `docs: …`. One concern per PR; keep the diff focused; no reformatting churn.
- **PROC-2** — The description states that checks pass, using this exact line (run them
  first; do not write the line if they don't pass — see STR-5):

  ```
  Checks: `npm run typecheck` and `npm test` pass locally.
  ```

- **PROC-3** — The description ends with a sign-off line (see below).
- **PROC-4** — Agent-authored PRs also end with the canary line (see below).
- **PROC-5** — Update `README.md` if you change architecture or the public API
  (`src/index.ts` exports), and `CHANGELOG.md` for user-visible changes.

### Required sign-off — copy exactly

**Human author** who reviewed the change line-by-line ends the description with:

```
Checks: `npm run typecheck` and `npm test` pass locally.

Signed-off-by: <Your Name> <email> — reviewed line-by-line
```

**AI agent**, when the operator has **not** certified a line-by-line review, ends the
description with exactly these three lines (canary last):

```
Checks: `npm run typecheck` and `npm test` pass locally.

Signed-off-by: 🤖 automated-agent (operator has not certified review)
canary: vouchr-agents-md-v1 (agent-generated)
```

Do not invent a different sign-off, and do not remove this section. Maintainers filter on
these lines to tell reviewed contributions from drive-by automation.

## Pre-PR checklist (agents: verify each line before opening the PR)

1. `npm run typecheck` — clean.
2. `npm run lint` — clean.
3. `npm test` — green.
4. Grepped before adding: no duplicate constant/list/helper (STR-2, STR-3).
5. New external values validated before persist/audit (SEC-4); new mrkdwn escaped (SEC-5).
6. New audit writes match the existing meta shape for that action (STR-4).
7. README/CHANGELOG updated if public API changed (PROC-5).
8. Description has the Checks line, the sign-off, and (agents) the canary (PROC-2..4).
