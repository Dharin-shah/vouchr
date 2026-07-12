## Issue contract

Issue: #

<!-- State the user/operator outcome and the explicit non-goals or removals. -->
<!-- Private security work uses its authorized advisory; never paste private details here. -->

## Acceptance evidence

<!-- One row per issue criterion. Point at the production path, not a copied surrogate. -->

| Criterion | Production path | Test / measurement |
| --- | --- | --- |
| | | |

## Edge-case disposition

<!-- Mark every row covered or N/A with a short reason; do not invent work. -->

- [ ] Raw input: missing/empty/malformed/unknown/duplicate/conflicting/boundary forms
- [ ] State: retry/replay/stale/interruption/rollback/two-replica races
- [ ] Resources: hard bounds, ownership, timeout/cancel/shutdown cleanup
- [ ] UX/docs: truthful committed outcome, one next step, executable examples
- [ ] Simplification: removed dead paths; no speculative compatibility/infrastructure

## Reusable finding disposition

<!-- Use one: same-PR regression/static check; canonical rule; existing owner issue; new narrow issue; none reusable. Link the guardrail/issue. #229 owns mechanical validation of this field. -->

Disposition:

## Verification

- [ ] `npm run typecheck` passes
- [ ] `npm run lint` passes
- [ ] `npm test` passes against the required local PostgreSQL
- [ ] Updated `README.md` if this changes architecture or public API
- [ ] No secret can reach logs, Slack messages, the audit table, or an error string

<!-- After all required checks pass, add the exact Checks line from AGENTS.md PROC-2. -->

## Sign-off

<!-- Keep exactly one. See AGENTS.md. -->

- Human, reviewed line-by-line: `Signed-off-by: <Your Name> <email> — reviewed line-by-line`
- AI agent, review not yet certified: `Signed-off-by: 🤖 automated-agent (operator has not certified review)`
