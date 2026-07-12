# Pre-code change contract

Keep this compact. Fill it in the plan/conversation; do not commit a completed copy.

## Authority and scope

- Target issue and current state:
- Newest operator/maintainer amendments:
- Dependencies already merged or still blocking:
- Outcome:
- Explicit non-goals/removals:
- Conflicts resolved:

## Reachable surface inventory

| Surface | Production entrypoint/caller | Public bypasses | Mutation/audit/docs/tests |
| --- | --- | --- | --- |
| | | | |

## Raw input grammar

For every applicable input include missing, empty, whitespace, malformed, unknown,
duplicate, conflicting, case-conflicting, oversized, minimum, maximum, and just-outside.

| Input | Canonical valid forms | Rejected forms | Where raw ambiguity is rejected | Core invariant |
| --- | --- | --- | --- | --- |
| | | | | |

## State and mutation timeline

| Step | State/lock acquired | Mutation/commit | Audit/user outcome | Failure/race/interruption |
| --- | --- | --- | --- | --- |
| | | | | |

## Resources, bounds, and performance

| Resource/work | Owner and cleanup | Hard bound at every callable layer | Failure/cancel/shutdown | Evidence |
| --- | --- | --- | --- | --- |
| | | | | |

## Failure and concurrency matrix

Cover only applicable cases: retry, duplicate delivery/click, stale/replayed state,
two replicas, dependency timeout/unavailability, transaction rollback, process stop,
partial upstream/local success, and rolling-version overlap.

| Case | Expected user/machine result | State/audit invariant | Regression/evidence |
| --- | --- | --- | --- |
| | | | |

## Acceptance-to-evidence map

Every issue criterion gets one row. “The code looks right” is not evidence.

| Acceptance criterion | Production path | Test/measurement | Failure that would make it fail |
| --- | --- | --- | --- |
| | | | |

## Simplification check

- What was deleted?
- What tempting compatibility, abstraction, configuration, or infrastructure was omitted?
- Why is each new helper/knob/index/state table required by more than a hypothetical future?
