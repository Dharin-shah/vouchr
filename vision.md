# Vouchr Vision

**Status:** Adopted product direction, 2026-07-11
**Current product stage:** Alpha; not yet production-ready

This document is the canonical product and scope direction for Vouchr. When an older design,
assessment, example, or guide conflicts with it, this document wins for product direction.
`AGENTS.md` remains canonical for contribution rules, and `SECURITY.md` remains canonical for
vulnerability reporting and the current security policy.

The repository will temporarily contain code and documentation for features this vision removes.
Those paths are migration work, not supported future direction.

## The product in one sentence

Vouchr is a self-hosted, Slack-native credential broker that lets an AI agent act with the right
human or channel credential without exposing that credential to the model, tool schema, Slack
transcript, application code, or logs.

## Why Vouchr exists

Teams building Slack agents repeatedly have to solve the same risky problems:

- connect each human to external providers;
- store and refresh credentials safely;
- decide which Slack identity or channel may use them;
- prevent credentials from entering model context, prompts, tools, logs, or chat;
- revoke access and preserve attribution when people, channels, and policies change.

Vouchr makes that credential boundary a small, reusable, self-hosted component. The agent receives
a constrained handle. Vouchr validates the destination and injects the credential only when it
sends the outbound provider request.

The product is not the connector catalog. It is the trustworthy boundary between Slack identity,
human consent, encrypted credentials, and provider egress.

## Product promise

For every supported request, Vouchr should make these statements true:

1. The model and agent never receive the credential.
2. The credential is resolved for the correct Slack owner and deployment.
3. Authorization is checked server-side at the mutation and again at egress.
4. A credential is sent only to a validated HTTPS provider destination.
5. Retries and replica races do not duplicate, resurrect, or delete the wrong state.
6. Success is shown only after success actually committed.
7. Failure is safe, bounded, private, and gives one useful next step.
8. Audit identifies the credential owner and the triggering human without containing secrets.

These are product invariants, not optional deployment modes.

## Supported product surface

### Slack is the control plane

Slack is where a human connects an account, approves a session, configures a shared credential,
disconnects, and receives private recovery guidance. The Bolt integration is the primary product
experience.

The headless HTTP broker remains a supported data plane for agent workers in other processes or
languages. It must receive short-lived, single-use, deployment-bound identity assertions from a
trusted minter. It is not a generic OAuth or MCP gateway product.

### Credential modes

Vouchr supports three modes:

| Mode | Meaning |
| --- | --- |
| `per-user` | Each person uses their own connected account. This is the default. |
| `session` | A person's credential is usable only in the approved Slack thread for a bounded time. |
| `shared` | A workspace administrator configures one channel-owned service credential. |

`shared` is for an intentional service account, not for silently borrowing another person's
account. It remains admin-gated, attributable to the triggering human, and unavailable where the
channel trust boundary is unsafe.

### Providers

Providers are strict declarative OAuth or key/reference definitions. A supported definition states
its OAuth behavior, refresh/revocation behavior, credential injection, and exact egress hosts,
paths, and methods.

Vouchr will ship a small useful built-in set and a safe generic definition path. It will not become
an integration marketplace or arbitrary plugin runtime.

### Production architecture

There is one production shape:

- stateless Vouchr replicas;
- PostgreSQL as the only runtime database;
- envelope encryption through the documented KMS integration;
- a trusted Slack installation and identity minter;
- one tested, non-root, immutable container image;
- normal TLS, secret management, and network controls supplied by the operator.

The default production proof uses at least two Vouchr replicas against one PostgreSQL database.

## Deliberate removals and non-goals

The following are intentionally outside the product:

- **SQLite runtime support.** No single-pod database mode, dual write, or permanent legacy adapter.
- **`union` credential borrowing.** One human's personal credential will not be delegated to other
  channel members. `per-user`, `session`, and `shared` cover the supported needs more clearly.
- **Private provider-response previews stored by Vouchr.** Hosts own provider-output rendering and
  data-loss prevention. Vouchr owns the credential boundary.
- **Transaction-semantic approval for arbitrary bodies.** Generic approval binds the supported
  endpoint, method, and query capability. Providers requiring transaction-level confirmation must
  implement trusted tool-specific UX in the host.
- **A general secret manager.** Vouchr integrates with KMS and external secret references; it does
  not replace Vault, cloud secret managers, or provider-side scopes.
- **A hosted Vouchr SaaS.** The project is self-hosted.
- **A distributed systems platform.** No Redis requirement, distributed semaphore, speculative
  cache, sharding framework, or multi-cloud abstraction without measured need.
- **An operations product.** Vouchr supplies safe logs, minimal metrics, health checks, a reference
  deployment, and runbooks—not a Helm/operator, dashboard, tracing, legal-hold, or chaos platform.

Removed features may have temporary migration code and rejection tests. They must not receive new
compatibility layers or hardening beyond what is needed to remove them safely.

## Experience we are building

### Normal user journey

1. A person asks a Slack agent to use a provider.
2. The agent asks Vouchr for a handle, never a token.
3. If no credential or session grant exists, Vouchr posts one private, deduplicated prompt.
4. The person connects through OAuth or approves the thread-scoped session.
5. Vouchr stores the credential encrypted and the person retries the request.
6. Vouchr validates policy and egress, injects the credential, and returns only the provider
   response.

No action should require the person to understand Vouchr internals.

### Failure journey

Denial, cancellation, expiry, replay, provider outage, Slack retry, stale controls, and partial
failure are expected states. Each must produce:

- truthful status;
- one stable machine-readable error;
- private, escaped, accessible copy;
- one safe next step;
- no secret or raw third-party error;
- no claim of success before the database mutation commits.

Slack interactions acknowledge before database, KMS, Slack API, or provider work. Repeated prompts,
double-clicks, and Slack retries converge on one state change and one audit result.

## Security model

Vouchr is secure by construction where it can be, and explicit about residual risk where it cannot.

### Invariants

- No credential, OAuth code/state, identity assertion, sensitive request body, or resolved secret
  appears in Slack, browser error pages, logs, metrics, audit metadata, tool schemas, or committed
  fixtures. Tests may use clearly synthetic, non-secret request bodies.
- OAuth state and approvals are bounded, single-use, owner-bound, and consumed atomically.
- Offboarding fences in-flight callbacks so earlier consent cannot recreate access afterward.
- Egress validates HTTPS, origin, path, method, redirects, and provider rules before reading the
  credential.
- Broker assertions are short-lived, replay-protected across replicas, and bound to one deployment.
- External values are validated before persistence or audit and escaped at render time.
- Partial credential deletion or revocation failure is never reported as complete success.

### Honest limits

- Provider responses return to the host and may contain sensitive data. The host decides what
  reaches the model or Slack.
- Provider-side scopes and permissions remain the final authorization boundary.
- A malicious self-hosted operator or full KMS/root-key compromise is outside Vouchr's protection.
- Generic write approval is not semantic understanding of an arbitrary provider transaction.

Production documentation and UX must state these limits without implying broader protection.

## Reliability and performance principles

Vouchr must be boring under failure and predictable under load.

- Every inbound and outbound path has finite time, body, response, pool, and concurrency bounds.
- Cancellation and shutdown release timers, sockets, response bodies, database clients, and locks.
- A 401 refresh retries once; non-idempotent writes are never retried automatically.
- PostgreSQL transactions and database ordering—not process clocks—decide concurrent state.
- Reads needed for manifests and Slack surfaces are batched instead of growing into per-provider
  query chains.
- One request decrypts only the credential it will use.
- Audit queries have measured indexes and pruning runs in bounded batches.
- The supported capacity envelope is measured with two replicas and records throughput, latency,
  memory, pool/KMS use, and overload behavior.

We prefer batching and explicit limits over caches and distributed coordination. New infrastructure
requires measurements showing that the simpler design is insufficient.

## Execution plan

The final production contract is tracked in
[#226](https://github.com/Dharin-shah/vouchr/issues/226). The numbered sections are
dependency groups and release gates, not a total issue order: ready work may proceed in
parallel when it does not create conflicting foundations.

### 1. Protect current users

- The #202, #203, and #201 security fixes are merged.
- Publish the patched maintenance release and coordinated advisories through
  [#223](https://github.com/Dharin-shah/vouchr/issues/223). Do not wait for unrelated production
  features before protecting installed users.

### 2. Simplify the product

- [#196](https://github.com/Dharin-shah/vouchr/issues/196) is complete: `union` is removed.
- [#204](https://github.com/Dharin-shah/vouchr/issues/204) is complete: PostgreSQL is the only
  runtime database and migration/runtime roles are separated.
- [#194](https://github.com/Dharin-shah/vouchr/issues/194): the commands/rendering/disconnect slice
  landed in [PR #244](https://github.com/Dharin-shah/vouchr/pull/244), and Vouchr-owned private
  previews are removed; complete pending-interaction state, OAuth/API recovery, typed errors, and
  the trusted broker-to-Slack recovery bridge.

No SQLite importer or runtime dual-write is part of the supported work. Any future compatibility
project would require a new explicit product decision backed by a concrete deployed lineage; it is
not a launch requirement.
With #196 and #204 complete, #194 may proceed alongside the retained-boundary work below;
it does not gate independent storage or broker-security changes.

### 3. Finish the retained security and performance boundary

After the PostgreSQL-only foundation, these issues may proceed independently where their files and
state machines do not conflict. #192, #208, #211, and #212 are complete. #209 must finish the
measured resource envelope for the deployment proof; #241 must close the documented KMS boundary
before a multi-workspace production claim.

- [#192](https://github.com/Dharin-shah/vouchr/issues/192) is complete: credential lifecycle
  mutations are atomic and idempotent across replicas and retries.
- [#208](https://github.com/Dharin-shah/vouchr/issues/208) is complete: audit indexes are measured and
  retention pruning is bounded.
- [#209](https://github.com/Dharin-shah/vouchr/issues/209): bound network, memory, database, and
  concurrency work and remove N+1 behavior.
- [#211](https://github.com/Dharin-shah/vouchr/issues/211) is complete: one strict provider, OAuth,
  and egress validation boundary is enforced.
- [#212](https://github.com/Dharin-shah/vouchr/issues/212) is complete: short-lived broker identity is
  deployment-bound with safe rotation and cross-replica replay protection.
- [#241](https://github.com/Dharin-shah/vouchr/issues/241): extend the KMS-envelope boundary to
  multi-workspace Slack installation tokens and prove migration/rotation behavior.

### 4. Prove one production deployment

- [#239](https://github.com/Dharin-shah/vouchr/issues/239): add deployment-wide containment and
  credential invalidation before exercising the compromise/recovery drill below.
- [#216](https://github.com/Dharin-shah/vouchr/issues/216): ship and exercise the exact image with
  PostgreSQL, KMS, two replicas, restore/failover, rolling upgrade, dependency failure, graceful
  drain, and representative load.
- [#217](https://github.com/Dharin-shah/vouchr/issues/217): require one reviewed, protected, scanned,
  reproducible build and release gate.

### 5. Obtain independent assurance and release

- Freeze one commit, image digest, identity-minter build, and production-like configuration.
- [#225](https://github.com/Dharin-shah/vouchr/issues/225): commission one source-assisted security
  assessment, remediate findings, and independently retest every high or critical fix.
- Complete the production-release stage of #223 using the assessed artifact or a reviewed
  remediation-only descendant.

## Definition of production-ready

Vouchr is production-ready only when all of the following are evidenced:

1. A patched maintenance release and coordinated advisories protect current users.
2. The canonical implementation and operations issues in #226 are complete.
3. The shared edge-case matrix passes with no external network against local real PostgreSQL,
   through the packed public API, and in the focused staging deployment as appropriate.
4. The exact image passes the two-replica restore, failover, rolling-upgrade, dependency-failure,
   graceful-drain, and load proof.
5. Independent assessment has no unresolved high or critical finding and remediation has passed
   retest.
6. The reviewed assessed artifact is published with accurate upgrade, support, and security
   guidance.

Green CI, high coverage, or an automated scanner alone is not production readiness.

## Scope and issue discipline

Future reviews should map observations to the canonical work in #226. A new launch-blocking issue
must include all of:

1. a defined attacker or failure source;
2. concrete prerequisites;
3. a reachable path in the supported product;
4. material externally observable impact;
5. a reproduction, regression test, or equivalent evidence;
6. proof that no canonical issue already owns it.

Test permutations belong in the shared edge-case matrix. Refactor preferences, governance
preferences, hypothetical future scale, and defense-in-depth without a concrete path are comments
or post-launch ideas—not new production blockers.

## Decision test for future features

Before adding a feature, answer yes to all of these:

- Does it strengthen the Slack-to-provider credential boundary or remove work every adopter must
  otherwise implement?
- Can the credential remain unreachable to the model, schemas, transcript, and application logs?
- Is authorization understandable to the affected human and enforceable at the server mutation?
- Can it work correctly with multiple PostgreSQL-backed replicas without a new state platform?
- Is the user need concrete enough to justify its security, UX, operational, and maintenance cost?
- Can it be tested through the public behavior and operated through the one supported deployment?

If not, Vouchr should remain smaller.
