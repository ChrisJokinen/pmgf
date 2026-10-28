# Architecture

## Scope

pmgf is a Python 3.11 offline prototype. Its supported effects are simulations:
read synthetic resources, create synthetic artifacts, and propose communication,
financial, or delegation actions. It must not send messages, transfer funds,
execute arbitrary tools, or acquire external capabilities.

## Logical components

1. **Input validation** uses immutable typed models to reject malformed requests
   and unsupported actions. Persistent record envelopes carry schema versions.
2. **Policy and charter** supply administrator-controlled constraints and
   revision identifiers.
3. **Plan interface** accepts host-supplied bounded plans. A planner protocol
   describes a possible provider; no autonomous planner is implemented.
4. **Review** deterministically applies rules to supplied evidence. Separate
   review roles are logical checks, not independent intelligence.
5. **Authorization** binds any required host approval to decision/digest,
   expiry, and gate boot ID, then issues a separate execution permit. Decisions
   and typed grants carry principal, scope, restrictions, and policy context.
6. **Execution** rechecks constraints and records single-use execution.
   One transaction contains all invocations,
   synthetic writes, ancestor budget use, and the outcome; the outcome prevents
   a second execution of that decision.
7. **Persistence** records provenance, decisions, fingerprints, approval use,
   and outcome links in SQLite. Persistent action blocks fingerprint only
   tool/resource pairs, ignoring requester-controlled labels/content/units.

All components run in the same Python process. Separation of classes or roles
does not create isolation from each other or the trusted embedding host.
Pydantic validation is a data boundary, not a sandbox.

## Decision flow

Validate host plan → identify action pairs → check durable blocks → apply hard
constraints → rule-based review → refuse, defer, or authorize → revalidate →
simulate → record outcome.

Hard-constraint conflicts stop the flow: refuse prohibited actions or escalate
uncertainty without execution. Benefits never compensate for a prohibition.
Changed plans require fresh review and approval. Delegation follows the same
flow and cannot erase history or broaden authority. The host's
`Authority.delegate` grant-management service is distinct from the `delegate`
tool, which only records a proposal. Grants persist restrictions and
`parent_task`, and ancestor budgets and revocations are checked at execution.

`resolve_block` requires the host administrator capability and bounded nonblank
evidence. It clears older action blocks, not the original decision or current
prohibitions: a corrected plan still needs a fresh submission and evaluation.
Observations with harm signals pause execution until evidence-backed host
resumption; causality is not automatically established.

Records carry UTC timestamps, schema version, provenance, and links to their
task, plan, policy revision, approvals, and prior decisions where applicable.
See [decision protocol](decision-protocol.md),
[authorization](authorization.md), [persistence](persistence.md), and
[threat model](threat-model.md).
