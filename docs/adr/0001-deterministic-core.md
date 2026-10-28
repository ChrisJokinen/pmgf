# ADR 0001: Deterministic offline core

Status: accepted for prototype scope.

Decision date and approving maintainer: **[not yet recorded]**.

## Context

The project needs inspectable policy decisions and reproducible evaluation
without suggesting that an autonomous reviewer can establish safety or truth.
External effects would introduce identity, isolation, and operational risks
outside the prototype's current boundary.

## Decision

Use a Python 3.11 deterministic core, typed Pydantic records, and SQLite
persistence. Apply explicit rule-based review before bounded simulation.
Keep components in one process and acknowledge that they are not isolated.

Support only synthetic reads, artifact creation, and proposed communication,
financial, or delegation actions with no external effects. Bind approvals to
exact plans, scope, expiry, and per-decision single use; bind both approvals and
permits to a gate `boot_id` so restart invalidates them. Persist semantic task
identity as conservative tool/resource-pair action blocks, ignoring content,
signals, labels, and units, to prevent refusal/deferral laundering through
retries or delegation. Evidence-backed host resolution requires fresh
evaluation, not an override of old decisions or hard constraints.

Keep all synthetic effects, invocation records, ancestor budget charges, and
execution outcome in a single SQLite transaction. Separate proposal-only
`delegate` tool behavior from host `Authority.delegate` grant management.
Typed child grants retain restrictions and `parent_task` and cannot broaden
parent authority.

Hard constraints precede scoring. Conflicts are refused or escalated without
execution. Trusted administrators alone revise charter/policy; no human
approval overrides a prohibition.

Record UTC timestamps, schema versions, provenance, and linked audit events
through an append-only API with internal hash chaining. Use synthetic data
only because automated deletion is not provided.

## Consequences

The design favors reproducibility and traceability over open-ended autonomy.
It enables targeted tests but does not guarantee completeness of policy,
truth of evidence, authentic human identity, or independent review.

The embedding host and administrator remain trusted. SQLite hash chaining is
not tamperproof, and there is no cryptographic external trust anchor, network
sandbox, or real-tool support. Adding those requires a new decision and threat
model rather than silently widening this one.

## Alternatives

An unconstrained model-led executor and real-world adapters are excluded from
this prototype. Multiple same-process reviewers may organize checks but cannot
substitute for isolation or independent assurance.
