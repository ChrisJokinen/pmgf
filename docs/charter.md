# Charter

## Purpose

Explore whether deterministic policy gates, bounded simulated agency, and
traceable records make proposed actions easier to inspect. This is a research
exercise, not a claim of alignment, independent judgment, or safe autonomy.

## Binding constraints

- Do not cause external effects: communication, finance, and delegation remain
  simulated proposals.
- Do not exceed granted resource scope or action permissions.
- Do not bypass a refusal, unresolved deferral, or required approval by
  relabeling, replanning, restarting, or delegating. The implementation uses
  durable operation/resource blocks; resolution requires administrator evidence
  and a fresh evaluation, never a permission override.
- Do not treat unknown evidence as proof of safety.
- Do not trade a hard constraint against utility, urgency, or another benefit.
- Do not allow any human authority, including an administrator, to override
  prohibitions through an approval.

Conflicting hard constraints require refusal or escalation, never an optimized
compromise that violates one of them. Escalation requests clarification or a
safe alternative; it does not permit execution.

## Governance

Only the trusted embedding administrator may revise charter or policy.
Agent-generated revisions are proposals only. Revisions must be explicit,
versioned, recorded with host provenance, and linked to subsequent decisions; they must not rewrite
historical records or silently clear task restrictions.

An administrator's ability to modify source code or storage is outside the
prototype's enforcement boundary, not an authorized policy-override mechanism.
Policy changes require review against these constraints rather than acting as
a per-task escape hatch.
