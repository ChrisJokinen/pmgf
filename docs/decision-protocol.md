# Decision protocol

1. Validate the request, schema version, synthetic actor, action vocabulary,
   resource scope, and evidence shape.
2. Check persistent action blocks. Their semantic fingerprint is deliberately
   coarse: hash each tool/resource pair, ignoring content, signals, labels,
   units, and objective. Any overlap blocks the plan across task IDs, actors,
   grants, delegation, and restarts. Every non-permitted decision adds blocks.
3. Accept a host-supplied bounded plan and compute its exact digest from the
   complete canonical serialized model. Record policy/charter revisions and
   evidence provenance. A planner protocol exists, not an autonomous planner.
4. Apply hard constraints first. Refuse a prohibited plan. Defer or escalate
   missing evidence and unresolved conflicts without executing.
5. Apply deterministic rule-based review. Report concerns and uncertainty.
   Numerical estimates, if present, cannot overrule hard constraints.
6. If eligible, obtain the trusted-admin approval required by risk or conditions,
   then request a separate execution authorization. Both bind to the exact
   plan/decision, expiry, and current gate `boot_id`. Approval is not permission
   to violate a prohibition.
7. Immediately before simulation, recheck policy, history, digest, scope,
   expiry, and permit status. Changed inputs require fresh review.
8. Atomically record all synthetic invocations, effects, ancestor budget use,
   and outcome in one SQLite transaction. The durable execution outcome marks
   the decision as executed, preventing reuse of any permit for that decision.

Dispositions are `APPROVE`, `APPROVE_WITH_CONDITIONS`, `REVISE`, `ESCALATE`,
`DEFER`, and `REFUSE`; only the first two are potentially executable. Approval
is not execution. Governance denials are audited; failed transactions roll back
effects rather than reporting success.

The host may call `resolve_block` with its administrator capability and bounded,
nonblank resolution evidence. This appends resolutions for the plan's action
keys; it does not change the old decision, validate the evidence, or perform
evaluation. Submit a corrected plan for fresh evaluation afterward. Later
non-permitted decisions create fresh blocks. Hard prohibitions remain binding.
This mechanism can overblock benign requests and does not recognize equivalent
objectives expressed through different tool/resource pairs.

After execution, `observe` records supplied outcomes, confidence, evidence,
and harm signals. Harm signals create an incident and pause execution globally;
causality is explicitly not established. Administrator `resume` requires
bounded corrective evidence and records remediation/resumption, without
disabling other checks.

Every decision records a UTC timestamp, schema version, provenance, reason,
and links to relevant task, plan, revisions, and prior records.
