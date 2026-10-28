# Authorization

The trusted host configures synthetic principal/credential pairs.
`Authority.authenticate` checks these and returns opaque in-memory session
objects. These checks exercise authorization logic; they do not authenticate
real people or establish legal authority. Administrator operations require
the host's distinct object-identity capability.

## Permit contract

An administrator-created `human_approval` binds the decision ID, exact plan
digest, current gate `boot_id`, and UTC expiry. Its source is the trusted host
adapter, not an independently authenticated human. A separate `authorization`
record binds decision, digest, principal, optional approval ID, boot ID, and
expiry. The linked decision/grant supplies scope and policy context.

Execution records an `execution_outcome` in the same SQLite transaction as all
synthetic effects and budget use. The gate rejects any further execution of
that decision, including through another approval or authorization. This is
the single-use mechanism, not a mutable "consumed" flag on the approval.

Before simulation, reject absent, expired, used, mismatched, or invalidated
permits. A changed plan requires a new digest, review, and approval. Unused
permits and approvals are invalidated by a new gate `boot_id` on restart or
gate reconstruction; persisted records are not restart-surviving capabilities.

Approval never bypasses a refusal, unresolved deferral, inherited delegation
restriction, or hard constraint. No human authority can approve an exception
to a prohibition. Ambiguous authority or conflicting constraints require
refusal or escalation without execution.

Only the trusted administrator can revise policy or charter. A requester,
planner, reviewer, or delegate cannot grant itself that role through task
content. Administrator access to the host remains outside these logical checks.

Typed `Grant` records contain principal, allowed tools/resources, expiry,
budget, maximum risk, signal restrictions, charter/policy versions, and optional
`parent`/`parent_task`. The gate checks every ancestor for expiry, revocation,
active versions, restrictions, and budget. Child grants may only narrow scope,
expiry, budget, and maximum risk, and may only add restrictions.

The host clock is trusted for expiry. Digests bind content; without an external
trust anchor they do not prove who approved it or prevent privileged rewriting.
