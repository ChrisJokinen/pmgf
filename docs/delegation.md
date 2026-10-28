# Delegation

The `delegate` tool is a simulated proposal only. It never invokes a remote
agent, communicates externally, or issues a grant. Separately, the embedding
host can call `Authority.delegate` to create an attenuated persistent grant.
Parent and child roles share one process and offer no isolation or independent
review.

A typed child `Grant` includes its synthetic principal, tools, resources,
expiry, budget, maximum risk, signal restrictions, policy/charter versions,
parent grant ID, and `parent_task` decision-request ID. The caller must own the
parent grant and have `delegate` permission. Child tools/resources, expiry,
budget, and risk cannot exceed the parent's; restrictions must include all
parent restrictions. The parent task must belong to that grant and have no
non-permitted decision.

Persistent parent/child links preserve lineage. Execution rechecks all ancestor
grants, including expiry/revocation, versions, restrictions, and aggregate budget
use; child expenditure also charges ancestors. Global action blocks apply to
children regardless of actor, wording, units, or task ID because their
fingerprints depend only on tool/resource pairs.

Delegation does not transfer a reusable approval. A child plan requiring
approval needs its own exact-plan, scoped, single-use, expiring authorization.
Neither actor can approve a prohibition away or revise policy.

There is no autonomous child-task runner or result propagation service. Results
and parent-task links are host-supplied evidence, not guaranteed facts.
Lineage checking detects cycles, but there is no explicit maximum depth.
Tool/resource matching is coarse and not a universal semantic-bypass detector.
