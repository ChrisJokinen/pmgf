# Glossary

| Term | Meaning |
| --- | --- |
| Actor | Synthetic identity supplied by the trusted embedding host; not an authenticated human |
| Administrator | Trusted host role permitted to revise charter/policy, not to approve prohibited execution |
| Charter | Versioned statement of purpose and binding constraints |
| Policy | Explicit rules applying charter constraints to a request and plan |
| Hard constraint | A prohibition or obligation that cannot be traded against benefits |
| Plan | Bounded description of proposed simulated actions, resources, and relevant context |
| Plan digest | Deterministic digest of an exact canonical plan used to bind authorization |
| Semantic task / action fingerprint | Persistent digest of a tool/resource pair; ignores task IDs, content, signals, labels, and units; not general natural-language equivalence |
| Refusal | Decision that a request or plan is prohibited; not reset by retry or delegation |
| Deferral | No-execution decision pending missing evidence or resolution of uncertainty |
| Escalation | Request for clarification or review; never permission to bypass a prohibition |
| Human approval | Host-admin record binding a permitted decision, exact digest, expiry, and gate boot ID; not authentication of a human |
| Authorization / permit | Separate expiring, boot-bound execution record; an outcome makes its decision single-use |
| Boot ID | New identifier for each gate instance, invalidating earlier approvals and authorizations |
| Block resolution | Host-admin evidence record clearing earlier action blocks; requires a corrected submission and fresh evaluation |
| Review | Deterministic rule-based assessment of supplied evidence, not independent intelligence |
| Delegation | Either a proposal-only tool action or a distinct host service issuing attenuated grants with parent-task links |
| Provenance | Recorded origin and links connecting inputs, revisions, decisions, approvals, and outcomes |
| Append-only API | Application interface adding records rather than silently rewriting history |
| Hash chain | Internal linkage useful for checking consistency, not a tamperproof external trust anchor |
| Simulation | Local synthetic state change or proposal with no real external effect |
