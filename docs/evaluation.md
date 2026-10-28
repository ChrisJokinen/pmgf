# Evaluation

Evaluate observable invariants using synthetic inputs and deterministic
expected outcomes. The intended implementation stack is Python 3.11,
Pydantic, SQLite, pytest, Ruff, and mypy. Use existing repository commands;
this document does not report executed tests or passing results.

## Required scenarios

| Area | Evidence to collect |
| --- | --- |
| Validation | Malformed records, unsupported actions, out-of-scope resources, and oversized inputs fail closed |
| Hard constraints | Prohibited and conflicting plans never execute despite utility, urgency, or approval |
| Review | Repeated equivalent inputs yield reproducible rule-based decisions; missing evidence is explicit |
| Authorization | Changed digests, wrong actors/scopes, expiry, replay, and restart-invalidated permits are rejected |
| Persistence | Non-permitted decisions block matching tool/resource pairs across new IDs, actors, content/signals/units changes, restarts, and delegation; evidence-backed block resolution still requires fresh evaluation |
| Delegation | Scope/expiry/budget/risk expansion and restriction removal are rejected; parent-task ownership, lineage cycles, ancestor revocation, and shared budgets are checked |
| Audit | Records have UTC timestamps, schema versions, provenance, valid links, and detectable chain inconsistencies |
| Transactions | Concurrent and interrupted operations cannot execute a decision twice; synthetic writes, invocations, ancestor budget use, and outcome remain atomic |
| Effect boundary | Successful actions alter synthetic state only; no messages, transfers, or real tools are invoked |

Separate unit checks from restart/integration scenarios. Record exact revision,
policy version, fixtures, commands, actual results, and known gaps. Include
negative tests and boundary cases, not only successful plans.

Passing checks establish behavior only for covered cases. Risk scores are
based on supplied evidence, not an oracle. Logical reviewer agreement is not
independent corroboration, and benchmark success does not establish safety for
real-world deployment.

The current baseline uses supplied severity, likelihood, population,
vulnerability, reversibility, uncertainty, cascading effects, sensitive-data,
and authority-clarity fields. Missing fields impose at least R3 and lead to
deferral. Prohibited signals refuse; declared conflicts, minority harm, or
systemic signals escalate. Reviewer challenges include unverified assumptions,
dependencies, declared risks, omitted affected parties, and missing evidence.
These are deterministic checks of declarations, not verification of facts or
full interpretation of charter prose.
