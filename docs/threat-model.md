# Threat model

## Scope, assets, and adversaries

The protected assets are the charter and policy revisions, bounded authority,
synthetic resources, plan integrity, durable task decisions, single-use
approvals, provenance, and the integrity and confidentiality of audit records.
Real credentials, funds, personal data, and external services are deliberately
excluded from supported operation.

Potential adversaries include a requester submitting misleading evidence, an
agent producing an unsafe plan, a delegate trying to broaden scope, and an
operator accidentally reusing approvals or mishandling records. A malicious
embedding host or administrator can defeat the implementation and is outside
the enforceable trust boundary.

## Boundaries

- **Requester → validated records:** input is untrusted; validation does not
  make factual claims true.
- **Plan → review → authorization → simulation:** each transition must preserve
  exact plan identity and policy context.
- **Parent → delegate:** authority may narrow, never expand; task history must
  remain linked.
- **Process → SQLite:** persistence preserves state across ordinary restarts,
  but filesystem access remains under host control.
- **Administrator → charter/policy:** revision authority belongs to the trusted
  host administrator, not synthetic actors.

All logical components share one Python process. There is no process isolation,
human authentication, network sandbox, real-tool adapter, or cryptographic
external trust anchor.

## Attack paths, mitigations, and residual risks

| Threat and affected assets | Attack path | Required mitigation | Residual risk |
| --- | --- | --- | --- |
| Prompt injection; policy and authority | Instructions embedded in task text or evidence claim higher authority | Treat content as data; use deterministic rules and explicit typed permissions; never derive admin rights from prose | Semantically misleading content can still influence supplied evidence |
| Identity spoofing; approvals and attribution | Requester supplies another actor's identifier | Host-configured synthetic credentials produce opaque in-memory sessions; bind decisions and grants to session principals | No authentication of real humans; a compromised host can impersonate anyone |
| Unauthorized policy change; charter | Agent submits a permissive revision or claims an emergency override | Trusted-admin-only revision path; version and attribute changes; approvals cannot override prohibitions | Host admin can edit code or storage outside the model |
| Constraint trade-off; safety gates | A high benefit score offsets a hard prohibition | Hard constraints precede scoring; refuse or escalate conflicts | Rules may omit a real-world hazard |
| Evidence laundering; review quality | Fabricated or selectively omitted facts appear in a benign-looking plan | Preserve provenance, report missing evidence, defer uncertainty, and avoid oracle claims | Rule-based review cannot establish truth or discover every omission |
| Reviewer collusion or common-mode error; decisions | Logical reviewers repeat the same mistaken assumption | Disclose deterministic rule-based review; test rules and disagreement paths | Same-process reviewers are not genuinely independent |
| Approval replay; authorization | Reuse a permit for another execution or after restart | Bind approval to decision/digest and current gate `boot_id`; bind authorization to principal/digest/decision/expiry/boot; durable execution outcome blocks all subsequent executions of that decision | Host clock and transaction correctness remain trusted; gate reconstruction invalidates approvals and permits even without a process restart |
| Plan substitution / time-of-check-time-of-use; plan integrity | Change action, resources, or policy context after approval | Canonical exact-plan digest; recheck current policy and prerequisites immediately before simulation; require fresh approval after changes | Same-process or host compromise can bypass checks |
| Retry laundering; durable task decisions | Change task ID, wording, labels, units, or restart after refusal/deferral | Persist action-block fingerprints of tool/resource pairs for every non-permitted decision; check blocks on submission and execution across actors/grants | Coarse blocks can reject benign work on the same pair; a different tool/resource pair is not recognized as semantic equivalence |
| Delegation laundering; bounded authority | Child task relabels a refused request or asks for broader permissions | Typed grants carry restrictions and `parent_task`; require permitted parent task, attenuate scope/expiry/budget/risk, recheck ancestor grants and global action blocks | No explicit depth cap; lineage walks and historical scans can grow; evidence and policy coverage remain imperfect |
| Scope escape / real-tool misuse; resources | Path traversal, unsupported tool request, or proposal treated as executable | Validate bounded synthetic resource references; reject unsupported actions; no external-effect adapters | No OS/network sandbox; host code could add unsafe adapters |
| Audit alteration or deletion; provenance | Edit database rows or recompute chain after rewriting history | Append-only application API, transactional linked records, internal hash-chain verification | Not tamperproof: privileged file access can rewrite or truncate the entire history |
| Sensitive-data exposure; confidentiality | Put secrets or personal information into durable task/evidence records | Synthetic-only inputs, restricted host access, minimize recorded content | No automated deletion; records may persist in database copies and backups |
| Resource exhaustion; availability | Oversized requests, long delegation chains, repeated proposals, growing logs | Bound selected strings, plan action count, grant budgets, and numeric inputs; detect lineage cycles; operators must bound runs and storage | No explicit delegation-depth cap or global record quota; full historical scans and storage growth can exhaust resources |
| Crash or concurrency error; approvals and history | Interrupt consumption/recording or race competing execution attempts | Use SQLite transactions and durable consumption; fail closed on inconsistent state | Requires implementation verification; no exactly-once guarantee for future real-world effects |
| Unsafe resumption; incident and task restrictions | Operator clears a pause/block without correcting underlying conditions | Require admin capability and bounded nonblank evidence for `resume`/`resolve_block`; append correction records; continue ordinary gate checks and re-evaluate resolved requests | Evidence is a host assertion, not independently verified; clearing a block alone cannot make an old non-permitted decision executable |

## Assurance limits

Risk estimates reflect supplied evidence and explicit rules, not access to
ground truth. Tests can demonstrate selected invariants, not prove absence of
unsafe behavior. Production deployment would require a new threat model,
authenticated identities, enforceable isolation, external trust mechanisms,
and independently assessed adapters; those are not current capabilities.

The host `authority.delegate` service creates attenuated grants; the simulated
`delegate` tool only records a proposal and never calls that service. All
synthetic tool invocations, record writes, budget charges, and execution
outcomes commit or roll back together in one SQLite transaction.
