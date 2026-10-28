# Persistent Moral Governance Framework (PMGF)

**Version 0.1.0 — Experimental research prototype. Not production-certified.
Not a guarantee of AI alignment or safety.**

PMGF explores persistent governance of an agent's plans, authority, simulated
actions, and observed outcomes. Its purpose is to make constraints and decision
history explicit, rather than relying on prompt instructions or a model's
claim that an action is acceptable.

It does **not** establish consciousness, a conscience, moral truth, trustworthy
LLM reasoning, organizational endorsement, or sovereign authority over humans.
The baseline evaluator recognizes explicit structured signals; it cannot
discover hidden harms or verify the truth of supplied evidence.

## Architecture

```text
Trusted host: identities, admin capability, versioned charter/policy
    ↓
Explicit grants → candidate plans → evaluation → challenging review
    ↓                                 ↓
Exact-plan authorization gate ← persistent decision / optional host approval
    ↓
Bounded synthetic tools → atomic SQLite records → observations / incidents
```

The evaluator cannot grant permissions. The gate independently rechecks rules,
identity, scope, budget, risk, versions, approval, expiry, and replay state.
Only `APPROVE` and `APPROVE_WITH_CONDITIONS` can proceed to authorization.
All components share one trusted Python process: these are logical boundaries,
not isolation from malicious Python code or a database administrator.

## Install and quick start

Python 3.11+; no API credentials or AI provider required.
From the repository root:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install --no-build-isolation -e ".[dev]"
pytest -q
pmgf demo
```

Installation downloads dependencies. Once installed, the deterministic core,
tests, and demonstrations run without network access. Direct dependencies and
the tested development environment are pinned; this is not a hash-locked,
cross-platform supply-chain guarantee.

The demo runs all eight scenarios: worker safety, privacy, minority harm,
conflicting authority, delegation bypass, moral uncertainty, systemic
externalities, and unexpected harm. It prints structured results; no messages,
payments, physical effects, or shell commands are executed.

```sh
pmgf demo --database /tmp/pmgf-demo.sqlite
```

Use a **fresh** database path. The default is an in-memory database. A file
preserves the full demonstration, including an unresolved incident that pauses
execution. Reusing an existing governance database for a demo is rejected.

### Embedding example

```python
import secrets
from datetime import timedelta
from pathlib import Path

from pmgf.authority import Authority
from pmgf.evaluation import BaselineEvaluator, BaselineReviewer
from pmgf.models import Charter, Grant, Policy, now
from pmgf.persistence import Store
from pmgf.scenarios import example_plan
from pmgf.workflow import Workflow

store = Store(":memory:")
admin = object()  # Host capability: never hand this to a model.
credential = secrets.token_urlsafe(32)
authority = Authority(store, admin, {"synthetic-operator": credential})
authority.configure(
    admin,
    Charter.model_validate_json(Path("examples/charter.json").read_text()),
    Policy.model_validate_json(Path("examples/policy.json").read_text()),
)
session = authority.authenticate("synthetic-operator", credential)
grant = authority.issue(admin, Grant(
    principal="synthetic-operator",
    tools=frozenset({"read_record"}),
    resources=frozenset({"synthetic/example"}),
    expires=now() + timedelta(minutes=5),
    budget=10,
    charter_version="0.1.0",
    policy_version="0.1.0",
))
workflow = Workflow(store, authority, BaselineEvaluator(), BaselineReviewer())
plan = example_plan()
decision = workflow.submit(session, grant, plan)
permit = workflow.gate.authorize(session, decision, plan)
outcome = workflow.gate.execute(session, permit, plan)
print(store.get(outcome)["status"])  # simulated
store.close()
```

The synthetic identity adapter is not a production authentication service.
Only the trusted host may issue grants, revise governance, attest human
approval, resolve durable blocks, reverse synthetic records, or resume incidents.
Integrating genuine human identity/approval is outside this prototype.

## Development and tests

```sh
ruff check src tests
ruff format --check src tests
mypy src
pytest -q
pytest tests/test_scenarios.py -q
pytest tests/test_enforcement.py tests/test_recovery.py -q
```

Tests include unit, integration, scenario, and deterministic security
regressions; no LLM judges are used. CI runs these commands on Python 3.11 and
3.12. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Repository map

- `src/pmgf/`: models, SQLite store, authority, evaluation/review protocols,
  authorization/execution gate, workflow/monitoring, scenarios, CLI.
- `tests/`: foundation, enforcement, recovery, scenarios, and tools.
- `examples/`: validated sample charter, policy, and synthetic records.
- `docs/`: [architecture](docs/architecture.md),
  [charter](docs/charter.md), [decision protocol](docs/decision-protocol.md),
  [authorization](docs/authorization.md), [persistence](docs/persistence.md),
  [delegation](docs/delegation.md), [evaluation](docs/evaluation.md),
  [threat model](docs/threat-model.md), [limitations](docs/limitations.md),
  [roadmap](docs/roadmap.md), [glossary](docs/glossary.md), and [ADRs](docs/adr/).
- `.github/workflows/ci.yml`: least-privilege pinned-action CI.

## Security and maturity

No external-effect tool adapter exists. Reads access synthetic database records
only; create is reversible through a host-issued superseding record;
communication, financial, and delegation tools only record proposals.
Real delegation grants are a separate attenuating authority service.

Hard constraints cannot be overridden by aggregate utility or human approval.
Unresolved conflicts stop execution. Refusals/deferrals conservatively block
tool/resource pairs across new identifiers and delegates until a host records
resolution evidence; this can overblock legitimate revised work. Authorization
and required approvals expire, are bound to an exact plan, and cannot survive
gate recovery. A decision executes at most once.

SQLite transactions provide atomic synthetic effects, cumulative ancestor
budget accounting, and interruption safety. Hash chaining detects some
corruption; a database owner can rewrite or truncate the chain. Retention is
indefinite, with no automated deletion, encryption, or personal-data
redaction. Use synthetic data only and restrict database/backup access.
See [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md).

The next milestone is independent evidence validation, stronger host/process
isolation, externally anchored audit integrity, and richer reviewed policy
semantics—not real-world autonomous execution. Current limitations and
unfinished production capabilities are listed in [limitations](docs/limitations.md).

## License, attribution, and project administration

Software is [Apache-2.0](LICENSE); see [NOTICE](NOTICE),
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES), [AUTHORS.md](AUTHORS.md), and
[CITATION.cff](CITATION.cff). Dependencies retain their own licenses. External
prior work is identified separately from PMGF design decisions.

Maintainer contacts and citation authors are intentionally unassigned until
confirmed. Before public intake, configure a private security reporting route,
code-of-conduct contact, citation authors, branch protection, and required CI
checks. No package publication or external account configuration is performed
by this repository.