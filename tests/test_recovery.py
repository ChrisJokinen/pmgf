# SPDX-License-Identifier: Apache-2.0
import os
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import safe_plan

from pmgf.evaluation import BaselineEvaluator, BaselineReviewer
from pmgf.models import Action, GovernanceError
from pmgf.workflow import Workflow


def test_approval_is_invalid_after_recovery(environment):
    store, authority, workflow, admin, session, grant = environment
    plan = safe_plan(assessment=safe_plan().assessment.model_copy(update={"severity": 2}))
    decision = workflow.submit(session, grant, plan)
    approval = workflow.gate.approve(admin, decision)
    recovered = Workflow(store, authority, BaselineEvaluator(), BaselineReviewer())
    with pytest.raises(GovernanceError):
        recovered.gate.authorize(session, decision, plan, approval)
    fresh_approval = recovered.gate.approve(admin, decision)
    recovered.gate.authorize(session, decision, plan, fresh_approval)


def test_read_description_cannot_erase_refusal(environment):
    store, _, workflow, _, session, grant = environment
    unsafe = safe_plan(
        actions=(
            Action(tool="read_record", resource="synthetic/example", signals=frozenset({"unsafe"})),
        )
    )
    workflow.submit(session, grant, unsafe)
    disguised = safe_plan(
        actions=(
            Action(
                tool="read_record",
                resource="synthetic/example",
                synthetic_content="irrelevant altered description",
            ),
        )
    )
    decision = workflow.submit(session, grant, disguised)
    assert store.get(decision)["disposition"] == "DEFER"
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, decision, disguised)


def test_fingerprint_stable_across_hash_seeds():
    code = (
        "from pmgf.scenarios import example_plan; from pmgf.models import Action; "
        "p=example_plan().model_copy(update={'actions':(Action(tool='read_record', "
        "resource='synthetic/example', signals=frozenset({'one','two','three'})),)}); "
        "print(p.fingerprint)"
    )
    outputs = [
        subprocess.check_output(
            [sys.executable, "-c", code], env={**os.environ, "PYTHONHASHSEED": str(seed)}, text=True
        ).strip()
        for seed in range(3)
    ]
    assert len(set(outputs)) == 1


def test_real_database_reopen_can_execute_new_permit(tmp_path: Path):
    from datetime import timedelta

    from pmgf.authority import Authority
    from pmgf.models import Category, Charter, Grant, Policy, Principle, now
    from pmgf.persistence import Store

    path = str(tmp_path / "restart.sqlite")
    admin = object()
    store = Store(path)
    authority = Authority(store, admin, {"operator": "synthetic-only"})
    authority.configure(
        admin,
        Charter(
            version="1",
            principles=(
                Principle(id="safety", category=Category.HARD, statement="Protect people."),
            ),
        ),
        Policy(version="1"),
    )
    session = authority.authenticate("operator", "synthetic-only")
    grant = authority.issue(
        admin,
        Grant(
            principal="operator",
            tools=frozenset({"read_record"}),
            resources=frozenset({"synthetic/example"}),
            expires=now() + timedelta(hours=1),
            budget=10,
            charter_version="1",
            policy_version="1",
        ),
    )
    workflow = Workflow(store, authority, BaselineEvaluator(), BaselineReviewer())
    plan = safe_plan()
    decision = workflow.submit(session, grant, plan)
    permit = workflow.gate.authorize(session, decision, plan)
    store.close()
    reopened = Store(path)
    recovered_authority = Authority(reopened, object(), {"operator": "synthetic-only"})
    recovered_session = recovered_authority.authenticate("operator", "synthetic-only")
    recovered = Workflow(reopened, recovered_authority, BaselineEvaluator(), BaselineReviewer())
    with pytest.raises(GovernanceError):
        recovered.gate.execute(recovered_session, permit, plan)
    new_permit = recovered.gate.authorize(recovered_session, decision, plan)
    outcome = recovered.gate.execute(recovered_session, new_permit, plan)
    assert reopened.get(outcome)["status"] == "simulated"
    reopened.close()
