# SPDX-License-Identifier: Apache-2.0
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from pmgf.authority import Authority
from pmgf.evaluation import BaselineEvaluator, BaselineReviewer
from pmgf.models import (
    Action,
    Assessment,
    Category,
    Charter,
    Grant,
    Plan,
    Policy,
    Principle,
    Risk,
    now,
)
from pmgf.persistence import Store
from pmgf.workflow import Workflow


def safe_plan(**updates: object) -> Plan:
    data: dict[str, object] = {
        "objective": "Read synthetic example",
        "actions": (Action(tool="read_record", resource="synthetic/example"),),
        "expected_outcomes": ("Synthetic records read without external effects",),
        "affected_parties": ("synthetic operator",),
        "evidence": ("synthetic fixture",),
        "assessment": Assessment(
            severity=0,
            likelihood=0,
            population=1,
            vulnerability=False,
            reversible=True,
            uncertainty=0,
            cascading=False,
            sensitive_data=False,
            authority_clear=True,
        ),
    }
    data.update(updates)
    return Plan.model_validate(data)


@pytest.fixture
def environment(tmp_path: Path) -> Iterator[tuple[Store, Authority, Workflow, object, object, str]]:
    store = Store(str(tmp_path / "governance.sqlite"))
    admin = object()
    authority = Authority(
        store,
        admin,
        {
            "operator": "synthetic-test-only",
            "subordinate": "synthetic-child-only",
        },
    )
    authority.configure(
        admin,
        Charter(
            version="1",
            principles=(
                Principle(id="safety", category=Category.HARD, statement="Do not endanger people."),
            ),
        ),
        Policy(version="1"),
    )
    session = authority.authenticate("operator", "synthetic-test-only")
    grant_id = authority.issue(
        admin,
        Grant(
            principal="operator",
            tools=frozenset(
                {"read_record", "create_record", "financial", "propose_message", "delegate"}
            ),
            resources=frozenset({"synthetic/example"}),
            expires=now() + timedelta(hours=1),
            budget=100,
            max_risk=Risk.R3,
            charter_version="1",
            policy_version="1",
        ),
    )
    workflow = Workflow(store, authority, BaselineEvaluator(), BaselineReviewer())
    yield store, authority, workflow, admin, session, grant_id
    store.close()
