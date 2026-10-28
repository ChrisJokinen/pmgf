# SPDX-License-Identifier: Apache-2.0
from datetime import timedelta

import pytest
from conftest import safe_plan
from pydantic import ValidationError

from pmgf.evaluation import classify
from pmgf.models import Action, GovernanceError, Grant, Policy, Risk, now


@pytest.mark.parametrize(
    ("field", "value", "minimum"),
    [
        ("severity", 4, Risk.R4),
        ("likelihood", 3, Risk.R3),
        ("population", 100, Risk.R2),
        ("vulnerability", True, Risk.R2),
        ("reversible", False, Risk.R2),
        ("uncertainty", 3, Risk.R3),
        ("cascading", True, Risk.R3),
        ("sensitive_data", True, Risk.R2),
        ("authority_clear", False, Risk.R2),
    ],
)
def test_risk_factors(field, value, minimum):
    plan = safe_plan(assessment=safe_plan().assessment.model_copy(update={field: value}))
    assert classify(plan, Policy(version="1")) >= minimum


def test_resource_scope_is_a_risk_factor():
    plan = safe_plan(actions=(Action(tool="read_record", resource="synthetic/example", units=100),))
    assert classify(plan, Policy(version="1")) >= Risk.R2


def test_grant_risk_limit_is_not_overridden_by_approval(environment):
    _, authority, workflow, admin, session, _ = environment
    grant = authority.issue(
        admin,
        Grant(
            principal="operator",
            tools=frozenset({"read_record"}),
            resources=frozenset({"synthetic/example"}),
            budget=10,
            expires=now() + timedelta(hours=1),
            charter_version="1",
            policy_version="1",
            max_risk=Risk.R1,
        ),
    )
    plan = safe_plan(assessment=safe_plan().assessment.model_copy(update={"severity": 2}))
    decision = workflow.submit(session, grant, plan)
    approval = workflow.gate.approve(admin, decision)
    with pytest.raises(GovernanceError, match="risk exceeds"):
        workflow.gate.authorize(session, decision, plan, approval)


@pytest.mark.parametrize(
    "changes",
    [
        {"tool": "shell"},
        {"units": -1},
        {"units": True},
        {"resource": ""},
        {"synthetic_content": "x" * 513},
        {"unexpected": True},
    ],
)
def test_invalid_tool_input_rejected(changes):
    values = {"tool": "read_record", "resource": "synthetic/example", **changes}
    with pytest.raises(ValidationError):
        Action.model_validate(values)
