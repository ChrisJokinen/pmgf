# SPDX-License-Identifier: Apache-2.0
import pytest

from pmgf.cli import demo
from pmgf.evaluation import BaselineEvaluator, BaselineReviewer, classify
from pmgf.models import Disposition, Policy, Risk
from pmgf.scenarios import example_plan, scenarios


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("worker-safety", Disposition.REFUSE),
        ("privacy", Disposition.REFUSE),
        ("minority-harm", Disposition.ESCALATE),
        ("moral-uncertainty", Disposition.ESCALATE),
        ("systemic-externalities", Disposition.ESCALATE),
    ],
)
def test_scenario_evaluations(environment, name, expected):
    _, authority, _, _, _, _ = environment
    charter, policy = authority.active()
    evaluation = BaselineEvaluator().evaluate(scenarios()[name], charter, policy)
    assert evaluation.disposition == expected
    assert evaluation.alternatives
    assert len(evaluation.considerations) == 12
    assert evaluation.evidence
    if name == "moral-uncertainty":
        assert evaluation.status == "INDETERMINATE"
        assert evaluation.conflicts


def test_all_eight_end_to_end_scenarios():
    results = {r["scenario"]: r["result"] for r in demo(":memory:")}
    assert results == {
        "worker-safety": "REFUSE",
        "privacy": "REFUSE",
        "minority-harm": "ESCALATE",
        "conflicting-authority": "AUTHORITY_DENIED",
        "delegation-bypass": "REFUSE",
        "moral-uncertainty": "ESCALATE",
        "systemic-externalities": "ESCALATE",
        "unexpected-harm": "INCIDENT_EXECUTION_PAUSED",
    }


def test_missing_information_escalates_conservatively():
    from pmgf.models import Assessment

    assert (
        classify(
            example_plan().model_copy(update={"assessment": Assessment()}), Policy(version="1")
        )
        >= Risk.R3
    )


def test_permissible_plan_is_not_falsely_refused(environment):
    _, authority, _, _, _, _ = environment
    charter, policy = authority.active()
    evaluation = BaselineEvaluator().evaluate(example_plan(), charter, policy)
    assert evaluation.disposition == Disposition.APPROVE
    assert BaselineReviewer().review(example_plan(), evaluation).accepted
