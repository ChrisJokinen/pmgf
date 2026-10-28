# SPDX-License-Identifier: Apache-2.0
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from conftest import safe_plan

from pmgf.evaluation import BaselineEvaluator, BaselineReviewer
from pmgf.models import (
    Action,
    Decision,
    Disposition,
    GovernanceError,
    Grant,
    Observation,
    Policy,
    Review,
    now,
)
from pmgf.workflow import Workflow


def test_safe_execution_and_replay(environment):
    store, _, workflow, _, session, grant = environment
    plan = safe_plan()
    decision_id = workflow.submit(session, grant, plan)
    assert Decision.model_validate(store.get(decision_id)).disposition == Disposition.APPROVE
    permit = workflow.gate.authorize(session, decision_id, plan)
    result = workflow.gate.execute(session, permit, plan)
    assert store.get(result)["results"][0]["external_effect"] is False
    with pytest.raises(GovernanceError):
        workflow.gate.execute(session, permit, plan)
    assert store.records("authorization_denial")


def test_forged_identity(environment):
    _, authority, workflow, _, _, grant = environment
    with pytest.raises(GovernanceError):
        authority.authenticate("operator", "incorrect")
    with pytest.raises(GovernanceError):
        workflow.submit(object(), grant, safe_plan())


@pytest.mark.parametrize("change", ["resource", "tool", "content", "objective"])
def test_plan_mutation(environment, change):
    _, _, workflow, _, session, grant = environment
    plan = safe_plan()
    decision_id = workflow.submit(session, grant, plan)
    action = plan.actions[0]
    changes = {
        "resource": {"resource": "other"},
        "tool": {"tool": "create_record"},
        "content": {"synthetic_content": "changed"},
    }
    changed = (
        safe_plan(objective="changed")
        if change == "objective"
        else safe_plan(actions=(action.model_copy(update=changes[change]),))
    )
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, decision_id, changed)


def test_expired_grant(environment, monkeypatch):
    _, _, workflow, _, session, grant = environment
    import pmgf.authority

    monkeypatch.setattr(pmgf.authority, "now", lambda: now() + timedelta(days=1))
    with pytest.raises(GovernanceError):
        workflow.submit(session, grant, safe_plan())


def test_approval_is_structured_expiring_and_nontransferable(environment, monkeypatch):
    _, _, workflow, admin, session, grant = environment
    plan = safe_plan(assessment=safe_plan().assessment.model_copy(update={"severity": 2}))
    decision = workflow.submit(session, grant, plan)
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, decision, plan)
    with pytest.raises(GovernanceError):
        workflow.gate.approve(object(), decision)
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, decision, plan, "morally_approved=true")
    approval = workflow.gate.approve(admin, decision)
    second = workflow.submit(session, grant, plan)
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, second, plan, approval)
    permit = workflow.gate.authorize(session, decision, plan, approval)
    import pmgf.gate

    monkeypatch.setattr(pmgf.gate, "now", lambda: now() + timedelta(minutes=10))
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, decision, plan, approval)
    with pytest.raises(GovernanceError):
        workflow.gate.execute(session, permit, plan)


def test_policy_revision_invalidates_decision(environment):
    _, authority, workflow, admin, session, grant = environment
    plan = safe_plan()
    decision = workflow.submit(session, grant, plan)
    permit = workflow.gate.authorize(session, decision, plan)
    charter, _ = authority.active()
    authority.configure(admin, charter, Policy(version="2"))
    with pytest.raises(GovernanceError):
        workflow.gate.execute(session, permit, plan)


def test_restart_invalidates_unused_authorization(environment):
    store, authority, workflow, _, session, grant = environment
    plan = safe_plan()
    decision = workflow.submit(session, grant, plan)
    permit = workflow.gate.authorize(session, decision, plan)
    recovered = Workflow(store, authority, BaselineEvaluator(), BaselineReviewer())
    with pytest.raises(GovernanceError):
        recovered.gate.execute(session, permit, plan)
    replacement = recovered.gate.authorize(session, decision, plan)
    recovered.gate.execute(session, replacement, plan)


@pytest.mark.parametrize("missing", ["evaluator", "reviewer"])
def test_missing_services_fail_closed(environment, missing):
    store, _, workflow, _, session, grant = environment
    setattr(workflow, missing, None)
    plan = safe_plan()
    decision = workflow.submit(session, grant, plan)
    assert store.get(decision)["disposition"] == "DEFER"
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, decision, plan)


def test_invalid_evaluator_output(environment):
    class Invalid:
        def evaluate(self, *args):
            return {"morally_approved": True}

    store, _, workflow, _, session, grant = environment
    workflow.evaluator = Invalid()
    decision = workflow.submit(session, grant, safe_plan())
    assert store.get(decision)["disposition"] == "DEFER"


def test_compromised_evaluator_cannot_override_prohibition(environment):
    class Compromised:
        def evaluate(self, plan, charter, policy):
            return BaselineEvaluator().evaluate(safe_plan(), charter, policy)

    class Colluding:
        def review(self, *args):
            return Review(accepted=True)

    store, _, workflow, _, session, grant = environment
    workflow.evaluator = Compromised()
    workflow.reviewer = Colluding()
    plan = safe_plan(
        actions=(
            Action(tool="read_record", resource="synthetic/example", signals=frozenset({"unsafe"})),
        )
    )
    decision = workflow.submit(session, grant, plan)
    assert store.get(decision)["disposition"] == "REFUSE"
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, decision, plan)


def test_concurrent_requests_cannot_overspend(environment):
    store, authority, workflow, admin, session, _ = environment
    grant = authority.issue(
        admin,
        Grant(
            principal="operator",
            tools=frozenset({"read_record"}),
            resources=frozenset({"synthetic/example"}),
            budget=1,
            expires=now() + timedelta(hours=1),
            charter_version="1",
            policy_version="1",
        ),
    )
    plan = safe_plan()
    decisions = [workflow.submit(session, grant, plan) for _ in range(2)]
    permits = [workflow.gate.authorize(session, d, plan) for d in decisions]

    def execute(permit):
        try:
            workflow.gate.execute(session, permit, plan)
            return True
        except GovernanceError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(execute, permits)) == [False, True]
    assert len(store.records("execution_outcome")) == 1


def test_delegation_attenuation_and_revocation(environment):
    store, authority, workflow, admin, session, grant_id = environment
    decision_id = workflow.submit(session, grant_id, safe_plan())
    task = store.get(decision_id)["request_id"]
    parent = Grant.model_validate(store.get(grant_id))
    child = parent.model_copy(update={"parent": grant_id, "parent_task": task, "budget": 10})
    child_id = authority.delegate(session, grant_id, child)
    assert store.records("delegation")
    with pytest.raises(GovernanceError):
        authority.delegate(session, grant_id, child.model_copy(update={"budget": 101}))
    with pytest.raises(GovernanceError):
        authority.delegate(
            session,
            grant_id,
            child.model_copy(
                update={"restrictions": frozenset(), "resources": frozenset({"elsewhere"})}
            ),
        )
    authority.revoke(admin, grant_id)
    with pytest.raises(GovernanceError):
        workflow.submit(session, child_id, safe_plan())


def test_refusal_cannot_be_laundered_by_relabel_or_delegation(environment):
    store, authority, workflow, _, session, grant_id = environment
    unsafe = safe_plan(
        actions=(
            Action(tool="read_record", resource="synthetic/example", signals=frozenset({"unsafe"})),
        )
    )
    decision = workflow.submit(session, grant_id, unsafe)
    parent = Grant.model_validate(store.get(grant_id))
    child = parent.model_copy(
        update={
            "parent": grant_id,
            "parent_task": store.get(decision)["request_id"],
            "budget": 1,
        }
    )
    with pytest.raises(GovernanceError):
        authority.delegate(session, grant_id, child)
    relabelled = workflow.submit(session, grant_id, safe_plan(objective="different identifier"))
    assert store.get(relabelled)["disposition"] == "DEFER"


def test_cross_principal_isolation(environment):
    _, authority, workflow, _, session, grant = environment
    other = authority.authenticate("subordinate", "synthetic-child-only")
    with pytest.raises(GovernanceError):
        workflow.submit(other, grant, safe_plan())
    assert authority.principal(session) == "operator"


def test_unexpected_harm_pauses_and_requires_host_resumption(environment):
    store, _, workflow, admin, session, grant = environment
    plan = safe_plan()
    decision = workflow.submit(session, grant, plan)
    outcome = workflow.gate.execute(session, workflow.gate.authorize(session, decision, plan), plan)
    workflow.observe(
        session,
        outcome,
        Observation(
            observed_outcomes=("Unexpected synthetic harm",),
            confidence="low",
            evidence=("synthetic observation",),
            harm_signals=("unexpected effect",),
        ),
    )
    incident = store.records("incident")[0][0]
    next_decision = workflow.submit(session, grant, plan)
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, next_decision, plan)
    with pytest.raises(GovernanceError):
        workflow.resume(object(), incident, "reviewed")
    workflow.resume(admin, incident, "Synthetic remediation independently reviewed by host")
    permit = workflow.gate.authorize(session, next_decision, plan)
    workflow.gate.execute(session, permit, plan)
    assert store.get(incident)["causality"] == "not established"
