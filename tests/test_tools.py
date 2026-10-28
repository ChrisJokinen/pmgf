# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

import pytest
from conftest import safe_plan

from pmgf.authority import Authority
from pmgf.evaluation import BaselineEvaluator, BaselineReviewer
from pmgf.models import Action, Charter, GovernanceError, Grant, Policy
from pmgf.persistence import Store
from pmgf.workflow import Workflow


@pytest.mark.parametrize(
    "tool", ["read_record", "create_record", "propose_message", "financial", "delegate"]
)
def test_tools_require_gate_and_have_no_external_effects(environment, tool):
    store, _, workflow, _, session, grant = environment
    plan = safe_plan(
        actions=(
            Action(tool=tool, resource="synthetic/example", synthetic_content="synthetic content"),
        )
    )
    with pytest.raises(GovernanceError):
        workflow.gate.execute(session, "unrestricted", plan)
    decision = workflow.submit(session, grant, plan)
    permit = workflow.gate.authorize(session, decision, plan)
    outcome = workflow.gate.execute(session, permit, plan)
    result = store.get(outcome)["results"][0]
    assert result["external_effect"] is False
    assert store.get(result["invocation_id"], "tool_invocation")["simulated"] is True
    assert len(store.records("authority_grant")) == 1


def test_reversible_record(environment):
    store, _, workflow, admin, session, grant = environment
    plan = safe_plan(
        actions=(
            Action(
                tool="create_record",
                resource="synthetic/example",
                synthetic_content="synthetic content",
            ),
        )
    )
    decision = workflow.submit(session, grant, plan)
    outcome = workflow.gate.execute(session, workflow.gate.authorize(session, decision, plan), plan)
    record_id = store.get(outcome)["results"][0]["record_id"]
    with pytest.raises(GovernanceError):
        workflow.reverse_record(object(), record_id, "correct")
    workflow.reverse_record(admin, record_id, "Synthetic correction")
    assert store.get(record_id)["content"] == "synthetic content"
    read = safe_plan()
    decision = workflow.submit(session, grant, read)
    outcome = workflow.gate.execute(session, workflow.gate.authorize(session, decision, read), read)
    assert store.get(outcome)["results"][0]["records"] == []


def test_partial_execution_rolls_back_effect_budget_and_consumption(environment, monkeypatch):
    store, _, workflow, _, session, grant = environment
    plan = safe_plan(
        actions=(
            Action(tool="create_record", resource="synthetic/example", synthetic_content="first"),
            Action(tool="create_record", resource="synthetic/example", synthetic_content="second"),
        )
    )
    decision = workflow.submit(session, grant, plan)
    permit = workflow.gate.authorize(session, decision, plan)
    original = store.append

    def interrupt(kind, payload, **kwargs):
        if kind == "synthetic_record" and payload["content"] == "second":
            raise RuntimeError("simulated interruption")
        return original(kind, payload, **kwargs)

    monkeypatch.setattr(store, "append", interrupt)
    with pytest.raises(RuntimeError):
        workflow.gate.execute(session, permit, plan)
    assert not store.records("synthetic_record")
    assert not store.records("tool_invocation")
    assert not store.records("execution_outcome")
    assert not store.records("budget_use")
    monkeypatch.setattr(store, "append", original)
    workflow.gate.execute(session, permit, plan)
    assert len(store.records("synthetic_record")) == 2


def test_unconfigured_governance_is_fail_closed(tmp_path: Path):
    store = Store(str(tmp_path / "empty.sqlite"))
    authority = Authority(store, object(), {})
    workflow = Workflow(store, authority, BaselineEvaluator(), BaselineReviewer())
    with pytest.raises(GovernanceError):
        workflow.submit(object(), "missing", safe_plan())
    with pytest.raises(GovernanceError):
        authority.active()
    store.close()


def test_delegation_cycles_rejected(environment, monkeypatch):
    store, authority, _, _, _, grant_id = environment
    grant = Grant.model_validate(store.get(grant_id)).model_copy(
        update={
            "parent": grant_id,
            "parent_task": "synthetic-parent-task",
        }
    )
    # A cycle cannot be created through delegation; simulate corrupt service output.
    monkeypatch.setattr(store, "get", lambda *args: grant.model_dump(mode="json"))
    with pytest.raises(GovernanceError, match="cycle"):
        authority.lineage(grant_id)


def test_parent_restrictions_cannot_be_removed(environment):
    store, authority, workflow, admin, session, root_id = environment
    parent = Grant.model_validate(store.get(root_id)).model_copy(
        update={
            "restrictions": frozenset({"restricted"}),
        }
    )
    parent_id = authority.issue(admin, parent)
    decision = workflow.submit(session, parent_id, safe_plan())
    child = parent.model_copy(
        update={
            "parent": parent_id,
            "parent_task": store.get(decision)["request_id"],
            "restrictions": frozenset(),
        }
    )
    with pytest.raises(GovernanceError, match="increase authority"):
        authority.delegate(session, parent_id, child)
    assert store.records("authorization_denial")[-1][1]["operation"] == "delegate"


def test_evidence_backed_block_resolution_requires_reevaluation(environment):
    store, _, workflow, admin, session, grant = environment
    risky = safe_plan(
        actions=(
            Action(tool="read_record", resource="synthetic/example", signals=frozenset({"unsafe"})),
        )
    )
    refused = workflow.submit(session, grant, risky)
    with pytest.raises(GovernanceError):
        workflow.resolve_block(object(), risky, "evidence")
    workflow.resolve_block(admin, risky, "Synthetic correction verified")
    with pytest.raises(GovernanceError):
        workflow.gate.authorize(session, refused, risky)
    safe = safe_plan()
    fresh = workflow.submit(session, grant, safe)
    workflow.gate.authorize(session, fresh, safe)
    workflow.submit(session, grant, risky)
    blocked_again = workflow.submit(session, grant, safe)
    assert store.get(blocked_again)["disposition"] == "DEFER"


def test_example_configuration_validates():
    root = Path(__file__).resolve().parents[1]
    assert (
        Charter.model_validate_json((root / "examples/charter.json").read_text()).version == "0.1.0"
    )
    assert (
        Policy.model_validate_json((root / "examples/policy.json").read_text()).version == "0.1.0"
    )
    records = json.loads((root / "examples/records.json").read_text())
    assert records[0]["resource"].startswith("synthetic/")
