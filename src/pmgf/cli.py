# SPDX-License-Identifier: Apache-2.0
"""Offline synthetic scenario runner; never sends or spends anything."""

import argparse
import json
import secrets
from datetime import timedelta

from pmgf.authority import Authority
from pmgf.evaluation import BaselineEvaluator, BaselineReviewer
from pmgf.models import (
    Category,
    Charter,
    GovernanceError,
    Grant,
    Observation,
    Policy,
    Principle,
    Risk,
    now,
)
from pmgf.persistence import Store
from pmgf.scenarios import example_plan, scenarios
from pmgf.workflow import Workflow


def demo(database: str) -> list[dict[str, str]]:
    store = Store(database)
    try:
        if store.records("governance_change"):
            raise GovernanceError("demo requires a fresh database; choose a new path")
        admin = object()
        credential = secrets.token_urlsafe(32)
        authority = Authority(
            store, admin, {"synthetic-operator": credential, "synthetic-child": credential}
        )
        authority.configure(
            admin,
            Charter(
                version="0.1.0",
                principles=(
                    Principle(
                        id="safety", category=Category.HARD, statement="Do not endanger people."
                    ),
                    Principle(id="privacy", category=Category.STRONG, statement="Minimize data."),
                    Principle(
                        id="fairness",
                        category=Category.CONTEXTUAL,
                        statement="Consider distribution of benefits and harms.",
                    ),
                    Principle(
                        id="efficiency",
                        category=Category.PREFERENCE,
                        statement="Prefer efficient permissible plans.",
                    ),
                ),
            ),
            Policy(version="0.1.0"),
        )
        session = authority.authenticate("synthetic-operator", credential)
        candidates = scenarios()
        grant_id = authority.issue(
            admin,
            Grant(
                principal="synthetic-operator",
                tools=frozenset(
                    {"read_record", "create_record", "propose_message", "financial", "delegate"}
                ),
                resources=frozenset(
                    a.resource
                    for name, plan in candidates.items()
                    if name != "conflicting-authority"
                    for a in plan.actions
                ),
                expires=now() + timedelta(hours=1),
                budget=100,
                max_risk=Risk.R3,
                charter_version="0.1.0",
                policy_version="0.1.0",
            ),
        )
        workflow = Workflow(store, authority, BaselineEvaluator(), BaselineReviewer())
        results = []
        parent_decision = workflow.submit(session, grant_id, example_plan())
        for name, plan in candidates.items():
            active_session = session
            active_grant = grant_id
            if name == "delegation-bypass":
                parent = Grant.model_validate(store.get(grant_id))
                child = parent.model_copy(
                    update={
                        "principal": "synthetic-child",
                        "parent": grant_id,
                        "parent_task": store.get(parent_decision)["request_id"],
                        "budget": 10,
                    }
                )
                active_grant = authority.delegate(session, grant_id, child)
                active_session = authority.authenticate("synthetic-child", credential)
            try:
                decision_id = workflow.submit(active_session, active_grant, plan)
                disposition = store.get(decision_id)["disposition"]
                if name == "unexpected-harm":
                    permit = workflow.gate.authorize(active_session, decision_id, plan)
                    outcome = workflow.gate.execute(active_session, permit, plan)
                    workflow.observe(
                        active_session,
                        outcome,
                        Observation(
                            observed_outcomes=("Unexpected synthetic harm signal",),
                            confidence="low",
                            evidence=("synthetic-monitor-v1",),
                            harm_signals=("unexpected effect",),
                        ),
                    )
                    disposition = "INCIDENT_EXECUTION_PAUSED"
                results.append({"scenario": name, "result": disposition})
            except GovernanceError:
                results.append({"scenario": name, "result": "AUTHORITY_DENIED"})
        store.verify()
        return results
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="PMGF synthetic governance demonstrations")
    commands = parser.add_subparsers(dest="command", required=True)
    demo_parser = commands.add_parser("demo", help="run eight offline synthetic scenarios")
    demo_parser.add_argument("--database", default=":memory:", help="fresh SQLite path")
    args = parser.parse_args()
    try:
        print(json.dumps(demo(args.database), indent=2))
    except GovernanceError as exc:
        parser.exit(1, f"PMGF: {exc}\n")
