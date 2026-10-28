# SPDX-License-Identifier: Apache-2.0
"""Security boundary independent of evaluator recommendations.

The trusted host owns this object, its administrator capability and database.
Python object privacy is not a sandbox for malicious code in this process.
"""

from datetime import datetime, timedelta
from typing import Any

from pmgf.authority import Authority
from pmgf.evaluation import BaselineEvaluator
from pmgf.models import (
    Decision,
    Disposition,
    Evaluation,
    GovernanceError,
    Plan,
    Review,
    digest,
    identifier,
    now,
)
from pmgf.persistence import Store

PERMITTED = (Disposition.APPROVE, Disposition.APPROVE_WITH_CONDITIONS)


def action_keys(plan: Plan) -> set[str]:
    # Conservatively block the operation/resource, not requester-controlled descriptions.
    return {digest({"tool": a.tool, "resource": a.resource}) for a in plan.actions}


class Gate:
    def __init__(self, store: Store, authority: Authority) -> None:
        self.store = store
        self.authority = authority
        self.boot_id = identifier()
        with store.transaction():
            store.append("recovery", {"boot_id": self.boot_id, "unused_permits": "invalidated"})

    def _blocked(self, plan: Plan) -> bool:
        blocked: set[str] = set()
        # Record sequence, not a potentially adjusted host clock, orders supersession.
        for _, entry in self.store.records(("action_block", "block_resolution")):
            if "keys" in entry:
                blocked.update(entry["keys"])
            else:
                blocked.discard(entry["key"])
        return bool(blocked & action_keys(plan))

    def _healthy(self) -> None:
        resumed = {p["incident_id"] for _, p in self.store.records("resumption")}
        if any(i not in resumed for i, _ in self.store.records("incident")):
            raise GovernanceError("execution paused pending incident corrective action")

    def validate(
        self, session: object, decision_id: str, plan: Plan, approval_id: str | None
    ) -> tuple[Decision, list[str]]:
        plan = Plan.model_validate(plan.model_dump(mode="json"))
        decision = Decision.model_validate(self.store.get(decision_id, "decision"))
        charter, policy = self.authority.active()
        if decision.principal != self.authority.principal(session):
            raise GovernanceError("decision belongs to another principal")
        if decision.plan_digest != plan.fingerprint:
            raise GovernanceError("plan changed after evaluation")
        stored_plan = Plan.model_validate(self.store.get(decision.plan_id, "candidate_plan"))
        if stored_plan.fingerprint != plan.fingerprint:
            raise GovernanceError("decision and recorded plan differ")
        if (decision.charter_version, decision.policy_version) != (charter.version, policy.version):
            raise GovernanceError("stale policy or charter")
        evaluation = Evaluation.model_validate(self.store.get(decision.evaluation_id, "evaluation"))
        review = Review.model_validate(self.store.get(decision.review_id, "review"))
        baseline = BaselineEvaluator().evaluate(plan, charter, policy)
        if (
            decision.disposition not in PERMITTED
            or evaluation.disposition not in PERMITTED
            or evaluation.status != "DETERMINATE"
            or not review.accepted
            or review.challenges
            or evaluation.violations
            or evaluation.conflicts
            or baseline.disposition not in PERMITTED
            or baseline.risk > decision.risk
            or decision.risk > policy.maximum_risk
            or self._blocked(plan)
        ):
            raise GovernanceError("decision is not executable")
        self._healthy()
        lineage = self.authority.check(session, decision.grant_id, plan, decision.risk)
        if any(p["decision_id"] == decision_id for _, p in self.store.records("execution_outcome")):
            raise GovernanceError("decision already executed")
        if (
            decision.approval_required
            or decision.disposition == Disposition.APPROVE_WITH_CONDITIONS
            or decision.risk >= policy.approval_risk
        ):
            if approval_id is None:
                raise GovernanceError("trusted human approval required")
            approval = self.store.get(approval_id, "human_approval")
            if (
                approval["decision_id"] != decision_id
                or approval["plan_digest"] != plan.fingerprint
                or approval["boot_id"] != self.boot_id
                or datetime.fromisoformat(approval["expires"]) <= now()
            ):
                raise GovernanceError("forged, mismatched or stale approval")
        return decision, [record_id for record_id, _ in lineage]

    def approve(self, capability: object, decision_id: str) -> str:
        self.authority.require_admin(capability)
        with self.store.transaction():
            decision = Decision.model_validate(self.store.get(decision_id, "decision"))
            if decision.disposition not in PERMITTED:
                raise GovernanceError("cannot approve a non-permitted decision")
            _, policy = self.authority.active()
            return self.store.append(
                "human_approval",
                {
                    "decision_id": decision_id,
                    "plan_digest": decision.plan_digest,
                    "boot_id": self.boot_id,
                    "expires": (
                        now() + timedelta(seconds=policy.authorization_seconds)
                    ).isoformat(),
                    "source": "trusted-host-human-approval-adapter",
                },
                links=(decision_id,),
            )

    def authorize(
        self, session: object, decision_id: str, plan: Plan, approval_id: str | None = None
    ) -> str:
        try:
            with self.store.transaction():
                decision, _ = self.validate(session, decision_id, plan, approval_id)
                _, policy = self.authority.active()
                return self.store.append(
                    "authorization",
                    {
                        "decision_id": decision_id,
                        "plan_digest": plan.fingerprint,
                        "principal": decision.principal,
                        "approval_id": approval_id,
                        "boot_id": self.boot_id,
                        "expires": (
                            now() + timedelta(seconds=policy.authorization_seconds)
                        ).isoformat(),
                    },
                    links=(decision_id,) + ((approval_id,) if approval_id else ()),
                )
        except GovernanceError as exc:
            self.authority.audit_denial("authorize", str(exc))
            raise

    def execute(self, session: object, authorization_id: str, plan: Plan) -> str:
        try:
            with self.store.transaction():
                permit = self.store.get(authorization_id, "authorization")
                if (
                    permit["boot_id"] != self.boot_id
                    or datetime.fromisoformat(permit["expires"]) <= now()
                    or permit["plan_digest"] != plan.fingerprint
                ):
                    raise GovernanceError("expired, recovered or mismatched authorization")
                decision, ancestors = self.validate(
                    session, permit["decision_id"], plan, permit["approval_id"]
                )
                results: list[dict[str, Any]] = []
                for action in plan.actions:
                    invocation = self.store.append(
                        "tool_invocation",
                        {
                            "authorization_id": authorization_id,
                            "action": action.model_dump(mode="json"),
                            "simulated": True,
                        },
                        links=(authorization_id,),
                    )
                    result: dict[str, Any] = {
                        "tool": action.tool,
                        "external_effect": False,
                        "invocation_id": invocation,
                    }
                    if action.tool == "read_record":
                        reversed_ids = {
                            p["record_id"]
                            for _, p in self.store.records("synthetic_record_reversal")
                        }
                        result["records"] = [
                            p
                            for record_id, p in self.store.records("synthetic_record")
                            if p["resource"] == action.resource and record_id not in reversed_ids
                        ]
                    elif action.tool == "create_record":
                        result["record_id"] = self.store.append(
                            "synthetic_record",
                            {"resource": action.resource, "content": action.synthetic_content},
                            links=(invocation,),
                        )
                    else:
                        result["proposal"] = action.synthetic_content
                        result["units"] = action.units
                    results.append(result)
                self.store.append(
                    "budget_use",
                    {"grants": ancestors, "units": sum(a.units for a in plan.actions)},
                    links=tuple(ancestors),
                )
                return self.store.append(
                    "execution_outcome",
                    {
                        "decision_id": permit["decision_id"],
                        "authorization_id": authorization_id,
                        "expected_outcomes": plan.expected_outcomes,
                        "results": results,
                        "principal": decision.principal,
                        "status": "simulated",
                    },
                    links=(authorization_id, permit["decision_id"]),
                )
        except GovernanceError as exc:
            self.authority.audit_denial("execute", str(exc))
            raise
