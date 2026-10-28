# SPDX-License-Identifier: Apache-2.0
"""Decision protocol orchestration; dispositions do not confer permission."""

from pmgf.authority import Authority
from pmgf.evaluation import BaselineEvaluator, Evaluator, Reviewer
from pmgf.gate import PERMITTED, Gate, action_keys
from pmgf.models import (
    Decision,
    Disposition,
    Evaluation,
    GovernanceError,
    Observation,
    Plan,
    Review,
    now,
)
from pmgf.persistence import Store


class Workflow:
    def __init__(
        self,
        store: Store,
        authority: Authority,
        evaluator: Evaluator | None,
        reviewer: Reviewer | None,
    ) -> None:
        self.store = store
        self.authority = authority
        self.evaluator = evaluator
        self.reviewer = reviewer
        self.gate = Gate(store, authority)

    def submit(self, session: object, grant_id: str, plan: Plan) -> str:
        plan = Plan.model_validate(plan.model_dump(mode="json"))
        try:
            with self.store.transaction():
                principal = self.authority.principal(session)
                self.authority.check(session, grant_id, plan)
                charter, policy = self.authority.active()
                request_id = self.store.append(
                    "decision_request",
                    {"principal": principal, "grant_id": grant_id},
                    links=(grant_id,),
                )
                plan_id = self.store.append(
                    "candidate_plan", plan.model_dump(mode="json"), links=(request_id,)
                )
                baseline = BaselineEvaluator().evaluate(plan, charter, policy)
                try:
                    if self.evaluator is None or self.reviewer is None:
                        raise GovernanceError("missing evaluation or review service")
                    evaluation = Evaluation.model_validate(
                        self.evaluator.evaluate(plan, charter, policy).model_dump(mode="json")
                    )
                    review = Review.model_validate(
                        self.reviewer.review(plan, evaluation).model_dump(mode="json")
                    )
                except Exception:
                    # Do not log exception content: provider failures may contain credentials.
                    evaluation = baseline.model_copy(
                        update={"status": "INDETERMINATE", "disposition": Disposition.DEFER}
                    )
                    review = Review(accepted=False, challenges=("invalid or unavailable service",))
                disposition = evaluation.disposition
                if baseline.disposition not in PERMITTED:
                    disposition = baseline.disposition
                elif evaluation.status == "INDETERMINATE":
                    disposition = Disposition.DEFER
                elif (not review.accepted or review.challenges) and disposition in PERMITTED:
                    disposition = Disposition.ESCALATE
                if self.gate._blocked(plan):
                    disposition = Disposition.DEFER
                risk = max(evaluation.risk, baseline.risk)
                evaluation_id = self.store.append(
                    "evaluation", evaluation.model_dump(mode="json"), links=(plan_id,)
                )
                review_id = self.store.append(
                    "review", review.model_dump(mode="json"), links=(evaluation_id,)
                )
                decision = Decision(
                    request_id=request_id,
                    plan_id=plan_id,
                    evaluation_id=evaluation_id,
                    review_id=review_id,
                    plan_digest=plan.fingerprint,
                    grant_id=grant_id,
                    principal=principal,
                    charter_version=charter.version,
                    policy_version=policy.version,
                    disposition=disposition,
                    risk=risk,
                    approval_required=risk >= policy.approval_risk,
                )
                decision_id = self.store.append(
                    "decision",
                    decision.model_dump(mode="json"),
                    links=(request_id, plan_id, evaluation_id, review_id),
                )
                if disposition not in PERMITTED:
                    self.store.append(
                        "action_block",
                        {"keys": sorted(action_keys(plan)), "created": now().isoformat()},
                        links=(decision_id,),
                    )
                return decision_id
        except GovernanceError as exc:
            self.authority.audit_denial("submit", str(exc))
            raise

    def observe(self, session: object, outcome_id: str, observation: Observation) -> str:
        observation = Observation.model_validate(observation.model_dump(mode="json"))
        with self.store.transaction():
            outcome = self.store.get(outcome_id, "execution_outcome")
            if outcome["principal"] != self.authority.principal(session):
                raise GovernanceError("outcome belongs to another principal")
            observation_id = self.store.append(
                "observed_outcome", observation.model_dump(mode="json"), links=(outcome_id,)
            )
            if observation.harm_signals:
                incident_id = self.store.append(
                    "incident",
                    {"observation_id": observation_id, "causality": "not established"},
                    links=(observation_id, outcome_id),
                )
                self.store.append(
                    "corrective_action",
                    {
                        "incident_id": incident_id,
                        "action": "pause and require host review",
                        "escalation_required": True,
                    },
                    links=(incident_id,),
                )
            return observation_id

    def resume(self, capability: object, incident_id: str, evidence: str) -> None:
        self.authority.require_admin(capability)
        if not evidence.strip() or len(evidence) > 4096:
            raise GovernanceError("bounded corrective evidence is required")
        with self.store.transaction():
            self.store.get(incident_id, "incident")
            corrective_id = self.store.append(
                "corrective_action",
                {
                    "incident_id": incident_id,
                    "action": "host-reviewed remediation",
                    "evidence": evidence,
                },
                links=(incident_id,),
            )
            self.store.append(
                "resumption",
                {"incident_id": incident_id, "corrective_id": corrective_id},
                links=(incident_id, corrective_id),
            )

    def resolve_block(self, capability: object, plan: Plan, evidence: str) -> None:
        self.authority.require_admin(capability)
        if not evidence.strip() or len(evidence) > 4096:
            raise GovernanceError("bounded resolution evidence is required")
        with self.store.transaction():
            for key in action_keys(plan):
                self.store.append(
                    "block_resolution",
                    {"key": key, "evidence": evidence, "created": now().isoformat()},
                )

    def reverse_record(self, capability: object, record_id: str, evidence: str) -> str:
        self.authority.require_admin(capability)
        if not evidence.strip() or len(evidence) > 4096:
            raise GovernanceError("bounded correction evidence is required")
        with self.store.transaction():
            self.store.get(record_id, "synthetic_record")
            return self.store.append(
                "synthetic_record_reversal",
                {"record_id": record_id, "evidence": evidence},
                links=(record_id,),
            )
