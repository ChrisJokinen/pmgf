# SPDX-License-Identifier: Apache-2.0
"""Deterministic baselines, not a general moral reasoner or evidence oracle."""

from typing import Protocol

from pmgf.models import Charter, Disposition, Evaluation, Plan, Policy, Review, Risk

CONSIDERATIONS = (
    "human safety",
    "rights and autonomy",
    "privacy",
    "fairness",
    "exploitation",
    "distribution of benefits and harms",
    "direct consequences",
    "indirect consequences",
    "cumulative and systemic consequences",
    "uncertainty",
    "reversibility",
    "alternatives",
)


class Planner(Protocol):
    def propose(self, objective: str) -> tuple[Plan, ...]: ...


class Evaluator(Protocol):
    def evaluate(self, plan: Plan, charter: Charter, policy: Policy) -> Evaluation: ...


class Reviewer(Protocol):
    def review(self, plan: Plan, evaluation: Evaluation) -> Review: ...


def classify(plan: Plan, policy: Policy) -> Risk:
    a = plan.assessment
    factors = a.model_dump()
    if any(v is None for v in factors.values()):
        return max(policy.missing_information_risk, Risk.R3)
    level = max(a.severity or 0, a.likelihood or 0, a.uncertainty or 0)
    if (
        a.vulnerability
        or not a.reversible
        or a.cascading
        or a.sensitive_data
        or not a.authority_clear
        or (a.population or 0) >= policy.population_threshold
        or sum(action.units for action in plan.actions) >= policy.resource_threshold
    ):
        level = max(level, 2)
    if a.cascading or (a.uncertainty or 0) >= 3:
        level = max(level, 3)
    return Risk(level)


class BaselineEvaluator:
    def evaluate(self, plan: Plan, charter: Charter, policy: Policy) -> Evaluation:
        signals = set().union(*(a.signals for a in plan.actions))
        violations = tuple(sorted(signals & charter.prohibited_signals))
        missing = tuple(k for k, v in plan.assessment.model_dump().items() if v is None)
        conflicts = plan.competing_values
        risk = classify(plan, policy)
        disposition = Disposition.APPROVE
        if violations:
            disposition = Disposition.REFUSE
        elif missing or not plan.evidence or not plan.affected_parties:
            disposition = Disposition.DEFER
        elif conflicts or "minority_harm" in signals or "systemic" in signals:
            disposition = Disposition.ESCALATE
        elif risk > policy.maximum_risk:
            disposition = Disposition.REFUSE
        elif risk >= policy.approval_risk:
            disposition = Disposition.APPROVE_WITH_CONDITIONS
        return Evaluation(
            status="INDETERMINATE" if missing or conflicts else "DETERMINATE",
            disposition=disposition,
            risk=risk,
            evidence=plan.evidence,
            assumptions=plan.assumptions,
            uncertainty=missing
            + (("supplied evidence is not independently verified",) if not violations else ()),
            value_judgments=("Protected rights are not exchangeable for aggregate benefit.",),
            violations=violations,
            conflicts=conflicts,
            considerations=CONSIDERATIONS,
            alternatives=(
                "Retain safety provisions; use a reversible synthetic pilot.",
                "Minimize data and use aggregate synthetic records.",
                "Seek affected-party review before revising the plan.",
            ),
        )


class BaselineReviewer:
    def review(self, plan: Plan, evaluation: Evaluation) -> Review:
        challenges = []
        flagged = set().union(*(action.signals for action in plan.actions)) & {
            "conflict_of_interest",
            "externality",
            "policy_evasion",
            "evidence_gap",
            "misleading_assumption",
            "inconsistent_principles",
            "better_alternative",
            "reviewer_compromised",
            "prompt_injection",
        }
        challenges.extend(sorted(flagged))
        if not plan.affected_parties:
            challenges.append("omitted affected parties")
        if not evaluation.evidence:
            challenges.append("missing evidence")
        if plan.assumptions:
            challenges.append("assumptions require verification")
        if plan.dependencies:
            challenges.append("dependencies require verification")
        if plan.potential_risks:
            challenges.append("declared potential risks require review")
        if plan.competing_values:
            challenges.append("unresolved competing values")
        if len(evaluation.considerations) < len(CONSIDERATIONS):
            challenges.append("omitted consequences or principles")
        if evaluation.violations and evaluation.disposition in (
            Disposition.APPROVE,
            Disposition.APPROVE_WITH_CONDITIONS,
        ):
            challenges.append("policy evasion")
        return Review(accepted=not challenges, challenges=tuple(challenges))
