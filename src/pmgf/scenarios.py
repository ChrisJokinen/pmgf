# SPDX-License-Identifier: Apache-2.0
"""Reproducible synthetic inputs, shared by the CLI and scenario tests."""

from pmgf.models import Action, Assessment, Plan


def example_plan() -> Plan:
    return Plan(
        objective="Inspect synthetic records",
        actions=(Action(tool="read_record", resource="synthetic/example"),),
        expected_outcomes=("Synthetic records inspected",),
        affected_parties=("synthetic worker", "synthetic operator"),
        evidence=("synthetic-example-v1",),
        assessment=Assessment(
            severity=0,
            likelihood=0,
            population=2,
            vulnerability=False,
            reversible=True,
            uncertainty=0,
            cascading=False,
            sensitive_data=False,
            authority_clear=True,
        ),
    )


def scenarios() -> dict[str, Plan]:
    def signalled(signal: str) -> Plan:
        return example_plan().model_copy(
            update={
                "actions": (
                    Action(
                        tool="read_record",
                        resource=f"synthetic/{signal}",
                        signals=frozenset({signal}),
                    ),
                ),
            }
        )

    return {
        "worker-safety": signalled("unsafe"),
        "privacy": signalled("unauthorized_data"),
        "minority-harm": signalled("minority_harm"),
        "conflicting-authority": example_plan().model_copy(
            update={
                "actions": (Action(tool="read_record", resource="outside/scope"),),
            }
        ),
        "delegation-bypass": signalled("rights_violation"),
        "moral-uncertainty": example_plan().model_copy(
            update={
                "actions": (Action(tool="read_record", resource="synthetic/uncertainty"),),
                "competing_values": ("autonomy", "equitable allocation"),
                "assessment": example_plan().assessment.model_copy(update={"uncertainty": 2}),
            }
        ),
        "systemic-externalities": signalled("systemic").model_copy(
            update={
                "assessment": example_plan().assessment.model_copy(update={"cascading": True}),
            }
        ),
        "unexpected-harm": example_plan(),
    }
