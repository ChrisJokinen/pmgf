# SPDX-License-Identifier: Apache-2.0
"""Validated, immutable values crossing governance boundaries."""

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator


def now() -> datetime:
    return datetime.now(UTC)


def identifier() -> str:
    return str(uuid4())


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class GovernanceError(Exception):
    """A fail-closed governance boundary rejected an operation."""


class Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_max_length=4096)


class Disposition(str, Enum):
    APPROVE = "APPROVE"
    APPROVE_WITH_CONDITIONS = "APPROVE_WITH_CONDITIONS"
    REVISE = "REVISE"
    ESCALATE = "ESCALATE"
    DEFER = "DEFER"
    REFUSE = "REFUSE"


class Risk(int, Enum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4


class Category(str, Enum):
    HARD = "hard_constraint"
    STRONG = "strong_presumption"
    CONTEXTUAL = "contextual_principle"
    PREFERENCE = "optimization_preference"


class Principle(Model):
    id: str
    category: Category
    statement: str


class Charter(Model):
    version: str = Field(min_length=1)
    principles: tuple[Principle, ...] = Field(min_length=1)
    prohibited_signals: frozenset[str] = frozenset(
        {"unsafe", "unauthorized_data", "exploitation", "rights_violation"}
    )
    objectives: tuple[str, ...] = ("Support human welfare without overriding protections.",)

    @field_serializer("prohibited_signals")
    def sorted_signals(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def unique_principles(self) -> "Charter":
        if len({p.id for p in self.principles}) != len(self.principles):
            raise ValueError("principle identifiers must be unique")
        if not any(p.category == Category.HARD for p in self.principles):
            raise ValueError("at least one hard constraint is required")
        return self


class Policy(Model):
    version: str = Field(min_length=1)
    approval_risk: Risk = Risk.R2
    maximum_risk: Risk = Risk.R3
    authorization_seconds: int = Field(default=60, ge=1, le=300)
    missing_information_risk: Risk = Risk.R3
    population_threshold: int = Field(default=100, ge=1)
    resource_threshold: int = Field(default=100, ge=1)


Tool = Literal["read_record", "create_record", "propose_message", "financial", "delegate"]
Level = Annotated[int, Field(ge=0, le=4, strict=True)]


class Action(Model):
    tool: Tool
    resource: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_./-]+$")
    units: int = Field(default=1, ge=1, le=10000, strict=True)
    synthetic_content: str = Field(default="", max_length=512)
    signals: frozenset[str] = frozenset()

    @field_serializer("signals")
    def sorted_signals(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


class Assessment(Model):
    severity: Level | None = None
    likelihood: Level | None = None
    population: int | None = Field(default=None, ge=0, le=1000000, strict=True)
    vulnerability: bool | None = None
    reversible: bool | None = None
    uncertainty: Level | None = None
    cascading: bool | None = None
    sensitive_data: bool | None = None
    authority_clear: bool | None = None


class Plan(Model):
    objective: str = Field(min_length=1)
    actions: tuple[Action, ...] = Field(min_length=1, max_length=20)
    expected_outcomes: tuple[str, ...] = Field(min_length=1)
    affected_parties: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    potential_risks: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    competing_values: tuple[str, ...] = ()
    assessment: Assessment = Assessment()

    @property
    def fingerprint(self) -> str:
        return digest(self.model_dump(mode="json"))


class Grant(Model):
    principal: str = Field(min_length=1)
    tools: frozenset[Tool] = Field(min_length=1)
    resources: frozenset[str] = Field(min_length=1)
    expires: datetime
    budget: int = Field(ge=1, le=1000000, strict=True)
    max_risk: Risk = Risk.R1
    restrictions: frozenset[str] = frozenset()
    charter_version: str
    policy_version: str
    parent: str | None = None
    parent_task: str | None = None

    @field_serializer("tools", "resources", "restrictions")
    def sorted_permissions(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    @model_validator(mode="after")
    def aware_expiry(self) -> "Grant":
        if self.expires.tzinfo is None or self.expires.utcoffset() is None:
            raise ValueError("expiry must include a timezone")
        if self.parent is not None and not self.parent_task:
            raise ValueError("delegated grants require a parent task")
        return self


class Evaluation(Model):
    status: Literal["DETERMINATE", "INDETERMINATE"]
    disposition: Disposition
    risk: Risk
    evidence: tuple[str, ...]
    assumptions: tuple[str, ...]
    uncertainty: tuple[str, ...]
    value_judgments: tuple[str, ...]
    violations: tuple[str, ...]
    conflicts: tuple[str, ...]
    considerations: tuple[str, ...]
    alternatives: tuple[str, ...]


class Review(Model):
    accepted: bool
    challenges: tuple[str, ...] = ()


class Decision(Model):
    request_id: str
    plan_id: str
    evaluation_id: str
    review_id: str
    plan_digest: str
    grant_id: str
    principal: str
    charter_version: str
    policy_version: str
    disposition: Disposition
    risk: Risk
    approval_required: bool


class Observation(Model):
    observed_outcomes: tuple[str, ...] = Field(min_length=1)
    confidence: Literal["low", "medium", "high"]
    evidence: tuple[str, ...] = Field(min_length=1)
    harm_signals: tuple[str, ...] = ()
