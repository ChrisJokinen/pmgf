# SPDX-License-Identifier: Apache-2.0
"""Host-authenticated synthetic sessions and attenuating persistent grants."""

import hmac
from typing import Any

from pmgf.models import Charter, GovernanceError, Grant, Plan, Policy, Risk, now
from pmgf.persistence import Store


class Authority:
    def __init__(self, store: Store, admin: object, identities: dict[str, str]) -> None:
        self.store = store
        self._admin = admin
        self._identities = identities.copy()
        self._sessions: dict[object, str] = {}

    def require_admin(self, capability: object) -> None:
        if capability is not self._admin:
            raise GovernanceError("trusted host administrator capability required")

    def authenticate(self, principal: str, credential: str) -> object:
        expected = self._identities.get(principal)
        if expected is None or not hmac.compare_digest(expected.encode(), credential.encode()):
            raise GovernanceError("authentication failed")
        session = object()
        self._sessions[session] = principal
        return session

    def principal(self, session: object) -> str:
        if session not in self._sessions:
            raise GovernanceError("unknown or expired host session")
        return self._sessions[session]

    def configure(self, capability: object, charter: Charter, policy: Policy) -> None:
        self.require_admin(capability)
        charter = Charter.model_validate(charter.model_dump(mode="json"))
        policy = Policy.model_validate(policy.model_dump(mode="json"))
        with self.store.transaction():
            for kind, version, model in (
                ("charter", charter.version, charter),
                ("policy", policy.version, policy),
            ):
                existing = [
                    payload
                    for _, payload in self.store.records(kind)
                    if payload["version"] == version
                ]
                if existing and existing[0] != model.model_dump(mode="json"):
                    raise GovernanceError("versions are immutable; use a new version")
                if not existing:
                    self.store.append(kind, model.model_dump(mode="json"))
            self.store.append(
                "governance_change",
                {"charter_version": charter.version, "policy_version": policy.version},
            )

    def active(self) -> tuple[Charter, Policy]:
        changes = self.store.records("governance_change")
        if not changes:
            raise GovernanceError("governance services are not configured")
        active = changes[-1][1]
        charters = [
            Charter.model_validate(p)
            for _, p in self.store.records("charter")
            if p["version"] == active["charter_version"]
        ]
        policies = [
            Policy.model_validate(p)
            for _, p in self.store.records("policy")
            if p["version"] == active["policy_version"]
        ]
        if not charters or not policies:
            raise GovernanceError("missing active governance versions")
        return charters[0], policies[0]

    def issue(self, capability: object, grant: Grant) -> str:
        self.require_admin(capability)
        grant = Grant.model_validate(grant.model_dump(mode="json"))
        if grant.parent is not None:
            raise GovernanceError("use delegation for child grants")
        with self.store.transaction():
            self._versions(grant)
            if grant.expires <= now():
                raise GovernanceError("grant already expired")
            return self.store.append("authority_grant", grant.model_dump(mode="json"))

    def _versions(self, grant: Grant) -> None:
        charter, policy = self.active()
        if (grant.charter_version, grant.policy_version) != (charter.version, policy.version):
            raise GovernanceError("governance version mismatch")

    def lineage(self, grant_id: str) -> list[tuple[str, Grant]]:
        result = []
        seen: set[str] = set()
        revoked = {p["grant_id"] for _, p in self.store.records("revocation")}
        while grant_id:
            if grant_id in seen:
                raise GovernanceError("delegation cycle")
            seen.add(grant_id)
            grant = Grant.model_validate(self.store.get(grant_id, "authority_grant"))
            if grant_id in revoked or grant.expires <= now():
                raise GovernanceError("expired or revoked authority")
            self._versions(grant)
            result.append((grant_id, grant))
            grant_id = grant.parent or ""
        for (_, child), (_, parent) in zip(result, result[1:], strict=False):
            self._attenuated(child, parent)
        return result

    @staticmethod
    def _attenuated(child: Grant, parent: Grant) -> None:
        if (
            not child.tools <= parent.tools
            or not child.resources <= parent.resources
            or child.expires > parent.expires
            or child.budget > parent.budget
            or child.max_risk > parent.max_risk
            or not child.restrictions >= parent.restrictions
        ):
            raise GovernanceError("delegation cannot increase authority")

    def check(
        self, session: object, grant_id: str, plan: Plan, risk: Risk = Risk.R0
    ) -> list[tuple[str, Grant]]:
        lineage = self.lineage(grant_id)
        if lineage[0][1].principal != self.principal(session):
            raise GovernanceError("cross-principal access denied")
        for ancestor_id, grant in lineage:
            if risk > grant.max_risk:
                raise GovernanceError("risk exceeds authority")
            spent = sum(
                p["units"]
                for _, p in self.store.records("budget_use")
                if ancestor_id in p["grants"]
            )
            if spent + sum(a.units for a in plan.actions) > grant.budget:
                raise GovernanceError("resource budget exhausted")
            for action in plan.actions:
                if action.tool not in grant.tools or action.resource not in grant.resources:
                    raise GovernanceError("action or resource outside explicit permission")
                if action.signals & grant.restrictions:
                    raise GovernanceError("action violates authority restrictions")
        return lineage

    def delegate(self, session: object, parent_id: str, child: Grant) -> str:
        try:
            return self._delegate(session, parent_id, child)
        except GovernanceError as exc:
            self.audit_denial("delegate", str(exc))
            raise

    def _delegate(self, session: object, parent_id: str, child: Grant) -> str:
        child = Grant.model_validate(child.model_dump(mode="json"))
        with self.store.transaction():
            parent = self.lineage(parent_id)[0][1]
            if parent.principal != self.principal(session) or "delegate" not in parent.tools:
                raise GovernanceError("delegation permission required")
            if child.parent != parent_id:
                raise GovernanceError("incorrect parent authority")
            self._versions(child)
            self._attenuated(child, parent)
            if child.expires <= now():
                raise GovernanceError("delegated authority already expired")
            request = self.store.get(child.parent_task or "", "decision_request")
            if request["grant_id"] != parent_id:
                raise GovernanceError("parent task is not owned by parent authority")
            blocked = [
                p
                for _, p in self.store.records("decision")
                if p["request_id"] == child.parent_task
                and p["disposition"] not in ("APPROVE", "APPROVE_WITH_CONDITIONS")
            ]
            if blocked:
                raise GovernanceError("a refused or unresolved task cannot be delegated")
            record_id = self.store.append(
                "authority_grant",
                child.model_dump(mode="json"),
                links=(parent_id, child.parent_task or ""),
            )
            self.store.append(
                "delegation",
                {"parent": parent_id, "child": record_id, "parent_task": child.parent_task},
                links=(parent_id, record_id),
            )
            return record_id

    def revoke(self, capability: object, grant_id: str) -> None:
        self.require_admin(capability)
        with self.store.transaction():
            self.store.get(grant_id, "authority_grant")
            self.store.append("revocation", {"grant_id": grant_id}, links=(grant_id,))

    def audit_denial(self, operation: str, reason: str) -> None:
        with self.store.transaction():
            self.store.append("authorization_denial", {"operation": operation, "reason": reason})

    def snapshot(self) -> dict[str, Any]:
        charter, policy = self.active()
        return {"charter_version": charter.version, "policy_version": policy.version}
