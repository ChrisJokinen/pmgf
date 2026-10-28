# SPDX-License-Identifier: Apache-2.0
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from pmgf.authority import Authority
from pmgf.models import Charter, GovernanceError, Grant, Policy
from pmgf.persistence import Store


def test_persistence_restart(environment):
    store, authority, _, _, _, grant_id = environment
    charter, _ = authority.active()
    store.verify()
    assert store.get(grant_id, "authority_grant")["principal"] == "operator"
    assert charter.version == "1"


def test_restart_loads_charter(tmp_path: Path):
    from pmgf.models import Category, Principle

    path = str(tmp_path / "restart.sqlite")
    admin = object()
    store = Store(path)
    authority = Authority(store, admin, {})
    charter = Charter(
        version="1",
        principles=(Principle(id="safety", category=Category.HARD, statement="Protect people."),),
    )
    authority.configure(admin, charter, Policy(version="1"))
    store.close()
    reopened = Store(path)
    assert Authority(reopened, object(), {}).active()[0] == charter
    reopened.close()


def test_unauthorized_revision(environment):
    _, authority, _, _, _, _ = environment
    charter, policy = authority.active()
    with pytest.raises(GovernanceError):
        authority.configure(object(), charter, policy)


def test_immutable_version(environment):
    _, authority, _, admin, _, _ = environment
    charter, _ = authority.active()
    with pytest.raises(GovernanceError):
        authority.configure(admin, charter, Policy(version="1", resource_threshold=10))


def test_transaction_rollback(environment):
    store, *_ = environment
    with pytest.raises(RuntimeError), store.transaction():
        store.append("partial", {"written": True})
        raise RuntimeError("interrupted")
    assert not store.records("partial")
    store.verify()


def test_corrupt_database_rejected(tmp_path: Path):
    path = str(tmp_path / "corrupt.sqlite")
    store = Store(path)
    with store.transaction():
        store.append("example", {"synthetic": True})
    store.close()
    with sqlite3.connect(path) as db:
        db.execute("UPDATE records SET envelope = '{}'")
    with pytest.raises(GovernanceError):
        Store(path)


def test_naive_expiry_is_rejected():
    with pytest.raises(ValidationError):
        Grant(
            principal="p",
            tools=frozenset({"read_record"}),
            resources=frozenset({"x"}),
            expires=datetime(2099, 1, 1),
            budget=1,
            charter_version="1",
            policy_version="1",
        )
