# SPDX-License-Identifier: Apache-2.0
"""Append-only records; hash chaining detects accidents, not a database owner."""

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from pmgf.models import GovernanceError, canonical, digest, identifier, now


class Store:
    def __init__(self, path: str) -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS records "
            "(seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, envelope TEXT NOT NULL, "
            "hash TEXT NOT NULL)"
        )
        self.verify()

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self.verify()
                yield
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def verify(self) -> None:
        previous = ""
        sequence = 0
        try:
            for seq, record_id, raw, hashed in self._db.execute(
                "SELECT seq, id, envelope, hash FROM records ORDER BY seq"
            ):
                entry = json.loads(raw)
                sequence += 1
                if (
                    seq != sequence
                    or entry["id"] != record_id
                    or entry["previous"] != previous
                    or entry["schema_version"] != 1
                    or digest(entry) != hashed
                ):
                    raise GovernanceError("governance record integrity failure")
                previous = hashed
        except (ValueError, KeyError, TypeError) as exc:
            raise GovernanceError("invalid governance record") from exc

    def append(self, kind: str, payload: dict[str, Any], *, links: tuple[str, ...] = ()) -> str:
        if not self._db.in_transaction:
            raise GovernanceError("record writes require a transaction")
        for link in links:
            self.get(link)
        last = self._db.execute("SELECT hash FROM records ORDER BY seq DESC LIMIT 1").fetchone()
        record_id = identifier()
        entry = {
            "id": record_id,
            "schema_version": 1,
            "timestamp": now().isoformat(),
            "provenance": "pmgf/deterministic-host-v1",
            "kind": kind,
            "links": links,
            "payload": payload,
            "previous": last[0] if last else "",
        }
        self._db.execute(
            "INSERT INTO records(id, envelope, hash) VALUES (?, ?, ?)",
            (record_id, canonical(entry), digest(entry)),
        )
        return record_id

    def get(self, record_id: str, kind: str | None = None) -> dict[str, Any]:
        row = self._db.execute("SELECT envelope FROM records WHERE id = ?", (record_id,)).fetchone()
        if row is None:
            raise GovernanceError("missing governance record")
        entry: dict[str, Any] = json.loads(row[0])
        if kind is not None and entry["kind"] != kind:
            raise GovernanceError("incorrect governance record type")
        payload: dict[str, Any] = entry["payload"]
        return payload

    def records(self, kind: str | tuple[str, ...]) -> list[tuple[str, dict[str, Any]]]:
        result = []
        kinds = (kind,) if isinstance(kind, str) else kind
        for record_id, raw in self._db.execute("SELECT id, envelope FROM records ORDER BY seq"):
            entry = json.loads(raw)
            if entry["kind"] in kinds:
                result.append((record_id, entry["payload"]))
        return result
