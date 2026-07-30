"""Behavioural guarantees for the append-only maintenance audit trail (W03 slice 5b).

An audit row records a maintenance action in privacy-safe terms and is written on the caller's
transaction, so it commits or rolls back atomically with the state it attests. Malformed entries
fail closed with a fixed ``MH_STATE_AUDIT`` code before any write.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.state import (
    AuditRecord,
    GlobalCommitBarrier,
    StateError,
    initialize_control_state,
    list_audit,
    open_control_database,
    record_audit,
    schema_version,
)

_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_STAMP = "2026-07-28T12:00:00.000Z"


def _database(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    return database


def _record(database, **kwargs) -> None:
    with database.transaction() as connection:
        record_audit(connection, **kwargs)


def test_migration_6_creates_the_audit_table(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert schema_version(database) == 6
        tables = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "_audit" in tables
    finally:
        database.close()


def test_a_full_audit_row_round_trips(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _record(
            database,
            now=_NOW,
            action="retention_prune",
            actor="maintenance",
            outcome="pruned",
            resource="batch-1",
            reason="expired",
            record_count=3,
            byte_size=128,
        )
        rows = list_audit(database)
        assert rows == (
            AuditRecord(
                id=1,
                recorded_at=_STAMP,
                action="retention_prune",
                actor="maintenance",
                outcome="pruned",
                resource="batch-1",
                reason="expired",
                record_count=3,
                byte_size=128,
            ),
        )
    finally:
        database.close()


def test_optional_fields_default_to_none(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _record(database, now=_NOW, action="retention_apply", actor="maintenance", outcome="ok")
        row = list_audit(database)[0]
        assert (row.resource, row.reason, row.record_count, row.byte_size) == (
            None,
            None,
            None,
            None,
        )
    finally:
        database.close()


def test_ids_are_monotonic_and_append_ordered(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        for index in range(1, 4):
            _record(
                database,
                now=_NOW,
                action="a",
                actor="maintenance",
                outcome="ok",
                resource=str(index),
            )
        rows = list_audit(database)
        assert [r.id for r in rows] == [1, 2, 3]
        assert [r.resource for r in rows] == ["1", "2", "3"]
    finally:
        database.close()


def test_list_filters_by_action_and_respects_the_limit(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _record(database, now=_NOW, action="prune", actor="m", outcome="ok")
        _record(database, now=_NOW, action="compact", actor="m", outcome="ok")
        _record(database, now=_NOW, action="prune", actor="m", outcome="ok")
        assert [r.action for r in list_audit(database, action="prune")] == ["prune", "prune"]
        assert len(list_audit(database, limit=2)) == 2
    finally:
        database.close()


def test_an_audit_row_rolls_back_with_a_failed_caller_transaction(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="boom"):
            with database.transaction() as connection:
                record_audit(connection, now=_NOW, action="prune", actor="m", outcome="ok")
                raise RuntimeError("boom")
        # The audit row is transaction-scoped, so it did not survive the caller's rollback.
        assert list_audit(database) == ()
    finally:
        database.close()


@pytest.mark.parametrize(
    "field, value",
    [
        ("action", ""),
        ("action", 5),
        ("actor", ""),
        ("outcome", ""),
        ("resource", ""),
        ("resource", 5),
        ("reason", ""),
        ("record_count", -1),
        ("record_count", True),
        ("record_count", 2**63),  # would overflow the signed-64 INTEGER binding at INSERT
        ("byte_size", -1),
        ("byte_size", 2**63),
        ("action", "x" * 1025),
    ],
)
def test_malformed_fields_are_rejected(tmp_path: Path, field: str, value: object) -> None:
    database = _database(tmp_path)
    try:
        kwargs: dict[str, object] = {
            "now": _NOW,
            "action": "prune",
            "actor": "maintenance",
            "outcome": "ok",
        }
        kwargs[field] = value
        with pytest.raises(StateError) as captured:
            record_audit(database.connection, **kwargs)  # type: ignore[arg-type]
        assert captured.value.code == "MH_STATE_AUDIT"
        assert list_audit(database) == ()  # nothing written
    finally:
        database.close()


def test_record_rejects_a_naive_timestamp(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            record_audit(
                database.connection,
                now=datetime(2026, 7, 28, 12),  # naive, no tzinfo
                action="prune",
                actor="m",
                outcome="ok",
            )
        assert captured.value.code == "MH_STATE_AUDIT"
    finally:
        database.close()


@pytest.mark.parametrize("limit", [0, -1, 100_001])
def test_list_rejects_a_bad_limit(tmp_path: Path, limit: int) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            list_audit(database, limit=limit)
        assert captured.value.code == "MH_STATE_AUDIT"
    finally:
        database.close()


def test_list_rejects_a_malformed_action_filter(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            list_audit(database, action="")
        assert captured.value.code == "MH_STATE_AUDIT"
    finally:
        database.close()


def test_a_read_against_a_broken_store_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")
        with pytest.raises(StateError) as captured:
            list_audit(database)
        assert captured.value.code == "MH_STATE_AUDIT"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


def test_a_write_against_a_broken_store_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                record_audit(connection, now=_NOW, action="prune", actor="m", outcome="ok")
        # A backend fault on the insert normalizes to the fixed code with no leaked detail.
        assert captured.value.code == "MH_STATE_AUDIT"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()
