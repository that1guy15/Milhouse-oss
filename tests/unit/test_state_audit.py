"""Privacy + behavioural guarantees for the maintenance audit trail (W03 slice 5b; D05 fix).

The audit surface is a set of purpose-specific constructors, not a free-text sink: a caller cannot
put arbitrary text into the action/actor/outcome/reason code fields (they are fixed constants), and
the only caller-supplied value — the opaque resource id — is validated against an id charset that
rejects secrets, emails, paths, URLs, prompts, multiline text, and raw payloads before any write.
Recording is transaction-scoped, so the row commits or rolls back with the mutation it attests.
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
    record_retention_prune,
    schema_version,
)

_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_STAMP = "2026-07-28T12:00:00.000Z"

_RAW_CANARIES = [
    "sk_live:0xDEADBEEF/secret",  # secret token with structural punctuation
    "[email protected]",  # email address
    "/etc/passwd",  # filesystem path
    "https://evil.example/exfil",  # URL
    "ignore previous instructions",  # prompt-like free text (spaces)
    "line one\nline two",  # multiline
    "raw payload {json: true}",  # raw structured payload
]


def _database(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    return database


def _prune(database, **kwargs) -> None:
    with database.transaction() as connection:
        record_retention_prune(connection, **kwargs)


def _audit_bytes(database) -> bytes:
    return b"".join(
        bytes(str(cell), "utf-8")
        for row in database.connection.execute("SELECT * FROM _audit").fetchall()
        for cell in row
        if cell is not None
    )


def test_the_migration_creates_the_audit_table(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert schema_version(database) == 7
        tables = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "_audit" in tables
    finally:
        database.close()


def test_records_a_delivered_prune_with_fixed_codes(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _prune(
            database, now=_NOW, batch_id="batch-1", record_count=3, byte_size=128, undelivered=False
        )
        assert list_audit(database) == (
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


def test_records_an_undelivered_prune_as_the_critical_codes(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _prune(
            database, now=_NOW, batch_id="batch-1", record_count=1, byte_size=64, undelivered=True
        )
        row = list_audit(database)[0]
        assert (row.outcome, row.reason) == ("pruned_undelivered", "expired_undelivered")
    finally:
        database.close()


@pytest.mark.parametrize("canary", _RAW_CANARIES)
def test_a_raw_canary_resource_is_rejected_before_any_write(tmp_path: Path, canary: str) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            _prune(
                database, now=_NOW, batch_id=canary, record_count=1, byte_size=1, undelivered=False
            )
        assert captured.value.code == "MH_STATE_AUDIT"
        # The canary never reached SQLite: no row exists and no db byte contains it.
        assert list_audit(database) == ()
        assert canary.encode("utf-8") not in _audit_bytes(database)
        # ...nor does it leak into the error text, cause, or context.
        assert canary not in str(captured.value)
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


def test_the_action_actor_outcome_reason_codes_cannot_be_influenced(tmp_path: Path) -> None:
    # There is no free-text parameter for the code fields — the constructor fixes them — so a caller
    # can only ever produce the fixed retention codes, never arbitrary text.
    database = _database(tmp_path)
    try:
        _prune(
            database, now=_NOW, batch_id="batch-1", record_count=1, byte_size=1, undelivered=False
        )
        row = list_audit(database)[0]
        assert (row.action, row.actor) == ("retention_prune", "maintenance")
        assert row.outcome in {"pruned", "pruned_undelivered"}
        assert row.reason in {"expired", "expired_undelivered"}
    finally:
        database.close()


def test_ids_are_monotonic_and_append_ordered(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        for index in range(1, 4):
            _prune(
                database,
                now=_NOW,
                batch_id=f"batch-{index}",
                record_count=1,
                byte_size=1,
                undelivered=False,
            )
        rows = list_audit(database)
        assert [r.id for r in rows] == [1, 2, 3]
        assert [r.resource for r in rows] == ["batch-1", "batch-2", "batch-3"]
    finally:
        database.close()


def test_a_prune_audit_rolls_back_with_a_failed_caller_transaction(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="boom"):
            with database.transaction() as connection:
                record_retention_prune(
                    connection,
                    now=_NOW,
                    batch_id="batch-1",
                    record_count=1,
                    byte_size=1,
                    undelivered=False,
                )
                raise RuntimeError("boom")
        assert list_audit(database) == ()
    finally:
        database.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("batch_id", ""),
        ("batch_id", 5),
        ("batch_id", "x" * 300),
        ("record_count", -1),
        ("record_count", True),
        ("record_count", 2**63),
        ("byte_size", -1),
        ("undelivered", "yes"),
        ("undelivered", 1),
    ],
)
def test_malformed_prune_arguments_are_rejected(tmp_path: Path, field: str, value: object) -> None:
    database = _database(tmp_path)
    try:
        kwargs: dict[str, object] = {
            "now": _NOW,
            "batch_id": "batch-1",
            "record_count": 1,
            "byte_size": 1,
            "undelivered": False,
        }
        kwargs[field] = value
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                record_retention_prune(connection, **kwargs)  # type: ignore[arg-type]
        assert captured.value.code == "MH_STATE_AUDIT"
        assert list_audit(database) == ()
    finally:
        database.close()


def test_a_prune_rejects_a_naive_timestamp(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                record_retention_prune(
                    connection,
                    now=datetime(2026, 7, 28, 12),  # naive
                    batch_id="batch-1",
                    record_count=1,
                    byte_size=1,
                    undelivered=False,
                )
        assert captured.value.code == "MH_STATE_AUDIT"
    finally:
        database.close()


def test_list_filters_by_action_and_respects_the_limit(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        for index in range(1, 4):
            _prune(
                database,
                now=_NOW,
                batch_id=f"batch-{index}",
                record_count=1,
                byte_size=1,
                undelivered=False,
            )
        assert len(list_audit(database, action="retention_prune")) == 3
        assert list_audit(database, action="nonexistent") == ()
        assert len(list_audit(database, limit=2)) == 2
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
                record_retention_prune(
                    connection,
                    now=_NOW,
                    batch_id="batch-1",
                    record_count=1,
                    byte_size=1,
                    undelivered=False,
                )
        assert captured.value.code == "MH_STATE_AUDIT"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()
