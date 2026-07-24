from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.state import (
    Migration,
    StateError,
    apply_migrations,
    open_control_database,
    schema_version,
)

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)

_M1 = Migration(1, "create_ledger", ("CREATE TABLE ledger (id INTEGER PRIMARY KEY)",))
_M2 = Migration(2, "create_cursor", ("CREATE TABLE cursor (name TEXT PRIMARY KEY)",))


def _database(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return open_control_database(directory / "milhouse.sqlite3")


def test_apply_migrations_creates_tables_and_records_the_ledger(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert apply_migrations(database, (_M1, _M2), applied_at=_NOW) == 2
        assert schema_version(database) == 2
        tables = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {"ledger", "cursor"} <= tables
        recorded = database.connection.execute(
            "SELECT version, name, applied_at FROM _schema_migrations ORDER BY version"
        ).fetchall()
        assert [(r[0], r[1]) for r in recorded] == [(1, "create_ledger"), (2, "create_cursor")]
        assert recorded[0][2] == "2026-07-24T12:00:00.000Z"
    finally:
        database.close()


def test_apply_migrations_is_idempotent(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        apply_migrations(database, (_M1, _M2), applied_at=_NOW)
        assert apply_migrations(database, (_M1, _M2), applied_at=_NOW) == 2
        count = database.connection.execute("SELECT count(*) FROM _schema_migrations").fetchone()[0]
        assert count == 2
    finally:
        database.close()


def test_apply_migrations_extends_a_partial_ledger(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert apply_migrations(database, (_M1,), applied_at=_NOW) == 1
        assert apply_migrations(database, (_M1, _M2), applied_at=_NOW) == 2
    finally:
        database.close()


def test_a_modified_applied_migration_is_rejected_as_corruption(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        apply_migrations(database, (_M1,), applied_at=_NOW)
        tampered = Migration(1, "create_ledger", ("CREATE TABLE ledger (id INTEGER, extra TEXT)",))
        with pytest.raises(StateError) as captured:
            apply_migrations(database, (tampered,), applied_at=_NOW)
        assert captured.value.code == "MH_STATE_MIGRATION"
    finally:
        database.close()


def test_noncontiguous_definitions_are_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        gapped = (
            Migration(1, "a", ("CREATE TABLE a (x)",)),
            Migration(3, "c", ("CREATE TABLE c (x)",)),
        )
        with pytest.raises(StateError) as captured:
            apply_migrations(database, gapped, applied_at=_NOW)
        assert captured.value.code == "MH_STATE_MIGRATION"
    finally:
        database.close()


def test_a_failing_statement_rolls_back_atomically_without_leaking_sqlite_detail(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    try:
        broken = Migration(1, "broken", ("CREATE TABLE ok (x INTEGER)", "THIS IS NOT SQL"))
        with pytest.raises(StateError) as captured:
            apply_migrations(database, (broken,), applied_at=_NOW)
        assert captured.value.code == "MH_STATE_MIGRATION"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
        # neither the table nor the ledger row survives the rolled-back migration
        assert schema_version(database) == 0
        remaining = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "ok" not in remaining
    finally:
        database.close()


def test_empty_definitions_are_a_no_op(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert apply_migrations(database, (), applied_at=_NOW) == 0
        assert schema_version(database) == 0
    finally:
        database.close()
