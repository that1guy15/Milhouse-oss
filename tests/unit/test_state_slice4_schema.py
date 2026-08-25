"""Schema-level guarantees for the W03 slice-4 control tables.

These assert the *structural* invariants the slice-4 code relies on: the source cursor cannot be
written ahead of a committed segment (a foreign key, not a code check), and neither table accepts a
blank identifier or a non-positive revision. The behavioural advance/CAS logic is covered by the
cursor and derivation-checkpoint API suites; here we prove the database itself refuses malformed
rows even if a caller bypasses those APIs.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
    schema_version,
)

_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)


def _initialized(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    return database


def _insert_committed_segment(database, batch_id: str = "batch-1") -> str:
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
            "config_generation, scope, target_id, privacy_class, retention_days, record_count, "
            "content_sha256, byte_size, file_sha256, committed_at) VALUES "
            "(?, '2026-07-28', 1, 1, ?, 'installation', NULL, 'internal', 14, 3, ?, 128, ?, ?)",
            (batch_id, "c" * 64, "a" * 64, "f" * 64, "2026-07-28T12:00:00.000Z"),
        )
    return batch_id


def test_slice4_migrations_create_the_cursor_and_checkpoint_tables(tmp_path: Path) -> None:
    database = _initialized(tmp_path)
    try:
        assert (
            schema_version(database) >= 5
        )  # slice-4 migrations applied (later slices append more)
        tables = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {"_cursors", "_derivation_checkpoints"} <= tables
    finally:
        database.close()


def test_a_cursor_referencing_no_committed_segment_is_refused(tmp_path: Path) -> None:
    database = _initialized(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            with database.transaction() as connection:
                connection.execute(
                    "INSERT INTO _cursors (source, position, batch_id, revision, updated_at) "
                    "VALUES ('github', 'p1', 'no-such-segment', 1, ?)",
                    ("2026-07-28T12:00:00.000Z",),
                )
    finally:
        database.close()


def test_a_cursor_referencing_a_committed_segment_is_accepted(tmp_path: Path) -> None:
    database = _initialized(tmp_path)
    try:
        batch_id = _insert_committed_segment(database)
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _cursors (source, position, batch_id, revision, updated_at) "
                "VALUES ('github', 'p1', ?, 1, ?)",
                (batch_id, "2026-07-28T12:00:00.000Z"),
            )
        stored = database.connection.execute(
            "SELECT position, batch_id, revision FROM _cursors WHERE source = 'github'"
        ).fetchone()
        assert stored == ("p1", batch_id, 1)
    finally:
        database.close()


@pytest.mark.parametrize(
    ("source", "position", "revision"),
    [
        ("", "p1", 1),  # blank source
        ("github", "", 1),  # blank position
        ("github", "p1", 0),  # non-positive revision
    ],
)
def test_a_malformed_cursor_row_is_refused(
    tmp_path: Path, source: str, position: str, revision: int
) -> None:
    database = _initialized(tmp_path)
    try:
        batch_id = _insert_committed_segment(database)
        with pytest.raises(sqlite3.IntegrityError):
            with database.transaction() as connection:
                connection.execute(
                    "INSERT INTO _cursors (source, position, batch_id, revision, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (source, position, batch_id, revision, "2026-07-28T12:00:00.000Z"),
                )
    finally:
        database.close()


def test_a_checkpoint_is_keyed_by_rule_and_version(tmp_path: Path) -> None:
    database = _initialized(tmp_path)
    try:
        with database.transaction() as connection:
            connection.executemany(
                "INSERT INTO _derivation_checkpoints (rule, rule_version, position, revision, "
                "updated_at) VALUES (?, ?, ?, ?, ?)",
                [
                    ("alerts", 1, "p1", 1, "2026-07-28T12:00:00.000Z"),
                    ("alerts", 2, "p1", 1, "2026-07-28T12:00:00.000Z"),  # same rule, new version
                    ("feedback", 1, "p1", 1, "2026-07-28T12:00:00.000Z"),
                ],
            )
        count = database.connection.execute(
            "SELECT count(*) FROM _derivation_checkpoints"
        ).fetchone()[0]
        assert count == 3
        # The (rule, rule_version) pair is unique — a duplicate is a primary-key violation.
        with pytest.raises(sqlite3.IntegrityError):
            with database.transaction() as connection:
                connection.execute(
                    "INSERT INTO _derivation_checkpoints (rule, rule_version, position, revision, "
                    "updated_at) VALUES ('alerts', 1, 'p2', 2, ?)",
                    ("2026-07-28T12:00:00.000Z",),
                )
    finally:
        database.close()


@pytest.mark.parametrize(
    ("rule", "rule_version", "revision"),
    [
        ("", 1, 1),  # blank rule
        ("alerts", 0, 1),  # non-positive version
        ("alerts", 1, 0),  # non-positive revision
    ],
)
def test_a_malformed_checkpoint_row_is_refused(
    tmp_path: Path, rule: str, rule_version: int, revision: int
) -> None:
    database = _initialized(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            with database.transaction() as connection:
                connection.execute(
                    "INSERT INTO _derivation_checkpoints (rule, rule_version, position, revision, "
                    "updated_at) VALUES (?, ?, 'p1', ?, ?)",
                    (rule, rule_version, revision, "2026-07-28T12:00:00.000Z"),
                )
    finally:
        database.close()


def test_migration_7_makes_the_cursor_batch_id_detachable(tmp_path: Path) -> None:
    # D05: batch_id becomes nullable so retention can detach a cursor (preserving position/revision)
    # from a pruned privacy-expired segment, while the foreign key still refuses a non-null bad ref.
    database = _initialized(tmp_path)
    try:
        assert schema_version(database) >= 7
        batch_id = _insert_committed_segment(database)
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _cursors (source, position, batch_id, revision, updated_at) "
                "VALUES ('github', 'p1', ?, 1, ?)",
                (batch_id, "2026-07-28T12:00:00.000Z"),
            )
            connection.execute("UPDATE _cursors SET batch_id = NULL WHERE source = 'github'")
        row = database.connection.execute(
            "SELECT batch_id, position, revision FROM _cursors WHERE source = 'github'"
        ).fetchone()
        assert row == (None, "p1", 1)  # detached, checkpoint preserved
        with pytest.raises(sqlite3.IntegrityError):  # a non-null bad reference is still refused
            with database.transaction() as connection:
                connection.execute(
                    "UPDATE _cursors SET batch_id = 'no-such' WHERE source = 'github'"
                )
    finally:
        database.close()


def test_migration_7_preserves_existing_cursor_rows(tmp_path: Path) -> None:
    # The reviewer's upgrade-with-data path: a v6 database with a populated cursor row must survive
    # the migration-7 _cursors table recreation verbatim (position/revision intact), not just fresh.
    from milhouse.state import CONTROL_MIGRATIONS, migrate

    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    try:
        migrate(database, CONTROL_MIGRATIONS[:6], barrier=barrier, applied_at=_NOW)  # to v6
        assert schema_version(database) == 6
        batch_id = _insert_committed_segment(database)
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _cursors (source, position, batch_id, revision, updated_at) "
                "VALUES ('github', 'page-9', ?, 4, ?)",
                (batch_id, "2026-07-28T12:00:00.000Z"),
            )
        migrate(database, CONTROL_MIGRATIONS[:7], barrier=barrier, applied_at=_NOW)  # apply mig 7
        assert schema_version(database) == 7
        row = database.connection.execute(
            "SELECT source, position, batch_id, revision FROM _cursors WHERE source = 'github'"
        ).fetchone()
        assert row == ("github", "page-9", batch_id, 4)  # copied verbatim, no data loss
    finally:
        database.close()
