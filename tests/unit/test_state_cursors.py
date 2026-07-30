"""Behavioural guarantees for source ingestion cursors (W03 slice 4, pipeline rule 9).

A cursor advances only against a committed segment, and a monotonic-revision compare-and-set makes
concurrent or replayed advances safe: the loser fails closed rather than regressing or forking the
cursor. These tests drive the public API; the structural FK/CHECK guarantees live in
``test_state_slice4_schema``.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.state import (
    GlobalCommitBarrier,
    StateError,
    advance_cursor,
    initialize_control_state,
    open_control_database,
    read_cursor,
)

_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_LATER = datetime(2026, 7, 28, 12, 5, 0, tzinfo=UTC)


def _database(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    return database


def _commit_segment(database, batch_id: str) -> str:
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
            "config_generation, scope, target_id, privacy_class, retention_days, record_count, "
            "content_sha256, byte_size, file_sha256, committed_at) VALUES "
            "(?, '2026-07-28', 1, 1, ?, 'installation', NULL, 'internal', 14, 3, ?, 128, ?, ?)",
            (batch_id, "c" * 64, "a" * 64, "f" * 64, "2026-07-28T12:00:00.000Z"),
        )
    return batch_id


def test_a_source_with_no_cursor_reads_as_none(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert read_cursor(database, "github") is None
    finally:
        database.close()


def test_the_first_advance_creates_revision_one(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        batch_id = _commit_segment(database, "batch-1")
        cursor = advance_cursor(
            database,
            "github",
            position="page-2",
            batch_id=batch_id,
            now=_NOW,
            expected_revision=0,
        )
        assert (cursor.position, cursor.batch_id, cursor.revision) == ("page-2", batch_id, 1)
        assert cursor.updated_at == "2026-07-28T12:00:00.000Z"
        assert read_cursor(database, "github") == cursor
    finally:
        database.close()


def test_a_subsequent_advance_increments_the_revision(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        first_batch = _commit_segment(database, "batch-1")
        second_batch = _commit_segment(database, "batch-2")
        advance_cursor(
            database, "github", position="p1", batch_id=first_batch, now=_NOW, expected_revision=0
        )
        second = advance_cursor(
            database,
            "github",
            position="p2",
            batch_id=second_batch,
            now=_LATER,
            expected_revision=1,
        )
        assert (second.position, second.batch_id, second.revision) == ("p2", second_batch, 2)
        assert second.updated_at == "2026-07-28T12:05:00.000Z"
    finally:
        database.close()


def test_advancing_against_an_uncommitted_segment_fails_closed(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            advance_cursor(
                database,
                "github",
                position="p1",
                batch_id="no-such-segment",
                now=_NOW,
                expected_revision=0,
            )
        assert captured.value.code == "MH_STATE_CURSOR_SEGMENT"
        assert read_cursor(database, "github") is None  # nothing was written
    finally:
        database.close()


def test_a_stale_expected_revision_is_rejected_without_writing(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        first_batch = _commit_segment(database, "batch-1")
        second_batch = _commit_segment(database, "batch-2")
        advance_cursor(
            database, "github", position="p1", batch_id=first_batch, now=_NOW, expected_revision=0
        )
        # A second worker still believes the cursor is at revision 0 and loses the compare-and-set.
        with pytest.raises(StateError) as captured:
            advance_cursor(
                database,
                "github",
                position="rogue",
                batch_id=second_batch,
                now=_LATER,
                expected_revision=0,
            )
        assert captured.value.code == "MH_STATE_CURSOR_CONFLICT"
        current = read_cursor(database, "github")
        assert current is not None
        assert (current.position, current.revision) == ("p1", 1)  # the winner is untouched
    finally:
        database.close()


def test_expecting_a_prior_revision_on_a_fresh_cursor_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        batch_id = _commit_segment(database, "batch-1")
        with pytest.raises(StateError) as captured:
            advance_cursor(
                database,
                "github",
                position="p1",
                batch_id=batch_id,
                now=_NOW,
                expected_revision=1,  # nothing exists yet, so the stored revision is 0
            )
        assert captured.value.code == "MH_STATE_CURSOR_CONFLICT"
    finally:
        database.close()


def test_cursors_for_distinct_sources_are_independent(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        batch_id = _commit_segment(database, "batch-1")
        advance_cursor(
            database, "github", position="gh", batch_id=batch_id, now=_NOW, expected_revision=0
        )
        advance_cursor(
            database, "pagerduty", position="pd", batch_id=batch_id, now=_NOW, expected_revision=0
        )
        github = read_cursor(database, "github")
        pagerduty = read_cursor(database, "pagerduty")
        assert github is not None and github.position == "gh"
        assert pagerduty is not None and pagerduty.position == "pd"
    finally:
        database.close()


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("source", "", "MH_STATE_CURSOR_SOURCE"),
        ("source", 5, "MH_STATE_CURSOR_SOURCE"),
        ("position", "", "MH_STATE_CURSOR_POSITION"),
        ("batch_id", "", "MH_STATE_CURSOR_SEGMENT"),
        ("expected_revision", -1, "MH_STATE_CURSOR_REVISION"),
        ("expected_revision", True, "MH_STATE_CURSOR_REVISION"),
    ],
)
def test_malformed_arguments_are_rejected(
    tmp_path: Path, field: str, value: object, code: str
) -> None:
    database = _database(tmp_path)
    try:
        batch_id = _commit_segment(database, "batch-1")
        kwargs: dict[str, object] = {
            "source": "github",
            "position": "p1",
            "batch_id": batch_id,
            "now": _NOW,
            "expected_revision": 0,
        }
        kwargs[field] = value
        with pytest.raises(StateError) as captured:
            advance_cursor(database, **kwargs)  # type: ignore[arg-type]
        assert captured.value.code == code
    finally:
        database.close()


def test_read_cursor_rejects_a_malformed_source(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            read_cursor(database, "")
        assert captured.value.code == "MH_STATE_CURSOR_SOURCE"
    finally:
        database.close()


def test_a_read_against_a_broken_store_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _cursors")
        with pytest.raises(StateError) as captured:
            read_cursor(database, "github")
        assert captured.value.code == "MH_STATE_CURSOR"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


def test_an_advance_against_a_broken_store_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        batch_id = _commit_segment(database, "batch-1")
        # The segment lookup still succeeds; the cursor read/write beneath it hits a broken table.
        with database.transaction() as connection:
            connection.execute("DROP TABLE _cursors")
        with pytest.raises(StateError) as captured:
            advance_cursor(
                database, "github", position="p1", batch_id=batch_id, now=_NOW, expected_revision=0
            )
        assert captured.value.code == "MH_STATE_CURSOR"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


def test_a_closed_database_advance_fails_closed_without_leaking_detail(tmp_path: Path) -> None:
    database = _database(tmp_path)
    batch_id = _commit_segment(database, "batch-1")
    database.close()
    with pytest.raises(StateError) as captured:
        advance_cursor(
            database, "github", position="p1", batch_id=batch_id, now=_NOW, expected_revision=0
        )
    # A closed handle surfaces as the database-access fault, and no SQLite detail leaks through.
    assert captured.value.code in {"MH_STATE_CURSOR", "MH_STATE_CLOSED"}
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
