"""Unit tests for compaction/rehome provenance intents and generic sequences (A07, migration 12).

A reserved ``c[0-9a-f]{64}`` id is a genuine compaction successor ONLY if a durable successor intent
proves it (recorded before the successor is published); the rehome binds a legacy occupant to its
allocated non-reserved target via a rehome intent so a restart reuses it. Faults normalize to a
fixed ``MH_SPOOL_INTENT`` code.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.spooling.errors import SpoolError
from milhouse.spooling.intents import (
    REHOME_SEQUENCE,
    clear_intents_for_segment,
    clear_rehome_intent,
    is_recorded_successor,
    read_rehome_target,
    read_sequence,
    record_rehome_intent,
    record_successor_intent,
    set_sequence,
)
from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
)

_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_SUCCESSOR = "c" + "a" * 64
_SOURCE = "batch-source"


def _database(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    return database


def test_successor_intent_round_trip(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert not is_recorded_successor(database.connection, _SUCCESSOR)  # nothing recorded yet
        with database.transaction() as connection:
            record_successor_intent(
                connection, target_batch_id=_SUCCESSOR, source_batch_id=_SOURCE, now=_NOW
            )
        assert is_recorded_successor(database.connection, _SUCCESSOR)
        assert not is_recorded_successor(database.connection, "c" + "b" * 64)  # a different id
    finally:
        database.close()


def test_successor_intent_is_idempotent(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        for _ in range(2):
            with database.transaction() as connection:
                record_successor_intent(
                    connection, target_batch_id=_SUCCESSOR, source_batch_id=_SOURCE, now=_NOW
                )
        count = database.connection.execute("SELECT count(*) FROM _compaction_intents").fetchone()[
            0
        ]
        assert count == 1
    finally:
        database.close()


def test_rehome_intent_round_trip(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert read_rehome_target(database.connection, _SOURCE) is None
        with database.transaction() as connection:
            record_rehome_intent(
                connection, target_batch_id="r" + "0" * 64, source_batch_id=_SOURCE, now=_NOW
            )
        assert read_rehome_target(database.connection, _SOURCE) == "r" + "0" * 64
        # A rehome intent is not a successor intent — its target is not classified as a successor.
        assert not is_recorded_successor(database.connection, "r" + "0" * 64)
    finally:
        database.close()


def test_intents_reject_conflicting_target_or_source_bindings(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        target = "r" + "0" * 64
        with database.transaction() as connection:
            record_rehome_intent(
                connection, target_batch_id=target, source_batch_id=_SOURCE, now=_NOW
            )
        with pytest.raises(SpoolError) as target_conflict:
            with database.transaction() as connection:
                record_successor_intent(
                    connection,
                    target_batch_id=target,
                    source_batch_id="other-source",
                    now=_NOW,
                )
        assert target_conflict.value.code == "MH_SPOOL_INTENT"
        with pytest.raises(SpoolError) as source_conflict:
            with database.transaction() as connection:
                record_rehome_intent(
                    connection,
                    target_batch_id="r" + "1" * 64,
                    source_batch_id=_SOURCE,
                    now=_NOW,
                )
        assert source_conflict.value.code == "MH_SPOOL_INTENT"
        assert read_rehome_target(database.connection, _SOURCE) == target
    finally:
        database.close()


def test_rehome_intent_can_be_replaced_only_by_its_exact_mapping(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        target = "r" + "0" * 64
        with database.transaction() as connection:
            record_rehome_intent(
                connection, target_batch_id=target, source_batch_id=_SOURCE, now=_NOW
            )
            clear_rehome_intent(connection, source_batch_id=_SOURCE, target_batch_id=target)
            record_rehome_intent(
                connection,
                target_batch_id="r" + "1" * 64,
                source_batch_id=_SOURCE,
                now=_NOW,
            )
        assert read_rehome_target(database.connection, _SOURCE) == "r" + "1" * 64
        with pytest.raises(SpoolError) as mismatch:
            with database.transaction() as connection:
                clear_rehome_intent(connection, source_batch_id=_SOURCE, target_batch_id=target)
        assert mismatch.value.code == "MH_SPOOL_INTENT"
    finally:
        database.close()


def test_sequence_default_and_advance(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert read_sequence(database.connection, REHOME_SEQUENCE) == 0  # never advanced
        with database.transaction() as connection:
            set_sequence(connection, REHOME_SEQUENCE, 7)
        assert read_sequence(database.connection, REHOME_SEQUENCE) == 7
        with database.transaction() as connection:
            set_sequence(connection, REHOME_SEQUENCE, 42)  # monotonic advance (upsert)
        assert read_sequence(database.connection, REHOME_SEQUENCE) == 42
    finally:
        database.close()


def test_clear_intents_retires_a_segment_but_keeps_its_new_successor(tmp_path: Path) -> None:
    successor_of_x = "c" + "b" * 64
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            # X (=_SUCCESSOR) was itself a successor of _SOURCE — intent (X, _SOURCE). In the swap
            # that retires X, its own successor N is created — intent (N, X). Retiring X must drop
            # (X, _SOURCE) but KEEP (N, X), or N (a legitimate successor) would look like a legacy
            # occupant on the next pass and be wrongly rehomed.
            record_successor_intent(
                connection, target_batch_id=_SUCCESSOR, source_batch_id=_SOURCE, now=_NOW
            )
            record_successor_intent(
                connection, target_batch_id=successor_of_x, source_batch_id=_SUCCESSOR, now=_NOW
            )
        with database.transaction() as connection:
            clear_intents_for_segment(connection, _SUCCESSOR)  # retire X
        assert not is_recorded_successor(database.connection, _SUCCESSOR)  # (X, _SOURCE) dropped
        assert is_recorded_successor(database.connection, successor_of_x)  # (N, X) kept
    finally:
        database.close()


def test_reads_normalize_a_backend_failure(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _compaction_intents")
        with pytest.raises(SpoolError) as successor:
            is_recorded_successor(database.connection, _SUCCESSOR)
        assert successor.value.code == "MH_SPOOL_INTENT"
        with pytest.raises(SpoolError) as rehome:
            read_rehome_target(database.connection, _SOURCE)
        assert rehome.value.code == "MH_SPOOL_INTENT"
    finally:
        database.close()


def test_sequence_read_normalizes_a_backend_failure(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _sequences")
        with pytest.raises(SpoolError) as captured:
            read_sequence(database.connection, REHOME_SEQUENCE)
        assert captured.value.code == "MH_SPOOL_INTENT"
    finally:
        database.close()


def test_writes_normalize_a_backend_failure(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(SpoolError) as successor:
            with database.transaction() as connection:
                connection.execute("DROP TABLE _compaction_intents")
                record_successor_intent(
                    connection, target_batch_id=_SUCCESSOR, source_batch_id=_SOURCE, now=_NOW
                )
        assert successor.value.code == "MH_SPOOL_INTENT"
        with pytest.raises(SpoolError) as rehome:
            with database.transaction() as connection:
                connection.execute("DROP TABLE _compaction_intents")
                record_rehome_intent(
                    connection, target_batch_id="r" + "0" * 64, source_batch_id=_SOURCE, now=_NOW
                )
        assert rehome.value.code == "MH_SPOOL_INTENT"
        with pytest.raises(SpoolError) as sequence:
            with database.transaction() as connection:
                connection.execute("DROP TABLE _sequences")
                set_sequence(connection, REHOME_SEQUENCE, 1)
        assert sequence.value.code == "MH_SPOOL_INTENT"
    finally:
        database.close()
