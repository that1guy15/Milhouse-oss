"""G03 durable-write failure-injection harness (W03 slice 7).

Each test forces a failure at one durable-write boundary and asserts the boundary fails closed with
a fixed code and no partial state — the source-cursor update, the derivation checkpoint, and the
exporter checkpoint compare-and-set — plus the two crash-recovery invariants a kill exposes: a kill
before the atomic rename exposes no partial batch, and a kill after commit loses no acknowledged
record. Boundaries already exercised elsewhere (ledger insert/commit, temp write, file/dir fsync,
rename at the config layer, torn-tail quarantine, 0600/0700, privacy-expiry) are referenced by the
G03 packet.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from _g03_harness import (
    INSTALLATION_ID,
    NOW,
    NoopExporter,
    build_spool,
    commit_segment,
    inject_sql_fault,
    open_writer,
    segment_file,
    segment_rows,
    staged_temp_files,
)

from milhouse.config import filesystem as config_filesystem
from milhouse.config.filesystem import SecureFileError, SecureFileErrorKind
from milhouse.spooling import deliver_segment, replay_segments
from milhouse.spooling.errors import SpoolError
from milhouse.state import (
    StateError,
    advance_checkpoint,
    advance_cursor,
    read_checkpoint,
    read_cursor,
)


def _exporter_status(database: Any, batch_id: str, exporter_id: str) -> str | None:
    row = database.connection.execute(
        "SELECT delivery_status FROM _segment_exporters WHERE batch_id = ? AND exporter_id = ?",
        (batch_id, exporter_id),
    ).fetchone()
    return None if row is None else str(row[0])


# The ledger insert/commit boundary (a kill after the file is published, before the ledger row) is
# already covered: test_spool_commit.py forces the ledger transaction to fail and asserts
# MH_SPOOL_COMMIT with a durably-published orphan, and test_spool_reconcile.py proves the orphan
# reconciles back into the ledger. The G03 packet references those rather than duplicating them.


# --------------------------------------------------------------------------------------------------
# Source-cursor update boundary
# --------------------------------------------------------------------------------------------------


def test_a_cursor_update_fault_rolls_back_atomically(tmp_path: Path) -> None:
    database, _barrier, _spool_root, store = build_spool(tmp_path)
    try:
        commit_segment(store, "batch-a", ["a1"])
        first = advance_cursor(
            database, "github", position="page-1", batch_id="batch-a", now=NOW, expected_revision=0
        )
        assert first.revision == 1

        # Fail the cursor INSERT during the advance to revision 2: the transaction must roll back
        # and leave the cursor at revision 1, not a half-applied state.
        inject_sql_fault(database, "INSERT INTO _cursors")
        with pytest.raises(StateError) as captured:
            advance_cursor(
                database,
                "github",
                position="page-2",
                batch_id="batch-a",
                now=NOW,
                expected_revision=1,
            )
        assert captured.value.code == "MH_STATE_CURSOR"
        current = read_cursor(database, "github")
        assert current is not None
        assert (current.position, current.revision) == ("page-1", 1)  # unchanged
    finally:
        database.close()


# --------------------------------------------------------------------------------------------------
# Derivation checkpoint boundary
# --------------------------------------------------------------------------------------------------


def test_a_derivation_checkpoint_fault_rolls_back_atomically(tmp_path: Path) -> None:
    database, _barrier, _spool_root, _store = build_spool(tmp_path)
    try:
        first = advance_checkpoint(
            database, "rollup", 1, position="frame-1", now=NOW, expected_revision=0
        )
        assert first.revision == 1

        inject_sql_fault(database, "INSERT INTO _derivation_checkpoints")
        with pytest.raises(StateError) as captured:
            advance_checkpoint(
                database, "rollup", 1, position="frame-2", now=NOW, expected_revision=1
            )
        assert captured.value.code == "MH_STATE_DERIVATION"
        current = read_checkpoint(database, "rollup", 1)
        assert current is not None
        assert (current.position, current.revision) == ("frame-1", 1)  # unchanged
    finally:
        database.close()


# --------------------------------------------------------------------------------------------------
# Exporter checkpoint boundary — crash between destination confirmation and the checkpoint CAS
# --------------------------------------------------------------------------------------------------


def test_an_exporter_checkpoint_fault_leaves_delivery_retryable(tmp_path: Path) -> None:
    database, barrier, _spool_root, store = build_spool(tmp_path)
    try:
        record, frames = commit_segment(store, "batch-a", ["a1"])
        # The destination confirms (the exporter returns), then the checkpoint CAS fails; delivery
        # must fail closed and leave the row pending so a later pass retries (at-least-once).
        inject_sql_fault(database, "UPDATE _segment_exporters")
        with pytest.raises(SpoolError) as captured:
            deliver_segment(
                database,
                barrier,
                record,
                frames,
                {"clickhouse": NoopExporter()},
                now=NOW,
            )
        assert captured.value.code == "MH_SPOOL_EXPORT"
        assert _exporter_status(database, "batch-a", "clickhouse") == "pending"  # retryable
    finally:
        database.close()


# --------------------------------------------------------------------------------------------------
# Kill before the atomic rename — no partial batch
# --------------------------------------------------------------------------------------------------


def test_a_kill_before_rename_exposes_no_partial_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = build_spool(tmp_path)
    try:

        def failing_rename(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(config_filesystem, "_rename_no_replace", failing_rename)
        with pytest.raises(SpoolError):
            commit_segment(store, "batch-a", ["a1"])

        # No COMMITTED segment file is published and no ledger row exists — a failure before the
        # atomic rename never exposes a partial batch. A staged temporary (like a real crash
        # artifact) may linger, but it is never a committed batch.
        assert not segment_file(spool_root, "batch-a").exists()
        assert segment_rows(database) == set()

        # A restart reconciles: the stale staged temporary is recovered/quarantined and still never
        # becomes a committed batch — the batch was never acknowledged and nothing was lost.
        fresh_db, _writer = open_writer(database.path, barrier, spool_root)
        try:
            assert segment_rows(database) == set()
            assert not segment_file(spool_root, "batch-a").exists()
            assert staged_temp_files(spool_root) == []  # recovered by reconciliation
        finally:
            fresh_db.close()
    finally:
        database.close()


# --------------------------------------------------------------------------------------------------
# Kill after commit — no acknowledged record lost
# --------------------------------------------------------------------------------------------------


def test_a_kill_after_commit_loses_no_acknowledged_record(tmp_path: Path) -> None:
    database, barrier, spool_root, store = build_spool(tmp_path)
    try:
        _record, frames = commit_segment(store, "batch-a", ["a1", "a2"])  # commit returns = ack
        acknowledged_ids = [str(frame.record.record_id) for frame in frames]

        # A restart (fresh writer acquisition) reconciles; the row and file survive intact and the
        # acknowledged records replay identically.
        fresh_db, _writer = open_writer(database.path, barrier, spool_root)
        try:
            assert segment_rows(database) == {"batch-a"}
            assert segment_file(spool_root, "batch-a").exists()
            report = replay_segments(
                fresh_db,
                barrier,
                spool_root=spool_root,
                installation_id=INSTALLATION_ID,
                exporters={"clickhouse": NoopExporter()},
                now=NOW,
            )
            assert list(report.record_ids) == acknowledged_ids
        finally:
            fresh_db.close()
    finally:
        database.close()
