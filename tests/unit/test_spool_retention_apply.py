"""Behavioural + crash guarantees for destructive retention apply (W03 slice 5b part 2).

retention_apply prunes fully-expired committed segments under exclusive maintenance authority with a
confirm token. It re-verifies each segment under the lock, prunes row-first (ledger row + audit in
one transaction, then the durable file), leaves mixed/live/unreadable/disagreeing segments alone,
and converges after an interrupted prune (a leftover orphan file is re-registered by reconciliation
and re-pruned on a later pass).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.config.filesystem import SecureFileError, SecureFileErrorKind
from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.spooling import (
    DurableSpool,
    SegmentHeaderV1,
    SpoolFrameV1,
    deliver_segment,
    retention_apply,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling import retention as retention_module
from milhouse.spooling.errors import SpoolError
from milhouse.state import (
    GlobalCommitBarrier,
    advance_cursor,
    initialize_control_state,
    list_audit,
    open_control_database,
    read_cursor,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_DAY = "2026-07-28"
_GENERATION = "a" * 64
_EXPIRED_AT = _NOW + timedelta(hours=1)
_LIVE_AT = _NOW + timedelta(days=30)
_APPLY_NOW = _NOW + timedelta(days=1)


class _FakeExporter:
    def __init__(self, exporter_id: str) -> None:
        self._exporter_id = exporter_id

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record, frames) -> None:
        return None


def _envelope(source_event_id: str, expires_at: datetime) -> RecordEnvelopeV1:
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": _NOW,
        "observed_at": _NOW + timedelta(seconds=1),
        "ingested_at": _NOW + timedelta(seconds=2),
        "expires_at": expires_at,
        "source_event_id": source_event_id,
        "operation_id": "operation-1",
        "collector_run_id": "collector-run-1",
        "scope": "target",
        "source": SourceDescriptorV1.model_validate(
            {
                "id": "example-source",
                "type": "source.event",
                "producer": "collector",
                "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
                "source_generation_digest": "0" * 64,
                "observation": {"kind": "source.revision", "parts": {"revision": 1}},
            }
        ),
        "collector": CollectorDescriptorV1(
            id="c", type="site.canary", implementation_version="1.0.0"
        ),
        "target": TargetDescriptorV1(
            id="example-target", name="E", kind="web.service", environment="test"
        ),
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "data": EventDataV1(category="availability", status="healthy", message="ok"),
    }
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=_INSTALLATION_ID)


def _frames(batch_id: str, specs: list[tuple[str, datetime]]) -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(batch_id=batch_id, sequence=index, record=_envelope(event_id, expires_at))
        for index, (event_id, expires_at) in enumerate(specs, start=1)
    ]


def _header(batch_id: str, frames: list[SpoolFrameV1]) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    return SegmentHeaderV1(
        batch_id=batch_id,
        config_generation=_GENERATION,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=("clickhouse",),
        record_count=len(frames),
        content_sha256=spool_content_sha256(lines),
    )


def _spool(tmp_path: Path):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    spool_root = tmp_path / "spool"
    spool_root.mkdir(mode=0o700)
    os.chmod(spool_root, 0o700)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    )
    return database, barrier, spool_root, store


def _commit(store, batch_id: str, specs: list[tuple[str, datetime]]):
    frames = _frames(batch_id, specs)
    return store.commit_segment(_header(batch_id, frames), frames, committed_at=_NOW), frames


def _segment_file(spool_root: Path, batch_id: str) -> Path:
    return spool_root / "pending" / _DAY / f"{batch_id}.jsonl"


def _segment_rows(database) -> set[str]:
    return {
        row[0] for row in database.connection.execute("SELECT batch_id FROM _segments").fetchall()
    }


def _apply(database, barrier, spool_root, *, now=_APPLY_NOW, confirm=True):
    return retention_apply(
        database,
        barrier,
        spool_root=spool_root,
        installation_id=_INSTALLATION_ID,
        now=now,
        confirm=confirm,
    )


def test_confirm_is_required(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        with pytest.raises(SpoolError) as captured:
            _apply(database, barrier, spool_root, confirm=False)
        assert captured.value.code == "MH_SPOOL_RETENTION"
        assert _segment_rows(database) == {"batch-a"}  # nothing pruned
        assert _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_prunes_a_fully_expired_delivered_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _EXPIRED_AT)])
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}
        )
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-a"]
        assert result.pruned_records == 2
        assert result.pruned_bytes == record.byte_size
        assert result.pruned[0].file_removed is True
        assert result.pruned[0].delivered is True
        assert _segment_rows(database) == set()  # ledger row gone
        assert not _segment_file(spool_root, "batch-a").exists()  # file gone
        exporter_rows = database.connection.execute(
            "SELECT count(*) FROM _segment_exporters WHERE batch_id = 'batch-a'"
        ).fetchone()[0]
        assert exporter_rows == 0
        audit = list_audit(database)
        assert len(audit) == 1
        assert (audit[0].action, audit[0].outcome, audit[0].resource) == (
            "retention_prune",
            "pruned",
            "batch-a",
        )
        assert (audit[0].record_count, audit[0].byte_size) == (2, record.byte_size)
    finally:
        database.close()


def test_prunes_an_undelivered_expired_segment_as_a_critical_event(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])  # never delivered
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-a"]
        assert result.pruned[0].delivered is False
        assert [p.batch_id for p in result.undelivered_pruned] == ["batch-a"]
        audit = list_audit(database)
        assert audit[0].outcome == "pruned_undelivered"  # the critical case
        assert audit[0].reason == "expired_undelivered"
    finally:
        database.close()


def test_leaves_live_and_mixed_segments(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-expired", [("e1", _EXPIRED_AT)])
        _commit(store, "batch-mixed", [("m1", _EXPIRED_AT), ("m2", _LIVE_AT)])
        _commit(store, "batch-live", [("l1", _LIVE_AT)])
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-expired"]
        skipped = {s.batch_id: s.status for s in result.skipped}
        assert skipped == {"batch-mixed": "mixed", "batch-live": "live"}
        # The non-expired segments and their files survive.
        assert _segment_rows(database) == {"batch-mixed", "batch-live"}
        assert _segment_file(spool_root, "batch-mixed").exists()
        assert _segment_file(spool_root, "batch-live").exists()
    finally:
        database.close()


def test_skips_an_unreadable_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        _segment_file(spool_root, "batch-a").unlink()  # the file is gone before apply
        result = _apply(database, barrier, spool_root)
        assert result.pruned == ()
        assert [s.status for s in result.skipped] == ["unreadable"]
        assert result.skipped[0].code == "MH_SPOOL_NOT_FOUND"
        assert _segment_rows(database) == {"batch-a"}  # the ledger row is NOT pruned blind
    finally:
        database.close()


def test_skips_a_ledger_disagreeing_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        # Corrupt the ledger's recorded count so the durable file no longer agrees with its row.
        with database.transaction() as connection:
            connection.execute("UPDATE _segments SET record_count = 99 WHERE batch_id = 'batch-a'")
        result = _apply(database, barrier, spool_root)
        assert result.pruned == ()
        assert [s.status for s in result.skipped] == ["disagreeing"]
        assert _segment_file(spool_root, "batch-a").exists()  # never pruned on disagreement
    finally:
        database.close()


def test_rerun_is_idempotent(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        first = _apply(database, barrier, spool_root)
        assert len(first.pruned) == 1
        second = _apply(database, barrier, spool_root)
        assert second.pruned == ()  # nothing left to prune
        assert second.skipped == ()
    finally:
        database.close()


def test_rejects_an_unbound_or_invalid_barrier(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        foreign = GlobalCommitBarrier(tmp_path / "unrelated.lock")
        with pytest.raises(SpoolError) as unbound:
            _apply(database, foreign, spool_root)
        assert unbound.value.code == "MH_SPOOL_RETENTION"
        with pytest.raises(SpoolError) as bad_type:
            retention_apply(
                database,
                object(),  # type: ignore[arg-type]
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
            )
        assert bad_type.value.code == "MH_SPOOL_RETENTION"
        assert _segment_rows(database) == {"batch-a"}  # nothing pruned under a bad barrier
    finally:
        database.close()


def test_rejects_a_spool_root_not_bound_to_the_state_root(tmp_path: Path) -> None:
    database, barrier, _spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as captured:
            retention_apply(
                database,
                barrier,
                spool_root=tmp_path / "wrong-spool",  # not <state_root>/spool
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
            )
        assert captured.value.code == "MH_SPOOL_RETENTION"
    finally:
        database.close()


class _HostilePath:
    """A path-like whose __fspath__ raises — an unresolvable spool root."""

    def __fspath__(self) -> str:
        raise ValueError("hostile fspath")


def test_rejects_a_malformed_spool_root_path(tmp_path: Path) -> None:
    database, barrier, _spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as captured:
            retention_apply(
                database,
                barrier,
                spool_root=_HostilePath(),  # a PathLike that cannot be resolved
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
            )
        assert captured.value.code == "MH_SPOOL_RETENTION"
    finally:
        database.close()


def test_rejects_a_closed_database(tmp_path: Path) -> None:
    database, barrier, spool_root, _store = _spool(tmp_path)
    database.close()
    with pytest.raises(SpoolError) as captured:
        retention_apply(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            now=_APPLY_NOW,
            confirm=True,
        )
    assert captured.value.code == "MH_SPOOL_RETENTION"


def test_rejects_invalid_common_arguments(tmp_path: Path) -> None:
    database, barrier, spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as bad_id:
            retention_apply(
                database,
                barrier,
                spool_root=spool_root,
                installation_id="nope",
                now=_APPLY_NOW,
                confirm=True,
            )
        assert bad_id.value.code == "MH_SPOOL_IDENTITY"
        with pytest.raises(SpoolError) as bad_now:
            retention_apply(
                database,
                barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                now=datetime(2026, 7, 28, 12),  # naive
                confirm=True,
            )
        assert bad_now.value.code == "MH_SPOOL_RETENTION"
    finally:
        database.close()


def test_a_failed_transactional_prune_leaves_the_segment_intact(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        # Drop the audit table so the in-transaction record_audit fails AFTER the two DELETEs.
        # Because the prune is one transaction, the DELETEs roll back and the segment stays intact
        # (row AND file) — never a half-prune.
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")
        result = _apply(database, barrier, spool_root)
        assert result.pruned == ()
        assert [s.status for s in result.skipped] == ["fully_expired"]
        assert result.skipped[0].code == "MH_SPOOL_RETENTION"
        assert _segment_rows(database) == {"batch-a"}  # the ledger row was rolled back
        assert _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_an_interrupted_unlink_leaves_a_re_registerable_orphan_that_reconverges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])

        # Simulate a crash/failure AFTER the ledger row + audit commit but BEFORE the unlink.
        def failing_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(retention_module, "remove_regular_file_no_follow", failing_remove)
        first = _apply(database, barrier, spool_root)
        assert len(first.pruned) == 1
        assert first.pruned[0].file_removed is False  # the durable file lingers as an orphan
        assert [p.batch_id for p in first.orphaned_files] == ["batch-a"]
        # Row-first: the ledger row is gone but the file remains — NOT a row-without-file.
        assert _segment_rows(database) == set()
        assert _segment_file(spool_root, "batch-a").exists()

        # Reconciliation (run on a fresh writer acquisition) re-registers the orphan file.
        DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        assert _segment_rows(database) == {"batch-a"}  # re-registered as a committed segment

        # A later retention pass (unlink working again) re-prunes it to convergence.
        monkeypatch.undo()
        second = _apply(database, barrier, spool_root)
        assert len(second.pruned) == 1
        assert second.pruned[0].file_removed is True
        assert _segment_rows(database) == set()
        assert not _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_prunes_a_cursor_referenced_undelivered_expired_segment(tmp_path: Path) -> None:
    # D05: a privacy-expired segment referenced by an idle source's cursor must still be pruned; the
    # cursor is detached (batch_id -> NULL) while its resumable position/revision survive.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        advance_cursor(
            database, "github", position="page-7", batch_id="batch-a", now=_NOW, expected_revision=0
        )
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-a"]  # NOT skipped by the FK anymore
        assert _segment_rows(database) == set()
        assert not _segment_file(spool_root, "batch-a").exists()
        cursor = read_cursor(database, "github")
        assert cursor is not None
        assert cursor.batch_id is None  # detached
        assert (cursor.position, cursor.revision) == ("page-7", 1)  # resumable state preserved
        assert list_audit(database)[0].outcome == "pruned_undelivered"
    finally:
        database.close()


def test_prunes_a_cursor_referenced_delivered_expired_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}
        )
        advance_cursor(
            database, "github", position="page-7", batch_id="batch-a", now=_NOW, expected_revision=0
        )
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-a"]
        assert _segment_rows(database) == set()
        cursor = read_cursor(database, "github")
        assert cursor is not None and cursor.batch_id is None
        assert (cursor.position, cursor.revision) == ("page-7", 1)
        assert list_audit(database)[0].outcome == "pruned"
    finally:
        database.close()


def test_a_detached_cursor_survives_crash_reregistration_and_reprune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        advance_cursor(
            database, "github", position="page-7", batch_id="batch-a", now=_NOW, expected_revision=0
        )

        def failing_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(retention_module, "remove_regular_file_no_follow", failing_remove)
        first = _apply(database, barrier, spool_root)
        assert first.pruned[0].file_removed is False  # orphan file lingers; ledger row gone
        assert _segment_rows(database) == set()
        detached = read_cursor(database, "github")
        assert detached is not None and detached.batch_id is None
        assert (detached.position, detached.revision) == ("page-7", 1)

        # Reconciliation re-registers the orphan; the cursor stays detached (position/revision).
        DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        assert _segment_rows(database) == {"batch-a"}
        still = read_cursor(database, "github")
        assert still is not None and still.batch_id is None
        assert (still.position, still.revision) == ("page-7", 1)

        # A later pass re-prunes to convergence; the cursor checkpoint stays intact and resumable.
        monkeypatch.undo()
        second = _apply(database, barrier, spool_root)
        assert len(second.pruned) == 1
        assert _segment_rows(database) == set()
        final = read_cursor(database, "github")
        assert final is not None and final.batch_id is None
        assert (final.position, final.revision) == ("page-7", 1)
    finally:
        database.close()
