"""Integrity + state-machine guarantees for the exporter delivery protocol (W03 slice 4; D05 fix).

A terminal ``delivered`` can never be recorded for the wrong data: delivery binds the barrier to the
live database, reloads the authoritative ledger row, rejects a supplied record that does not match
it, and requires the supplied frames to hash to that row's content digest (with matching batch id and
count) before anything is forwarded. Each exporter object must self-identify, and only a compare-and-
set that actually advances the expected row is reported as a new delivery.
"""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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
    Exporter,
    SegmentHeaderV1,
    SegmentRecord,
    SpoolFrameV1,
    deliver_segment,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling import exporter as exporter_module
from milhouse.spooling.errors import SpoolError
from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_GENERATION = "a" * 64


class _FakeExporter:
    def __init__(self, exporter_id: str, *, fail: bool = False) -> None:
        self._exporter_id = exporter_id
        self._fail = fail
        self.deliveries: list[str] = []

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record: SegmentRecord, frames) -> None:
        self.deliveries.append(record.batch_id)
        if self._fail:
            raise RuntimeError("destination unavailable")


def _envelope(source_event_id: str) -> RecordEnvelopeV1:
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": _NOW,
        "observed_at": _NOW + timedelta(seconds=1),
        "ingested_at": _NOW + timedelta(seconds=2),
        "expires_at": _NOW + timedelta(days=30),
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


def _frames(batch_id: str, event_ids: tuple[str, ...]) -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(batch_id=batch_id, sequence=index, record=_envelope(event_id))
        for index, event_id in enumerate(event_ids, start=1)
    ]


def _header(
    batch_id: str, frames: list[SpoolFrameV1], exporters: tuple[str, ...]
) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    return SegmentHeaderV1(
        batch_id=batch_id,
        config_generation=_GENERATION,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=exporters,
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
    return database, barrier, store


def _commit(store, batch_id: str, event_ids: tuple[str, ...], exporters=("clickhouse",)):
    frames = _frames(batch_id, event_ids)
    record = store.commit_segment(_header(batch_id, frames, exporters), frames, committed_at=_NOW)
    return record, frames


def _status(database, batch_id: str, exporter_id: str) -> str | None:
    row = database.connection.execute(
        "SELECT delivery_status FROM _segment_exporters WHERE batch_id = ? AND exporter_id = ?",
        (batch_id, exporter_id),
    ).fetchone()
    return None if row is None else str(row[0])


def test_the_protocol_is_satisfied_by_a_concrete_exporter() -> None:
    assert isinstance(_FakeExporter("clickhouse"), Exporter)


def test_delivers_matching_frames_and_records_delivered(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1", "a2"))
        exporter = _FakeExporter("clickhouse")
        attempts = deliver_segment(database, barrier, record, frames, {"clickhouse": exporter})
        assert [(a.exporter_id, a.outcome) for a in attempts] == [("clickhouse", "delivered")]
        assert exporter.deliveries == ["batch-a"]
        assert _status(database, "batch-a", "clickhouse") == "delivered"
    finally:
        database.close()


def test_a_failing_exporter_records_failed(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        attempts = deliver_segment(
            database,
            barrier,
            record,
            frames,
            {"clickhouse": _FakeExporter("clickhouse", fail=True)},
        )
        assert [a.outcome for a in attempts] == ["failed"]
        assert _status(database, "batch-a", "clickhouse") == "failed"
    finally:
        database.close()


def test_an_already_delivered_exporter_is_skipped_idempotently(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        exporter = _FakeExporter("clickhouse")
        deliver_segment(database, barrier, record, frames, {"clickhouse": exporter})
        attempts = deliver_segment(database, barrier, record, frames, {"clickhouse": exporter})
        assert [a.outcome for a in attempts] == ["already_delivered"]
        assert exporter.deliveries == ["batch-a"]  # not delivered a second time
    finally:
        database.close()


def test_frames_from_another_segment_are_refused_and_nothing_is_certified(tmp_path: Path) -> None:
    # THE D05 integrity case: forwarding batch-b frames under the batch-a record must fail closed —
    # the exporter is never called and batch-a is never marked delivered.
    database, barrier, store = _spool(tmp_path)
    try:
        record_a, _frames_a = _commit(store, "batch-a", ("a1",))
        _record_b, frames_b = _commit(store, "batch-b", ("b1",))
        exporter = _FakeExporter("clickhouse")
        with pytest.raises(SpoolError) as captured:
            deliver_segment(database, barrier, record_a, frames_b, {"clickhouse": exporter})
        assert captured.value.code == "MH_SPOOL_EXPORT"
        assert exporter.deliveries == []  # nothing forwarded
        assert _status(database, "batch-a", "clickhouse") == "pending"  # never certified
    finally:
        database.close()


def test_same_batch_frames_with_a_different_content_digest_are_refused(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record_a, _frames_a = _commit(store, "batch-a", ("a1",))
        # A different batch-a frame: same batch id and count, but different record content.
        forged = _frames("batch-a", ("different-event",))
        with pytest.raises(SpoolError) as captured:
            deliver_segment(
                database, barrier, record_a, forged, {"clickhouse": _FakeExporter("clickhouse")}
            )
        assert captured.value.code == "MH_SPOOL_EXPORT"
        assert _status(database, "batch-a", "clickhouse") == "pending"
    finally:
        database.close()


def test_a_frame_count_mismatch_is_refused(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record_a, _frames_a = _commit(store, "batch-a", ("a1", "a2"))
        with pytest.raises(SpoolError) as captured:
            deliver_segment(
                database, barrier, record_a, [], {"clickhouse": _FakeExporter("clickhouse")}
            )
        assert captured.value.code == "MH_SPOOL_EXPORT"
    finally:
        database.close()


def test_a_fabricated_or_uncommitted_record_is_refused(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        with pytest.raises(SpoolError) as tampered:  # same batch id, tampered content digest
            deliver_segment(
                database,
                barrier,
                replace(record, content_sha256="d" * 64),
                frames,
                {"clickhouse": _FakeExporter("clickhouse")},
            )
        assert tampered.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as ghost:  # a batch id that was never committed
            deliver_segment(
                database,
                barrier,
                replace(record, batch_id="ghost-1"),
                frames,
                {"clickhouse": _FakeExporter("clickhouse")},
            )
        assert ghost.value.code == "MH_SPOOL_EXPORT"
    finally:
        database.close()


def test_a_mis_identified_exporter_object_never_certifies(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        impostor = _FakeExporter(
            "somewhere-else"
        )  # registered under 'clickhouse', claims another id
        attempts = deliver_segment(database, barrier, record, frames, {"clickhouse": impostor})
        assert [a.outcome for a in attempts] == ["no_exporter"]
        assert impostor.deliveries == []
        assert _status(database, "batch-a", "clickhouse") == "pending"
    finally:
        database.close()


def test_an_unsupplied_exporter_is_reported_without_touching_the_ledger(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        attempts = deliver_segment(database, barrier, record, frames, {})
        assert [a.outcome for a in attempts] == ["no_exporter"]
        assert _status(database, "batch-a", "clickhouse") == "pending"
    finally:
        database.close()


def test_a_wrong_barrier_is_refused(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        foreign = GlobalCommitBarrier(tmp_path / "unrelated.lock")
        with pytest.raises(SpoolError) as captured:
            deliver_segment(
                database, foreign, record, frames, {"clickhouse": _FakeExporter("clickhouse")}
            )
        assert captured.value.code == "MH_SPOOL_EXPORT"
        assert _status(database, "batch-a", "clickhouse") == "pending"
    finally:
        database.close()


def test_a_zero_row_compare_and_set_is_not_reported_as_a_new_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        # Deliver for real so the ledger row is terminal-delivered.
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}
        )
        # Force the reload to report the exporter as still pending (a stale snapshot); the attempt
        # succeeds but the compare-and-set affects zero rows because the row is already delivered, so
        # this pass must NOT claim a new delivery.
        stale = replace(
            record, exporters=(replace(record.exporters[0], delivery_status="pending"),)
        )
        monkeypatch.setattr(exporter_module, "_reload_record", lambda database, record: stale)
        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}
        )
        assert [a.outcome for a in attempts] == ["already_delivered"]
        assert _status(database, "batch-a", "clickhouse") == "delivered"
    finally:
        database.close()


def test_a_broken_delivery_ledger_write_normalizes_to_a_stable_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        # Bypass the DB reload, then drop the delivery ledger so only the status compare-and-set hits
        # the broken table; the backend fault must normalize to the fixed code.
        monkeypatch.setattr(exporter_module, "_reload_record", lambda database, record: record)
        with database.transaction() as connection:
            connection.execute("DROP TABLE _segment_exporters")
        with pytest.raises(SpoolError) as captured:
            deliver_segment(
                database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}
            )
        assert captured.value.code == "MH_SPOOL_EXPORT"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


def test_invalid_arguments_are_rejected(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        with pytest.raises(SpoolError) as bad_db:
            deliver_segment(object(), barrier, record, frames, {})  # type: ignore[arg-type]
        assert bad_db.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_barrier:
            deliver_segment(database, object(), record, frames, {})  # type: ignore[arg-type]
        assert bad_barrier.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_record:
            deliver_segment(database, barrier, object(), frames, {})  # type: ignore[arg-type]
        assert bad_record.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_exporters:
            deliver_segment(database, barrier, record, frames, None)  # type: ignore[arg-type]
        assert bad_exporters.value.code == "MH_SPOOL_EXPORT"
    finally:
        database.close()
