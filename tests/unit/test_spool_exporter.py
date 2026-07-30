"""Behavioural guarantees for the exporter delivery protocol (W03 slice 4, pipeline rules 11-12).

Delivery is at-least-once with a terminal ``delivered`` state: a confirmed delivery is recorded
only after the exporter returns, a failure stays retryable, and no later attempt can un-deliver a
segment. A misbehaving exporter is contained as a failed delivery rather than crashing the pipeline.
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
    ExporterDelivery,
    SegmentHeaderV1,
    SegmentRecord,
    SpoolFrameV1,
    deliver_segment,
    spool_content_sha256,
    spool_frame_line,
)
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
    """An in-memory exporter that records what it was handed and optionally fails delivery."""

    def __init__(self, exporter_id: str, *, fail: bool = False) -> None:
        self._exporter_id = exporter_id
        self._fail = fail
        self.deliveries: list[tuple[str, tuple[int, ...]]] = []

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record: SegmentRecord, frames) -> None:
        self.deliveries.append((record.batch_id, tuple(frame.sequence for frame in frames)))
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


def _frames() -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(batch_id="batch-1", sequence=1, record=_envelope("event-1")),
        SpoolFrameV1(batch_id="batch-1", sequence=2, record=_envelope("event-2")),
    ]


def _header(frames: list[SpoolFrameV1], *, exporters: tuple[str, ...]) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    return SegmentHeaderV1(
        batch_id="batch-1",
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


def _delivery_status(database, exporter_id: str) -> str | None:
    row = database.connection.execute(
        "SELECT delivery_status FROM _segment_exporters WHERE batch_id = ? AND exporter_id = ?",
        ("batch-1", exporter_id),
    ).fetchone()
    return None if row is None else str(row[0])


def _committed(tmp_path: Path, exporters: tuple[str, ...]):
    database, barrier, store = _spool(tmp_path)
    frames = _frames()
    record = store.commit_segment(_header(frames, exporters=exporters), frames, committed_at=_NOW)
    return database, barrier, record, frames


def test_the_exported_protocol_is_satisfied_by_a_concrete_exporter() -> None:
    assert isinstance(_FakeExporter("clickhouse"), Exporter)


def test_a_pending_exporter_is_delivered_after_confirmation(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("clickhouse",))
    try:
        exporter = _FakeExporter("clickhouse")
        attempts = deliver_segment(database, barrier, record, frames, {"clickhouse": exporter})
        assert [(a.exporter_id, a.outcome) for a in attempts] == [("clickhouse", "delivered")]
        assert exporter.deliveries == [("batch-1", (1, 2))]  # the exporter saw the segment's frames
        assert _delivery_status(database, "clickhouse") == "delivered"
    finally:
        database.close()


def test_a_failing_exporter_is_recorded_failed_and_stays_retryable(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("clickhouse",))
    try:
        failing = _FakeExporter("clickhouse", fail=True)
        attempts = deliver_segment(database, barrier, record, frames, {"clickhouse": failing})
        assert [a.outcome for a in attempts] == ["failed"]
        assert _delivery_status(database, "clickhouse") == "failed"

        # A failed row is retryable: a later pass with a working exporter delivers it.
        retried = replace(record, exporters=(ExporterDelivery("clickhouse", "failed"),))
        healthy = _FakeExporter("clickhouse")
        again = deliver_segment(database, barrier, retried, frames, {"clickhouse": healthy})
        assert [a.outcome for a in again] == ["delivered"]
        assert _delivery_status(database, "clickhouse") == "delivered"
    finally:
        database.close()


def test_a_delivered_exporter_is_skipped_idempotently(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("clickhouse",))
    try:
        exporter = _FakeExporter("clickhouse")
        deliver_segment(database, barrier, record, frames, {"clickhouse": exporter})
        delivered_record = replace(record, exporters=(ExporterDelivery("clickhouse", "delivered"),))
        attempts = deliver_segment(
            database, barrier, delivered_record, frames, {"clickhouse": exporter}
        )
        assert [a.outcome for a in attempts] == ["already_delivered"]
        assert exporter.deliveries == [("batch-1", (1, 2))]  # not delivered a second time
    finally:
        database.close()


def test_an_unsupplied_exporter_is_reported_without_touching_the_ledger(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("clickhouse",))
    try:
        attempts = deliver_segment(database, barrier, record, frames, {})
        assert [a.outcome for a in attempts] == ["no_exporter"]
        assert _delivery_status(database, "clickhouse") == "pending"  # untouched
    finally:
        database.close()


def test_a_malformed_exporter_id_is_reported_as_no_exporter(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("clickhouse",))
    try:
        # A defensive guard: even with an exporter supplied under a malformed key, no delivery runs.
        poisoned = replace(record, exporters=(ExporterDelivery("Bad Id", "pending"),))
        exporter = _FakeExporter("Bad Id")
        attempts = deliver_segment(database, barrier, poisoned, frames, {"Bad Id": exporter})
        assert [a.outcome for a in attempts] == ["no_exporter"]
        assert exporter.deliveries == []
    finally:
        database.close()


def test_multiple_exporters_are_delivered_independently(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("alerts", "clickhouse"))
    try:
        healthy = _FakeExporter("clickhouse")
        broken = _FakeExporter("alerts", fail=True)
        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": healthy, "alerts": broken}
        )
        outcomes = {a.exporter_id: a.outcome for a in attempts}
        assert outcomes == {"alerts": "failed", "clickhouse": "delivered"}
        assert _delivery_status(database, "clickhouse") == "delivered"
        assert _delivery_status(database, "alerts") == "failed"
    finally:
        database.close()


def test_a_confirmed_delivery_is_never_overwritten_by_a_later_failure(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("clickhouse",))
    try:
        # Simulate a concurrent pass that already delivered while this caller still holds a stale
        # record showing 'pending'. This caller's exporter then fails.
        with database.transaction() as connection:
            connection.execute(
                "UPDATE _segment_exporters SET delivery_status = 'delivered' "
                "WHERE batch_id = 'batch-1' AND exporter_id = 'clickhouse'"
            )
        failing = _FakeExporter("clickhouse", fail=True)
        attempts = deliver_segment(database, barrier, record, frames, {"clickhouse": failing})
        assert [a.outcome for a in attempts] == ["failed"]  # this pass observed a failure
        # ...but the compare-and-set refused to clobber the terminal 'delivered' row.
        assert _delivery_status(database, "clickhouse") == "delivered"
    finally:
        database.close()


def test_a_broken_ledger_write_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("clickhouse",))
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _segment_exporters")
        exporter = _FakeExporter("clickhouse")
        with pytest.raises(SpoolError) as captured:
            deliver_segment(database, barrier, record, frames, {"clickhouse": exporter})
        assert captured.value.code == "MH_SPOOL_EXPORT"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


def test_invalid_arguments_are_rejected(tmp_path: Path) -> None:
    database, barrier, record, frames = _committed(tmp_path, ("clickhouse",))
    try:
        with pytest.raises(SpoolError) as bad_db:
            deliver_segment(object(), barrier, record, frames, {})  # type: ignore[arg-type]
        assert bad_db.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_barrier:
            deliver_segment(database, object(), record, frames, {})  # type: ignore[arg-type]
        assert bad_barrier.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_record:
            deliver_segment(database, barrier, object(), frames, {})  # type: ignore[arg-type]
        assert bad_record.value.code == "MH_SPOOL_EXPORT"
    finally:
        database.close()
