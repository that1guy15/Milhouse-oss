"""Behavioural guarantees for deterministic, idempotent segment replay (W03 slice 4, section 4.3).

Replay re-reads committed segments as trusted state and re-drives delivery. It is deterministic
(segments in batch-id order, frames in sequence order) and idempotent (re-reading verifies the file
against the ledger; delivery is a compare-and-set), so replaying twice yields identical logical ids
and counts — the property the G03 evidence packet exercises at 10,000-record scale.
"""

from __future__ import annotations

import os
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
    SegmentHeaderV1,
    SpoolFrameV1,
    replay_segments,
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
    def __init__(self, exporter_id: str) -> None:
        self._exporter_id = exporter_id
        self.deliveries: list[str] = []

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record, frames) -> None:
        self.deliveries.append(record.batch_id)


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


def _commit(store, batch_id: str, event_ids: tuple[str, ...]) -> None:
    frames = _frames(batch_id, event_ids)
    store.commit_segment(_header(batch_id, frames), frames, committed_at=_NOW)


def test_replay_visits_segments_in_deterministic_order(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        # Commit out of lexical order to prove replay sorts by batch id, not commit order.
        _commit(store, "batch-b", ("b-1", "b-2"))
        _commit(store, "batch-a", ("a-1",))
        report = replay_segments(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            exporters={"clickhouse": _FakeExporter("clickhouse")},
        )
        assert report.segments == ("batch-a", "batch-b")
        assert report.record_count == 3
        assert len(report.record_ids) == 3
        assert len(set(report.record_ids)) == 3  # distinct logical records
    finally:
        database.close()


def test_replaying_twice_yields_identical_ids_and_counts(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1", "a-2"))
        _commit(store, "batch-b", ("b-1",))
        exporter = _FakeExporter("clickhouse")

        first = replay_segments(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            exporters={"clickhouse": exporter},
        )
        second = replay_segments(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            exporters={"clickhouse": exporter},
        )

        assert second.record_ids == first.record_ids  # identical logical id stream
        assert second.record_count == first.record_count == 3
        assert [a.outcome for a in first.delivery_attempts] == ["delivered", "delivered"]
        # The second pass re-emits the same ids but does NOT re-deliver already-delivered segments.
        assert [a.outcome for a in second.delivery_attempts] == [
            "already_delivered",
            "already_delivered",
        ]
        assert exporter.deliveries == ["batch-a", "batch-b"]  # delivered exactly once each
    finally:
        database.close()


def test_replay_can_narrow_to_pending_delivery(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1",))
        exporter = _FakeExporter("clickhouse")
        # Deliver everything first.
        replay_segments(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            exporters={"clickhouse": exporter},
        )
        # Now only pending-delivery segments are in scope — there are none left.
        narrowed = replay_segments(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            exporters={"clickhouse": exporter},
            delivery_status="pending",
        )
        assert narrowed.segments == ()
        assert narrowed.record_count == 0
    finally:
        database.close()


def test_replay_rejects_a_durable_file_that_drifted_from_the_ledger(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1",))
        # Corrupt only the ledger's recorded digest; the durable file is still valid and authentic,
        # so the trusted reader passes but the cross-check against the ledger row must fail closed.
        with database.transaction() as connection:
            connection.execute(
                "UPDATE _segments SET file_sha256 = ? WHERE batch_id = 'batch-a'", ("d" * 64,)
            )
        with pytest.raises(SpoolError) as captured:
            replay_segments(
                database,
                barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                exporters={"clickhouse": _FakeExporter("clickhouse")},
            )
        assert captured.value.code == "MH_SPOOL_REPLAY"
    finally:
        database.close()


def test_replay_fails_closed_when_a_committed_file_is_missing(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1",))
        segment_file = spool_root / "pending" / "2026-07-28" / "batch-a.jsonl"
        segment_file.unlink()
        with pytest.raises(SpoolError) as captured:
            replay_segments(
                database,
                barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                exporters={"clickhouse": _FakeExporter("clickhouse")},
            )
        assert (
            captured.value.code == "MH_SPOOL_NOT_FOUND"
        )  # a committed row with no file fails hard
    finally:
        database.close()


def test_replay_over_an_empty_ledger_is_an_empty_report(tmp_path: Path) -> None:
    database, barrier, spool_root, _store = _spool(tmp_path)
    try:
        report = replay_segments(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            exporters={},
        )
        assert report.segments == ()
        assert report.record_ids == ()
        assert report.delivery_attempts == ()
    finally:
        database.close()


def test_replay_rejects_invalid_arguments(tmp_path: Path) -> None:
    database, barrier, spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as bad_db:
            replay_segments(
                object(),  # type: ignore[arg-type]
                barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                exporters={},
            )
        assert bad_db.value.code == "MH_SPOOL_REPLAY"
        with pytest.raises(SpoolError) as bad_barrier:
            replay_segments(
                database,
                object(),  # type: ignore[arg-type]
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                exporters={},
            )
        assert bad_barrier.value.code == "MH_SPOOL_REPLAY"
        with pytest.raises(SpoolError) as bad_id:
            replay_segments(
                database,
                barrier,
                spool_root=spool_root,
                installation_id="not-an-installation",
                exporters={},
            )
        assert bad_id.value.code == "MH_SPOOL_IDENTITY"
    finally:
        database.close()
