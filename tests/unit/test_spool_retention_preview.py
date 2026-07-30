"""Behavioural guarantees for read-only retention preview (W03 slice 5b, plan section 4.8).

Retention is per-record-expiry driven: a segment is fully expired only when its every record's
``expires_at`` has passed, mixed when some have, and live when none have. Preview classifies each
segment by reading its durable frames and reports exact reclaimable counts/bytes without mutating.
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
    deliver_segment,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.retention import (
    STATUS_DISAGREEING,
    STATUS_FULLY_EXPIRED,
    STATUS_LIVE,
    STATUS_MIXED,
    STATUS_UNREADABLE,
    retention_preview,
)
from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_DAY = "2026-07-28"
_GENERATION = "a" * 64
_EXPIRED_AT = _NOW + timedelta(hours=1)  # already past by preview time
_LIVE_AT = _NOW + timedelta(days=30)  # still in the future by preview time
_PREVIEW_NOW = _NOW + timedelta(days=1)


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


def test_preview_classifies_fully_expired_mixed_and_live(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-expired", [("e1", _EXPIRED_AT), ("e2", _EXPIRED_AT)])
        _commit(store, "batch-mixed", [("m1", _EXPIRED_AT), ("m2", _LIVE_AT)])
        _commit(store, "batch-live", [("l1", _LIVE_AT)])
        preview = retention_preview(
            database, spool_root=spool_root, installation_id=_INSTALLATION_ID, now=_PREVIEW_NOW
        )
        by_id = {s.batch_id: s.status for s in preview.segments}
        assert by_id == {
            "batch-expired": STATUS_FULLY_EXPIRED,
            "batch-mixed": STATUS_MIXED,
            "batch-live": STATUS_LIVE,
        }
        assert [s.batch_id for s in preview.fully_expired] == ["batch-expired"]
        assert [s.batch_id for s in preview.compaction_candidates] == ["batch-mixed"]
    finally:
        database.close()


def test_reclaimable_counts_and_bytes_sum_only_fully_expired(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        expired_record, _ = _commit(
            store, "batch-expired", [("e1", _EXPIRED_AT), ("e2", _EXPIRED_AT)]
        )
        _commit(store, "batch-live", [("l1", _LIVE_AT)])
        preview = retention_preview(
            database, spool_root=spool_root, installation_id=_INSTALLATION_ID, now=_PREVIEW_NOW
        )
        assert preview.reclaimable_records == 2  # only the expired segment's two records
        assert preview.reclaimable_bytes == expired_record.byte_size
    finally:
        database.close()


def test_an_expired_but_undelivered_segment_is_flagged(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        delivered_record, delivered_frames = _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        deliver_segment(
            database,
            barrier,
            delivered_record,
            delivered_frames,
            {"clickhouse": _FakeExporter("clickhouse")},
        )
        _commit(store, "batch-b", [("b1", _EXPIRED_AT)])  # left undelivered
        preview = retention_preview(
            database, spool_root=spool_root, installation_id=_INSTALLATION_ID, now=_PREVIEW_NOW
        )
        # Both are fully expired, but only the undelivered one is a critical-on-removal case.
        assert {s.batch_id for s in preview.fully_expired} == {"batch-a", "batch-b"}
        assert [s.batch_id for s in preview.undelivered_expired] == ["batch-b"]
    finally:
        database.close()


def test_an_empty_segment_is_left_live(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        frames: list[SpoolFrameV1] = []
        store.commit_segment(_header("batch-empty", frames), frames, committed_at=_NOW)
        preview = retention_preview(
            database, spool_root=spool_root, installation_id=_INSTALLATION_ID, now=_PREVIEW_NOW
        )
        assert preview.segments[0].status == STATUS_LIVE  # no record-class expiry to reason about
        assert preview.fully_expired == ()
    finally:
        database.close()


def test_an_unreadable_segment_is_reported_not_prunable(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        _segment_file(spool_root, "batch-a").unlink()
        preview = retention_preview(
            database, spool_root=spool_root, installation_id=_INSTALLATION_ID, now=_PREVIEW_NOW
        )
        segment = preview.segments[0]
        assert segment.status == STATUS_UNREADABLE
        assert segment.code == "MH_SPOOL_NOT_FOUND"
        assert preview.fully_expired == ()  # never treated as reclaimable
        assert [s.batch_id for s in preview.unreadable] == ["batch-a"]
    finally:
        database.close()


def test_a_ledger_disagreeing_segment_is_not_reclaimable(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        # The durable file is still readable and expired, but the ledger row no longer agrees with
        # it. Preview must report it disagreeing (matching what apply skips), not fully_expired,
        # so the reclaimable estimate never overstates.
        with database.transaction() as connection:
            connection.execute("UPDATE _segments SET record_count = 99 WHERE batch_id = 'batch-a'")
        preview = retention_preview(
            database, spool_root=spool_root, installation_id=_INSTALLATION_ID, now=_PREVIEW_NOW
        )
        assert preview.segments[0].status == STATUS_DISAGREEING
        assert preview.fully_expired == ()
        assert preview.reclaimable_records == 0
    finally:
        database.close()


def test_preview_over_an_empty_ledger_is_empty(tmp_path: Path) -> None:
    database, _barrier, spool_root, _store = _spool(tmp_path)
    try:
        preview = retention_preview(
            database, spool_root=spool_root, installation_id=_INSTALLATION_ID, now=_PREVIEW_NOW
        )
        assert preview.segments == ()
        assert preview.reclaimable_records == 0
        assert preview.reclaimable_bytes == 0
    finally:
        database.close()


def test_preview_rejects_invalid_arguments(tmp_path: Path) -> None:
    database, _barrier, spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as bad_db:
            retention_preview(
                object(),
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                now=_PREVIEW_NOW,  # type: ignore[arg-type]
            )
        assert bad_db.value.code == "MH_SPOOL_RETENTION"
        with pytest.raises(SpoolError) as bad_root:
            retention_preview(
                database,
                spool_root=None,
                installation_id=_INSTALLATION_ID,
                now=_PREVIEW_NOW,  # type: ignore[arg-type]
            )
        assert bad_root.value.code == "MH_SPOOL_RETENTION"
        with pytest.raises(SpoolError) as bad_id:
            retention_preview(
                database, spool_root=spool_root, installation_id="nope", now=_PREVIEW_NOW
            )
        assert bad_id.value.code == "MH_SPOOL_IDENTITY"
        with pytest.raises(SpoolError) as bad_now:
            retention_preview(
                database,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                now=datetime(2026, 7, 28, 12),  # naive
            )
        assert bad_now.value.code == "MH_SPOOL_RETENTION"
    finally:
        database.close()
