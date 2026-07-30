"""Behavioural guarantees for the read-only spool audit (W03 slice 5a, ``spool verify``).

Verify walks ledger→file and reports each segment's integrity and delivery watermark WITHOUT
mutating anything. Its defining property (vs replay) is that it EXAMINES EVERY segment and RECORDS
failures rather than raising on the first bad one, so one corrupt or missing file never hides the
state of the rest.
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
    verify_spool,
)
from milhouse.spooling.errors import SpoolError
from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_DAY = "2026-07-28"
_GENERATION = "a" * 64


class _FakeExporter:
    def __init__(self, exporter_id: str) -> None:
        self._exporter_id = exporter_id

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record, frames) -> None:  # a confirming exporter
        return None


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


def _commit(store, batch_id: str, event_ids: tuple[str, ...]):
    frames = _frames(batch_id, event_ids)
    return store.commit_segment(_header(batch_id, frames), frames, committed_at=_NOW), frames


def _segment_file(spool_root: Path, batch_id: str) -> Path:
    return spool_root / "pending" / _DAY / f"{batch_id}.jsonl"


def test_a_healthy_undelivered_spool_verifies_intact(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1", "a-2"))
        _commit(store, "batch-b", ("b-1",))
        report = verify_spool(database, spool_root=spool_root, installation_id=_INSTALLATION_ID)
        assert [s.batch_id for s in report.segments] == ["batch-a", "batch-b"]
        assert all(s.intact and s.code is None for s in report.segments)
        assert report.intact is True
        assert report.compromised == ()
        # Exporters are still pending, so the delivery watermark is not yet satisfied.
        assert all(s.delivered is False for s in report.segments)
        assert report.fully_delivered is False
    finally:
        database.close()


def test_the_delivery_watermark_reflects_completed_delivery(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a-1",))
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}
        )
        report = verify_spool(database, spool_root=spool_root, installation_id=_INSTALLATION_ID)
        assert report.intact is True
        assert report.fully_delivered is True
        assert report.segments[0].delivered is True
    finally:
        database.close()


def test_a_missing_file_is_reported_without_hiding_the_rest(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1",))
        _commit(store, "batch-b", ("b-1",))
        _segment_file(spool_root, "batch-a").unlink()
        report = verify_spool(database, spool_root=spool_root, installation_id=_INSTALLATION_ID)
        by_id = {s.batch_id: s for s in report.segments}
        assert by_id["batch-a"].intact is False
        assert by_id["batch-a"].code == "MH_SPOOL_NOT_FOUND"
        # The audit did NOT abort: the healthy sibling is still reported.
        assert by_id["batch-b"].intact is True
        assert report.intact is False
        assert [s.batch_id for s in report.compromised] == ["batch-a"]
    finally:
        database.close()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("file_sha256", "'" + "d" * 64 + "'"),  # whole-file digest drift
        ("content_sha256", "'" + "e" * 64 + "'"),  # frame-bytes digest drift
        ("byte_size", "999999"),  # size drift
        ("record_count", "99"),  # count drift
        ("privacy_class", "'public'"),  # policy-field drift with intact bytes
        ("retention_days", "3650"),  # policy-field drift with intact bytes
        ("config_generation", "'" + "b" * 64 + "'"),  # policy-field drift with intact bytes
    ],
)
def test_any_ledger_field_drift_is_classified_as_a_verify_mismatch(
    tmp_path: Path, column: str, value: str
) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1",))
        # The durable file stays valid and authentic; only one ledger column is edited. verify uses
        # reconciliation's full agreement predicate, so a policy-field edit with intact bytes is
        # caught, not merely a digest change.
        with database.transaction() as connection:
            connection.execute(
                f"UPDATE _segments SET {column} = {value} WHERE batch_id = 'batch-a'"
            )
        report = verify_spool(database, spool_root=spool_root, installation_id=_INSTALLATION_ID)
        assert report.segments[0].intact is False
        assert report.segments[0].code == "MH_SPOOL_VERIFY"
    finally:
        database.close()


def test_a_corrupt_file_is_classified_not_raised(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1",))
        # Rewrite the segment body in place with non-canonical bytes; the trusted reader must reject
        # it, and verify must record the classification rather than raise.
        _segment_file(spool_root, "batch-a").write_bytes(b'{"not":"a header"}\n')
        report = verify_spool(database, spool_root=spool_root, installation_id=_INSTALLATION_ID)
        assert report.segments[0].intact is False
        assert report.segments[0].code is not None
        assert report.segments[0].code.startswith("MH_SPOOL_")
    finally:
        database.close()


def test_verify_over_an_empty_ledger_is_empty_and_vacuously_healthy(tmp_path: Path) -> None:
    database, _barrier, spool_root, _store = _spool(tmp_path)
    try:
        report = verify_spool(database, spool_root=spool_root, installation_id=_INSTALLATION_ID)
        assert report.segments == ()
        assert report.intact is True
        assert report.fully_delivered is True
        assert report.compromised == ()
    finally:
        database.close()


def test_verify_holds_no_barrier_so_it_runs_under_an_exclusive_hold(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", ("a-1",))
        # Verify acquires no barrier; it must complete even while exclusive maintenance authority is
        # held, or it would deadlock/block maintenance while auditing.
        with barrier.exclusive():
            report = verify_spool(database, spool_root=spool_root, installation_id=_INSTALLATION_ID)
        assert report.intact is True
    finally:
        database.close()


def test_verify_rejects_invalid_arguments(tmp_path: Path) -> None:
    database, _barrier, spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as bad_db:
            verify_spool(object(), spool_root=spool_root, installation_id=_INSTALLATION_ID)  # type: ignore[arg-type]
        assert bad_db.value.code == "MH_SPOOL_VERIFY"
        with pytest.raises(SpoolError) as bad_root:
            verify_spool(database, spool_root=None, installation_id=_INSTALLATION_ID)  # type: ignore[arg-type]
        assert bad_root.value.code == "MH_SPOOL_VERIFY"
        with pytest.raises(SpoolError) as bad_id:
            verify_spool(database, spool_root=spool_root, installation_id="not-an-installation")
        assert bad_id.value.code == "MH_SPOOL_IDENTITY"
    finally:
        database.close()
