"""Integrity + state-machine guarantees for the exporter delivery protocol (W03 slice 4; D05 fix).

A terminal ``delivered`` can never be recorded for the wrong data: delivery freezes the caller's
frames to one immutable tuple, binds the barrier to the live database, reloads the authoritative
ledger row, rejects a supplied record that does not match it, and requires that frozen tuple to hash
to the row's content digest (matching batch id and count) before anything is forwarded. Delivery is
fenced under one shared-barrier hold so privacy-expiry retention cannot prune mid-delivery, is
withheld for any expired record, and reports a pruned row as ``segment_gone`` — never as a delivery.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
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
from milhouse.state.errors import StateError

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_GENERATION = "a" * 64


class _FakeExporter:
    def __init__(self, exporter_id: str, *, fail: bool = False) -> None:
        self._exporter_id = exporter_id
        self._fail = fail
        self.deliveries: list[str] = []
        self.received_frames: tuple[SpoolFrameV1, ...] | None = None

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record: SegmentRecord, frames) -> None:
        self.deliveries.append(record.batch_id)
        self.received_frames = tuple(frames)
        if self._fail:
            raise RuntimeError("destination unavailable")


def _envelope(source_event_id: str, *, expires_at: datetime | None = None) -> RecordEnvelopeV1:
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": _NOW,
        "observed_at": _NOW + timedelta(seconds=1),
        "ingested_at": _NOW + timedelta(seconds=2),
        "expires_at": expires_at if expires_at is not None else _NOW + timedelta(days=30),
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


def _frames(
    batch_id: str, event_ids: tuple[str, ...], *, expires_at: datetime | None = None
) -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(
            batch_id=batch_id, sequence=index, record=_envelope(event_id, expires_at=expires_at)
        )
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


def _commit(
    store, batch_id: str, event_ids: tuple[str, ...], exporters=("clickhouse",), *, expires_at=None
):
    frames = _frames(batch_id, event_ids, expires_at=expires_at)
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
        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": exporter}, now=_NOW
        )
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
            now=_NOW,
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
        deliver_segment(database, barrier, record, frames, {"clickhouse": exporter}, now=_NOW)
        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": exporter}, now=_NOW
        )
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
            deliver_segment(
                database, barrier, record_a, frames_b, {"clickhouse": exporter}, now=_NOW
            )
        assert captured.value.code == "MH_SPOOL_EXPORT"
        assert exporter.deliveries == []  # nothing forwarded
        assert _status(database, "batch-a", "clickhouse") == "pending"  # never certified
    finally:
        database.close()


def test_a_mutating_frame_sequence_is_frozen_before_validation_and_forwarding(
    tmp_path: Path,
) -> None:
    # D05 re-review: the caller's Sequence must be materialized ONCE, so a sequence that yields
    # different contents on a later read cannot forward one batch while the digest certified
    # another.
    database, barrier, store = _spool(tmp_path)
    try:
        record_a, good = _commit(store, "batch-a", ("a1", "a2"))
        _record_b, bad = _commit(store, "batch-b", ("b1", "b2"))

        class _MutatingFrames(Sequence):
            def __init__(self) -> None:
                self._good = tuple(good)
                self._bad = tuple(bad)
                self.reads = 0

            def _pick(self):
                # First two reads (validation) yield the true frames; a later read (the old
                # forwarding path) would yield another batch — the freeze must prevent that read.
                return self._good if self.reads < 2 else self._bad

            def __getitem__(self, index):
                return self._pick()[index]

            def __len__(self) -> int:
                return len(self._good)

            def __iter__(self):
                snapshot = self._pick()
                self.reads += 1
                return iter(snapshot)

        mutating = _MutatingFrames()
        exporter = _FakeExporter("clickhouse")
        attempts = deliver_segment(
            database, barrier, record_a, mutating, {"clickhouse": exporter}, now=_NOW
        )
        assert [a.outcome for a in attempts] == ["delivered"]
        assert mutating.reads == 1  # materialized exactly once, then never re-read
        assert exporter.received_frames == tuple(good)  # forwarded the validated snapshot
    finally:
        database.close()


def test_a_malformed_frame_object_is_refused(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, _frames = _commit(store, "batch-a", ("a1",))
        with pytest.raises(SpoolError) as captured:
            deliver_segment(
                database,
                barrier,
                record,
                [object()],
                {"clickhouse": _FakeExporter("clickhouse")},
                now=_NOW,
            )
        assert captured.value.code == "MH_SPOOL_EXPORT"
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
                database,
                barrier,
                record_a,
                forged,
                {"clickhouse": _FakeExporter("clickhouse")},
                now=_NOW,
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
                database,
                barrier,
                record_a,
                [],
                {"clickhouse": _FakeExporter("clickhouse")},
                now=_NOW,
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
                now=_NOW,
            )
        assert tampered.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as ghost:  # a batch id that was never committed
            deliver_segment(
                database,
                barrier,
                replace(record, batch_id="ghost-1"),
                frames,
                {"clickhouse": _FakeExporter("clickhouse")},
                now=_NOW,
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
        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": impostor}, now=_NOW
        )
        assert [a.outcome for a in attempts] == ["no_exporter"]
        assert impostor.deliveries == []
        assert _status(database, "batch-a", "clickhouse") == "pending"
    finally:
        database.close()


def test_an_unsupplied_exporter_is_reported_without_touching_the_ledger(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        attempts = deliver_segment(database, barrier, record, frames, {}, now=_NOW)
        assert [a.outcome for a in attempts] == ["no_exporter"]
        assert _status(database, "batch-a", "clickhouse") == "pending"
    finally:
        database.close()


def test_a_wrong_barrier_is_refused(tmp_path: Path) -> None:
    database, _barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        foreign = GlobalCommitBarrier(tmp_path / "unrelated.lock")
        with pytest.raises(SpoolError) as captured:
            deliver_segment(
                database,
                foreign,
                record,
                frames,
                {"clickhouse": _FakeExporter("clickhouse")},
                now=_NOW,
            )
        assert captured.value.code == "MH_SPOOL_EXPORT"
        assert _status(database, "batch-a", "clickhouse") == "pending"
    finally:
        database.close()


def test_delivery_fences_out_maintenance_exclusive(tmp_path: Path) -> None:
    # D05 re-review: delivery holds the SHARED barrier across the whole forward, so maintenance
    # (retention_apply, which prunes under EXCLUSIVE) cannot run while a delivery is in flight.
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        probe: dict[str, object] = {}

        class _FenceProbe:
            @property
            def exporter_id(self) -> str:
                return "clickhouse"

            def deliver(self, record: SegmentRecord, frames: object) -> None:
                # While this delivery is in flight the shared side is held; a non-blocking
                # exclusive acquisition must fail busy, proving retention is fenced out.
                try:
                    with barrier.exclusive(blocking=False):
                        probe["blocked"] = False
                except StateError as error:
                    probe["blocked"] = True
                    probe["code"] = error.code

        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FenceProbe()}, now=_NOW
        )
        assert [a.outcome for a in attempts] == ["delivered"]
        assert probe["blocked"] is True
        assert probe["code"] == "MH_STATE_BARRIER_BUSY"
    finally:
        database.close()


def test_an_expired_segment_is_withheld_from_delivery(tmp_path: Path) -> None:
    # D05 re-review hard-expiry: a segment whose records have reached expires_at must never egress.
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        exporter = _FakeExporter("clickhouse")
        after_expiry = _NOW + timedelta(days=31)  # past the records' +30d expiry
        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": exporter}, now=after_expiry
        )
        assert [a.outcome for a in attempts] == ["expired"]
        assert exporter.deliveries == []  # nothing forwarded
        assert _status(database, "batch-a", "clickhouse") == "pending"  # never certified
    finally:
        database.close()


def test_an_expired_segment_still_reports_its_already_delivered_exporters(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}, now=_NOW
        )
        after_expiry = _NOW + timedelta(days=31)
        again = _FakeExporter("clickhouse")
        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": again}, now=after_expiry
        )
        assert [a.outcome for a in attempts] == ["already_delivered"]
        assert again.deliveries == []  # an expired segment forwards nothing
    finally:
        database.close()


def test_a_segment_pruned_mid_delivery_is_reported_gone_not_delivered(tmp_path: Path) -> None:
    # D05 re-review: a missing row must never be conflated with an already-delivered one.
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))

        class _SelfPruning:
            @property
            def exporter_id(self) -> str:
                return "clickhouse"

            def deliver(self, record: SegmentRecord, frames: object) -> None:
                # Simulate the row being pruned out from under the in-flight delivery.
                with database.transaction() as connection:
                    connection.execute(
                        "DELETE FROM _segment_exporters WHERE batch_id = ?", (record.batch_id,)
                    )

        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": _SelfPruning()}, now=_NOW
        )
        assert [a.outcome for a in attempts] == ["segment_gone"]
        assert _status(database, "batch-a", "clickhouse") is None  # row gone, never certified
    finally:
        database.close()


def test_a_zero_row_compare_and_set_is_reported_already_delivered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))
        # Deliver for real so the ledger row is terminal-delivered.
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}, now=_NOW
        )
        # Force the reload to report the exporter as still pending (a stale snapshot); the attempt
        # succeeds but the compare-and-set affects zero rows because the row is already delivered.
        # The still-present delivered row must be reported already_delivered, never a new delivery.
        stale = replace(
            record, exporters=(replace(record.exporters[0], delivery_status="pending"),)
        )
        monkeypatch.setattr(exporter_module, "_reload_record", lambda database, record: stale)
        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}, now=_NOW
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
        # Bypass the DB reload, then drop the delivery ledger so only the status CAS hits
        # the broken table; the backend fault must normalize to the fixed code.
        monkeypatch.setattr(exporter_module, "_reload_record", lambda database, record: record)
        with database.transaction() as connection:
            connection.execute("DROP TABLE _segment_exporters")
        with pytest.raises(SpoolError) as captured:
            deliver_segment(
                database,
                barrier,
                record,
                frames,
                {"clickhouse": _FakeExporter("clickhouse")},
                now=_NOW,
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
            deliver_segment(object(), barrier, record, frames, {}, now=_NOW)  # type: ignore[arg-type]
        assert bad_db.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_barrier:
            deliver_segment(database, object(), record, frames, {}, now=_NOW)  # type: ignore[arg-type]
        assert bad_barrier.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_record:
            deliver_segment(database, barrier, object(), frames, {}, now=_NOW)  # type: ignore[arg-type]
        assert bad_record.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_exporters:
            deliver_segment(database, barrier, record, frames, None, now=_NOW)  # type: ignore[arg-type]
        assert bad_exporters.value.code == "MH_SPOOL_EXPORT"
        with pytest.raises(SpoolError) as bad_now:
            deliver_segment(
                database,
                barrier,
                record,
                frames,
                {},
                now=datetime(2026, 7, 28, 12, 0, 0),  # naive: no tzinfo
            )
        assert bad_now.value.code == "MH_SPOOL_EXPORT"
    finally:
        database.close()


def test_segment_is_expired_predicate_handles_empty_and_boundaries() -> None:
    # Directly exercise the hard-expiry predicate, including the empty-frame branch. A record's
    # expires_at must be after its ingested_at, so "expired" is expressed by evaluating at a later
    # `now`, never by constructing a past-dated envelope.
    assert exporter_module._segment_is_expired([], _NOW) is False
    frames = _frames("batch-a", ("a1",), expires_at=_NOW + timedelta(hours=1))
    assert exporter_module._segment_is_expired(frames, _NOW) is False  # now is before expiry
    assert exporter_module._segment_is_expired(frames, _NOW + timedelta(hours=2)) is True


def test_an_exporter_whose_id_property_raises_is_contained(tmp_path: Path) -> None:
    database, barrier, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", ("a1",))

        class _RaisingId:
            @property
            def exporter_id(self) -> str:
                raise RuntimeError("hostile id property")

            def deliver(self, record: SegmentRecord, frames: object) -> None:
                raise AssertionError("must not be called")

        attempts = deliver_segment(
            database, barrier, record, frames, {"clickhouse": _RaisingId()}, now=_NOW
        )
        assert [a.outcome for a in attempts] == ["no_exporter"]  # contained, not raised
        assert _status(database, "batch-a", "clickhouse") == "pending"
    finally:
        database.close()
