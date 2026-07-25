from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
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
    OrphanRegistration,
    SegmentAnomaly,
    SegmentHeaderV1,
    SpoolError,
    SpoolFrameV1,
    SpoolReconciler,
    build_segment_bytes,
    publish_segment_bytes,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling import reconcile as reconcile_module
from milhouse.spooling.reconcile import _fingerprint
from milhouse.state import (
    GlobalCommitBarrier,
    StateError,
    initialize_control_state,
    open_control_database,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_OTHER_INSTALLATION_ID = "mh_in1_00000000000040008000000000000001"
_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)
_DAY = "2026-07-24"


def _envelope(source_event_id: str, installation_id: str = _INSTALLATION_ID) -> RecordEnvelopeV1:
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
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=installation_id)


def _segment(
    batch_id: str = "batch-1", *, installation_id: str = _INSTALLATION_ID, exporters=("clickhouse",)
) -> tuple[SegmentHeaderV1, tuple[SpoolFrameV1, ...]]:
    frames = tuple(
        SpoolFrameV1(
            batch_id=batch_id, sequence=index, record=_envelope(f"event-{index}", installation_id)
        )
        for index in range(1, 3)
    )
    lines = [spool_frame_line(frame) for frame in frames]
    header = SegmentHeaderV1(
        batch_id=batch_id,
        config_generation="a" * 64,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=exporters,
        record_count=len(frames),
        content_sha256=spool_content_sha256(lines),
    )
    return header, frames


def _control(tmp_path: Path):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    spool_root = tmp_path / "spool"
    spool_root.mkdir(mode=0o700)
    os.chmod(spool_root, 0o700)
    return database, barrier, spool_root


def _reconciler(tmp_path: Path, installation_id: str = _INSTALLATION_ID):
    database, barrier, spool_root = _control(tmp_path)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=installation_id
    )
    reconciler = SpoolReconciler(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=installation_id
    )
    return database, store, spool_root, reconciler


def _publish_orphan(spool_root: Path, day: str, name: str, content: bytes) -> Path:
    pending = spool_root / "pending"
    if not pending.exists():
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
    day_dir = pending / day
    if not day_dir.exists():
        day_dir.mkdir(mode=0o700)
        os.chmod(day_dir, 0o700)
    path = day_dir / name
    publish_segment_bytes(path, content)
    return path


def _count(database, table: str = "_segments") -> int:
    return database.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


# --- empty and healthy ---------------------------------------------------------------------------


def test_reconciling_an_empty_spool_reports_nothing(tmp_path: Path) -> None:
    database, _store, _spool_root, reconciler = _reconciler(tmp_path)
    try:
        report = reconciler.reconcile()
        assert report == reconcile_module.ReconciliationReport((), (), 0, 0)
    finally:
        database.close()


def test_a_committed_segment_reconciles_as_healthy(tmp_path: Path) -> None:
    database, store, _spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        store.commit_segment(header, frames, committed_at=_NOW)
        report = reconciler.reconcile()
        assert report.healthy == 1
        assert report.scanned == 1
        assert report.registered == ()
        assert report.anomalies == ()
    finally:
        database.close()


# --- mandatory reconciliation on writer acquisition (P1-1) ---------------------------------------


def test_acquiring_the_writer_reconciles_orphans_before_any_commit(tmp_path: Path) -> None:
    # publish an orphan, then acquire a fresh writer via the normal API — no separate reconcile call
    database, barrier, spool_root = _control(tmp_path)
    try:
        header, frames = _segment(batch_id="orphan-1")
        _publish_orphan(spool_root, _DAY, "orphan-1.jsonl", build_segment_bytes(header, frames))
        assert _count(database) == 0

        store = DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        # the orphan is registered by acquisition alone, before this writer publishes anything
        assert store.read_segment("orphan-1") is not None
        assert store.last_reconciliation.registered == (OrphanRegistration("orphan-1", _DAY),)

        later, later_frames = _segment(batch_id="later-2")
        store.commit_segment(later, later_frames, committed_at=_NOW)
        assert {r.batch_id for r in store.list_segments()} == {"orphan-1", "later-2"}
    finally:
        database.close()


def test_acquisition_barrier_failure_surfaces_a_spool_error(tmp_path: Path) -> None:
    database, barrier, spool_root = _control(tmp_path)
    os.chmod(tmp_path / "control" / "commit.lock", 0o644)  # a tampered lock fails the secure open
    try:
        with pytest.raises(SpoolError) as captured:
            DurableSpool(
                database=database,
                barrier=barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
            )
        assert captured.value.code == "MH_SPOOL_BARRIER"
    finally:
        os.chmod(tmp_path / "control" / "commit.lock", 0o600)
        database.close()


def test_a_crashed_commit_retry_converges_after_reacquisition(tmp_path: Path) -> None:
    # end-to-end convergence: crash a real commit after publication, re-acquire via the normal
    # writer API, and prove a same-batch retry is distinguishable from an unrecoverable collision
    database, barrier, spool_root = _control(tmp_path)
    try:
        store = DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        header, frames = _segment(batch_id="batch-1")

        class _TxnFailDatabase:
            def transaction(self) -> object:
                raise StateError("MH_STATE_TXN", "planted transaction-boundary failure")

        store._database = _TxnFailDatabase()  # type: ignore[attr-defined]
        with pytest.raises(SpoolError) as crashed:
            store.commit_segment(header, frames, committed_at=_NOW)
        assert crashed.value.code == "MH_SPOOL_COMMIT"  # published durably, no ledger row
        assert _count(database) == 0

        # a fresh acquisition through the normal writer API registers the crash artifact...
        recovered = DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        registered = recovered.read_segment("batch-1")
        assert registered is not None
        assert registered.origin == "reconciled"
        # ...so a retry of the SAME batch converges: publication refuses the existing name while
        # the ledger already carries the batch, letting the caller distinguish done from colliding
        with pytest.raises(SpoolError) as retried:
            recovered.commit_segment(header, frames, committed_at=_NOW)
        assert retried.value.code == "MH_SPOOL_EXISTS"
        assert _count(database) == 1  # no duplicate ledger rows from the retry
    finally:
        database.close()


def test_acquisition_reconciles_under_the_exclusive_barrier_side(tmp_path: Path) -> None:
    # pin the barrier MODE: acquisition must reconcile under exclusive() (a regression to shared()
    # would let two concurrent acquisitions scan the same orphan) and a commit under shared()
    database, _barrier, spool_root = _control(tmp_path)
    calls: list[str] = []

    class _SpyBarrier(GlobalCommitBarrier):
        @contextlib.contextmanager
        def exclusive(self, *, blocking: bool = True) -> Iterator[None]:
            calls.append("exclusive")
            with super().exclusive(blocking=blocking):
                yield

        @contextlib.contextmanager
        def shared(self, *, blocking: bool = True) -> Iterator[None]:
            calls.append("shared")
            with super().shared(blocking=blocking):
                yield

    try:
        store = DurableSpool(
            database=database,
            barrier=_SpyBarrier(tmp_path / "control" / "commit.lock"),
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        assert calls == ["exclusive"]
        header, frames = _segment()
        store.commit_segment(header, frames, committed_at=_NOW)
        assert calls == ["exclusive", "shared"]
    finally:
        database.close()


def test_a_second_writer_acquisition_waits_for_the_exclusive_barrier(tmp_path: Path) -> None:
    import threading

    database, barrier, spool_root = _control(tmp_path)
    header, frames = _segment(batch_id="orphan-1")
    _publish_orphan(spool_root, _DAY, "orphan-1.jsonl", build_segment_bytes(header, frames))
    acquired = threading.Event()
    outcome: dict[str, object] = {}

    def _acquire() -> None:
        # a second writer with its own connection and barrier descriptor (SQLite connections are
        # thread-bound, and a separate flock descriptor genuinely contends with the held lock)
        second = open_control_database(tmp_path / "control" / "milhouse.sqlite3")
        try:
            store = DurableSpool(
                database=second,
                barrier=GlobalCommitBarrier(tmp_path / "control" / "commit.lock"),
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
            )
            outcome["registered"] = store.last_reconciliation.registered
        finally:
            second.close()
        acquired.set()

    try:
        with barrier.exclusive():
            worker = threading.Thread(target=_acquire, daemon=True)
            worker.start()
            # while the first writer holds the exclusive barrier, the second cannot finish acquiring
            assert not acquired.wait(timeout=0.5)
        assert acquired.wait(timeout=10)  # released: the queued acquisition completes...
        assert outcome["registered"] == (OrphanRegistration("orphan-1", _DAY),)  # ...and reconciled
    finally:
        database.close()


def test_the_package_export_surface_cannot_bypass_mandatory_reconciliation() -> None:
    import milhouse.spooling as spooling

    # Pin the export surface: the only exported symbol that both publishes a segment and registers
    # it in the ledger is DurableSpool, whose acquisition mandatorily reconciles.
    # publish_segment_bytes/write_spool_segment publish FILES only (a crash-equivalent orphan that
    # the next acquisition registers), and run_reconciliation_scan IS the reconciliation itself.
    # No ledger-writing helper is exported; widening this surface is a deliberate, reviewed change.
    assert set(spooling.__all__) == {
        "DurableSpool",
        "ExporterDelivery",
        "OrphanRegistration",
        "ParsedSegment",
        "ReconciliationReport",
        "SegmentAnomaly",
        "SegmentHeaderV1",
        "SegmentRecord",
        "SpoolError",
        "SpoolFrameV1",
        "SpoolReconciler",
        "build_segment_bytes",
        "parse_segment_bytes",
        "publish_segment_bytes",
        "read_trusted_segment",
        "read_untrusted_segment",
        "run_reconciliation_scan",
        "spool_content_sha256",
        "spool_frame_line",
        "spool_segment_header_line",
        "write_spool_segment",
    }
    assert "insert_segment_row" not in spooling.__all__
    with pytest.raises(TypeError):
        DurableSpool(database=None, barrier=None, spool_root="x")  # type: ignore[call-arg]


# --- orphan registration -------------------------------------------------------------------------


def test_a_valid_orphan_is_registered_from_its_durable_header(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))

        report = reconciler.reconcile()

        assert report.registered == (OrphanRegistration("batch-1", _DAY),)
        assert report.anomalies == ()
        row = database.connection.execute(
            "SELECT day, committed_at, origin FROM _segments WHERE batch_id = 'batch-1'"
        ).fetchone()
        assert row == (_DAY, f"{_DAY}T00:00:00.000Z", "reconciled")
        exporters = database.connection.execute(
            "SELECT exporter_id, delivery_status FROM _segment_exporters WHERE batch_id = 'batch-1'"
        ).fetchall()
        assert exporters == [("clickhouse", "pending")]
    finally:
        database.close()


def test_reconciliation_is_idempotent(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        assert len(reconciler.reconcile().registered) == 1
        second = reconciler.reconcile()
        assert second.registered == ()
        assert second.healthy == 1
        assert second.anomalies == ()
        assert _count(database) == 1
    finally:
        database.close()


def test_a_multi_exporter_orphan_registers_every_exporter(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(exporters=("alpha", "beta"))
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        reconciler.reconcile()
        rows = database.connection.execute(
            "SELECT exporter_id FROM _segment_exporters WHERE batch_id = 'batch-1' "
            "ORDER BY exporter_id"
        ).fetchall()
        assert [r[0] for r in rows] == ["alpha", "beta"]
    finally:
        database.close()


# --- provenance and egress during reconciliation -------------------------------------------------


def test_an_orphan_minted_by_a_foreign_installation_is_not_registered(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(installation_id=_OTHER_INSTALLATION_ID)
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        report = reconciler.reconcile()
        assert report.registered == ()
        assert report.anomalies == (
            SegmentAnomaly("batch-1", _DAY, "corrupt_orphan", "MH_SPOOL_RECORD"),
        )
        assert _count(database) == 0
    finally:
        database.close()


def test_an_egress_denied_orphan_is_not_registered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the matrix admits every valid class today, but a denial must leave both tables unchanged
    database, _store, spool_root, reconciler = _reconciler(tmp_path)

    def _deny(_privacy_class: str) -> None:
        raise SpoolError("MH_SPOOL_EGRESS", "denied")

    monkeypatch.setattr(reconcile_module, "authorize_local_persistence", _deny)
    try:
        header, frames = _segment()
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        report = reconciler.reconcile()
        assert report.registered == ()
        assert report.anomalies == (
            SegmentAnomaly("batch-1", _DAY, "corrupt_orphan", "MH_SPOOL_EGRESS"),
        )
        assert _count(database) == 0
        assert _count(database, "_segment_exporters") == 0
    finally:
        database.close()


# --- full ledger/file agreement (P1-2) -----------------------------------------------------------


def test_a_fully_matching_committed_file_is_healthy(tmp_path: Path) -> None:
    database, store, _spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(exporters=("alpha", "beta"))
        store.commit_segment(header, frames, committed_at=_NOW)
        report = reconciler.reconcile()
        assert report.healthy == 1
        assert report.anomalies == ()
    finally:
        database.close()


@pytest.mark.parametrize(
    "mutation",
    [
        f"UPDATE _segments SET config_generation = '{'b' * 64}' WHERE batch_id = 'batch-1'",
        "UPDATE _segments SET privacy_class = 'public' WHERE batch_id = 'batch-1'",
        "UPDATE _segments SET retention_days = 29 WHERE batch_id = 'batch-1'",
        "UPDATE _segments SET record_count = 1 WHERE batch_id = 'batch-1'",
        "UPDATE _segments SET content_sha256 = 'c' || substr(content_sha256, 2) "
        "WHERE batch_id = 'batch-1'",
        "UPDATE _segments SET byte_size = byte_size + 1 WHERE batch_id = 'batch-1'",
        "UPDATE _segments SET file_sha256 = 'e' || substr(file_sha256, 2) "
        "WHERE batch_id = 'batch-1'",
        "UPDATE _segments SET target_id = 'other-target' WHERE batch_id = 'batch-1'",
        "UPDATE _segments SET scope = 'installation', target_id = NULL WHERE batch_id = 'batch-1'",
        "DELETE FROM _segment_exporters WHERE batch_id = 'batch-1'",
    ],
)
def test_a_committed_file_that_disagrees_with_any_ledger_field_is_not_healthy(
    tmp_path: Path, mutation: str
) -> None:
    database, store, _spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        store.commit_segment(header, frames, committed_at=_NOW)
        with database.transaction() as connection:
            connection.execute(mutation)
        report = reconciler.reconcile()
        assert report.healthy == 0
        assert report.anomalies == (
            SegmentAnomaly("batch-1", _DAY, "corrupt_file", "ledger_mismatch"),
        )
    finally:
        database.close()


@pytest.mark.parametrize(
    "mutation",
    [
        # add a well-formed extra exporter row
        "INSERT INTO _segment_exporters (batch_id, exporter_id, delivery_status) "
        "VALUES ('batch-1', 'extra', 'pending')",
        # rename an exporter to a different valid identity
        "UPDATE _segment_exporters SET exporter_id = 'renamed' "
        "WHERE batch_id = 'batch-1' AND exporter_id = 'alpha'",
        # remove one of several exporters (the sole-exporter deletion is covered separately)
        "DELETE FROM _segment_exporters WHERE batch_id = 'batch-1' AND exporter_id = 'beta'",
    ],
)
def test_an_exporter_set_change_in_any_direction_is_not_healthy(
    tmp_path: Path, mutation: str
) -> None:
    # every mutation passes per-row validation (well-formed ids and statuses); only the exact
    # identity-set comparison against the durable header can catch it
    database, store, _spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(exporters=("alpha", "beta"))
        store.commit_segment(header, frames, committed_at=_NOW)
        with database.transaction() as connection:
            connection.execute(mutation)
        report = reconciler.reconcile()
        assert report.healthy == 0
        assert report.anomalies == (
            SegmentAnomaly("batch-1", _DAY, "corrupt_file", "ledger_mismatch"),
        )
        assert report.registered == ()
    finally:
        database.close()


def test_a_corrupt_committed_file_is_flagged(tmp_path: Path) -> None:
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        store.commit_segment(header, frames, committed_at=_NOW)
        (spool_root / "pending" / _DAY / "batch-1.jsonl").write_bytes(b"truncated\n")
        report = reconciler.reconcile()
        assert report.healthy == 0
        assert report.anomalies[0].kind == "corrupt_file"
        assert report.anomalies[0].detail.startswith("MH_SPOOL_")
    finally:
        database.close()


def test_a_malformed_ledger_row_is_flagged(tmp_path: Path) -> None:
    database, _store, _spool_root, reconciler = _reconciler(tmp_path)
    try:
        # length-10 but not a calendar day: passes the CHECK, fails semantic validation
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                "config_generation, scope, target_id, privacy_class, retention_days, record_count, "
                "content_sha256, byte_size, file_sha256, committed_at, origin) VALUES "
                "('bad', '2026-13-45', 1, 1, ?, 'target', 't', 'internal', 30, 1, ?, 10, ?, "
                "'2026-13-45T00:00:00.000Z', 'committed')",
                ("a" * 64, "c" * 64, "d" * 64),
            )
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("bad", "", "corrupt_ledger", "unreadable_row"),)
        assert report.healthy == 0
    finally:
        database.close()


def test_a_missing_segment_file_is_flagged(tmp_path: Path) -> None:
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        store.commit_segment(header, frames, committed_at=_NOW)
        (spool_root / "pending" / _DAY / "batch-1.jsonl").unlink()
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("batch-1", _DAY, "missing_file", "absent"),)
        assert report.healthy == 0
    finally:
        database.close()


# --- conflicting duplicates (P1-3) ---------------------------------------------------------------


@pytest.mark.parametrize("variant", ["identical", "different_frames", "different_exporters"])
def test_a_batch_at_two_paths_registers_none(tmp_path: Path, variant: str) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header_a, frames_a = _segment(batch_id="batch-1")
        content_a = build_segment_bytes(header_a, frames_a)
        if variant == "identical":
            content_b = content_a
        elif variant == "different_exporters":
            header_b, frames_b = _segment(batch_id="batch-1", exporters=("clickhouse", "extra"))
            content_b = build_segment_bytes(header_b, frames_b)
        else:  # genuinely different frame content: other source events, other record ids
            frames_b = tuple(
                SpoolFrameV1(batch_id="batch-1", sequence=index, record=_envelope(f"other-{index}"))
                for index in (1, 2)
            )
            lines = [spool_frame_line(frame) for frame in frames_b]
            header_b = SegmentHeaderV1(
                batch_id="batch-1",
                config_generation="a" * 64,
                scope="target",
                target_id="example-target",
                privacy_class="internal",
                retention_days=30,
                required_exporters=("clickhouse",),
                record_count=len(frames_b),
                content_sha256=spool_content_sha256(lines),
            )
            content_b = build_segment_bytes(header_b, frames_b)
            assert content_b != content_a  # the two durable histories genuinely conflict
        _publish_orphan(spool_root, "2026-07-23", "batch-1.jsonl", content_a)
        _publish_orphan(spool_root, "2026-07-24", "batch-1.jsonl", content_b)

        report = reconciler.reconcile()

        assert report.registered == ()
        assert {a.kind for a in report.anomalies} == {"conflict"}
        assert len(report.anomalies) == 2
        assert _count(database) == 0
        assert _count(database, "_segment_exporters") == 0
        # a re-run stays mutation-free and deterministic
        assert reconciler.reconcile().registered == ()
        assert _count(database) == 0
    finally:
        database.close()


# --- foreign names and bounds, with no raw path in the report (P2-1) -----------------------------


def test_an_orphan_whose_name_disagrees_with_its_header_is_flagged(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(batch_id="batch-1")
        _publish_orphan(spool_root, _DAY, "impostor.jsonl", build_segment_bytes(header, frames))
        report = reconciler.reconcile()
        assert report.registered == ()
        assert report.anomalies == (
            SegmentAnomaly("impostor", _DAY, "foreign_name", "header_batch_id"),
        )
    finally:
        database.close()


@pytest.mark.parametrize(
    ("name", "detail"),
    [("batch-1.txt", "suffix"), ("..sneaky.jsonl", "batch_id")],
)
def test_a_foreign_file_name_is_fingerprinted(tmp_path: Path, name: str, detail: str) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        day_dir = pending / _DAY
        day_dir.mkdir(mode=0o700)
        os.chmod(day_dir, 0o700)
        (day_dir / name).write_bytes(b"x")
        os.chmod(day_dir / name, 0o600)
        report = reconciler.reconcile()
        assert report.anomalies == (
            SegmentAnomaly(_fingerprint(name), _DAY, "foreign_name", detail),
        )
        assert name not in report.anomalies[0].batch_id
    finally:
        database.close()


def test_an_invalid_day_name_is_fingerprinted_and_leaks_no_raw_name(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        canary = "CANARY_SECRET-not-a-day"
        (pending / canary).mkdir(mode=0o700)
        report = reconciler.reconcile()
        assert report.anomalies == (
            SegmentAnomaly("", _fingerprint(canary), "foreign_name", "day"),
        )
        assert canary not in repr(report.anomalies[0])
    finally:
        database.close()


@pytest.mark.parametrize("day", ["not-a-date", "2026-13-45", "2026-07- 5", "2026"])
def test_a_non_canonical_day_directory_is_rejected_without_a_poison_row(
    tmp_path: Path, day: str
) -> None:
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        _publish_orphan(spool_root, day, "batch-1.jsonl", build_segment_bytes(header, frames))
        report = reconciler.reconcile()
        assert report.registered == ()
        assert report.anomalies == (SegmentAnomaly("", _fingerprint(day), "foreign_name", "day"),)
        assert _count(database) == 0
        assert store.list_segments() == ()  # the ledger stays readable — no poison row
    finally:
        database.close()


def test_a_symlinked_day_directory_is_reported_unsafe(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        (pending / _DAY).symlink_to(tmp_path)
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", _DAY, "foreign_name", "day_unsafe"),)
    finally:
        database.close()


def test_a_world_writable_day_directory_is_reported_unsafe(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    pending = spool_root / "pending"
    pending.mkdir(mode=0o700)
    os.chmod(pending, 0o700)
    day_dir = pending / _DAY
    day_dir.mkdir(mode=0o700)
    os.chmod(day_dir, 0o777)
    try:
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", _DAY, "foreign_name", "day_unsafe"),)
    finally:
        os.chmod(day_dir, 0o700)
        database.close()


def test_a_world_writable_pending_directory_is_reported_unsafe(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    pending = spool_root / "pending"
    pending.mkdir(mode=0o700)
    os.chmod(pending, 0o777)
    try:
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", "", "foreign_name", "pending_unsafe"),)
    finally:
        os.chmod(pending, 0o700)
        database.close()


def _two_day_dirs(spool_root: Path) -> Path:
    pending = spool_root / "pending"
    pending.mkdir(mode=0o700)
    os.chmod(pending, 0o700)
    for day in ("2026-07-24", "2026-07-25"):
        (pending / day).mkdir(mode=0o700)
    return pending


def test_too_many_day_directories_hits_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_DAYS", 1)
    _two_day_dirs(spool_root)
    try:
        assert SegmentAnomaly("", "", "limit", "day_limit") in reconciler.reconcile().anomalies
    finally:
        database.close()


def test_too_many_entries_in_a_day_hits_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ENTRIES", 1)
    day_dir = spool_root / "pending" / _DAY
    day_dir.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "pending", 0o700)
    os.chmod(day_dir, 0o700)
    for name in ("a.jsonl", "b.jsonl"):
        (day_dir / name).write_bytes(b"x")
    try:
        assert reconciler.reconcile().anomalies == (
            SegmentAnomaly("", _DAY, "foreign_name", "day_too_many"),
        )
    finally:
        database.close()


def test_too_many_total_files_stops_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_TOTAL", 0)
    day_dir = spool_root / "pending" / _DAY
    day_dir.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "pending", 0o700)
    os.chmod(day_dir, 0o700)
    (day_dir / "batch-1.jsonl").write_bytes(b"x")
    try:
        assert SegmentAnomaly("", "", "limit", "scan_limit") in reconciler.reconcile().anomalies
    finally:
        database.close()


def test_too_many_anomalies_hits_the_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 1)
    pending = spool_root / "pending"
    pending.mkdir(mode=0o700)
    os.chmod(pending, 0o700)
    for junk in ("not-a-day-1", "not-a-day-2", "not-a-day-3"):
        (pending / junk).mkdir(mode=0o700)
    try:
        report = reconciler.reconcile()
        # once the cap is hit the limit anomaly is recorded once; further overflow is dropped
        assert SegmentAnomaly("", "", "limit", "anomaly_limit") in report.anomalies
        assert len(report.anomalies) == 2
    finally:
        database.close()


def test_a_file_for_a_malformed_ledger_row_is_not_reread(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                "config_generation, scope, target_id, privacy_class, retention_days, record_count, "
                "content_sha256, byte_size, file_sha256, committed_at, origin) VALUES "
                "('batch-1', '2026-13-45', 1, 1, ?, 'target', 't', 'internal', 30, 1, ?, 10, ?, "
                "'2026-13-45T00:00:00.000Z', 'committed')",
                ("a" * 64, "c" * 64, "d" * 64),
            )
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"anything\n")
        report = reconciler.reconcile()
        # the malformed row is reported once; its file is skipped, not registered or certified
        assert report.anomalies == (
            SegmentAnomaly("batch-1", "", "corrupt_ledger", "unreadable_row"),
        )
        assert report.healthy == 0
        assert report.registered == ()
    finally:
        database.close()


# --- origin exposure through the ledger API (P2-3) -----------------------------------------------


def test_the_ledger_api_surfaces_committed_and_reconciled_origins(tmp_path: Path) -> None:
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        committed_header, committed_frames = _segment(batch_id="committed-1")
        store.commit_segment(committed_header, committed_frames, committed_at=_NOW)
        orphan_header, orphan_frames = _segment(batch_id="reconciled-1")
        _publish_orphan(
            spool_root,
            _DAY,
            "reconciled-1.jsonl",
            build_segment_bytes(orphan_header, orphan_frames),
        )
        reconciler.reconcile()

        origins = {record.batch_id: record.origin for record in store.list_segments()}
        assert origins == {"committed-1": "committed", "reconciled-1": "reconciled"}
        reconciled = store.read_segment("reconciled-1")
        assert reconciled is not None
        assert reconciled.committed_at == f"{_DAY}T00:00:00.000Z"
    finally:
        database.close()


# --- binding, barrier, and failure boundary ------------------------------------------------------


def test_the_reconciler_rejects_a_bad_binding_or_installation(tmp_path: Path) -> None:
    database, barrier, spool_root = _control(tmp_path)
    try:
        for kwargs, code in (
            ({"database": object()}, "MH_SPOOL_STORE"),
            ({"barrier": object()}, "MH_SPOOL_STORE"),
            (
                {"barrier": GlobalCommitBarrier(tmp_path / "control" / "other.lock")},
                "MH_SPOOL_STORE",
            ),
            ({"spool_root": tmp_path / "elsewhere"}, "MH_SPOOL_STORE"),
            ({"installation_id": "bad"}, "MH_SPOOL_IDENTITY"),
        ):
            base = {
                "database": database,
                "barrier": barrier,
                "spool_root": spool_root,
                "installation_id": _INSTALLATION_ID,
            }
            base.update(kwargs)
            with pytest.raises(SpoolError) as captured:
                SpoolReconciler(**base)  # type: ignore[arg-type]
            assert captured.value.code == code
    finally:
        database.close()


def test_reconciliation_happens_inside_the_exclusive_barrier(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    header, frames = _segment()
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
    real_barrier = reconciler._barrier  # type: ignore[attr-defined]

    class _AssertingBarrier:
        @contextlib.contextmanager
        def exclusive(self, *, blocking: bool = True) -> Iterator[None]:
            assert _count(database) == 0  # not yet registered when the exclusive lock is taken
            with real_barrier.exclusive(blocking=blocking):
                yield

    reconciler._barrier = _AssertingBarrier()  # type: ignore[attr-defined]
    try:
        assert len(reconciler.reconcile().registered) == 1
        assert _count(database) == 1
    finally:
        database.close()


def test_a_barrier_acquisition_failure_surfaces_a_spool_error(tmp_path: Path) -> None:
    # a tampered lock makes the secure barrier open fail with a StateError; the writer API must only
    # ever surface a fixed MH_SPOOL_* error, never a raw state error
    database, _store, _spool_root, reconciler = _reconciler(tmp_path)
    os.chmod(tmp_path / "control" / "commit.lock", 0o644)
    try:
        with pytest.raises(SpoolError) as captured:
            reconciler.reconcile()
        assert captured.value.code == "MH_SPOOL_BARRIER"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        os.chmod(tmp_path / "control" / "commit.lock", 0o600)
        database.close()


def test_a_malformed_ledger_batch_id_is_fingerprinted_not_echoed(tmp_path: Path) -> None:
    database, _store, _spool_root, reconciler = _reconciler(tmp_path)
    injected = "evil\nINJECTED-CANARY"
    try:
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                "config_generation, scope, target_id, privacy_class, retention_days, record_count, "
                "content_sha256, byte_size, file_sha256, committed_at, origin) VALUES "
                "(?, '2026-07-24', 1, 1, ?, 'target', 't', 'internal', 30, 1, ?, 10, ?, "
                "'2026-07-24T00:00:00.000Z', 'committed')",
                (injected, "a" * 64, "c" * 64, "d" * 64),
            )
        report = reconciler.reconcile()
        assert report.anomalies == (
            SegmentAnomaly(_fingerprint(injected), "", "corrupt_ledger", "unreadable_row"),
        )
        assert "INJECTED-CANARY" not in repr(report.anomalies[0])
    finally:
        database.close()


def test_an_unreadable_ledger_fails_closed(tmp_path: Path) -> None:
    database, _store, _spool_root, reconciler = _reconciler(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _segments")
        with pytest.raises(SpoolError) as captured:
            reconciler.reconcile()
        assert captured.value.code == "MH_SPOOL_LEDGER"
    finally:
        database.close()


def test_a_registration_failure_is_reported_as_reconcile_uncertain(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        with database.transaction() as connection:
            connection.execute("DROP TABLE _segment_exporters")
        with pytest.raises(SpoolError) as captured:
            reconciler.reconcile()
        assert captured.value.code == "MH_SPOOL_RECONCILE"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()
