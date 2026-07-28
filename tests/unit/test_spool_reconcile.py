from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
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
        assert report == reconcile_module.ReconciliationReport((), (), (), 0, 0, complete=True)
    finally:
        database.close()


@pytest.mark.parametrize("root_state", ["missing", "symlink", "mode", "owner", "acl"])
def test_an_untrusted_spool_root_is_never_certified_as_an_empty_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_state: str
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    real_fstat = os.fstat
    real_acl_check = reconcile_module.require_no_extended_acl
    trusted_empty = tmp_path / "trusted-empty"
    if root_state == "missing":
        spool_root.rmdir()
    elif root_state == "symlink":
        spool_root.rmdir()
        trusted_empty.mkdir(mode=0o700)
        os.chmod(trusted_empty, 0o700)
        spool_root.symlink_to(trusted_empty, target_is_directory=True)
    elif root_state == "mode":
        os.chmod(spool_root, 0o755)
    elif root_state == "owner":
        root_inode = os.lstat(spool_root).st_ino

        def _foreign_root(descriptor: int) -> os.stat_result:
            info = real_fstat(descriptor)
            if info.st_ino != root_inode:
                return info
            fields = list(info)
            fields[4] = os.geteuid() + 1
            return os.stat_result(fields)

        monkeypatch.setattr(os, "fstat", _foreign_root)
    else:
        root_inode = os.lstat(spool_root).st_ino

        def _root_acl(descriptor: int) -> None:
            if real_fstat(descriptor).st_ino == root_inode:
                raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)
            real_acl_check(descriptor)

        monkeypatch.setattr(reconcile_module, "require_no_extended_acl", _root_acl)

    try:
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert report.quarantined == ()
        assert report.anomalies == (SegmentAnomaly("", "", "foreign_name", "spool_root_unsafe"),)
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


def test_a_commit_through_a_long_lived_writer_registers_a_later_crash_orphan(
    tmp_path: Path,
) -> None:
    # the gate review's reproduction: writer A outlives its constructor; writer B then crashes a
    # commit after publication; a commit through A must register B's orphan BEFORE A's new row
    database, barrier, spool_root = _control(tmp_path)
    second = open_control_database(tmp_path / "control" / "milhouse.sqlite3")
    try:
        writer_a = DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        assert writer_a.last_reconciliation.registered == ()

        writer_b = DurableSpool(
            database=second,
            barrier=GlobalCommitBarrier(tmp_path / "control" / "commit.lock"),
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )

        class _TxnFailDatabase:
            @property
            def path(self) -> Path:
                return second.path

            @property
            def connection(self) -> object:
                return second.connection

            def transaction(self) -> object:
                raise StateError("MH_STATE_TXN", "planted transaction-boundary failure")

        writer_b._database = _TxnFailDatabase()  # type: ignore[attr-defined]
        between_header, between_frames = _segment(batch_id="between-1")
        with pytest.raises(SpoolError) as crashed:
            writer_b.commit_segment(between_header, between_frames, committed_at=_NOW)
        assert crashed.value.code == "MH_SPOOL_COMMIT"
        assert _count(database) == 0  # the orphan is durable but unregistered

        later_header, later_frames = _segment(batch_id="later-2")
        writer_a.commit_segment(later_header, later_frames, committed_at=_NOW)

        # A's commit registered the orphan within its own critical section, before its new row
        assert writer_a.last_reconciliation.registered == (OrphanRegistration("between-1", _DAY),)
        origins = {r.batch_id: r.origin for r in writer_a.list_segments()}
        assert origins == {"between-1": "reconciled", "later-2": "committed"}
    finally:
        second.close()
        database.close()


def test_a_same_batch_retry_through_a_long_lived_writer_converges(tmp_path: Path) -> None:
    # the retry itself heals: the pre-commit scan registers the crash orphan, then publication
    # refuses the existing name — the caller distinguishes done from colliding without re-acquiring
    database, barrier, spool_root = _control(tmp_path)
    try:
        writer_a = DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        header, frames = _segment(batch_id="batch-1")
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))

        with pytest.raises(SpoolError) as retried:
            writer_a.commit_segment(header, frames, committed_at=_NOW)
        assert retried.value.code == "MH_SPOOL_EXISTS"
        registered = writer_a.read_segment("batch-1")
        assert registered is not None
        assert registered.origin == "reconciled"
        assert _count(database) == 1
    finally:
        database.close()


def test_an_orphan_from_another_process_is_registered_by_a_commit(tmp_path: Path) -> None:
    # cross-process interleaving: a separate OS process durably publishes an orphan after writer A
    # was constructed; A's next commit registers it
    import subprocess
    import sys

    database, barrier, spool_root = _control(tmp_path)
    try:
        writer_a = DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        header, frames = _segment(batch_id="foreign-proc-1")
        content_path = tmp_path / "content.bin"
        content_path.write_bytes(build_segment_bytes(header, frames))
        day_dir = spool_root / "pending" / _DAY
        day_dir.mkdir(mode=0o700, parents=True)
        os.chmod(spool_root / "pending", 0o700)
        os.chmod(day_dir, 0o700)
        script = (
            "import pathlib, sys\n"
            "from milhouse.spooling import publish_segment_bytes\n"
            "content = pathlib.Path(sys.argv[1]).read_bytes()\n"
            "publish_segment_bytes(pathlib.Path(sys.argv[2]), content)\n"
        )
        subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(content_path),
                str(day_dir / "foreign-proc-1.jsonl"),
            ],
            check=True,
            timeout=60,
        )

        later_header, later_frames = _segment(batch_id="later-2")
        writer_a.commit_segment(later_header, later_frames, committed_at=_NOW)
        assert writer_a.last_reconciliation.registered == (
            OrphanRegistration("foreign-proc-1", _DAY),
        )
        assert {r.batch_id for r in writer_a.list_segments()} == {"foreign-proc-1", "later-2"}
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
            # reads (the pre-commit scan) succeed; only the write-side boundary fails, exactly
            # like a crash between publication and the ledger insert
            @property
            def path(self) -> Path:
                return database.path

            @property
            def connection(self) -> object:
                return database.connection

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


def test_the_no_gap_lock_protocol_holds_exclusive_across_reconcile_and_commit(
    tmp_path: Path,
) -> None:
    # pin the no-gap protocol: acquisition reconciles under ONE exclusive hold, and every commit
    # runs reconcile+publish+insert under ONE exclusive hold — never a shared publish, never an
    # unlock window between reconciliation and publication
    database, _barrier, spool_root = _control(tmp_path)
    calls: list[str] = []
    held_through_publish: list[bool] = []
    pending = spool_root / "pending"

    class _SpyBarrier(GlobalCommitBarrier):
        @contextlib.contextmanager
        def exclusive(self, *, blocking: bool = True) -> Iterator[object]:
            calls.append("exclusive")
            before = pending.exists()
            with super().exclusive(blocking=blocking) as hold:
                yield hold
            # if publication happened during THIS single hold, pending appears while it was held
            held_through_publish.append(not before and pending.exists())

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
        # exactly one more exclusive hold covered the whole reconcile+publish+insert; no shared use
        assert calls == ["exclusive", "exclusive"]
        assert held_through_publish == [False, True]
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

    # Pin the export surface: the only exported symbols that can mutate reconciliation/ledger state
    # are DurableSpool (construction and every commit reconcile under the exclusive barrier) and
    # SpoolReconciler.reconcile (acquires the exclusive barrier internally).
    # publish_segment_bytes/write_spool_segment publish FILES only (a crash-equivalent orphan that
    # the next reconciliation registers). The raw mutating scan is NOT exported: a barrier-less
    # reconciliation entrypoint was the re-review's P1 bypass. Widening this surface is a
    # deliberate, reviewed change.
    assert set(spooling.__all__) == {
        "DurableSpool",
        "ExporterDelivery",
        "OrphanRegistration",
        "ParsedSegment",
        "QuarantinedFile",
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
        "spool_content_sha256",
        "spool_frame_line",
        "spool_segment_header_line",
        "write_spool_segment",
    }
    assert "insert_segment_row" not in spooling.__all__
    assert "run_reconciliation_scan" not in spooling.__all__
    assert not hasattr(spooling, "run_reconciliation_scan")
    with pytest.raises(TypeError):
        DurableSpool(database=None, barrier=None, spool_root="x")  # type: ignore[call-arg]


def test_every_reconciliation_entrypoint_holds_exclusive_before_mutating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # spy on the scan body itself: whenever any supported entrypoint reaches it, the exclusive
    # barrier must already be held (a probe acquisition from a second descriptor fails BUSY) and the
    # authority token passed to it must be live
    database, barrier, spool_root = _control(tmp_path)
    probe = GlobalCommitBarrier(tmp_path / "control" / "commit.lock")
    real_run = reconcile_module._Scan.run
    held_checks: list[tuple[bool, bool]] = []

    def _asserting_run(self, authority):  # type: ignore[no-untyped-def]
        blocked = False
        try:
            with probe.exclusive(blocking=False):
                pass
        except StateError:
            blocked = True
        held_checks.append((blocked, bool(getattr(authority, "active", False))))
        return real_run(self, authority)

    monkeypatch.setattr(reconcile_module._Scan, "run", _asserting_run)
    try:
        store = DurableSpool(  # entrypoint 1: writer acquisition
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        header, frames = _segment()
        store.commit_segment(header, frames, committed_at=_NOW)  # entrypoint 2: every commit
        reconciler = SpoolReconciler(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        reconciler.reconcile()  # entrypoint 3: the explicit startup pass
        # exclusive was held and the authority token live at every scan invocation
        assert held_checks == [(True, True), (True, True), (True, True)]
    finally:
        database.close()


def test_a_direct_unheld_scan_call_fails_before_any_mutation(tmp_path: Path) -> None:
    # the re-review's reproduction: the raw scan body must be impossible to run without owning
    # barrier authority — a direct internal call with no live hold fails before touching the ledger
    from milhouse.state.barrier import ExclusiveHold

    database, barrier, spool_root = _control(tmp_path)
    header, frames = _segment(batch_id="orphan-1")
    _publish_orphan(spool_root, _DAY, "orphan-1.jsonl", build_segment_bytes(header, frames))
    try:
        assert not hasattr(reconcile_module, "_run_reconciliation_scan")  # the old bypass is gone
        own_lock = tmp_path / "control" / "commit.lock"
        for bogus_authority in (None, object(), ExclusiveHold(own_lock)):  # absent/foreign/inactive
            scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
            with pytest.raises(SpoolError) as captured:
                scan.run(bogus_authority)  # type: ignore[arg-type]
            assert captured.value.code == "MH_SPOOL_BARRIER"
        # a STALE token captured from a completed hold is inactive and equally refused
        with barrier.exclusive() as hold:
            pass
        assert not hold.active
        with pytest.raises(SpoolError) as stale:
            reconcile_module._Scan(database, spool_root, _INSTALLATION_ID).run(hold)
        assert stale.value.code == "MH_SPOOL_BARRIER"
        # nothing mutated: the orphan remains unregistered, both tables are unchanged, and the
        # filesystem is untouched (no quarantine directory was ever created)
        assert _count(database) == 0
        assert _count(database, "_segment_exporters") == 0
        assert (spool_root / "pending" / _DAY / "orphan-1.jsonl").exists()
        assert not (spool_root / "quarantine").exists()
    finally:
        database.close()


def test_exclusive_authority_is_bound_to_the_state_root(tmp_path: Path) -> None:
    # the re-review's reproduction: a live hold of state root B's barrier is NOT authority for
    # state root A — both the wrapper binding and the scan's token-identity check must refuse
    (tmp_path / "rootA").mkdir()
    (tmp_path / "rootB").mkdir()
    database_a, barrier_a, spool_a = _control(tmp_path / "rootA")
    database_b, barrier_b, _spool_b = _control(tmp_path / "rootB")
    header, frames = _segment(batch_id="orphan-1")
    _publish_orphan(spool_a, _DAY, "orphan-1.jsonl", build_segment_bytes(header, frames))
    try:
        # (1) the wrapper with database/spool A but barrier B fails the binding before mutation
        with pytest.raises(SpoolError) as mismatched:
            reconcile_module._reconcile_under_barrier(
                database=database_a,
                barrier=barrier_b,
                spool_root=spool_a,
                installation_id=_INSTALLATION_ID,
            )
        assert mismatched.value.code == "MH_SPOOL_STORE"
        assert _count(database_a) == 0

        # (2) a direct A scan with B's LIVE token fails the identity check before mutation
        with barrier_b.exclusive() as foreign_live_hold:
            assert foreign_live_hold.active
            with pytest.raises(SpoolError) as foreign:
                reconcile_module._Scan(database_a, spool_a, _INSTALLATION_ID).run(foreign_live_hold)
            assert foreign.value.code == "MH_SPOOL_BARRIER"
        assert _count(database_a) == 0
        assert _count(database_a, "_segment_exporters") == 0

        # (3) the correctly bound A wrapper still registers
        report = reconcile_module._reconcile_under_barrier(
            database=database_a,
            barrier=barrier_a,
            spool_root=spool_a,
            installation_id=_INSTALLATION_ID,
        )
        assert report.registered == (OrphanRegistration("orphan-1", _DAY),)
        assert _count(database_a) == 1
    finally:
        database_a.close()
        database_b.close()


def test_a_token_carries_no_activation_capability(tmp_path: Path) -> None:
    # the re-review forged a hold via its _issue() method; issuance now lives only in the barrier's
    # private live-hold registry — the token exposes NO callable, method, or assignable state that
    # can activate it
    from milhouse.state.barrier import ExclusiveHold

    hold = ExclusiveHold(tmp_path / "control" / "commit.lock")
    assert not hold.active
    callables = [
        name
        for name in dir(ExclusiveHold)
        if not name.startswith("__") and callable(getattr(ExclusiveHold, name, None))
    ]
    assert callables == []  # no token method exists, activating or otherwise
    assert not hasattr(hold, "_issue")
    assert not hasattr(hold, "_revoke")
    with pytest.raises(AttributeError):
        hold._active = True  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        hold.__active = True  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        hold.active = True  # type: ignore[misc]
    assert not hold.active  # the trust decision is not reachable from the token at all


def test_a_context_issued_token_is_live_exactly_during_its_hold(tmp_path: Path) -> None:
    _database, barrier, _spool_root = _control(tmp_path)
    try:
        with barrier.exclusive() as hold:
            assert hold.active
        assert not hold.active  # revoked the moment the context exits
    finally:
        _database.close()


def test_the_anomaly_cap_stops_directory_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the cap bounds lock-hold WORK: once it fires, later directories are never opened
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 1)
    pending = spool_root / "pending"
    pending.mkdir(mode=0o700)
    os.chmod(pending, 0o700)
    for junk in ("0000-junk-a", "0000-junk-b"):  # sort before the valid day; both invalid names
        (pending / junk).mkdir(mode=0o700)
    header, frames = _segment(batch_id="batch-1")
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
    opened: list[int] = []
    real_names = reconcile_module._secure_names_from_descriptor

    def _recording_names(descriptor: int):
        opened.append(os.fstat(descriptor).st_ino)
        return real_names(descriptor)

    monkeypatch.setattr(reconcile_module, "_secure_names_from_descriptor", _recording_names)
    try:
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert report.scanned == 0  # no entry was ever classified
        assert opened == [os.lstat(pending).st_ino]  # the valid day directory was never opened
        assert _count(database) == 0
    finally:
        database.close()


def test_the_anomaly_cap_stops_within_day_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the within-day analogue: entries after the cap are neither classified nor read
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 1)
    header, frames = _segment(batch_id="batch-1")
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
    day_dir = spool_root / "pending" / _DAY
    for junk in ("0-junk-a.txt", "0-junk-b.txt"):  # sort before batch-1.jsonl; foreign suffixes
        (day_dir / junk).write_bytes(b"x")
        os.chmod(day_dir / junk, 0o600)
    reads: list[Path] = []
    real_read = reconcile_module.read_trusted_segment

    def _recording_read(path, **kwargs):  # type: ignore[no-untyped-def]
        reads.append(path)
        return real_read(path, **kwargs)

    monkeypatch.setattr(reconcile_module, "read_trusted_segment", _recording_read)
    try:
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert report.scanned == 2  # the two junk entries only; batch-1 never advanced the count
        assert reads == []  # the valid file was never opened or classified
        assert _count(database) == 0
    finally:
        database.close()


def test_the_barrier_wrapper_acquires_exclusive_itself(tmp_path: Path) -> None:
    # the only module-level reconciliation callable owns the barrier: a probe acquisition from a
    # second descriptor fails busy while its observe callback runs
    database, barrier, spool_root = _control(tmp_path)
    probe = GlobalCommitBarrier(tmp_path / "control" / "commit.lock")
    held: list[bool] = []

    def _observe(_report: object) -> None:
        blocked = False
        try:
            with probe.exclusive(blocking=False):
                pass
        except StateError:
            blocked = True
        held.append(blocked)

    try:
        report = reconcile_module._reconcile_under_barrier(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            observe=_observe,
        )
        assert held == [True]
        assert report.complete
    finally:
        database.close()


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


def test_recovery_authorizes_the_exact_local_persistence_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # spy on require_egress itself: recovery must authorize exactly LOCAL_SPOOL and LOCAL_SQLITE
    # with the segment's privacy class and require REDACTED_RECORD — a rewrite querying one surface,
    # a wrong surface, or accepting any disposition must fail this test
    from milhouse.privacy import EgressDisposition, EgressSurface
    from milhouse.spooling import ledger as ledger_module

    database, barrier, spool_root = _control(tmp_path)
    reconciler = SpoolReconciler(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    )
    calls: list[tuple[object, str]] = []

    def _spy(*, surface: object, privacy_class: str) -> object:
        calls.append((surface, privacy_class))
        return EgressDisposition.REDACTED_RECORD

    monkeypatch.setattr(ledger_module, "require_egress", _spy)
    try:
        header, frames = _segment()
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        report = reconciler.reconcile()
        assert len(report.registered) == 1
        assert calls == [
            (EgressSurface.LOCAL_SPOOL, "internal"),
            (EgressSurface.LOCAL_SQLITE, "internal"),
        ]
    finally:
        database.close()


def test_an_unexpected_disposition_registers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a disposition other than REDACTED_RECORD, returned WITHOUT PrivacyError, must still deny:
    # normalized to MH_SPOOL_EGRESS with zero segment and exporter rows
    from milhouse.privacy import EgressDisposition
    from milhouse.spooling import ledger as ledger_module

    database, barrier, spool_root = _control(tmp_path)
    reconciler = SpoolReconciler(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    )
    monkeypatch.setattr(ledger_module, "require_egress", lambda **_kw: EgressDisposition.METADATA)
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
def test_a_foreign_file_name_is_omitted(tmp_path: Path, name: str, detail: str) -> None:
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
        assert report.anomalies == (SegmentAnomaly("", _DAY, "foreign_name", detail),)
        assert name not in report.anomalies[0].batch_id
    finally:
        database.close()


def test_an_invalid_day_name_is_omitted_and_leaks_no_raw_name(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        canary = "CANARY_SECRET-not-a-day"
        (pending / canary).mkdir(mode=0o700)
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", "", "foreign_name", "day"),)
        # neither the raw name nor ANY derivative (incl. a dictionary-recoverable bare SHA-256
        # of it) reaches the report: the field is omitted entirely
        import hashlib

        surface = repr(report)
        assert canary not in surface
        assert hashlib.sha256(canary.encode()).hexdigest()[:16] not in surface
        assert "sha256:" not in surface
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
        assert report.anomalies == (SegmentAnomaly("", "", "foreign_name", "day"),)
        assert _count(database) == 0
        assert store.list_segments() == ()  # the ledger stays readable — no poison row
    finally:
        database.close()


def test_a_regular_file_where_a_day_directory_belongs_is_unsafe(tmp_path: Path) -> None:
    # a valid day NAME that is not a directory: the O_DIRECTORY open fails ENOTDIR and the entry is
    # reported unsafe, never listed or followed
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        (pending / _DAY).write_bytes(b"not a directory")
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", _DAY, "foreign_name", "day_unsafe"),)
        assert report.scanned == 0
    finally:
        database.close()


def test_an_overlong_foreign_file_name_is_omitted(tmp_path: Path) -> None:
    # a near-NAME_MAX entry name never reaches the report raw; the batch-id pattern (max 128) fails
    # and only the fixed-length fingerprint is recorded
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        name = "n" * 240 + ".jsonl"
        day_dir = spool_root / "pending" / _DAY
        day_dir.mkdir(mode=0o700, parents=True)
        os.chmod(spool_root / "pending", 0o700)
        os.chmod(day_dir, 0o700)
        (day_dir / name).write_bytes(b"x")
        os.chmod(day_dir / name, 0o600)
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", _DAY, "foreign_name", "batch_id"),)
        assert "n" * 100 not in repr(report.anomalies[0])
    finally:
        database.close()


def test_an_overlong_ledger_batch_id_is_omitted(tmp_path: Path) -> None:
    database, _store, _spool_root, reconciler = _reconciler(tmp_path)
    injected = "x" * 300  # exceeds the 128-char batch-id bound; passes every table constraint
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
        assert report.anomalies == (SegmentAnomaly("", "", "corrupt_ledger", "unreadable_row"),)
        assert "x" * 100 not in repr(report.anomalies[0])
    finally:
        database.close()


def test_a_control_byte_directory_name_is_omitted(tmp_path: Path) -> None:
    # POSIX permits newline and control bytes in names; the raw name must never reach the report
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    canary = "SECRET\nCANARY\x01-day"
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        (pending / canary).mkdir(mode=0o700)
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", "", "foreign_name", "day"),)
        surface = repr(report.anomalies[0]) + repr(report)
        assert "SECRET" not in surface
        assert "CANARY" not in surface
        assert "\\n" not in report.anomalies[0].day and "\n" not in report.anomalies[0].day
    finally:
        database.close()


def _swap_then_read(swap_action, calls: list[int]):  # type: ignore[no-untyped-def]
    """A deterministic race hook: run the swap before the first trusted read, then delegate."""

    from milhouse.spooling.reader import read_trusted_segment as real_read

    def _wrapper(path, *, installation_id, expected_parent=None):  # type: ignore[no-untyped-def]
        if not calls:
            calls.append(1)
            swap_action()
        return real_read(path, installation_id=installation_id, expected_parent=expected_parent)

    return _wrapper


def test_a_day_directory_replaced_after_enumeration_registers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the re-review's reproduction: swap the owned 0700 day directory between enumeration and the
    # trusted read, leaving a same-name file with a DIFFERENT exporter policy; the read must bind to
    # the inventoried directory identity and fail closed instead of registering the replacement
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    header_a, frames_a = _segment(batch_id="batch-1", exporters=("alpha",))
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header_a, frames_a))
    day_dir = spool_root / "pending" / _DAY

    def _swap() -> None:
        os.rename(day_dir, spool_root / "pending" / "displaced")
        day_dir.mkdir(mode=0o700)
        os.chmod(day_dir, 0o700)
        header_b, frames_b = _segment(batch_id="batch-1", exporters=("beta",))
        publish_segment_bytes(day_dir / "batch-1.jsonl", build_segment_bytes(header_b, frames_b))

    calls: list[int] = []
    monkeypatch.setattr(reconcile_module, "read_trusted_segment", _swap_then_read(_swap, calls))
    try:
        report = reconciler.reconcile()
        assert calls == [1]  # the swap genuinely ran before the read
        assert report.registered == ()
        assert report.healthy == 0
        assert report.anomalies == (
            SegmentAnomaly("batch-1", _DAY, "corrupt_orphan", "MH_SPOOL_CHANGED"),
        )
        assert _count(database) == 0
        assert _count(database, "_segment_exporters") == 0  # the beta policy was never bound
    finally:
        database.close()


def test_an_ancestor_directory_replaced_after_enumeration_registers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ancestor variant: the whole pending tree is swapped for a same-shape replacement
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    header_a, frames_a = _segment(batch_id="batch-1", exporters=("alpha",))
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header_a, frames_a))
    pending = spool_root / "pending"

    def _swap() -> None:
        os.rename(pending, spool_root / "pending-displaced")
        day_dir = pending / _DAY
        day_dir.mkdir(mode=0o700, parents=True)
        os.chmod(pending, 0o700)
        os.chmod(day_dir, 0o700)
        header_b, frames_b = _segment(batch_id="batch-1", exporters=("beta",))
        publish_segment_bytes(day_dir / "batch-1.jsonl", build_segment_bytes(header_b, frames_b))

    calls: list[int] = []
    monkeypatch.setattr(reconcile_module, "read_trusted_segment", _swap_then_read(_swap, calls))
    try:
        report = reconciler.reconcile()
        assert calls == [1]
        assert report.registered == ()
        assert report.anomalies == (
            SegmentAnomaly("batch-1", _DAY, "corrupt_orphan", "MH_SPOOL_CHANGED"),
        )
        assert _count(database) == 0
    finally:
        database.close()


def test_a_committed_file_in_a_replaced_directory_is_not_certified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the committed-verification path must also bind to the inventoried directory identity
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    header, frames = _segment(batch_id="batch-1")
    store.commit_segment(header, frames, committed_at=_NOW)
    day_dir = spool_root / "pending" / _DAY
    content = build_segment_bytes(header, frames)

    def _swap() -> None:
        os.rename(day_dir, spool_root / "pending" / "displaced")
        day_dir.mkdir(mode=0o700)
        os.chmod(day_dir, 0o700)
        publish_segment_bytes(day_dir / "batch-1.jsonl", content)  # even byte-identical content

    calls: list[int] = []
    monkeypatch.setattr(reconcile_module, "read_trusted_segment", _swap_then_read(_swap, calls))
    try:
        report = reconciler.reconcile()
        assert calls == [1]
        assert report.healthy == 0
        assert report.anomalies == (
            SegmentAnomaly("batch-1", _DAY, "corrupt_file", "MH_SPOOL_CHANGED"),
        )
    finally:
        database.close()


def test_a_foreign_owned_pending_directory_is_reported_unsafe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # exercise the distinct OWNER predicate without root: shift the uid the check compares against,
    # so the (mode-correct, world-invisible) directory reads as foreign-owned
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    pending = spool_root / "pending"
    pending.mkdir(mode=0o700)
    os.chmod(pending, 0o700)
    real_uid = os.geteuid()
    pending_inode = os.lstat(pending).st_ino
    real_fstat = os.fstat

    def _foreign_pending(descriptor: int) -> os.stat_result:
        info = real_fstat(descriptor)
        if info.st_ino != pending_inode:
            return info
        fields = list(info)
        fields[4] = real_uid + 1
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", _foreign_pending)
    try:
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", "", "foreign_name", "pending_unsafe"),)
        assert not report.complete
        assert report.registered == ()
    finally:
        database.close()


def test_a_foreign_owned_day_directory_is_reported_unsafe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    pending = spool_root / "pending"
    pending.mkdir(mode=0o700)
    os.chmod(pending, 0o700)
    day_dir = pending / _DAY
    day_dir.mkdir(mode=0o700)
    os.chmod(day_dir, 0o700)
    real_uid = os.geteuid()
    day_inode = os.lstat(day_dir).st_ino
    real_fstat = os.fstat

    def _foreign_day(descriptor: int) -> os.stat_result:
        info = real_fstat(descriptor)
        if info.st_ino != day_inode:
            return info
        fields = list(info)
        fields[4] = real_uid + 1  # st_uid in the portable ten-field stat_result sequence
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", _foreign_day)
    try:
        report = reconciler.reconcile()
        assert SegmentAnomaly("", _DAY, "foreign_name", "day_unsafe") in report.anomalies
        assert not report.complete
        assert report.registered == ()
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


def test_a_duplicate_straddling_the_day_bound_registers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the re-review's reproduction class: a conflicting copy hidden just beyond a bound must make
    # the whole pass mutation-free, never register the visible copy arbitrarily
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_DAYS", 1)
    header_a, frames_a = _segment(batch_id="batch-1")
    header_b, frames_b = _segment(batch_id="batch-1", exporters=("clickhouse", "extra"))
    _publish_orphan(
        spool_root, "2026-07-23", "batch-1.jsonl", build_segment_bytes(header_a, frames_a)
    )
    _publish_orphan(
        spool_root, "2026-07-24", "batch-1.jsonl", build_segment_bytes(header_b, frames_b)
    )
    try:
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert report.healthy == 0
        assert SegmentAnomaly("", "", "limit", "day_limit") in report.anomalies
        assert _count(database) == 0
        assert _count(database, "_segment_exporters") == 0
        # re-runs stay mutation-free and deterministic
        assert reconciler.reconcile().registered == ()
        assert _count(database) == 0
    finally:
        database.close()


def test_a_duplicate_straddling_the_total_bound_registers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_TOTAL", 1)
    header_a, frames_a = _segment(batch_id="batch-1")
    header_b, frames_b = _segment(batch_id="batch-1", exporters=("clickhouse", "extra"))
    _publish_orphan(
        spool_root, "2026-07-23", "batch-1.jsonl", build_segment_bytes(header_a, frames_a)
    )
    _publish_orphan(
        spool_root, "2026-07-24", "batch-1.jsonl", build_segment_bytes(header_b, frames_b)
    )
    try:
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert report.healthy == 0
        assert SegmentAnomaly("", "", "limit", "scan_limit") in report.anomalies
        assert _count(database) == 0
        assert _count(database, "_segment_exporters") == 0
        assert reconciler.reconcile().registered == ()
        assert _count(database) == 0
    finally:
        database.close()


def test_a_valid_orphan_beyond_the_anomaly_cap_is_not_registered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 1)
    header, frames = _segment(batch_id="batch-1")
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
    pending = spool_root / "pending"
    for junk in ("not-a-day-1", "not-a-day-2", "not-a-day-3"):
        (pending / junk).mkdir(mode=0o700)
    try:
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()  # the valid orphan is NOT registered past the cap
        assert SegmentAnomaly("", "", "limit", "anomaly_limit") in report.anomalies
        assert _count(database) == 0
    finally:
        database.close()


def test_the_anomaly_cap_on_the_final_candidate_registers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the re-review's reproduction: a positive cap where the LAST classified candidate fires
    # anomaly_limit — there is no next loop iteration, so only a post-phase check can void the pass
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 1)
    header, frames = _segment(batch_id="a-valid")
    _publish_orphan(spool_root, _DAY, "a-valid.jsonl", build_segment_bytes(header, frames))
    day_dir = spool_root / "pending" / _DAY
    for corrupt in ("b-corrupt.jsonl", "c-corrupt.jsonl"):  # sorted after a-valid
        (day_dir / corrupt).write_bytes(b"junk\n")
        os.chmod(day_dir / corrupt, 0o600)
    try:
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()  # the staged a-valid orphan was discarded, not promoted
        assert report.healthy == 0
        assert SegmentAnomaly("", "", "limit", "anomaly_limit") in report.anomalies
        assert _count(database) == 0
        assert _count(database, "_segment_exporters") == 0
        # re-runs stay mutation-free and deterministic
        assert reconciler.reconcile().registered == ()
        assert _count(database) == 0
    finally:
        database.close()


def test_the_anomaly_cap_during_missing_file_classification_registers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the analogous boundary in the other classification phase: missing-file anomalies exhaust the
    # cap after an orphan was staged — the staged orphan must still be discarded
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 2)
    header, frames = _segment(batch_id="a-valid")
    _publish_orphan(spool_root, _DAY, "a-valid.jsonl", build_segment_bytes(header, frames))
    try:
        with database.transaction() as connection:
            for name in ("m1", "m2", "m3"):  # valid committed rows whose files are absent
                connection.execute(
                    "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                    "config_generation, scope, target_id, privacy_class, retention_days, "
                    "record_count, content_sha256, byte_size, file_sha256, committed_at, origin) "
                    "VALUES (?, '2026-07-24', 1, 1, ?, 'target', 't', 'internal', 30, 1, ?, 10, ?, "
                    "'2026-07-24T12:00:00.000Z', 'committed')",
                    (name, "a" * 64, "c" * 64, "d" * 64),
                )
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert report.healthy == 0
        assert SegmentAnomaly("", "", "limit", "anomaly_limit") in report.anomalies
        rows = {
            row[0]
            for row in database.connection.execute("SELECT batch_id FROM _segments").fetchall()
        }
        assert rows == {"m1", "m2", "m3"}  # only the pre-inserted rows; a-valid was not promoted
        assert _count(database, "_segment_exporters") == 0
    finally:
        database.close()


def test_the_writer_fails_closed_on_a_truncated_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # mandatory recovery cannot certify a partial view: acquisition and commits both fail closed
    database, barrier, spool_root = _control(tmp_path)
    header, frames = _segment(batch_id="orphan-1")
    _publish_orphan(spool_root, _DAY, "orphan-1.jsonl", build_segment_bytes(header, frames))
    try:
        store = DurableSpool(  # a complete scan first: acquisition succeeds and registers
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        monkeypatch.setattr(reconcile_module, "_MAX_TOTAL", 0)
        later_header, later_frames = _segment(batch_id="later-2")
        with pytest.raises(SpoolError) as commit_error:
            store.commit_segment(later_header, later_frames, committed_at=_NOW)
        assert commit_error.value.code == "MH_SPOOL_INCOMPLETE"
        # nothing was published or recorded for the refused commit
        assert not (spool_root / "pending" / _DAY / "later-2.jsonl").exists()
        assert {r.batch_id for r in store.list_segments()} == {"orphan-1"}
        with pytest.raises(SpoolError) as acquire_error:
            DurableSpool(
                database=database,
                barrier=barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
            )
        assert acquire_error.value.code == "MH_SPOOL_INCOMPLETE"
    finally:
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
        report = reconciler.reconcile()
        # the scan STOPS at the bound: the limit anomaly is the only outcome — the over-limit file
        # is neither scanned, classified (no corrupt_orphan), nor registered
        assert report.anomalies == (SegmentAnomaly("", "", "limit", "scan_limit"),)
        assert report.scanned == 0
        assert report.registered == ()
        assert report.healthy == 0
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
        # read_segment must preserve the distinction independently of list_segments
        reconciled = store.read_segment("reconciled-1")
        assert reconciled is not None
        assert reconciled.origin == "reconciled"
        assert reconciled.committed_at == f"{_DAY}T00:00:00.000Z"
        committed = store.read_segment("committed-1")
        assert committed is not None
        assert committed.origin == "committed"
    finally:
        database.close()


def test_a_row_without_an_origin_value_defaults_to_committed(tmp_path: Path) -> None:
    # legacy compatibility: a row written without the origin column (as any pre-migration-3 writer
    # would) takes the column DEFAULT and reads back as a committed record
    database, store, _spool_root, _reconciler_unused = _reconciler(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                "config_generation, scope, target_id, privacy_class, retention_days, record_count, "
                "content_sha256, byte_size, file_sha256, committed_at) VALUES "
                "('legacy-1', '2026-07-24', 1, 1, ?, 'target', 't', 'internal', 30, 1, ?, 10, ?, "
                "'2026-07-24T12:00:00.000Z')",
                ("a" * 64, "c" * 64, "d" * 64),
            )
        stored = database.connection.execute(
            "SELECT origin FROM _segments WHERE batch_id = 'legacy-1'"
        ).fetchone()[0]
        assert stored == "committed"
        record = store.read_segment("legacy-1")
        assert record is not None
        assert record.origin == "committed"  # the default flows through full validation
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

    class _AssertingBarrier(GlobalCommitBarrier):
        @contextlib.contextmanager
        def exclusive(self, *, blocking: bool = True) -> Iterator[object]:
            assert _count(database) == 0  # not yet registered when the exclusive lock is taken
            with super().exclusive(blocking=blocking) as hold:
                yield hold

    reconciler._barrier = _AssertingBarrier(  # type: ignore[attr-defined]
        tmp_path / "control" / "commit.lock"
    )
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


def test_a_malformed_ledger_batch_id_is_omitted_not_echoed(tmp_path: Path) -> None:
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
        assert report.anomalies == (SegmentAnomaly("", "", "corrupt_ledger", "unreadable_row"),)
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
