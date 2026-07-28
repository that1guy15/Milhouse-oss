from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.config.filesystem import FileSnapshot, SecureFileError, SecureFileErrorKind
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
    QuarantinedFile,
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
    initialize_control_state,
    open_control_database,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)
_DAY = "2026-07-24"


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


def _segment(
    batch_id: str = "batch-1", *, events: tuple[str, ...] = ("event-1", "event-2")
) -> tuple[SegmentHeaderV1, tuple[SpoolFrameV1, ...]]:
    frames = tuple(
        SpoolFrameV1(batch_id=batch_id, sequence=index, record=_envelope(event))
        for index, event in enumerate(events, start=1)
    )
    lines = [spool_frame_line(frame) for frame in frames]
    header = SegmentHeaderV1(
        batch_id=batch_id,
        config_generation="a" * 64,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=("clickhouse",),
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


def _reconciler(tmp_path: Path):
    database, barrier, spool_root = _control(tmp_path)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    )
    reconciler = SpoolReconciler(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
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


# --- corrupt files move to quarantine ------------------------------------------------------------


def test_a_corrupt_orphan_is_quarantined(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk, not a segment\n")
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        moved = report.quarantined[0]
        assert moved.batch_id == "batch-1"
        assert moved.day == _DAY
        assert moved.detail.startswith("MH_SPOOL_")
        assert not path.exists()  # gone from pending
        target = spool_root / "quarantine" / _DAY / "batch-1.jsonl"
        assert target.read_bytes() == b"junk, not a segment\n"  # preserved, never deleted
        assert _count(database) == 0
        # a re-run is clean: pending is empty and nothing further moves
        second = reconciler.reconcile()
        assert second.quarantined == ()
        assert second.anomalies == ()
        assert second.scanned == 0
    finally:
        database.close()


def test_a_corrupt_committed_file_is_quarantined(tmp_path: Path) -> None:
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        store.commit_segment(header, frames, committed_at=_NOW)
        path = spool_root / "pending" / _DAY / "batch-1.jsonl"
        path.write_bytes(b"truncated\n")
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert report.quarantined[0].batch_id == "batch-1"
        assert not path.exists()
        assert (spool_root / "quarantine" / _DAY / "batch-1.jsonl").exists()
        # the ledger row survives as evidence; the next scan reports its file missing
        second = reconciler.reconcile()
        assert second.anomalies == (SegmentAnomaly("batch-1", _DAY, "missing_file", "absent"),)
    finally:
        database.close()


def test_a_mismatched_committed_file_is_quarantined(tmp_path: Path) -> None:
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment()
        store.commit_segment(header, frames, committed_at=_NOW)
        with database.transaction() as connection:
            connection.execute("UPDATE _segments SET retention_days = 7 WHERE batch_id = 'batch-1'")
        report = reconciler.reconcile()
        assert report.quarantined == (QuarantinedFile("batch-1", _DAY, "ledger_mismatch"),)
        assert (spool_root / "quarantine" / _DAY / "batch-1.jsonl").exists()
    finally:
        database.close()


def test_an_egress_denied_orphan_is_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)

    def _deny(_privacy_class: str) -> None:
        raise SpoolError("MH_SPOOL_EGRESS", "denied")

    monkeypatch.setattr(reconcile_module, "authorize_local_persistence", _deny)
    try:
        header, frames = _segment()
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        report = reconciler.reconcile()
        assert report.registered == ()
        assert report.quarantined == (QuarantinedFile("batch-1", _DAY, "MH_SPOOL_EGRESS"),)
        assert _count(database) == 0
    finally:
        database.close()


# --- conflict quarantine -------------------------------------------------------------------------


def test_a_divergent_conflict_quarantines_every_copy(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header_a, frames_a = _segment(batch_id="batch-1")
        header_b, frames_b = _segment(batch_id="batch-1", events=("other-1", "other-2"))
        _publish_orphan(
            spool_root, "2026-07-23", "batch-1.jsonl", build_segment_bytes(header_a, frames_a)
        )
        _publish_orphan(
            spool_root, "2026-07-24", "batch-1.jsonl", build_segment_bytes(header_b, frames_b)
        )
        report = reconciler.reconcile()
        assert report.registered == ()
        assert set(report.quarantined) == {
            QuarantinedFile("batch-1", "2026-07-23", "conflict_divergent"),
            QuarantinedFile("batch-1", "2026-07-24", "conflict_divergent"),
        }
        assert (spool_root / "quarantine" / "2026-07-23" / "batch-1.jsonl").exists()
        assert (spool_root / "quarantine" / "2026-07-24" / "batch-1.jsonl").exists()
        assert _count(database) == 0
        # a re-run is clean and mutation-free: the conflict left pending entirely
        second = reconciler.reconcile()
        assert second.quarantined == ()
        assert second.anomalies == ()
    finally:
        database.close()


def test_an_identical_conflict_quarantines_every_copy_as_duplicate(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(batch_id="batch-1")
        content = build_segment_bytes(header, frames)
        _publish_orphan(spool_root, "2026-07-23", "batch-1.jsonl", content)
        _publish_orphan(spool_root, "2026-07-24", "batch-1.jsonl", content)
        report = reconciler.reconcile()
        assert report.registered == ()
        assert {q.detail for q in report.quarantined} == {"conflict_duplicate"}
        assert len(report.quarantined) == 2
        assert _count(database) == 0
    finally:
        database.close()


# --- stale staged temporaries --------------------------------------------------------------------


def test_a_stale_staged_temporary_is_quarantined(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(batch_id="batch-1")
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        stage = spool_root / "pending" / _DAY / ".milhouse-stage-abc123"
        stage.write_bytes(b"partial write from a crashed writer")
        os.chmod(stage, 0o600)

        report = reconciler.reconcile()

        # the valid orphan still registers; the staged temporary is quarantined by policy
        assert len(report.registered) == 1
        assert QuarantinedFile("", _DAY, "stale_temp") in report.quarantined
        assert SegmentAnomaly("", _DAY, "stale_temp", "staged_temporary") in report.anomalies
        assert not stage.exists()
        assert (spool_root / "quarantine" / _DAY / ".milhouse-stage-abc123").exists()
    finally:
        database.close()


# --- move mechanics ------------------------------------------------------------------------------


def test_a_quarantine_name_collision_retries_with_a_counter(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
        # pre-place a colliding quarantine file: a hostile collision must not wedge recovery
        quarantine_day = spool_root / "quarantine" / _DAY
        quarantine_day.mkdir(mode=0o700, parents=True)
        os.chmod(spool_root / "quarantine", 0o700)
        os.chmod(quarantine_day, 0o700)
        (quarantine_day / "batch-1.jsonl").write_bytes(b"already here")
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"already here"  # untouched
        assert (quarantine_day / "1.batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


def test_quarantine_directories_are_private(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
        reconciler.reconcile()
        for directory in (spool_root / "quarantine", spool_root / "quarantine" / _DAY):
            info = os.lstat(directory)
            assert stat.S_IMODE(info.st_mode) == 0o700
    finally:
        database.close()


def test_a_replaced_day_directory_blocks_the_move(tmp_path: Path) -> None:
    # the move re-verifies the inventoried directory identity: a swap between classification and
    # mutation must fail with the fixed code, never move a file from the replacement directory
    database, _store, spool_root, _reconciler_unused = _reconciler(tmp_path)
    try:
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
        scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
        day_dir = spool_root / "pending" / _DAY
        captured = reconcile_module.FileIdentity.from_stat(os.stat(day_dir))
        snapshot = reconcile_module.FileSnapshot.from_stat(os.lstat(day_dir / "batch-1.jsonl"))
        digest = hashlib.sha256(b"junk\n").hexdigest()
        os.rename(day_dir, spool_root / "pending" / "displaced")
        replacement = spool_root / "pending" / _DAY
        replacement.mkdir(mode=0o700)
        os.chmod(replacement, 0o700)
        (replacement / "batch-1.jsonl").write_bytes(b"impostor")
        outcome = scan._move_to_quarantine(_DAY, "batch-1.jsonl", captured, snapshot, digest)
        assert outcome == "changed"
        assert (replacement / "batch-1.jsonl").exists()  # the impostor was not moved
    finally:
        database.close()


def test_an_incomplete_pass_moves_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 1)
    try:
        path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
        pending = spool_root / "pending"
        for junk in ("0000-junk-a", "0000-junk-b"):  # sort first; exhaust the cap in inventory
            (pending / junk).mkdir(mode=0o700)
        report = reconciler.reconcile()
        assert not report.complete
        assert report.quarantined == ()
        assert path.exists()  # nothing moved on a truncated pass
        assert not (spool_root / "quarantine").exists()
    finally:
        database.close()


def test_a_foreign_named_file_is_reported_but_not_moved(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        day_dir = spool_root / "pending" / _DAY
        day_dir.mkdir(mode=0o700, parents=True)
        os.chmod(spool_root / "pending", 0o700)
        os.chmod(day_dir, 0o700)
        foreign = day_dir / "not-a-segment.txt"
        foreign.write_bytes(b"x")
        os.chmod(foreign, 0o600)
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert foreign.exists()  # left in place: no well-formed quarantine name
        assert report.anomalies == (SegmentAnomaly("", _DAY, "foreign_name", "suffix"),)
    finally:
        database.close()


# --- ACL envelope --------------------------------------------------------------------------------


def test_an_acl_bearing_pending_directory_is_unsafe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    pending = spool_root / "pending"
    pending.mkdir(mode=0o700)
    os.chmod(pending, 0o700)
    pending_inode = os.lstat(pending).st_ino
    real_acl_check = reconcile_module.require_no_extended_acl

    def _acl_on_pending(descriptor: int) -> None:
        if os.fstat(descriptor).st_ino == pending_inode:
            raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)
        real_acl_check(descriptor)

    monkeypatch.setattr(reconcile_module, "require_no_extended_acl", _acl_on_pending)
    try:
        report = reconciler.reconcile()
        assert report.anomalies == (SegmentAnomaly("", "", "foreign_name", "pending_unsafe"),)
        assert not report.complete
    finally:
        database.close()


def test_an_acl_bearing_spool_root_fails_the_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from milhouse.spooling import commit as commit_module

    database, store, _spool_root, _reconciler_unused = _reconciler(tmp_path)

    def _acl_everywhere(_descriptor: int) -> None:
        raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)

    monkeypatch.setattr(commit_module, "require_no_extended_acl", _acl_everywhere)
    try:
        header, frames = _segment()
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(header, frames, committed_at=_NOW)
        assert captured.value.code == "MH_SPOOL_DIR"
    finally:
        database.close()


# --- failure branches ----------------------------------------------------------------------------


def test_raw_hash_fails_safe_on_unreadable_subjects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert reconcile_module._raw_sha256(tmp_path / "absent") is None
    directory = tmp_path / "a-directory"
    directory.mkdir()
    assert reconcile_module._raw_sha256(directory) is None
    big = tmp_path / "big"
    big.write_bytes(b"x" * 32)
    monkeypatch.setattr(reconcile_module, "MAX_SEGMENT_FILE_BYTES", 8)
    assert reconcile_module._raw_sha256(big) is None


def test_a_blocked_quarantine_root_reports_and_never_wedges(tmp_path: Path) -> None:
    # a regular FILE squatting on spool/quarantine cannot be secured as a directory; the move is
    # reported blocked, the corrupt file stays in pending, and recovery/commits keep working —
    # the adversarial review showed one un-quarantinable file must not wedge all commits
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
        (spool_root / "quarantine").write_bytes(b"squatter")
        report = reconciler.reconcile()
        assert report.complete
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "unreachable") in (
            report.anomalies
        )
        assert path.exists()  # left in place, re-reported every scan
        # a healthy, unrelated commit still succeeds despite the blocked quarantine
        header, frames = _segment(batch_id="healthy-1")
        store.commit_segment(header, frames, committed_at=_NOW)
        assert store.read_segment("healthy-1") is not None
    finally:
        database.close()


def test_exhausted_collision_retries_report_blocked(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
        quarantine_day = spool_root / "quarantine" / _DAY
        quarantine_day.mkdir(mode=0o700, parents=True)
        os.chmod(spool_root / "quarantine", 0o700)
        os.chmod(quarantine_day, 0o700)
        (quarantine_day / "batch-1.jsonl").write_bytes(b"x")
        for attempt in range(1, 100):  # occupy every retry candidate
            (quarantine_day / f"{attempt}.batch-1.jsonl").write_bytes(b"x")
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "collision") in (
            report.anomalies
        )
        assert (spool_root / "pending" / _DAY / "batch-1.jsonl").exists()
    finally:
        database.close()


def test_the_wrapper_binding_rejects_each_bad_argument(tmp_path: Path) -> None:
    database, barrier, spool_root = _control(tmp_path)
    try:
        cases = (
            ({"barrier": object()}, "MH_SPOOL_STORE"),
            ({"database": object()}, "MH_SPOOL_STORE"),
            ({"spool_root": tmp_path / "elsewhere"}, "MH_SPOOL_STORE"),
            ({"installation_id": "bad"}, "MH_SPOOL_IDENTITY"),
        )
        for overrides, code in cases:
            kwargs: dict[str, object] = {
                "database": database,
                "barrier": barrier,
                "spool_root": spool_root,
                "installation_id": _INSTALLATION_ID,
            }
            kwargs.update(overrides)
            with pytest.raises(SpoolError) as captured:
                reconcile_module._reconcile_under_barrier(**kwargs)  # type: ignore[arg-type]
            assert captured.value.code == code
    finally:
        database.close()


def test_the_cap_breaks_out_of_candidate_and_missing_file_loops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # fire the cap mid-classification with items remaining in BOTH phases: the loops break early
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 2)
    try:
        for name in ("a-corrupt.jsonl", "b-corrupt.jsonl", "c-corrupt.jsonl", "d-corrupt.jsonl"):
            _publish_orphan(spool_root, _DAY, name, b"junk\n")
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert report.quarantined == ()
        with database.transaction() as connection:
            for name in ("m1", "m2", "m3", "m4"):
                connection.execute(
                    "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                    "config_generation, scope, target_id, privacy_class, retention_days, "
                    "record_count, content_sha256, byte_size, file_sha256, committed_at, origin) "
                    "VALUES (?, '2026-07-24', 1, 1, ?, 'target', 't', 'internal', 30, 1, ?, 10, "
                    "?, '2026-07-24T12:00:00.000Z', 'committed')",
                    (name, "a" * 64, "c" * 64, "d" * 64),
                )
        second = reconciler.reconcile()
        assert not second.complete
        assert second.registered == ()
    finally:
        database.close()


def test_the_cap_firing_on_the_final_inventory_entry_voids_the_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 1)
    try:
        header, frames = _segment(batch_id="a-valid")
        _publish_orphan(spool_root, _DAY, "a-valid.jsonl", build_segment_bytes(header, frames))
        day_dir = spool_root / "pending" / _DAY
        for junk in ("z1.txt", "z2.txt"):  # sorted last: the cap fires on the final entries
            (day_dir / junk).write_bytes(b"x")
            os.chmod(day_dir / junk, 0o600)
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert _count(database) == 0
    finally:
        database.close()


def test_a_conflict_never_demotes_a_healthy_committed_segment(tmp_path: Path) -> None:
    # the adversarial review's reproduction: commit batch-1 (acknowledged success), then a retry
    # publishes a same-batch duplicate on another day and crashes at the ledger PK. The conflict
    # must quarantine ONLY the duplicate — the ledger-designated healthy copy is kept, because the
    # ledger already unambiguously chose it (no directory-order choice is involved)
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(batch_id="batch-1")
        store.commit_segment(header, frames, committed_at=_NOW)
        committed_path = spool_root / "pending" / _DAY / "batch-1.jsonl"
        retry_header, retry_frames = _segment(batch_id="batch-1", events=("retry-1", "retry-2"))
        _publish_orphan(
            spool_root,
            "2026-07-25",
            "batch-1.jsonl",
            build_segment_bytes(retry_header, retry_frames),
        )

        report = reconciler.reconcile()

        assert report.quarantined == (
            QuarantinedFile("batch-1", "2026-07-25", "conflict_divergent"),
        )
        assert committed_path.exists()  # the acknowledged segment was NOT demoted
        assert report.healthy == 1
        assert {a.kind for a in report.anomalies} == {"conflict"}  # the situation is still reported
        record = store.read_segment("batch-1")
        assert record is not None
        assert record.day == _DAY
        # the next scan is clean: one healthy ledger-designated file, no dangling row
        second = reconciler.reconcile()
        assert second.healthy == 1
        assert second.anomalies == ()
        assert second.quarantined == ()
    finally:
        database.close()


def test_a_conflict_with_a_corrupt_ledger_day_copy_quarantines_all(tmp_path: Path) -> None:
    # if the ledger's own-day copy no longer agrees, no copy is ledger-designated: all quarantine
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(batch_id="batch-1")
        store.commit_segment(header, frames, committed_at=_NOW)
        (spool_root / "pending" / _DAY / "batch-1.jsonl").write_bytes(b"corrupted\n")
        retry_header, retry_frames = _segment(batch_id="batch-1", events=("retry-1", "retry-2"))
        _publish_orphan(
            spool_root,
            "2026-07-25",
            "batch-1.jsonl",
            build_segment_bytes(retry_header, retry_frames),
        )
        report = reconciler.reconcile()
        assert len(report.quarantined) == 2
        assert report.healthy == 0
        # the ledger row survives as evidence and the next scan reports its file missing
        second = reconciler.reconcile()
        assert second.anomalies == (SegmentAnomaly("batch-1", _DAY, "missing_file", "absent"),)
    finally:
        database.close()


# --- P0 regressions: no-follow leaf classification -----------------------------------------------


_CANARY = b"synthetic-private-canary"


def _assert_no_canary_beneath_quarantine(spool_root: Path, canary: Path) -> None:
    # the reviewer's exact demand: no foreign inode and no canary byte is ever present beneath
    # quarantine, however the scan misbehaved
    assert os.lstat(canary).st_nlink == 1  # never hard-linked anywhere
    quarantine = spool_root / "quarantine"
    if not quarantine.exists():
        return
    for path in quarantine.rglob("*"):
        info = os.lstat(path)
        assert info.st_ino != os.lstat(canary).st_ino
        if stat.S_ISREG(info.st_mode):
            assert path.read_bytes() != _CANARY


def test_a_staged_symlink_to_an_external_canary_is_never_quarantined(tmp_path: Path) -> None:
    # the re-review's P0 reproduction: a symlink named like a staged temporary must never be
    # followed, moved, or unlinked — linking it imported arbitrary foreign file content
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        canary = tmp_path / "private-canary"
        canary.write_bytes(_CANARY)
        os.chmod(canary, 0o600)
        header, frames = _segment(batch_id="batch-1")
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", build_segment_bytes(header, frames))
        evil = spool_root / "pending" / _DAY / ".milhouse-stage-link"
        os.symlink(canary, evil)

        report = reconciler.reconcile()

        assert len(report.registered) == 1  # the valid orphan still registers
        assert report.quarantined == ()  # the symlink produced NO quarantine entry
        assert SegmentAnomaly("", _DAY, "stale_temp", "staged_temporary") in report.anomalies
        assert SegmentAnomaly("", _DAY, "quarantine_blocked", "unsafe") in report.anomalies
        assert os.path.islink(evil)  # left exactly in place, never unlinked
        assert canary.read_bytes() == _CANARY
        assert not (spool_root / "quarantine").exists()  # nothing was moved at all
        _assert_no_canary_beneath_quarantine(spool_root, canary)
    finally:
        database.close()


def test_staged_directory_fifo_hardlink_and_loose_mode_shapes_are_refused(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        day_dir = pending / _DAY
        day_dir.mkdir(mode=0o700)
        os.chmod(day_dir, 0o700)
        (day_dir / ".milhouse-stage-dir").mkdir(mode=0o700)
        os.mkfifo(day_dir / ".milhouse-stage-fifo", 0o600)
        hard = day_dir / ".milhouse-stage-hard"
        hard.write_bytes(b"two names")
        os.chmod(hard, 0o600)
        os.link(hard, tmp_path / "second-name")  # nlink == 2 with no quarantine twin
        loose = day_dir / ".milhouse-stage-mode"
        loose.write_bytes(b"loose")
        os.chmod(loose, 0o644)
        # an EXISTING empty quarantine day exercises the twin probe's full candidate sweep
        quarantine_day = spool_root / "quarantine" / _DAY
        quarantine_day.mkdir(mode=0o700, parents=True)
        os.chmod(spool_root / "quarantine", 0o700)
        os.chmod(quarantine_day, 0o700)

        report = reconciler.reconcile()

        assert report.complete
        assert report.quarantined == ()
        blocked = [a for a in report.anomalies if a.kind == "quarantine_blocked"]
        assert blocked == [SegmentAnomaly("", _DAY, "quarantine_blocked", "unsafe")] * 4
        assert (day_dir / ".milhouse-stage-dir").is_dir()
        assert stat.S_ISFIFO(os.lstat(day_dir / ".milhouse-stage-fifo").st_mode)
        assert hard.read_bytes() == b"two names"
        assert loose.read_bytes() == b"loose"
        assert list(quarantine_day.iterdir()) == []  # nothing was ever linked in
    finally:
        database.close()


def test_device_and_socket_shapes_are_never_permitted() -> None:
    # device nodes cannot be created unprivileged, so the fixed shape predicate is proven directly
    uid = os.getuid()

    def _info(mode: int, *, nlink: int = 1, owner: int = uid) -> os.stat_result:
        return os.stat_result((mode, 1, 2, nlink, owner, 0, 0, 0, 0, 0))

    assert reconcile_module._permitted_quarantine_shape(_info(stat.S_IFREG | 0o600))
    for refused in (
        stat.S_IFCHR | 0o600,  # character device
        stat.S_IFBLK | 0o600,  # block device
        stat.S_IFSOCK | 0o600,  # socket
        stat.S_IFIFO | 0o600,  # FIFO
        stat.S_IFDIR | 0o700,  # directory
        stat.S_IFLNK | 0o777,  # symlink (also refused earlier by the no-follow open)
        stat.S_IFREG | 0o644,  # loose mode
        stat.S_IFREG | 0o400,  # tightened mode
    ):
        assert not reconcile_module._permitted_quarantine_shape(_info(refused))
    assert not reconcile_module._permitted_quarantine_shape(_info(stat.S_IFREG | 0o600, nlink=2))
    assert not reconcile_module._permitted_quarantine_shape(
        _info(stat.S_IFREG | 0o600, owner=uid + 1)
    )
    # multi-link files are always refused: the copy-based move adopts an interrupted move by
    # DIGEST at move time, so no extra-link shape is ever admissible at classification
    assert not reconcile_module._permitted_quarantine_shape(_info(stat.S_IFREG | 0o600, nlink=3))


def test_an_acl_bearing_leaf_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    real_check = reconcile_module.require_no_extended_acl

    def _acl_on_files(descriptor: int) -> None:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)
        real_check(descriptor)

    try:
        stage = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
        os.rename(stage, stage.with_name(".milhouse-stage-acl"))
        monkeypatch.setattr(reconcile_module, "require_no_extended_acl", _acl_on_files)
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("", _DAY, "quarantine_blocked", "unsafe") in report.anomalies
        assert (spool_root / "pending" / _DAY / ".milhouse-stage-acl").exists()
    finally:
        database.close()


def test_a_regular_replacement_swapped_in_during_the_copy_is_never_unlinked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the deterministic race, copy edition: replace the classified file at its name while the
    # verified copy publishes — the quarantine copy holds EXACTLY the classified bytes (they
    # were read from the verified descriptor, not the name) and the replacement is never
    # unlinked; the newcomer is scanned next pass
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    aside = tmp_path / "displaced-original"
    real_link = os.link
    swapped: list[bool] = []

    def _swapping_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):  # type: ignore[no-untyped-def]
        if not swapped:
            swapped.append(True)
            os.rename(path, aside)
            path.write_bytes(b"replacement-not-classified")
            os.chmod(path, 0o600)
        return real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks
        )

    monkeypatch.setattr(os, "link", _swapping_link)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        target = spool_root / "quarantine" / _DAY / "batch-1.jsonl"
        assert target.read_bytes() == b"junk\n"  # exactly the classified digest, nothing else
        assert path.read_bytes() == b"replacement-not-classified"  # never unlinked
        assert aside.read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_symlink_replacement_swapped_in_during_the_copy_is_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    canary = tmp_path / "private-canary"
    canary.write_bytes(_CANARY)
    os.chmod(canary, 0o600)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    aside = tmp_path / "displaced-original"
    real_link = os.link
    swapped: list[bool] = []

    def _swapping_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):  # type: ignore[no-untyped-def]
        if not swapped:
            swapped.append(True)
            os.rename(path, aside)
            os.symlink(canary, path)
        return real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks
        )

    monkeypatch.setattr(os, "link", _swapping_link)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        target = spool_root / "quarantine" / _DAY / "batch-1.jsonl"
        assert target.read_bytes() == b"junk\n"  # the classified bytes, never the canary
        assert os.path.islink(path)  # the swapped-in symlink was never unlinked or followed
        assert aside.read_bytes() == b"junk\n"
        assert canary.read_bytes() == _CANARY
        _assert_no_canary_beneath_quarantine(spool_root, canary)
    finally:
        database.close()


# --- P1 regressions: durable ordering and outcome taxonomy ---------------------------------------


def _dir_ident(path: Path) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (info.st_dev, info.st_ino)


def test_the_move_orders_target_fsync_before_source_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the re-review's P1: the target name must be durable BEFORE the source is touched, and the
    # freshly created quarantine directories must be made durable by fsyncing their parents
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = spool_root / "pending" / _DAY
    quarantine_root = spool_root / "quarantine"
    quarantine_day = quarantine_root / _DAY
    log: list[tuple[str, object]] = []
    real_link, real_fsync, real_replace, real_unlink = os.link, os.fsync, os.replace, os.unlink

    def _labelled(fd: int) -> object:
        ident = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        for label, target in (
            ("spool-root", spool_root),
            ("quarantine-root", quarantine_root),
            ("quarantine-day", quarantine_day),
            ("pending-day", pending_day),
        ):
            if _dir_ident(target) == ident:
                return label
        return "other"

    def _logging_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):  # type: ignore[no-untyped-def]
        log.append(("link", follow_symlinks))
        return real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks
        )

    def _logging_fsync(fd: int) -> None:
        log.append(("fsync", _labelled(fd)))
        real_fsync(fd)

    def _logging_unlink(name, *, dir_fd=None):  # type: ignore[no-untyped-def]
        label = "other" if dir_fd is None else _labelled(dir_fd)
        log.append(("unlink", label))
        real_unlink(name, dir_fd=dir_fd)

    def _logging_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):  # type: ignore[no-untyped-def]
        label = "other" if src_dir_fd is None else _labelled(src_dir_fd)
        log.append(("retire", label))
        real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(os, "link", _logging_link)
    monkeypatch.setattr(os, "fsync", _logging_fsync)
    monkeypatch.setattr(os, "replace", _logging_replace)
    monkeypatch.setattr(os, "unlink", _logging_unlink)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert [entry for entry in log if entry[0] == "link"] == [("link", False)]  # no-follow
        link_at = log.index(("link", False))
        # each freshly created quarantine directory was made durable by fsyncing its parent,
        # BEFORE anything was linked into it
        assert log.index(("fsync", "spool-root")) < link_at
        assert log.index(("fsync", "quarantine-root")) < link_at
        # The target is durable before the source is atomically retired. The retirement is made
        # durable before its cleanup, and that cleanup is flushed last.
        assert [entry for entry in log if entry == ("unlink", "pending-day")] == [
            ("unlink", "pending-day")
        ]
        retire_at = log.index(("retire", "pending-day"))
        cleanup_at = log.index(("unlink", "pending-day"))
        pending_syncs = [
            index for index, entry in enumerate(log) if entry == ("fsync", "pending-day")
        ]
        assert (
            link_at
            < log.index(("fsync", "quarantine-day"))
            < retire_at
            < pending_syncs[0]
            < cleanup_at
            < pending_syncs[-1]
        )
        assert not path.exists()
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_transient_target_fsync_failure_is_verified_and_self_heals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a publish failure is never taken at face value: the move VERIFIES whether the durable
    # name appeared — after a single transient directory-fsync failure the copy is found,
    # re-proven durable, and the move completes in the same pass
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    real_fsync = os.fsync
    fail = [True]

    def _failing_fsync(fd: int) -> None:
        info = os.fstat(fd)
        if fail and _dir_ident(quarantine_day) == (info.st_dev, info.st_ino):
            fail.clear()
            raise OSError(5, "planted target fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _failing_fsync)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert not path.exists()
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_persistent_target_fsync_failure_reports_uncertain_and_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the re-review's P2: when durability can neither be proven nor disproven, the report says
    # UNCERTAIN — never a clean blocked code while an unproven copy exists
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    real_fsync = os.fsync
    failing = [True]

    def _failing_fsync(fd: int) -> None:
        info = os.fstat(fd)
        if failing and _dir_ident(quarantine_day) == (info.st_dev, info.st_ino):
            raise OSError(5, "planted target fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _failing_fsync)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        # the report matches the observed two-name state: source AND an unproven copy exist
        assert path.read_bytes() == b"junk\n"
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
        failing.clear()
        second = reconciler.reconcile()  # the retry adopts the same-digest copy and completes
        assert len(second.quarantined) == 1
        assert not path.exists()
        entries = sorted(entry.name for entry in quarantine_day.iterdir())
        assert entries == ["batch-1.jsonl"]  # one durable name, no aliases, no debris
    finally:
        database.close()


def test_a_link_failure_blocks_cleanly_with_the_source_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_link = os.link
    fail = [True]

    def _failing_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):  # type: ignore[no-untyped-def]
        if fail:
            fail.clear()
            raise OSError(5, "planted link failure")
        return real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks
        )

    monkeypatch.setattr(os, "link", _failing_link)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"
        quarantine_day = spool_root / "quarantine" / _DAY
        # VERIFIED blocked: no candidate name appeared (staging debris is not a candidate)
        assert [e.name for e in quarantine_day.iterdir() if not e.name.startswith(".")] == []
        second = reconciler.reconcile()  # the retry clears the stage debris and completes
        assert len(second.quarantined) == 1
        assert not path.exists()
        assert sorted(e.name for e in quarantine_day.iterdir()) == ["batch-1.jsonl"]
    finally:
        database.close()


@pytest.mark.parametrize("target_parts", [("quarantine",), ("quarantine", _DAY)])
def test_a_blocked_quarantine_directory_mkdir_reports_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_parts: tuple[str, ...]
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    blocked_name = target_parts[-1] if target_parts else "quarantine"
    blocked_name = blocked_name if target_parts != ("quarantine", _DAY) else _DAY
    real_mkdir = os.mkdir
    fail = [True]

    def _failing_mkdir(target, mode=0o777, *, dir_fd=None):  # type: ignore[no-untyped-def]
        if fail and target == blocked_name and dir_fd is not None:
            raise OSError(13, "planted mkdir failure")
        return real_mkdir(target, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", _failing_mkdir)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "unreachable") in (
            report.anomalies
        )
        assert path.read_bytes() == b"junk\n"
        fail.clear()
        second = reconciler.reconcile()  # the retry converges once the directory can be created
        assert len(second.quarantined) == 1
        assert not path.exists()
    finally:
        database.close()


def test_an_undurable_directory_creation_is_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a directory whose creating parent fsync fails is not durably named: the move must not
    # proceed into it
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    monkeypatch.setattr(reconcile_module, "_fsync_descriptor", lambda _fd: False)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "unreachable") in (
            report.anomalies
        )
        assert path.read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_source_unlink_failure_reports_commit_uncertain_and_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # after the target is durable, a retirement-unlink failure is COMMIT-UNCERTAIN: never reported
    # as completed, and the next scan adopts the target through the encoded candidate base
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = spool_root / "pending" / _DAY
    quarantine_day = spool_root / "quarantine" / _DAY
    real_unlink = os.unlink
    fail = [True]

    def _failing_unlink(name, *, dir_fd=None):  # type: ignore[no-untyped-def]
        if fail and dir_fd is not None:
            info = os.fstat(dir_fd)
            if _dir_ident(pending_day) == (info.st_dev, info.st_ino):
                fail.clear()
                raise OSError(5, "planted unlink failure")
        return real_unlink(name, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", _failing_unlink)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        # The public source name is gone, but the exact bytes remain under a private retirement.
        # The durable target and staged source are separate inodes.
        target = quarantine_day / "batch-1.jsonl"
        assert not path.exists()
        retirements = tuple(pending_day.glob(f"{reconcile_module._RETIRE_PREFIX}*"))
        assert len(retirements) == 1
        assert os.stat(retirements[0]).st_ino != os.stat(target).st_ino
        assert target.read_bytes() == retirements[0].read_bytes() == b"junk\n"
        # the retry converges by adopting the same-digest copy: one durable target, no debris
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert list(pending_day.iterdir()) == []
        assert sorted(entry.name for entry in quarantine_day.iterdir()) == ["batch-1.jsonl"]
        assert target.read_bytes() == b"junk\n"
        third = reconciler.reconcile()  # and the scan after that is clean
        assert third.quarantined == ()
        assert third.anomalies == ()
    finally:
        database.close()


def test_a_source_fsync_failure_after_unlink_reports_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = spool_root / "pending" / _DAY
    quarantine_day = spool_root / "quarantine" / _DAY
    real_fsync = os.fsync
    pending_fsyncs: list[int] = []

    def _failing_fsync(fd: int) -> None:
        info = os.fstat(fd)
        if _dir_ident(pending_day) == (info.st_dev, info.st_ino):
            pending_fsyncs.append(fd)
            if len(pending_fsyncs) == 2:
                raise OSError(5, "planted source fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _failing_fsync)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        # the durable quarantine name survives; the source name is already gone
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
        assert not path.exists()
        second = reconciler.reconcile()  # nothing is left to converge: the next scan is clean
        assert second.quarantined == ()
        assert second.anomalies == ()
        assert [entry.name for entry in quarantine_day.iterdir()] == ["batch-1.jsonl"]
    finally:
        database.close()


# --- round-2 regressions: content-bound moves (P1) -----------------------------------------------


def test_an_in_place_rewrite_before_the_move_is_never_certified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the round-2 P1 reproduction: mutate the classified file IN PLACE (same inode) between
    # classification and the move — inode identity alone must never authorize the move
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    original_inode = os.lstat(path).st_ino
    real_ensure = reconcile_module._ensure_private_dir_at
    mutated: list[bool] = []

    def _mutating_ensure(parent_fd, name):  # type: ignore[no-untyped-def]
        if not mutated:
            mutated.append(True)
            with path.open("r+b") as handle:  # same inode, new bytes
                handle.write(b"replacement-bytes-never-classified")
        return real_ensure(parent_fd, name)

    monkeypatch.setattr(reconcile_module, "_ensure_private_dir_at", _mutating_ensure)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        assert os.lstat(path).st_ino == original_inode  # untouched: same inode, mutated bytes
        assert path.read_bytes() == b"replacement-bytes-never-classified"
        quarantine_day = spool_root / "quarantine" / _DAY
        candidates = [e.name for e in quarantine_day.iterdir() if not e.name.startswith(".")]
        assert candidates == []  # no target holds the never-classified bytes
    finally:
        database.close()


def test_a_same_size_in_place_rewrite_before_the_move_is_never_certified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # even a same-length rewrite (size unchanged) is caught: the snapshot's mtime/ctime and the
    # digest both bind the move to the exact classified content
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_ensure = reconcile_module._ensure_private_dir_at
    mutated: list[bool] = []

    def _mutating_ensure(parent_fd, name):  # type: ignore[no-untyped-def]
        if not mutated:
            mutated.append(True)
            with path.open("r+b") as handle:
                handle.write(b"JUNK\n")  # same length, same inode, different bytes
        return real_ensure(parent_fd, name)

    monkeypatch.setattr(reconcile_module, "_ensure_private_dir_at", _mutating_ensure)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        assert path.read_bytes() == b"JUNK\n"  # never unlinked
        quarantine_day = spool_root / "quarantine" / _DAY
        assert [e.name for e in quarantine_day.iterdir() if not e.name.startswith(".")] == []
    finally:
        database.close()


def test_an_in_place_rewrite_during_target_creation_is_never_unlinked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the round-2 P1's second window: mutate in place AFTER the verified read, DURING target
    # creation — the target must contain only the exact classified digest, and the mutated
    # source must never be unlinked; the next scan quarantines the new bytes separately
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    original_inode = os.lstat(path).st_ino
    real_link = os.link
    mutated: list[bool] = []

    def _mutating_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):  # type: ignore[no-untyped-def]
        if not mutated:
            mutated.append(True)
            with path.open("r+b") as handle:  # same inode, new bytes, mid-publish
                handle.write(b"replacement-bytes-never-classified")
        return real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks
        )

    monkeypatch.setattr(os, "link", _mutating_link)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        target = spool_root / "quarantine" / _DAY / "batch-1.jsonl"
        assert target.read_bytes() == b"junk\n"  # exactly the classified digest
        assert os.lstat(target).st_ino != original_inode  # a copy: the writable inode is severed
        assert os.lstat(path).st_ino == original_inode
        assert path.read_bytes() == b"replacement-bytes-never-classified"  # never unlinked
        # the next scan treats the mutated leftover as a fresh subject and quarantines it too
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert not path.exists()
        quarantine_day = spool_root / "quarantine" / _DAY
        assert (quarantine_day / "1.batch-1.jsonl").read_bytes() == (
            b"replacement-bytes-never-classified"
        )
        assert target.read_bytes() == b"junk\n"  # both histories preserved, nothing lost
    finally:
        database.close()


# --- round-2 regressions: parent-fsync durability on retry (P1) ----------------------------------


@pytest.mark.parametrize("failed_parent_parts", [(), ("quarantine",)])
def test_a_failed_parent_fsync_is_reproven_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_parent_parts: tuple[str, ...]
) -> None:
    # the round-2 P1 reproduction: a directory that survived a failed parent fsync must never
    # be implicitly trusted — the retry must fsync the SAME parent successfully before any
    # copy or unlink, even though the directory already exists
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    failed_parent = spool_root.joinpath(*failed_parent_parts)  # spool root, or quarantine root
    real_fsync = reconcile_module._fsync_descriptor
    plant: list[bool] = [True]
    proven: list[Path] = []

    def _ident(target: Path):  # type: ignore[no-untyped-def]
        try:
            info = os.stat(target)
        except OSError:
            return None
        return (info.st_dev, info.st_ino)

    def _planted_fsync(descriptor: int):  # type: ignore[no-untyped-def]
        info = os.fstat(descriptor)
        fd_ident = (info.st_dev, info.st_ino)
        if plant and fd_ident == _ident(failed_parent):
            plant.clear()
            return False
        outcome = real_fsync(descriptor)
        if outcome:
            for label in (spool_root, spool_root / "quarantine"):
                if fd_ident == _ident(label):
                    proven.append(label)
        return outcome

    monkeypatch.setattr(reconcile_module, "_fsync_descriptor", _planted_fsync)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "unreachable") in (
            report.anomalies
        )
        assert path.read_bytes() == b"junk\n"  # nothing moved, nothing unlinked
        # retry with fsync restored: the previously failed parent is fsynced successfully
        # BEFORE the copy lands, despite both directories already existing
        proven.clear()
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert failed_parent in proven  # the exact failed parent was re-proven durable
        assert not path.exists()
        assert (spool_root / "quarantine" / _DAY / "batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


def test_every_accepted_directory_parent_is_fsynced_even_when_it_already_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    # pre-create both quarantine directories so mkdir never runs
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    real_fsync = reconcile_module._fsync_descriptor
    proven: list[Path] = []

    def _recording_fsync(descriptor: int):  # type: ignore[no-untyped-def]
        info = os.fstat(descriptor)
        for label in (spool_root, spool_root / "quarantine"):
            try:
                target = os.stat(label)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
                proven.append(label)
        return real_fsync(descriptor)

    monkeypatch.setattr(reconcile_module, "_fsync_descriptor", _recording_fsync)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert spool_root in proven  # the quarantine root's parent entry, re-proven
        assert (spool_root / "quarantine") in proven  # the day directory's parent entry
    finally:
        database.close()


# --- round-2 regressions: verified outcome reporting (P2) ----------------------------------------


def test_a_stage_unlink_failure_after_the_link_is_verified_and_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a failure AFTER the candidate name exists is never reported at face value: the move
    # verifies the durable name appeared, adopts it, and completes
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_unlink = os.unlink
    plant: list[bool] = [True]

    def _failing_unlink(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if plant and target == reconcile_module._QUARANTINE_STAGE:
            plant.clear()
            raise OSError(5, "planted stage unlink failure")
        return real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _failing_unlink)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1  # verified: the copy landed, the move completed
        assert not path.exists()
        quarantine_day = spool_root / "quarantine" / _DAY
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
        second = reconciler.reconcile()  # nothing further to converge
        assert second.quarantined == ()
        assert second.anomalies == ()
    finally:
        database.close()


# --- copy-machinery failure branches -------------------------------------------------------------


def test_directory_validation_helpers_fail_safe(tmp_path: Path) -> None:
    loose = tmp_path / "loose"
    loose.mkdir(mode=0o755)
    os.chmod(loose, 0o755)
    descriptor = os.open(loose, os.O_RDONLY)
    try:
        assert reconcile_module._validated_dir_descriptor(descriptor) is None  # wrong mode
    finally:
        os.close(descriptor)
    parent = os.open(tmp_path, os.O_RDONLY)
    try:
        assert reconcile_module._ensure_private_dir_at(parent, "loose") is None  # refused child
        accepted = reconcile_module._ensure_private_dir_at(parent, "fresh")
        assert accepted is not None  # created, parent-fsynced, validated, opened
        child_fd, identity = accepted
        os.close(child_fd)
        assert identity.inode == os.stat(tmp_path / "fresh").st_ino
    finally:
        os.close(parent)


def test_the_exact_reader_refuses_shrinkage_growth_and_unreadable_descriptors(
    tmp_path: Path,
) -> None:
    subject = tmp_path / "subject"
    subject.write_bytes(b"12345678")
    descriptor = os.open(subject, os.O_RDONLY)
    try:
        assert reconcile_module._read_descriptor(descriptor, 8) == b"12345678"
    finally:
        os.close(descriptor)
    descriptor = os.open(subject, os.O_RDONLY)
    try:
        assert reconcile_module._read_descriptor(descriptor, 16) is None  # shrank vs classified
    finally:
        os.close(descriptor)
    descriptor = os.open(subject, os.O_RDONLY)
    try:
        assert reconcile_module._read_descriptor(descriptor, 4) is None  # grew vs classified
    finally:
        os.close(descriptor)
    directory_fd = os.open(tmp_path, os.O_RDONLY)
    try:
        assert reconcile_module._read_descriptor(directory_fd, 4) is None  # unreadable subject
    finally:
        os.close(directory_fd)


def test_raw_hash_refuses_growth_past_the_bound_mid_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the in-loop bound fires when a file grows between its fstat and the read
    big = tmp_path / "big"
    big.write_bytes(b"x" * 32)
    real_fstat = os.fstat

    def _lying_fstat(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        return os.stat_result(
            (
                info.st_mode,
                info.st_ino,
                info.st_dev,
                info.st_nlink,
                info.st_uid,
                info.st_gid,
                4,
                0,
                0,
                0,
            )
        )

    monkeypatch.setattr(reconcile_module, "MAX_SEGMENT_FILE_BYTES", 8)
    monkeypatch.setattr(os, "fstat", _lying_fstat)
    assert reconcile_module._raw_sha256(big) is None


def test_a_source_that_vanishes_before_the_move_blocks_as_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_ensure = reconcile_module._ensure_private_dir_at
    removed: list[bool] = []

    def _removing_ensure(parent_fd, name):  # type: ignore[no-untyped-def]
        if not removed:
            removed.append(True)
            os.unlink(path)
        return real_ensure(parent_fd, name)

    monkeypatch.setattr(reconcile_module, "_ensure_private_dir_at", _removing_ensure)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
    finally:
        database.close()


def test_a_read_race_that_defeats_the_snapshot_is_caught_by_the_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # even bytes the snapshot cannot distinguish are refused: the digest binds the exact content
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_read = reconcile_module._read_descriptor
    calls: list[int] = []

    def _tampering_read(descriptor: int, size: int):  # type: ignore[no-untyped-def]
        calls.append(descriptor)
        if len(calls) == 2:  # the move's verification read (classification was the first)
            real_read(descriptor, size)
            return b"tampd\n"[:size]
        return real_read(descriptor, size)

    monkeypatch.setattr(reconcile_module, "_read_descriptor", _tampering_read)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        assert path.exists()
    finally:
        database.close()


def test_a_mutation_during_the_verification_read_is_caught_by_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the post-read snapshot re-check: bytes read BEFORE an in-place mutation hash correctly,
    # but the ctime backstop refuses to certify a file that changed underneath the read
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_read = reconcile_module._read_descriptor
    calls: list[int] = []

    def _racing_read(descriptor: int, size: int):  # type: ignore[no-untyped-def]
        calls.append(descriptor)
        content = real_read(descriptor, size)
        if len(calls) == 2:  # mutate in place AFTER the move's read returned the real bytes
            with path.open("r+b") as handle:
                handle.write(b"JUNK\n")
        return content

    monkeypatch.setattr(reconcile_module, "_read_descriptor", _racing_read)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        assert path.read_bytes() == b"JUNK\n"  # never unlinked
    finally:
        database.close()


def test_a_source_removed_after_the_copy_is_a_completed_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_link = os.link
    removed: list[bool] = []

    def _removing_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):  # type: ignore[no-untyped-def]
        outcome = real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks
        )
        if not removed:
            removed.append(True)
            os.unlink(path)  # the source name vanishes after the copy is published
        return outcome

    monkeypatch.setattr(os, "link", _removing_link)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1  # the classified bytes ARE durably quarantined
        assert (spool_root / "quarantine" / _DAY / "batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_symlink_squatting_a_candidate_name_is_never_followed_or_replaced(
    tmp_path: Path,
) -> None:
    # a symlink is decisively NOT our copy: it advances the counter without ever being
    # followed or replaced, and the move completes at the next candidate
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside\n")
    os.symlink(outside, quarantine_day / "batch-1.jsonl")
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert not path.exists()
        assert (quarantine_day / "1.batch-1.jsonl").read_bytes() == b"junk\n"
        assert outside.read_bytes() == b"outside\n"  # the squatting symlink was never followed
        assert os.path.islink(quarantine_day / "batch-1.jsonl")  # and never replaced
    finally:
        database.close()


def test_a_fifo_squatting_a_candidate_name_advances_the_counter(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    os.mkfifo(quarantine_day / "batch-1.jsonl", 0o600)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert not path.exists()
        assert (quarantine_day / "1.batch-1.jsonl").read_bytes() == b"junk\n"
        assert stat.S_ISFIFO(os.lstat(quarantine_day / "batch-1.jsonl").st_mode)  # untouched
    finally:
        database.close()


def test_an_unexaminable_candidate_occupant_reports_uncertain_and_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # an occupant that can be neither adopted nor ruled out COULD be our own earlier
    # interrupted copy: a clean blocked code would overclaim, so the ambiguity is reported
    # honestly and the next scan converges once the occupant can be examined
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    (quarantine_day / "batch-1.jsonl").write_bytes(b"junk\n")  # in fact our earlier copy
    os.chmod(quarantine_day / "batch-1.jsonl", 0o600)
    real_read = reconcile_module._read_descriptor
    calls: list[int] = []

    def _failing_adopt_read(descriptor: int, size: int):  # type: ignore[no-untyped-def]
        calls.append(descriptor)
        if len(calls) == 3:  # classification, move source read, then the adoption probe
            return None
        return real_read(descriptor, size)

    monkeypatch.setattr(reconcile_module, "_read_descriptor", _failing_adopt_read)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"  # the source is untouched
        second = reconciler.reconcile()  # examinable now: adopted, source unlinked, no alias
        assert len(second.quarantined) == 1
        assert not path.exists()
        assert sorted(e.name for e in quarantine_day.iterdir()) == ["batch-1.jsonl"]
    finally:
        database.close()


def test_stage_debris_from_an_earlier_crash_is_cleared_and_the_move_completes(
    tmp_path: Path,
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    debris = quarantine_day / reconcile_module._QUARANTINE_STAGE
    debris.write_bytes(b"half-written crash artifact")
    os.chmod(debris, 0o600)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert not path.exists()
        assert sorted(e.name for e in quarantine_day.iterdir()) == ["batch-1.jsonl"]
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_short_stage_write_blocks_verifiably_and_the_retry_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_write = os.write
    plant: list[bool] = [True]

    def _short_write(fd: int, data: bytes) -> int:
        if plant and data == b"junk\n":
            plant.clear()
            return real_write(fd, data[:-1])
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", _short_write)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"
        quarantine_day = spool_root / "quarantine" / _DAY
        assert [e.name for e in quarantine_day.iterdir() if not e.name.startswith(".")] == []
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert sorted(e.name for e in quarantine_day.iterdir()) == ["batch-1.jsonl"]
    finally:
        database.close()


def test_a_conflict_keeper_skips_copies_on_foreign_days(tmp_path: Path) -> None:
    # a duplicate whose day SORTS BEFORE the ledger's own day still never becomes the keeper:
    # only the ledger-designated day's agreeing copy is kept
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(batch_id="batch-1")
        store.commit_segment(header, frames, committed_at=_NOW)  # ledger day = 2026-07-24
        early_header, early_frames = _segment(batch_id="batch-1", events=("early-1", "early-2"))
        _publish_orphan(
            spool_root,
            "2026-07-23",
            "batch-1.jsonl",
            build_segment_bytes(early_header, early_frames),
        )
        report = reconciler.reconcile()
        assert report.healthy == 1  # the ledger's own-day copy is kept
        assert report.quarantined == (
            QuarantinedFile("batch-1", "2026-07-23", "conflict_divergent"),
        )
        assert (spool_root / "pending" / _DAY / "batch-1.jsonl").exists()
    finally:
        database.close()


def test_the_cap_stops_the_conflict_loop_between_batches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the candidate phase emits four conflict anomalies (within the budget of five); batch-1's
    # unsafe copies then exhaust the budget INSIDE the resolution loop, so batch-2's resolution
    # never starts and the capped pass moves nothing
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    monkeypatch.setattr(reconcile_module, "_MAX_ANOMALIES", 5)
    try:
        for batch in ("batch-1", "batch-2"):
            for day in ("2026-07-23", "2026-07-24"):
                path = _publish_orphan(
                    spool_root, day, f"{batch}.jsonl", f"{batch}-{day}\n".encode()
                )
                if batch == "batch-1":
                    os.chmod(path, 0o644)  # unsafe leaf shape: queueing it costs an anomaly
        report = reconciler.reconcile()
        assert not report.complete  # the cap voided the pass
        assert report.quarantined == ()  # and an incomplete pass moves nothing
        for batch in ("batch-1", "batch-2"):
            for day in ("2026-07-23", "2026-07-24"):
                assert (spool_root / "pending" / day / f"{batch}.jsonl").exists()
    finally:
        database.close()


def test_an_anomaly_after_the_limit_marker_is_dropped_silently(tmp_path: Path) -> None:
    database, _store, spool_root, _reconciler_unused = _reconciler(tmp_path)
    try:
        scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
        for index in range(reconcile_module._MAX_ANOMALIES + 5):
            scan._anomaly("batch-1", _DAY, "conflict", f"n{index}")
        assert len(scan._anomalies) == reconcile_module._MAX_ANOMALIES + 1  # + the limit marker
        assert scan._anomalies[-1] == SegmentAnomaly("", "", "limit", "anomaly_limit")
    finally:
        database.close()


def test_a_conflict_whose_ledger_day_copy_is_missing_keeps_nothing(tmp_path: Path) -> None:
    # the keeper scan exhausts without an own-day copy: no keeper, every copy quarantines
    database, store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        header, frames = _segment(batch_id="batch-1")
        store.commit_segment(header, frames, committed_at=_NOW)  # ledger day = 2026-07-24
        os.unlink(spool_root / "pending" / _DAY / "batch-1.jsonl")  # the own-day file vanishes
        for day in ("2026-07-23", "2026-07-25"):
            _publish_orphan(spool_root, day, "batch-1.jsonl", f"copy-{day}\n".encode())
        report = reconciler.reconcile()
        assert report.healthy == 0  # nothing agreed, nothing kept
        assert len(report.quarantined) == 2  # both foreign-day copies quarantined
        # the batch is seen (its conflicted copies exist), so no missing-file claim is made;
        # the NEXT scan, with the conflicts cleared, reports the ledger row's file missing
        second = reconciler.reconcile()
        assert SegmentAnomaly("batch-1", _DAY, "missing_file", "absent") in second.anomalies
    finally:
        database.close()


def test_a_day_directory_swap_during_classification_refuses_the_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, _reconciler_unused = _reconciler(tmp_path)
    try:
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
        scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
        day_dir = spool_root / "pending" / _DAY
        stale_identity = reconcile_module.FileIdentity.from_stat(os.stat(day_dir))
        os.rename(day_dir, spool_root / "pending" / "displaced")
        replacement = spool_root / "pending" / _DAY
        replacement.mkdir(mode=0o700)
        os.chmod(replacement, 0o700)
        (replacement / "batch-1.jsonl").write_bytes(b"impostor")
        assert scan._inspect_leaf(_DAY, "batch-1.jsonl", stale_identity) is None
    finally:
        database.close()


def test_an_oversize_subject_is_refused_at_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"x" * 64)
    monkeypatch.setattr(reconcile_module, "MAX_SEGMENT_FILE_BYTES", 8)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "unsafe") in report.anomalies
        assert path.exists()  # bounded work: never read, never moved
    finally:
        database.close()


def test_an_oversize_quarantine_candidate_is_rejected_before_its_bytes_are_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, _reconciler_unused = _reconciler(tmp_path)
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(quarantine_day.parent, 0o700)
    os.chmod(quarantine_day, 0o700)
    candidate = quarantine_day / "candidate"
    candidate.write_bytes(b"x" * 9)
    os.chmod(candidate, 0o600)
    target_fd = os.open(quarantine_day, os.O_RDONLY)
    reads: list[int] = []
    real_read = reconcile_module._read_descriptor

    def _recording_read(descriptor: int, size: int) -> bytes | None:
        reads.append(size)
        return real_read(descriptor, size)

    monkeypatch.setattr(reconcile_module, "MAX_SEGMENT_FILE_BYTES", 8)
    monkeypatch.setattr(reconcile_module, "_read_descriptor", _recording_read)
    try:
        scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
        digest = hashlib.sha256(b"x" * 9).hexdigest()
        assert scan._certify_target(target_fd, "candidate", digest) is None
        assert reads == []
    finally:
        os.close(target_fd)
        database.close()


def test_an_empty_subject_is_quarantined_as_an_empty_copy(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        day_dir = pending / _DAY
        day_dir.mkdir(mode=0o700)
        os.chmod(day_dir, 0o700)
        stage = day_dir / ".milhouse-stage-empty"
        stage.touch(mode=0o600)  # a crashed writer that never wrote a byte
        os.chmod(stage, 0o600)
        report = reconciler.reconcile()
        assert QuarantinedFile("", _DAY, "stale_temp") in report.quarantined
        assert not stage.exists()
        target = spool_root / "quarantine" / _DAY / ".milhouse-stage-empty"
        assert target.read_bytes() == b""
    finally:
        database.close()


def test_an_unreadable_subject_at_classification_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    monkeypatch.setattr(reconcile_module, "_read_descriptor", lambda _fd, _size: None)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "unsafe") in report.anomalies
        assert path.exists()
    finally:
        database.close()


def test_a_stage_open_failure_blocks_verifiably_and_the_retry_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_open = os.open
    plant: list[bool] = [True]

    def _failing_open(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if plant and target == reconcile_module._QUARANTINE_STAGE:
            plant.clear()
            raise PermissionError(13, "planted stage open failure")
        return real_open(target, *args, **kwargs)

    monkeypatch.setattr(os, "open", _failing_open)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert not path.exists()
    finally:
        database.close()


def test_a_subject_named_like_the_stage_is_never_published_at_the_stage_name(
    tmp_path: Path,
) -> None:
    # the verification workflow's break: a pending subject named EXACTLY like the fixed staging
    # name would have its copy published at a name the design defines as clearable debris — the
    # next publish into that day would destroy the only copy behind a verified "quarantined"
    # claim; such a subject must land at a counter-prefixed candidate instead
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    try:
        pending = spool_root / "pending"
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
        day_dir = pending / _DAY
        day_dir.mkdir(mode=0o700)
        os.chmod(day_dir, 0o700)
        hostile = day_dir / reconcile_module._QUARANTINE_STAGE  # a stale-temp-shaped plant
        hostile.write_bytes(b"bytes that must survive")
        os.chmod(hostile, 0o600)
        _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")  # a second same-day subject

        report = reconciler.reconcile()

        assert len(report.quarantined) == 2  # both subjects quarantined in ONE pass
        quarantine_day = spool_root / "quarantine" / _DAY
        survivor = quarantine_day / f"1.{reconcile_module._QUARANTINE_STAGE}"
        assert survivor.read_bytes() == b"bytes that must survive"  # never at the stage name
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
        # the copy survives ANY further activity in this day, including more publishes
        _publish_orphan(spool_root, _DAY, "batch-2.jsonl", b"more junk\n")
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert survivor.read_bytes() == b"bytes that must survive"
        assert (quarantine_day / "batch-2.jsonl").read_bytes() == b"more junk\n"
    finally:
        database.close()


def test_the_copy_data_is_fsynced_before_the_publish_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the honesty audit showed no test pinned the stage-file DATA fsync: dropping it would let
    # a power loss leave a durable candidate NAME whose bytes never reached the disk
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    log: list[tuple[str, str]] = []
    real_fsync, real_link, real_replace = os.fsync, os.link, os.replace

    def _kind(fd: int) -> str:
        return "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"

    def _logging_fsync(fd: int) -> None:
        log.append(("fsync", _kind(fd)))
        real_fsync(fd)

    def _logging_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):  # type: ignore[no-untyped-def]
        log.append(("link", ""))
        return real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks
        )

    def _logging_replace(src, dst, *args, **kwargs):  # type: ignore[no-untyped-def]
        if src == "batch-1.jsonl" and str(dst).startswith(reconcile_module._RETIRE_PREFIX):
            log.append(("retire", "source"))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "fsync", _logging_fsync)
    monkeypatch.setattr(os, "link", _logging_link)
    monkeypatch.setattr(os, "replace", _logging_replace)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        link_at = log.index(("link", ""))
        # The copy's bytes are durable before its name is published, and both precede retirement.
        assert ("fsync", "file") in log[:link_at]
        assert log.index(("retire", "source")) > link_at
    finally:
        database.close()


def test_an_adopted_copy_is_file_fsynced_before_the_source_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    (quarantine_day / "batch-1.jsonl").write_bytes(b"junk\n")  # an earlier interrupted copy
    os.chmod(quarantine_day / "batch-1.jsonl", 0o600)
    log: list[tuple[str, str]] = []
    real_fsync, real_replace = os.fsync, os.replace

    def _kind(fd: int) -> str:
        return "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"

    def _logging_fsync(fd: int) -> None:
        log.append(("fsync", _kind(fd)))
        real_fsync(fd)

    def _logging_replace(src, dst, *args, **kwargs):  # type: ignore[no-untyped-def]
        if src == "batch-1.jsonl" and str(dst).startswith(reconcile_module._RETIRE_PREFIX):
            log.append(("retire", "source"))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "fsync", _logging_fsync)
    monkeypatch.setattr(os, "replace", _logging_replace)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert not path.exists()
        unlink_at = log.index(("retire", "source"))
        # the adopted candidate's DATA was re-proven durable before the source was removed
        assert ("fsync", "file") in log[:unlink_at]
    finally:
        database.close()


def test_a_permission_denied_candidate_occupant_reports_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    (quarantine_day / "batch-1.jsonl").write_bytes(b"junk\n")
    os.chmod(quarantine_day / "batch-1.jsonl", 0o600)
    real_open = os.open
    opens: list[str] = []

    def _blocked_second_open(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if target == "batch-1.jsonl" and kwargs.get("dir_fd") is not None:
            opens.append(target)
            # trusted-read leaf open, classification, move source open, then the adoption probe
            if len(opens) == 4:
                raise PermissionError(13, "planted open failure")
        return real_open(target, *args, **kwargs)

    monkeypatch.setattr(os, "open", _blocked_second_open)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"
    finally:
        database.close()


# --- round-3 regressions: quarantine namespace binding (P1) --------------------------------------


def test_a_day_directory_displaced_after_validation_blocks_the_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the round-3 reproduction: rename the quarantine day OUTSIDE the spool root immediately
    # after the target descriptor opened, replacing the pathname with another owned 0700 dir —
    # publication must refuse, the source must keep its name, and NOTHING may be written
    # through the displaced descriptor
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    displaced = tmp_path / "displaced-day"
    real_read = reconcile_module._read_descriptor
    calls: list[int] = []

    def _swapping_read(descriptor: int, size: int):  # type: ignore[no-untyped-def]
        calls.append(descriptor)
        if len(calls) == 2:  # the move's source read: the chain is validated and held open
            quarantine_day = spool_root / "quarantine" / _DAY
            os.rename(quarantine_day, displaced)
            replacement = spool_root / "quarantine" / _DAY
            replacement.mkdir(mode=0o700)
            os.chmod(replacement, 0o700)
        return real_read(descriptor, size)

    monkeypatch.setattr(reconcile_module, "_read_descriptor", _swapping_read)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        assert path.read_bytes() == b"junk\n"  # the source keeps its name
        assert list(displaced.iterdir()) == []  # nothing written through the displaced fd
        assert list((spool_root / "quarantine" / _DAY).iterdir()) == []
    finally:
        database.close()


def test_a_quarantine_root_swap_after_validation_blocks_the_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    displaced_root = tmp_path / "displaced-root"
    real_read = reconcile_module._read_descriptor
    calls: list[int] = []

    def _swapping_read(descriptor: int, size: int):  # type: ignore[no-untyped-def]
        calls.append(descriptor)
        if len(calls) == 2:
            os.rename(spool_root / "quarantine", displaced_root)
            replacement = spool_root / "quarantine"
            replacement.mkdir(mode=0o700)
            os.chmod(replacement, 0o700)
        return real_read(descriptor, size)

    monkeypatch.setattr(reconcile_module, "_read_descriptor", _swapping_read)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        assert path.read_bytes() == b"junk\n"
        assert list((displaced_root / _DAY).iterdir()) == []
    finally:
        database.close()


def test_a_day_directory_displaced_after_publication_never_unlinks_the_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a swap landing AFTER the copy published: the copy's namespace binding can no longer be
    # proven, so the source is never unlinked and the outcome is reported uncertain
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    displaced = tmp_path / "displaced-day"
    real_link = os.link
    swapped: list[bool] = []

    def _swapping_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):  # type: ignore[no-untyped-def]
        outcome = real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks
        )
        if not swapped:
            swapped.append(True)
            quarantine_day = spool_root / "quarantine" / _DAY
            os.rename(quarantine_day, displaced)
            replacement = spool_root / "quarantine" / _DAY
            replacement.mkdir(mode=0o700)
            os.chmod(replacement, 0o700)
        return outcome

    monkeypatch.setattr(os, "link", _swapping_link)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()  # never reported successful
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"  # the source is NEVER unlinked
    finally:
        database.close()


def test_a_certified_target_mutated_before_the_unlink_refuses_the_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the certified copy's identity is re-proven immediately before the source unlink
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_binding = reconcile_module._Scan._quarantine_binding_holds
    calls: list[int] = []

    def _mutating_binding(self, day, identities):  # type: ignore[no-untyped-def]
        outcome = real_binding(self, day, identities)
        calls.append(1)
        if len(calls) == 2:  # the pre-unlink re-proof: mutate the certified copy first
            target = spool_root / "quarantine" / _DAY / "batch-1.jsonl"
            with target.open("r+b") as handle:
                handle.write(b"JUNK\n")
        return outcome

    monkeypatch.setattr(reconcile_module._Scan, "_quarantine_binding_holds", _mutating_binding)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"  # the source keeps its name
    finally:
        database.close()


# --- round-3 regressions: adoption envelope (P1) -------------------------------------------------


def test_a_same_digest_foreign_hard_link_is_never_adopted(tmp_path: Path) -> None:
    # the round-3 reproduction: a pre-placed hard link to an OUTSIDE file with the same bytes
    # must never be adopted — the "copy" would stay mutable through the foreign alias while the
    # source is deleted; it is a collision, and the real copy lands on a severed inode
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    outside = tmp_path / "outside-alias"
    outside.write_bytes(b"junk\n")  # identical bytes: the digest alone would match
    os.chmod(outside, 0o600)
    os.link(outside, quarantine_day / "batch-1.jsonl")  # nlink == 2, foreign alias retained
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert not path.exists()  # the source moved — but only after a certified severed copy
        severed = quarantine_day / "1.batch-1.jsonl"
        assert severed.read_bytes() == b"junk\n"
        assert os.lstat(severed).st_nlink == 1  # the real copy is on its own inode
        # the foreign alias can still mutate ITS file, but the certified copy is unreachable
        with outside.open("r+b") as handle:
            handle.write(b"HACK\n")
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"HACK\n"  # the foreign link
        assert severed.read_bytes() == b"junk\n"  # the certified quarantine copy is immutable
    finally:
        database.close()


def test_a_loose_mode_same_digest_candidate_is_never_adopted(tmp_path: Path) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    loose = quarantine_day / "batch-1.jsonl"
    loose.write_bytes(b"junk\n")
    os.chmod(loose, 0o644)  # same digest, loose mode: outside the envelope
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert not path.exists()
        assert (quarantine_day / "1.batch-1.jsonl").read_bytes() == b"junk\n"
        assert stat.S_IMODE(os.lstat(loose).st_mode) == 0o644  # untouched, never adopted
    finally:
        database.close()


def test_an_acl_bearing_same_digest_candidate_is_never_adopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    marked = quarantine_day / "batch-1.jsonl"
    marked.write_bytes(b"junk\n")
    os.chmod(marked, 0o600)
    marked_inode = os.lstat(marked).st_ino
    real_check = reconcile_module.require_no_extended_acl

    def _acl_on_the_candidate(descriptor: int) -> None:
        if os.fstat(descriptor).st_ino == marked_inode:
            raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)
        real_check(descriptor)

    monkeypatch.setattr(reconcile_module, "require_no_extended_acl", _acl_on_the_candidate)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        assert not path.exists()
        assert (quarantine_day / "1.batch-1.jsonl").read_bytes() == b"junk\n"
        assert marked.read_bytes() == b"junk\n"  # the ACL bearer is refused, never adopted
    finally:
        database.close()


def test_a_candidate_mutated_during_adoption_is_never_certified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    candidate = quarantine_day / "batch-1.jsonl"
    candidate.write_bytes(b"junk\n")
    os.chmod(candidate, 0o600)
    real_read = reconcile_module._read_descriptor
    calls: list[int] = []

    def _racing_read(descriptor: int, size: int):  # type: ignore[no-untyped-def]
        calls.append(descriptor)
        content = real_read(descriptor, size)
        if len(calls) == 3:  # the adoption read: mutate AFTER the bytes were read
            with candidate.open("r+b") as handle:
                handle.write(b"JUNK\n")
        return content

    monkeypatch.setattr(reconcile_module, "_read_descriptor", _racing_read)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"  # the source is never unlinked
    finally:
        database.close()


def test_chain_and_binding_helpers_fail_safe(tmp_path: Path) -> None:
    database, _store, spool_root, _reconciler_unused = _reconciler(tmp_path)
    try:
        stale_fd = os.open(tmp_path, os.O_RDONLY)
        os.close(stale_fd)
        assert not reconcile_module._fsync_descriptor(stale_fd)  # stale descriptor: not trusted
        assert reconcile_module._validated_dir_descriptor(stale_fd) is None
        scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
        # a loose spool root refuses the whole chain
        os.chmod(spool_root, 0o755)
        assert scan._open_quarantine_chain(_DAY) is None
        os.chmod(spool_root, 0o700)
        # a vanished spool root refuses the chain
        vanished = reconcile_module._Scan(database, tmp_path / "absent", _INSTALLATION_ID)
        assert vanished._open_quarantine_chain(_DAY) is None
        # the binding refuses a root identity mismatch and a missing quarantine dir
        fake = reconcile_module.FileIdentity(device=1, inode=2)
        real_root = reconcile_module.FileIdentity.from_stat(os.stat(spool_root))
        assert not scan._quarantine_binding_holds(_DAY, (fake, fake, fake))
        assert not scan._quarantine_binding_holds(_DAY, (real_root, fake, fake))
    finally:
        database.close()


def test_an_uncertifiable_fresh_copy_reports_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # even a copy we just created is never trusted without certification: an ACL appearing on
    # it (or any envelope failure) refuses the success claim and the source unlink
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    target = spool_root / "quarantine" / _DAY / "batch-1.jsonl"
    real_check = reconcile_module.require_no_extended_acl

    def _acl_on_the_target(descriptor: int) -> None:
        if target.exists() and os.fstat(descriptor).st_ino == os.lstat(target).st_ino:
            raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)
        real_check(descriptor)

    monkeypatch.setattr(reconcile_module, "require_no_extended_acl", _acl_on_the_target)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"  # the source keeps its name
    finally:
        database.close()


def test_a_target_vanishing_before_the_unlink_reports_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_binding = reconcile_module._Scan._quarantine_binding_holds
    calls: list[int] = []

    def _removing_binding(self, day, identities):  # type: ignore[no-untyped-def]
        outcome = real_binding(self, day, identities)
        calls.append(1)
        if len(calls) == 2:  # before the pre-unlink certification: the copy vanishes
            os.unlink(spool_root / "quarantine" / _DAY / "batch-1.jsonl")
        return outcome

    monkeypatch.setattr(reconcile_module._Scan, "_quarantine_binding_holds", _removing_binding)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_candidate_mutated_while_being_made_durable_is_never_adopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the adoption re-checks the snapshot AFTER its fsyncs: a mutation landing between the
    # durability proof and the certification is refused
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "quarantine", 0o700)
    os.chmod(quarantine_day, 0o700)
    candidate = quarantine_day / "batch-1.jsonl"
    candidate.write_bytes(b"junk\n")
    os.chmod(candidate, 0o600)
    candidate_inode = os.lstat(candidate).st_ino
    real_fsync = os.fsync
    fired: list[bool] = []

    def _mutating_fsync(fd: int) -> None:
        real_fsync(fd)
        info = os.fstat(fd)
        if not fired and stat.S_ISREG(info.st_mode) and info.st_ino == candidate_inode:
            fired.append(True)
            with candidate.open("r+b") as handle:  # mutate right after the durability proof
                handle.write(b"JUNK\n")

    monkeypatch.setattr(os, "fsync", _mutating_fsync)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"
    finally:
        database.close()


# --- round-4 regressions: mutation-time live namespace and envelope proof ------------------------


@pytest.mark.parametrize("swap_level", ["day", "root"])
def test_target_displaced_during_final_certification_never_authorizes_source_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_level: str
) -> None:
    """The final target proof must be followed by a fresh secure live-chain proof."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_root = spool_root / "quarantine"
    quarantine_day = quarantine_root / _DAY
    displaced = tmp_path / f"displaced-target-{swap_level}"
    real_certify = reconcile_module._Scan._certify_target
    calls: list[int] = []

    def _displacing_certify(self, target_fd, candidate, digest):  # type: ignore[no-untyped-def]
        certified = real_certify(self, target_fd, candidate, digest)
        calls.append(1)
        if len(calls) == 2:
            if swap_level == "day":
                os.rename(quarantine_day, displaced)
                quarantine_day.mkdir(mode=0o700)
                os.chmod(quarantine_day, 0o700)
            else:
                os.rename(quarantine_root, displaced)
                quarantine_day.mkdir(mode=0o700, parents=True)
                os.chmod(quarantine_root, 0o700)
                os.chmod(quarantine_day, 0o700)
        return certified

    monkeypatch.setattr(reconcile_module._Scan, "_certify_target", _displacing_certify)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert source.read_bytes() == b"junk\n"
        displaced_target = (
            displaced / "batch-1.jsonl"
            if swap_level == "day"
            else displaced / _DAY / "batch-1.jsonl"
        )
        assert not displaced_target.exists()  # this pass's escaped copy was proven and removed
        assert list(quarantine_day.iterdir()) == []
        if swap_level == "day":
            quarantine_day.rmdir()
            os.rename(displaced, quarantine_day)
        else:
            quarantine_day.rmdir()
            quarantine_root.rmdir()
            os.rename(displaced, quarantine_root)
        retry = reconciler.reconcile()
        assert len(retry.quarantined) == 1
        assert not source.exists()
    finally:
        database.close()


@pytest.mark.parametrize("swap_level", ["day", "root"])
def test_pending_chain_displaced_after_source_open_never_unlinks_outside_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_level: str
) -> None:
    """A held pending descriptor is not unlink authority after its live chain moves."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_root = spool_root / "pending"
    pending_day = pending_root / _DAY
    displaced = tmp_path / f"displaced-pending-{swap_level}"
    real_read = reconcile_module._read_descriptor
    calls: list[int] = []

    def _displacing_read(descriptor: int, size: int):  # type: ignore[no-untyped-def]
        content = real_read(descriptor, size)
        calls.append(descriptor)
        if len(calls) == 2:
            if swap_level == "day":
                os.rename(pending_day, displaced)
                pending_day.mkdir(mode=0o700)
                os.chmod(pending_day, 0o700)
            else:
                os.rename(pending_root, displaced)
                pending_day.mkdir(mode=0o700, parents=True)
                os.chmod(pending_root, 0o700)
                os.chmod(pending_day, 0o700)
        return content

    monkeypatch.setattr(reconcile_module, "_read_descriptor", _displacing_read)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        displaced_source = (
            displaced / "batch-1.jsonl"
            if swap_level == "day"
            else displaced / _DAY / "batch-1.jsonl"
        )
        assert displaced_source.read_bytes() == b"junk\n"
        assert not (pending_day / "batch-1.jsonl").exists()
        if swap_level == "day":
            pending_day.rmdir()
            os.rename(displaced, pending_day)
        else:
            pending_day.rmdir()
            pending_root.rmdir()
            os.rename(displaced, pending_root)
        retry = reconciler.reconcile()
        assert len(retry.quarantined) == 1
        assert not (spool_root / "pending" / _DAY / "batch-1.jsonl").exists()
        candidates = tuple((spool_root / "quarantine" / _DAY).glob("*batch-1.jsonl"))
        assert len(candidates) == 1
        assert candidates[0].read_bytes() == b"junk\n"
    finally:
        database.close()


def test_quarantine_directory_mode_drift_before_publication_never_reports_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The held target descriptor must retain the private 0700 envelope at publication."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    real_publish = reconcile_module._Scan._publish_copy
    changed: list[bool] = []

    def _loosening_publish(self, day, identities, candidate, content, digest):  # type: ignore[no-untyped-def]
        if not changed:
            changed.append(True)
            os.chmod(quarantine_day, 0o755)
        return real_publish(self, day, identities, candidate, content, digest)

    monkeypatch.setattr(reconcile_module._Scan, "_publish_copy", _loosening_publish)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert any(anomaly.kind.startswith("quarantine_") for anomaly in report.anomalies)
        assert source.read_bytes() == b"junk\n"
    finally:
        database.close()


@pytest.mark.parametrize("swap_level", ["day", "root"])
def test_pending_chain_displaced_after_publication_preserves_validated_recovery_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_level: str
) -> None:
    """A lost final source chain cannot discard the already durable quarantine copy."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_root = spool_root / "pending"
    pending_day = pending_root / _DAY
    quarantine_day = spool_root / "quarantine" / _DAY
    displaced = tmp_path / f"pending-after-publication-{swap_level}"
    real_publish = reconcile_module._Scan._publish_copy
    swapped: list[bool] = []

    def _displacing_publish(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_publish(self, *args, **kwargs)
        if not swapped and result[0] == "placed":
            swapped.append(True)
            if swap_level == "day":
                os.rename(pending_day, displaced)
                os.mkdir(pending_day, 0o700)
            else:
                os.rename(pending_root, displaced)
                os.mkdir(pending_root, 0o700)
                os.mkdir(pending_day, 0o700)
        return result

    monkeypatch.setattr(reconcile_module._Scan, "_publish_copy", _displacing_publish)
    try:
        report = reconciler.reconcile()
        assert swapped == [True]
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        displaced_source = (
            displaced / "batch-1.jsonl"
            if swap_level == "day"
            else displaced / _DAY / "batch-1.jsonl"
        )
        assert displaced_source.read_bytes() == b"junk\n"
        recovery_copy = quarantine_day / "batch-1.jsonl"
        assert recovery_copy.read_bytes() == b"junk\n"
        assert list(pending_day.iterdir()) == []

        if swap_level == "day":
            pending_day.rmdir()
            os.rename(displaced, pending_day)
        else:
            pending_day.rmdir()
            pending_root.rmdir()
            os.rename(displaced, pending_root)
        retry = reconciler.reconcile()
        assert len(retry.quarantined) == 1
        assert list(pending_day.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert [target.name for target in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
    finally:
        database.close()


@pytest.mark.parametrize("swap_level", ["day", "root"])
def test_pending_chain_displaced_during_final_source_validation_never_unlinks_outside_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_level: str
) -> None:
    """The final source-name check cannot authorize unlink through a newly stale descriptor."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_root = spool_root / "pending"
    pending_day = pending_root / _DAY
    pending_day_inode = os.lstat(pending_day).st_ino
    displaced = tmp_path / f"final-pending-{swap_level}"
    real_stat = os.stat
    swapped: list[bool] = []

    def _displacing_stat(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        dir_fd = kwargs.get("dir_fd")
        if (
            not swapped
            and target == "batch-1.jsonl"
            and dir_fd is not None
            and os.fstat(dir_fd).st_ino == pending_day_inode
        ):
            swapped.append(True)
            if swap_level == "day":
                os.rename(pending_day, displaced)
                os.mkdir(pending_day, 0o700)
            else:
                os.rename(pending_root, displaced)
                os.mkdir(pending_root, 0o700)
                os.mkdir(pending_day, 0o700)
        return real_stat(target, *args, **kwargs)

    monkeypatch.setattr(os, "stat", _displacing_stat)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        displaced_source = (
            displaced / "batch-1.jsonl"
            if swap_level == "day"
            else displaced / _DAY / "batch-1.jsonl"
        )
        assert displaced_source.read_bytes() == b"junk\n"
        recovery_copy = spool_root / "quarantine" / _DAY / "batch-1.jsonl"
        assert recovery_copy.read_bytes() == b"junk\n"
        if swap_level == "day":
            pending_day.rmdir()
            os.rename(displaced, pending_day)
        else:
            pending_day.rmdir()
            pending_root.rmdir()
            os.rename(displaced, pending_root)
        retry = reconciler.reconcile()
        assert len(retry.quarantined) == 1
        assert not (spool_root / "pending" / _DAY / "batch-1.jsonl").exists()
        candidates = tuple((spool_root / "quarantine" / _DAY).glob("*batch-1.jsonl"))
        assert len(candidates) == 1
        assert candidates[0].read_bytes() == b"junk\n"
    finally:
        database.close()


@pytest.mark.parametrize(
    ("namespace", "level"),
    [("quarantine", "root"), ("quarantine", "day"), ("pending", "root"), ("pending", "day")],
)
def test_live_binding_rejects_directory_mode_drift_at_every_namespace_level(
    tmp_path: Path, namespace: str, level: str
) -> None:
    database, _store, spool_root, _reconciler_unused = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
    quarantine_chain = scan._open_quarantine_chain(_DAY)
    assert quarantine_chain is not None
    quarantine_descriptors, quarantine_identities = quarantine_chain
    reconcile_module._close_descriptors(quarantine_descriptors)
    pending_day = spool_root / "pending" / _DAY
    pending_chain = scan._open_pending_chain(
        _DAY, reconcile_module.FileIdentity.from_stat(os.lstat(pending_day))
    )
    assert pending_chain is not None
    pending_descriptors, pending_identities = pending_chain
    reconcile_module._close_descriptors(pending_descriptors)
    target = spool_root / namespace / (_DAY if level == "day" else "")
    os.chmod(target, 0o755)
    try:
        if namespace == "quarantine":
            assert not scan._quarantine_binding_holds(_DAY, quarantine_identities)
        else:
            assert not scan._pending_binding_holds(_DAY, pending_identities)
    finally:
        database.close()


@pytest.mark.parametrize(
    ("namespace", "level"),
    [("quarantine", "root"), ("quarantine", "day"), ("pending", "root"), ("pending", "day")],
)
def test_live_binding_rejects_directory_acl_drift_at_every_namespace_level(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    namespace: str,
    level: str,
) -> None:
    database, _store, spool_root, _reconciler_unused = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
    quarantine_chain = scan._open_quarantine_chain(_DAY)
    assert quarantine_chain is not None
    quarantine_descriptors, quarantine_identities = quarantine_chain
    reconcile_module._close_descriptors(quarantine_descriptors)
    pending_day = spool_root / "pending" / _DAY
    pending_chain = scan._open_pending_chain(
        _DAY, reconcile_module.FileIdentity.from_stat(os.lstat(pending_day))
    )
    assert pending_chain is not None
    pending_descriptors, pending_identities = pending_chain
    reconcile_module._close_descriptors(pending_descriptors)
    target = spool_root / namespace / (_DAY if level == "day" else "")
    target_inode = os.lstat(target).st_ino
    real_acl_check = reconcile_module.require_no_extended_acl

    def _acl_drift(descriptor: int) -> None:
        if os.fstat(descriptor).st_ino == target_inode:
            raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)
        real_acl_check(descriptor)

    monkeypatch.setattr(reconcile_module, "require_no_extended_acl", _acl_drift)
    try:
        if namespace == "quarantine":
            assert not scan._quarantine_binding_holds(_DAY, quarantine_identities)
        else:
            assert not scan._pending_binding_holds(_DAY, pending_identities)
    finally:
        database.close()


def test_live_bindings_recheck_the_owner_predicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, _reconciler_unused = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    scan = reconcile_module._Scan(database, spool_root, _INSTALLATION_ID)
    quarantine_chain = scan._open_quarantine_chain(_DAY)
    assert quarantine_chain is not None
    quarantine_descriptors, quarantine_identities = quarantine_chain
    reconcile_module._close_descriptors(quarantine_descriptors)
    pending_day = spool_root / "pending" / _DAY
    pending_chain = scan._open_pending_chain(
        _DAY, reconcile_module.FileIdentity.from_stat(os.lstat(pending_day))
    )
    assert pending_chain is not None
    pending_descriptors, pending_identities = pending_chain
    reconcile_module._close_descriptors(pending_descriptors)
    actual_uid = reconcile_module._current_uid()
    monkeypatch.setattr(reconcile_module, "_current_uid", lambda: actual_uid + 1)
    try:
        assert not scan._quarantine_binding_holds(_DAY, quarantine_identities)
        assert not scan._pending_binding_holds(_DAY, pending_identities)
    finally:
        database.close()


def test_pending_root_swap_during_inventory_invalidates_the_whole_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One inventory may never combine day names from two pending namespaces."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    original = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_root = spool_root / "pending"
    displaced = tmp_path / "inventory-pending"
    real_names = reconcile_module._secure_names_from_descriptor
    calls: list[int] = []

    def _swapping_names(descriptor: int):
        result = real_names(descriptor)
        calls.append(descriptor)
        if len(calls) == 2:
            os.rename(pending_root, displaced)
            os.mkdir(pending_root, 0o700)
        return result

    monkeypatch.setattr(reconcile_module, "_secure_names_from_descriptor", _swapping_names)
    try:
        report = reconciler.reconcile()
        assert not report.complete
        assert report.registered == ()
        assert report.quarantined == ()
        assert SegmentAnomaly("", "", "foreign_name", "pending_changed") in report.anomalies
        assert not original.exists()
        assert (displaced / _DAY / "batch-1.jsonl").read_bytes() == b"junk\n"
        assert list(pending_root.iterdir()) == []
    finally:
        database.close()


def test_final_source_unlink_follows_pending_proof_and_final_target_certification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_inode = os.lstat(spool_root / "pending" / _DAY).st_ino
    events: list[str] = []
    real_certify = reconcile_module._Scan._certify_live_target
    real_target_binding = reconcile_module._Scan._quarantine_binding_holds
    real_source_binding = reconcile_module._Scan._pending_binding_holds
    real_unlink = os.unlink

    def _certify(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_certify(self, *args, **kwargs)
        events.append("certify-target")
        return result

    def _target_binding(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_target_binding(self, *args, **kwargs)
        events.append("bind-target")
        return result

    def _source_binding(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_source_binding(self, *args, **kwargs)
        events.append("bind-pending")
        return result

    def _unlink(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        dir_fd = kwargs.get("dir_fd")
        if (
            str(target).startswith(reconcile_module._RETIRE_PREFIX)
            and dir_fd is not None
            and os.fstat(dir_fd).st_ino == pending_inode
        ):
            events.append("unlink-retirement")
        return real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(reconcile_module._Scan, "_certify_live_target", _certify)
    monkeypatch.setattr(reconcile_module._Scan, "_quarantine_binding_holds", _target_binding)
    monkeypatch.setattr(reconcile_module._Scan, "_pending_binding_holds", _source_binding)
    monkeypatch.setattr(os, "unlink", _unlink)
    try:
        report = reconciler.reconcile()
        assert len(report.quarantined) == 1
        unlink_index = events.index("unlink-retirement")
        assert events[unlink_index - 3 : unlink_index] == [
            "certify-target",
            "bind-pending",
            "bind-target",
        ]
    finally:
        database.close()


@pytest.mark.parametrize("swap_level", ["day", "root"])
def test_publication_reopens_the_live_target_and_cleans_a_displaced_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_level: str
) -> None:
    """A held target descriptor is cleanup authority, never publication authority."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_root = spool_root / "quarantine"
    quarantine_day = quarantine_root / _DAY
    displaced = tmp_path / f"publish-displaced-{swap_level}"
    real_publish = reconcile_module._Scan._publish_copy
    swapped: list[bool] = []

    def _displacing_publish(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if not swapped:
            swapped.append(True)
            if swap_level == "day":
                os.rename(quarantine_day, displaced)
                os.mkdir(quarantine_day, 0o700)
            else:
                os.rename(quarantine_root, displaced)
                os.mkdir(quarantine_root, 0o700)
                os.mkdir(quarantine_day, 0o700)
        return real_publish(self, *args, **kwargs)

    monkeypatch.setattr(reconcile_module._Scan, "_publish_copy", _displacing_publish)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert source.read_bytes() == b"junk\n"
        escaped_day = displaced if swap_level == "day" else displaced / _DAY
        assert list(escaped_day.iterdir()) == []
        assert list(quarantine_day.iterdir()) == []
    finally:
        database.close()


def test_publication_certification_cleanup_preserves_a_same_digest_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cleanup authority is the published inode snapshot, never digest equality alone."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    displaced_copy = quarantine_day / "created-copy"
    candidate = quarantine_day / "batch-1.jsonl"
    real_certify = reconcile_module._Scan._certify_target
    fired: list[bool] = []

    def _replacing_certify(self, target_fd, target, digest):  # type: ignore[no-untyped-def]
        if not fired and target == "batch-1.jsonl":
            fired.append(True)
            os.rename(candidate, displaced_copy)
            candidate.write_bytes(b"junk\n")
            os.chmod(candidate, 0o600)
            return None
        return real_certify(self, target_fd, target, digest)

    monkeypatch.setattr(reconcile_module._Scan, "_certify_target", _replacing_certify)
    try:
        report = reconciler.reconcile()
        assert fired == [True]
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert source.read_bytes() == b"junk\n"
        assert candidate.read_bytes() == displaced_copy.read_bytes() == b"junk\n"
        assert os.stat(candidate).st_ino != os.stat(displaced_copy).st_ino
    finally:
        database.close()


def test_publication_routes_a_certified_same_digest_replacement_through_adoption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A replacement can be adopted safely, but never gains created-copy cleanup authority."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    displaced_copy = quarantine_day / "created-copy"
    candidate = quarantine_day / "batch-1.jsonl"
    real_certify = reconcile_module._Scan._certify_target
    fired: list[bool] = []

    def _replacing_certify(self, target_fd, target, digest):  # type: ignore[no-untyped-def]
        if not fired and target == "batch-1.jsonl":
            fired.append(True)
            os.rename(candidate, displaced_copy)
            candidate.write_bytes(b"junk\n")
            os.chmod(candidate, 0o600)
        return real_certify(self, target_fd, target, digest)

    monkeypatch.setattr(reconcile_module._Scan, "_certify_target", _replacing_certify)
    try:
        report = reconciler.reconcile()
        assert fired == [True]
        assert len(report.quarantined) == 1
        assert not source.exists()
        assert candidate.read_bytes() == displaced_copy.read_bytes() == b"junk\n"
        assert os.stat(candidate).st_ino != os.stat(displaced_copy).st_ino
    finally:
        database.close()


def test_publication_exception_cleanup_preserves_a_same_digest_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exception/finally cleanup paths carry the same exact-inode authority."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    displaced_day = tmp_path / "publication-exception-displaced"
    candidate = quarantine_day / "batch-1.jsonl"
    created_copy_name = "created-copy"
    real_fsync = os.fsync
    fired: list[bool] = []

    def _replacing_fsync(descriptor: int) -> None:
        info = os.fstat(descriptor)
        if (
            not fired
            and quarantine_day.exists()
            and os.lstat(quarantine_day).st_ino == info.st_ino
            and candidate.exists()
            and not (quarantine_day / reconcile_module._QUARANTINE_STAGE).exists()
        ):
            fired.append(True)
            os.rename(candidate, quarantine_day / created_copy_name)
            candidate.write_bytes(b"junk\n")
            os.chmod(candidate, 0o600)
            os.rename(quarantine_day, displaced_day)
            os.mkdir(quarantine_day, 0o700)
            raise OSError(5, "planted target-directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", _replacing_fsync)
    try:
        report = reconciler.reconcile()
        assert fired == [True]
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert source.read_bytes() == b"junk\n"
        replacement = displaced_day / "batch-1.jsonl"
        created_copy = displaced_day / created_copy_name
        assert replacement.read_bytes() == created_copy.read_bytes() == b"junk\n"
        assert os.stat(replacement).st_ino != os.stat(created_copy).st_ino
        assert list(quarantine_day.iterdir()) == []
    finally:
        database.close()


def test_target_displaced_by_the_last_pending_proof_never_authorizes_source_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The target proof which authorizes removal must follow every pending-chain callback."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    displaced = tmp_path / "target-displaced-by-pending-proof"
    real_pending_binding = reconcile_module._Scan._pending_binding_holds
    swapped: list[bool] = []

    def _displacing_pending_binding(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_pending_binding(self, *args, **kwargs)
        if not swapped and (quarantine_day / "batch-1.jsonl").exists():
            swapped.append(True)
            os.rename(quarantine_day, displaced)
            os.mkdir(quarantine_day, 0o700)
        return result

    monkeypatch.setattr(
        reconcile_module._Scan, "_pending_binding_holds", _displacing_pending_binding
    )
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert not source.exists()
        retirements = tuple(source.parent.glob(f"{reconcile_module._RETIRE_PREFIX}*"))
        assert len(retirements) == 1
        assert retirements[0].read_bytes() == b"junk\n"
        assert list(displaced.iterdir()) == []  # this pass created the escaped copy and cleaned it

        quarantine_day.rmdir()
        os.rename(displaced, quarantine_day)
        retry = reconciler.reconcile()
        assert len(retry.quarantined) == 1
        assert list(source.parent.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert [target.name for target in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
    finally:
        database.close()


@pytest.mark.parametrize("swap_level", ["day", "root"])
@pytest.mark.parametrize("certify_call", [2, 3], ids=["pre-retirement", "post-retirement"])
def test_pending_displaced_during_final_target_certification_is_never_unlinked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swap_level: str,
    certify_call: int,
) -> None:
    """Both target-certification phases are followed by a pending live-binding proof."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_root = spool_root / "pending"
    pending_day = pending_root / _DAY
    quarantine_day = spool_root / "quarantine" / _DAY
    displaced = tmp_path / f"pending-during-certify-{certify_call}-{swap_level}"
    real_certify = reconcile_module._Scan._certify_live_target
    calls: list[int] = []

    def _displacing_certify(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_certify(self, *args, **kwargs)
        calls.append(1)
        if len(calls) == certify_call:
            if swap_level == "day":
                os.rename(pending_day, displaced)
                os.mkdir(pending_day, 0o700)
            else:
                os.rename(pending_root, displaced)
                os.mkdir(pending_root, 0o700)
                os.mkdir(pending_day, 0o700)
        return result

    monkeypatch.setattr(reconcile_module._Scan, "_certify_live_target", _displacing_certify)
    try:
        report = reconciler.reconcile()
        assert len(calls) >= certify_call
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        displaced_day = displaced if swap_level == "day" else displaced / _DAY
        staged = tuple(displaced_day.iterdir())
        assert len(staged) == 1
        assert staged[0].read_bytes() == b"junk\n"
        if certify_call == 2:
            assert staged[0].name == "batch-1.jsonl"
        else:
            assert staged[0].name.startswith(reconcile_module._RETIRE_PREFIX)
        targets = tuple(quarantine_day.iterdir())
        assert [target.name for target in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
        assert list(pending_day.iterdir()) == []

        if swap_level == "day":
            pending_day.rmdir()
            os.rename(displaced, pending_day)
        else:
            pending_day.rmdir()
            pending_root.rmdir()
            os.rename(displaced, pending_root)
        retry = reconciler.reconcile()
        assert len(retry.quarantined) == 1
        assert list(pending_day.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert [target.name for target in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
    finally:
        database.close()


@pytest.mark.parametrize("certify_call", [2, 3], ids=["pre-retirement", "post-retirement"])
def test_a_final_quarantine_binding_failure_preserves_recoverable_source_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, certify_call: int
) -> None:
    """Each final target certification is followed by its own explicit live-binding decision."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = source.parent
    quarantine_day = spool_root / "quarantine" / _DAY
    real_certify = reconcile_module._Scan._certify_live_target
    real_binding = reconcile_module._Scan._quarantine_binding_holds
    calls: list[int] = []
    armed: list[bool] = []

    def _arming_certify(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_certify(self, *args, **kwargs)
        calls.append(1)
        if len(calls) == certify_call:
            armed.append(True)
        return result

    def _failing_binding(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if armed:
            armed.clear()
            return False
        return real_binding(self, *args, **kwargs)

    monkeypatch.setattr(reconcile_module._Scan, "_certify_live_target", _arming_certify)
    monkeypatch.setattr(reconcile_module._Scan, "_quarantine_binding_holds", _failing_binding)
    try:
        first = reconciler.reconcile()
        assert len(calls) >= certify_call
        assert first.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in first.anomalies
        staged = tuple(pending_day.iterdir())
        assert len(staged) == 1
        assert staged[0].read_bytes() == b"junk\n"
        if certify_call == 2:
            assert staged[0].name == "batch-1.jsonl"
        else:
            assert staged[0].name.startswith(reconcile_module._RETIRE_PREFIX)
        assert list(quarantine_day.iterdir()) == []

        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert list(pending_day.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert [entry.name for entry in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
    finally:
        database.close()


@pytest.mark.parametrize("namespace", ["pending", "quarantine"])
@pytest.mark.parametrize("swap_level", ["day", "root"])
def test_an_adjacent_unlink_namespace_swap_is_detected_as_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    namespace: str,
    swap_level: str,
) -> None:
    """The unavoidable same-UID syscall window never produces a false success claim."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_root = spool_root / "pending"
    pending_day = pending_root / _DAY
    quarantine_root = spool_root / "quarantine"
    quarantine_day = quarantine_root / _DAY
    live_root = pending_root if namespace == "pending" else quarantine_root
    live_day = pending_day if namespace == "pending" else quarantine_day
    displaced = tmp_path / f"adjacent-unlink-{namespace}-{swap_level}"
    real_unlink = os.unlink
    fired: list[bool] = []

    def _displacing_unlink(target, *, dir_fd=None):  # type: ignore[no-untyped-def]
        if not fired and str(target).startswith(reconcile_module._RETIRE_PREFIX):
            fired.append(True)
            if swap_level == "day":
                os.rename(live_day, displaced)
                os.mkdir(live_day, 0o700)
            else:
                os.rename(live_root, displaced)
                os.mkdir(live_root, 0o700)
                os.mkdir(live_day, 0o700)
        return real_unlink(target, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", _displacing_unlink)
    try:
        first = reconciler.reconcile()
        assert fired == [True]
        assert first.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in first.anomalies
        assert not source.exists()
        displaced_day = displaced if swap_level == "day" else displaced / _DAY
        if namespace == "pending":
            assert list(displaced_day.iterdir()) == []
            assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
        else:
            assert (displaced_day / "batch-1.jsonl").read_bytes() == b"junk\n"
            assert list(quarantine_day.iterdir()) == []

        live_day.rmdir()
        if swap_level == "day":
            os.rename(displaced, live_day)
        else:
            live_root.rmdir()
            os.rename(displaced, live_root)
        second = reconciler.reconcile()
        assert second.quarantined == ()
        assert second.anomalies == ()
        assert (spool_root / "quarantine" / _DAY / "batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


@pytest.mark.parametrize("swap_level", ["day", "root"])
def test_target_displaced_during_final_source_stat_leaves_recoverable_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_level: str
) -> None:
    """A target move after the source decision cannot turn retirement into deletion."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = spool_root / "pending" / _DAY
    pending_inode = os.lstat(pending_day).st_ino
    quarantine_root = spool_root / "quarantine"
    quarantine_day = quarantine_root / _DAY
    displaced = tmp_path / f"target-during-source-stat-{swap_level}"
    real_stat = os.stat
    source_stats: list[int] = []

    def _displacing_stat(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_stat(target, *args, **kwargs)
        dir_fd = kwargs.get("dir_fd")
        if (
            target == "batch-1.jsonl"
            and dir_fd is not None
            and os.fstat(dir_fd).st_ino == pending_inode
        ):
            source_stats.append(1)
            if len(source_stats) == 2:
                if swap_level == "day":
                    os.rename(quarantine_day, displaced)
                    os.mkdir(quarantine_day, 0o700)
                else:
                    os.rename(quarantine_root, displaced)
                    os.mkdir(quarantine_root, 0o700)
                    os.mkdir(quarantine_day, 0o700)
        return result

    monkeypatch.setattr(os, "stat", _displacing_stat)
    try:
        report = reconciler.reconcile()
        assert len(source_stats) >= 2
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert not source.exists()
        retirements = tuple(pending_day.glob(f"{reconcile_module._RETIRE_PREFIX}*"))
        assert len(retirements) == 1
        assert retirements[0].read_bytes() == b"junk\n"
        escaped_day = displaced if swap_level == "day" else displaced / _DAY
        assert list(escaped_day.iterdir()) == []
        assert list(quarantine_day.iterdir()) == []

        if swap_level == "day":
            quarantine_day.rmdir()
            os.rename(displaced, quarantine_day)
        else:
            quarantine_day.rmdir()
            quarantine_root.rmdir()
            os.rename(displaced, quarantine_root)
        retry = reconciler.reconcile()
        assert len(retry.quarantined) == 1
        assert list(pending_day.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert [target.name for target in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
    finally:
        database.close()


def test_an_interrupted_retirement_reuses_the_original_candidate_without_debris(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retry adopts the encoded candidate instead of publishing under the private stage name."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = source.parent
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(quarantine_day.parent, 0o700)
    os.chmod(quarantine_day, 0o700)
    target = quarantine_day / "batch-1.jsonl"
    target.write_bytes(b"junk\n")
    os.chmod(target, 0o600)
    real_pending_binding = reconcile_module._Scan._pending_binding_holds
    calls: list[int] = []

    def _failing_post_retirement_proof(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(1)
        if len(calls) == 3:
            return False
        return real_pending_binding(self, *args, **kwargs)

    monkeypatch.setattr(
        reconcile_module._Scan, "_pending_binding_holds", _failing_post_retirement_proof
    )
    try:
        first = reconciler.reconcile()
        assert first.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in first.anomalies
        assert not source.exists()
        retirements = tuple(pending_day.glob(f"{reconcile_module._RETIRE_PREFIX}*"))
        assert len(retirements) == 1
        assert retirements[0].read_bytes() == b"junk\n"
        assert [entry.name for entry in quarantine_day.iterdir()] == ["batch-1.jsonl"]

        second = reconciler.reconcile()
        assert second.quarantined == (QuarantinedFile("", _DAY, "stale_temp"),)
        assert list(pending_day.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert [entry.name for entry in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
        third = reconciler.reconcile()
        assert third.quarantined == ()
        assert third.anomalies == ()
    finally:
        database.close()


@pytest.mark.parametrize("name_length", [240, 255])
def test_a_name_max_staged_temporary_uses_a_bounded_recoverable_candidate(
    tmp_path: Path, name_length: int
) -> None:
    """A legal long entry cannot make retirement fail forever with ``ENAMETOOLONG``."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    prefix = reconcile_module._STAGE_PREFIX
    name = f"{prefix}{'x' * (name_length - len(prefix))}"
    source = _publish_orphan(spool_root, _DAY, name, b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    try:
        first = reconciler.reconcile()
        assert first.quarantined == (QuarantinedFile("", _DAY, "stale_temp"),)
        assert SegmentAnomaly("", _DAY, "stale_temp", "staged_temporary") in first.anomalies
        assert not source.exists()
        assert list(source.parent.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert len(targets) == 1
        assert targets[0].name.startswith(".milhouse-quarantine-")
        assert len(os.fsencode(targets[0].name)) <= os.pathconf(quarantine_day, "PC_NAME_MAX")
        assert targets[0].read_bytes() == b"junk\n"
        second = reconciler.reconcile()
        assert second.quarantined == ()
        assert second.anomalies == ()
    finally:
        database.close()


def test_a_candidate_is_refused_when_name_max_cannot_fit_a_recovery_name() -> None:
    snapshot = FileSnapshot(device=1, inode=2, size=3, modified_ns=4, changed_ns=5)

    assert reconcile_module._bounded_candidate_base("x", snapshot, "a" * 64, 1) is None


@pytest.mark.parametrize(
    ("failure", "detail"),
    [("name-max", "io"), ("candidate-budget", "collision")],
)
def test_candidate_name_bound_failures_leave_the_source_unmodified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, detail: str
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    quarantine_day = spool_root / "quarantine" / _DAY
    if failure == "name-max":

        def _failing_pathconf(_descriptor: int, _name: str) -> int:
            raise OSError(5, "planted pathconf failure")

        monkeypatch.setattr(os, "fpathconf", _failing_pathconf)
    else:
        monkeypatch.setattr(reconcile_module, "_bounded_candidate_base", lambda *_args: None)
    try:
        report = reconciler.reconcile()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", detail) in report.anomalies
        assert source.read_bytes() == b"junk\n"
        assert list(quarantine_day.iterdir()) == []
    finally:
        database.close()


@pytest.mark.parametrize("failure", ["unreadable", "mismatch"])
def test_retirement_certification_failure_is_uncertain_and_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """An uncertified retirement remains staged and is not falsely reported as completed."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = source.parent
    quarantine_day = spool_root / "quarantine" / _DAY
    real_certify = reconcile_module._Scan._certify_target
    fired: list[bool] = []

    def _failing_retirement_certify(self, target_fd, candidate, digest):  # type: ignore[no-untyped-def]
        result = real_certify(self, target_fd, candidate, digest)
        if not fired and candidate.startswith(reconcile_module._RETIRE_PREFIX):
            fired.append(True)
            if failure == "unreadable":
                return None
            assert result is not None
            return FileSnapshot(
                result.device,
                result.inode,
                result.size + 1,
                result.modified_ns,
                result.changed_ns,
            )
        return result

    monkeypatch.setattr(reconcile_module._Scan, "_certify_target", _failing_retirement_certify)
    try:
        first = reconciler.reconcile()
        assert fired == [True]
        assert first.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in first.anomalies
        assert not source.exists()
        retirements = tuple(pending_day.glob(f"{reconcile_module._RETIRE_PREFIX}*"))
        assert len(retirements) == 1
        assert retirements[0].read_bytes() == b"junk\n"
        assert [entry.name for entry in quarantine_day.iterdir()] == ["batch-1.jsonl"]

        second = reconciler.reconcile()
        assert second.quarantined == (QuarantinedFile("", _DAY, "stale_temp"),)
        assert list(pending_day.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert [entry.name for entry in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
    finally:
        database.close()


@pytest.mark.parametrize("failure_point", ["certification", "cleanup"])
def test_a_public_replacement_racing_retirement_failure_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_point: str
) -> None:
    """Failure paths retain the private source instead of restoring with destructive replace."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = source.parent
    quarantine_day = spool_root / "quarantine" / _DAY
    fired: list[bool] = []

    if failure_point == "certification":
        real_certify = reconcile_module._Scan._certify_target

        def _failing_certify(self, target_fd, candidate, digest):  # type: ignore[no-untyped-def]
            if not fired and candidate.startswith(reconcile_module._RETIRE_PREFIX):
                fired.append(True)
                source.write_bytes(b"replacement\n")
                os.chmod(source, 0o600)
                return None
            return real_certify(self, target_fd, candidate, digest)

        monkeypatch.setattr(reconcile_module._Scan, "_certify_target", _failing_certify)
    else:
        real_unlink = os.unlink

        def _failing_unlink(target, *, dir_fd=None):  # type: ignore[no-untyped-def]
            if (
                not fired
                and str(target).startswith(reconcile_module._RETIRE_PREFIX)
                and dir_fd is not None
                and os.fstat(dir_fd).st_ino == os.lstat(pending_day).st_ino
            ):
                fired.append(True)
                source.write_bytes(b"replacement\n")
                os.chmod(source, 0o600)
                raise OSError(5, "planted retirement cleanup failure")
            return real_unlink(target, dir_fd=dir_fd)

        monkeypatch.setattr(os, "unlink", _failing_unlink)

    try:
        first = reconciler.reconcile()
        assert fired == [True]
        assert first.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in first.anomalies
        assert source.read_bytes() == b"replacement\n"
        retirements = tuple(pending_day.glob(f"{reconcile_module._RETIRE_PREFIX}*"))
        assert len(retirements) == 1
        assert retirements[0].read_bytes() == b"junk\n"
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"

        second = reconciler.reconcile()
        assert len(second.quarantined) == 2
        assert list(pending_day.iterdir()) == []
        assert {entry.read_bytes() for entry in quarantine_day.iterdir()} == {
            b"junk\n",
            b"replacement\n",
        }
        third = reconciler.reconcile()
        assert third.quarantined == ()
        assert third.anomalies == ()
    finally:
        database.close()


def test_failed_source_retirement_cleans_only_its_empty_reservation_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = source.parent
    quarantine_day = spool_root / "quarantine" / _DAY
    real_replace = os.replace
    fired: list[bool] = []

    def _failing_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):  # type: ignore[no-untyped-def]
        if (
            not fired
            and src == "batch-1.jsonl"
            and str(dst).startswith(reconcile_module._RETIRE_PREFIX)
        ):
            fired.append(True)
            raise OSError(5, "planted retirement failure")
        return real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(os, "replace", _failing_replace)
    try:
        first = reconciler.reconcile()
        assert fired == [True]
        assert first.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in first.anomalies
        assert source.read_bytes() == b"junk\n"
        assert [entry.name for entry in pending_day.iterdir()] == ["batch-1.jsonl"]
        assert [entry.name for entry in quarantine_day.iterdir()] == ["batch-1.jsonl"]

        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert list(pending_day.iterdir()) == []
        targets = tuple(quarantine_day.iterdir())
        assert [entry.name for entry in targets] == ["batch-1.jsonl"]
        assert targets[0].read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_retirement_reservation_open_failure_is_uncertain_and_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = source.parent
    quarantine_day = spool_root / "quarantine" / _DAY
    real_open = os.open
    fired: list[bool] = []

    def _failing_open(target, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        if (
            not fired
            and str(target).startswith(reconcile_module._RETIRE_PREFIX)
            and flags & os.O_EXCL
        ):
            fired.append(True)
            raise OSError(5, "planted reservation failure")
        return real_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", _failing_open)
    try:
        first = reconciler.reconcile()
        assert fired == [True]
        assert first.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in first.anomalies
        assert source.read_bytes() == b"junk\n"
        assert [entry.name for entry in pending_day.iterdir()] == ["batch-1.jsonl"]
        assert [entry.name for entry in quarantine_day.iterdir()] == ["batch-1.jsonl"]

        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert list(pending_day.iterdir()) == []
        assert [entry.name for entry in quarantine_day.iterdir()] == ["batch-1.jsonl"]
    finally:
        database.close()


def test_a_retired_source_advances_when_its_encoded_target_was_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bounded candidate sequence preserves a conflicting target and still converges."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    pending_day = source.parent
    quarantine_day = spool_root / "quarantine" / _DAY
    quarantine_day.mkdir(mode=0o700, parents=True)
    os.chmod(quarantine_day.parent, 0o700)
    os.chmod(quarantine_day, 0o700)
    target = quarantine_day / "batch-1.jsonl"
    target.write_bytes(b"junk\n")
    os.chmod(target, 0o600)
    real_pending_binding = reconcile_module._Scan._pending_binding_holds
    calls: list[int] = []

    def _failing_post_retirement_proof(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(1)
        if len(calls) == 3:
            return False
        return real_pending_binding(self, *args, **kwargs)

    monkeypatch.setattr(
        reconcile_module._Scan, "_pending_binding_holds", _failing_post_retirement_proof
    )
    try:
        first = reconciler.reconcile()
        assert first.quarantined == ()
        retirements = tuple(pending_day.glob(f"{reconcile_module._RETIRE_PREFIX}*"))
        assert len(retirements) == 1
        target.write_bytes(b"different\n")

        second = reconciler.reconcile()
        assert second.quarantined == (QuarantinedFile("", _DAY, "stale_temp"),)
        assert list(pending_day.iterdir()) == []
        targets = {entry.name: entry.read_bytes() for entry in quarantine_day.iterdir()}
        assert targets == {
            "1.batch-1.jsonl": b"junk\n",
            "batch-1.jsonl": b"different\n",
        }
        third = reconciler.reconcile()
        assert third.quarantined == ()
        assert third.anomalies == ()
    finally:
        database.close()


def test_source_removed_during_final_target_certification_is_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A source that vanishes after the initial stat must not be reported completed."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    real_certify = reconcile_module._Scan._certify_live_target
    certify_calls: list[int] = []

    def _removing_certify(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_certify(self, *args, **kwargs)
        certify_calls.append(1)
        if len(certify_calls) == 2:
            os.unlink(source)
        return result

    monkeypatch.setattr(reconcile_module._Scan, "_certify_live_target", _removing_certify)
    try:
        report = reconciler.reconcile()
        assert not source.exists()
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
        assert (spool_root / "quarantine" / _DAY / "batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


def test_source_replaced_during_final_target_certification_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lengthy target reads must finish before the source's final snapshot decision."""

    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    source = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    classified = tmp_path / "classified-source"
    real_certify = reconcile_module._Scan._certify_live_target
    certify_calls: list[int] = []

    def _replacing_certify(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = real_certify(self, *args, **kwargs)
        certify_calls.append(1)
        if len(certify_calls) == 2:
            os.rename(source, classified)
            source.write_bytes(b"replacement\n")
            os.chmod(source, 0o600)
        return result

    monkeypatch.setattr(reconcile_module._Scan, "_certify_live_target", _replacing_certify)
    try:
        report = reconciler.reconcile()
        assert source.read_bytes() == b"replacement\n"
        assert classified.read_bytes() == b"junk\n"
        assert report.quarantined == ()
        assert (spool_root / "quarantine" / _DAY / "batch-1.jsonl").read_bytes() == b"junk\n"
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_uncertain", "io") in report.anomalies
    finally:
        database.close()
