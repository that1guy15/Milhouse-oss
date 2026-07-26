from __future__ import annotations

import os
import stat
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
        leaf = reconcile_module.FileIdentity.from_stat(os.lstat(day_dir / "batch-1.jsonl"))
        os.rename(day_dir, spool_root / "pending" / "displaced")
        replacement = spool_root / "pending" / _DAY
        replacement.mkdir(mode=0o700)
        os.chmod(replacement, 0o700)
        (replacement / "batch-1.jsonl").write_bytes(b"impostor")
        assert scan._move_to_quarantine(_DAY, "batch-1.jsonl", captured, leaf) == "changed"
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

    def _acl_everywhere(_descriptor: int) -> None:
        raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)

    monkeypatch.setattr(reconcile_module, "require_no_extended_acl", _acl_everywhere)
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
    # the interrupted-move twin shape admits exactly-two links and nothing else unusual
    assert reconcile_module._interrupted_move_shape(_info(stat.S_IFREG | 0o600, nlink=2))
    assert not reconcile_module._interrupted_move_shape(_info(stat.S_IFREG | 0o600))
    assert not reconcile_module._interrupted_move_shape(_info(stat.S_IFCHR | 0o600, nlink=2))
    assert not reconcile_module._interrupted_move_shape(
        _info(stat.S_IFREG | 0o600, nlink=2, owner=uid + 1)
    )


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


def test_a_regular_replacement_swapped_in_before_link_is_never_moved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the re-review's deterministic race: replace the classified file with a DIFFERENT regular
    # file immediately before the hard link — zero moves, zero unlinks, both objects preserved
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
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        assert path.read_bytes() == b"replacement-not-classified"  # never unlinked
        assert aside.read_bytes() == b"junk\n"  # the classified original is preserved
        quarantine_day = spool_root / "quarantine" / _DAY
        assert list(quarantine_day.iterdir()) == []  # the mismatched link was rolled back
    finally:
        database.close()


def test_a_symlink_replacement_swapped_in_before_link_is_never_moved(
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
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "changed") in report.anomalies
        assert os.path.islink(path)  # the swapped-in symlink was never unlinked
        assert aside.read_bytes() == b"junk\n"
        assert canary.read_bytes() == _CANARY
        assert list((spool_root / "quarantine" / _DAY).iterdir()) == []
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
    real_link, real_fsync, real_unlink = os.link, os.fsync, os.unlink

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

    monkeypatch.setattr(os, "link", _logging_link)
    monkeypatch.setattr(os, "fsync", _logging_fsync)
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
        # the target directory is durable before the source is touched; the source directory
        # is flushed last
        assert [entry for entry in log if entry == ("unlink", "pending-day")] == [
            ("unlink", "pending-day")
        ]
        assert (
            link_at
            < log.index(("fsync", "quarantine-day"))
            < log.index(("unlink", "pending-day"))
            < log.index(("fsync", "pending-day"))
        )
        assert not path.exists()
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
    finally:
        database.close()


def test_a_target_fsync_failure_blocks_cleanly_with_the_source_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the re-review's planted failure: with the first target-directory fsync failing, the move
    # must report blocked AND the file must actually still be in pending — state and report agree
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
        assert report.quarantined == ()
        assert SegmentAnomaly("batch-1", _DAY, "quarantine_blocked", "io") in report.anomalies
        assert path.read_bytes() == b"junk\n"  # blocked really does mean: still in pending
        assert list(quarantine_day.iterdir()) == []  # the undurable link was rolled back
        # the retry converges: one durable name, no aliases
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert not path.exists()
        assert [entry.name for entry in quarantine_day.iterdir()] == ["batch-1.jsonl"]
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
        assert list((spool_root / "quarantine" / _DAY).iterdir()) == []
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert not path.exists()
    finally:
        database.close()


@pytest.mark.parametrize("target_parts", [("quarantine",), ("quarantine", _DAY)])
def test_a_blocked_quarantine_directory_mkdir_reports_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_parts: tuple[str, ...]
) -> None:
    database, _store, spool_root, reconciler = _reconciler(tmp_path)
    path = _publish_orphan(spool_root, _DAY, "batch-1.jsonl", b"junk\n")
    blocked_path = spool_root.joinpath(*target_parts)
    real_mkdir = os.mkdir
    fail = [True]

    def _failing_mkdir(target, mode=0o777, *, dir_fd=None):  # type: ignore[no-untyped-def]
        if fail and Path(target) == blocked_path:
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
    monkeypatch.setattr(reconcile_module, "_fsync_dir", lambda _path: False)
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
    # after the target is durable, an unlink failure is COMMIT-UNCERTAIN: never reported as
    # completed, never as still-pending — and the next scan adopts the same-inode twin
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
        # the durable target and the pending twin are the SAME inode under two names
        assert os.stat(path).st_ino == os.stat(quarantine_day / "batch-1.jsonl").st_ino
        # the retry converges by adopting the twin: one durable name, no aliases
        second = reconciler.reconcile()
        assert len(second.quarantined) == 1
        assert not path.exists()
        assert [entry.name for entry in quarantine_day.iterdir()] == ["batch-1.jsonl"]
        assert (quarantine_day / "batch-1.jsonl").read_bytes() == b"junk\n"
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
    fail = [True]

    def _failing_fsync(fd: int) -> None:
        info = os.fstat(fd)
        if fail and _dir_ident(pending_day) == (info.st_dev, info.st_ino):
            fail.clear()
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
