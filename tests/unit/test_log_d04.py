"""D04 remediation: regression evidence for the five post-merge exact-head review P1s.

Each test pins a defect the merge-race review reproduced on the PR #45 tree, so a regression
re-opens a failing test rather than silently re-crossing the durability, privacy, authority, or
filesystem-containment contract.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.core import FixedClock
from milhouse.core import log_store as log_store_module
from milhouse.core.log_store import (
    StructuredLogStore,
    recover_structured_logs,
    retention_apply,
    retention_preview,
)
from milhouse.core.log_wire import StructuredLogHeaderV1, structured_log_header_line
from milhouse.core.logging import (
    LogEventSpec,
    LoggingError,
    LogLevel,
    LogMetric,
    LogMetricKind,
    LogMetricSpec,
    StructuredLogEventV1,
    StructuredLogger,
)
from milhouse.privacy import Pseudonymizer
from milhouse.state import GlobalCommitBarrier, initialize_control_state, open_control_database
from milhouse.state.errors import StateError

_NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)
_RECORDS = LogMetricSpec("records", LogMetricKind.COUNT)
_SPEC = LogEventSpec("collector.completed", LogLevel.INFO, metrics=(_RECORDS,))


def _monotonic() -> float:
    return 0.0


class _Sink:
    def write(self, event: StructuredLogEventV1) -> None:  # pragma: no cover - unused capture
        pass


def _event(timestamp: datetime = _NOW) -> StructuredLogEventV1:
    logger = StructuredLogger(
        catalog=(_SPEC,),
        clock=FixedClock(timestamp),
        sink=_Sink(),
        minimum_level=LogLevel.DEBUG,
        pseudonymizer=Pseudonymizer(b"f" * 32),
    )
    event = logger.emit(_SPEC, metrics=(LogMetric(_RECORDS, 1),))
    assert event is not None
    return event


def _state_root(tmp_path: Path) -> Path:
    logs = tmp_path / "logs"
    logs.mkdir(mode=0o700)
    os.chmod(logs, 0o700)
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    return logs


def _barrier(tmp_path: Path) -> GlobalCommitBarrier:
    control = tmp_path / "control"
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    database.close()
    return barrier


def _store(logs: Path) -> StructuredLogStore:
    return StructuredLogStore(
        logs_dir=logs, retention_days=14, monotonic=_monotonic, opened_at=_NOW
    )


def _events_on_disk(logs: Path) -> int:
    total = 0
    for path in logs.glob("structured-log.*.jsonl"):
        for line in path.read_bytes().split(b"\n"):
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue  # a corrupt/tampered line is not a valid event
            if obj.get("line") == "event":
                total += 1
    return total


def _corrupt(path: Path) -> None:
    path.write_bytes(path.read_bytes()[:-10] + b"tampered!\n")  # break only the trailer


# --- D04-3: the rotation bound can no longer permanently retain an expired active segment ---------


def test_retention_retires_the_expired_active_after_reclaiming_room(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs = _state_root(tmp_path)
    monkeypatch.setattr(log_store_module, "MAX_ROTATIONS", 2)
    store = _store(logs)
    store.append(_event())
    store.rotate(closed_at=_NOW + timedelta(minutes=1))  # rotation 1: valid, will expire
    store.append(_event(_NOW + timedelta(minutes=2)))
    store.rotate(closed_at=_NOW + timedelta(minutes=3))  # rotation 2: will be corrupted/refused
    store.append(_event(_NOW + timedelta(minutes=4)))  # active sequence 3 holds an event
    store.close()
    _corrupt(logs / f"structured-log.{2:020d}.jsonl")
    barrier = _barrier(tmp_path)
    report = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=365),
    )
    # reclaiming rotation 1 frees room, so the due active (3) is still retired despite corrupt 2
    assert report.active is not None and report.active.rotated is True
    assert sorted(segment.sequence for segment in report.segments) == [1, 3]
    assert [refused.sequence for refused in report.refused] == [2]
    assert _events_on_disk(logs) == 1  # only the refused corrupt rotation's evidence bytes remain


def test_retention_reports_blocked_when_the_bound_is_pinned_by_a_refused_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs = _state_root(tmp_path)
    monkeypatch.setattr(log_store_module, "MAX_ROTATIONS", 1)
    store = _store(logs)
    store.append(_event())
    store.rotate(closed_at=_NOW + timedelta(minutes=1))  # the only rotation; will be corrupted
    store.append(_event(_NOW + timedelta(minutes=2)))  # active sequence 2 holds an event
    store.close()
    _corrupt(logs / f"structured-log.{1:020d}.jsonl")
    barrier = _barrier(tmp_path)
    first = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=365),
    )
    # the corrupt rotation pins the bound and cannot be pruned, so the expired active is reported
    # blocked rather than silently retained behind a "successful" apply
    assert first.active is not None
    assert first.active.expired is True and first.active.rotated is False
    assert first.active.code == "MH_LOG_RETENTION_BOUND"
    assert first.segments == ()
    assert [refused.sequence for refused in first.refused] == [1]
    # retry convergence: a later apply is idempotent — same blocked result, no sequence reuse
    second = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=366),
    )
    assert second.active is not None and second.active.code == "MH_LOG_RETENTION_BOUND"
    reopened = _store(logs)
    try:
        assert reopened.sequence == 2  # the active is still sequence 2 — no sequence reuse
    finally:
        reopened.close()


# --- D04-5: recovery removes only a classified staging crash artifact, never a foreign occupant ---

_STAGING = ".structured-log.next.tmp"


def _plant_foreign_regular(staging: Path, tmp_path: Path) -> None:
    staging.write_bytes(b"not a header line at all\n")  # complete line, not a header
    os.chmod(staging, 0o600)


def _plant_symlink(staging: Path, tmp_path: Path) -> None:
    os.symlink(tmp_path / "outside", staging)


def _plant_hard_link(staging: Path, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"x")
    os.chmod(target, 0o600)
    os.link(target, staging)  # nlink == 2


def _plant_directory(staging: Path, tmp_path: Path) -> None:
    staging.mkdir(mode=0o700)


def _plant_fifo(staging: Path, tmp_path: Path) -> None:
    os.mkfifo(staging, 0o600)  # a no-follow non-blocking open must not hang


def _plant_shaped_but_invalid(staging: Path, tmp_path: Path) -> None:
    staging.write_bytes(b'{"line":"header"}\n')  # header-shaped but missing required fields
    os.chmod(staging, 0o600)


_FOREIGN = [
    ("regular", _plant_foreign_regular),
    ("symlink", _plant_symlink),
    ("hard-link", _plant_hard_link),
    ("directory", _plant_directory),
    ("fifo", _plant_fifo),
    ("shaped-invalid", _plant_shaped_but_invalid),
]


@pytest.mark.parametrize("plant", [p for _, p in _FOREIGN], ids=[n for n, _ in _FOREIGN])
def test_recovery_refuses_and_preserves_a_foreign_staging_occupant(
    tmp_path: Path,
    plant,  # type: ignore[no-untyped-def]
) -> None:
    logs = _state_root(tmp_path)
    _store(logs).close()
    staging = logs / _STAGING
    plant(staging, tmp_path)
    barrier = _barrier(tmp_path)
    with pytest.raises(LoggingError) as refused:
        recover_structured_logs(logs_dir=logs, barrier=barrier, monotonic=_monotonic)
    assert refused.value.code == "MH_LOG_RECOVER"
    assert os.path.lexists(staging)  # the occupant is left exactly in place, never followed


def test_recovery_refuses_a_staging_header_at_a_reused_sequence(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs)
    store.rotate(closed_at=_NOW)  # rotation 1 survives; a staging header must exceed it
    store.close()
    staging = logs / _STAGING
    staging.write_bytes(
        structured_log_header_line(
            StructuredLogHeaderV1(sequence=1, opened_at=_NOW, retention_days=14)
        )
    )
    os.chmod(staging, 0o600)
    barrier = _barrier(tmp_path)
    with pytest.raises(LoggingError) as refused:
        recover_structured_logs(logs_dir=logs, barrier=barrier, monotonic=_monotonic)
    assert refused.value.code == "MH_LOG_RECOVER"
    assert staging.exists()  # a reused sequence is not a crash artifact; left in place


def test_recovery_removes_a_complete_successor_staging_header(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    _store(logs).close()  # fresh store: current is sequence 1, no rotations
    staging = logs / _STAGING
    staging.write_bytes(
        structured_log_header_line(
            StructuredLogHeaderV1(sequence=2, opened_at=_NOW, retention_days=14)
        )
    )
    os.chmod(staging, 0o600)
    barrier = _barrier(tmp_path)
    report = recover_structured_logs(logs_dir=logs, barrier=barrier, monotonic=_monotonic)
    assert report.removed_staging is True
    assert not staging.exists()


# --- D04-1: maintenance no longer deadlocks re-acquiring an already-held exclusive barrier ---


def test_maintenance_runs_under_an_already_held_exclusive_barrier(tmp_path: Path) -> None:
    import threading

    logs = _state_root(tmp_path)
    _store(logs).close()
    barrier = _barrier(tmp_path)
    done = threading.Event()
    result: dict[str, object] = {}

    def _run() -> None:
        # a genuine OUTER exclusive hold; each maintenance call must re-enter the same instance,
        # not re-acquire a second flock (which would deadlock)
        with barrier.exclusive():
            recover_structured_logs(logs_dir=logs, barrier=barrier, monotonic=_monotonic)
            result["preview"] = retention_preview(
                logs_dir=logs, barrier=barrier, monotonic=_monotonic, retention_days=14, now=_NOW
            )
            result["apply"] = retention_apply(
                logs_dir=logs, barrier=barrier, monotonic=_monotonic, retention_days=14, now=_NOW
            )
        done.set()

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    assert done.wait(timeout=5), "nested maintenance deadlocked while re-acquiring the barrier"
    assert result["preview"].segments == ()  # type: ignore[union-attr]
    assert result["apply"].segments == ()  # type: ignore[union-attr]


def test_a_foreign_same_thread_instance_is_rejected_not_deadlocked(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    _store(logs).close()
    held = _barrier(tmp_path)
    foreign = GlobalCommitBarrier(tmp_path / "control" / "commit.lock")  # same lock, other instance
    with held.exclusive():
        # a different instance for the same lock, in THIS thread, must fail closed (would deadlock),
        # never silently reuse the held authority
        with pytest.raises(StateError) as rejected:
            retention_apply(
                logs_dir=logs,
                barrier=foreign,
                monotonic=_monotonic,
                retention_days=14,
                now=_NOW,
            )
        assert rejected.value.code == "MH_STATE_BARRIER"


def test_a_barrier_path_mutated_during_a_hold_cannot_reuse_its_authority(tmp_path: Path) -> None:
    _state_root(tmp_path)
    held = _barrier(tmp_path)
    other = tmp_path / "other" / "control"
    other.mkdir(parents=True, mode=0o700)
    with held.exclusive():
        # tamper root A's held barrier to name root B, then re-enter: it must not let root A's held
        # flock stand in as root B authority
        held._path = (other / "commit.lock").resolve()
        with pytest.raises(StateError) as rejected:
            with held.exclusive():
                pass  # pragma: no cover - the re-entry fails closed before the body
        assert rejected.value.code == "MH_STATE_BARRIER"


# --- D04-2 + D04-4: state-root anchoring and full-chain no-follow ---


def _nested_root(tmp_path: Path) -> tuple[Path, Path, GlobalCommitBarrier]:
    root = tmp_path
    control = root / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    data = root / "data"
    data.mkdir(mode=0o700)
    os.chmod(data, 0o700)
    logs = data / "logs"  # [paths].logs nested below the state root
    logs.mkdir(mode=0o700)
    os.chmod(logs, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    database.close()
    return root, logs, barrier


def test_maintenance_accepts_a_plan_valid_nested_logs_directory(tmp_path: Path) -> None:
    root, logs, barrier = _nested_root(tmp_path)
    store = StructuredLogStore(
        logs_dir=logs,
        retention_days=14,
        monotonic=_monotonic,
        opened_at=_NOW,
        state_root=root,
    )
    store.append(_event())
    store.close()
    # the state root is derived from the barrier, so the nested logs is authenticated, not the
    # MH_LOG_AUTHORITY the old logs.parent assumption produced
    preview = retention_preview(
        logs_dir=logs, barrier=barrier, monotonic=_monotonic, retention_days=14, now=_NOW
    )
    assert preview.active is not None and preview.active.code is None
    recovered = recover_structured_logs(logs_dir=logs, barrier=barrier, monotonic=_monotonic)
    assert recovered.truncated_bytes == 0  # authenticated and recoverable


def test_a_symlinked_ancestor_is_rejected_for_the_store_and_maintenance(tmp_path: Path) -> None:
    root = tmp_path
    control = root / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    real = root / "real"
    real.mkdir(mode=0o700)
    os.chmod(real, 0o700)
    (real / "logs").mkdir(mode=0o700)
    os.chmod(real / "logs", 0o700)
    os.symlink(real, root / "alias")  # a directory-symlink ancestor between root and logs
    through_symlink = root / "alias" / "logs"

    with pytest.raises(LoggingError) as construct:
        StructuredLogStore(
            logs_dir=through_symlink,
            retention_days=14,
            monotonic=_monotonic,
            opened_at=_NOW,
            state_root=root,
        )
    assert construct.value.code == "MH_LOG_DIR"  # never published through the symlink

    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    database.close()
    with pytest.raises(LoggingError) as maintained:
        retention_preview(
            logs_dir=through_symlink,
            barrier=barrier,
            monotonic=_monotonic,
            retention_days=14,
            now=_NOW,
        )
    assert maintained.value.code == "MH_LOG_DIR"
    assert (root / "alias").is_symlink()  # the symlink is never followed or removed
