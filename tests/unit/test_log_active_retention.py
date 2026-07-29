"""P1-1: retention rotates and prunes an expired ACTIVE segment.

Retention historically pruned only closed rotations, so a quiet installation could keep the active
segment's events past the 14-day log-class privacy ceiling forever. Retention now authenticates the
active segment under the exclusive barrier and log lock, closes and rotates it in the fixed crash
order when its effective deadline has passed, publishes a fresh empty successor, and prunes the
newly closed segment — while an unrecoverable active is left for recovery and crashes at every
rotate boundary converge without losing the only durable name.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.core import FixedClock
from milhouse.core.log_store import (
    StructuredLogStore,
    recover_structured_logs,
    retention_apply,
    retention_preview,
)
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

_NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)
_CURRENT = "structured-log.current.jsonl"
_RECORDS = LogMetricSpec("records", LogMetricKind.COUNT)
_SPEC = LogEventSpec("collector.completed", LogLevel.INFO, metrics=(_RECORDS,))


def _monotonic() -> float:
    return 0.0


class _Sink:
    def write(self, event: StructuredLogEventV1) -> None:  # pragma: no cover - unused capture
        pass


def _event(timestamp: datetime = _NOW, records: int = 1) -> StructuredLogEventV1:
    logger = StructuredLogger(
        catalog=(_SPEC,),
        clock=FixedClock(timestamp),
        sink=_Sink(),
        minimum_level=LogLevel.DEBUG,
        pseudonymizer=Pseudonymizer(b"f" * 32),
    )
    event = logger.emit(_SPEC, metrics=(LogMetric(_RECORDS, records),))
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


def _store(
    logs: Path, *, retention_days: int = 14, opened_at: datetime = _NOW
) -> StructuredLogStore:
    return StructuredLogStore(
        logs_dir=logs, retention_days=retention_days, monotonic=_monotonic, opened_at=opened_at
    )


def _events_on_disk(logs: Path) -> int:
    total = 0
    for path in logs.glob("structured-log.*.jsonl"):
        for line in path.read_bytes().split(b"\n"):
            if line and json.loads(line).get("line") == "event":
                total += 1
    return total


# --- rotate-and-prune the expired active segment -------------------------------------------------


def test_apply_rotates_and_prunes_an_expired_active_with_events(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()  # active sequence 1 holds one event and was never rotated
    barrier = _barrier(tmp_path)
    report = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=15),
    )
    assert report.active is not None
    assert (report.active.sequence, report.active.rotated) == (1, True)
    assert [segment.sequence for segment in report.segments] == [1]  # the rotated active pruned
    assert _events_on_disk(logs) == 0  # the event bytes no longer outlive the ceiling
    reopened = _store(logs)
    try:
        assert reopened.sequence == 2  # a fresh empty successor, no sequence reuse
        assert reopened.event_count == 0
    finally:
        reopened.close()


def test_apply_rotates_and_prunes_an_expired_empty_active(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    _store(logs).close()  # active sequence 1 is header-only (no events)
    barrier = _barrier(tmp_path)
    report = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=15),
    )
    assert report.active is not None and report.active.rotated is True
    assert [segment.sequence for segment in report.segments] == [1]
    reopened = _store(logs)
    try:
        assert reopened.sequence == 2
    finally:
        reopened.close()


def test_apply_leaves_an_unexpired_active_untouched(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    barrier = _barrier(tmp_path)
    report = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=1),  # well before the 14-day deadline
    )
    assert report.active is not None
    assert report.active.expired is False and report.active.rotated is False
    assert report.segments == ()
    assert _events_on_disk(logs) == 1  # the event stays in the still-live active segment
    assert (logs / _CURRENT).exists()


def test_a_tightened_policy_retires_the_active_segment_early(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs, retention_days=14)
    store.append(_event())
    store.close()
    barrier = _barrier(tmp_path)
    # captured deadline is opened + 14d, but the current policy tightens it to opened + 1d
    report = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=1,
        now=_NOW + timedelta(days=2),
    )
    assert report.active is not None and report.active.rotated is True
    assert [segment.sequence for segment in report.segments] == [1]
    assert _events_on_disk(logs) == 0


def test_preview_reports_a_due_active_without_mutating(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    barrier = _barrier(tmp_path)
    report = retention_preview(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=15),
    )
    assert report.active is not None
    assert report.active.sequence == 1
    assert report.active.expired is True and report.active.rotated is False
    assert _events_on_disk(logs) == 1  # preview mutated nothing


def test_apply_refuses_an_unrecoverable_active_and_still_prunes_closed(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.rotate(closed_at=_NOW + timedelta(minutes=1))  # closed rotation 1
    store.append(_event(_NOW + timedelta(minutes=2)))
    store.close()  # active sequence 2 holds one event
    current = logs / _CURRENT
    current.write_bytes(current.read_bytes() + b'{"line":"event"')  # a torn, incomplete tail
    barrier = _barrier(tmp_path)
    report = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=15),
    )
    assert report.active is not None
    assert report.active.rotated is False
    assert report.active.code == "MH_LOG_RECOVERY_REQUIRED"
    assert [segment.sequence for segment in report.segments] == [1]  # closed rotation still prunes
    assert current.exists()  # the torn active is left for recovery, never rotated


# --- crashes at every rotate boundary converge under recovery ------------------------------------


class _FailOnce:
    def __init__(self, real):  # type: ignore[no-untyped-def]
        self.real = real
        self.fired = False

    def __call__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if not self.fired:
            self.fired = True
            raise OSError(5, "planted crash")
        return self.real(*args, **kwargs)


@pytest.mark.parametrize("operation", ["fsync", "write", "link", "unlink", "rename"])
def test_a_crash_at_a_rotate_boundary_converges_without_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.flush()
    store.close()  # active sequence 1 holds one durable event
    barrier = _barrier(tmp_path)

    monkeypatch.setattr(os, operation, _FailOnce(getattr(os, operation)))
    with pytest.raises(LoggingError) as crashed:
        retention_apply(
            logs_dir=logs,
            barrier=barrier,
            monotonic=_monotonic,
            retention_days=14,
            now=_NOW + timedelta(days=15),
        )
    assert crashed.value.code == "MH_LOG_ROTATE"
    monkeypatch.undo()  # the crash is a one-time event; recovery restarts clean

    recover_structured_logs(logs_dir=logs, barrier=barrier, monotonic=_monotonic)
    assert _events_on_disk(logs) == 1  # the acknowledged event survives exactly once
    reopened = _store(logs)
    try:
        rotated_names = [
            path.name for path in logs.glob("structured-log.*.jsonl") if path.name != _CURRENT
        ]
        # no sequence reuse: the live sequence strictly exceeds every surviving rotation
        for name in rotated_names:
            assert reopened.sequence > int(name[len("structured-log.") : -len(".jsonl")])
        reopened.append(_event(_NOW + timedelta(days=15)))  # the store is usable again
        reopened.flush()
    finally:
        reopened.close()
