"""Regression evidence for the PR #45 gate-review findings P1-2/3/5/7/8 and P2.

Each test pins the exact defect the independent gate review reproduced, so a regression re-opens a
failing test rather than silently crossing the durability, privacy, or ceiling contract again.
"""

from __future__ import annotations

import fcntl
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.core import FixedClock
from milhouse.core import log_store as log_store_module
from milhouse.core.log_store import (
    StructuredLogStore,
    retention_apply,
)
from milhouse.core.log_wire import (
    StructuredLogHeaderV1,
    StructuredLogTrailerV1,
    structured_log_content_sha256,
    structured_log_event_line,
    structured_log_header_line,
    structured_log_trailer_line,
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
_STAGING = ".structured-log.next.tmp"
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


# --- P1-2: trailer expires_at must re-derive from the header, not be trusted ---------------------


def test_a_forged_early_expiry_trailer_is_refused_not_deleted(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    header = StructuredLogHeaderV1(sequence=1, opened_at=_NOW, retention_days=14)
    header_line = structured_log_header_line(header)
    event_line = structured_log_event_line(_event())
    # a canonical trailer with a VALID content digest but an expires_at forged 13 days early:
    # the trailer is outside content_sha256, so only re-deriving the deadline from the header
    # catches it (A05, ADR 0016)
    forged = structured_log_trailer_line(
        StructuredLogTrailerV1(
            sequence=1,
            closed_at=_NOW,
            last_event_at=_NOW,
            event_count=1,
            content_sha256=structured_log_content_sha256(header_line, [event_line]),
            expires_at=_NOW + timedelta(days=1),  # header says +14d
        )
    )
    segment = logs / f"structured-log.{1:020d}.jsonl"
    segment.write_bytes(header_line + event_line + forged)
    os.chmod(segment, 0o600)
    barrier = _barrier(tmp_path)
    report = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=2),  # past the forged +1d, before the real +14d
    )
    assert report.segments == ()  # not deleted on the forged deadline
    assert [(refused.sequence, refused.code) for refused in report.refused] == [
        (1, "MH_LOG_RETENTION")
    ]
    assert segment.exists()


# --- P1-3: live rotation fsyncs the directory between the link and the unlink --------------------


def test_live_rotation_fsyncs_the_directory_between_link_and_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    calls: list[tuple[str, object]] = []
    real_link, real_unlink, real_fsync = os.link, os.unlink, os.fsync

    def _spy_link(src, dst, **kw):  # type: ignore[no-untyped-def]
        calls.append(("link", dst))
        return real_link(src, dst, **kw)

    def _spy_unlink(path, **kw):  # type: ignore[no-untyped-def]
        calls.append(("unlink", path))
        return real_unlink(path, **kw)

    def _spy_fsync(fd):  # type: ignore[no-untyped-def]
        calls.append(("fsync", "dir" if fd == store._directory_fd else "file"))
        return real_fsync(fd)

    monkeypatch.setattr(os, "link", _spy_link)
    monkeypatch.setattr(os, "unlink", _spy_unlink)
    monkeypatch.setattr(os, "fsync", _spy_fsync)
    try:
        store.rotate(closed_at=_NOW + timedelta(minutes=1))
    finally:
        monkeypatch.undo()
        store.close()
    rotated = f"structured-log.{1:020d}.jsonl"
    relevant = [c for c in calls if c[0] in ("link", "unlink") or c == ("fsync", "dir")]
    assert relevant[:4] == [
        ("link", rotated),
        ("fsync", "dir"),
        ("unlink", _CURRENT),
        ("fsync", "dir"),
    ]


# --- P1-5: a logs-directory swap after open never redirects writes -------------------------------


def test_a_logs_directory_swap_after_open_fails_closed(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    store = _store(logs)
    try:
        displaced = tmp_path / "displaced"
        os.rename(logs, displaced)  # the held descriptor follows the moved inode
        logs.mkdir(mode=0o700)  # a replacement at the configured path
        os.chmod(logs, 0o700)
        with pytest.raises(LoggingError) as conflict:
            store.append(_event())
        assert conflict.value.code == "MH_LOG_CONFLICT"
        assert not (logs / _CURRENT).exists()  # the replacement never received the write
        assert (displaced / _CURRENT).exists()  # the data stayed with the original inode
    finally:
        store.close()


# --- P1-7: a short initial-header write is never published as a successful segment ---------------


class _ShortWriteOnce:
    def __init__(self, real):  # type: ignore[no-untyped-def]
        self.real = real
        self.fired = False

    def __call__(self, fd, data, *args, **kwargs):  # type: ignore[no-untyped-def]
        written = self.real(fd, data, *args, **kwargs)
        if not self.fired:
            self.fired = True
            return written - 1  # report one byte short although the bytes reached disk
        return written


def test_a_short_header_write_never_publishes_a_current_segment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs = _state_root(tmp_path)
    monkeypatch.setattr(os, "write", _ShortWriteOnce(os.write))
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_ROTATE"
    assert not (logs / _CURRENT).exists()  # no malformed current is published
    assert (logs / _STAGING).exists()  # only safely classified staging debris, for recovery


# --- P1-8: retention unlinks only the exact validated inode, never a replacement -----------------


def test_retention_never_unlinks_a_replacement_swapped_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs = _state_root(tmp_path)
    header = StructuredLogHeaderV1(sequence=1, opened_at=_NOW, retention_days=14)
    header_line = structured_log_header_line(header)
    event_line = structured_log_event_line(_event())
    trailer = structured_log_trailer_line(
        StructuredLogTrailerV1(
            sequence=1,
            closed_at=_NOW,
            last_event_at=_NOW,
            event_count=1,
            content_sha256=structured_log_content_sha256(header_line, [event_line]),
            expires_at=_NOW + timedelta(days=14),
        )
    )
    segment = logs / f"structured-log.{1:020d}.jsonl"
    segment.write_bytes(header_line + event_line + trailer)
    os.chmod(segment, 0o600)
    barrier = _barrier(tmp_path)

    real_unlink_verified = log_store_module._unlink_verified

    def _swap_then_verify(directory_fd, name, identity):  # type: ignore[no-untyped-def]
        # a hostile same-user process replaces the validated inode between preview and unlink
        os.unlink(name, dir_fd=directory_fd)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        replacement = os.open(name, flags, 0o600, dir_fd=directory_fd)
        os.write(replacement, b"replacement\n")
        os.close(replacement)
        return real_unlink_verified(directory_fd, name, identity)

    monkeypatch.setattr(log_store_module, "_unlink_verified", _swap_then_verify)
    report = retention_apply(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=15),
    )
    assert report.segments == ()  # the original sequence is never claimed removed
    assert [(refused.sequence, refused.code) for refused in report.refused] == [
        (1, "MH_LOG_RETENTION")
    ]
    assert segment.read_bytes() == b"replacement\n"  # the replacement is left byte-for-byte intact


# --- P2: a contended log lock sleeps between retries instead of busy-spinning a core -------------


def test_a_contended_log_lock_sleeps_between_retries(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    _store(logs).close()
    holder = os.open(logs / "structured-log.lock", os.O_RDWR)
    fcntl.flock(holder, fcntl.LOCK_EX)
    ticks = iter([0.0, 1.0, 2.0, 3.0, 4.0, 6.0, 7.0, 8.0])
    waits: list[float] = []

    def _advancing() -> float:
        return next(ticks)

    try:
        with pytest.raises(LoggingError) as captured:
            StructuredLogStore(
                logs_dir=logs,
                retention_days=14,
                monotonic=_advancing,
                opened_at=_NOW,
                sleeper=waits.append,
            )
        assert captured.value.code == "MH_LOG_LOCK"
        assert waits, "the contended lock must sleep, not busy-spin"
        assert all(wait == log_store_module._LOCK_POLL_SECONDS for wait in waits)
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
