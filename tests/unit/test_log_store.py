from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.core import FixedClock
from milhouse.core import log_store as log_store_module
from milhouse.core.log_store import (
    LogRecoveryReport,
    StructuredLogStore,
    recover_structured_logs,
    retention_apply,
    retention_preview,
)
from milhouse.core.log_wire import (
    StructuredLogHeaderV1,
    StructuredLogTrailerV1,
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
_RECORDS = LogMetricSpec("records", LogMetricKind.COUNT)
_SPEC = LogEventSpec("collector.completed", LogLevel.INFO, metrics=(_RECORDS,))


class _CapturingSink:
    def write(self, event: StructuredLogEventV1) -> None:  # pragma: no cover - unused capture
        pass


def _event(timestamp: datetime = _NOW, records: int = 1) -> StructuredLogEventV1:
    logger = StructuredLogger(
        catalog=(_SPEC,),
        clock=FixedClock(timestamp),
        sink=_CapturingSink(),
        minimum_level=LogLevel.DEBUG,
        pseudonymizer=Pseudonymizer(b"f" * 32),
    )
    event = logger.emit(_SPEC, metrics=(LogMetric(_RECORDS, records),))
    assert event is not None
    return event


def _monotonic() -> float:
    return 0.0


def _state_root(tmp_path: Path) -> tuple[Path, Path]:
    logs = tmp_path / "logs"
    logs.mkdir(mode=0o700)
    os.chmod(logs, 0o700)
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    return logs, control


def _store(
    logs: Path, *, retention_days: int = 14, opened_at: datetime = _NOW
) -> StructuredLogStore:
    return StructuredLogStore(
        logs_dir=logs, retention_days=retention_days, monotonic=_monotonic, opened_at=opened_at
    )


def _hold_for(tmp_path: Path):
    control = tmp_path / "control"
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    database.close()
    return barrier


# --- fresh store and append ----------------------------------------------------------------------


def test_a_fresh_store_publishes_a_first_header_and_appends(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    try:
        assert store.sequence == 1
        current = logs / "structured-log.current.jsonl"
        assert stat.S_IMODE(os.lstat(current).st_mode) == 0o600
        first_line = current.read_bytes()
        header = json.loads(first_line.decode().splitlines()[0])
        assert header["line"] == "header"
        assert header["sequence"] == 1
        assert header["retention_days"] == 14
        store.append(_event())
        store.flush()
        lines = current.read_bytes().split(b"\n")[:-1]
        assert len(lines) == 2
        event = json.loads(lines[1].decode())
        assert event["line"] == "event"
        assert store.event_count == 1
    finally:
        store.close()


def test_reopening_resumes_the_active_segment(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    reopened = _store(logs)
    try:
        assert reopened.sequence == 1
        assert reopened.event_count == 1
        reopened.append(_event(records=2))
        assert reopened.event_count == 2
    finally:
        reopened.close()


def test_a_closed_store_refuses_further_appends(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.close()
    with pytest.raises(LoggingError) as captured:
        store.append(_event())
    assert captured.value.code == "MH_LOG_CLOSED"


# --- rotation ------------------------------------------------------------------------------------


def test_an_explicit_rotation_closes_and_publishes_the_next_segment(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    try:
        store.append(_event())
        store.rotate(closed_at=_NOW + timedelta(minutes=5))
        rotated = logs / f"structured-log.{1:020d}.jsonl"
        assert rotated.exists()
        lines = rotated.read_bytes().split(b"\n")[:-1]
        header = json.loads(lines[0].decode())
        trailer = json.loads(lines[-1].decode())
        assert header["line"] == "header"
        assert trailer["line"] == "trailer"
        assert trailer["sequence"] == 1
        assert trailer["event_count"] == 1
        # the digest covers the exact header plus ordered event bytes, excluding the trailer
        expected = hashlib.sha256(b"\n".join(lines[:-1]) + b"\n").hexdigest()
        assert trailer["content_sha256"] == expected
        # expires_at is opened_at plus the captured retention
        assert trailer["expires_at"].startswith("2026-08-09T")
        assert store.sequence == 2
        assert store.event_count == 0
    finally:
        store.close()


def test_an_empty_segment_rotates_with_a_null_last_event(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    try:
        store.rotate(closed_at=_NOW)
        rotated = logs / f"structured-log.{1:020d}.jsonl"
        trailer = json.loads(rotated.read_bytes().split(b"\n")[-2].decode())
        assert trailer["event_count"] == 0
        assert trailer["last_event_at"] is None
    finally:
        store.close()


def test_a_utc_day_change_rotates_before_the_append(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    try:
        store.append(_event())
        store.append(_event(_NOW + timedelta(days=1)))  # next UTC day
        assert store.sequence == 2
        assert store.event_count == 1  # the new day's event landed in the fresh segment
        assert (logs / f"structured-log.{1:020d}.jsonl").exists()
    finally:
        store.close()


def test_a_size_bound_rotates_before_the_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from milhouse.core import log_store as log_store_module

    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    try:
        store.append(_event())
        monkeypatch.setattr(log_store_module, "MAX_SEGMENT_BYTES", 1_100)
        store.append(_event(records=2))  # would exceed the bound with the reserved trailer
        assert store.sequence == 2
    finally:
        store.close()


def test_a_retention_policy_change_rotates_before_the_append(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs, retention_days=14)
    store.append(_event())
    store.close()
    changed = _store(logs, retention_days=7)  # tightened policy
    try:
        changed.append(_event(records=2))
        assert changed.sequence == 2  # the old segment closed with its captured 14-day retention
        rotated = logs / f"structured-log.{1:020d}.jsonl"
        trailer = json.loads(rotated.read_bytes().split(b"\n")[-2].decode())
        assert trailer["expires_at"].startswith("2026-08-09T")  # captured at 14 days, not 7
    finally:
        changed.close()


def test_sequence_overflow_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    top = (1 << 63) - 1
    (logs / f"structured-log.{top:020d}.jsonl").write_bytes(b"x")
    os.chmod(logs / f"structured-log.{top:020d}.jsonl", 0o600)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_OVERFLOW"


# --- crash artifacts and recovery ----------------------------------------------------------------


def test_a_torn_tail_requires_recovery_and_recovery_truncates_it(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    current = logs / "structured-log.current.jsonl"
    intact = current.read_bytes()
    with open(current, "ab") as handle:
        handle.write(b'{"line":"event","truncated')  # a torn, incomplete final write

    with pytest.raises(LoggingError) as refused:
        _store(logs)
    assert refused.value.code == "MH_LOG_RECOVERY_REQUIRED"

    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        report = recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert report == LogRecoveryReport(
        truncated_bytes=26, removed_staging=False, completed_rotation=False
    )
    assert current.read_bytes() == intact  # truncated exactly back to the last complete line

    healed = _store(logs)
    try:
        assert healed.event_count == 1
    finally:
        healed.close()


def test_a_leftover_staging_file_requires_recovery_and_is_removed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.close()
    staging = logs / ".structured-log.next.tmp"
    staging.write_bytes(b"crashed header")
    os.chmod(staging, 0o600)
    with pytest.raises(LoggingError) as refused:
        _store(logs)
    assert refused.value.code == "MH_LOG_RECOVERY_REQUIRED"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        report = recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert report.removed_staging is True
    assert not staging.exists()
    healed = _store(logs)
    healed.close()


def test_a_complete_malformed_line_is_not_repairable(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.close()
    current = logs / "structured-log.current.jsonl"
    with open(current, "ab") as handle:
        handle.write(b"complete but malformed\n")
    with pytest.raises(LoggingError) as refused:
        _store(logs)
    assert refused.value.code == "MH_LOG_EVENT"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as unrepaired:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert unrepaired.value.code == "MH_LOG_EVENT"


def test_a_planted_foreign_trailer_never_completes_a_rotation(tmp_path: Path) -> None:
    # a final trailer flags recovery, but recovery authenticates it against the exact bytes it
    # certifies: a trailer lifted from another segment fails the digest and is refused as a
    # plant, never linked into the rotated history
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.rotate(closed_at=_NOW)
    store.close()
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    trailer_line = rotated.read_bytes().split(b"\n")[-2] + b"\n"
    current = logs / "structured-log.current.jsonl"
    with open(current, "ab") as handle:
        handle.write(trailer_line)
    with pytest.raises(LoggingError) as refused:
        _store(logs)
    assert refused.value.code == "MH_LOG_RECOVERY_REQUIRED"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as rejected:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert rejected.value.code == "MH_LOG_RECOVER"
    assert current.exists()  # the plant is refused in place; nothing is moved or deleted
    assert not (logs / f"structured-log.{2:020d}.jsonl").exists()


def test_a_conflicting_active_sequence_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.rotate(closed_at=_NOW)  # rotation 1 exists; current is sequence 2
    store.close()
    # replace current with a stale sequence-1 header: sequence reuse is forbidden
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    header_line = rotated.read_bytes().split(b"\n")[0] + b"\n"
    current = logs / "structured-log.current.jsonl"
    current.write_bytes(header_line)
    with pytest.raises(LoggingError) as refused:
        _store(logs)
    assert refused.value.code == "MH_LOG_SEQUENCE"


def test_recovery_requires_live_authority_for_this_state_root(tmp_path: Path) -> None:
    from milhouse.state.barrier import ExclusiveHold

    logs, control = _state_root(tmp_path)
    _store(logs).close()
    with pytest.raises(LoggingError) as inactive:
        recover_structured_logs(
            logs_dir=logs,
            hold=ExclusiveHold(control / "commit.lock"),  # constructed: never active
            monotonic=_monotonic,
        )
    assert inactive.value.code == "MH_LOG_AUTHORITY"
    # a live hold of a DIFFERENT state root's barrier is not authority here
    (tmp_path / "other" / "control").mkdir(parents=True, mode=0o700)
    os.chmod(tmp_path / "other" / "control", 0o700)
    other_database = open_control_database(tmp_path / "other" / "control" / "milhouse.sqlite3")
    other_barrier = GlobalCommitBarrier(tmp_path / "other" / "control" / "commit.lock")
    initialize_control_state(other_database, barrier=other_barrier, applied_at=_NOW)
    other_database.close()
    with other_barrier.exclusive() as foreign_hold:
        with pytest.raises(LoggingError) as foreign:
            recover_structured_logs(logs_dir=logs, hold=foreign_hold, monotonic=_monotonic)
    assert foreign.value.code == "MH_LOG_AUTHORITY"


# --- locking -------------------------------------------------------------------------------------


def test_a_contended_log_lock_times_out_on_injected_monotonic_time(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    _store(logs).close()
    lock_path = logs / "structured-log.lock"
    holder = os.open(lock_path, os.O_RDWR)
    fcntl.flock(holder, fcntl.LOCK_EX)
    ticks = iter([0.0, 1.0, 2.0, 6.0, 7.0, 8.0, 9.0, 10.0])

    def advancing() -> float:
        return next(ticks)

    try:
        with pytest.raises(LoggingError) as captured:
            StructuredLogStore(
                logs_dir=logs, retention_days=14, monotonic=advancing, opened_at=_NOW
            )
        assert captured.value.code == "MH_LOG_LOCK"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)


# --- security envelope ---------------------------------------------------------------------------


def test_a_loose_logs_directory_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    os.chmod(logs, 0o755)
    try:
        with pytest.raises(LoggingError) as captured:
            _store(logs)
        assert captured.value.code == "MH_LOG_DIR"
    finally:
        os.chmod(logs, 0o700)


def test_a_symlinked_current_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    target = tmp_path / "elsewhere.jsonl"
    target.write_bytes(b"x")
    (logs / "structured-log.current.jsonl").symlink_to(target)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_OPEN"


def test_a_loose_mode_current_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.close()
    os.chmod(logs / "structured-log.current.jsonl", 0o644)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_FILE"


# --- retention -----------------------------------------------------------------------------------


def _rotate_days(logs: Path, days: int) -> None:
    store = _store(logs)
    for offset in range(days):
        store.append(_event(_NOW + timedelta(days=offset)))
    store.close()


def test_retention_preview_and_apply_respect_captured_deadlines(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs, retention_days=14)
    store.append(_event())
    store.rotate(closed_at=_NOW + timedelta(minutes=1))  # rotation 1: expires _NOW + 14d
    store.append(_event(_NOW + timedelta(minutes=2)))
    store.rotate(closed_at=_NOW + timedelta(minutes=3))  # rotation 2: expires _NOW + 14d
    store.close()
    barrier = _hold_for(tmp_path)

    # preview under a RELAXED policy: captured deadlines are never extended
    with barrier.exclusive() as hold:
        relaxed = retention_preview(
            logs_dir=logs,
            hold=hold,
            monotonic=_monotonic,
            retention_days=3650,
            now=_NOW + timedelta(days=15),
        )
    assert [segment.expired for segment in relaxed.segments] == [True, True]
    assert all(s.effective_expires_at == s.expires_at for s in relaxed.segments)
    assert relaxed.refused == ()

    # preview under a TIGHTENED policy: unexpired deadlines shorten
    with barrier.exclusive() as hold:
        tightened = retention_preview(
            logs_dir=logs,
            hold=hold,
            monotonic=_monotonic,
            retention_days=1,
            now=_NOW + timedelta(days=2),
        )
    assert [segment.expired for segment in tightened.segments] == [True, True]
    assert all(s.effective_expires_at < s.expires_at for s in tightened.segments)

    # apply deletes only the expired closed rotations, never the active segment
    with barrier.exclusive() as hold:
        removed = retention_apply(
            logs_dir=logs,
            hold=hold,
            monotonic=_monotonic,
            retention_days=14,
            now=_NOW + timedelta(days=15),
        )
    assert [segment.sequence for segment in removed.segments] == [1, 2]
    assert removed.refused == ()
    assert not (logs / f"structured-log.{1:020d}.jsonl").exists()
    assert not (logs / f"structured-log.{2:020d}.jsonl").exists()
    assert (logs / "structured-log.current.jsonl").exists()


def test_retention_keeps_unexpired_segments(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs, retention_days=14)
    store.append(_event())
    store.rotate(closed_at=_NOW)
    store.close()
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        removed = retention_apply(
            logs_dir=logs,
            hold=hold,
            monotonic=_monotonic,
            retention_days=14,
            now=_NOW + timedelta(days=1),  # well before the 14-day deadline
        )
    assert removed.segments == ()
    assert removed.refused == ()
    assert (logs / f"structured-log.{1:020d}.jsonl").exists()


def test_retention_refuses_a_corrupt_segment_and_still_prunes_valid_expired_ones(
    tmp_path: Path,
) -> None:
    # per-segment validation: one bit-rotted rotation is reported refused and left in place,
    # while the valid expired rotation around it still prunes — a single corrupt segment can
    # no longer turn retention off for the whole directory and drive unbounded growth
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.rotate(closed_at=_NOW)  # rotation 1: stays valid
    store.append(_event(_NOW + timedelta(minutes=1)))
    store.rotate(closed_at=_NOW + timedelta(minutes=2))  # rotation 2: gets corrupted
    store.close()
    corrupted = logs / f"structured-log.{2:020d}.jsonl"
    content = corrupted.read_bytes()
    corrupted.write_bytes(content[:-10] + b"tampered!\n")
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        report = retention_apply(
            logs_dir=logs,
            hold=hold,
            monotonic=_monotonic,
            retention_days=1,
            now=_NOW + timedelta(days=3650),
        )
    assert [segment.sequence for segment in report.segments] == [1]  # the valid one pruned
    assert [(refused.sequence, refused.code) for refused in report.refused] == [
        (2, "MH_LOG_RETENTION")
    ]
    assert not (logs / f"structured-log.{1:020d}.jsonl").exists()
    assert corrupted.exists()  # the refused segment is evidence: reported, never deleted


# --- line-format hardening (every fixed refusal branch) ------------------------------------------


def _header_line(sequence: int = 1, retention_days: int = 14) -> bytes:
    return structured_log_header_line(
        StructuredLogHeaderV1(sequence=sequence, opened_at=_NOW, retention_days=retention_days)
    )


def test_timestamp_parsing_refuses_non_canonical_values() -> None:
    for bad in (5, None, "2026-07-26T12:00:00Z", "2026-07-26 12:00:00.000Z", "not-a-stamp"):
        with pytest.raises(LoggingError) as captured:
            log_store_module._parse_timestamp(bad, "MH_LOG_HEADER")
        assert captured.value.code == "MH_LOG_HEADER"
    parsed = log_store_module._parse_timestamp("2026-07-26T12:00:00.000Z", "MH_LOG_HEADER")
    assert parsed == _NOW


def test_header_line_refusals_are_exhaustive() -> None:
    canonical = _header_line()
    payload = json.loads(canonical.decode())
    oversized = canonical[:-1] + b" " * 4096 + b"\n"
    wrong_keys = json.dumps({**payload, "extra": 1}, sort_keys=True).encode() + b"\n"
    wrong_line = json.dumps({**payload, "line": "event"}, sort_keys=True).encode() + b"\n"
    wrong_scope = json.dumps({**payload, "scope": "target"}, sort_keys=True).encode() + b"\n"
    non_int = json.dumps({**payload, "sequence": "1"}, sort_keys=True).encode() + b"\n"
    invalid_field = json.dumps({**payload, "sequence": -1}, sort_keys=True).encode() + b"\n"
    non_canonical = (
        json.dumps(payload, sort_keys=True, indent=1).replace("\n", " ").encode() + b"\n"
    )
    for bad in (
        oversized,
        b"not json\n",
        b"[1]\n",
        wrong_keys,
        wrong_line,
        wrong_scope,
        non_int,
        invalid_field,
        non_canonical,
    ):
        with pytest.raises(LoggingError) as captured:
            log_store_module._parse_header_line(bad)
        assert captured.value.code == "MH_LOG_HEADER"
    assert log_store_module._parse_header_line(canonical).sequence == 1


def test_event_line_refusals_are_exhaustive(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    current = logs / "structured-log.current.jsonl"
    event_line = current.read_bytes().split(b"\n")[1] + b"\n"
    payload = json.loads(event_line.decode())
    oversized = event_line[:-1] + b" " * 65536 + b"\n"
    wrong_keys = json.dumps({**payload, "extra": 1}, sort_keys=True).encode() + b"\n"
    wrong_line = json.dumps({**payload, "line": "header"}, sort_keys=True).encode() + b"\n"
    wrong_privacy = json.dumps({**payload, "privacy": "secret"}, sort_keys=True).encode() + b"\n"
    for bad in (oversized, b"junk\n", wrong_keys, wrong_line, wrong_privacy):
        with pytest.raises(LoggingError) as captured:
            log_store_module._validate_event_line(bad)
        assert captured.value.code == "MH_LOG_EVENT"
    assert log_store_module._validate_event_line(event_line) == _NOW


def test_trailer_detection_is_bounded_and_shape_checked() -> None:
    huge = b'{"line": "trailer", "pad": "' + b"x" * 8192 + b'"}\n'
    assert not log_store_module._is_trailer_line(huge)
    assert not log_store_module._is_trailer_line(b"not json\n")
    assert not log_store_module._is_trailer_line(b"[1, 2]\n")
    assert log_store_module._is_trailer_line(b'{"line": "trailer"}\n')


def test_bounded_reads_refuse_oversized_segments(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.write_bytes(b"x" * 64)
    descriptor = os.open(big, os.O_RDONLY)
    try:
        with pytest.raises(LoggingError) as captured:
            log_store_module._read_bounded(descriptor, 8, "MH_LOG_OPEN")
        assert captured.value.code == "MH_LOG_OPEN"
    finally:
        os.close(descriptor)


def test_active_splitting_refuses_degenerate_content() -> None:
    for bad in (b"", b"no final newline at all", b"header\n\nevent\n"):
        with pytest.raises(LoggingError) as captured:
            log_store_module._split_active(bad)
        assert captured.value.code == "MH_LOG_OPEN"
    header, events, torn = log_store_module._split_active(b"h\ne\ntail")
    assert (header, events, torn) == (b"h\n", [b"e\n"], b"tail")


def test_rotated_name_parsing_refuses_hostile_names() -> None:
    assert log_store_module._sequence_from_name("structured-log.current.jsonl") is None
    assert log_store_module._sequence_from_name("structured-log.123.jsonl") is None
    assert log_store_module._sequence_from_name("structured-log." + "a" * 20 + ".jsonl") is None
    arabic = "\u0661" * 20  # ARABIC-INDIC ONE: isdigit() but not isascii(); int() accepts it
    assert log_store_module._sequence_from_name(f"structured-log.{arabic}.jsonl") is None
    assert log_store_module._sequence_from_name("unrelated.jsonl") is None
    assert log_store_module._sequence_from_name(f"structured-log.{7:020d}.jsonl") == 7


def test_the_rotation_count_bound_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    for sequence in (1, 2, 3):
        name = logs / f"structured-log.{sequence:020d}.jsonl"
        name.write_bytes(b"{}\n")
        os.chmod(name, 0o600)
    monkeypatch.setattr(log_store_module, "MAX_ROTATIONS", 2)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_ROTATIONS"


# --- construction and append failure normalization -----------------------------------------------


def test_construction_validates_its_inputs_and_directory(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    for bad_retention in (0, -1, 3_651, True, "14"):
        with pytest.raises(LoggingError) as captured:
            StructuredLogStore(
                logs_dir=logs,
                retention_days=bad_retention,  # type: ignore[arg-type]
                monotonic=_monotonic,
                opened_at=_NOW,
            )
        assert captured.value.code == "MH_LOG_RETENTION"
    with pytest.raises(LoggingError) as missing:
        _store(tmp_path / "missing")
    assert missing.value.code == "MH_LOG_DIR"


def test_a_raw_read_failure_normalizes_to_a_fixed_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # an os.read failure inside active-segment validation must surface as MH_LOG_OPEN,
    # never as an uncoded OSError escaping the constructor
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()

    def _failing_read(_fd: int, _size: int) -> bytes:
        raise OSError(5, "planted read failure")

    monkeypatch.setattr(os, "read", _failing_read)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_OPEN"


def test_an_unexaminable_staging_name_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    real_stat = os.stat

    def _blocked_stat(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if target == ".structured-log.next.tmp" and kwargs.get("dir_fd") is not None:
            raise PermissionError(13, "planted stat failure")
        return real_stat(target, *args, **kwargs)

    monkeypatch.setattr(os, "stat", _blocked_stat)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_OPEN"


def test_the_append_descriptor_is_validated_and_normalized(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    current = logs / "structured-log.current.jsonl"
    try:
        os.chmod(current, 0o644)
        with pytest.raises(LoggingError) as loose:
            store._open_for_append()
        assert loose.value.code == "MH_LOG_FILE"
        os.chmod(current, 0o600)
        os.unlink(current)
        with pytest.raises(LoggingError) as absent:
            store._open_for_append()
        assert absent.value.code == "MH_LOG_OPEN"
    finally:
        store.close()


def test_an_event_without_a_timestamp_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    try:
        with pytest.raises(LoggingError) as captured:
            store._event_timestamp(object())  # type: ignore[arg-type]
        assert captured.value.code == "MH_LOG_EVENT"
    finally:
        store.close()


def test_append_write_failures_normalize_to_a_fixed_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    real_write = os.write
    mode: list[str] = []

    def _planted_write(fd: int, data: bytes) -> int:
        if mode and mode[0] == "short":
            mode.clear()
            return real_write(fd, data[:-1])
        if mode and mode[0] == "error":
            mode.clear()
            raise OSError(5, "planted write failure")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", _planted_write)
    try:
        mode.append("short")
        with pytest.raises(LoggingError) as short:
            store.append(_event())
        assert short.value.code == "MH_LOG_APPEND"
        # a failed append fails STOP: memory and disk diverged (a partial line is on disk), so
        # appending past it would compound the fragment into a complete malformed line
        with pytest.raises(LoggingError) as stopped:
            store.append(_event(records=2))
        assert stopped.value.code == "MH_LOG_CLOSED"
        # reopen refuses the torn fragment; recovery truncates it; the store then resumes
        with pytest.raises(LoggingError) as torn:
            _store(logs)
        assert torn.value.code == "MH_LOG_RECOVERY_REQUIRED"
        barrier = _hold_for(tmp_path)
        with barrier.exclusive() as hold:
            report = recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
        assert report.truncated_bytes > 0
        healed = _store(logs)
        mode.append("error")
        with pytest.raises(LoggingError) as errored:
            healed.append(_event(records=2))
        assert errored.value.code == "MH_LOG_APPEND"
        with pytest.raises(LoggingError) as errored_stop:
            healed.append(_event(records=3))
        assert errored_stop.value.code == "MH_LOG_CLOSED"
    finally:
        store.close()


def test_a_flush_failure_normalizes_to_a_fixed_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())

    def _failing_fsync(_fd: int) -> None:
        raise OSError(5, "planted fsync failure")

    monkeypatch.setattr(os, "fsync", _failing_fsync)
    try:
        with pytest.raises(LoggingError) as captured:
            store.flush()
        assert captured.value.code == "MH_LOG_APPEND"
    finally:
        store.close()  # the shutdown flush swallows the planted failure by design


def test_close_is_idempotent(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.close()
    store.close()  # a second close is a no-op, not an error


# --- rotation failure normalization --------------------------------------------------------------


def test_a_failed_publish_of_a_fresh_segment_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)

    def _failing_rename(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise OSError(5, "planted rename failure")

    monkeypatch.setattr(os, "rename", _failing_rename)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_ROTATE"


def test_rotation_write_and_link_failures_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    real_write = os.write
    real_link = os.link
    plant: list[str] = []

    def _planted_write(fd: int, data: bytes) -> int:
        if plant and plant[0] == "short-trailer" and data.startswith(b'{"closed_at"'):
            plant.clear()
            return real_write(fd, data[:-1])
        return real_write(fd, data)

    def _planted_link(*args, **kwargs):  # type: ignore[no-untyped-def]
        if plant and plant[0] == "link":
            plant.clear()
            raise OSError(5, "planted link failure")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "write", _planted_write)
    monkeypatch.setattr(os, "link", _planted_link)
    store = _store(logs)
    plant.append("short-trailer")
    with pytest.raises(LoggingError) as short:
        store.rotate(closed_at=_NOW)
    assert short.value.code == "MH_LOG_ROTATE"
    store.close()

    other = tmp_path / "other-logs"
    other.mkdir(mode=0o700)
    os.chmod(other, 0o700)
    second = _store(other)
    plant.append("link")
    with pytest.raises(LoggingError) as linkfail:
        second.rotate(closed_at=_NOW)
    assert linkfail.value.code == "MH_LOG_ROTATE"
    second.close()


def test_an_out_of_range_expiry_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    late = datetime(9999, 12, 25, tzinfo=UTC)
    store = _store(logs, opened_at=late)
    try:
        with pytest.raises(LoggingError) as captured:
            store.rotate(closed_at=late)
        assert captured.value.code == "MH_LOG_RETENTION"
    finally:
        store.close()


# --- recovery hardening --------------------------------------------------------------------------


def test_recovery_with_nothing_to_repair_reports_zero(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        report = recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert report == LogRecoveryReport(
        truncated_bytes=0, removed_staging=False, completed_rotation=False
    )


def test_recovery_refuses_a_symlinked_current(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    outside = tmp_path / "outside"
    outside.write_bytes(b"foreign\n")
    os.symlink(outside, logs / "structured-log.current.jsonl")
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"
    assert outside.read_bytes() == b"foreign\n"


def test_recovery_refuses_a_trailer_in_the_active_segment(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    rotated_like = (
        logs / "structured-log.current.jsonl"
    )  # append a trailer to the ACTIVE segment: an ambiguous crash artifact, not repairable
    trailer = structured_log_trailer_line(
        StructuredLogTrailerV1(
            sequence=1,
            closed_at=_NOW,
            last_event_at=_NOW,
            event_count=1,
            content_sha256="a" * 64,
            expires_at=_NOW + timedelta(days=14),
        )
    )
    with rotated_like.open("ab") as handle:
        handle.write(trailer)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"


def test_a_failed_truncation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    with (logs / "structured-log.current.jsonl").open("ab") as handle:
        handle.write(b'{"torn')  # a torn incomplete tail

    def _failing_ftruncate(_fd: int, _size: int) -> None:
        raise OSError(5, "planted truncate failure")

    monkeypatch.setattr(os, "ftruncate", _failing_ftruncate)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"


def test_an_unexaminable_staging_name_fails_recovery_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    barrier = _hold_for(tmp_path)
    real_stat = os.stat

    def _blocked_stat(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if target == ".structured-log.next.tmp" and kwargs.get("dir_fd") is not None:
            raise PermissionError(13, "planted stat failure")
        return real_stat(target, *args, **kwargs)

    monkeypatch.setattr(os, "stat", _blocked_stat)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"


def test_a_failed_staging_removal_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    staging = logs / ".structured-log.next.tmp"
    staging.write_bytes(b"{}\n")
    os.chmod(staging, 0o600)
    real_unlink = os.unlink

    def _failing_unlink(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if target == ".structured-log.next.tmp":
            raise OSError(5, "planted unlink failure")
        return real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _failing_unlink)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"


# --- retention hardening -------------------------------------------------------------------------


def _closed_rotation(tmp_path: Path) -> Path:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.rotate(closed_at=_NOW + timedelta(minutes=1))
    store.close()
    return logs


def test_retention_validates_its_policy_input(tmp_path: Path) -> None:
    logs = _closed_rotation(tmp_path)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            retention_preview(
                logs_dir=logs, hold=hold, monotonic=_monotonic, retention_days=0, now=_NOW
            )
    assert captured.value.code == "MH_LOG_RETENTION"


def _preview(logs, barrier, **overrides):  # type: ignore[no-untyped-def]
    kwargs = {"retention_days": 14, "now": _NOW}
    kwargs.update(overrides)
    with barrier.exclusive() as hold:
        return retention_preview(logs_dir=logs, hold=hold, monotonic=_monotonic, **kwargs)


def test_retention_refuses_a_loose_mode_closed_segment(tmp_path: Path) -> None:
    logs = _closed_rotation(tmp_path)
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    os.chmod(rotated, 0o644)
    report = _preview(logs, _hold_for(tmp_path))
    assert report.segments == ()
    assert [(r.sequence, r.code) for r in report.refused] == [(1, "MH_LOG_FILE")]


def test_retention_refuses_a_symlinked_closed_segment(tmp_path: Path) -> None:
    logs = _closed_rotation(tmp_path)
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    content = rotated.read_bytes()
    outside = tmp_path / "outside"
    outside.write_bytes(content)
    os.unlink(rotated)
    os.symlink(outside, rotated)
    report = _preview(logs, _hold_for(tmp_path))
    assert report.segments == ()
    assert [(r.sequence, r.code) for r in report.refused] == [(1, "MH_LOG_RETENTION")]
    assert outside.read_bytes() == content  # the symlink target was never followed for deletion


def test_retention_refuses_structural_damage_to_a_closed_segment(tmp_path: Path) -> None:
    logs = _closed_rotation(tmp_path)
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    pristine = rotated.read_bytes()
    barrier = _hold_for(tmp_path)
    header_only = pristine.split(b"\n")[0] + b"\n"
    for damaged in (pristine[:-1], header_only):  # no final LF; fewer than two lines
        rotated.write_bytes(damaged)
        os.chmod(rotated, 0o600)
        report = _preview(logs, barrier)
        assert report.segments == ()
        assert [(r.sequence, r.code) for r in report.refused] == [(1, "MH_LOG_RETENTION")]
        assert rotated.exists()  # refused, never deleted


def test_retention_refuses_a_sequence_name_disagreement(tmp_path: Path) -> None:
    logs = _closed_rotation(tmp_path)
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    os.rename(rotated, logs / f"structured-log.{2:020d}.jsonl")
    report = _preview(logs, _hold_for(tmp_path))
    assert report.segments == ()
    assert [(r.sequence, r.code) for r in report.refused] == [(2, "MH_LOG_RETENTION")]


def test_trailer_line_refusals_are_exhaustive(tmp_path: Path) -> None:
    header = StructuredLogHeaderV1(sequence=1, opened_at=_NOW, retention_days=14)
    digest_of_header = hashlib.sha256(structured_log_header_line(header)).hexdigest()
    canonical_trailer = StructuredLogTrailerV1(
        sequence=1,
        closed_at=_NOW,
        last_event_at=None,
        event_count=0,
        content_sha256=digest_of_header,
        expires_at=_NOW + timedelta(days=14),
    )
    canonical = structured_log_trailer_line(canonical_trailer)
    payload = json.loads(canonical.decode())
    oversized = canonical[:-1] + b" " * 8192 + b"\n"
    wrong_keys = json.dumps({**payload, "extra": 1}, sort_keys=True).encode() + b"\n"
    wrong_line = json.dumps({**payload, "line": "header"}, sort_keys=True).encode() + b"\n"
    non_int = json.dumps({**payload, "event_count": "0"}, sort_keys=True).encode() + b"\n"
    invalid_field = json.dumps({**payload, "content_sha256": "zz"}, sort_keys=True).encode() + b"\n"
    non_canonical = (
        json.dumps(payload, sort_keys=True, indent=1).replace("\n", " ").encode() + b"\n"
    )
    for bad in (oversized, wrong_keys, wrong_line, non_int, invalid_field, non_canonical):
        with pytest.raises(LoggingError) as captured:
            log_store_module._parse_trailer_line(bad, header, [])
        assert captured.value.code == "MH_LOG_RETENTION"
    # a canonical trailer whose counts disagree with the actual segment bytes is refused
    lying_trailer = StructuredLogTrailerV1(
        sequence=1,
        closed_at=_NOW,
        last_event_at=_NOW,
        event_count=1,
        content_sha256=digest_of_header,
        expires_at=_NOW + timedelta(days=14),
    )
    with pytest.raises(LoggingError) as disagreeing:
        log_store_module._parse_trailer_line(structured_log_trailer_line(lying_trailer), header, [])
    assert disagreeing.value.code == "MH_LOG_RETENTION"
    # and the intact canonical trailer parses
    parsed = log_store_module._parse_trailer_line(canonical, header, [])
    assert parsed.sequence == 1


def test_a_failed_expired_unlink_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs = _closed_rotation(tmp_path)
    barrier = _hold_for(tmp_path)
    real_unlink = os.unlink

    def _failing_unlink(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(target, str) and target.startswith("structured-log."):
            raise OSError(5, "planted unlink failure")
        return real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _failing_unlink)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            retention_apply(
                logs_dir=logs,
                hold=hold,
                monotonic=_monotonic,
                retention_days=14,
                now=_NOW + timedelta(days=365),
            )
    assert captured.value.code == "MH_LOG_RETENTION"
    assert (logs / f"structured-log.{1:020d}.jsonl").exists()  # nothing silently lost


# --- lock and envelope hardening -----------------------------------------------------------------


def test_a_symlinked_lock_name_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    outside = tmp_path / "outside-lock"
    outside.write_bytes(b"")
    os.symlink(outside, logs / "structured-log.lock")
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_LOCK"


def test_a_loose_mode_lock_file_fails_closed(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    lock = logs / "structured-log.lock"
    lock.write_bytes(b"")
    os.chmod(lock, 0o644)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_FILE"


def test_an_acl_probe_failure_on_a_log_file_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ANY acl-probe failure on a file — not just a typed refusal — normalizes to MH_LOG_FILE
    logs, _control = _state_root(tmp_path)
    real_check = log_store_module.require_no_extended_acl

    def _erroring_on_files(descriptor: int) -> None:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ValueError("planted probe failure")
        real_check(descriptor)

    monkeypatch.setattr(log_store_module, "require_no_extended_acl", _erroring_on_files)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_FILE"


def test_a_failed_staging_write_cleans_up_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a failure while the staging descriptor is still open takes the cleanup path, not a leak
    logs, _control = _state_root(tmp_path)

    def _failing_fsync(_fd: int) -> None:
        raise OSError(5, "planted fsync failure")

    monkeypatch.setattr(os, "fsync", _failing_fsync)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_ROTATE"


# --- adversarial-review regressions: retention prune vs reopen (P0) ------------------------------


def test_reopening_after_a_retention_prune_succeeds(tmp_path: Path) -> None:
    # the adversarial review's P0: pruning expired rotations must never brick the store — the
    # surviving rotated names bound the active sequence from below only
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.rotate(closed_at=_NOW + timedelta(minutes=1))
    store.append(_event(records=2))
    store.rotate(closed_at=_NOW + timedelta(minutes=2))
    store.close()  # rotations {1, 2}, active sequence 3
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        removed = retention_apply(
            logs_dir=logs,
            hold=hold,
            monotonic=_monotonic,
            retention_days=14,
            now=_NOW + timedelta(days=15),
        )
    assert [segment.sequence for segment in removed.segments] == [1, 2]  # every rotation pruned
    reopened = _store(logs)
    try:
        assert reopened.sequence == 3  # the active history survives the prune
        reopened.append(_event(records=3))
        reopened.rotate(closed_at=_NOW + timedelta(minutes=3))
        assert (logs / f"structured-log.{3:020d}.jsonl").exists()  # no sequence reuse
        assert reopened.sequence == 4
    finally:
        reopened.close()


def test_an_active_sequence_at_or_beneath_a_surviving_rotation_fails_closed(
    tmp_path: Path,
) -> None:
    # the attack the old check caught must STAY caught: an active sequence that collides with or
    # trails a surviving rotation implies forbidden reuse
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.rotate(closed_at=_NOW)
    store.close()  # rotation {1}, active sequence 2
    current = logs / "structured-log.current.jsonl"
    for stale_sequence in (1, 0):
        stale = structured_log_header_line(
            StructuredLogHeaderV1(
                sequence=max(stale_sequence, 1), opened_at=_NOW, retention_days=14
            )
        )
        current.write_bytes(stale)
        os.chmod(current, 0o600)
        with pytest.raises(LoggingError) as captured:
            _store(logs)
        assert captured.value.code == "MH_LOG_SEQUENCE"


# --- adversarial-review regressions: single-live-appender coherence (P1) -------------------------


def test_a_second_live_store_conflicts_instead_of_corrupting(tmp_path: Path) -> None:
    # the adversarial review reproduced silent corruption from two live stores; now the store
    # whose cached state went stale fails STOP before writing, and the survivor's rotation
    # certifies exactly the bytes on disk
    logs, _control = _state_root(tmp_path)
    first = _store(logs)
    first.append(_event())
    second = _store(logs)  # opens cleanly, caching the current state including first's event
    second.append(_event(records=2))  # coherent at this instant: succeeds
    with pytest.raises(LoggingError) as conflicted:
        first.append(_event(records=3))  # first's cached size is now stale
    assert conflicted.value.code == "MH_LOG_CONFLICT"
    with pytest.raises(LoggingError) as stopped:
        first.append(_event(records=4))  # fail stop: the loser never writes again
    assert stopped.value.code == "MH_LOG_CLOSED"
    second.rotate(closed_at=_NOW + timedelta(minutes=1))
    second.close()
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    lines = rotated.read_bytes().split(b"\n")[:-1]
    trailer = json.loads(lines[-1].decode())
    assert trailer["event_count"] == 2  # exactly the two events on disk — nothing lost
    assert trailer["content_sha256"] == hashlib.sha256(b"\n".join(lines[:-1]) + b"\n").hexdigest()
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        preview = retention_preview(
            logs_dir=logs, hold=hold, monotonic=_monotonic, retention_days=14, now=_NOW
        )
    assert [segment.sequence for segment in preview.segments] == [1]  # the segment validates


def test_a_stale_descriptor_after_a_foreign_rotation_conflicts(tmp_path: Path) -> None:
    # the review's second reproduction: a store whose current was rotated beneath it must never
    # write past the trailer of the now-immutable closed segment
    logs, _control = _state_root(tmp_path)
    first = _store(logs)
    first.append(_event())
    second = _store(logs)
    first.rotate(closed_at=_NOW + timedelta(minutes=1))
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    sealed = rotated.read_bytes()
    with pytest.raises(LoggingError) as conflicted:
        second.append(_event(records=2))  # cached descriptor no longer names current
    assert conflicted.value.code == "MH_LOG_CONFLICT"
    assert rotated.read_bytes() == sealed  # the closed segment is untouched
    first.append(_event(records=3))  # the surviving store continues normally
    assert first.event_count == 1
    first.close()


def test_an_externally_removed_current_conflicts(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    os.unlink(logs / "structured-log.current.jsonl")
    with pytest.raises(LoggingError) as captured:
        store.append(_event())
    assert captured.value.code == "MH_LOG_CONFLICT"


# --- adversarial-review regressions: interrupted-rotation recovery (P2) --------------------------


def _interrupt_rotation_before_link(
    logs: Path, monkeypatch: pytest.MonkeyPatch, *, events: int = 1
) -> StructuredLogStore:
    """Drive a rotation to the durable-trailer point, then fail its link deterministically."""

    store = _store(logs)
    for index in range(events):
        store.append(_event(records=index + 1))
    real_link = os.link
    plant: list[bool] = [True]

    def _failing_link(*args, **kwargs):  # type: ignore[no-untyped-def]
        if plant:
            plant.clear()
            raise OSError(5, "planted link failure")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "link", _failing_link)
    with pytest.raises(LoggingError) as captured:
        store.rotate(closed_at=_NOW + timedelta(minutes=1))
    assert captured.value.code == "MH_LOG_ROTATE"
    monkeypatch.setattr(os, "link", real_link)
    return store


def test_recovery_completes_a_rotation_interrupted_before_the_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the review's P2 wedge: a transient link failure mid-rotation must be recoverable, per the
    # plan's every-crash-boundary claim — the durable authentic trailer IS the rotation
    logs, _control = _state_root(tmp_path)
    store = _interrupt_rotation_before_link(logs, monkeypatch)
    with pytest.raises(LoggingError) as stopped:
        store.append(_event())  # the failed rotation poisoned the store: fail stop
    assert stopped.value.code == "MH_LOG_CLOSED"
    with pytest.raises(LoggingError) as reopened:
        _store(logs)
    assert reopened.value.code == "MH_LOG_RECOVERY_REQUIRED"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        report = recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert report.completed_rotation
    assert not (logs / "structured-log.current.jsonl").exists()
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    assert rotated.exists()
    with barrier.exclusive() as hold:
        preview = retention_preview(
            logs_dir=logs, hold=hold, monotonic=_monotonic, retention_days=14, now=_NOW
        )
    assert [segment.sequence for segment in preview.segments] == [1]  # validates post-completion
    healed = _store(logs)
    try:
        assert healed.sequence == 2  # the successor sequence, never a reuse
        healed.append(_event(records=9))
    finally:
        healed.close()


def test_recovery_completes_a_rotation_interrupted_before_the_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    real_unlink = os.unlink
    plant: list[bool] = [True]

    def _failing_unlink(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if plant and target == "structured-log.current.jsonl":
            plant.clear()
            raise OSError(5, "planted unlink failure")
        return real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _failing_unlink)
    with pytest.raises(LoggingError) as captured:
        store.rotate(closed_at=_NOW + timedelta(minutes=1))
    assert captured.value.code == "MH_LOG_ROTATE"
    monkeypatch.setattr(os, "unlink", real_unlink)
    # state: current and the rotated name are the SAME inode (nlink == 2)
    current = logs / "structured-log.current.jsonl"
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    assert os.lstat(current).st_ino == os.lstat(rotated).st_ino
    with pytest.raises(LoggingError) as reopened:
        _store(logs)
    assert reopened.value.code == "MH_LOG_RECOVERY_REQUIRED"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        report = recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert report.completed_rotation
    assert not current.exists()
    assert os.lstat(rotated).st_nlink == 1
    healed = _store(logs)
    try:
        assert healed.sequence == 2
    finally:
        healed.close()


def test_a_torn_tail_after_a_trailer_is_truncated_and_the_rotation_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    _interrupt_rotation_before_link(logs, monkeypatch)
    current = logs / "structured-log.current.jsonl"
    with current.open("ab") as handle:
        handle.write(b'{"torn')  # a fragment torn after the durable trailer
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        report = recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert report.truncated_bytes == len(b'{"torn')
    assert report.completed_rotation
    rotated = logs / f"structured-log.{1:020d}.jsonl"
    assert rotated.read_bytes().endswith(b"}\n")  # the fragment never reached the rotation
    assert not current.exists()


def test_recovery_refuses_a_squatted_rotated_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    _interrupt_rotation_before_link(logs, monkeypatch)
    squatter = logs / f"structured-log.{1:020d}.jsonl"
    squatter.write_bytes(b"occupied\n")
    os.chmod(squatter, 0o600)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    # a foreign occupant of the active's own rotated name is indistinguishable from forbidden
    # sequence reuse: refused BEFORE any mutation, with the open path's exact identity
    assert captured.value.code == "MH_LOG_SEQUENCE"
    assert squatter.read_bytes() == b"occupied\n"  # never replaced
    assert (logs / "structured-log.current.jsonl").exists()  # never unlinked


def test_a_two_link_active_segment_with_a_mismatched_twin_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    _interrupt_rotation_before_link(logs, monkeypatch)
    current = logs / "structured-log.current.jsonl"
    os.link(current, logs / "aside-name")  # nlink == 2, but the twin is NOT the rotated name
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"
    assert current.exists()


def test_a_foreign_extra_link_without_a_trailer_is_refused(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    current = logs / "structured-log.current.jsonl"
    os.link(current, logs / "foreign-name")
    with pytest.raises(LoggingError) as reopened:
        _store(logs)
    assert reopened.value.code == "MH_LOG_RECOVERY_REQUIRED"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_FILE"
    assert current.exists()


def test_a_triply_linked_active_segment_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    _interrupt_rotation_before_link(logs, monkeypatch)
    current = logs / "structured-log.current.jsonl"
    os.link(current, logs / "aside-one")
    os.link(current, logs / "aside-two")  # nlink == 3: beyond any interrupted-rotation shape
    with pytest.raises(LoggingError) as reopened:
        _store(logs)
    assert reopened.value.code == "MH_LOG_FILE"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_FILE"


def test_data_past_a_trailer_is_ambiguous_and_unrepairable(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    current = logs / "structured-log.current.jsonl"
    header_line, event_line = (part + b"\n" for part in current.read_bytes().split(b"\n")[:-1])
    current.write_bytes(header_line + b'{"line": "trailer"}\n' + event_line)
    os.chmod(current, 0o600)
    with pytest.raises(LoggingError) as reopened:
        _store(logs)
    assert reopened.value.code == "MH_LOG_AMBIGUOUS"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    # the SAME identity as the open path, so a caller can code-dispatch "permanently
    # unrepairable" and stop retrying recovery
    assert captured.value.code == "MH_LOG_AMBIGUOUS"


def test_a_mismatched_sequence_trailer_fails_authentication(tmp_path: Path) -> None:
    # a trailer whose bytes are canonical and whose digest agrees but whose SEQUENCE disagrees
    # with the header it sits under is a plant, not an interrupted rotation
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.close()
    current = logs / "structured-log.current.jsonl"
    header_line = current.read_bytes()
    forged = structured_log_trailer_line(
        StructuredLogTrailerV1(
            sequence=2,
            closed_at=_NOW,
            last_event_at=None,
            event_count=0,
            content_sha256=hashlib.sha256(header_line).hexdigest(),
            expires_at=_NOW + timedelta(days=14),
        )
    )
    current.write_bytes(header_line + forged)
    os.chmod(current, 0o600)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"
    assert current.exists()


def test_a_failed_rotation_completion_converges_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, _control = _state_root(tmp_path)
    _interrupt_rotation_before_link(logs, monkeypatch)
    real_unlink = os.unlink
    plant: list[bool] = [True]

    def _failing_unlink(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if plant and target == "structured-log.current.jsonl":
            plant.clear()
            raise OSError(5, "planted unlink failure")
        return real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _failing_unlink)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"
    # the rotated name is already durable; the retry adopts the same-inode twin and completes
    with barrier.exclusive() as hold:
        report = recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert report.completed_rotation
    assert not (logs / "structured-log.current.jsonl").exists()
    assert os.lstat(logs / f"structured-log.{1:020d}.jsonl").st_nlink == 1


# --- adversarial-review regression: path normalization (P3) --------------------------------------


def test_an_invalid_logs_dir_path_normalizes_to_a_fixed_code(tmp_path: Path) -> None:
    _logs, _control = _state_root(tmp_path)
    barrier = _hold_for(tmp_path)
    with pytest.raises(LoggingError) as constructing:
        StructuredLogStore(
            logs_dir=12345,  # type: ignore[arg-type]
            retention_days=14,
            monotonic=_monotonic,
            opened_at=_NOW,
        )
    assert constructing.value.code == "MH_LOG_DIR"
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as recovering:
            recover_structured_logs(logs_dir=12345, hold=hold, monotonic=_monotonic)  # type: ignore[arg-type]
        assert recovering.value.code == "MH_LOG_DIR"
        with pytest.raises(LoggingError) as previewing:
            retention_preview(
                logs_dir=12345,  # type: ignore[arg-type]
                hold=hold,
                monotonic=_monotonic,
                retention_days=14,
                now=_NOW,
            )
        assert previewing.value.code == "MH_LOG_DIR"
        with pytest.raises(LoggingError) as applying:
            retention_apply(
                logs_dir=12345,  # type: ignore[arg-type]
                hold=hold,
                monotonic=_monotonic,
                retention_days=14,
                now=_NOW,
            )
        assert applying.value.code == "MH_LOG_DIR"


def test_an_acl_probe_failure_on_the_active_segment_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the active-segment envelope normalizes ANY acl-probe failure, like every other log file
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    real_check = log_store_module.require_no_extended_acl

    def _erroring_on_the_segment(descriptor: int) -> None:
        info = os.fstat(descriptor)
        if stat.S_ISREG(info.st_mode) and info.st_size > 0:  # the lock file is empty
            raise ValueError("planted probe failure")
        real_check(descriptor)

    monkeypatch.setattr(log_store_module, "require_no_extended_acl", _erroring_on_the_segment)
    with pytest.raises(LoggingError) as captured:
        _store(logs)
    assert captured.value.code == "MH_LOG_FILE"


# --- verification-workflow regressions -----------------------------------------------------------


def test_recovery_refuses_a_conflicting_sequence_before_any_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the verification workflow's reproduction: a trailer-final current at sequence 1 with a
    # surviving rotation at 5 is forbidden reuse, not a crash artifact — no legitimate crash
    # schedule produces it; recovery must fail closed with the open path's exact identity and
    # mutate NOTHING (completing it would re-mint a pruned rotation's sequence)
    logs, _control = _state_root(tmp_path)
    _interrupt_rotation_before_link(logs, monkeypatch)  # authentic trailer-final at sequence 1
    current = logs / "structured-log.current.jsonl"
    frozen = current.read_bytes()
    survivor = logs / f"structured-log.{5:020d}.jsonl"
    survivor.write_bytes(b"{}\n")
    os.chmod(survivor, 0o600)
    with pytest.raises(LoggingError) as reopened:
        _store(logs)
    assert reopened.value.code == "MH_LOG_SEQUENCE"
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as recovering:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert recovering.value.code == "MH_LOG_SEQUENCE"
    assert current.read_bytes() == frozen  # zero mutation
    assert not (logs / f"structured-log.{1:020d}.jsonl").exists()  # nothing was linked


def test_recovery_refuses_to_truncate_under_a_conflicting_sequence(
    tmp_path: Path,
) -> None:
    # the torn-tail branch refuses the same conflict BEFORE its ftruncate mutation
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    store.close()
    current = logs / "structured-log.current.jsonl"
    with current.open("ab") as handle:
        handle.write(b'{"torn')
    frozen = current.read_bytes()
    survivor = logs / f"structured-log.{5:020d}.jsonl"
    survivor.write_bytes(b"{}\n")
    os.chmod(survivor, 0o600)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as recovering:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert recovering.value.code == "MH_LOG_SEQUENCE"
    assert current.read_bytes() == frozen  # the torn tail was NOT truncated


def test_a_hostile_pathlike_normalizes_to_a_fixed_code(tmp_path: Path) -> None:
    # the verification workflow's escape: a plain PathLike whose __fspath__ raises a
    # non-(OSError/TypeError/ValueError) exception must not leak uncoded from any entrypoint
    class _HostilePath:
        def __fspath__(self) -> str:
            raise RuntimeError("SECRET-FSPATH-DETAIL /var/secret/path")

    _logs, _control = _state_root(tmp_path)
    barrier = _hold_for(tmp_path)
    with pytest.raises(LoggingError) as constructing:
        StructuredLogStore(
            logs_dir=_HostilePath(),  # type: ignore[arg-type]
            retention_days=14,
            monotonic=_monotonic,
            opened_at=_NOW,
        )
    assert constructing.value.code == "MH_LOG_DIR"
    assert "SECRET" not in repr(constructing.value.args)
    assert constructing.value.__context__ is None and constructing.value.__cause__ is None
    with barrier.exclusive() as hold:
        for operation in (
            lambda h: recover_structured_logs(
                logs_dir=_HostilePath(),  # type: ignore[arg-type]
                hold=h,
                monotonic=_monotonic,
            ),
            lambda h: retention_preview(
                logs_dir=_HostilePath(),  # type: ignore[arg-type]
                hold=h,
                monotonic=_monotonic,
                retention_days=14,
                now=_NOW,
            ),
            lambda h: retention_apply(
                logs_dir=_HostilePath(),  # type: ignore[arg-type]
                hold=h,
                monotonic=_monotonic,
                retention_days=14,
                now=_NOW,
            ),
        ):
            with pytest.raises(LoggingError) as refused:
                operation(hold)
            assert refused.value.code == "MH_LOG_DIR"
            assert "SECRET" not in repr(refused.value.args)


def test_the_live_store_refuses_to_rotate_past_the_rotation_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the verification workflow's self-brick: creating the rotation that crosses MAX_ROTATIONS
    # would fail reopen AND retention with no API escape — the live store now refuses first,
    # fails stop, and retention retains its escape
    logs, _control = _state_root(tmp_path)
    monkeypatch.setattr(log_store_module, "MAX_ROTATIONS", 2)
    store = _store(logs)
    store.rotate(closed_at=_NOW)
    store.rotate(closed_at=_NOW + timedelta(minutes=1))  # at the bound: two rotations
    with pytest.raises(LoggingError) as refused:
        store.rotate(closed_at=_NOW + timedelta(minutes=2))
    assert refused.value.code == "MH_LOG_ROTATIONS"
    with pytest.raises(LoggingError) as stopped:
        store.append(_event())
    assert stopped.value.code == "MH_LOG_CLOSED"  # a refused rotation fails stop
    reopened = _store(logs)  # reopen still works: the bound was never crossed
    assert reopened.sequence == 3
    reopened.close()
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        removed = retention_apply(
            logs_dir=logs,
            hold=hold,
            monotonic=_monotonic,
            retention_days=14,
            now=_NOW + timedelta(days=365),
        )
    assert [segment.sequence for segment in removed.segments] == [1, 2]  # the API escape works
    resumed = _store(logs)
    try:
        resumed.rotate(closed_at=_NOW + timedelta(minutes=3))  # rotation resumes post-prune
        assert resumed.sequence == 4
    finally:
        resumed.close()


def test_an_empty_active_segment_fails_recovery_with_the_recovery_code(tmp_path: Path) -> None:
    logs, _control = _state_root(tmp_path)
    current = logs / "structured-log.current.jsonl"
    current.touch(mode=0o600)
    os.chmod(current, 0o600)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"  # recovery's own identity, not MH_LOG_OPEN


def test_an_unexaminable_twin_refuses_the_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # if the rotated-name occupant cannot be examined, it is never presumed to be our twin
    logs, _control = _state_root(tmp_path)
    store = _store(logs)
    store.append(_event())
    real_unlink = os.unlink
    plant: list[bool] = [True]

    def _failing_unlink(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if plant and target == "structured-log.current.jsonl":
            plant.clear()
            raise OSError(5, "planted unlink failure")
        return real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _failing_unlink)
    with pytest.raises(LoggingError):
        store.rotate(closed_at=_NOW + timedelta(minutes=1))  # nlink == 2 twin state
    monkeypatch.setattr(os, "unlink", real_unlink)
    rotated_name = f"structured-log.{1:020d}.jsonl"
    real_stat = os.stat

    def _blocked_stat(target, *args, **kwargs):  # type: ignore[no-untyped-def]
        if target == rotated_name and kwargs.get("dir_fd") is not None:
            raise PermissionError(13, "planted stat failure")
        return real_stat(target, *args, **kwargs)

    monkeypatch.setattr(os, "stat", _blocked_stat)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_SEQUENCE"
    assert (logs / "structured-log.current.jsonl").exists()  # zero mutation


def test_a_raced_squatter_at_link_time_is_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # defense in depth: even a squatter appearing BETWEEN the sequence check and the link
    # (impossible without same-user interference under the exclusive hold) is never replaced
    logs, _control = _state_root(tmp_path)
    store = _interrupt_rotation_before_link(logs, monkeypatch)
    store.close()
    real_link = os.link
    plant: list[bool] = [True]

    def _racing_link(*args, **kwargs):  # type: ignore[no-untyped-def]
        if plant:
            plant.clear()
            raise FileExistsError(17, "raced squatter")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "link", _racing_link)
    barrier = _hold_for(tmp_path)
    with barrier.exclusive() as hold:
        with pytest.raises(LoggingError) as captured:
            recover_structured_logs(logs_dir=logs, hold=hold, monotonic=_monotonic)
    assert captured.value.code == "MH_LOG_RECOVER"
    assert (logs / "structured-log.current.jsonl").exists()  # never unlinked
