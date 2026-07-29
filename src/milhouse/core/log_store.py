"""Durable structured-log file surface: persist, rotate, recover, retain (W03, plan section 4.15).

W02 owns the stored wire (header/event/trailer line bytes, the ``local_log`` egress guard, and the
sink interface); this module owns the filesystem: the ``[paths].logs`` layout
(``structured-log.current.jsonl``, rotated ``structured-log.<20-digit-sequence>.jsonl``, the
``.structured-log.next.tmp`` staging file, and ``structured-log.lock``), descriptor-relative
no-follow close-on-exec access to owner-only ``0700``/``0600`` names, crash recovery, and retention.

:class:`StructuredLogStore` is the append surface. Opening it validates the directory envelope and
the entire active segment; a torn or ambiguous state fails closed with ``MH_LOG_RECOVERY_REQUIRED``
so appending past a crash artifact is impossible — recovery is an explicit maintenance operation,
never opt-in and never implicit. A successful append means one complete event line was written, not
that it is crash-durable; ``flush``, rotation, and ``close`` fsync the active descriptor. Rotation
happens before an append when the segment including its reserved trailer would exceed 8 MiB, when
the event's UTC day differs from the header's, or when the captured retention no longer matches the
store's policy — and explicitly via :meth:`rotate` — following the fixed order: fsync, trailer,
no-replace rename, directory fsync, next header staged to the temporary, publish, directory fsync.
Sequences are twenty decimal digits, never reused, and overflow fails closed.

:func:`recover_structured_logs` and :func:`retention_preview` / :func:`retention_apply` are
maintenance operations: they require the state root's own :class:`GlobalCommitBarrier` and take its
*exclusive* side themselves for the whole operation, honoring the lock order — global barrier
exclusive hold, then ``structured-log.lock``, then descriptors. Authority is the genuine exclusive
``flock``, never a caller-mintable token, so a barrier bound to any other lock path is refused.
Recovery truncates a torn incomplete active tail to its last complete line, completes an
interrupted rotation whose durable trailer authenticates against the exact bytes it certifies, and
removes a crashed pre-publish temporary — covering every write, fsync, and rename crash boundary —
while complete malformed lines, conflicting sequences, inauthentic trailers, and data past a
trailer fail closed. Retention deletes only validated closed
segments whose effective deadline — the captured trailer deadline, shortened but never extended by
the current policy — has passed, with a descriptor-bound unlink and a parent fsync; validation is
per segment, so a rotation that fails it is reported refused and left in place without blocking
the rest. Retention may prune any subset of rotations: surviving rotated names bound the active
sequence from below only, and a fully emptied logs directory is a fresh history starting at
sequence one; the live store refuses to create the rotation that would cross ``MAX_ROTATIONS``,
so the maintenance path always retains its API escape. The store is a SINGLE live appender: every
append and rotation revalidates, under the log lock, that its cached descriptor still names the
whole of ``current``; a second live store, or any stat-visible foreign mutation (a changed inode,
link count, or byte size), fails stop with ``MH_LOG_CONFLICT`` before any byte is written, so
cooperating stores can never corrupt a closed segment or silently lose an event. A same-user
tamperer rewriting bytes in place at the same size, or deleting the lock file mid-hold, is
outside what ``stat`` can distinguish; such tampering is detected fail-closed downstream, at
rotation certification and per-segment retention validation. Failures that reject an operation
WITHOUT mutating — lock contention (``MH_LOG_LOCK``), egress refusal (``MH_LOG_EVENT``), a closed
store (``MH_LOG_CLOSED``) — leave the store usable; any failed or conflicted MUTATION
(``MH_LOG_APPEND``, ``MH_LOG_ROTATE``, ``MH_LOG_ROTATIONS``, ``MH_LOG_CONFLICT``, a rotation
expiry failure) fails stop: the store closes itself and must be reconstructed, leaving a state
reopen or recovery re-derives from the durable bytes alone. Rotation triggers compare the
EVENT's timestamp against the header's opened UTC day, so an oscillating caller-supplied clock
spends one sequence per day flip — Milhouse's injected clock discipline keeps timestamps
non-decreasing.

Every failure is a fixed ``MH_LOG_*`` error raised outside any handler, so no filesystem, JSON, or
event detail reaches its cause, context, args, or traceback.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import NoReturn

from milhouse.config.filesystem import (
    lexical_absolute_path,
    require_no_extended_acl,
)
from milhouse.core.canonical import MAX_CANONICAL_INT
from milhouse.core.clock import TimeError, format_timestamp
from milhouse.core.log_wire import (
    MAX_EVENT_LINE_BYTES,
    MAX_HEADER_LINE_BYTES,
    MAX_TRAILER_LINE_BYTES,
    StructuredLogHeaderV1,
    StructuredLogTrailerV1,
    structured_log_event_line,
    structured_log_header_line,
    structured_log_trailer_line,
)
from milhouse.core.logging import LoggingError, StructuredLogEventV1
from milhouse.state.barrier import GlobalCommitBarrier, _is_bound_barrier

_LF = b"\n"
_CURRENT_NAME = "structured-log.current.jsonl"
_STAGING_NAME = ".structured-log.next.tmp"
_LOCK_NAME = "structured-log.lock"
_BARRIER_NAME = "commit.lock"
_CONTROL_DIR = "control"
_ROTATED_PREFIX = "structured-log."
_ROTATED_SUFFIX = ".jsonl"
_SEQUENCE_DIGITS = 20
_DIR_MODE = 0o700
_FILE_MODE = 0o600
MAX_SEGMENT_BYTES = 8 * 1024 * 1024  # including the reserved trailer line
MAX_ROTATIONS = 10_000
LOCK_WAIT_SECONDS = 5.0
_LOCK_POLL_SECONDS = 0.05
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def _fail(code: str, message: str) -> NoReturn:
    raise LoggingError(code, message)


def _current_uid() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # pragma: no cover - Milhouse supports only POSIX hosts
        _fail("MH_LOG_UNSUPPORTED", "the log store requires a POSIX ownership model")
    return int(geteuid())


def _require_platform() -> None:
    if _NOFOLLOW == 0:  # pragma: no cover - Milhouse supports only no-follow POSIX hosts
        _fail("MH_LOG_UNSUPPORTED", "the log store requires no-follow file support")


def _resolve_logs_dir(logs_dir: str | Path) -> Path:
    """Resolve the logs directory path, normalizing an invalid input to a fixed code."""

    failed = False
    resolved: Path | None = None
    try:
        resolved = lexical_absolute_path(logs_dir)
    except Exception:
        # a hostile PathLike can raise ANYTHING from __fspath__ during Path();
        # every resolution failure normalizes to the fixed code, no exception escapes uncoded
        failed = True
    if failed or resolved is None:
        _fail("MH_LOG_DIR", "the logs directory path is invalid")
    return resolved


def _open_logs_dir(logs_dir: Path) -> int:
    """Open the logs directory as an owned, exact-0700, ACL-free no-follow descriptor."""

    unsafe = False
    descriptor: int | None = None
    try:
        descriptor = os.open(logs_dir, os.O_RDONLY | _NOFOLLOW | _DIRECTORY | _CLOEXEC)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _current_uid()
            or stat.S_IMODE(info.st_mode) != _DIR_MODE
        ):
            unsafe = True
        else:
            require_no_extended_acl(descriptor)
    except Exception:
        unsafe = True
    if unsafe:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                pass
        _fail("MH_LOG_DIR", "the logs directory must be an owned, ACL-free 0o700 directory")
    assert descriptor is not None
    return descriptor


def _require_live_directory(directory_fd: int, logs_dir: Path, code: str) -> None:
    """Require the configured logs path to still name the held directory descriptor.

    A directory swap after open would otherwise silently redirect every descriptor-relative
    write outside ``[paths].logs`` while the API reports success — the held descriptor follows
    the renamed directory. Every mutation and maintenance operation re-proves the live binding
    under the log lock before touching anything (POSIX offers no bind-and-operate, so the
    one-syscall residual window is closed to cooperating processes by that lock).
    """

    bound = False
    probe: int | None = None
    try:
        probe = os.open(logs_dir, os.O_RDONLY | _NOFOLLOW | _DIRECTORY | _CLOEXEC)
        held = os.fstat(directory_fd)
        live = os.fstat(probe)
        bound = (held.st_dev, held.st_ino) == (live.st_dev, live.st_ino)
    except OSError:
        bound = False
    finally:
        if probe is not None:
            try:
                os.close(probe)
            except OSError:  # pragma: no cover - defensive close failure
                bound = False
    if not bound:
        _fail(code, "the configured logs directory no longer names the held descriptor")


def _open_regular_at(directory_fd: int, name: str, *, flags: int) -> int:
    """Open a name beneath the held directory descriptor, no-follow and close-on-exec."""

    return os.open(name, flags | _NOFOLLOW | _CLOEXEC, mode=_FILE_MODE, dir_fd=directory_fd)


def _require_private_file(descriptor: int) -> None:
    """Require an opened log file to be an owned, exact-0600, single-link regular file."""

    unsafe = False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != _current_uid()
            or stat.S_IMODE(info.st_mode) != _FILE_MODE
            or info.st_nlink != 1
        ):
            unsafe = True
        else:
            require_no_extended_acl(descriptor)
    except Exception:
        unsafe = True
    if unsafe:
        _fail("MH_LOG_FILE", "a log file must be an owned, single-link, ACL-free 0o600 file")


def _examine_active_envelope(descriptor: int) -> os.stat_result:
    """Envelope-check the opened ACTIVE segment, tolerating an interrupted rotation's extra link.

    Exactly :func:`_require_private_file` except that ``st_nlink == 2`` is admitted: a crash or
    failure between rotation's no-replace link and its unlink leaves the active inode durably
    under both its current and rotated names — a state recovery completes. Every other shape
    (including any further link count) fails closed.
    """

    unsafe = False
    info: os.stat_result | None = None
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != _current_uid()
            or stat.S_IMODE(info.st_mode) != _FILE_MODE
            or info.st_nlink not in (1, 2)
        ):
            unsafe = True
        else:
            require_no_extended_acl(descriptor)
    except Exception:
        unsafe = True
    if unsafe or info is None:
        _fail("MH_LOG_FILE", "a log file must be an owned, single-link, ACL-free 0o600 file")
    return info


class _LogLock:
    """The ``structured-log.lock`` flock: five seconds on injected monotonic time, polled with
    an injected sleeper so contention never busy-spins a core."""

    __slots__ = ("_directory_fd", "_monotonic", "_sleeper")

    def __init__(
        self,
        directory_fd: int,
        monotonic: Callable[[], float],
        sleeper: Callable[[float], None],
    ) -> None:
        self._directory_fd = directory_fd
        self._monotonic = monotonic
        self._sleeper = sleeper

    def acquire(self) -> int:
        failed = False
        timed_out = False
        descriptor: int | None = None
        try:
            descriptor = _open_regular_at(
                self._directory_fd, _LOCK_NAME, flags=os.O_RDWR | os.O_CREAT
            )
            _require_private_file(descriptor)
            deadline = self._monotonic() + LOCK_WAIT_SECONDS
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if self._monotonic() >= deadline:
                        timed_out = True
                        break
                    self._sleeper(_LOCK_POLL_SECONDS)
        except LoggingError:
            # _require_private_file is the only LoggingError source, so the descriptor is open
            assert descriptor is not None
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                pass
            raise
        except OSError:
            failed = True
        if failed or timed_out or descriptor is None:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:  # pragma: no cover - defensive close failure
                    pass
            _fail("MH_LOG_LOCK", "the structured-log lock could not be acquired")
        return descriptor

    def release(self, descriptor: int) -> None:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:  # pragma: no cover - defensive unlock failure
            pass
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive close failure
            pass


def _parse_line_object(line: bytes, code: str) -> dict[str, object]:
    failed = False
    value: object = None
    try:
        value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        failed = True
    if failed or type(value) is not dict:
        _fail(code, "a structured-log line must be a single JSON object")
    return value


_HEADER_KEYS = frozenset({"line", "opened_at", "retention_days", "schema", "scope", "sequence"})
_EVENT_KEYS = frozenset(
    {"error", "fingerprint", "level", "line", "metrics", "name", "privacy", "schema", "ts"}
)
_TRAILER_KEYS = frozenset(
    {
        "closed_at",
        "content_sha256",
        "event_count",
        "expires_at",
        "last_event_at",
        "line",
        "schema",
        "sequence",
    }
)


def _parse_timestamp(value: object, code: str) -> datetime:
    invalid = False
    parsed: datetime | None = None
    if type(value) is not str:
        invalid = True
    else:
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            invalid = True
    if invalid or parsed is None:
        _fail(code, "a canonical UTC millisecond timestamp is required")
    from datetime import UTC

    return parsed.replace(tzinfo=UTC)


def _parse_header_line(line: bytes) -> StructuredLogHeaderV1:
    if len(line) > MAX_HEADER_LINE_BYTES:
        _fail("MH_LOG_HEADER", "the header line exceeds its byte bound")
    payload = _parse_line_object(line, "MH_LOG_HEADER")
    if frozenset(payload) != _HEADER_KEYS:
        _fail("MH_LOG_HEADER", "the header line has an unexpected field set")
    if payload["line"] != "header" or payload["schema"] != 1 or payload["scope"] != "installation":
        _fail("MH_LOG_HEADER", "the header line is not a v1 installation header")
    sequence = payload["sequence"]
    retention = payload["retention_days"]
    if type(sequence) is not int or type(retention) is not int:
        _fail("MH_LOG_HEADER", "the header carries non-integer fields")
    opened_at = _parse_timestamp(payload["opened_at"], "MH_LOG_HEADER")
    invalid = False
    header: StructuredLogHeaderV1 | None = None
    try:
        header = StructuredLogHeaderV1(
            sequence=sequence, opened_at=opened_at, retention_days=retention
        )
    except LoggingError:
        invalid = True
    if invalid or header is None:
        _fail("MH_LOG_HEADER", "the header line fails field validation")
    if structured_log_header_line(header) != line:
        _fail("MH_LOG_HEADER", "the header line is not canonical")
    return header


def _validate_event_line(line: bytes) -> datetime:
    """Structurally validate one complete stored event line; return its timestamp.

    Complete lines must be well formed — recovery repairs only a torn INCOMPLETE tail, so a
    malformed complete line fails closed here, per section 4.15.
    """

    if len(line) > MAX_EVENT_LINE_BYTES:
        _fail("MH_LOG_EVENT", "an event line exceeds its byte bound")
    payload = _parse_line_object(line, "MH_LOG_EVENT")
    if frozenset(payload) != _EVENT_KEYS:
        _fail("MH_LOG_EVENT", "an event line has an unexpected field set")
    if payload["line"] != "event" or payload["schema"] != 1 or payload["privacy"] != "internal":
        _fail("MH_LOG_EVENT", "an event line is not a v1 internal event")
    return _parse_timestamp(payload["ts"], "MH_LOG_EVENT")


def _is_trailer_line(line: bytes) -> bool:
    if len(line) > MAX_TRAILER_LINE_BYTES:
        return False
    try:
        value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False
    return type(value) is dict and value.get("line") == "trailer"


def _read_bounded(descriptor: int, bound: int, code: str) -> bytes:
    info = os.fstat(descriptor)
    if info.st_size > bound:
        _fail(code, "a log segment exceeds its byte bound")
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1 << 20)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _split_active(
    content: bytes, code: str = "MH_LOG_OPEN"
) -> tuple[bytes, list[bytes], bytes | None]:
    """Split active-segment bytes into header line, event lines, and any torn tail."""

    if not content:
        _fail(code, "the active segment is empty")
    torn: bytes | None = None
    body = content
    if not content.endswith(_LF):
        # a torn, incomplete final write: everything past the last LF is the recoverable tail
        cut = content.rfind(_LF)
        if cut < 0:
            _fail(code, "the active segment has no complete line")
        body, torn = content[: cut + 1], content[cut + 1 :]
    parts = body.split(_LF)[:-1]
    lines = [part + _LF for part in parts]
    if any(part == b"" for part in parts):
        _fail(code, "the active segment contains a blank line")
    return lines[0], lines[1:], torn


def _sequence_from_name(name: str) -> int | None:
    if not (name.startswith(_ROTATED_PREFIX) and name.endswith(_ROTATED_SUFFIX)):
        return None
    stem = name[len(_ROTATED_PREFIX) : -len(_ROTATED_SUFFIX)]
    if stem == "current":
        return None
    if len(stem) != _SEQUENCE_DIGITS or not stem.isascii() or not stem.isdigit():
        return None
    return int(stem)


def _rotated_name(sequence: int) -> str:
    return f"{_ROTATED_PREFIX}{sequence:0{_SEQUENCE_DIGITS}d}{_ROTATED_SUFFIX}"


def _list_rotated(directory_fd: int) -> dict[int, str]:
    rotated: dict[int, str] = {}
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            sequence = _sequence_from_name(entry.name)
            if sequence is not None:
                rotated[sequence] = entry.name
                if len(rotated) > MAX_ROTATIONS:
                    _fail("MH_LOG_ROTATIONS", "the rotation count exceeds its bound")
    return rotated


def _require_logs_barrier(barrier: GlobalCommitBarrier, logs_dir: Path) -> None:
    """Require the state root's own commit barrier before maintenance takes its exclusive side.

    The logs directory is a runtime child of the state root, whose control-plane commit lock is
    ``<state_root>/control/commit.lock``. Maintenance authority is the genuine exclusive ``flock``
    of THAT barrier — acquired by the caller of ``barrier.exclusive()`` below, never a mintable
    token — so a barrier bound to any other lock path, or any non-barrier object, is not authority
    here and fails closed before a descriptor is opened.
    """

    expected = lexical_absolute_path(logs_dir).parent / _CONTROL_DIR / _BARRIER_NAME
    if not _is_bound_barrier(barrier, expected):
        _fail("MH_LOG_AUTHORITY", "maintenance requires a live exclusive hold of this state root")


class StructuredLogStore:
    """The durable append surface for the installation's structured operational log.

    Construction validates the directory envelope and the whole active segment, creating a fresh
    first segment when none exists. A torn tail, a leftover staging file, a final durable trailer,
    or a linked active segment fails closed with ``MH_LOG_RECOVERY_REQUIRED`` (all four are
    completable crash artifacts), while a sequence conflict (``MH_LOG_SEQUENCE``) and data past a
    trailer (``MH_LOG_AMBIGUOUS``) are not crash artifacts and stay unrepairable — so a crash
    artifact can never be appended past. Appends take only the structured-log lock (global barrier
    authority, when the caller holds it for its own operation, is passed through, never reacquired
    here) and revalidate cached state under it, failing stop with ``MH_LOG_CONFLICT`` if the
    active segment changed beneath the store.
    """

    __slots__ = (
        "_closed",
        "_descriptor",
        "_digest",
        "_directory_fd",
        "_event_count",
        "_header",
        "_last_event_at",
        "_lock",
        "_logs_dir",
        "_retention_days",
        "_size",
    )

    def __init__(
        self,
        *,
        logs_dir: str | Path,
        retention_days: int,
        monotonic: Callable[[], float],
        opened_at: datetime,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        _require_platform()
        if type(retention_days) is not int or not 1 <= retention_days <= 3_650:
            _fail("MH_LOG_RETENTION", "a bounded positive retention is required")
        self._logs_dir = _resolve_logs_dir(logs_dir)
        self._retention_days = retention_days
        self._closed = False
        self._directory_fd = _open_logs_dir(self._logs_dir)
        self._lock = _LogLock(self._directory_fd, monotonic, sleeper)
        lock_fd = self._lock.acquire()
        try:
            self._open_active(opened_at)
        except BaseException:
            self._lock.release(lock_fd)
            try:
                os.close(self._directory_fd)
            except OSError:  # pragma: no cover - defensive close failure
                pass
            raise
        self._lock.release(lock_fd)

    # -- construction ----------------------------------------------------------------------------

    def _open_active(self, opened_at: datetime) -> None:
        if self._staging_exists():
            _fail("MH_LOG_RECOVERY_REQUIRED", "a staging file is present; run log recovery")
        rotated = _list_rotated(self._directory_fd)
        highest = max(rotated) if rotated else 0
        exists = True
        try:
            descriptor = _open_regular_at(self._directory_fd, _CURRENT_NAME, flags=os.O_RDONLY)
        except FileNotFoundError:
            exists = False
        except OSError:
            _fail("MH_LOG_OPEN", "the active segment could not be opened")
        if not exists:
            self._start_segment(highest + 1, opened_at)
            return
        failed_validation: str | None = None
        content = b""
        info: os.stat_result | None = None
        try:
            info = _examine_active_envelope(descriptor)
            content = _read_bounded(descriptor, MAX_SEGMENT_BYTES, "MH_LOG_OPEN")
        except OSError:
            # normalized: a raw read failure must not escape as an uncoded OSError
            failed_validation = "MH_LOG_OPEN"
        finally:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                failed_validation = "MH_LOG_OPEN"
        if failed_validation is not None:
            _fail(failed_validation, "the active segment could not be read")
        assert info is not None
        if info.st_nlink != 1:
            # rotation linked the rotated name but never unlinked current: recovery completes it
            _fail(
                "MH_LOG_RECOVERY_REQUIRED",
                "an interrupted rotation left a linked active segment; run log recovery",
            )
        header_line, event_lines, torn = _split_active(content)
        if torn is not None:
            _fail("MH_LOG_RECOVERY_REQUIRED", "the active segment has a torn tail; run recovery")
        header = _parse_header_line(header_line)
        if header.sequence <= highest:
            # retention prunes rotations, so the surviving rotated names bound the active
            # sequence from BELOW only; an active sequence at or beneath a surviving rotation
            # implies forbidden sequence reuse and is not repairable
            _fail("MH_LOG_SEQUENCE", "the active sequence conflicts with the rotations")
        last_event_at: datetime | None = None
        for index, line in enumerate(event_lines):
            if _is_trailer_line(line):
                if index == len(event_lines) - 1:
                    # rotation durably wrote its trailer but the rename never completed
                    _fail(
                        "MH_LOG_RECOVERY_REQUIRED",
                        "an interrupted rotation left a trailer in the active segment; "
                        "run log recovery",
                    )
                # data past a trailer is never a crash artifact: appends stop at rotation, so
                # this is evidence of foreign writes into a closed history — not repairable
                _fail("MH_LOG_AMBIGUOUS", "the active segment carries data past a trailer")
            last_event_at = _validate_event_line(line)
        digest = hashlib.sha256()
        digest.update(header_line)
        for line in event_lines:
            digest.update(line)
        self._header = header
        self._event_count = len(event_lines)
        self._last_event_at = last_event_at
        self._size = len(content)
        self._digest = digest
        self._descriptor = self._open_for_append()

    def _staging_exists(self) -> bool:
        try:
            os.stat(_STAGING_NAME, dir_fd=self._directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            _fail("MH_LOG_OPEN", "the staging name could not be examined")
        return True

    def _open_for_append(self) -> int:
        failed = False
        descriptor: int | None = None
        try:
            descriptor = _open_regular_at(
                self._directory_fd, _CURRENT_NAME, flags=os.O_WRONLY | os.O_APPEND
            )
            _require_private_file(descriptor)
        except LoggingError:
            # _require_private_file is the only LoggingError source, so the descriptor is open
            assert descriptor is not None
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                pass
            raise
        except OSError:
            failed = True
        if failed or descriptor is None:
            _fail("MH_LOG_OPEN", "the active segment could not be opened for append")
        return descriptor

    def _start_segment(self, sequence: int, opened_at: datetime) -> None:
        if sequence > MAX_CANONICAL_INT:
            _fail("MH_LOG_OVERFLOW", "the log sequence space is exhausted")
        header = StructuredLogHeaderV1(
            sequence=sequence, opened_at=opened_at, retention_days=self._retention_days
        )
        header_line = structured_log_header_line(header)
        failed = False
        descriptor: int | None = None
        try:
            descriptor = _open_regular_at(
                self._directory_fd, _STAGING_NAME, flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL
            )
            if os.write(descriptor, header_line) != len(header_line):
                # a short header write must never be published as a successful segment
                failed = True
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if not failed:
                os.rename(
                    _STAGING_NAME,
                    _CURRENT_NAME,
                    src_dir_fd=self._directory_fd,
                    dst_dir_fd=self._directory_fd,
                )
                os.fsync(self._directory_fd)
        except OSError:
            failed = True
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:  # pragma: no cover - defensive close failure
                    failed = True
        if failed:
            _fail("MH_LOG_ROTATE", "a fresh active segment could not be published")
        digest = hashlib.sha256()
        digest.update(header_line)
        self._header = header
        self._event_count = 0
        self._last_event_at = None
        self._size = len(header_line)
        self._digest = digest
        self._descriptor = self._open_for_append()

    # -- append path -----------------------------------------------------------------------------

    def append(self, event: StructuredLogEventV1) -> None:
        """Append one event line, rotating first when a rotation trigger applies.

        A successful return means one complete line was appended, not that it is crash-durable;
        call :meth:`flush` (or rely on rotation/close) for durability.
        """

        self._require_open()
        line = structured_log_event_line(event)  # the egress guard runs before any byte is written
        event_at = self._event_timestamp(event)
        lock_fd = self._lock.acquire()
        try:
            self._require_coherent()
            if self._rotation_due(len(line), event_at):
                self._rotate_locked(event_at)
            self._write_line(line, event_at)
        except LoggingError:
            # fail stop: a failed or conflicted mutation leaves memory and disk divergent, and
            # appending past it would compound the damage into complete malformed lines that
            # recovery must refuse; reopen/recovery re-derive a consistent state from the bytes
            self._poison()
            raise
        finally:
            self._lock.release(lock_fd)

    def _require_coherent(self) -> None:
        """Under the log lock, require the cached descriptor to still be the whole of current.

        The append path caches the active descriptor, byte size, and running digest. If the
        cached inode no longer names ``current``, gained a hard link, or the on-disk size
        disagrees with the cached size, some other live store or process appended or rotated in
        between — continuing would write past the trailer of an immutable closed segment or
        certify a trailer that disagrees with the bytes. The store fails stop with a fixed
        conflict code instead, so exactly one live appender survives and closed segments are
        never corrupted.
        """

        _require_live_directory(self._directory_fd, self._logs_dir, "MH_LOG_CONFLICT")
        conflicted = False
        try:
            cached = os.fstat(self._descriptor)
            named = os.stat(_CURRENT_NAME, dir_fd=self._directory_fd, follow_symlinks=False)
            if (
                (cached.st_dev, cached.st_ino) != (named.st_dev, named.st_ino)
                or cached.st_nlink != 1
                or cached.st_size != self._size
            ):
                conflicted = True
        except OSError:
            conflicted = True
        if conflicted:
            _fail("MH_LOG_CONFLICT", "the active segment changed beneath this store")

    def _poison(self) -> None:
        """Fail stop after a failed or conflicted mutation.

        Memory and disk may diverge, so the store closes itself: later appends raise
        ``MH_LOG_CLOSED`` instead of compounding on-disk damage, and reopen or recovery
        re-derive a consistent state from the durable bytes alone.
        """

        self._closed = True
        self._close_descriptor()
        self._close_directory()

    def _event_timestamp(self, event: StructuredLogEventV1) -> datetime:
        timestamp = getattr(event, "timestamp", None)
        if not isinstance(timestamp, datetime):
            _fail("MH_LOG_EVENT", "a structured event carries a canonical timestamp")
        return timestamp

    def _rotation_due(self, line_length: int, event_at: datetime) -> bool:
        if self._size + line_length + MAX_TRAILER_LINE_BYTES > MAX_SEGMENT_BYTES:
            return True
        if event_at.date() != self._header.opened_at.date():
            return True  # the UTC day changed
        return self._header.retention_days != self._retention_days

    def _write_line(self, line: bytes, event_at: datetime) -> None:
        failed = False
        try:
            written = os.write(self._descriptor, line)
            if written != len(line):
                failed = True
        except OSError:
            failed = True
        if failed:
            _fail("MH_LOG_APPEND", "an event line could not be appended")
        self._size += len(line)
        self._event_count += 1
        self._last_event_at = event_at
        self._digest.update(line)

    def rotate(self, *, closed_at: datetime) -> None:
        """Rotate the active segment now (the maintenance-due trigger)."""

        self._require_open()
        lock_fd = self._lock.acquire()
        try:
            self._require_coherent()
            self._rotate_locked(closed_at)
        except LoggingError:
            self._poison()  # fail stop, exactly as a failed append
            raise
        finally:
            self._lock.release(lock_fd)

    def _rotate_locked(self, closed_at: datetime) -> None:
        # the maintenance path (_list_rotated) fails closed past MAX_ROTATIONS, so creating the
        # rotation that crosses the bound would brick reopen AND retention with no API escape;
        # the live store refuses first, leaving retention able to prune
        if len(_list_rotated(self._directory_fd)) >= MAX_ROTATIONS:
            _fail("MH_LOG_ROTATIONS", "the rotation count is at its bound; run retention first")
        expires_at = self._expiry(self._header.opened_at, self._header.retention_days)
        trailer = StructuredLogTrailerV1(
            sequence=self._header.sequence,
            closed_at=closed_at,
            last_event_at=self._last_event_at,
            event_count=self._event_count,
            content_sha256=self._digest.hexdigest(),
            expires_at=expires_at,
        )
        trailer_line = structured_log_trailer_line(trailer)
        rotated_name = _rotated_name(self._header.sequence)
        failed = False
        try:
            os.fsync(self._descriptor)
            written = os.write(self._descriptor, trailer_line)
            if written != len(trailer_line):
                failed = True
            else:
                os.fsync(self._descriptor)
                os.close(self._descriptor)
                self._descriptor = -1  # a later fail-stop close must never hit a reused number
                # no-replace rename: link the current name to its rotated name, then unlink
                os.link(
                    _CURRENT_NAME,
                    rotated_name,
                    src_dir_fd=self._directory_fd,
                    dst_dir_fd=self._directory_fd,
                )
                # the rotated name is durable BEFORE current is removed, so no crash point
                # loses the only filesystem name for the closed segment (the recovery helper
                # already used this order; the live path now matches it)
                os.fsync(self._directory_fd)
                os.unlink(_CURRENT_NAME, dir_fd=self._directory_fd)
                os.fsync(self._directory_fd)
        except OSError:
            failed = True
        if failed:
            _fail("MH_LOG_ROTATE", "the active segment could not be rotated")
        self._start_segment(self._header.sequence + 1, closed_at)

    def _expiry(self, opened_at: datetime, retention_days: int) -> datetime:
        invalid = False
        deadline: datetime | None = None
        try:
            deadline = opened_at + timedelta(days=retention_days)
            format_timestamp(deadline)
        except (OverflowError, TimeError):
            invalid = True
        if invalid or deadline is None:
            _fail("MH_LOG_RETENTION", "the segment expiry is out of range")
        return deadline

    def flush(self) -> None:
        """Make every appended line crash-durable."""

        self._require_open()
        failed = False
        try:
            os.fsync(self._descriptor)
        except OSError:
            failed = True
        if failed:
            # after a failed fsync the durable state of buffered lines is unknowable: fail stop
            self._poison()
            _fail("MH_LOG_APPEND", "the active segment could not be flushed")

    def close(self) -> None:
        """Fsync and release every descriptor; the store cannot be used afterwards."""

        if self._closed:
            return
        self._closed = True
        for closer in (self._flush_quietly, self._close_descriptor, self._close_directory):
            closer()

    def _flush_quietly(self) -> None:
        try:
            os.fsync(self._descriptor)
        except OSError:  # pragma: no cover - defensive shutdown flush
            pass

    def _close_descriptor(self) -> None:
        try:
            os.close(self._descriptor)
        except OSError:  # pragma: no cover - defensive close failure
            pass

    def _close_directory(self) -> None:
        try:
            os.close(self._directory_fd)
        except OSError:  # pragma: no cover - defensive close failure
            pass

    def _require_open(self) -> None:
        if self._closed:
            _fail("MH_LOG_CLOSED", "the log store is closed")

    @property
    def sequence(self) -> int:
        return self._header.sequence

    @property
    def event_count(self) -> int:
        return self._event_count


# -- maintenance: recovery ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LogRecoveryReport:
    """The outcome of one structured-log recovery pass (fixed reasons only)."""

    truncated_bytes: int
    removed_staging: bool
    completed_rotation: bool


def recover_structured_logs(
    *,
    logs_dir: str | Path,
    barrier: GlobalCommitBarrier,
    monotonic: Callable[[], float],
    sleeper: Callable[[float], None] = time.sleep,
) -> LogRecoveryReport:
    """Repair crash artifacts under exclusive maintenance authority.

    Three crash artifacts are repairable, covering every write, fsync, and rename boundary of
    the append and rotation paths per section 4.15: a torn INCOMPLETE active tail is truncated
    back to its last complete line (fsyncing the file); an INTERRUPTED ROTATION — the trailer is
    durably the final complete line and authenticates against the header and event bytes it
    certifies (canonical form, sequence, event count, and content digest all agree) but the
    no-replace rename never completed — is finished by linking the rotated name (or adopting the
    already-linked same-inode twin) and unlinking current, so the next open starts the successor
    segment; and a crashed pre-publish staging file is removed. A trailer that fails
    authentication, data past a trailer (``MH_LOG_AMBIGUOUS``, the same identity the open path
    assigns that exact state), a foreign extra hard link, complete malformed lines, and
    conflicting sequences (``MH_LOG_SEQUENCE``, checked against the surviving rotations BEFORE
    any mutation in every branch) are NOT crash artifacts and fail closed.
    """

    _require_platform()
    resolved = _resolve_logs_dir(logs_dir)
    _require_logs_barrier(barrier, resolved)
    with barrier.exclusive():
        directory_fd = _open_logs_dir(resolved)
        lock = _LogLock(directory_fd, monotonic, sleeper)
        lock_fd = lock.acquire()
        try:
            _require_live_directory(directory_fd, resolved, "MH_LOG_DIR")
            truncated, completed = _repair_active(directory_fd)
            removed = _remove_staging(directory_fd)
            return LogRecoveryReport(
                truncated_bytes=truncated, removed_staging=removed, completed_rotation=completed
            )
        finally:
            lock.release(lock_fd)
            try:
                os.close(directory_fd)
            except OSError:  # pragma: no cover - defensive close failure
                pass


def _repair_active(directory_fd: int) -> tuple[int, bool]:
    """Repair the active segment; return (truncated tail bytes, whether a rotation completed)."""

    exists = True
    descriptor: int | None = None
    try:
        descriptor = _open_regular_at(directory_fd, _CURRENT_NAME, flags=os.O_RDWR)
    except FileNotFoundError:
        exists = False
    except OSError:
        _fail("MH_LOG_RECOVER", "the active segment could not be opened for recovery")
    if not exists:
        return (0, False)
    assert descriptor is not None
    failed = False
    truncated = 0
    completed = False
    try:
        info = _examine_active_envelope(descriptor)
        content = _read_bounded(descriptor, MAX_SEGMENT_BYTES, "MH_LOG_RECOVER")
        header_line, body_lines, torn = _split_active(content, "MH_LOG_RECOVER")
        header = _parse_header_line(header_line)
        rotated = _list_rotated(directory_fd)
        highest = max(rotated, default=0)
        conflicted = header.sequence < highest
        if not conflicted and header.sequence == highest:
            # the ONE legitimate shape at the boundary: rotation's link completed (the rotated
            # name at the active's own sequence is the SAME inode) but the unlink did not; any
            # other occupant of that name means forbidden sequence reuse
            twin_is_self = False
            try:
                twin = os.stat(rotated[highest], dir_fd=directory_fd, follow_symlinks=False)
                twin_is_self = (twin.st_dev, twin.st_ino) == (info.st_dev, info.st_ino)
            except OSError:
                twin_is_self = False
            conflicted = not twin_is_self
        if conflicted:
            # mirror the open path's invariant BEFORE any mutation: an active sequence beneath
            # a surviving rotation (or colliding with a foreign occupant of its own rotated
            # name) is forbidden reuse, never a crash artifact — no legitimate crash schedule
            # produces it, so its trailer is a plant and completing it would re-mint a pruned
            # rotation's sequence
            _fail("MH_LOG_SEQUENCE", "the active sequence conflicts with the rotations")
        trailer_at = next(
            (index for index, line in enumerate(body_lines) if _is_trailer_line(line)), None
        )
        if trailer_at is not None and trailer_at != len(body_lines) - 1:
            # appends stop at rotation, so bytes past a trailer are foreign writes into a
            # closed history, never a crash artifact: fail closed with the same identity the
            # open path assigns this exact state, so a caller can code-dispatch "permanently
            # unrepairable" and stop retrying recovery
            _fail("MH_LOG_AMBIGUOUS", "the active segment carries data past a trailer")
        if trailer_at is None:
            if info.st_nlink != 1:
                # an extra hard link without a rotation trailer is not an interrupted rotation
                _fail("MH_LOG_FILE", "the active segment carries a foreign extra hard link")
            for line in body_lines:
                _validate_event_line(line)
            if torn is not None:
                os.ftruncate(descriptor, len(content) - len(torn))
                os.fsync(descriptor)
                os.fsync(directory_fd)
                truncated = len(torn)
        else:
            event_lines = body_lines[:-1]
            for line in event_lines:
                _validate_event_line(line)
            authentic = True
            trailer: StructuredLogTrailerV1 | None = None
            try:
                trailer = _parse_trailer_line(body_lines[-1], header, event_lines)
            except LoggingError:
                authentic = False
            if not authentic or trailer is None or trailer.sequence != header.sequence:
                # only rotation writes a trailer, and it certifies exactly these bytes: a
                # trailer that fails canonical, sequence, count, or digest agreement is a
                # plant, not a crash artifact
                _fail("MH_LOG_RECOVER", "the trailer in the active segment fails authentication")
            if torn is not None:
                # the crash tore a write AFTER the durable trailer (the staged next header
                # never published): drop the fragment, the trailer stays the final line
                os.ftruncate(descriptor, len(content) - len(torn))
                os.fsync(descriptor)
                truncated = len(torn)
            _complete_rotation(directory_fd, header.sequence, info)
            completed = True
    except LoggingError:
        raise
    except OSError:
        failed = True
    finally:
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive close failure
            failed = True
    if failed:
        _fail("MH_LOG_RECOVER", "the active segment could not be repaired")
    return (truncated, completed)


def _complete_rotation(directory_fd: int, sequence: int, info: os.stat_result) -> None:
    """Finish an interrupted rotation: durably name the rotated segment, then unlink current.

    When the crash happened after rotation's link (the active inode already carries two names),
    the existing rotated entry must be that SAME inode; any other occupant of the rotated name
    is a squatter and nothing is linked or unlinked. The rotated name is made durable with a
    directory fsync BEFORE current is removed, so no crash point loses the only name.
    """

    rotated = _rotated_name(sequence)
    blocked = False
    failed = False
    try:
        if info.st_nlink == 2:
            # the link already happened; the second name must be our rotated twin
            matched = False
            try:
                existing = os.stat(rotated, dir_fd=directory_fd, follow_symlinks=False)
                matched = (existing.st_dev, existing.st_ino) == (info.st_dev, info.st_ino)
            except OSError:
                matched = False
            blocked = not matched
        else:
            try:
                os.link(
                    _CURRENT_NAME,
                    rotated,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                # current has one link, so the occupant cannot be our twin: never replace it
                blocked = True
        if not blocked:
            os.fsync(directory_fd)  # the rotated name is durable BEFORE current is removed
            os.unlink(_CURRENT_NAME, dir_fd=directory_fd)
            os.fsync(directory_fd)
    except OSError:
        failed = True
    if blocked:
        _fail("MH_LOG_RECOVER", "the rotated name for the interrupted rotation is unavailable")
    if failed:
        _fail("MH_LOG_RECOVER", "the interrupted rotation could not be completed")


def _remove_staging(directory_fd: int) -> bool:
    try:
        os.stat(_STAGING_NAME, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        _fail("MH_LOG_RECOVER", "the staging name could not be examined")
    failed = False
    try:
        os.unlink(_STAGING_NAME, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError:
        failed = True
    if failed:
        _fail("MH_LOG_RECOVER", "the crashed staging file could not be removed")
    return True


# -- maintenance: retention -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RetainedSegment:
    """One validated closed rotation with its captured and effective deadlines."""

    sequence: int
    expires_at: datetime
    effective_expires_at: datetime
    expired: bool


@dataclass(frozen=True, slots=True)
class RefusedSegment:
    """One closed rotation retention refused to certify, with its fixed failure code.

    A refused rotation is REPORTED and left exactly in place — it is never deleted (its bytes
    are the only evidence of what happened to it) and it never blocks the validated segments
    around it from being previewed or pruned, so one bit-rotted rotation cannot turn retention
    off for the whole directory and drive unbounded growth toward the rotation-count bound.
    """

    sequence: int
    code: str


@dataclass(frozen=True, slots=True)
class RetentionReport:
    """The outcome of one retention pass.

    ``segments`` holds every VALIDATED rotation (for preview) or exactly the validated expired
    rotations that were removed (for apply); ``refused`` holds the per-segment fixed failure
    codes for rotations that failed validation and were left untouched.
    """

    segments: tuple[RetainedSegment, ...]
    refused: tuple[RefusedSegment, ...]


def retention_preview(
    *,
    logs_dir: str | Path,
    barrier: GlobalCommitBarrier,
    monotonic: Callable[[], float],
    retention_days: int,
    now: datetime,
    sleeper: Callable[[float], None] = time.sleep,
) -> RetentionReport:
    """List closed rotations with their effective deadlines; mutates nothing.

    The effective deadline is the captured trailer deadline shortened — never extended — by the
    current policy: a tightening may shorten an unexpired deadline, but a later relaxation never
    extends an already captured one. Validation is PER SEGMENT: a rotation that fails it is
    reported in ``refused`` with its fixed code and never blocks the rest.
    """

    _require_platform()
    resolved = _resolve_logs_dir(logs_dir)
    _require_logs_barrier(barrier, resolved)
    with barrier.exclusive():
        directory_fd = _open_logs_dir(resolved)
        lock = _LogLock(directory_fd, monotonic, sleeper)
        lock_fd = lock.acquire()
        try:
            _require_live_directory(directory_fd, resolved, "MH_LOG_DIR")
            report, _validated = _preview_locked(directory_fd, retention_days, now)
            return report
        finally:
            lock.release(lock_fd)
            try:
                os.close(directory_fd)
            except OSError:  # pragma: no cover - defensive close failure
                pass


def _preview_locked(
    directory_fd: int, retention_days: int, now: datetime
) -> tuple[RetentionReport, dict[int, tuple[int, int, int, int, int]]]:
    if type(retention_days) is not int or not 1 <= retention_days <= 3_650:
        _fail("MH_LOG_RETENTION", "a bounded positive retention is required")
    rotated = _list_rotated(directory_fd)
    segments: list[RetainedSegment] = []
    refused: list[RefusedSegment] = []
    validated: dict[int, tuple[int, int, int, int, int]] = {}
    for sequence in sorted(rotated):
        code: str | None = None
        header: StructuredLogHeaderV1 | None = None
        trailer: StructuredLogTrailerV1 | None = None
        identity: tuple[int, int, int, int, int] | None = None
        try:
            header, trailer, identity = _read_closed_segment(
                directory_fd, rotated[sequence], sequence
            )
        except LoggingError as error:
            code = error.code  # a fixed MH_LOG_* code, value-safe by construction
        if code is not None or header is None or trailer is None or identity is None:
            refused.append(RefusedSegment(sequence=sequence, code=code or "MH_LOG_RETENTION"))
            continue
        validated[sequence] = identity
        policy_deadline = header.opened_at + timedelta(days=retention_days)
        effective = min(trailer.expires_at, policy_deadline)
        segments.append(
            RetainedSegment(
                sequence=sequence,
                expires_at=trailer.expires_at,
                effective_expires_at=effective,
                expired=effective <= now,
            )
        )
    return RetentionReport(segments=tuple(segments), refused=tuple(refused)), validated


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """The identity retention carries from validation to unlink: device, inode, size, times."""

    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_closed_segment(
    directory_fd: int, name: str, sequence: int
) -> tuple[StructuredLogHeaderV1, StructuredLogTrailerV1, tuple[int, int, int, int, int]]:
    failed = False
    descriptor: int | None = None
    content = b""
    identity: tuple[int, int, int, int, int] | None = None
    try:
        descriptor = _open_regular_at(directory_fd, name, flags=os.O_RDONLY)
        _require_private_file(descriptor)
        content = _read_bounded(descriptor, MAX_SEGMENT_BYTES, "MH_LOG_RETENTION")
        identity = _file_identity(os.fstat(descriptor))
    except LoggingError:
        raise
    except OSError:
        failed = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                failed = True
    if failed or identity is None or not content.endswith(_LF):
        _fail("MH_LOG_RETENTION", "a closed segment could not be read")
    parts = content.split(_LF)[:-1]
    if len(parts) < 2 or any(part == b"" for part in parts):
        _fail("MH_LOG_RETENTION", "a closed segment is structurally invalid")
    header = _parse_header_line(parts[0] + _LF)
    trailer = _parse_trailer_line(parts[-1] + _LF, header, [part + _LF for part in parts[1:-1]])
    if header.sequence != sequence or trailer.sequence != sequence:
        _fail("MH_LOG_RETENTION", "a closed segment's sequence disagrees with its name")
    return header, trailer, identity


def _parse_trailer_line(
    line: bytes, header: StructuredLogHeaderV1, event_lines: list[bytes]
) -> StructuredLogTrailerV1:
    if len(line) > MAX_TRAILER_LINE_BYTES:
        _fail("MH_LOG_RETENTION", "the trailer line exceeds its byte bound")
    payload = _parse_line_object(line, "MH_LOG_RETENTION")
    if frozenset(payload) != _TRAILER_KEYS:
        _fail("MH_LOG_RETENTION", "the trailer line has an unexpected field set")
    if payload["line"] != "trailer" or payload["schema"] != 1:
        _fail("MH_LOG_RETENTION", "the trailer line is not a v1 trailer")
    for line_bytes in event_lines:
        _validate_event_line(line_bytes)
    digest = hashlib.sha256()
    digest.update(structured_log_header_line(header))
    for line_bytes in event_lines:
        digest.update(line_bytes)
    sequence = payload["sequence"]
    count = payload["event_count"]
    if type(sequence) is not int or type(count) is not int:
        _fail("MH_LOG_RETENTION", "the trailer carries non-integer fields")
    closed_at = _parse_timestamp(payload["closed_at"], "MH_LOG_RETENTION")
    expires_at = _parse_timestamp(payload["expires_at"], "MH_LOG_RETENTION")
    last_event_raw = payload["last_event_at"]
    last_event_at = (
        None if last_event_raw is None else _parse_timestamp(last_event_raw, "MH_LOG_RETENTION")
    )
    invalid = False
    trailer: StructuredLogTrailerV1 | None = None
    try:
        trailer = StructuredLogTrailerV1(
            sequence=sequence,
            closed_at=closed_at,
            last_event_at=last_event_at,
            event_count=count,
            content_sha256=str(payload["content_sha256"]),
            expires_at=expires_at,
        )
    except LoggingError:
        invalid = True
    if invalid or trailer is None:
        _fail("MH_LOG_RETENTION", "the trailer line fails field validation")
    if structured_log_trailer_line(trailer) != line:
        _fail("MH_LOG_RETENTION", "the trailer line is not canonical")
    if trailer.event_count != len(event_lines) or trailer.content_sha256 != digest.hexdigest():
        _fail("MH_LOG_RETENTION", "the trailer disagrees with the segment bytes")
    # A05 fixes the captured deadline as EXACTLY opened_at + retention_days: the trailer is
    # outside content_sha256, so a one-field corruption could otherwise shorten the deadline
    # and erase valid history early — the deadline must re-derive from the header, bounded
    deadline_invalid = False
    expected_deadline: datetime | None = None
    try:
        expected_deadline = header.opened_at + timedelta(days=header.retention_days)
        format_timestamp(expected_deadline)
    except (OverflowError, TimeError):
        deadline_invalid = True
    if deadline_invalid or expected_deadline is None:
        _fail("MH_LOG_RETENTION", "the captured deadline is out of range")
    if trailer.expires_at != expected_deadline:
        _fail("MH_LOG_RETENTION", "the trailer deadline disagrees with the header")
    return trailer


def retention_apply(
    *,
    logs_dir: str | Path,
    barrier: GlobalCommitBarrier,
    monotonic: Callable[[], float],
    retention_days: int,
    now: datetime,
    sleeper: Callable[[float], None] = time.sleep,
) -> RetentionReport:
    """Delete expired, fully validated closed rotations; return exactly what was removed.

    Only validated closed segments whose effective deadline has passed are deleted, with a
    descriptor-bound unlink and a parent fsync. A rotation that fails validation is reported in
    ``refused`` and left exactly in place — never deleted, and never blocking the validated
    segments around it. The active segment is never deleted here; rotate it first if it must be
    retired.
    """

    _require_platform()
    resolved = _resolve_logs_dir(logs_dir)
    _require_logs_barrier(barrier, resolved)
    with barrier.exclusive():
        directory_fd = _open_logs_dir(resolved)
        lock = _LogLock(directory_fd, monotonic, sleeper)
        lock_fd = lock.acquire()
        try:
            _require_live_directory(directory_fd, resolved, "MH_LOG_DIR")
            preview, validated = _preview_locked(directory_fd, retention_days, now)
            removed: list[RetainedSegment] = []
            refused = list(preview.refused)
            for segment in preview.segments:
                if not segment.expired:
                    continue
                if _unlink_verified(
                    directory_fd, _rotated_name(segment.sequence), validated[segment.sequence]
                ):
                    removed.append(segment)
                else:
                    # the name no longer resolves to the exact object whose expiry was proven: the
                    # replacement is left byte-for-byte intact and the sequence is NOT claimed
                    # removed — reported refused instead
                    refused.append(
                        RefusedSegment(sequence=segment.sequence, code="MH_LOG_RETENTION")
                    )
            return RetentionReport(segments=tuple(removed), refused=tuple(refused))
        finally:
            lock.release(lock_fd)
            try:
                os.close(directory_fd)
            except OSError:  # pragma: no cover - defensive close failure
                pass


def _unlink_verified(
    directory_fd: int, name: str, identity: tuple[int, int, int, int, int]
) -> bool:
    """Delete one expired rotation ONLY if the name still resolves to the validated object.

    The name is re-opened no-follow and its full identity (device, inode, size, mtime, ctime)
    plus the private-file envelope compared against what validation certified; any drift —
    replacement, rewrite, extra link, mode or ACL change — returns False and the occupant is
    left untouched (POSIX offers no compare-and-unlink, so the one-syscall window that remains
    is closed to cooperating processes by the log lock held across preview and apply). A
    verified unlink that then fails raises the fixed retention code.
    """

    descriptor: int | None = None
    verified = False
    try:
        descriptor = _open_regular_at(directory_fd, name, flags=os.O_RDONLY)
        _require_private_file(descriptor)
        verified = _file_identity(os.fstat(descriptor)) == identity
    except (LoggingError, OSError):
        verified = False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                verified = False
    if not verified:
        return False
    failed = False
    try:
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError:
        failed = True
    if failed:
        _fail("MH_LOG_RETENTION", "an expired segment could not be removed")
    return True


__all__ = [
    "LOCK_WAIT_SECONDS",
    "MAX_ROTATIONS",
    "MAX_SEGMENT_BYTES",
    "LogRecoveryReport",
    "RefusedSegment",
    "RetainedSegment",
    "RetentionReport",
    "StructuredLogStore",
    "recover_structured_logs",
    "retention_apply",
    "retention_preview",
]
