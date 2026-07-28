"""The global commit barrier: shared for durable writers, exclusive for maintenance (W03 slice 1).

Plan section 4.3 and ADR 0004 require every durable writer to hold the *shared* side of one global
commit barrier while backup, restore, migration, and declared maintenance take the *exclusive* side.
That is a cross-process readers-writer lock with writer preference: many writers coexist, and once a
maintainer is queued, new writers wait behind it while existing writers drain.

Both sides use ``fcntl.flock`` on a securely opened, read-only, no-follow descriptor validated as an
owner-only, single-link, regular file (reusing the W02 secure-open machinery). It is never reopened
for writing or truncated, so a stale, accidental, or hostile same-user hard link, symlink, or
loose-mode file can never turn acquisition into control-state destruction; unsafe files fail closed.
Writer preference is a two-file turnstile: a shared holder briefly takes the gate shared, takes the
main lock shared, then releases the gate; an exclusive holder holds the gate exclusive for its whole
duration, so later shared entrants block at the gate. The barrier is advisory, POSIX-only, and fails
closed without ``flock``; contention on a non-blocking acquisition raises ``MH_STATE_BARRIER_BUSY``.
"""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn

from milhouse.config.filesystem import (
    SecureFileError,
    SecureFileErrorKind,
    create_regular_file_no_follow,
    lexical_absolute_path,
    open_regular_file_no_follow,
)
from milhouse.state.errors import StateError

_LOCK_MODE = 0o600
_LOCK_SEED = b"milhouse-commit-barrier\n"
_GATE_SUFFIX = ".gate"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


def _current_uid() -> int:
    getuid = getattr(os, "getuid", None)
    if getuid is None:  # pragma: no cover - Milhouse supports only POSIX hosts
        _fail("MH_STATE_UNSUPPORTED", "the commit barrier requires a POSIX ownership model")
    return int(getuid())


def _create_lock_if_absent(path: Path) -> None:
    other_failure = False
    try:
        create_regular_file_no_follow(
            path, _LOCK_SEED, mode=_LOCK_MODE, require_private_parent=True
        )
    except SecureFileError as error:
        if error.kind is not SecureFileErrorKind.ALREADY_EXISTS:
            other_failure = True
    if other_failure:
        _fail("MH_STATE_BARRIER", "the commit barrier lock could not be created")


def _secure_lock_descriptor(path: Path) -> int:
    """Open the validated owner-only single-link lock file read-only, creating it if absent."""

    created = False
    while True:
        descriptor: int | None = None
        not_found = False
        open_failed = False
        try:
            descriptor = open_regular_file_no_follow(path, require_private_parent=True).descriptor
        except SecureFileError as error:
            not_found = error.kind is SecureFileErrorKind.NOT_FOUND
            open_failed = not not_found
        if open_failed:
            _fail("MH_STATE_BARRIER", "the commit barrier lock could not be securely opened")
        if not_found:
            if created:
                _fail("MH_STATE_BARRIER", "the commit barrier lock could not be securely opened")
            _create_lock_if_absent(path)
            created = True
            continue
        metadata = os.fstat(descriptor)  # type: ignore[arg-type]
        if (
            metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != _LOCK_MODE
            or metadata.st_uid != _current_uid()
        ):
            try:
                os.close(descriptor)  # type: ignore[arg-type]
            except OSError:
                pass
            _fail(
                "MH_STATE_BARRIER_UNSAFE",
                "the commit barrier lock must be an owner-only single-link regular file",
            )
        return descriptor  # type: ignore[return-value]


def _acquire(descriptor: int, operation: int, *, blocking: bool) -> None:
    mode = operation if blocking else operation | fcntl.LOCK_NB
    busy = False
    errored = False
    try:
        fcntl.flock(descriptor, mode)
    except BlockingIOError:
        busy = True
    except OSError:
        errored = True
    if errored:
        _fail("MH_STATE_BARRIER", "the commit barrier could not be acquired")
    if busy:
        _fail("MH_STATE_BARRIER_BUSY", "the commit barrier is held")


def _release(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:  # pragma: no cover - defensive: releasing our own flock does not fail
        pass


def _close(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:  # pragma: no cover - defensive: closing our own descriptor does not fail
        pass


class GlobalCommitBarrier:
    """A cross-process, writer-preferring readers-writer commit barrier over one lock file pair."""

    __slots__ = ("_gate_path", "_path")

    def __init__(self, lock_path: str | Path) -> None:
        if _NOFOLLOW == 0:  # pragma: no cover - Milhouse supports only no-follow POSIX hosts
            _fail("MH_STATE_UNSUPPORTED", "the commit barrier requires no-follow file support")
        self._path = lexical_absolute_path(lock_path)
        self._gate_path = self._path.with_name(self._path.name + _GATE_SUFFIX)

    @property
    def path(self) -> Path:
        return self._path

    @contextmanager
    def shared(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the shared writer side; shared holders coexist under writer preference."""

        main_fd = _secure_lock_descriptor(self._path)
        gate_fd: int | None = None
        gate_held = False
        main_held = False
        try:
            gate_fd = _secure_lock_descriptor(self._gate_path)
            _acquire(gate_fd, fcntl.LOCK_SH, blocking=blocking)
            gate_held = True
            _acquire(main_fd, fcntl.LOCK_SH, blocking=blocking)
            main_held = True
            _release(gate_fd)
            gate_held = False
            yield
        finally:
            if gate_held and gate_fd is not None:
                _release(gate_fd)
            if main_held:
                _release(main_fd)
            if gate_fd is not None:
                _close(gate_fd)
            _close(main_fd)

    @contextmanager
    def exclusive(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the exclusive side; block new shared entrants and drain existing ones."""

        main_fd = _secure_lock_descriptor(self._path)
        gate_fd: int | None = None
        gate_held = False
        main_held = False
        try:
            gate_fd = _secure_lock_descriptor(self._gate_path)
            _acquire(gate_fd, fcntl.LOCK_EX, blocking=blocking)
            gate_held = True
            _acquire(main_fd, fcntl.LOCK_EX, blocking=blocking)
            main_held = True
            yield
        finally:
            if main_held:
                _release(main_fd)
            if gate_held and gate_fd is not None:
                _release(gate_fd)
            if gate_fd is not None:
                _close(gate_fd)
            _close(main_fd)
