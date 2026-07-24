"""The global commit barrier: shared for durable writers, exclusive for maintenance (W03 slice 1).

Plan section 4.3 and ADR 0004 require every durable writer to hold the *shared* side of one global
commit barrier while backup, restore, migration, and declared maintenance take the *exclusive* side.
That is a cross-process readers-writer lock: many writers coexist, and the exclusive side waits for
all of them to release and blocks new ones.

The exclusive side is a ``filelock.FileLock`` (BSD ``flock`` ``LOCK_EX``); the shared side is
``fcntl.flock`` ``LOCK_SH`` on the same lock file. ``filelock`` exposes only exclusive locks, so it
cannot express the shared writer side alone, but both use BSD ``flock`` so they conflict correctly
across processes. The barrier is advisory, POSIX-only, and fails closed without ``flock``.
Contention on a non-blocking acquisition raises a fixed ``MH_STATE_BARRIER_BUSY``.
"""

from __future__ import annotations

import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn

from filelock import FileLock, Timeout

from milhouse.config.filesystem import lexical_absolute_path
from milhouse.state.errors import StateError

_LOCK_FILE_MODE = 0o600
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


class GlobalCommitBarrier:
    """A cross-process readers-writer commit barrier keyed by one advisory lock file."""

    __slots__ = ("_path",)

    def __init__(self, lock_path: str | Path) -> None:
        if _NOFOLLOW == 0:  # pragma: no cover - Milhouse supports only no-follow POSIX hosts
            _fail("MH_STATE_UNSUPPORTED", "the commit barrier requires no-follow file support")
        self._path = lexical_absolute_path(lock_path)

    @property
    def path(self) -> Path:
        return self._path

    def _ensure_lock_file(self) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | _NOFOLLOW | _CLOEXEC
        descriptor: int | None = None
        failed = False
        try:
            descriptor = os.open(self._path, flags, _LOCK_FILE_MODE)
        except FileExistsError:
            failed = False
        except OSError:
            failed = True
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if failed:
            _fail("MH_STATE_BARRIER", "the commit barrier lock could not be created")

    @contextmanager
    def shared(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the shared writer side; concurrent shared holders coexist."""

        self._ensure_lock_file()
        descriptor: int | None = None
        acquired = False
        try:
            try:
                descriptor = os.open(self._path, os.O_RDWR | _NOFOLLOW | _CLOEXEC)
            except OSError:
                descriptor = None
            if descriptor is None:
                _fail("MH_STATE_BARRIER", "the commit barrier lock could not be opened")
            mode = fcntl.LOCK_SH if blocking else fcntl.LOCK_SH | fcntl.LOCK_NB
            try:
                fcntl.flock(descriptor, mode)
                acquired = True
            except OSError:
                acquired = False
            if not acquired:
                _fail("MH_STATE_BARRIER_BUSY", "the shared commit barrier is exclusively held")
            yield
        finally:
            if descriptor is not None:
                if acquired:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    except OSError:
                        pass
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @contextmanager
    def exclusive(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the exclusive maintenance side; blocks until every shared holder releases."""

        self._ensure_lock_file()
        lock = FileLock(str(self._path))
        timed_out = False
        os_failed = False
        try:
            lock.acquire(blocking=blocking)
        except Timeout:
            timed_out = True
        except OSError:
            os_failed = True
        if os_failed:
            _fail("MH_STATE_BARRIER", "the exclusive commit barrier could not be acquired")
        if timed_out:
            _fail("MH_STATE_BARRIER_BUSY", "the exclusive commit barrier is held")
        try:
            yield
        finally:
            try:
                lock.release()
            except (OSError, RuntimeError):
                pass
