"""Secure SQLite control-plane database open, pragmas, and transaction boundary (W03 slice 1).

The control database is the transactional control plane of ADR 0004 and plan section 4.4: it holds
ledgers, cursors, leases, projections, idempotency, migrations, and audit metadata, never raw
payloads. This module owns only the secure open and the transaction boundary; migrations,
leases, and
the global commit barrier live in sibling modules.

The database file is created ``0600`` with ``O_EXCL``/``O_NOFOLLOW`` inside an already-secured
private
parent directory, opened in write-ahead-logging mode with ``FULL`` synchronous durability and
enforced
foreign keys, and validated to be a non-symlink regular file with no group or world access. Every
failure raises a fixed :class:`StateError` outside the handler, so no SQLite or filesystem detail
leaks.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn

from milhouse.config.filesystem import SecureFileError, lexical_absolute_path
from milhouse.state.errors import StateError

_FILE_MODE = 0o600
_FORBIDDEN_MODE_BITS = 0o077
_BUSY_TIMEOUT_MS = 5_000


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


def _current_uid() -> int:
    getuid = getattr(os, "getuid", None)
    if getuid is None:  # pragma: no cover - Milhouse supports only POSIX hosts
        _fail("MH_STATE_UNSUPPORTED", "control state requires a POSIX ownership model")
    return int(getuid())


def _require_private_parent(parent: Path) -> None:
    info: os.stat_result | None
    try:
        info = os.lstat(parent)
    except OSError:
        info = None
    if (
        info is None
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != _current_uid()
        or (stat.S_IMODE(info.st_mode) & _FORBIDDEN_MODE_BITS)
    ):
        _fail("MH_STATE_DIR", "the control directory must be an owned private directory")


def _create_owner_only_file(path: Path) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    failed = False
    try:
        descriptor = os.open(path, flags, _FILE_MODE)
        os.fchmod(descriptor, _FILE_MODE)
    except OSError:
        failed = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if failed:
        _fail("MH_STATE_FILE", "the control database file could not be created owner-only")


def _ensure_secure_db_file(path: Path) -> bool:
    """Create the DB file owner-only if absent, else validate it; return whether it was created."""

    info: os.stat_result | None
    examine_failed = False
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        info = None
    except OSError:
        info = None
        examine_failed = True
    if examine_failed:
        _fail("MH_STATE_FILE", "the control database path could not be examined")
    if info is None:
        _create_owner_only_file(path)
        return True
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _fail("MH_STATE_FILE", "the control database must be a regular non-symlink file")
    if info.st_uid != _current_uid() or (stat.S_IMODE(info.st_mode) & _FORBIDDEN_MODE_BITS):
        _fail("MH_STATE_FILE", "the control database must be owner-only")
    return False


def _connect_wal(path: Path) -> sqlite3.Connection:
    connection: sqlite3.Connection | None = None
    journal_mode: object = None
    failed = False
    try:
        connection = sqlite3.connect(str(path), isolation_level=None, check_same_thread=True)
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        row = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        journal_mode = None if row is None else row[0]
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
    except sqlite3.Error:
        failed = True
    if failed:
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                pass
        _fail(
            "MH_STATE_OPEN", "the control database could not be opened in write-ahead-logging mode"
        )
    if type(journal_mode) is not str or journal_mode.lower() != "wal":
        connection.close()  # type: ignore[union-attr]
        _fail("MH_STATE_OPEN", "the control database must use write-ahead logging")
    return connection  # type: ignore[return-value]


class ControlDatabase:
    """A secured, WAL-mode SQLite control-plane connection with an explicit transaction boundary."""

    __slots__ = ("_closed", "_connection", "_created", "_path")

    def __init__(self, *, connection: sqlite3.Connection, path: Path, created: bool) -> None:
        self._connection = connection
        self._path = path
        self._created = created
        self._closed = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def created(self) -> bool:
        """True when this open created the database file, False when it reopened an existing one."""

        return self._created

    @property
    def connection(self) -> sqlite3.Connection:
        if self._closed:
            _fail("MH_STATE_CLOSED", "the control database is closed")
        return self._connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run one ``BEGIN IMMEDIATE`` transaction: commit on success, roll back on error.

        A caller exception rolls back and propagates unchanged. A SQLite begin/commit failure rolls
        back and raises a fixed ``MH_STATE_TXN`` outside the handler, never leaking SQLite detail.
        """

        connection = self.connection
        began = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            began = True
        except sqlite3.Error:
            began = False
        if not began:
            _fail("MH_STATE_TXN", "the control transaction could not begin")
        try:
            yield connection
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        committed = False
        try:
            connection.execute("COMMIT")
            committed = True
        except sqlite3.Error:
            committed = False
        if not committed:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            _fail("MH_STATE_TXN", "the control transaction could not commit")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._connection.close()
        except sqlite3.Error:
            pass


def _validated_database_path(database: object) -> Path | None:
    """Return the exact live main-database path for a genuine open control handle.

    ``ControlDatabase.path`` is descriptive metadata, not authority by itself. Bind it back to the
    live SQLite connection before another subsystem derives a state root or lock path from it, so a
    caller cannot wrap one database connection with another database's pathname.
    """

    if type(database) is not ControlDatabase:
        return None
    try:
        if object.__getattribute__(database, "_closed"):
            return None
        connection = object.__getattribute__(database, "_connection")
        claimed = lexical_absolute_path(object.__getattribute__(database, "_path"))
        if type(connection) is not sqlite3.Connection:
            return None
        rows = connection.execute("PRAGMA database_list").fetchall()
    except (AttributeError, OSError, SecureFileError, sqlite3.Error, TypeError, ValueError):
        return None
    main_paths = [
        row[2]
        for row in rows
        if len(row) >= 3 and row[1] == "main" and type(row[2]) is str and row[2]
    ]
    if len(main_paths) != 1:
        return None
    try:
        live = lexical_absolute_path(main_paths[0])
    except SecureFileError:
        return None
    return claimed if live == claimed else None


def open_control_database(path: str | Path) -> ControlDatabase:
    """Open (creating if absent) the SQLite control database under an already-secured private dir.

    The parent directory must already exist as an owned ``0700`` directory; the database file is
    created ``0600`` with ``O_EXCL``/``O_NOFOLLOW`` and opened in WAL mode with ``FULL`` synchronous
    and enforced foreign keys. Any failure raises a fixed :class:`StateError` outside the handler.
    """

    resolved = lexical_absolute_path(path)
    _require_private_parent(resolved.parent)
    created = _ensure_secure_db_file(resolved)
    connection = _connect_wal(resolved)
    return ControlDatabase(connection=connection, path=resolved, created=created)
