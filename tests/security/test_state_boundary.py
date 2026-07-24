"""Fail-closed boundary tests for the W03 control-plane state (secure open, migrations, barrier).

These inject filesystem and SQLite failures and assert every path fails closed with a fixed
``MH_STATE_*`` error and no leaked SQLite or OS detail in the error's cause, context, or args.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.state import (
    ControlDatabase,
    GlobalCommitBarrier,
    Migration,
    StateError,
    apply_migrations,
    open_control_database,
)
from milhouse.state import barrier as barrier_module
from milhouse.state import database as database_module

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)


def _private_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def _assert_clean(error: StateError) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None


class _RaisingConnection:
    """A minimal connection stand-in whose statements raise, to exercise the error boundary."""

    def __init__(self, *, raise_on: str) -> None:
        self._raise_on = raise_on

    def execute(self, sql: str, *args: object) -> object:
        if self._raise_on in sql:
            raise sqlite3.OperationalError("planted control-plane failure")
        return None

    def close(self) -> None:
        raise sqlite3.OperationalError("planted close failure")


@pytest.mark.security
def test_file_creation_failure_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _private_dir(tmp_path)

    def _boom(*_args: object, **_kwargs: object) -> int:
        raise PermissionError("planted create failure")

    monkeypatch.setattr(database_module.os, "open", _boom)
    with pytest.raises(StateError) as captured:
        open_control_database(directory / "milhouse.sqlite3")
    assert captured.value.code == "MH_STATE_FILE"
    _assert_clean(captured.value)


@pytest.mark.security
def test_unexaminable_path_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = _private_dir(tmp_path)
    real_lstat = database_module.os.lstat

    def _selective(path: object) -> os.stat_result:
        if str(path).endswith("milhouse.sqlite3"):
            raise PermissionError("planted lstat failure")
        return real_lstat(path)

    monkeypatch.setattr(database_module.os, "lstat", _selective)
    with pytest.raises(StateError) as captured:
        open_control_database(directory / "milhouse.sqlite3")
    assert captured.value.code == "MH_STATE_FILE"
    _assert_clean(captured.value)


@pytest.mark.security
def test_connect_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = _private_dir(tmp_path)

    def _boom(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        raise sqlite3.OperationalError("planted connect failure")

    monkeypatch.setattr(database_module.sqlite3, "connect", _boom)
    with pytest.raises(StateError) as captured:
        open_control_database(directory / "milhouse.sqlite3")
    assert captured.value.code == "MH_STATE_OPEN"
    _assert_clean(captured.value)


class _JournalProxy:
    """Wrap a real connection but report a non-WAL journal mode to exercise the fail-closed path."""

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real

    def execute(self, sql: str, *rest: object) -> object:
        if "journal_mode" in sql:
            return self._real.execute("PRAGMA journal_mode = DELETE", *rest)
        return self._real.execute(sql, *rest)

    def close(self) -> None:
        self._real.close()


@pytest.mark.security
def test_a_non_wal_journal_mode_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _private_dir(tmp_path)
    real_connect = database_module.sqlite3.connect

    def _proxy_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        return _JournalProxy(real_connect(*args, **kwargs))  # type: ignore[arg-type, return-value]

    monkeypatch.setattr(database_module.sqlite3, "connect", _proxy_connect)
    with pytest.raises(StateError) as captured:
        open_control_database(directory / "milhouse.sqlite3")
    assert captured.value.code == "MH_STATE_OPEN"


@pytest.mark.security
def test_transaction_begin_failure_fails_closed(tmp_path: Path) -> None:
    database = ControlDatabase(
        connection=_RaisingConnection(raise_on="BEGIN"),  # type: ignore[arg-type]
        path=tmp_path / "x",
        created=False,
    )
    with pytest.raises(StateError) as captured:
        with database.transaction():
            pass
    assert captured.value.code == "MH_STATE_TXN"
    _assert_clean(captured.value)


@pytest.mark.security
def test_transaction_commit_failure_fails_closed(tmp_path: Path) -> None:
    database = ControlDatabase(
        connection=_RaisingConnection(raise_on="COMMIT"),  # type: ignore[arg-type]
        path=tmp_path / "x",
        created=False,
    )
    with pytest.raises(StateError) as captured:
        with database.transaction():
            pass
    assert captured.value.code == "MH_STATE_TXN"
    _assert_clean(captured.value)


@pytest.mark.security
def test_close_swallows_a_connection_error(tmp_path: Path) -> None:
    database = ControlDatabase(
        connection=_RaisingConnection(raise_on="never"),  # type: ignore[arg-type]
        path=tmp_path / "x",
        created=False,
    )
    database.close()  # the planted close failure must be swallowed, not raised


@pytest.mark.security
@pytest.mark.parametrize(
    "definitions",
    [
        (Migration(1, "", ("CREATE TABLE a (x)",)),),
        (Migration(1, "a", ()),),
        (Migration(1, "a", ("   ",)),),
    ],
)
def test_invalid_migration_definitions_fail_closed(
    tmp_path: Path, definitions: tuple[Migration, ...]
) -> None:
    directory = _private_dir(tmp_path)
    database = open_control_database(directory / "milhouse.sqlite3")
    try:
        with pytest.raises(StateError) as captured:
            apply_migrations(database, definitions, applied_at=_NOW)
        assert captured.value.code == "MH_STATE_MIGRATION"
    finally:
        database.close()


@pytest.mark.security
def test_non_tuple_migrations_fail_closed(tmp_path: Path) -> None:
    directory = _private_dir(tmp_path)
    database = open_control_database(directory / "milhouse.sqlite3")
    try:
        with pytest.raises(StateError) as captured:
            apply_migrations(
                database, [Migration(1, "a", ("CREATE TABLE a (x)",))], applied_at=_NOW
            )  # type: ignore[arg-type]
        assert captured.value.code == "MH_STATE_MIGRATION"
    finally:
        database.close()


@pytest.mark.security
def test_barrier_lock_creation_failure_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    barrier = GlobalCommitBarrier(_private_dir(tmp_path) / "commit.lock")

    def _boom(*_args: object, **_kwargs: object) -> int:
        raise PermissionError("planted lock creation failure")

    monkeypatch.setattr(barrier_module.os, "open", _boom)
    with pytest.raises(StateError) as captured:
        with barrier.shared():
            pass
    assert captured.value.code == "MH_STATE_BARRIER"
    _assert_clean(captured.value)


@pytest.mark.security
def test_barrier_exclusive_os_error_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    barrier = GlobalCommitBarrier(_private_dir(tmp_path) / "commit.lock")

    def _boom(self: object, *args: object, **kwargs: object) -> None:
        raise OSError("planted exclusive acquire failure")

    monkeypatch.setattr(barrier_module.FileLock, "acquire", _boom)
    with pytest.raises(StateError) as captured:
        with barrier.exclusive():
            pass
    assert captured.value.code == "MH_STATE_BARRIER"
    _assert_clean(captured.value)
