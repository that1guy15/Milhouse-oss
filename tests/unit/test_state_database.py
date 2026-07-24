from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from milhouse.state import ControlDatabase, StateError, open_control_database


def _private_dir(root: Path, name: str = "control") -> Path:
    directory = root / name
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)  # defeat the inherited umask
    return directory


def _db_path(root: Path) -> Path:
    return _private_dir(root) / "milhouse.sqlite3"


def test_open_creates_an_owner_only_wal_database(tmp_path: Path) -> None:
    path = _db_path(tmp_path)
    database = open_control_database(path)
    try:
        assert database.created is True
        assert database.path == path
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600
        assert database.connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert database.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert database.connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    finally:
        database.close()


def test_reopening_an_existing_database_does_not_report_creation(tmp_path: Path) -> None:
    path = _db_path(tmp_path)
    first = open_control_database(path)
    first.close()
    second = open_control_database(path)
    try:
        assert second.created is False
    finally:
        second.close()


def test_transaction_commits_on_success_and_rolls_back_on_error(tmp_path: Path) -> None:
    database = open_control_database(_db_path(tmp_path))
    try:
        with database.transaction() as connection:
            connection.execute("CREATE TABLE t (x INTEGER NOT NULL)")
            connection.execute("INSERT INTO t VALUES (1)")
        assert database.connection.execute("SELECT count(*) FROM t").fetchone()[0] == 1

        with pytest.raises(RuntimeError, match="boom"):
            with database.transaction() as connection:
                connection.execute("INSERT INTO t VALUES (2)")
                raise RuntimeError("boom")
        # the caller's exception propagated unchanged and the row was rolled back
        assert database.connection.execute("SELECT count(*) FROM t").fetchone()[0] == 1
    finally:
        database.close()


def test_rejects_a_group_or_world_accessible_parent_directory(tmp_path: Path) -> None:
    directory = tmp_path / "loose"
    directory.mkdir()
    os.chmod(directory, 0o777)
    with pytest.raises(StateError) as captured:
        open_control_database(directory / "milhouse.sqlite3")
    assert captured.value.code == "MH_STATE_DIR"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_rejects_a_symlinked_database_path(tmp_path: Path) -> None:
    directory = _private_dir(tmp_path)
    target = directory / "real.sqlite3"
    target.write_bytes(b"")
    os.chmod(target, 0o600)
    link = directory / "milhouse.sqlite3"
    link.symlink_to(target)
    with pytest.raises(StateError) as captured:
        open_control_database(link)
    assert captured.value.code == "MH_STATE_FILE"


def test_rejects_an_existing_group_readable_database_file(tmp_path: Path) -> None:
    directory = _private_dir(tmp_path)
    path = directory / "milhouse.sqlite3"
    path.write_bytes(b"")
    os.chmod(path, 0o640)
    with pytest.raises(StateError) as captured:
        open_control_database(path)
    assert captured.value.code == "MH_STATE_FILE"


def test_using_a_closed_database_fails_closed(tmp_path: Path) -> None:
    database = open_control_database(_db_path(tmp_path))
    database.close()
    database.close()  # idempotent
    with pytest.raises(StateError) as captured:
        _ = database.connection
    assert captured.value.code == "MH_STATE_CLOSED"


def test_open_control_database_returns_the_wrapper_type(tmp_path: Path) -> None:
    database = open_control_database(_db_path(tmp_path))
    try:
        assert isinstance(database, ControlDatabase)
    finally:
        database.close()
