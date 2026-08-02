"""Unit tests for the durable installation pseudonym-key identity (migration 11, ADR 0007 A07).

The control plane records the installation's NON-SECRET key id and epoch so audited compaction can
bind loaded key material to the installation's own identity. Establishment is transaction-scoped and
idempotent for an identical identity, and refuses a conflicting one; reading returns ``None`` until
provisioned. Every fault normalizes to the fixed ``MH_STATE_INSTALLATION_KEY`` code.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
)
from milhouse.state.errors import StateError
from milhouse.state.installation import (
    establish_installation_key,
    read_installation_key,
    read_installation_key_row,
)

_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_KEY_ID = "mh_pk1_0123456789abcdef"
_OTHER_KEY_ID = "mh_pk1_fedcba9876543210"


def _database(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    return database


def test_read_returns_none_when_unprovisioned(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert read_installation_key(database) is None
    finally:
        database.close()


def test_establish_and_read_round_trip(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            establish_installation_key(connection, key_id=_KEY_ID, epoch=3, now=_NOW)
        assert read_installation_key(database) == (_KEY_ID, 3)
    finally:
        database.close()


def test_establish_is_idempotent_for_the_same_identity(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            establish_installation_key(connection, key_id=_KEY_ID, epoch=1, now=_NOW)
        with database.transaction() as connection:
            establish_installation_key(connection, key_id=_KEY_ID, epoch=1, now=_NOW)  # no-op
        # Exactly one singleton row survives.
        count = database.connection.execute("SELECT count(*) FROM _installation_key").fetchone()[0]
        assert count == 1
        assert read_installation_key(database) == (_KEY_ID, 1)
    finally:
        database.close()


def test_establish_rejects_a_conflicting_identity(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            establish_installation_key(connection, key_id=_KEY_ID, epoch=1, now=_NOW)
        with pytest.raises(StateError) as different_id:
            with database.transaction() as connection:
                establish_installation_key(connection, key_id=_OTHER_KEY_ID, epoch=1, now=_NOW)
        assert different_id.value.code == "MH_STATE_INSTALLATION_KEY"
        with pytest.raises(StateError) as different_epoch:
            with database.transaction() as connection:
                establish_installation_key(connection, key_id=_KEY_ID, epoch=2, now=_NOW)
        assert different_epoch.value.code == "MH_STATE_INSTALLATION_KEY"
        assert read_installation_key(database) == (_KEY_ID, 1)  # unchanged
    finally:
        database.close()


@pytest.mark.parametrize(
    "key_id",
    ["", "mh_pk1_", "mh_pk1_XYZ", "mh_pk2_0123456789abcdef", "0123456789abcdef", 123],
)
def test_a_malformed_key_id_is_rejected(tmp_path: Path, key_id: object) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                establish_installation_key(
                    connection,
                    key_id=key_id,  # type: ignore[arg-type]
                    epoch=1,
                    now=_NOW,
                )
        assert captured.value.code == "MH_STATE_INSTALLATION_KEY"
        assert read_installation_key(database) is None
    finally:
        database.close()


@pytest.mark.parametrize("epoch", [0, -1, 2_147_483_648, True, "1"])
def test_a_bad_epoch_is_rejected(tmp_path: Path, epoch: object) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                establish_installation_key(
                    connection,
                    key_id=_KEY_ID,
                    epoch=epoch,  # type: ignore[arg-type]
                    now=_NOW,
                )
        assert captured.value.code == "MH_STATE_INSTALLATION_KEY"
    finally:
        database.close()


def test_a_naive_timestamp_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                establish_installation_key(
                    connection,
                    key_id=_KEY_ID,
                    epoch=1,
                    now=datetime(2026, 7, 28, 12),  # naive
                )
        assert captured.value.code == "MH_STATE_INSTALLATION_KEY"
    finally:
        database.close()


def test_read_row_on_the_connection_matches_the_database_reader(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            establish_installation_key(connection, key_id=_KEY_ID, epoch=5, now=_NOW)
            assert read_installation_key_row(connection) == (_KEY_ID, 5)
        assert read_installation_key(database) == (_KEY_ID, 5)
    finally:
        database.close()


def test_read_rejects_a_wrong_type_database(tmp_path: Path) -> None:
    with pytest.raises(StateError) as captured:
        read_installation_key(object())  # type: ignore[arg-type]
    assert captured.value.code == "MH_STATE_INSTALLATION_KEY"


def test_read_normalizes_a_backend_failure(tmp_path: Path) -> None:
    # Any residual backend fault normalizes to the fixed code (the table is dropped so the SELECT
    # raises), never leaking a raw sqlite error.
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _installation_key")
        with pytest.raises(StateError) as captured:
            read_installation_key(database)
        assert captured.value.code == "MH_STATE_INSTALLATION_KEY"
    finally:
        database.close()


def test_establish_normalizes_a_backend_failure(tmp_path: Path) -> None:
    # A backend fault during establishment normalizes to the fixed code and rolls back (here the
    # SELECT the idempotency check issues fails because the table is gone).
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                connection.execute("DROP TABLE _installation_key")
                establish_installation_key(connection, key_id=_KEY_ID, epoch=1, now=_NOW)
        assert captured.value.code == "MH_STATE_INSTALLATION_KEY"
    finally:
        database.close()
