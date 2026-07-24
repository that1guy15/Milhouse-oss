from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.state import (
    GlobalCommitBarrier,
    StateError,
    acquire_lease,
    initialize_control_state,
    open_control_database,
    release_lease,
    renew_lease,
    require_current_lease,
)

_T0 = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)


def _migrated(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_T0)
    return database


def test_acquire_records_a_fenced_bounded_lease(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        lease = acquire_lease(database, "scheduler", "worker-a", now=_T0, ttl_seconds=60)
        assert lease.holder == "worker-a"
        assert lease.fence == 1
        assert lease.acquired_at == "2026-07-24T12:00:00.000Z"
        assert lease.expires_at == "2026-07-24T12:01:00.000Z"
    finally:
        database.close()


def test_a_live_lease_blocks_a_different_holder(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        acquire_lease(database, "scheduler", "worker-a", now=_T0, ttl_seconds=60)
        with pytest.raises(StateError) as captured:
            acquire_lease(
                database, "scheduler", "worker-b", now=_T0 + timedelta(seconds=30), ttl_seconds=60
            )
        assert captured.value.code == "MH_STATE_LEASE_HELD"
    finally:
        database.close()


def test_taking_over_an_expired_lease_increments_the_fence(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        first = acquire_lease(database, "scheduler", "worker-a", now=_T0, ttl_seconds=60)
        taken = acquire_lease(
            database, "scheduler", "worker-b", now=_T0 + timedelta(seconds=61), ttl_seconds=60
        )
        assert first.fence == 1
        assert taken.holder == "worker-b"
        assert taken.fence == 2
    finally:
        database.close()


def test_reacquiring_own_lease_renews_and_keeps_the_fence(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        acquire_lease(database, "scheduler", "worker-a", now=_T0, ttl_seconds=60)
        renewed = acquire_lease(
            database, "scheduler", "worker-a", now=_T0 + timedelta(seconds=30), ttl_seconds=60
        )
        assert renewed.fence == 1
        assert renewed.expires_at == "2026-07-24T12:01:30.000Z"
    finally:
        database.close()


def test_renew_requires_a_live_owned_lease_and_keeps_the_fence(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        acquire_lease(database, "scheduler", "worker-a", now=_T0, ttl_seconds=60)
        renewed = renew_lease(
            database, "scheduler", "worker-a", now=_T0 + timedelta(seconds=30), ttl_seconds=60
        )
        assert renewed.fence == 1
        with pytest.raises(StateError) as expired:
            renew_lease(
                database, "scheduler", "worker-a", now=_T0 + timedelta(seconds=999), ttl_seconds=60
            )
        assert expired.value.code == "MH_STATE_LEASE_LOST"
        with pytest.raises(StateError) as foreign:
            renew_lease(
                database, "scheduler", "worker-b", now=_T0 + timedelta(seconds=5), ttl_seconds=60
            )
        assert foreign.value.code == "MH_STATE_LEASE_LOST"
    finally:
        database.close()


def test_release_only_removes_the_holders_lease(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        acquire_lease(database, "scheduler", "worker-a", now=_T0, ttl_seconds=60)
        assert release_lease(database, "scheduler", "worker-b") is False
        assert release_lease(database, "scheduler", "worker-a") is True
        taken = acquire_lease(database, "scheduler", "worker-b", now=_T0, ttl_seconds=60)
        assert taken.holder == "worker-b"
    finally:
        database.close()


def test_a_fenced_stale_holder_cannot_pass_the_lease_guard(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        stale = acquire_lease(database, "job", "worker-a", now=_T0, ttl_seconds=60)
        current = acquire_lease(
            database, "job", "worker-b", now=_T0 + timedelta(seconds=61), ttl_seconds=60
        )
        assert current.fence == stale.fence + 1
        # the current holder passes the guard...
        with database.transaction() as connection:
            require_current_lease(connection, current)
        # ...but the taken-over holder is rejected in the same transaction as any protected mutation
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                require_current_lease(connection, stale)
        assert captured.value.code == "MH_STATE_LEASE_LOST"
    finally:
        database.close()


def test_invalid_ttl_and_identifiers_fail_closed(tmp_path: Path) -> None:
    database = _migrated(tmp_path)
    try:
        for bad_ttl in (0, -1, 3650 * 86_400 + 1):
            with pytest.raises(StateError) as ttl:
                acquire_lease(database, "scheduler", "worker-a", now=_T0, ttl_seconds=bad_ttl)
            assert ttl.value.code == "MH_STATE_LEASE_TTL"
        with pytest.raises(StateError) as name:
            acquire_lease(database, "", "worker-a", now=_T0, ttl_seconds=60)
        assert name.value.code == "MH_STATE_LEASE_NAME"
        with pytest.raises(StateError) as holder:
            acquire_lease(database, "scheduler", "", now=_T0, ttl_seconds=60)
        assert holder.value.code == "MH_STATE_LEASE_HOLDER"
    finally:
        database.close()
