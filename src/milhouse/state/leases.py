"""SQLite named leases for multi-process coordination (W03 slice 1).

A lease is a named, holder-owned, time-bounded claim in the control database (plan section 4.4:
"collector leases, next-run times, and latest outcomes"). Acquire, renew, and release run in one
``BEGIN IMMEDIATE`` transaction, so SQLite serializes contenders and one holder wins. Expiry is
compared on the canonical RFC3339 millisecond string, lexically ordered in UTC, so no parsing is
needed. Time is injected as an aware UTC instant; leases never read the wall clock themselves.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NoReturn

from milhouse.core.clock import format_timestamp
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_LEASES_TABLE = "_leases"


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


@dataclass(frozen=True, slots=True)
class Lease:
    """An owned, time-bounded lease as recorded in the control database."""

    name: str
    holder: str
    acquired_at: str
    expires_at: str


def _validate_identifier(value: object, code: str, subject: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        _fail(code, f"a lease {subject} must be bounded non-empty text")
    return value


def _stamps(now: datetime, ttl_seconds: int) -> tuple[str, str]:
    if type(ttl_seconds) is not int or ttl_seconds <= 0:
        _fail("MH_STATE_LEASE_TTL", "a lease requires a positive whole-second lifetime")
    acquired = format_timestamp(now)
    expires = format_timestamp(now + timedelta(seconds=ttl_seconds))
    return acquired, expires


def _ensure_table(database: ControlDatabase) -> None:
    with database.transaction() as connection:
        connection.execute(
            f"CREATE TABLE IF NOT EXISTS {_LEASES_TABLE} ("
            "name TEXT PRIMARY KEY NOT NULL, "
            "holder TEXT NOT NULL, "
            "acquired_at TEXT NOT NULL, "
            "expires_at TEXT NOT NULL)"
        )


def _current(connection: sqlite3.Connection, name: str) -> tuple[str, str, str] | None:
    row = connection.execute(
        f"SELECT holder, acquired_at, expires_at FROM {_LEASES_TABLE} WHERE name = ?", (name,)
    ).fetchone()
    if row is None:
        return None
    return str(row[0]), str(row[1]), str(row[2])


def acquire_lease(
    database: ControlDatabase,
    name: str,
    holder: str,
    *,
    now: datetime,
    ttl_seconds: int,
) -> Lease:
    """Acquire or take over ``name`` for ``holder``; fail closed if another holder's lease is live.

    Re-acquiring one's own lease renews it. Taking over is allowed only once the recorded lease has
    expired (``expires_at <= now``).
    """

    _validate_identifier(name, "MH_STATE_LEASE_NAME", "name")
    _validate_identifier(holder, "MH_STATE_LEASE_HOLDER", "holder")
    acquired, expires = _stamps(now, ttl_seconds)
    now_stamp = format_timestamp(now)
    _ensure_table(database)
    with database.transaction() as connection:
        existing = _current(connection, name)
        if existing is not None:
            existing_holder, _existing_acquired, existing_expires = existing
            if existing_holder != holder and existing_expires > now_stamp:
                _fail("MH_STATE_LEASE_HELD", "the lease is held by a different live holder")
        connection.execute(
            f"INSERT INTO {_LEASES_TABLE} (name, holder, acquired_at, expires_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET holder = excluded.holder, "
            "acquired_at = excluded.acquired_at, expires_at = excluded.expires_at",
            (name, holder, acquired, expires),
        )
    return Lease(name=name, holder=holder, acquired_at=acquired, expires_at=expires)


def renew_lease(
    database: ControlDatabase,
    name: str,
    holder: str,
    *,
    now: datetime,
    ttl_seconds: int,
) -> Lease:
    """Extend a lease ``holder`` still holds and that has not expired; fail closed otherwise."""

    _validate_identifier(name, "MH_STATE_LEASE_NAME", "name")
    _validate_identifier(holder, "MH_STATE_LEASE_HOLDER", "holder")
    acquired, expires = _stamps(now, ttl_seconds)
    now_stamp = format_timestamp(now)
    _ensure_table(database)
    with database.transaction() as connection:
        existing = _current(connection, name)
        if existing is None or existing[0] != holder or existing[2] <= now_stamp:
            _fail("MH_STATE_LEASE_LOST", "the lease is not held by this holder or has expired")
        connection.execute(
            f"UPDATE {_LEASES_TABLE} SET acquired_at = ?, expires_at = ? WHERE name = ?",
            (acquired, expires, name),
        )
    return Lease(name=name, holder=holder, acquired_at=acquired, expires_at=expires)


def release_lease(database: ControlDatabase, name: str, holder: str) -> bool:
    """Release a lease held by ``holder``. Returns True if a matching lease was removed."""

    _validate_identifier(name, "MH_STATE_LEASE_NAME", "name")
    _validate_identifier(holder, "MH_STATE_LEASE_HOLDER", "holder")
    _ensure_table(database)
    with database.transaction() as connection:
        cursor = connection.execute(
            f"DELETE FROM {_LEASES_TABLE} WHERE name = ? AND holder = ?", (name, holder)
        )
        removed = cursor.rowcount
    return removed > 0
