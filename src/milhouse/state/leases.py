"""SQLite named leases with fencing for multi-process coordination (W03 slice 1).

A lease is a named, holder-owned, time-bounded claim in the ``_leases`` control table (created by
the package migration, never by lease code) with a monotonic ``fence`` token. The token increments
on each ownership change and stays stable across renewals, so a stale holder cannot resume work
after takeover: a lease-protected mutation validates name, holder, and fence in the same
transaction via ``require_current_lease``. Acquire, renew, and release each run in one
``BEGIN IMMEDIATE`` transaction, so SQLite serializes contenders and one holder wins. Expiry
compares the canonical RFC3339 millisecond string, which is lexically ordered in UTC. Time is
injected as an aware UTC instant. Every SQLite or time failure is normalized to a fixed
``MH_STATE_*`` error raised outside the handler; the TTL is bounded before any arithmetic.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NoReturn

from milhouse.core.clock import TimeError, format_timestamp
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_LEASES_TABLE = "_leases"
_MAX_TTL_SECONDS = 3650 * 86_400  # ten years; bounds the deadline arithmetic


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


@dataclass(frozen=True, slots=True)
class Lease:
    """An owned, fenced, time-bounded lease as recorded in the control database."""

    name: str
    holder: str
    fence: int
    acquired_at: str
    expires_at: str


def _validate_identifier(value: object, code: str, subject: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        _fail(code, f"a lease {subject} must be bounded non-empty text")
    return value


def _validate_ttl(ttl_seconds: object) -> int:
    if type(ttl_seconds) is not int or not 0 < ttl_seconds <= _MAX_TTL_SECONDS:
        _fail("MH_STATE_LEASE_TTL", "a lease requires a positive bounded whole-second lifetime")
    return ttl_seconds


def _stamps(now: datetime, ttl_seconds: int) -> tuple[str, str]:
    acquired = format_timestamp(now)
    expires = format_timestamp(now + timedelta(seconds=ttl_seconds))
    return acquired, expires


def _current(connection: sqlite3.Connection, name: str) -> tuple[str, int, str] | None:
    row = connection.execute(
        f"SELECT holder, fence, expires_at FROM {_LEASES_TABLE} WHERE name = ?", (name,)
    ).fetchone()
    if row is None:
        return None
    return str(row[0]), int(row[1]), str(row[2])


def acquire_lease(
    database: ControlDatabase,
    name: str,
    holder: str,
    *,
    now: datetime,
    ttl_seconds: int,
) -> Lease:
    """Acquire or take over ``name`` for ``holder``; fail closed if another holder's lease is live.

    Re-acquiring one's own lease renews it and keeps the fence; taking over an expired lease
    increments
    the fence.
    """

    _validate_identifier(name, "MH_STATE_LEASE_NAME", "name")
    _validate_identifier(holder, "MH_STATE_LEASE_HOLDER", "holder")
    _validate_ttl(ttl_seconds)
    lease: Lease | None = None
    failed = False
    try:
        acquired, expires = _stamps(now, ttl_seconds)
        now_stamp = format_timestamp(now)
        with database.transaction() as connection:
            existing = _current(connection, name)
            if existing is not None:
                existing_holder, existing_fence, existing_expires = existing
                if existing_holder != holder and existing_expires > now_stamp:
                    _fail("MH_STATE_LEASE_HELD", "the lease is held by a different live holder")
                fence = existing_fence if existing_holder == holder else existing_fence + 1
            else:
                fence = 1
            connection.execute(
                f"INSERT INTO {_LEASES_TABLE} (name, holder, fence, acquired_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET holder = excluded.holder, fence = excluded.fence, "
                "acquired_at = excluded.acquired_at, expires_at = excluded.expires_at",
                (name, holder, fence, acquired, expires),
            )
        lease = Lease(
            name=name, holder=holder, fence=fence, acquired_at=acquired, expires_at=expires
        )
    except (sqlite3.Error, OverflowError, TimeError):
        failed = True
    if failed:
        _fail("MH_STATE_LEASE", "the lease could not be acquired")
    assert lease is not None
    return lease


def renew_lease(
    database: ControlDatabase,
    name: str,
    holder: str,
    *,
    now: datetime,
    ttl_seconds: int,
) -> Lease:
    """Extend a lease ``holder`` still holds and that has not expired; keep the fence, fail
    otherwise."""

    _validate_identifier(name, "MH_STATE_LEASE_NAME", "name")
    _validate_identifier(holder, "MH_STATE_LEASE_HOLDER", "holder")
    _validate_ttl(ttl_seconds)
    lease: Lease | None = None
    failed = False
    try:
        acquired, expires = _stamps(now, ttl_seconds)
        now_stamp = format_timestamp(now)
        with database.transaction() as connection:
            existing = _current(connection, name)
            if existing is None or existing[0] != holder or existing[2] <= now_stamp:
                _fail("MH_STATE_LEASE_LOST", "the lease is not held by this holder or has expired")
            fence = existing[1]
            connection.execute(
                f"UPDATE {_LEASES_TABLE} SET acquired_at = ?, expires_at = ? WHERE name = ?",
                (acquired, expires, name),
            )
        lease = Lease(
            name=name, holder=holder, fence=fence, acquired_at=acquired, expires_at=expires
        )
    except (sqlite3.Error, OverflowError, TimeError):
        failed = True
    if failed:
        _fail("MH_STATE_LEASE", "the lease could not be renewed")
    assert lease is not None
    return lease


def release_lease(database: ControlDatabase, name: str, holder: str) -> bool:
    """Release a lease held by ``holder``. Returns True if a matching lease was removed."""

    _validate_identifier(name, "MH_STATE_LEASE_NAME", "name")
    _validate_identifier(holder, "MH_STATE_LEASE_HOLDER", "holder")
    removed = 0
    failed = False
    try:
        with database.transaction() as connection:
            cursor = connection.execute(
                f"DELETE FROM {_LEASES_TABLE} WHERE name = ? AND holder = ?", (name, holder)
            )
            removed = cursor.rowcount
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("MH_STATE_LEASE", "the lease could not be released")
    return removed > 0


def require_current_lease(connection: sqlite3.Connection, lease: Lease) -> None:
    """Assert, inside the caller's transaction, that ``lease`` is still the current fenced owner.

    Call this in the same transaction as a lease-protected mutation so a stale holder whose lease
    was
    taken over cannot commit. Fails closed with ``MH_STATE_LEASE_LOST`` on any mismatch.
    """

    stale = False
    failed = False
    try:
        row = connection.execute(
            f"SELECT holder, fence FROM {_LEASES_TABLE} WHERE name = ?", (lease.name,)
        ).fetchone()
        stale = row is None or str(row[0]) != lease.holder or int(row[1]) != lease.fence
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("MH_STATE_LEASE", "the lease could not be validated")
    if stale:
        _fail("MH_STATE_LEASE_LOST", "the lease is no longer held by this holder")
