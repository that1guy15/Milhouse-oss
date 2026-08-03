"""Durable installation pseudonym-key identity in the control plane (ADR 0007 addendum A07).

A keyed audit derivative is trustworthy only if produced by *this* installation's own key. Because a
:class:`~milhouse.privacy.pseudonym.Pseudonymizer` is constructible from any 32 bytes, loading a key
file at the config-bound path proves file hygiene, not installation identity. W03's dependency-ready
maintenance lifecycle creates or adopts the bound key under exclusive authority and records the
installation's NON-SECRET key ID and epoch (migration 11, the singleton ``_installation_key``
table). Audited compaction loads the key with these exact expected values; after establishment it
fails closed before spool mutation on a missing/malformed key or an ID/epoch mismatch. W06 ``init``
reuses the same established identity rather than owning a prerequisite that would make W03 unusable.

The record carries no secret — only the public key ID (``mh_pk1_`` + 16 hex) and epoch. Writing is
transaction-scoped: :func:`establish_installation_key` runs on the caller's open connection, in the
same transaction as the surrounding provisioning, and is idempotent for an identical identity while
refusing a conflicting one (key rotation is a separate, later contract). Every fault normalizes to a
fixed ``MH_STATE_INSTALLATION_KEY`` code raised outside the handler.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime
from typing import NoReturn

from milhouse.core.clock import TimeError, format_timestamp
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_TABLE = "_installation_key"
_KEY_ID_PATTERN = re.compile(r"mh_pk1_[0-9a-f]{16}", flags=re.ASCII)
_MAX_EPOCH = 2_147_483_647  # signed-32 upper bound, matching the pseudonym epoch domain


def _fail(message: str) -> NoReturn:
    raise StateError("MH_STATE_INSTALLATION_KEY", message)


def _validate_key_id(value: object) -> str:
    if type(value) is not str or _KEY_ID_PATTERN.fullmatch(value) is None:
        _fail("an installation key id must be 'mh_pk1_' followed by 16 lowercase hex characters")
    return value


def _validate_epoch(value: object) -> int:
    # ``bool`` is an ``int`` subtype; reject it so a stray flag cannot pose as an epoch.
    if type(value) is not int or not 1 <= value <= _MAX_EPOCH:
        _fail("an installation key epoch must be a whole number in 1..2^31-1")
    return value


def establish_installation_key(
    connection: sqlite3.Connection,
    *,
    key_id: str,
    epoch: int,
    now: datetime,
) -> None:
    """Record the installation's non-secret pseudonym key ID and epoch, on the caller's transaction.

    Idempotent for an identical ``(key_id, epoch)`` and refuses a conflicting one: the control plane
    binds exactly one installation identity, so a differing key id or epoch fails closed rather than
    silently overwriting attributable lineage (key rotation is a separate, later contract). Call
    inside the same transaction as the key-file provisioning so the record and key commit or roll
    back together.
    """

    _validate_key_id(key_id)
    _validate_epoch(epoch)

    invalid_time = False
    established_at = ""
    try:
        established_at = format_timestamp(now)
    except (OverflowError, TimeError):
        invalid_time = True
    if invalid_time:
        _fail("an installation key timestamp must be an aware in-range UTC instant")

    failed = False
    try:
        # Insert the singleton, leaving any existing row intact: idempotency and conflict are
        # decided by the read-back below, so a recorded identity is never silently overwritten.
        connection.execute(
            f"INSERT INTO {_TABLE} (id, key_id, epoch, established_at) VALUES (1, ?, ?, ?) "
            "ON CONFLICT (id) DO NOTHING",
            (key_id, epoch, established_at),
        )
    except (sqlite3.Error, OverflowError):
        failed = True
    if failed:
        _fail("the installation key identity could not be recorded")
    # Identical identity → the insert was a no-op and this matches (idempotent). A different stored
    # identity → the insert was a no-op and this differs, so fail closed rather than overwrite.
    if read_installation_key_row(connection) != (key_id, epoch):
        _fail("the control plane already records a different installation key identity")


def read_installation_key_row(connection: sqlite3.Connection) -> tuple[str, int] | None:
    """Return the recorded ``(key_id, epoch)`` on the caller's connection, or ``None`` if unset."""

    failed = False
    row: tuple[object, ...] | None = None
    try:
        row = connection.execute(f"SELECT key_id, epoch FROM {_TABLE} WHERE id = 1").fetchone()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("the installation key identity could not be read")
    if row is None:
        return None
    key_id, epoch = row[0], row[1]
    if not isinstance(epoch, int):  # pragma: no cover - the schema CHECK stores epoch as INTEGER
        _fail("the recorded installation key epoch is not an integer")
    return _validate_key_id(key_id), epoch


def read_installation_key(database: ControlDatabase) -> tuple[str, int] | None:
    """Return the recorded installation ``(key_id, epoch)``, or ``None`` when unprovisioned."""

    if type(database) is not ControlDatabase:
        _fail("a control database is required")
    return read_installation_key_row(database.connection)


__all__ = [
    "establish_installation_key",
    "read_installation_key",
    "read_installation_key_row",
]
