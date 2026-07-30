"""Source ingestion cursors advanced only against committed segments (W03 slice 4).

A source cursor records how far ingestion from a named source has been durably committed. Pipeline
rule 9 requires a cursor to advance only in a transaction that references an existing committed
segment ledger row: :func:`advance_cursor` takes the ``batch_id`` of the segment that was just
committed and, in one ``BEGIN IMMEDIATE`` transaction, asserts that segment exists before writing
the new position. The ``_cursors.batch_id`` foreign key makes the same guarantee structural, so a
cursor can never point past the durable spool even if a caller bypasses this API.

Concurrent advances are serialized by the transaction and disambiguated by a compare-and-set on a
monotonic ``revision``: a worker passes the revision it last observed, so it only advances from the
position it saw and a racing advance cannot silently overwrite it. ``position`` is an opaque,
source-defined resumable coordinate; it carries no raw provider payload. Every SQLite or time
failure normalizes to a stable ``MH_STATE_*`` code raised outside the handler.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn

from milhouse.core.clock import TimeError, format_timestamp
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_CURSORS_TABLE = "_cursors"


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


@dataclass(frozen=True, slots=True)
class SourceCursor:
    """A source ingestion cursor as recorded in the control database.

    ``batch_id`` is the committed segment this cursor last advanced against, or ``None`` once that
    segment has been pruned by retention: the detach preserves the payload-free ``position``/
    ``revision`` checkpoint while releasing the reference so the expired segment can be removed.
    """

    source: str
    position: str
    batch_id: str | None
    revision: int
    updated_at: str


def _validate_identifier(value: object, code: str, subject: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        _fail(code, f"a cursor {subject} must be bounded non-empty text")
    return value


def _validate_revision(value: object) -> int:
    # ``bool`` is an ``int`` subtype; reject it so a stray flag cannot pose as revision 0/1.
    if type(value) is not int or value < 0:
        _fail("MH_STATE_CURSOR_REVISION", "an expected cursor revision must be a whole number >= 0")
    return value


def _row_to_cursor(row: Sequence[Any]) -> SourceCursor:
    return SourceCursor(
        source=str(row[0]),
        position=str(row[1]),
        batch_id=None if row[2] is None else str(row[2]),
        revision=int(row[3]),
        updated_at=str(row[4]),
    )


def read_cursor(database: ControlDatabase, source: str) -> SourceCursor | None:
    """Return the current cursor for ``source``, or ``None`` if it has never advanced."""

    _validate_identifier(source, "MH_STATE_CURSOR_SOURCE", "source")
    row: tuple[object, ...] | None = None
    failed = False
    try:
        row = database.connection.execute(
            f"SELECT source, position, batch_id, revision, updated_at "
            f"FROM {_CURSORS_TABLE} WHERE source = ?",
            (source,),
        ).fetchone()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("MH_STATE_CURSOR", "the cursor could not be read")
    return None if row is None else _row_to_cursor(row)


def advance_cursor(
    database: ControlDatabase,
    source: str,
    *,
    position: str,
    batch_id: str,
    now: datetime,
    expected_revision: int,
) -> SourceCursor:
    """Advance ``source`` to ``position`` against committed segment ``batch_id``.

    ``expected_revision`` is the revision the caller last observed (``0`` if the cursor has never
    advanced). The advance runs in one transaction that asserts the segment is committed and that
    the stored revision still equals ``expected_revision``; on either mismatch it fails closed
    without writing, so a concurrent or replayed advance cannot fork or regress the cursor.
    """

    _validate_identifier(source, "MH_STATE_CURSOR_SOURCE", "source")
    _validate_identifier(position, "MH_STATE_CURSOR_POSITION", "position")
    _validate_identifier(batch_id, "MH_STATE_CURSOR_SEGMENT", "segment reference")
    _validate_revision(expected_revision)
    cursor: SourceCursor | None = None
    failed = False
    try:
        updated_at = format_timestamp(now)
        with database.transaction() as connection:
            segment = connection.execute(
                "SELECT 1 FROM _segments WHERE batch_id = ?", (batch_id,)
            ).fetchone()
            if segment is None:
                _fail(
                    "MH_STATE_CURSOR_SEGMENT",
                    "a cursor advances only against a committed segment",
                )
            existing = connection.execute(
                f"SELECT revision FROM {_CURSORS_TABLE} WHERE source = ?", (source,)
            ).fetchone()
            current_revision = int(existing[0]) if existing is not None else 0
            if current_revision != expected_revision:
                _fail("MH_STATE_CURSOR_CONFLICT", "the cursor was advanced concurrently")
            revision = current_revision + 1
            connection.execute(
                f"INSERT INTO {_CURSORS_TABLE} (source, position, batch_id, revision, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(source) DO UPDATE SET position = excluded.position, "
                "batch_id = excluded.batch_id, revision = excluded.revision, "
                "updated_at = excluded.updated_at",
                (source, position, batch_id, revision, updated_at),
            )
        cursor = SourceCursor(
            source=source,
            position=position,
            batch_id=batch_id,
            revision=revision,
            updated_at=updated_at,
        )
    except (sqlite3.Error, OverflowError, TimeError):
        failed = True
    if failed:
        _fail("MH_STATE_CURSOR", "the cursor could not be advanced")
    assert cursor is not None
    return cursor
