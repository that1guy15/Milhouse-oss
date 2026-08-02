"""Authoritative compaction/rehome provenance (A07, migration 12).

A ``c[0-9a-f]{64}`` id was a valid producer batch id before the reservation, so a reserved segment's
``origin`` cannot prove whether it is a genuine compaction successor or a legal pre-reservation
occupant. Compaction therefore records a durable INTENT for each successor BEFORE it publishes the
successor file, and the reserved-namespace upgrade rehomes every reserved segment that no intent or
verified pre-upgrade source/successor pair proves genuine. Because ``_compaction_intents`` starts
empty at the schema-12 upgrade, the first exclusive maintenance pass reconstructs any genuine pair
from its trusted segment bytes before classifying the remaining reserved rows as legacy occupants.
New successors carry their intent before publication, so every later crash orphan is adoptable.

A ``rehome`` intent binds the source to its collision-resistant allocated target so a restart reuses
the same target. Every function is transaction-scoped on the caller's connection; faults normalize
to a fixed ``MH_SPOOL_INTENT`` code.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import NoReturn

from milhouse.core.clock import TimeError, format_timestamp
from milhouse.spooling.errors import SpoolError

_INTENTS = "_compaction_intents"
_SEQUENCES = "_sequences"
_SUCCESSOR = "successor"
_REHOME = "rehome"
REHOME_SEQUENCE = "rehome_target"


def _fail(message: str) -> NoReturn:
    raise SpoolError("MH_SPOOL_INTENT", message)


def _timestamp(now: datetime) -> str:
    invalid = False
    stamp = ""
    try:
        stamp = format_timestamp(now)
    except (OverflowError, TimeError):  # pragma: no cover - now is validated before the barrier
        invalid = True
    if invalid:  # pragma: no cover - now is validated before the barrier on every caller path
        _fail("an intent timestamp must be an aware in-range UTC instant")
    return stamp


def record_successor_intent(
    connection: sqlite3.Connection, *, target_batch_id: str, source_batch_id: str, now: datetime
) -> None:
    """Record that ``target_batch_id`` is compaction's intended successor of ``source_batch_id``.

    Idempotent (``INSERT OR IGNORE``): a re-run re-asserts the same intent. It must
    commit BEFORE the successor file is published, so a crash between the intent and the ledger
    swap still leaves the reserved id provably a genuine successor (adoptable, never rehomed).
    """

    stamp = _timestamp(now)
    failed = False
    try:
        existing = connection.execute(
            f"SELECT source_batch_id, kind FROM {_INTENTS} WHERE target_batch_id = ?",
            (target_batch_id,),
        ).fetchone()
        if existing is None:
            connection.execute(
                f"INSERT INTO {_INTENTS} "
                "(target_batch_id, source_batch_id, kind, created_at) VALUES (?, ?, ?, ?)",
                (target_batch_id, source_batch_id, _SUCCESSOR, stamp),
            )
        elif existing != (source_batch_id, _SUCCESSOR):
            failed = True
    except (sqlite3.Error, OverflowError):
        failed = True
    if failed:
        _fail("a compaction successor intent could not be recorded")


def record_rehome_intent(
    connection: sqlite3.Connection, *, target_batch_id: str, source_batch_id: str, now: datetime
) -> None:
    """Bind a legacy reserved occupant ``source_batch_id`` to its allocated non-reserved
    ``target_batch_id`` so a restart reuses the same target. Must be committed BEFORE publishing."""

    stamp = _timestamp(now)
    failed = False
    try:
        existing_target = connection.execute(
            f"SELECT source_batch_id, kind FROM {_INTENTS} WHERE target_batch_id = ?",
            (target_batch_id,),
        ).fetchone()
        existing_source = connection.execute(
            f"SELECT target_batch_id FROM {_INTENTS} WHERE source_batch_id = ? AND kind = ?",
            (source_batch_id, _REHOME),
        ).fetchone()
        if existing_target is None and existing_source is None:
            connection.execute(
                f"INSERT INTO {_INTENTS} "
                "(target_batch_id, source_batch_id, kind, created_at) VALUES (?, ?, ?, ?)",
                (target_batch_id, source_batch_id, _REHOME, stamp),
            )
        elif existing_target != (source_batch_id, _REHOME) or existing_source != (target_batch_id,):
            failed = True
    except (sqlite3.Error, OverflowError):
        failed = True
    if failed:
        _fail("a rehome intent could not be recorded")


def clear_rehome_intent(
    connection: sqlite3.Connection, *, source_batch_id: str, target_batch_id: str
) -> None:
    """Clear exactly one conflicting rehome allocation before atomically replacing it."""

    failed = False
    try:
        cursor = connection.execute(
            f"DELETE FROM {_INTENTS} WHERE source_batch_id = ? AND target_batch_id = ? "
            "AND kind = ?",
            (source_batch_id, target_batch_id, _REHOME),
        )
        if cursor.rowcount != 1:
            failed = True
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("a rehome intent could not be replaced")


def is_recorded_successor(connection: sqlite3.Connection, target_batch_id: str) -> bool:
    """Whether ``target_batch_id`` is a durably-recorded compaction successor (not a legacy id)."""

    failed = False
    row: tuple[object, ...] | None = None
    try:
        row = connection.execute(
            f"SELECT 1 FROM {_INTENTS} WHERE target_batch_id = ? AND kind = ?",
            (target_batch_id, _SUCCESSOR),
        ).fetchone()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("a compaction successor intent could not be read")
    return row is not None


def read_rehome_target(connection: sqlite3.Connection, source_batch_id: str) -> str | None:
    """Return the target already allocated to rehome ``source_batch_id`` (``None`` if none)."""

    failed = False
    row: tuple[object, ...] | None = None
    try:
        row = connection.execute(
            f"SELECT target_batch_id FROM {_INTENTS} WHERE source_batch_id = ? AND kind = ?",
            (source_batch_id, _REHOME),
        ).fetchone()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("a rehome intent could not be read")
    if row is None:
        return None
    return str(row[0])


def read_sequence(connection: sqlite3.Connection, name: str) -> int:
    """Return the monotonic counter ``name`` (0 when it has never been advanced)."""

    failed = False
    row: tuple[object, ...] | None = None
    try:
        row = connection.execute(
            f"SELECT value FROM {_SEQUENCES} WHERE name = ?", (name,)
        ).fetchone()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("a control-plane sequence could not be read")
    if row is None:
        return 0
    value = row[0]
    if not isinstance(value, int):  # pragma: no cover - the schema CHECK stores value as INTEGER
        _fail("a control-plane sequence value is not an integer")
    return value


def set_sequence(connection: sqlite3.Connection, name: str, value: int) -> None:
    """Persist the monotonic counter ``name``. The caller only ever advances it (never rewinds)."""

    if type(value) is not int or value < 0:  # pragma: no cover - callers only pass advanced values
        _fail("a control-plane sequence value must be a non-negative integer")
    failed = False
    try:
        connection.execute(
            f"INSERT INTO {_SEQUENCES} (name, value) VALUES (?, ?) "
            "ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            (name, value),
        )
    except (sqlite3.Error, OverflowError):
        failed = True
    if failed:
        _fail("a control-plane sequence could not be advanced")


def clear_intents_for_segment(connection: sqlite3.Connection, batch_id: str) -> None:
    """Drop the retired segment's OWN intent — the row whose TARGET is ``batch_id`` (it was itself a
    successor or rehome target, now retired). Intents whose SOURCE is ``batch_id`` are deliberately
    kept: in the same swap that retires ``batch_id`` its own successor is being created, and that
    new successor's intent has ``batch_id`` as its source and must survive. Best-effort cleanup."""

    try:
        connection.execute(f"DELETE FROM {_INTENTS} WHERE target_batch_id = ?", (batch_id,))
    except sqlite3.Error:  # pragma: no cover - best-effort; a stale intent is harmless
        pass


__all__ = [
    "REHOME_SEQUENCE",
    "clear_intents_for_segment",
    "clear_rehome_intent",
    "is_recorded_successor",
    "read_rehome_target",
    "read_sequence",
    "record_rehome_intent",
    "record_successor_intent",
    "set_sequence",
]
