"""Append-only maintenance audit trail (W03 slice 5b, plan sections 4.4/4.6/4.9).

Every deliberate maintenance mutation — retention pruning, compaction, purge, restore — records one
append-only row in ``_audit`` describing what happened in privacy-safe terms: the action, the actor
class, an optional opaque resource id, an outcome, a safe coded reason, and safe counts. An audit
row never carries the acted-on raw payload (plan section 4.6 ``audit``).

:func:`record_audit` is transaction-scoped: the caller records the audit row on the SAME open
connection, inside the SAME transaction, as the mutation it attests (e.g. the ledger prune), so the
trail and the state it describes commit or roll back together and can never diverge. Inputs are
fully validated before the insert so a malformed entry fails closed with a fixed ``MH_STATE_AUDIT``
code rather than tripping a database CHECK; the CHECK constraints remain as defense in depth. The
read side normalizes any SQLite fault to the same fixed code raised outside the handler.
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

_AUDIT_TABLE = "_audit"
_MAX_TEXT = 1024
_MAX_COUNT = 2**63 - 1  # the largest value SQLite's signed 64-bit INTEGER can store
_DEFAULT_LIMIT = 1000
_MAX_LIMIT = 100_000


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One append-only maintenance audit entry as recorded in the control database."""

    id: int
    recorded_at: str
    action: str
    actor: str
    outcome: str
    resource: str | None
    reason: str | None
    record_count: int | None
    byte_size: int | None


def _validate_required_text(value: object, subject: str) -> str:
    if type(value) is not str or not 0 < len(value) <= _MAX_TEXT:
        _fail("MH_STATE_AUDIT", f"an audit {subject} must be bounded non-empty text")
    return value


def _validate_optional_text(value: object, subject: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not 0 < len(value) <= _MAX_TEXT:
        _fail("MH_STATE_AUDIT", f"an audit {subject} must be bounded non-empty text or absent")
    return value


def _validate_optional_count(value: object, subject: str) -> int | None:
    if value is None:
        return None
    # ``bool`` is an ``int`` subtype; reject it so a stray flag cannot pose as a count. The upper
    # bound keeps a too-large count from overflowing the signed-64 INTEGER binding at INSERT and
    # escaping as a raw OverflowError instead of the fixed code.
    if type(value) is not int or not 0 <= value <= _MAX_COUNT:
        _fail("MH_STATE_AUDIT", f"an audit {subject} must be a whole number in 0..2^63-1 or absent")
    return value


def record_audit(
    connection: sqlite3.Connection,
    *,
    now: datetime,
    action: str,
    actor: str,
    outcome: str,
    resource: str | None = None,
    reason: str | None = None,
    record_count: int | None = None,
    byte_size: int | None = None,
) -> None:
    """Append one audit row on the caller's open transaction connection.

    Call this inside the same transaction as the mutation it describes so the trail and the state
    commit or roll back atomically together. Every field is validated first; a malformed entry fails
    closed with ``MH_STATE_AUDIT`` before any write.
    """

    _validate_required_text(action, "action")
    _validate_required_text(actor, "actor")
    _validate_required_text(outcome, "outcome")
    _validate_optional_text(resource, "resource")
    _validate_optional_text(reason, "reason")
    _validate_optional_count(record_count, "record count")
    _validate_optional_count(byte_size, "byte size")
    invalid_time = False
    recorded_at = ""
    try:
        recorded_at = format_timestamp(now)
    except (OverflowError, TimeError):
        invalid_time = True
    if invalid_time:
        _fail("MH_STATE_AUDIT", "an audit timestamp must be an aware in-range UTC instant")
    failed = False
    try:
        connection.execute(
            f"INSERT INTO {_AUDIT_TABLE} "
            "(recorded_at, action, actor, outcome, resource, reason, record_count, byte_size) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (recorded_at, action, actor, outcome, resource, reason, record_count, byte_size),
        )
    except (sqlite3.Error, OverflowError):
        # Normalize any residual backend fault to the fixed code raised outside the handler, so no
        # SQLite/binding detail escapes; the caller's transaction still rolls back.
        failed = True
    if failed:
        _fail("MH_STATE_AUDIT", "the audit row could not be recorded")


def _row_to_audit(row: Sequence[Any]) -> AuditRecord:
    return AuditRecord(
        id=int(row[0]),
        recorded_at=str(row[1]),
        action=str(row[2]),
        actor=str(row[3]),
        outcome=str(row[4]),
        resource=None if row[5] is None else str(row[5]),
        reason=None if row[6] is None else str(row[6]),
        record_count=None if row[7] is None else int(row[7]),
        byte_size=None if row[8] is None else int(row[8]),
    )


def list_audit(
    database: ControlDatabase, *, action: str | None = None, limit: int = _DEFAULT_LIMIT
) -> tuple[AuditRecord, ...]:
    """Return audit rows in append order (oldest first), optionally filtered to one ``action``."""

    if type(limit) is not int or not 0 < limit <= _MAX_LIMIT:
        _fail("MH_STATE_AUDIT", "an audit read limit must be a whole number in 1..100000")
    if action is not None:
        _validate_required_text(action, "action")
    rows: list[tuple[Any, ...]] = []
    failed = False
    columns = "id, recorded_at, action, actor, outcome, resource, reason, record_count, byte_size"
    try:
        if action is None:
            rows = database.connection.execute(
                f"SELECT {columns} FROM {_AUDIT_TABLE} ORDER BY id LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = database.connection.execute(
                f"SELECT {columns} FROM {_AUDIT_TABLE} WHERE action = ? ORDER BY id LIMIT ?",
                (action, limit),
            ).fetchall()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("MH_STATE_AUDIT", "the audit trail could not be read")
    return tuple(_row_to_audit(row) for row in rows)
