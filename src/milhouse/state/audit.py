"""Append-only maintenance audit trail (W03 slice 5b, plan sections 4.4/4.6/4.9; D05 privacy fix).

Every deliberate maintenance mutation — retention pruning, compaction, purge, restore — records one
append-only row in ``_audit`` describing what happened in privacy-safe terms: a fixed action code, a
fixed actor class, a fixed outcome and reason code, an optional KEYED resource pseudonym, and safe
counts. An audit row never carries the acted-on raw payload, a secret, a path, a URL, or free text
(plan section 4.6 ``audit``, ADR 0007).

The public surface is a set of **purpose-specific constructors** (e.g.
:func:`record_retention_prune`) rather than a free-text sink: each constructor fixes its own
action/actor/outcome/reason codes as constants, so a caller cannot inject arbitrary text into those
fields. The one caller-supplied identifier — a batch id — is charset-validated and, per plan section
4.7, may be persisted ONLY as an installation-keyed HMAC pseudonym, never as a public unsalted hash
(a plain SHA-256 of a low-entropy id is dictionary-recoverable and correlates across installations).
The pseudonym key is created by ``init`` (W06) and is not yet wired into the control plane, so when
no :class:`~milhouse.privacy.pseudonym.Pseudonymizer` is supplied the identifier derivative is
OMITTED (the resource is ``NULL``) rather than stored reversibly — exactly as ``spooling/reconcile``
already does. Recording is transaction-scoped: the caller writes the row on the SAME open
connection, in the SAME transaction as the mutation it attests, so the trail and the state commit or
roll back together. Every fault normalizes to a fixed ``MH_STATE_AUDIT`` code raised outside the
handler.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, NoReturn

from milhouse.core.clock import TimeError, format_timestamp
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

if TYPE_CHECKING:
    from milhouse.privacy.pseudonym import Pseudonymizer

_AUDIT_TABLE = "_audit"
_MAX_COUNT = 2**63 - 1  # the largest value SQLite's signed 64-bit INTEGER can store
_DEFAULT_LIMIT = 1000
_MAX_LIMIT = 100_000
# An opaque resource identifier: a batch/target id shape. It admits ``[A-Za-z0-9._-]`` starting
# alphanumeric and so rejects every raw-text canary — a path (``/``), email (``@``), URL (``://``),
# prompt or multiline (whitespace/newline), and most secret/payload shapes.
_RESOURCE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", flags=re.ASCII)


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


def _validate_resource(value: object) -> str:
    if type(value) is not str or _RESOURCE_PATTERN.fullmatch(value) is None:
        _fail("MH_STATE_AUDIT", "an audit resource must be an opaque identifier, not free text")
    return value


_RESOURCE_KIND = "batch"


def _keyed_resource(pseudonymizer: Pseudonymizer | None, batch_id: str) -> str | None:
    """Return the keyed HMAC pseudonym of ``batch_id``, or ``None`` when no key is wired.

    Plan section 4.7 requires a persisted identifier derivative to be a keyed installation-local
    HMAC pseudonym, never a public unsalted hash. The pseudonym key is created by ``init`` (W06) and
    is not yet wired into the control plane, so when no pseudonymizer is supplied the derivative is
    OMITTED rather than persisted as a reversible hash — the precedent ``spooling/reconcile`` sets.
    When a key is wired, the same call yields a keyed ``mh_fp1_`` token, no schema change.
    """

    if pseudonymizer is None:
        return None
    return pseudonymizer.fingerprint(_RESOURCE_KIND, batch_id)


def _validate_count(value: object, subject: str) -> int:
    # ``bool`` is an ``int`` subtype; reject it so a stray flag cannot pose as a count. The upper
    # bound keeps a too-large count from overflowing the signed-64 INTEGER binding at INSERT.
    if type(value) is not int or not 0 <= value <= _MAX_COUNT:
        _fail("MH_STATE_AUDIT", f"an audit {subject} must be a whole number in 0..2^63-1")
    return value


def _insert_audit(
    connection: sqlite3.Connection,
    *,
    now: datetime,
    action: str,
    actor: str,
    outcome: str,
    resource: str | None,
    reason: str,
    record_count: int,
    byte_size: int,
) -> None:
    """Insert one audit row. Internal: only the typed constructors call it, with fixed codes.

    ``action``/``actor``/``outcome``/``reason`` are code constants owned by the calling constructor,
    never caller free text; ``resource`` is a keyed pseudonym or ``None`` and the counts are the
    already-validated caller data. Only the timestamp is validated here before the insert; any
    residual backend fault normalizes to the fixed code.
    """

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


def record_retention_prune(
    connection: sqlite3.Connection,
    *,
    now: datetime,
    batch_id: str,
    record_count: int,
    byte_size: int,
    undelivered: bool,
    pseudonymizer: Pseudonymizer | None = None,
) -> None:
    """Record that retention pruned one committed segment, on the caller's open transaction.

    The action/actor/outcome/reason codes are fixed here, so no free text reaches the audit row. The
    only caller-supplied identifier is ``batch_id``: it is charset-validated and persisted only as a
    keyed pseudonym when ``pseudonymizer`` is supplied, and OMITTED (resource ``NULL``) otherwise,
    so a reversible unsalted hash is never stored (plan section 4.7). ``undelivered`` distinguishes
    the critical case where the segment reached its privacy deadline before it was exported. Call
    inside the same transaction as the prune so the two commit or roll back together.
    """

    if type(undelivered) is not bool:
        _fail("MH_STATE_AUDIT", "the undelivered flag must be a boolean")
    _validate_resource(batch_id)
    _validate_count(record_count, "record count")
    _validate_count(byte_size, "byte size")
    _insert_audit(
        connection,
        now=now,
        action="retention_prune",
        actor="maintenance",
        outcome="pruned_undelivered" if undelivered else "pruned",
        reason="expired_undelivered" if undelivered else "expired",
        resource=_keyed_resource(pseudonymizer, batch_id),
        record_count=record_count,
        byte_size=byte_size,
    )


def record_compaction(
    connection: sqlite3.Connection,
    *,
    now: datetime,
    old_batch_id: str,
    new_batch_id: str,
    old_record_count: int,
    old_byte_size: int,
    new_record_count: int,
    new_byte_size: int,
    pseudonymizer: Pseudonymizer | None = None,
) -> None:
    """Record a mixed-expiry compaction as a linked pair of append-only audit rows.

    The ``_audit`` table carries one resource per row, so old→new lineage is expressed as two rows
    written on the caller's transaction: a ``compacted_from`` row for the superseded old segment and
    a ``compacted_into`` row for the new segment. They share ``action="compaction"`` and
    ``recorded_at``, and their adjacent ids preserve the from→into order. Each batch id is
    charset-validated and persisted only as a keyed pseudonym when ``pseudonymizer`` is supplied,
    OMITTED (resource ``NULL``) otherwise, so a reversible unsalted hash is never stored (plan
    section 4.7). The dropped (expired) record count is the difference of the two ``record_count``
    values.
    Call inside the same transaction as the ledger swap so the lineage and the state commit or roll
    back together.
    """

    _validate_resource(old_batch_id)
    _validate_resource(new_batch_id)
    _validate_count(old_record_count, "record count")
    _validate_count(old_byte_size, "byte size")
    _validate_count(new_record_count, "record count")
    _validate_count(new_byte_size, "byte size")
    _insert_audit(
        connection,
        now=now,
        action="compaction",
        actor="maintenance",
        outcome="compacted_from",
        reason="mixed_expiry",
        resource=_keyed_resource(pseudonymizer, old_batch_id),
        record_count=old_record_count,
        byte_size=old_byte_size,
    )
    _insert_audit(
        connection,
        now=now,
        action="compaction",
        actor="maintenance",
        outcome="compacted_into",
        reason="mixed_expiry",
        resource=_keyed_resource(pseudonymizer, new_batch_id),
        record_count=new_record_count,
        byte_size=new_byte_size,
    )


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
    if action is not None and (type(action) is not str or not action):
        _fail("MH_STATE_AUDIT", "an audit action filter must be non-empty text")
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
