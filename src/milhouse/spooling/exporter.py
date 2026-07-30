"""Exporter delivery protocol over the segment delivery ledger (W03 slice 4, pipeline rules 11-12).

An exporter forwards a committed segment's frames to one destination (a warehouse, an alert sink).
This module owns the *protocol* and the *ledger state machine*, not any concrete destination: the
concrete ClickHouse exporter is W04. The :class:`Exporter` contract is deliberately narrow — an id
and a ``deliver`` that returns on destination confirmation and raises on any failure.

The delivery ledger (``_segment_exporters.delivery_status``) is a per-(segment, exporter) state
machine: ``pending``/``failed`` are retryable, ``delivered`` is terminal. Rule 12 requires the
exporter checkpoint to advance only after the destination confirms, so :func:`deliver_segment`
attempts delivery *outside* the barrier and, only once ``deliver`` returns, records ``delivered`` in
one shared-barrier transaction. The status write is a compare-and-set that never overwrites a
``delivered`` row, so a concurrent or replayed delivery cannot un-deliver a segment and a
double-attempt is a no-op. Because a crash between confirmation and the status write leaves the row
retryable, the delivery is at-least-once and exporters MUST be idempotent.

Every SQLite or barrier failure normalizes to a fixed ``MH_SPOOL_EXPORT`` error raised outside the
handler, and a misbehaving exporter that raises an arbitrary exception is contained as a failed
delivery rather than crashing the pipeline.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import NoReturn, Protocol, runtime_checkable

from milhouse.spooling.errors import SpoolError
from milhouse.spooling.ledger import SegmentRecord
from milhouse.spooling.segment import EXPORTER_ID_PATTERN, SpoolFrameV1
from milhouse.state.barrier import GlobalCommitBarrier
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_DELIVERED = "delivered"
_FAILED = "failed"

# Attempt outcomes reported back to the caller. The first two mutate the ledger; the rest explain
# why no delivery was attempted for that exporter on this pass.
OUTCOME_DELIVERED = "delivered"
OUTCOME_FAILED = "failed"
OUTCOME_ALREADY_DELIVERED = "already_delivered"
OUTCOME_NO_EXPORTER = "no_exporter"


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


@runtime_checkable
class Exporter(Protocol):
    """A destination that forwards a segment's frames, confirming delivery by returning normally."""

    @property
    def exporter_id(self) -> str: ...

    def deliver(self, record: SegmentRecord, frames: Sequence[SpoolFrameV1]) -> None:
        """Forward ``frames`` for ``record`` to the destination; raise on any delivery failure."""


@dataclass(frozen=True, slots=True)
class ExporterAttempt:
    """The outcome of one exporter's delivery attempt for one segment on a single pass."""

    batch_id: str
    exporter_id: str
    outcome: str


def _record_status(
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    batch_id: str,
    exporter_id: str,
    status: str,
) -> None:
    """Compare-and-set the delivery status under the shared barrier; never clobber ``delivered``.

    The ``delivery_status != 'delivered'`` guard makes ``delivered`` terminal: a late ``failed``
    from a slower attempt cannot overwrite a delivery another pass already confirmed, and
    re-recording ``delivered`` is idempotent.
    """

    failed = False
    try:
        with barrier.shared(), database.transaction() as connection:
            connection.execute(
                "UPDATE _segment_exporters SET delivery_status = ? "
                "WHERE batch_id = ? AND exporter_id = ? AND delivery_status != ?",
                (status, batch_id, exporter_id, _DELIVERED),
            )
    except (sqlite3.Error, StateError):
        failed = True
    if failed:
        _fail("MH_SPOOL_EXPORT", "the exporter delivery status could not be recorded")


def _attempt_delivery(
    exporter: Exporter, record: SegmentRecord, frames: Sequence[SpoolFrameV1]
) -> bool:
    # A confirmed delivery is a normal return; any exception — including one a third-party exporter
    # raises — is contained as a retryable failure so one destination cannot crash the pipeline.
    try:
        exporter.deliver(record, frames)
    except Exception:
        return False
    return True


def deliver_segment(
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    record: SegmentRecord,
    frames: Sequence[SpoolFrameV1],
    exporters: Mapping[str, Exporter],
) -> tuple[ExporterAttempt, ...]:
    """Attempt every not-yet-delivered exporter for ``record`` and record each outcome.

    Delivery is attempted outside the barrier; only a confirmed delivery (or a contained failure) is
    written back, in a shared-barrier compare-and-set that leaves ``delivered`` terminal. Exporters
    already ``delivered`` are skipped, and an exporter the caller did not supply is reported as
    ``no_exporter`` without touching the ledger.
    """

    if type(database) is not ControlDatabase:
        _fail("MH_SPOOL_EXPORT", "a control database is required")
    if type(barrier) is not GlobalCommitBarrier:
        _fail("MH_SPOOL_EXPORT", "a commit barrier is required")
    if not isinstance(record, SegmentRecord):
        _fail("MH_SPOOL_EXPORT", "a segment record is required")

    attempts: list[ExporterAttempt] = []
    for exporter_row in record.exporters:
        exporter_id = exporter_row.exporter_id
        if exporter_row.delivery_status == _DELIVERED:
            attempts.append(
                ExporterAttempt(record.batch_id, exporter_id, OUTCOME_ALREADY_DELIVERED)
            )
            continue
        exporter = exporters.get(exporter_id)
        if exporter is None or EXPORTER_ID_PATTERN.fullmatch(exporter_id) is None:
            attempts.append(ExporterAttempt(record.batch_id, exporter_id, OUTCOME_NO_EXPORTER))
            continue
        delivered = _attempt_delivery(exporter, record, frames)
        status = _DELIVERED if delivered else _FAILED
        _record_status(database, barrier, record.batch_id, exporter_id, status)
        outcome = OUTCOME_DELIVERED if delivered else OUTCOME_FAILED
        attempts.append(ExporterAttempt(record.batch_id, exporter_id, outcome))
    return tuple(attempts)
