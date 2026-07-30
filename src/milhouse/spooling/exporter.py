"""Exporter delivery protocol over the segment delivery ledger (W03 slice 4, pipeline rules 11-12).

An exporter forwards a committed segment's frames to one destination (a warehouse, an alert sink).
This module owns the *protocol* and the *ledger state machine*, not any concrete destination: the
concrete ClickHouse exporter is W04. The :class:`Exporter` contract is deliberately narrow — an id
and a ``deliver`` that returns on destination confirmation and raises on any failure.

Delivery is integrity-bound so a terminal ``delivered`` can never be recorded for the wrong data
(D05): :func:`deliver_segment` binds the barrier to the live control database, reloads the segment's
authoritative ledger row and rejects a supplied record that does not match it, and requires the
supplied frames to hash to that row's ``content_sha256`` (with matching batch id and count) before a
single byte is forwarded — so a caller cannot forward one segment's frames while certifying another.
It also requires each exporter object to self-identify as the ledger row it is delivering, and treats
the final compare-and-set as authoritative: only a CAS that actually advances the expected row to
``delivered`` is reported as a new delivery.

The delivery ledger (``_segment_exporters.delivery_status``) is a per-(segment, exporter) state
machine: ``pending``/``failed`` are retryable, ``delivered`` is terminal. Rule 12 requires the
exporter checkpoint to advance only after the destination confirms, so delivery is attempted *outside*
the barrier and, only once ``deliver`` returns, recorded in one shared-barrier compare-and-set that
never overwrites a ``delivered`` row. A crash between confirmation and the write leaves the row
retryable, so delivery is at-least-once and exporters MUST be idempotent. Every SQLite or barrier
failure normalizes to a fixed ``MH_SPOOL_EXPORT`` error, and a misbehaving exporter that raises is
contained as a failed delivery.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import NoReturn, Protocol, runtime_checkable

from milhouse.spooling.errors import SpoolError
from milhouse.spooling.ledger import SegmentRecord, read_segment_record
from milhouse.spooling.segment import (
    EXPORTER_ID_PATTERN,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.state.barrier import GlobalCommitBarrier, _is_bound_barrier
from milhouse.state.database import ControlDatabase, _validated_database_path
from milhouse.state.errors import StateError

_DELIVERED = "delivered"
_FAILED = "failed"
_BARRIER_NAME = "commit.lock"

# Attempt outcomes reported back to the caller. The first two mutate the ledger; the rest explain
# why no delivery was newly recorded for that exporter on this pass.
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


def _require_bound_barrier(database: ControlDatabase, barrier: GlobalCommitBarrier) -> None:
    database_path = _validated_database_path(database)
    if database_path is None or not _is_bound_barrier(
        barrier, database_path.parent / _BARRIER_NAME
    ):
        # Bind the barrier to THIS database's commit lock: the delivery CAS is serialized only if the
        # shared hold is on the same lock the writers use.
        _fail("MH_SPOOL_EXPORT", "the barrier must be the control-plane commit lock")


def _reload_record(database: ControlDatabase, record: SegmentRecord) -> SegmentRecord:
    """Reload the authoritative ledger row for ``record`` and reject a stale or fabricated record."""

    live = read_segment_record(database, record.batch_id)
    if live is None:
        _fail("MH_SPOOL_EXPORT", "the segment is not committed")
    if (
        live.content_sha256 != record.content_sha256
        or live.file_sha256 != record.file_sha256
        or live.record_count != record.record_count
        or live.byte_size != record.byte_size
    ):
        _fail("MH_SPOOL_EXPORT", "the supplied record does not match the committed segment")
    return live


def _require_frames_belong(record: SegmentRecord, frames: Sequence[SpoolFrameV1]) -> None:
    """Require ``frames`` to be exactly the committed segment's frames, or fail closed.

    The definitive check is that the frames' canonical bytes hash to the ledger's ``content_sha256``;
    the count and per-frame batch-id checks give a precise failure for the common wrong-segment case.
    Without this a caller could forward one segment's records while certifying delivery of another.
    """

    if len(frames) != record.record_count:
        _fail("MH_SPOOL_EXPORT", "the frame count does not match the segment")
    if any(frame.batch_id != record.batch_id for frame in frames):
        _fail("MH_SPOOL_EXPORT", "a frame does not belong to the segment")
    if spool_content_sha256([spool_frame_line(frame) for frame in frames]) != record.content_sha256:
        _fail("MH_SPOOL_EXPORT", "the frames do not match the segment content digest")


def _advance_status(
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    batch_id: str,
    exporter_id: str,
    status: str,
) -> int:
    """Compare-and-set the delivery status under the shared barrier; return the affected row count.

    The ``delivery_status != 'delivered'`` guard makes ``delivered`` terminal: a late ``failed`` from
    a slower attempt cannot overwrite a confirmed delivery, and re-recording ``delivered`` is a no-op.
    A zero affected-row count means the expected row was already terminal (or gone), so the caller
    does not report a new delivery.
    """

    affected = 0
    failed = False
    try:
        with barrier.shared(), database.transaction() as connection:
            cursor = connection.execute(
                "UPDATE _segment_exporters SET delivery_status = ? "
                "WHERE batch_id = ? AND exporter_id = ? AND delivery_status != ?",
                (status, batch_id, exporter_id, _DELIVERED),
            )
            affected = cursor.rowcount
    except (sqlite3.Error, StateError):
        failed = True
    if failed:
        _fail("MH_SPOOL_EXPORT", "the exporter delivery status could not be recorded")
    return affected


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

    The barrier is bound to the database, the ledger row is reloaded and the supplied record and
    frames are validated against it before anything is forwarded, and each exporter object must
    self-identify. Delivery is attempted outside the barrier; only a confirmed delivery that the
    compare-and-set actually advances to ``delivered`` (affected-row count of one) is reported as a
    new delivery. Exporters already ``delivered`` are skipped and an unknown or mis-identified
    exporter is reported ``no_exporter`` without touching the ledger.
    """

    if type(database) is not ControlDatabase:
        _fail("MH_SPOOL_EXPORT", "a control database is required")
    if type(barrier) is not GlobalCommitBarrier:
        _fail("MH_SPOOL_EXPORT", "a commit barrier is required")
    if not isinstance(record, SegmentRecord):
        _fail("MH_SPOOL_EXPORT", "a segment record is required")
    if not isinstance(exporters, Mapping):
        _fail("MH_SPOOL_EXPORT", "an exporter mapping is required")
    _require_bound_barrier(database, barrier)
    live = _reload_record(database, record)
    _require_frames_belong(live, frames)

    attempts: list[ExporterAttempt] = []
    for exporter_row in live.exporters:
        exporter_id = exporter_row.exporter_id
        if exporter_row.delivery_status == _DELIVERED:
            attempts.append(ExporterAttempt(live.batch_id, exporter_id, OUTCOME_ALREADY_DELIVERED))
            continue
        exporter = exporters.get(exporter_id)
        if (
            exporter is None
            or EXPORTER_ID_PATTERN.fullmatch(exporter_id) is None
            or getattr(exporter, "exporter_id", None) != exporter_id
        ):
            # Unknown, malformed, or a mis-identified exporter object (registered under a key it does
            # not claim as its own id) must never certify delivery.
            attempts.append(ExporterAttempt(live.batch_id, exporter_id, OUTCOME_NO_EXPORTER))
            continue
        delivered = _attempt_delivery(exporter, live, frames)
        status = _DELIVERED if delivered else _FAILED
        affected = _advance_status(database, barrier, live.batch_id, exporter_id, status)
        if delivered:
            outcome = OUTCOME_DELIVERED if affected == 1 else OUTCOME_ALREADY_DELIVERED
        else:
            outcome = OUTCOME_FAILED
        attempts.append(ExporterAttempt(live.batch_id, exporter_id, outcome))
    return tuple(attempts)
