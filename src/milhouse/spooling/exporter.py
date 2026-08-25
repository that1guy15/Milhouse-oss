"""Exporter delivery protocol over the segment delivery ledger (W03 slice 4, pipeline rules 11-12).

An exporter forwards a committed segment's frames to one destination (a warehouse, an alert sink).
This module owns the *protocol* and the *ledger state machine*, not any concrete destination: the
concrete ClickHouse exporter is W04. The :class:`Exporter` contract is deliberately narrow — an id
and a ``deliver`` that returns on destination confirmation and raises on any failure.

Delivery is integrity-bound so a terminal ``delivered`` can never be recorded for the wrong data
(D05): :func:`deliver_segment` freezes the caller's frames into one immutable tuple, binds the
barrier to the live control database, reloads the segment's authoritative ledger row and rejects a
supplied record that does not match it, and requires that exact frozen tuple to hash to the row's
``content_sha256`` (with matching batch id and count) before a single byte is forwarded — so a
caller cannot validate one frame set and forward another, nor forward one segment's frames while
certifying another. It also requires each exporter object to self-identify as the row it delivers.

Delivery is *fenced* and *expiry-aware* (D05 re-review):

* **Fenced.** The whole reload → forward → checkpoint runs under a single ``barrier.shared()`` hold,
  so privacy-expiry ``retention_apply`` (which prunes under the *exclusive* side) cannot delete a
  segment mid-delivery. The shared side is held across the destination round-trip; maintenance waits
  for in-flight deliveries to drain, exactly as a readers-writer lock requires.
* **Expiry-aware.** A segment with any expired record is withheld — never forwarded — because
  record-class privacy expiry is a hard upper bound (plan §§4.8-4.9): expired data must never
  egress, even if retention has not pruned it yet. A mixed-expiry segment is withheld (fail-closed)
  rather than leaking its expired records; rewriting it into a live-only segment is deferred
  compaction work (plan §4.7).

The delivery ledger (``_segment_exporters.delivery_status``) is a per-(segment, exporter) state
machine: ``pending``/``failed`` are retryable, ``delivered`` is terminal. Rule 12 requires the
exporter checkpoint to advance only after the destination confirms, so delivery is recorded, once
``deliver`` returns, in one compare-and-set that never overwrites a ``delivered`` row. That CAS is
authoritative: only a CAS that actually advances the expected row is reported as a new delivery, a
row that is already ``delivered`` is reported ``already_delivered``, and a row that has *vanished*
(pruned out from under the delivery) is reported ``segment_gone`` — never conflated with a delivery.
A crash between confirmation and the write leaves the row retryable, so delivery is at-least-once
and exporters MUST be idempotent. Every SQLite or barrier failure normalizes to a fixed
``MH_SPOOL_EXPORT`` error, and a misbehaving exporter that raises is contained as a failed delivery.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn, Protocol, runtime_checkable

from milhouse.core.clock import TimeError, format_timestamp
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

# Compare-and-set outcomes of the delivery-status write, under the already-held shared barrier.
_CAS_ADVANCED = "advanced"
_CAS_ALREADY = "already"
_CAS_GONE = "gone"

# Attempt outcomes reported back to the caller. The first two mutate the ledger; the rest explain
# why no delivery was newly recorded for that exporter on this pass.
OUTCOME_DELIVERED = "delivered"
OUTCOME_FAILED = "failed"
OUTCOME_ALREADY_DELIVERED = "already_delivered"
OUTCOME_NO_EXPORTER = "no_exporter"
OUTCOME_EXPIRED = "expired"
OUTCOME_SEGMENT_GONE = "segment_gone"


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


def _require_now(now: object) -> None:
    invalid = False
    try:
        format_timestamp(now)  # type: ignore[arg-type]  # rejects a naive/out-of-range instant
    except (OverflowError, TimeError, AttributeError, TypeError):
        invalid = True
    if invalid:
        _fail("MH_SPOOL_EXPORT", "the delivery instant must be an aware in-range UTC instant")


def _require_bound_barrier(database: ControlDatabase, barrier: GlobalCommitBarrier) -> None:
    database_path = _validated_database_path(database)
    if database_path is None or not _is_bound_barrier(
        barrier, database_path.parent / _BARRIER_NAME
    ):
        # Bind the barrier to THIS database's commit lock: the shared hold only fences maintenance
        # and serializes the CAS if it is on the same lock the writers and retention use.
        _fail("MH_SPOOL_EXPORT", "the barrier must be the control-plane commit lock")


def _reload_record(database: ControlDatabase, record: SegmentRecord) -> SegmentRecord:
    """Reload the ledger row for ``record`` and reject a stale or fabricated record."""

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

    The definitive check is that the frames' canonical bytes hash to ``content_sha256``;
    the count and batch-id checks give a precise failure for the common wrong-segment case.
    Without this a caller could forward one segment's records while certifying delivery of another.
    ``frames`` is the already-frozen tuple, so this validates the exact object that is forwarded.
    """

    if len(frames) != record.record_count:
        _fail("MH_SPOOL_EXPORT", "the frame count does not match the segment")
    if any(frame.batch_id != record.batch_id for frame in frames):
        _fail("MH_SPOOL_EXPORT", "a frame does not belong to the segment")
    if spool_content_sha256([spool_frame_line(frame) for frame in frames]) != record.content_sha256:
        _fail("MH_SPOOL_EXPORT", "the frames do not match the segment content digest")


def _segment_is_expired(frames: Sequence[SpoolFrameV1], now: datetime) -> bool:
    """Return whether ANY record in ``frames`` has reached its ``expires_at`` at ``now``.

    Record-class privacy expiry is a hard upper bound: a fully-live segment (every record still
    unexpired) may egress; a mixed or fully-expired one is withheld (fail-closed), so no expired
    record is ever forwarded. Stripping expired records out of a mixed segment is deferred
    compaction work (plan §4.7). An empty frame set carries no record to reason about, not expired.
    """

    if not frames:
        return False
    return min(frame.record.expires_at for frame in frames) <= now


def _advance_status_locked(
    database: ControlDatabase, batch_id: str, exporter_id: str, status: str
) -> str:
    """Compare-and-set the delivery status; the caller already holds the shared barrier.

    Returns ``_CAS_ADVANCED`` when this call moved the row to ``status`` (affected exactly one row),
    ``_CAS_ALREADY`` when the row is already terminal ``delivered`` (the CAS matched nothing), or
    ``_CAS_GONE`` when the row no longer exists. Distinguishing a vanished row from an
    already-delivered one is what keeps a segment pruned out from under an in-flight delivery from
    ever being reported as delivered. The barrier is NOT re-acquired here — nesting ``shared()``
    under a queued exclusive maintainer could deadlock at the turnstile gate — so the single shared
    hold taken by :func:`deliver_segment` serializes this CAS against maintenance.
    """

    failed = False
    result = _CAS_GONE
    try:
        with database.transaction() as connection:
            cursor = connection.execute(
                "UPDATE _segment_exporters SET delivery_status = ? "
                "WHERE batch_id = ? AND exporter_id = ? AND delivery_status != ?",
                (status, batch_id, exporter_id, _DELIVERED),
            )
            if cursor.rowcount == 1:
                result = _CAS_ADVANCED
            else:
                row = connection.execute(
                    "SELECT delivery_status FROM _segment_exporters "
                    "WHERE batch_id = ? AND exporter_id = ?",
                    (batch_id, exporter_id),
                ).fetchone()
                result = _CAS_GONE if row is None else _CAS_ALREADY
    except (sqlite3.Error, StateError):
        failed = True
    if failed:
        _fail("MH_SPOOL_EXPORT", "the exporter delivery status could not be recorded")
    return result


def _self_identifies(exporter: Exporter, exporter_id: str) -> bool:
    # The exporter object is the least-trusted input; contain a misbehaving ``exporter_id`` property
    # (one that raises anything, not only AttributeError) as a mis-identification rather than
    # letting a raw exception escape the fixed-code contract.
    try:
        return exporter.exporter_id == exporter_id
    except Exception:
        return False


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


def _delivered_outcome(cas_result: str) -> str:
    if cas_result == _CAS_ADVANCED:
        return OUTCOME_DELIVERED
    if cas_result == _CAS_ALREADY:
        return OUTCOME_ALREADY_DELIVERED
    # The row vanished (pruned) between reload and CAS: never certify a delivery for it.
    return OUTCOME_SEGMENT_GONE


def deliver_segment(
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    record: SegmentRecord,
    frames: Sequence[SpoolFrameV1],
    exporters: Mapping[str, Exporter],
    *,
    now: datetime,
) -> tuple[ExporterAttempt, ...]:
    """Attempt every not-yet-delivered exporter for ``record`` and record each outcome.

    The caller's ``frames`` are frozen to one immutable tuple up front, and that exact tuple is both
    validated against the reloaded ledger row and forwarded. The whole reload → forward → checkpoint
    runs under one ``barrier.shared()`` hold, so privacy-expiry retention cannot prune a segment
    mid-delivery. A segment with any expired record is withheld (``expired``) and never forwarded.
    Delivery is attempted while the shared side is held; only a confirmed delivery whose CAS
    advances the expected row is reported ``delivered``, an already-terminal row is
    ``already_delivered``, and a row pruned out from under the delivery is ``segment_gone``.
    Exporters already ``delivered`` are skipped; an unknown or mis-identified exporter is
    reported ``no_exporter`` without touching the ledger.
    """

    if type(database) is not ControlDatabase:
        _fail("MH_SPOOL_EXPORT", "a control database is required")
    if type(barrier) is not GlobalCommitBarrier:
        _fail("MH_SPOOL_EXPORT", "a commit barrier is required")
    if not isinstance(record, SegmentRecord):
        _fail("MH_SPOOL_EXPORT", "a segment record is required")
    if not isinstance(exporters, Mapping):
        _fail("MH_SPOOL_EXPORT", "an exporter mapping is required")
    _require_now(now)
    # Freeze the caller-owned sequence to one immutable snapshot BEFORE validating or forwarding, so
    # a sequence that yields different contents on a second read cannot deliver one batch while the
    # digest check certified another (D05 re-review).
    frames = tuple(frames)
    if any(not isinstance(frame, SpoolFrameV1) for frame in frames):
        _fail("MH_SPOOL_EXPORT", "a segment frame is malformed")
    _require_bound_barrier(database, barrier)

    attempts: list[ExporterAttempt] = []
    with barrier.shared():
        live = _reload_record(database, record)
        _require_frames_belong(live, frames)
        if _segment_is_expired(frames, now):
            # Hard privacy expiry: withhold the whole segment. Forward nothing; report each exporter
            # so the caller sees the segment was withheld (not delivered, not failed).
            return tuple(
                ExporterAttempt(
                    live.batch_id,
                    row.exporter_id,
                    OUTCOME_ALREADY_DELIVERED
                    if row.delivery_status == _DELIVERED
                    else OUTCOME_EXPIRED,
                )
                for row in live.exporters
            )
        for exporter_row in live.exporters:
            exporter_id = exporter_row.exporter_id
            if exporter_row.delivery_status == _DELIVERED:
                attempts.append(
                    ExporterAttempt(live.batch_id, exporter_id, OUTCOME_ALREADY_DELIVERED)
                )
                continue
            exporter = exporters.get(exporter_id)
            if (
                exporter is None
                or EXPORTER_ID_PATTERN.fullmatch(exporter_id) is None
                or not _self_identifies(exporter, exporter_id)
            ):
                # Unknown, malformed, or a mis-identified exporter object (one registered under a
                # key it does not claim as its own id) must never certify delivery.
                attempts.append(ExporterAttempt(live.batch_id, exporter_id, OUTCOME_NO_EXPORTER))
                continue
            delivered = _attempt_delivery(exporter, live, frames)
            if delivered:
                cas_result = _advance_status_locked(
                    database, live.batch_id, exporter_id, _DELIVERED
                )
                outcome = _delivered_outcome(cas_result)
            else:
                _advance_status_locked(database, live.batch_id, exporter_id, _FAILED)
                outcome = OUTCOME_FAILED
            attempts.append(ExporterAttempt(live.batch_id, exporter_id, outcome))
    return tuple(attempts)
