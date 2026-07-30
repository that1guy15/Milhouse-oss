"""Spool retention: preview and apply over committed segments (W03 slice 5b, plan section 4.8/4.9).

Retention is driven by each record's own ``expires_at``, not the segment's commit time: a committed
segment can be pruned wholesale only when EVERY record it contains has expired. A segment with some
expired and some live records is a *mixed-expiry* segment that must be rewritten by audited
compaction (slice 5c), never deleted here, so no unexpired record is ever lost. Record-class privacy
expiry is a hard upper bound — an expired segment is removed even if it was never delivered — so an
expired-yet-undelivered segment is flagged for a critical audit/health event before removal.

This module classifies each segment by reading its durable frames back through the trusted reader
and taking the min/max record ``expires_at``:

* ``fully_expired`` — max expiry has passed; prunable wholesale.
* ``mixed`` — some records expired, some live; a compaction candidate (5c), never pruned here.
* ``live`` — nothing expired yet.
* ``unreadable`` — the durable file could not be read as trusted state; reported, never silently
  dropped, and never treated as prunable.

:func:`retention_preview` is read-only and reports exact reclaimable counts and bytes without
mutating. The mutating :func:`retention_apply` is added in the same slice. Every failure normalizes
to a fixed ``MH_SPOOL_*`` error raised outside the handler.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from milhouse.core.clock import TimeError, format_timestamp
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.ledger import SegmentRecord, list_segment_records
from milhouse.spooling.reader import INSTALLATION_ID_PATTERN, read_trusted_segment
from milhouse.state.database import ControlDatabase

_PENDING = "pending"
_DELIVERED = "delivered"

STATUS_FULLY_EXPIRED = "fully_expired"
STATUS_MIXED = "mixed"
STATUS_LIVE = "live"
STATUS_UNREADABLE = "unreadable"


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


@dataclass(frozen=True, slots=True)
class SegmentRetention:
    """One committed segment's retention classification.

    ``byte_size``/``record_count`` come from the ledger row (what pruning would reclaim). ``code``
    is the fixed ``MH_SPOOL_*`` classification when the durable file is ``unreadable``, else
    ``None``. ``delivered`` is whether every required exporter has delivered — a ``fully_expired``
    segment that is not delivered means data reached its privacy deadline before it was exported.
    """

    batch_id: str
    status: str
    record_count: int
    byte_size: int
    delivered: bool
    code: str | None


@dataclass(frozen=True, slots=True)
class RetentionPreview:
    """A read-only view of what retention would reclaim and what needs compaction."""

    segments: tuple[SegmentRetention, ...]

    @property
    def fully_expired(self) -> tuple[SegmentRetention, ...]:
        """Segments whose every record has expired — prunable wholesale."""

        return tuple(s for s in self.segments if s.status == STATUS_FULLY_EXPIRED)

    @property
    def compaction_candidates(self) -> tuple[SegmentRetention, ...]:
        """Mixed-expiry segments that slice-5c compaction must rewrite rather than delete."""

        return tuple(s for s in self.segments if s.status == STATUS_MIXED)

    @property
    def unreadable(self) -> tuple[SegmentRetention, ...]:
        """Segments whose durable file could not be read as trusted state."""

        return tuple(s for s in self.segments if s.status == STATUS_UNREADABLE)

    @property
    def undelivered_expired(self) -> tuple[SegmentRetention, ...]:
        """Fully-expired segments that were never delivered — a critical event on removal."""

        return tuple(s for s in self.fully_expired if not s.delivered)

    @property
    def reclaimable_records(self) -> int:
        return sum(s.record_count for s in self.fully_expired)

    @property
    def reclaimable_bytes(self) -> int:
        return sum(s.byte_size for s in self.fully_expired)


def _require_now(now: datetime) -> None:
    invalid = False
    try:
        format_timestamp(now)  # rejects a naive or out-of-range instant the same way commit does
    except (OverflowError, TimeError, AttributeError, TypeError):
        invalid = True
    if invalid:
        _fail("MH_SPOOL_RETENTION", "the retention instant must be an aware in-range UTC instant")


def _classify(
    record: SegmentRecord, spool_root: Path, installation_id: str, now: datetime
) -> SegmentRetention:
    delivered = all(exporter.delivery_status == _DELIVERED for exporter in record.exporters)
    path = spool_root / _PENDING / record.day / f"{record.batch_id}.jsonl"
    status = STATUS_LIVE
    code: str | None = None
    try:
        parsed = read_trusted_segment(path, installation_id=installation_id)
    except SpoolError as error:
        return SegmentRetention(
            batch_id=record.batch_id,
            status=STATUS_UNREADABLE,
            record_count=record.record_count,
            byte_size=record.byte_size,
            delivered=delivered,
            code=error.code,
        )
    expiries = [frame.record.expires_at for frame in parsed.frames]
    if not expiries:
        # A segment with a header but no record frames carries no record-class expiry to reason
        # about; leave it live rather than ever auto-pruning an ambiguous segment.
        status = STATUS_LIVE
    elif max(expiries) <= now:
        status = STATUS_FULLY_EXPIRED
    elif min(expiries) <= now:
        status = STATUS_MIXED
    return SegmentRetention(
        batch_id=record.batch_id,
        status=status,
        record_count=record.record_count,
        byte_size=record.byte_size,
        delivered=delivered,
        code=code,
    )


def _validate_common(database: object, spool_root: object, installation_id: object) -> None:
    if type(database) is not ControlDatabase:
        _fail("MH_SPOOL_RETENTION", "a control database is required")
    if not isinstance(spool_root, (str, os.PathLike)):
        _fail("MH_SPOOL_RETENTION", "a spool root path is required")
    if (
        type(installation_id) is not str
        or INSTALLATION_ID_PATTERN.fullmatch(installation_id) is None
    ):
        _fail("MH_SPOOL_IDENTITY", "a well-formed installation id is required")


def retention_preview(
    database: ControlDatabase,
    *,
    spool_root: str | Path,
    installation_id: str,
    now: datetime,
) -> RetentionPreview:
    """Classify every committed segment by record-class expiry without mutating anything.

    Reports the fully-expired segments (with exact reclaimable counts and bytes), the mixed-expiry
    compaction candidates, and any unreadable segments, plus which fully-expired segments were never
    delivered. Holds no barrier; a file that changes mid-read is reported unreadable by the trusted
    reader rather than raising.
    """

    _validate_common(database, spool_root, installation_id)
    _require_now(now)
    root = Path(spool_root)
    records = list_segment_records(database)
    segments = tuple(_classify(record, root, installation_id, now) for record in records)
    return RetentionPreview(segments=segments)
