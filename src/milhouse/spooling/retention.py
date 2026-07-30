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
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn, cast

from milhouse.config.filesystem import (
    SecureFileError,
    SecureFileErrorKind,
    lexical_absolute_path,
    remove_regular_file_no_follow,
)
from milhouse.core.clock import TimeError, format_timestamp
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.ledger import SegmentRecord, list_segment_records
from milhouse.spooling.reader import INSTALLATION_ID_PATTERN, read_trusted_segment
from milhouse.spooling.reconcile import _agrees
from milhouse.state.audit import record_retention_prune
from milhouse.state.barrier import GlobalCommitBarrier, _is_bound_barrier
from milhouse.state.database import ControlDatabase, _validated_database_path
from milhouse.state.errors import StateError

_PENDING = "pending"
_SPOOL = "spool"
_DELIVERED = "delivered"
_BARRIER_NAME = "commit.lock"

FILE_REMOVED = "removed"
FILE_ORPHANED = "orphaned"
FILE_UNCERTAIN = "uncertain"

STATUS_FULLY_EXPIRED = "fully_expired"
STATUS_MIXED = "mixed"
STATUS_LIVE = "live"
STATUS_UNREADABLE = "unreadable"
STATUS_DISAGREEING = "disagreeing"


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
    if not _agrees(parsed, record.day, record.batch_id, record):
        # A readable file that disagrees with its ledger row is never reclaimable; report it as
        # disagreeing so the preview matches what apply would do (apply skips it) rather than
        # overstating the reclaimable estimate.
        return SegmentRetention(
            batch_id=record.batch_id,
            status=STATUS_DISAGREEING,
            record_count=record.record_count,
            byte_size=record.byte_size,
            delivered=delivered,
            code="MH_SPOOL_VERIFY",
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
    database_path = _validated_database_path(database)
    if database_path is None:
        _fail("MH_SPOOL_RETENTION", "a control database is required")
    if not isinstance(spool_root, (str, os.PathLike)):
        _fail("MH_SPOOL_RETENTION", "a spool root path is required")
    try:
        resolved_spool = lexical_absolute_path(cast("str | Path", spool_root))
    except SecureFileError:
        _fail("MH_SPOOL_RETENTION", "a spool root path is required")
    # Bind the spool root to this database's state root, exactly as commit/reconciliation do.
    # Without it a misconfigured spool_root would find every segment 'unreadable' and silently prune
    # nothing, so expired data at the real spool would never be reclaimed while the operator thinks
    # retention ran. Fail closed instead.
    if resolved_spool != database_path.parent.parent / _SPOOL:
        _fail("MH_SPOOL_RETENTION", "the spool root must be <state_root>/spool")
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


@dataclass(frozen=True, slots=True)
class PrunedSegment:
    """One committed segment removed by a retention apply pass.

    ``file_outcome`` is tri-state: ``removed`` (the file was unlinked and the removal fsynced),
    ``orphaned`` (a pre-unlink failure left the file present — because the prune is row-first,
    reconciliation adopts it and a later pass re-prunes, convergent), or ``uncertain`` (the unlink
    succeeded but its durability fsync failed, so the entry is gone but may not survive a crash; the
    operator/reconciler re-inspects rather than asserting an orphan). ``delivered`` records if the
    segment finished exporting — a pruned undelivered segment is a critical event (data reached its
    privacy deadline unexported).
    """

    batch_id: str
    record_count: int
    byte_size: int
    delivered: bool
    file_outcome: str


@dataclass(frozen=True, slots=True)
class RetentionResult:
    """The outcome of one retention apply pass."""

    pruned: tuple[PrunedSegment, ...]
    skipped: tuple[SegmentRetention, ...]

    @property
    def pruned_records(self) -> int:
        return sum(segment.record_count for segment in self.pruned)

    @property
    def pruned_bytes(self) -> int:
        return sum(segment.byte_size for segment in self.pruned)

    @property
    def undelivered_pruned(self) -> tuple[PrunedSegment, ...]:
        """Pruned segments that were never delivered — the critical-event cases."""

        return tuple(segment for segment in self.pruned if not segment.delivered)

    @property
    def orphaned_files(self) -> tuple[PrunedSegment, ...]:
        """Pruned segments whose durable file could not be unlinked (a re-registerable orphan)."""

        return tuple(segment for segment in self.pruned if segment.file_outcome == FILE_ORPHANED)

    @property
    def uncertain_files(self) -> tuple[PrunedSegment, ...]:
        """Pruned segments whose unlink succeeded but whose durability fsync did not confirm."""

        return tuple(segment for segment in self.pruned if segment.file_outcome == FILE_UNCERTAIN)


def _validate_barrier(database: ControlDatabase, barrier: object) -> None:
    if type(barrier) is not GlobalCommitBarrier:
        _fail("MH_SPOOL_RETENTION", "a commit barrier is required")
    database_path = _validated_database_path(database)
    if database_path is None or not _is_bound_barrier(
        barrier, database_path.parent / _BARRIER_NAME
    ):
        # Retention prunes under the EXCLUSIVE side; if the barrier is not the control-plane commit
        # lock, its exclusive hold would not actually exclude the writers that use the real lock, so
        # a concurrent commit could publish into a segment being pruned. Fail closed.
        _fail("MH_SPOOL_RETENTION", "the barrier must be the control-plane commit lock")


def _prune_segment(
    database: ControlDatabase,
    record: SegmentRecord,
    path: Path,
    now: datetime,
    *,
    delivered: bool,
) -> PrunedSegment | None:
    """Delete the ledger row + exporter rows + audit row in one transaction, then unlink the file.

    Row-first: the ledger deletion and its audit commit atomically, and only then is the durable
    file unlinked. A crash or unlink failure after the commit leaves an orphan file (reconciliation
    re-registers it, a later retention re-prunes it — convergent), never a row without a file.
    Returns ``None`` if the transactional deletion itself failed (the segment is left fully intact).

    Any source cursor that references this segment is DETACHED first (batch_id set to NULL) in the
    same transaction, preserving its payload-free position/revision checkpoint so an idle source's
    privacy-expired segment can be removed instead of being pinned indefinitely by the cursor
    foreign key (D05).
    """

    failed = False
    try:
        with database.transaction() as connection:
            connection.execute(
                "UPDATE _cursors SET batch_id = NULL WHERE batch_id = ?", (record.batch_id,)
            )
            connection.execute(
                "DELETE FROM _segment_exporters WHERE batch_id = ?", (record.batch_id,)
            )
            connection.execute("DELETE FROM _segments WHERE batch_id = ?", (record.batch_id,))
            record_retention_prune(
                connection,
                now=now,
                batch_id=record.batch_id,
                record_count=record.record_count,
                byte_size=record.byte_size,
                undelivered=not delivered,
            )
    except (sqlite3.Error, StateError):
        failed = True
    if failed:
        return None
    file_outcome = FILE_REMOVED
    try:
        remove_regular_file_no_follow(path)
    except SecureFileError as error:
        # The ledger row is already gone. Distinguish a pre-unlink failure (the file lingers as a
        # re-registerable orphan) from a post-unlink durability failure (the entry is gone but its
        # removal may not survive a crash — commit-uncertain, not an asserted orphan).
        file_outcome = (
            FILE_UNCERTAIN if error.kind is SecureFileErrorKind.COMMIT_UNCERTAIN else FILE_ORPHANED
        )
    return PrunedSegment(
        batch_id=record.batch_id,
        record_count=record.record_count,
        byte_size=record.byte_size,
        delivered=delivered,
        file_outcome=file_outcome,
    )


def _apply_one(
    database: ControlDatabase,
    record: SegmentRecord,
    root: Path,
    installation_id: str,
    now: datetime,
) -> tuple[PrunedSegment | None, SegmentRetention | None]:
    """Re-verify one segment under the exclusive hold and prune it iff it is fully expired.

    Returns ``(pruned, None)`` when the segment was pruned, else ``(None, skipped)`` with the
    classification explaining why it was left in place (live, mixed, unreadable, disagreeing, or a
    failed transactional prune).
    """

    delivered = all(exporter.delivery_status == _DELIVERED for exporter in record.exporters)
    path = root / _PENDING / record.day / f"{record.batch_id}.jsonl"

    def _skip(status: str, code: str | None) -> tuple[None, SegmentRetention]:
        return None, SegmentRetention(
            batch_id=record.batch_id,
            status=status,
            record_count=record.record_count,
            byte_size=record.byte_size,
            delivered=delivered,
            code=code,
        )

    try:
        parsed = read_trusted_segment(path, installation_id=installation_id)
    except SpoolError as error:
        return _skip(STATUS_UNREADABLE, error.code)
    if not _agrees(parsed, record.day, record.batch_id, record):
        # A file that disagrees with its ledger row may be tampered/corrupt; never prune it — verify
        # and reconciliation own that anomaly.
        return _skip(STATUS_DISAGREEING, "MH_SPOOL_VERIFY")
    expiries = [frame.record.expires_at for frame in parsed.frames]
    if not expiries or max(expiries) > now:
        status = STATUS_LIVE if (not expiries or min(expiries) > now) else STATUS_MIXED
        return _skip(status, None)
    pruned = _prune_segment(database, record, path, now, delivered=delivered)
    if pruned is None:
        return _skip(STATUS_FULLY_EXPIRED, "MH_SPOOL_RETENTION")
    return pruned, None


def retention_apply(
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    *,
    spool_root: str | Path,
    installation_id: str,
    now: datetime,
    confirm: bool,
) -> RetentionResult:
    """Prune every fully-expired committed segment under exclusive maintenance authority.

    ``confirm`` must be ``True`` — a preview-then-apply guard, so retention never deletes data on an
    accidental call. The whole pass runs under ``barrier.exclusive()`` so no writer can publish
    while segments are pruned. Each segment is re-read and re-verified against its ledger row under
    the lock; only a segment that agrees and is fully expired (max record ``expires_at`` past
    ``now``) is pruned, row-first, with an audit row (``pruned`` or ``pruned_undelivered`` for the
    critical case). Mixed-expiry segments are left for compaction; unreadable or disagreeing
    segments are left for verify/reconciliation. Every failure normalizes to a fixed ``MH_SPOOL_*``
    code.
    """

    _validate_common(database, spool_root, installation_id)
    _validate_barrier(database, barrier)
    _require_now(now)
    if confirm is not True:
        _fail("MH_SPOOL_RETENTION", "retention apply requires an explicit confirmation")
    root = Path(spool_root)

    pruned: list[PrunedSegment] = []
    skipped: list[SegmentRetention] = []
    with barrier.exclusive():
        for record in list_segment_records(database):
            pruned_segment, skipped_segment = _apply_one(
                database, record, root, installation_id, now
            )
            if pruned_segment is not None:
                pruned.append(pruned_segment)
            else:
                assert skipped_segment is not None
                skipped.append(skipped_segment)
    return RetentionResult(pruned=tuple(pruned), skipped=tuple(skipped))
