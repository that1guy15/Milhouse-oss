"""Audited, restartable compaction of mixed-expiry spool segments (W03 slice 5c, plan §§4.8-4.9).

A *mixed-expiry* segment holds some records whose ``expires_at`` has passed and some still live.
Retention may not prune it (that would drop unexpired records) and delivery withholds it (expired
records must not egress), so it is rewritten here: :func:`compact_apply` builds a NEW segment
containing ONLY the still-unexpired frames, records the old→new lineage in the audit trail, and
retires the old segment — removing only the expired frames while never losing a live record (ADR
0004: "compaction removes only expired frames; full mode never prunes the last recoverable unexpired
copy").

The protocol runs under one ``barrier.exclusive()`` hold (the same maintenance authority retention
takes, so no writer can publish while a segment is being rewritten). For each mixed segment it
re-reads and re-verifies the durable file against its ledger row, builds the new segment, publishes
its fsynced file, VERIFIES the new file reads back and agrees with its intended row, and only then,
in one transaction, records the new ledger row, re-points any source cursor to the new segment,
deletes the old ledger row, and writes the lineage audit — and only after that commit unlinks the
old file. The new segment's ``batch_id`` is derived deterministically from the surviving records'
identities, so an interrupted pass re-runs idempotently: a crash before the ledger swap leaves the
new file as a re-registerable orphan (reconciliation adopts it, a later pass finishes the retire),
and a crash before the old-file unlink leaves the old file as a re-registerable orphan of a segment
that is still mixed (a later pass finds the deterministic new segment already committed and just
retires the old). Delivery's hard-expiry gate withholds the still-present old mixed segment
throughout the window, so no expired frame ever egresses mid-compaction. Every failure normalizes to
a fixed ``MH_SPOOL_*`` error raised outside the handler.
"""

from __future__ import annotations

import hashlib
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
from milhouse.domain.identity import ScopeV1
from milhouse.domain.records import PrivacyClassV1
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.ledger import (
    ORIGIN_COMMITTED,
    ExporterDelivery,
    SegmentRecord,
    insert_segment_row,
    list_segment_records,
    read_segment_record,
)
from milhouse.spooling.reader import INSTALLATION_ID_PATTERN, read_trusted_segment
from milhouse.spooling.reconcile import _agrees
from milhouse.spooling.retention import FILE_ORPHANED, FILE_REMOVED, FILE_UNCERTAIN
from milhouse.spooling.segment import (
    SegmentHeaderV1,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling.writer import build_segment_bytes, publish_segment_bytes
from milhouse.state.audit import record_compaction
from milhouse.state.barrier import GlobalCommitBarrier, _is_bound_barrier
from milhouse.state.database import ControlDatabase, _validated_database_path
from milhouse.state.errors import StateError

_PENDING = "pending"
_SPOOL = "spool"
_BARRIER_NAME = "commit.lock"
_EXISTS_CODE = "MH_SPOOL_EXISTS"

# The compacted segment's batch id is this prefix plus the SHA-256 hex of the surviving records'
# ordered ids, so it is deterministic (re-runs are idempotent) and cannot collide with a batch id.
_COMPACTED_PREFIX = "c"

STATUS_LIVE = "live"
STATUS_FULLY_EXPIRED = "fully_expired"
STATUS_UNREADABLE = "unreadable"
STATUS_DISAGREEING = "disagreeing"
STATUS_VERIFY_FAILED = "verify_failed"
STATUS_PUBLISH_FAILED = "publish_failed"
STATUS_COMMIT_FAILED = "commit_failed"


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


@dataclass(frozen=True, slots=True)
class CompactedSegment:
    """One mixed-expiry segment rewritten into a new segment holding only its unexpired frames.

    ``file_outcome`` is the tri-state result of removing the OLD file (``removed``/``orphaned``/
    ``uncertain``, as in retention): ``orphaned`` means a later pass re-adopts and re-retires it,
    ``uncertain`` means the unlink succeeded but its durability fsync did not confirm.
    """

    old_batch_id: str
    new_batch_id: str
    dropped_records: int
    retained_records: int
    retained_bytes: int
    file_outcome: str


@dataclass(frozen=True, slots=True)
class SkippedSegment:
    """A segment compaction left in place, with the reason and any fixed classification code."""

    batch_id: str
    status: str
    code: str | None


@dataclass(frozen=True, slots=True)
class CompactionResult:
    """The outcome of one compaction apply pass."""

    compacted: tuple[CompactedSegment, ...]
    skipped: tuple[SkippedSegment, ...]

    @property
    def dropped_records(self) -> int:
        return sum(segment.dropped_records for segment in self.compacted)

    @property
    def retained_records(self) -> int:
        return sum(segment.retained_records for segment in self.compacted)

    @property
    def orphaned_files(self) -> tuple[CompactedSegment, ...]:
        """Compacted segments whose OLD file could not be unlinked (a re-registerable orphan)."""

        return tuple(s for s in self.compacted if s.file_outcome == FILE_ORPHANED)

    @property
    def uncertain_files(self) -> tuple[CompactedSegment, ...]:
        """Compacted segments whose OLD-file unlink succeeded but whose durability fsync did not."""

        return tuple(s for s in self.compacted if s.file_outcome == FILE_UNCERTAIN)


def _require_now(now: datetime) -> None:
    invalid = False
    try:
        format_timestamp(now)  # rejects a naive or out-of-range instant the same way commit does
    except (OverflowError, TimeError, AttributeError, TypeError):
        invalid = True
    if invalid:
        _fail("MH_SPOOL_COMPACTION", "the compaction instant must be an aware in-range UTC instant")


def _validate_common(database: object, spool_root: object, installation_id: object) -> None:
    if type(database) is not ControlDatabase:
        _fail("MH_SPOOL_COMPACTION", "a control database is required")
    database_path = _validated_database_path(database)
    if database_path is None:
        _fail("MH_SPOOL_COMPACTION", "a control database is required")
    if not isinstance(spool_root, (str, os.PathLike)):
        _fail("MH_SPOOL_COMPACTION", "a spool root path is required")
    try:
        resolved_spool = lexical_absolute_path(cast("str | Path", spool_root))
    except SecureFileError:
        _fail("MH_SPOOL_COMPACTION", "a spool root path is required")
    # Bind the spool root to this database's state root, exactly as commit/retention do, so a
    # misconfigured root cannot silently rewrite nothing (fail closed with privacy weight).
    if resolved_spool != database_path.parent.parent / _SPOOL:
        _fail("MH_SPOOL_COMPACTION", "the spool root must be <state_root>/spool")
    if (
        type(installation_id) is not str
        or INSTALLATION_ID_PATTERN.fullmatch(installation_id) is None
    ):
        _fail("MH_SPOOL_IDENTITY", "a well-formed installation id is required")


def _validate_barrier(database: ControlDatabase, barrier: object) -> None:
    if type(barrier) is not GlobalCommitBarrier:
        _fail("MH_SPOOL_COMPACTION", "a commit barrier is required")
    database_path = _validated_database_path(database)
    if database_path is None or not _is_bound_barrier(
        barrier, database_path.parent / _BARRIER_NAME
    ):
        # Compaction rewrites under the EXCLUSIVE side; a barrier that is not the control-plane
        # commit lock would not exclude the writers using the real lock. Fail closed.
        _fail("MH_SPOOL_COMPACTION", "the barrier must be the control-plane commit lock")


def _derive_batch_id(live_frames: list[SpoolFrameV1]) -> str:
    # Deterministic in the surviving records' ids (independent of the old batch id and of which
    # frames expired), so re-compacting the same survivors yields the same new segment identity —
    # the property that makes an interrupted pass converge idempotently.
    material = "\n".join(str(frame.record.record_id) for frame in live_frames)
    return _COMPACTED_PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _build_new_segment(
    record: SegmentRecord, live_frames: list[SpoolFrameV1], new_batch_id: str
) -> tuple[SegmentRecord, bytes]:
    """Build the compacted segment's record and durable bytes from the surviving frames.

    The new segment inherits every immutable policy field and the per-exporter delivery status of
    the old segment (its live records already had that state), and re-stamps the frames with the
    new batch id and contiguous sequences. ``committed_at`` is the day-start stamp reconciliation
    would assign a re-registered orphan, so a crash-re-registered new row is byte-identical here.
    """

    new_frames = [
        SpoolFrameV1(batch_id=new_batch_id, sequence=index, record=frame.record)
        for index, frame in enumerate(live_frames, start=1)
    ]
    exporter_ids = tuple(sorted({exporter.exporter_id for exporter in record.exporters}))
    status_by_id = {exporter.exporter_id: exporter.delivery_status for exporter in record.exporters}
    content_sha256 = spool_content_sha256([spool_frame_line(frame) for frame in new_frames])
    # The record came from a committed segment, so its scope/privacy_class are already valid
    # literals; SegmentHeaderV1.__post_init__ re-validates them, so the casts are safe.
    header = SegmentHeaderV1(
        batch_id=new_batch_id,
        config_generation=record.config_generation,
        scope=cast(ScopeV1, record.scope),
        target_id=record.target_id,
        privacy_class=cast(PrivacyClassV1, record.privacy_class),
        retention_days=record.retention_days,
        required_exporters=exporter_ids,
        record_count=len(new_frames),
        content_sha256=content_sha256,
    )
    content = build_segment_bytes(header, new_frames)
    new_record = SegmentRecord(
        batch_id=new_batch_id,
        day=record.day,
        schema_version=record.schema_version,
        frame_version=record.frame_version,
        config_generation=record.config_generation,
        scope=record.scope,
        target_id=record.target_id,
        privacy_class=record.privacy_class,
        retention_days=record.retention_days,
        record_count=len(new_frames),
        content_sha256=content_sha256,
        byte_size=len(content),
        file_sha256=hashlib.sha256(content).hexdigest(),
        committed_at=f"{record.day}T00:00:00.000Z",
        origin=ORIGIN_COMMITTED,
        exporters=tuple(ExporterDelivery(eid, status_by_id[eid]) for eid in exporter_ids),
    )
    return new_record, content


def _remove_old_file(path: Path) -> str:
    try:
        remove_regular_file_no_follow(path)
    except SecureFileError as error:
        # Distinguish a post-unlink durability failure (entry gone, may not survive a crash) from a
        # pre-unlink failure (the file lingers as a re-registerable orphan), as retention does.
        if error.kind is SecureFileErrorKind.COMMIT_UNCERTAIN:
            return FILE_UNCERTAIN
        return FILE_ORPHANED
    return FILE_REMOVED


def _swap_ledger(
    database: ControlDatabase,
    old_record: SegmentRecord,
    new_record: SegmentRecord,
    *,
    now: datetime,
    insert_new: bool,
) -> bool:
    """Atomically publish the new row (if needed), re-point cursors, delete the old row, and audit.

    Returns whether the transaction committed. Cursors are RE-POINTED to the new segment (not
    detached), since the live records they checkpoint survive in it; the new row is inserted before
    the re-point so the ``_cursors`` foreign key is satisfied, and the old row is deleted only after
    no cursor references it.
    """

    failed = False
    try:
        with database.transaction() as connection:
            if insert_new:
                insert_segment_row(connection, new_record)
            connection.execute(
                "UPDATE _cursors SET batch_id = ? WHERE batch_id = ?",
                (new_record.batch_id, old_record.batch_id),
            )
            connection.execute(
                "DELETE FROM _segment_exporters WHERE batch_id = ?", (old_record.batch_id,)
            )
            connection.execute("DELETE FROM _segments WHERE batch_id = ?", (old_record.batch_id,))
            record_compaction(
                connection,
                now=now,
                old_batch_id=old_record.batch_id,
                new_batch_id=new_record.batch_id,
                old_record_count=old_record.record_count,
                old_byte_size=old_record.byte_size,
                new_record_count=new_record.record_count,
                new_byte_size=new_record.byte_size,
            )
    except (sqlite3.Error, StateError):
        failed = True
    return not failed


def _compact_one(
    database: ControlDatabase,
    root: Path,
    installation_id: str,
    now: datetime,
    record: SegmentRecord,
) -> tuple[CompactedSegment | None, SkippedSegment | None]:
    """Compact one segment iff it is mixed-expiry; else return why it was skipped."""

    old_path = root / _PENDING / record.day / f"{record.batch_id}.jsonl"

    def _skip(status: str, code: str | None) -> tuple[None, SkippedSegment]:
        return None, SkippedSegment(record.batch_id, status, code)

    try:
        parsed = read_trusted_segment(old_path, installation_id=installation_id)
    except SpoolError as error:
        return _skip(STATUS_UNREADABLE, error.code)
    if not _agrees(parsed, record.day, record.batch_id, record):
        return _skip(STATUS_DISAGREEING, "MH_SPOOL_VERIFY")

    live_frames = [frame for frame in parsed.frames if frame.record.expires_at > now]
    dropped = len(parsed.frames) - len(live_frames)
    if dropped == 0:
        return _skip(STATUS_LIVE, None)  # nothing expired — not a compaction candidate
    if not live_frames:
        return _skip(
            STATUS_FULLY_EXPIRED, None
        )  # all expired — retention prunes it, not compaction

    new_batch_id = _derive_batch_id(live_frames)
    try:
        new_record, content = _build_new_segment(record, live_frames, new_batch_id)
    except SpoolError as error:
        return _skip(
            STATUS_VERIFY_FAILED, error.code
        )  # could not build the new segment; old intact
    new_path = root / _PENDING / record.day / f"{new_batch_id}.jsonl"

    existing = read_segment_record(database, new_batch_id)
    if existing is None:
        try:
            publish_segment_bytes(new_path, content)
        except SpoolError as error:
            # A leftover orphan file from a prior interrupted pass is adopted (verified below); any
            # other publish failure leaves the old segment fully intact.
            if error.code != _EXISTS_CODE:
                return _skip(STATUS_PUBLISH_FAILED, error.code)
        reference = new_record
        insert_new = True
    else:
        reference = existing
        insert_new = False

    # Verify the on-disk new segment reads back and agrees with its authoritative row BEFORE the old
    # segment is retired, so a corrupt or foreign file at the new name can never lose the live data.
    try:
        parsed_new = read_trusted_segment(new_path, installation_id=installation_id)
    except SpoolError as error:
        return _skip(STATUS_VERIFY_FAILED, error.code)
    if not _agrees(parsed_new, reference.day, new_batch_id, reference):
        return _skip(STATUS_VERIFY_FAILED, "MH_SPOOL_VERIFY")

    if not _swap_ledger(database, record, new_record, now=now, insert_new=insert_new):
        return _skip(STATUS_COMMIT_FAILED, "MH_SPOOL_COMPACTION")

    file_outcome = _remove_old_file(old_path)
    return (
        CompactedSegment(
            old_batch_id=record.batch_id,
            new_batch_id=new_batch_id,
            dropped_records=dropped,
            retained_records=len(live_frames),
            retained_bytes=new_record.byte_size,
            file_outcome=file_outcome,
        ),
        None,
    )


def compact_apply(
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    *,
    spool_root: str | Path,
    installation_id: str,
    now: datetime,
    confirm: bool,
) -> CompactionResult:
    """Rewrite every mixed-expiry committed segment into a new unexpired-only segment, audited.

    ``confirm`` must be ``True`` — a preview-then-apply guard so compaction never mutates on an
    accidental call. The whole pass runs under ``barrier.exclusive()``. Each segment is re-read and
    re-verified against its ledger row under the lock; a mixed-expiry segment (some records expired,
    some live) is rewritten, a segment with nothing expired or with everything expired is left alone
    (retention prunes the fully-expired ones), and an unreadable or disagreeing segment is left for
    verify/reconciliation. Every failure normalizes to a fixed ``MH_SPOOL_*`` code.
    """

    _validate_common(database, spool_root, installation_id)
    _validate_barrier(database, barrier)
    _require_now(now)
    if confirm is not True:
        _fail("MH_SPOOL_COMPACTION", "compaction apply requires an explicit confirmation")
    root = Path(spool_root)

    compacted: list[CompactedSegment] = []
    skipped: list[SkippedSegment] = []
    with barrier.exclusive():
        for record in list_segment_records(database):
            done, skip = _compact_one(database, root, installation_id, now, record)
            if done is not None:
                compacted.append(done)
            else:
                assert skip is not None
                skipped.append(skip)
    return CompactionResult(compacted=tuple(compacted), skipped=tuple(skipped))
