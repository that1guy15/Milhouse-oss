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
from typing import TYPE_CHECKING, NoReturn, cast

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
    ORIGIN_RECONCILED,
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
    is_reserved_compaction_batch_id,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling.writer import build_segment_bytes, publish_segment_bytes
from milhouse.state.audit import record_compaction
from milhouse.state.barrier import GlobalCommitBarrier, _is_bound_barrier
from milhouse.state.database import ControlDatabase, _validated_database_path
from milhouse.state.errors import StateError

if TYPE_CHECKING:
    from milhouse.privacy.pseudonym import Pseudonymizer

_PENDING = "pending"
_SPOOL = "spool"
_BARRIER_NAME = "commit.lock"
_DELIVERED = "delivered"

# The compacted segment's batch id is this prefix plus the SHA-256 hex of the surviving records'
# ordered ids, so it is deterministic (re-runs are idempotent) and lies in the reserved compaction
# successor namespace. Producers may never commit into that namespace (rejected at the commit
# ingress), so the derived id is UNFORGEABLE: no caller-chosen segment can occupy it. It is thus
# always either free, or already holds THIS compaction's intended successor (crash recovery). Only a
# SHA-256 collision — which no finite or predictable input can produce — could place a non-successor
# there, and that fails closed loudly rather than ever stranding expired frames (G03 review finding
# #1: a bounded probe over predictable ids could still be exhausted and strand; the reservation
# removes the reachable stranding entirely, so no probe is needed).
_COMPACTED_PREFIX = "c"

STATUS_LIVE = "live"
STATUS_FULLY_EXPIRED = "fully_expired"
STATUS_UNREADABLE = "unreadable"
STATUS_DISAGREEING = "disagreeing"
STATUS_VERIFY_FAILED = "verify_failed"
STATUS_PUBLISH_FAILED = "publish_failed"
STATUS_COMMIT_FAILED = "commit_failed"
# A non-successor row/file at the reserved derived id: reachable only under a SHA-256 collision, so
# this is a fail-closed integrity outcome, never a routine bounded-probe exhaustion. The old segment
# is left fully intact (a live record is never lost); the skip is reported, never silent.
STATUS_RESERVED_CONFLICT = "reserved_conflict"


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
    # the property that makes an interrupted pass converge idempotently. The id lands in the
    # ``c`` + 64-hex namespace that producers may never commit into, so it is unforgeable.
    material = "\n".join(str(frame.record.record_id) for frame in live_frames)
    batch_id = _COMPACTED_PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()
    # Defensive: the derived id must be exactly the reserved successor shape the commit ingress
    # protects; if this invariant ever broke (e.g. the prefix changed), a producer could forge the
    # id, so fail closed. A ``c`` + 64-hex digest always matches, so this never fires in practice.
    if not is_reserved_compaction_batch_id(batch_id):  # pragma: no cover - defensive invariant
        _fail("MH_SPOOL_COMPACTION", "the derived successor id is not in the reserved namespace")
    return batch_id


def _build_new_segment(
    record: SegmentRecord, live_frames: list[SpoolFrameV1], new_batch_id: str
) -> tuple[SegmentRecord, bytes]:
    """Build the compacted segment's record and durable bytes from the surviving frames.

    The new segment inherits every immutable policy field and the per-exporter delivery status of
    the old segment (its live records already had that state), and re-stamps the frames with the
    new batch id and contiguous sequences. The exact commit instant of the compacted subset is not
    the old segment's, and it must stay within the records' own ``day`` (a later compaction day
    cannot be the ``committed_at`` prefix), so ``committed_at`` is the reconstructed day-start stamp
    and ``origin`` is ``reconciled`` — the ledger's truthful marker for a reconstructed instant, and
    the value reconciliation assigns a re-registered orphan, so a crash-re-registered new row is
    byte-identical here.
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
        origin=ORIGIN_RECONCILED,
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


def _is_intended_successor(existing: SegmentRecord, intended: SegmentRecord) -> bool:
    """Whether an existing row at the derived id is EXACTLY the successor this compaction intends.

    A committed segment's ``batch_id`` is caller-chosen, so the deterministic derived id could be
    occupied by an unrelated segment (no cryptographic collision needed). Reusing such a row would
    retire the mixed segment against foreign data and lose the live records, so an existing row is
    reusable only if every file-attestable identity field — including both digests — and the
    exporter id set equal the intended successor's. ``origin`` (a crash-re-registered orphan is
    ``reconciled``) and the per-exporter delivery statuses are deliberately excluded: the former is
    not identity, and the latter are restored to the intended states during the swap.
    """

    return (
        existing.batch_id == intended.batch_id
        and existing.day == intended.day
        and existing.schema_version == intended.schema_version
        and existing.frame_version == intended.frame_version
        and existing.config_generation == intended.config_generation
        and existing.scope == intended.scope
        and existing.target_id == intended.target_id
        and existing.privacy_class == intended.privacy_class
        and existing.retention_days == intended.retention_days
        and existing.record_count == intended.record_count
        and existing.content_sha256 == intended.content_sha256
        and existing.byte_size == intended.byte_size
        and existing.file_sha256 == intended.file_sha256
        and {e.exporter_id for e in existing.exporters}
        == {e.exporter_id for e in intended.exporters}
    )


def _swap_ledger(
    database: ControlDatabase,
    old_record: SegmentRecord,
    new_record: SegmentRecord,
    *,
    now: datetime,
    insert_new: bool,
    pseudonymizer: Pseudonymizer | None,
) -> bool:
    """Atomically publish/restore the successor, re-point cursors, delete the old row, and audit.

    Returns whether the transaction committed. Cursors are RE-POINTED to the new segment (not
    detached), since the live records they checkpoint survive in it; the new row is inserted before
    the re-point so the ``_cursors`` foreign key is satisfied, and the old row is deleted only after
    no cursor references it.

    When the successor row already exists (a crash-re-registered orphan is registered with every
    exporter ``pending``), its per-exporter delivery states are restored to the intended states
    inherited from the old segment — but only for rows not already ``delivered``, so a successor
    a prior pass already confirmed delivered is never regressed to pending (which would re-expose an
    acknowledged record to duplicate external delivery).

    ``pseudonymizer`` (when supplied) keys the old→new lineage identifiers recorded in ``_audit``;
    when it is ``None`` (no installation key wired) the lineage resources are OMITTED as ``NULL``,
    never stored as a reversible hash (plan §4.7).
    """

    failed = False
    try:
        with database.transaction() as connection:
            if insert_new:
                insert_segment_row(connection, new_record)
            else:
                for exporter in new_record.exporters:
                    connection.execute(
                        "UPDATE _segment_exporters SET delivery_status = ? "
                        "WHERE batch_id = ? AND exporter_id = ? AND delivery_status != ?",
                        (
                            exporter.delivery_status,
                            new_record.batch_id,
                            exporter.exporter_id,
                            _DELIVERED,
                        ),
                    )
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
                pseudonymizer=pseudonymizer,
            )
    except (sqlite3.Error, StateError):
        failed = True
    return not failed


def _resolve_successor(
    database: ControlDatabase,
    root: Path,
    installation_id: str,
    record: SegmentRecord,
    live_frames: list[SpoolFrameV1],
) -> tuple[str, SegmentRecord, bytes, bool, bool] | None:
    """Resolve the single deterministic successor slot for this compaction.

    The successor id is derived from the surviving record ids and lands in the reserved ``c`` +
    64-hex namespace that producers may never commit into, so it is unforgeable: it is free (publish
    a new file and insert a row), already holds THIS compaction's intended successor as a committed
    row (reuse it — crash recovery), or holds it as an unrecorded orphan file (adopt it — insert the
    row). Because the namespace is reserved, the only way a NON-successor could occupy the id is a
    SHA-256 collision, which no finite or predictable input can produce; that fails closed (returns
    ``None``, the caller reports it) rather than ever retiring the old segment against foreign data.
    There is no bounded probe: a single derived id can no longer be stranded past its privacy
    deadline by occupying predictable alternatives (G03 review finding #1).
    Returns ``(batch_id, new_record, content, needs_publish, insert_new)`` or ``None``.
    """

    candidate = _derive_batch_id(live_frames)
    new_record, content = _build_new_segment(record, live_frames, candidate)
    existing = read_segment_record(database, candidate)
    if existing is not None:
        if _is_intended_successor(existing, new_record):
            return candidate, new_record, content, False, False  # reuse committed successor
        return None  # reserved id holds a non-successor committed row (SHA-256 collision only)
    candidate_path = root / _PENDING / record.day / f"{candidate}.jsonl"
    if not os.path.lexists(candidate_path):
        return candidate, new_record, content, True, True  # free slot — publish and insert
    # A name exists with no ledger row (this compaction's crash orphan under the reserved id). Adopt
    # it only if it is exactly this compaction's intended successor; otherwise fail closed.
    try:
        parsed = read_trusted_segment(candidate_path, installation_id=installation_id)
    except SpoolError:
        return None  # reserved id holds an unreadable file (SHA-256 collision only)
    if _agrees(parsed, new_record.day, candidate, new_record):
        return candidate, new_record, content, False, True  # our orphan — adopt (insert row)
    return None  # reserved id holds a non-successor file (SHA-256 collision only)


def _compact_one(
    database: ControlDatabase,
    root: Path,
    installation_id: str,
    now: datetime,
    record: SegmentRecord,
    pseudonymizer: Pseudonymizer | None,
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

    # Resolve the single reserved-namespace successor id. It is free or already this compaction's
    # successor; only a SHA-256 collision could place a non-successor there, so ``None`` is a
    # fail-closed integrity outcome, never a routine occupancy. A failure leaves the old segment
    # fully intact — a live record is never lost.
    try:
        resolved = _resolve_successor(database, root, installation_id, record, live_frames)
    except SpoolError as error:
        return _skip(STATUS_VERIFY_FAILED, error.code)
    if resolved is None:
        return _skip(STATUS_RESERVED_CONFLICT, "MH_SPOOL_COMPACTION")
    new_batch_id, new_record, content, needs_publish, insert_new = resolved
    new_path = root / _PENDING / record.day / f"{new_batch_id}.jsonl"

    if needs_publish:
        # The resolver only returns needs_publish for a slot with no name present, so publication
        # onto that free slot under the exclusive hold cannot collide; any failure (including a
        # surprise existing name) leaves the old segment fully intact.
        try:
            publish_segment_bytes(new_path, content)
        except SpoolError as error:
            return _skip(STATUS_PUBLISH_FAILED, error.code)

    # Verify the on-disk file agrees with the INTENDED successor (``new_record``) — never with a
    # pre-existing row — BEFORE the old segment is retired, so a foreign or corrupt file at the
    # chosen name can never cause the live data to be lost.
    try:
        parsed_new = read_trusted_segment(new_path, installation_id=installation_id)
    except SpoolError as error:
        return _skip(STATUS_VERIFY_FAILED, error.code)
    if not _agrees(parsed_new, new_record.day, new_batch_id, new_record):
        return _skip(STATUS_VERIFY_FAILED, "MH_SPOOL_VERIFY")

    if not _swap_ledger(
        database, record, new_record, now=now, insert_new=insert_new, pseudonymizer=pseudonymizer
    ):
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
    pseudonymizer: Pseudonymizer | None = None,
) -> CompactionResult:
    """Rewrite every mixed-expiry committed segment into a new unexpired-only segment, audited.

    ``confirm`` must be ``True`` — a preview-then-apply guard so compaction never mutates on an
    accidental call. The whole pass runs under ``barrier.exclusive()``. Each segment is re-read and
    re-verified against its ledger row under the lock; a mixed-expiry segment (some records expired,
    some live) is rewritten, a segment with nothing expired or with everything expired is left alone
    (retention prunes the fully-expired ones), and an unreadable or disagreeing segment is left for
    verify/reconciliation. Every failure normalizes to a fixed ``MH_SPOOL_*`` code.

    ``pseudonymizer`` keys the old→new lineage recorded in ``_audit`` per plan §4.7. A maintenance
    caller loads the installation key with
    :func:`milhouse.privacy.keys.load_pseudonym_key` and passes the resulting
    :class:`~milhouse.privacy.pseudonym.Pseudonymizer`; when it is absent (no key provisioned yet)
    the lineage resources are recorded as ``NULL`` rather than as a reversible hash. The
    derivation runs inside the audit boundary, which requires the exact trusted ``Pseudonymizer``
    type, so an untrusted look-alike can never persist a caller-shaped value.
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
            done, skip = _compact_one(database, root, installation_id, now, record, pseudonymizer)
            if done is not None:
                compacted.append(done)
            else:
                assert skip is not None
                skipped.append(skip)
    return CompactionResult(compacted=tuple(compacted), skipped=tuple(skipped))
