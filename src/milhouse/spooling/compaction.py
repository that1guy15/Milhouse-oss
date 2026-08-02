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
from collections.abc import Callable
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
from milhouse.privacy.keys import load_pseudonym_key
from milhouse.privacy.pseudonym import PrivacyError, Pseudonymizer
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.intents import (
    REHOME_SEQUENCE,
    clear_intents_for_segment,
    is_recorded_successor,
    read_rehome_target,
    read_sequence,
    record_rehome_intent,
    record_successor_intent,
    set_sequence,
)
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
from milhouse.spooling.writer import (
    _publish_reserved_successor,
    build_segment_bytes,
    publish_segment_bytes,
)
from milhouse.state.audit import record_compaction
from milhouse.state.barrier import GlobalCommitBarrier, _is_bound_barrier
from milhouse.state.database import ControlDatabase, _validated_database_path
from milhouse.state.errors import StateError
from milhouse.state.installation import read_installation_key

if TYPE_CHECKING:
    from milhouse.config._models import MilhouseConfig
    from milhouse.config.paths import RuntimePaths

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
# A07 rehome target prefix: a legacy reserved-namespace occupant is rewritten to an ``r`` +
# 64-hex namespace — a producer batch-id shape NEVER in the reserved ``c[0-9a-f]{64}`` namespace, so
# the rehomed segment is an ordinary committed segment. The suffix is a MONOTONIC control-plane
# counter (not a content-derived predictable id), so a producer cannot pre-occupy the target (G03
# review #79-P1-1); on the rare conflict the counter increments — unbounded, so it always converges.
_REHOME_PREFIX = "r"
# An infinite-loop guard on the monotonic allocation. Only finitely many ids can be occupied and the
# counter is unbounded, so a free target is always found long before this bound; it never fires.
_MAX_REHOME_PROBE = 1 << 20

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
    """The outcome of one compaction apply pass.

    ``rehomed`` holds legacy reserved-namespace committed occupants that this pass auto-converged to
    a fresh non-reserved id before compacting (A07); each is a zero-dropped old→new rewrite.
    """

    compacted: tuple[CompactedSegment, ...]
    skipped: tuple[SkippedSegment, ...]
    rehomed: tuple[CompactedSegment, ...] = ()

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
    except SecureFileError:  # pragma: no cover - defensive: a str/PathLike rarely fails lexically
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


def _derive_batch_id(record: SegmentRecord, live_frames: list[SpoolFrameV1]) -> str:
    # The successor id must be deterministic in the FULL intended identity — everything
    # ``_is_intended_successor`` compares — plus a source-specific discriminator (the old batch id),
    # NOT just the surviving record ids. Two mixed segments that share a surviving record id but
    # differ in exporters, policy, or source would otherwise derive the same id, so the first
    # compacts and the second sees a NON-successor at the id and strands its expired frame (G03
    # review: same-survivor collision). Including the old batch id also keeps each source segment's
    # successor distinct (compaction removes only expired frames; it never merges two segments), and
    # keeps a re-run of the SAME source idempotent. The fields below are all independent of the new
    # batch id (unlike the content/file digests, which are computed over frames that embed it). The
    # id lands in the reserved ``c`` + 64-hex namespace that producers may never publish into.
    exporter_ids = sorted({exporter.exporter_id for exporter in record.exporters})
    material = "\n".join(
        [
            "milhouse-compaction-successor-v2",
            record.batch_id,
            record.config_generation,
            record.scope,
            record.target_id or "",
            record.privacy_class,
            str(record.retention_days),
            str(len(exporter_ids)),
            *exporter_ids,
            str(len(live_frames)),
            *[str(frame.record.record_id) for frame in live_frames],
        ]
    )
    batch_id = _COMPACTED_PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()
    # Defensive: the derived id must be exactly the reserved successor shape the publish ingress
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


def _clear_retirement(database: ControlDatabase, batch_id: str) -> None:
    """Clear the old segment's retirement tombstone once its file is durably gone. Best-effort: on
    any failure the tombstone is left for mandatory reconciliation to finish, so the intent is never
    lost (mirrors retention)."""

    try:
        with database.transaction() as connection:
            connection.execute("DELETE FROM _retirements WHERE batch_id = ?", (batch_id,))
    except (sqlite3.Error, StateError):  # pragma: no cover - best-effort; reconciliation finishes
        pass


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
    pseudonymizer: Pseudonymizer,
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

    ``pseudonymizer`` keys the old→new lineage identifiers recorded in ``_audit`` and is bound to
    the installation's control-plane key identity (A07); a caller-supplied key never reaches here.

    A durable RETIREMENT TOMBSTONE for the OLD segment (``_retirements``, scoped to the old
    ``file_sha256``) is written in this SAME transaction as the swap, so a crash between the commit
    and the old-file unlink cannot resurrect the retired mixed segment: mandatory reconciliation
    finds the tombstone and finishes the deletion (or fences it) instead of re-registering the old
    file as a live committed segment with its expired frame present (G03 review: commit-uncertain
    re-adoption). It is cleared by the caller only after a durable ``removed`` outcome; on any
    non-removed outcome it stays for reconciliation.
    """

    invalid_time = False
    retired_at = ""
    try:
        retired_at = format_timestamp(now)
    except (OverflowError, TimeError):  # pragma: no cover - now is validated before the barrier
        invalid_time = True
    if invalid_time:  # pragma: no cover - now is validated by _require_now before the barrier
        return False  # a bad instant cannot produce a valid tombstone; leave the segment intact

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
            # The old segment is retired: drop any intents naming it, so the intents
            # table stays ~one row per live reserved segment / pending rehome. If the old was a
            # genuine successor its successor-intent goes; a rehome source its rehome-intent
            # goes (its target is the segment that survives). The NEW successor's own intent
            # was recorded before publication and is untouched.
            clear_intents_for_segment(connection, old_record.batch_id)
            # Durable retirement intent for the old file, in the swap transaction (see docstring).
            # OR REPLACE keeps a re-run idempotent if a prior uncleared tombstone lingers.
            connection.execute(
                "INSERT OR REPLACE INTO _retirements (batch_id, day, file_sha256, retired_at) "
                "VALUES (?, ?, ?, ?)",
                (old_record.batch_id, old_record.day, old_record.file_sha256, retired_at),
            )
            record_compaction(
                connection,
                now=now,
                old_batch_id=old_record.batch_id,
                new_batch_id=new_record.batch_id,
                old_record_count=old_record.record_count,
                old_byte_size=old_record.byte_size,
                new_record_count=new_record.record_count,
                new_byte_size=new_record.byte_size,
                # Immutable evidence of the exact retired/replacement bytes (plan §§4.8-4.9): old
                # digests were verified against the file by ``_agrees`` at the start of this
                # compaction; the new digests were verified by reading the published successor back.
                old_content_sha256=old_record.content_sha256,
                old_file_sha256=old_record.file_sha256,
                new_content_sha256=new_record.content_sha256,
                new_file_sha256=new_record.file_sha256,
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

    The successor id is derived from the FULL intended identity (every field
    ``_is_intended_successor`` compares) plus the old batch id, and lands in the reserved ``c`` +
    64-hex namespace that no producer publish path may write into, so it is unforgeable AND unique
    to this exact successor: it is free (publish a new file and insert a row), already holds THIS
    compaction's intended successor as a committed row (reuse it — crash recovery), or holds it as
    an unrecorded orphan file (adopt it — insert the row). Because the id is a function of the whole
    successor identity, any occupant is either exactly this successor or a SHA-256 collision (no
    finite or predictable input produces one); a non-successor fails closed (returns ``None``, the
    caller reports it) rather than ever retiring the old segment against foreign data. There is no
    bounded probe and no same-survivor/different-policy strand (G03 review findings #1/#2).
    Returns ``(batch_id, new_record, content, needs_publish, insert_new)`` or ``None``.
    """

    return _resolve_target(
        database, root, installation_id, record, live_frames, _derive_batch_id(record, live_frames)
    )


def _resolve_target(
    database: ControlDatabase,
    root: Path,
    installation_id: str,
    record: SegmentRecord,
    frames: list[SpoolFrameV1],
    candidate: str,
) -> tuple[str, SegmentRecord, bytes, bool, bool] | None:
    """Resolve the single deterministic ``candidate`` target slot for an old→new segment rewrite.

    Shared by audited compaction (reserved-namespace successor) and the A07 reserved-occupant rehome
    (non-reserved successor). The ``candidate`` id is a function of the source's complete intended
    identity, so any occupant is either exactly this rewrite's intended target (crash recovery) or a
    SHA-256 collision (no finite/predictable input produces one); a non-target fails closed
    (``None``). Returns ``(batch_id, new_record, content, needs_publish, insert_new)`` or ``None``.
    """

    new_record, content = _build_new_segment(record, frames, candidate)
    existing = read_segment_record(database, candidate)
    if existing is not None:
        if _is_intended_successor(existing, new_record):
            return candidate, new_record, content, False, False  # reuse committed target
        return None  # id holds a non-target committed row (SHA-256 collision only)
    candidate_path = root / _PENDING / record.day / f"{candidate}.jsonl"
    if not os.path.lexists(candidate_path):
        return candidate, new_record, content, True, True  # free slot — publish and insert
    # A name exists with no ledger row (this rewrite's crash orphan under the target id). Adopt it
    # only if it is exactly this rewrite's intended target; otherwise fail closed.
    try:
        parsed = read_trusted_segment(candidate_path, installation_id=installation_id)
    except SpoolError:
        return None  # id holds an unreadable file (SHA-256 collision only)
    if _agrees(parsed, new_record.day, candidate, new_record):
        return candidate, new_record, content, False, True  # our orphan — adopt (insert row)
    return None  # id holds a non-target file (SHA-256 collision only)


def _skipped(record: SegmentRecord, status: str, code: str | None) -> tuple[None, SkippedSegment]:
    return None, SkippedSegment(record.batch_id, status, code)


def _record_successor_intent(
    database: ControlDatabase, *, target: str, source: str, now: datetime
) -> bool:
    """Durably record (own transaction) that ``target`` is compaction's intended successor of
    ``source``. Returns whether it committed; idempotent across re-runs."""

    committed = True
    try:
        with database.transaction() as connection:
            record_successor_intent(
                connection, target_batch_id=target, source_batch_id=source, now=now
            )
    except (sqlite3.Error, StateError, SpoolError):
        committed = False
    return committed


def _allocate_rehome_target(
    database: ControlDatabase, root: Path, record: SegmentRecord, now: datetime
) -> str:
    """Return the non-reserved target this rehome will publish ``record`` into.

    A durable ``rehome`` intent binds the source to its target, so a re-run REUSES the same target
    (idempotent, restartable). A first allocation takes the next value of the monotonic
    ``rehome_target`` counter, skipping any occupied id and advancing the counter past the one used.
    Because the counter is unbounded and only finitely many ids can be occupied, a free target
    always exists — the upgrade converges. Recorded in its own committed transaction BEFORE the
    file is published.
    """

    day_dir = root / _PENDING / record.day
    with database.transaction() as connection:
        existing = read_rehome_target(connection, record.batch_id)
        if existing is not None:
            return existing
        counter = read_sequence(connection, REHOME_SEQUENCE)
        target = ""
        for _probe in range(_MAX_REHOME_PROBE):
            target = _REHOME_PREFIX + format(counter, "064x")
            counter += 1
            occupied = connection.execute(
                "SELECT 1 FROM _segments WHERE batch_id = ?", (target,)
            ).fetchone() is not None or os.path.lexists(day_dir / f"{target}.jsonl")
            if not occupied:
                break
        else:  # pragma: no cover - unreachable: finitely many ids, unbounded counter
            _fail("MH_SPOOL_COMPACTION", "no free rehome target could be allocated")
        set_sequence(connection, REHOME_SEQUENCE, counter)
        record_rehome_intent(
            connection, target_batch_id=target, source_batch_id=record.batch_id, now=now
        )
    return target


def _finish_rewrite(
    database: ControlDatabase,
    root: Path,
    installation_id: str,
    now: datetime,
    record: SegmentRecord,
    resolved: tuple[str, SegmentRecord, bytes, bool, bool] | None,
    *,
    pseudonymizer: Pseudonymizer,
    publish: Callable[[Path, bytes], None],
    dropped: int,
    retained: int,
    record_successor: bool,
) -> tuple[CompactedSegment | None, SkippedSegment | None]:
    """Publish (if needed), verify, swap, and retire — the shared crash-safe tail of a rewrite.

    Used by audited compaction (reserved-namespace successor, ``publish`` = the reserved authority)
    and the A07 reserved-occupant rehome (non-reserved successor, ``publish`` = the ordinary
    path). ``resolved`` is the target slot from :func:`_resolve_target` (``None`` → a non-target
    occupant, fail closed); ``dropped``/``retained`` label the reported result. Every failure
    normalizes to a skip that leaves the OLD segment fully intact — a live record is never lost, and
    the new file is verified against the INTENDED target (never a pre-existing row) before the
    retired.

    When ``record_successor`` is set (compaction), a successor INTENT is committed before the
    reserved successor file is published, so the reserved id is provably a genuine compaction
    successor — a crash-published successor is adoptable, never mistaken for a legacy occupant and
    rehomed (which would duplicate its records). The rehome records its own intent during target
    allocation, so it passes ``record_successor=False``.
    """

    if resolved is None:
        return _skipped(record, STATUS_RESERVED_CONFLICT, "MH_SPOOL_COMPACTION")
    new_batch_id, new_record, content, needs_publish, insert_new = resolved
    new_path = root / _PENDING / record.day / f"{new_batch_id}.jsonl"

    if needs_publish:
        # Record the successor provenance intent BEFORE publishing (its own committed transaction),
        # so a crash between the intent and the ledger swap still proves the reserved id genuine.
        if record_successor and not _record_successor_intent(
            database, target=new_batch_id, source=record.batch_id, now=now
        ):
            return _skipped(record, STATUS_COMMIT_FAILED, "MH_SPOOL_COMPACTION")
        # The resolver only returns needs_publish for a slot with no name present, so publication
        # onto that free slot under the exclusive hold cannot collide; any failure (including a
        # surprise existing name) leaves the old segment fully intact.
        try:
            publish(new_path, content)
        except SpoolError as error:
            return _skipped(record, STATUS_PUBLISH_FAILED, error.code)

    try:
        parsed_new = read_trusted_segment(new_path, installation_id=installation_id)
    except SpoolError as error:
        return _skipped(record, STATUS_VERIFY_FAILED, error.code)
    if not _agrees(parsed_new, new_record.day, new_batch_id, new_record):
        return _skipped(record, STATUS_VERIFY_FAILED, "MH_SPOOL_VERIFY")

    if not _swap_ledger(
        database, record, new_record, now=now, insert_new=insert_new, pseudonymizer=pseudonymizer
    ):
        return _skipped(record, STATUS_COMMIT_FAILED, "MH_SPOOL_COMPACTION")

    file_outcome = _remove_old_file(root / _PENDING / record.day / f"{record.batch_id}.jsonl")
    if file_outcome == FILE_REMOVED:
        # The old file is durably gone, so the retirement is complete: clear the tombstone. On any
        # non-removed outcome it REMAINS and mandatory reconciliation finishes the deletion behind a
        # durability fence, so a commit-uncertain unlink can never resurrect the retired segment.
        _clear_retirement(database, record.batch_id)
    return (
        CompactedSegment(
            old_batch_id=record.batch_id,
            new_batch_id=new_batch_id,
            dropped_records=dropped,
            retained_records=retained,
            retained_bytes=new_record.byte_size,
            file_outcome=file_outcome,
        ),
        None,
    )


def _compact_one(
    database: ControlDatabase,
    root: Path,
    installation_id: str,
    now: datetime,
    record: SegmentRecord,
    pseudonymizer: Pseudonymizer,
) -> tuple[CompactedSegment | None, SkippedSegment | None]:
    """Compact one segment iff it is mixed-expiry; else return why it was skipped."""

    old_path = root / _PENDING / record.day / f"{record.batch_id}.jsonl"
    try:
        parsed = read_trusted_segment(old_path, installation_id=installation_id)
    except SpoolError as error:
        return _skipped(record, STATUS_UNREADABLE, error.code)
    if not _agrees(parsed, record.day, record.batch_id, record):
        return _skipped(record, STATUS_DISAGREEING, "MH_SPOOL_VERIFY")

    live_frames = [frame for frame in parsed.frames if frame.record.expires_at > now]
    dropped = len(parsed.frames) - len(live_frames)
    if dropped == 0:
        return _skipped(record, STATUS_LIVE, None)  # nothing expired — not a candidate
    if not live_frames:
        return _skipped(record, STATUS_FULLY_EXPIRED, None)  # all expired — retention prunes it

    # Resolve the single reserved-namespace successor id (free / this compaction's own successor);
    # only a SHA-256 collision could place a non-successor there. A failure leaves the old segment
    # fully intact — a live record is never lost.
    try:
        resolved = _resolve_successor(database, root, installation_id, record, live_frames)
    except SpoolError as error:
        return _skipped(record, STATUS_VERIFY_FAILED, error.code)
    return _finish_rewrite(
        database,
        root,
        installation_id,
        now,
        record,
        resolved,
        pseudonymizer=pseudonymizer,
        publish=_publish_reserved_successor,
        dropped=dropped,
        retained=len(live_frames),
        record_successor=True,
    )


def _rehome_one(
    database: ControlDatabase,
    root: Path,
    installation_id: str,
    now: datetime,
    record: SegmentRecord,
    pseudonymizer: Pseudonymizer,
) -> tuple[CompactedSegment | None, SkippedSegment | None]:
    """Rehome one legacy reserved-namespace occupant to a fresh NON-reserved id (A07).

    A ``c[0-9a-f]{64}`` id was a valid producer batch id before the reservation, so a pre-upgrade
    install can hold a reserved-namespace segment that no successor intent proves genuine — a
    producer-committed row OR a pre-upgrade producer crash's orphan reconciliation registered
    ``origin=reconciled``. Rather than wedge acquisition (the earlier design — G03 review #79-P1-4),
    compaction rewrites it — preserving EVERY record — to a non-reserved MONOTONIC target a producer
    cannot pre-occupy (#79-P1-1), retiring the old file under a durable tombstone, so the reserved
    namespace then holds only genuine compaction successors. The target allocation and its publish →
    verify → swap → retire tail are idempotent and restartable across every crash boundary. A rehome
    that cannot complete this pass leaves the occupant intact for the next pass; acquisition is
    never blocked.
    """

    old_path = root / _PENDING / record.day / f"{record.batch_id}.jsonl"
    try:
        parsed = read_trusted_segment(old_path, installation_id=installation_id)
    except SpoolError as error:
        return _skipped(record, STATUS_UNREADABLE, error.code)
    if not _agrees(parsed, record.day, record.batch_id, record):
        return _skipped(record, STATUS_DISAGREEING, "MH_SPOOL_VERIFY")
    if not parsed.frames:  # pragma: no cover - a committed segment always carries frames
        return _skipped(record, STATUS_DISAGREEING, "MH_SPOOL_VERIFY")

    # Allocate (or reuse) a MONOTONIC non-reserved target and bind it durably to the source BEFORE
    # publishing, then resolve that exact target slot (free / this rehome's own crash orphan).
    target = _allocate_rehome_target(database, root, record, now)
    resolved = _resolve_target(database, root, installation_id, record, list(parsed.frames), target)
    # ALL frames are retained (dropped=0): the rehome is a pure relocation, not an expiry rewrite.
    # The target is NON-reserved, so it publishes through the ordinary producer path. The rehome
    # intent is already recorded (record_successor=False).
    return _finish_rewrite(
        database,
        root,
        installation_id,
        now,
        record,
        resolved,
        pseudonymizer=pseudonymizer,
        publish=publish_segment_bytes,
        dropped=0,
        retained=len(parsed.frames),
        record_successor=False,
    )


def _load_installation_key(
    database: ControlDatabase, config: MilhouseConfig, paths: RuntimePaths
) -> Pseudonymizer:
    """Load the installation's own pseudonym key, BOUND to the control-plane key identity (A07).

    Provenance is not established merely by loading a file at the config-bound path: a
    :class:`Pseudonymizer` is constructible from any 32 bytes, and a wrong, restored, rotated, or
    cross-installation valid key can sit at that path. So compaction (a) binds the config/runtime
    ``state_root`` to THIS control database's state root — exactly as ``spool_root`` is bound — so a
    foreign config/paths pair cannot key lineage; (b) reads the recorded non-secret key
    id/epoch from the control plane (``_installation_key``, established by ``init``/W06); and (c)
    loads the key with those exact ``expected_key_id``/epoch. An absent record (unprovisioned), a
    missing/unloadable/malformed key, a cross-installation state root, or id/epoch mismatch all fail
    closed HERE, before the barrier and before any file/ledger/cursor/audit mutation. Because the
    caller supplies no key object, a forged ``Pseudonymizer`` can never reach the audit
    path (G03 review: caller-forgeable key not bound to the installation)."""

    database_path = _validated_database_path(database)
    if database_path is None:  # pragma: no cover - _validate_common already rejects this
        _fail("MH_SPOOL_COMPACTION", "a control database is required")
    # Bind the runtime state root to the control database's state root, so a config/paths pair from
    # another installation (a different key at a valid path) cannot pass provenance.
    expected_state_root = database_path.parent.parent
    try:
        actual_state_root = lexical_absolute_path(cast("str | Path", paths.state_root))
    except SecureFileError:  # pragma: no cover - defensive: a resolved state_root rarely fails
        _fail("MH_SPOOL_COMPACTION", "the runtime state root is invalid")
    if actual_state_root != expected_state_root:
        _fail("MH_SPOOL_COMPACTION", "the runtime state root must match the control database")

    try:
        recorded = read_installation_key(database)
    except StateError:  # pragma: no cover - defensive: the database type is already validated
        _fail("MH_SPOOL_COMPACTION", "the installation key identity could not be read")
    if recorded is None:
        _fail("MH_SPOOL_COMPACTION", "compaction requires the provisioned installation key")
    key_id, epoch = recorded

    loaded: Pseudonymizer | None = None
    try:
        loaded = load_pseudonym_key(config, paths, epoch=epoch, expected_key_id=key_id)
    except PrivacyError:
        loaded = None
    if loaded is None:
        _fail(
            "MH_SPOOL_COMPACTION",
            "the provisioned installation key could not be loaded or verified",
        )
    return loaded


def compact_apply(
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    *,
    spool_root: str | Path,
    installation_id: str,
    now: datetime,
    confirm: bool,
    config: MilhouseConfig,
    paths: RuntimePaths,
) -> CompactionResult:
    """Rewrite every mixed-expiry committed segment into a new unexpired-only segment, audited.

    ``confirm`` must be ``True`` — a preview-then-apply guard so compaction never mutates on an
    accidental call. The whole pass runs under ``barrier.exclusive()``. Each segment is re-read and
    re-verified against its ledger row under the lock; a mixed-expiry segment (some records expired,
    some live) is rewritten, a segment with nothing expired or with everything expired is left alone
    (retention prunes the fully-expired ones), and an unreadable or disagreeing segment is left for
    verify/reconciliation. Every failure normalizes to a fixed ``MH_SPOOL_*`` code.

    Keyed old→new lineage is a W03 deliverable (plan §4.7), and per ADR 0007 addendum A07 its
    authority is established by LOADING the installation's own pseudonym key inside the validated
    ``config``/``paths`` boundary (:func:`milhouse.privacy.keys.load_pseudonym_key`) — compaction
    accepts no caller-supplied key object. A missing (unprovisioned installation), unloadable, or
    cross-installation key fails closed HERE, before the barrier and before any file, ledger, or
    audit mutation; compaction therefore cannot run on an un-``init``'d installation.
    """

    _validate_common(database, spool_root, installation_id)
    _validate_barrier(database, barrier)
    _require_now(now)
    if confirm is not True:
        _fail("MH_SPOOL_COMPACTION", "compaction apply requires an explicit confirmation")
    # Establish keyed-lineage provenance (A07) only after the inputs validate, but still before the
    # barrier and any mutation: an unprovisioned/wrong/cross-installation key fails closed here.
    pseudonymizer = _load_installation_key(database, config, paths)
    root = Path(spool_root)

    compacted: list[CompactedSegment] = []
    skipped: list[SkippedSegment] = []
    rehomed: list[CompactedSegment] = []
    with barrier.exclusive():
        # A07 auto-converging remediation FIRST: rehome any reserved-namespace segment that no
        # durable successor intent proves genuine — a legal pre-reservation occupant (a
        # producer-committed row OR a pre-upgrade producer crash's orphan reconciliation registered
        # ``origin=reconciled``). Origin cannot distinguish these from genuine successors, so
        # provenance is authoritative: a reserved id is a genuine successor ONLY if an intent proves
        # it (G03 review #79-P1-2). No legal upgraded install is ever wedged (#79-P1-4).
        for record in list_segment_records(database):
            if is_reserved_compaction_batch_id(record.batch_id) and not is_recorded_successor(
                database.connection, record.batch_id
            ):
                done, skip = _rehome_one(
                    database, root, installation_id, now, record, pseudonymizer
                )
                if done is not None:
                    rehomed.append(done)
                else:
                    assert skip is not None
                    skipped.append(skip)
        # Then compact mixed-expiry segments. Re-read the ledger (the rehome changed it) and never
        # compact a still-unproven reserved row in place (a rehome that did not complete this pass)
        # — that would derive another reserved successor instead of converging the namespace.
        for record in list_segment_records(database):
            if is_reserved_compaction_batch_id(record.batch_id) and not is_recorded_successor(
                database.connection, record.batch_id
            ):
                continue
            done, skip = _compact_one(database, root, installation_id, now, record, pseudonymizer)
            if done is not None:
                compacted.append(done)
            else:
                assert skip is not None
                skipped.append(skip)
    return CompactionResult(
        compacted=tuple(compacted), skipped=tuple(skipped), rehomed=tuple(rehomed)
    )
