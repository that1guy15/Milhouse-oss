"""Deterministic, idempotent replay of committed segments (W03 slice 4, plan section 4.3).

Replay reprocesses committed segments — re-reading each durable file back as trusted state and
re-driving downstream delivery — so a rebuilt or recovered installation converges on exactly the
logical records the spool already holds. Two properties make it safe to run repeatedly, which the
G03 evidence packet exercises at scale ("replay 10,000 records twice yields identical logical ids
and counts"):

* **Deterministic.** Segments are visited in ``batch_id`` order and frames in contiguous sequence
  order, so the emitted record-id stream is identical on every run over the same ledger.
* **Idempotent.** Each segment's durable bytes are re-read through :func:`read_trusted_segment`
  (full no-follow, ownership, canonical, and record-provenance re-verification) and cross-checked
  against the ledger's recorded digests before anything downstream runs, so a tampered or drifted
  file fails closed rather than replaying corrupt state. Delivery is driven through the exporter
  protocol, whose compare-and-set makes an already-delivered segment a no-op — so a second replay
  re-emits the same record ids without re-delivering.

Replay never mutates the durable files or the ledger's segment rows; it only advances the
delivery-side checkpoints the exporter protocol owns. Every failure is a fixed ``MH_SPOOL_*`` error
raised outside any handler.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from milhouse.config.filesystem import SecureFileError, lexical_absolute_path
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.exporter import Exporter, ExporterAttempt, deliver_segment
from milhouse.spooling.ledger import SegmentRecord, list_segment_records
from milhouse.spooling.reader import (
    INSTALLATION_ID_PATTERN,
    ParsedSegment,
    read_trusted_segment,
)
from milhouse.state.barrier import GlobalCommitBarrier
from milhouse.state.database import ControlDatabase, _validated_database_path

_PENDING = "pending"
_SPOOL = "spool"


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


@dataclass(frozen=True, slots=True)
class ReplayReport:
    """The deterministic result of one replay pass over the committed segments."""

    segments: tuple[str, ...]
    record_ids: tuple[str, ...]
    delivery_attempts: tuple[ExporterAttempt, ...]

    @property
    def record_count(self) -> int:
        return len(self.record_ids)


def _verify_against_ledger(parsed: ParsedSegment, record: SegmentRecord) -> None:
    """Require the durable file to match the ledger's recorded digests exactly, or fail closed.

    The trusted reader already proves the file is canonical, owner-only, and record-authentic; this
    adds that it is the *same* segment the ledger committed — identical bytes, digest, and count —
    so replay can never process a file that drifted from the row that authorizes it.
    """

    if (
        parsed.file_sha256 != record.file_sha256
        or parsed.byte_size != record.byte_size
        or parsed.header.content_sha256 != record.content_sha256
        or len(parsed.frames) != record.record_count
    ):
        _fail("MH_SPOOL_REPLAY", "a durable segment does not match its ledger row")


def replay_segments(
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    *,
    spool_root: str | Path,
    installation_id: str,
    exporters: Mapping[str, Exporter],
    delivery_status: str | None = None,
) -> ReplayReport:
    """Replay committed segments deterministically, driving idempotent exporter delivery.

    ``delivery_status`` optionally narrows the pass to segments with an exporter in that state (e.g.
    ``"pending"`` to drive only undelivered work); with ``None`` every committed segment is
    replayed, which is the shape the recovery/rebuild path and the G03 double-replay evidence use.
    The returned record-id stream is identical across runs over an unchanged ledger.
    """

    if type(database) is not ControlDatabase:
        _fail("MH_SPOOL_REPLAY", "a control database is required")
    if type(barrier) is not GlobalCommitBarrier:
        _fail("MH_SPOOL_REPLAY", "a commit barrier is required")
    if (
        type(installation_id) is not str
        or INSTALLATION_ID_PATTERN.fullmatch(installation_id) is None
    ):
        _fail("MH_SPOOL_IDENTITY", "a well-formed installation id is required")
    # Bind the spool root to this database's state root so replay reprocesses the authoritative
    # durable spool, never a shadow copy (D05 P2).
    database_path = _validated_database_path(database)
    if database_path is None:
        _fail("MH_SPOOL_REPLAY", "a control database is required")
    try:
        root = lexical_absolute_path(spool_root)
    except SecureFileError:
        _fail("MH_SPOOL_REPLAY", "a spool root path is required")
    if root != database_path.parent.parent / _SPOOL:
        _fail("MH_SPOOL_REPLAY", "the spool root must be <state_root>/spool")

    records = list_segment_records(database, delivery_status=delivery_status)
    segments: list[str] = []
    record_ids: list[str] = []
    attempts: list[ExporterAttempt] = []
    for record in records:
        path = root / _PENDING / record.day / f"{record.batch_id}.jsonl"
        parsed = read_trusted_segment(path, installation_id=installation_id)
        _verify_against_ledger(parsed, record)
        segments.append(record.batch_id)
        record_ids.extend(frame.record.record_id for frame in parsed.frames)
        attempts.extend(deliver_segment(database, barrier, record, parsed.frames, exporters))
    return ReplayReport(
        segments=tuple(segments),
        record_ids=tuple(record_ids),
        delivery_attempts=tuple(attempts),
    )
