"""Read-only local views over spooled state for the Milhouse CLI (W06 inspect commands).

``spool list`` / ``spool show``, ``events``, and ``doctor`` read the durable spool and control
ledger and report privacy-safe *metadata only* — never the raw record payload — consistent with the
local-query egress policy (plan section 4.7). Everything here is local and read-only over the spool:
no network, no mutation, no secret resolution. The whole-record egress that feeds the G04b
ClickHouse export is not here: it is the spool's own G03-certified delivery ledger, which
``storage export`` drives through :func:`~milhouse.spooling.replay.replay_segments`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from milhouse.cli import bootstrap
from milhouse.config import RuntimePaths
from milhouse.core.clock import format_timestamp
from milhouse.spooling import ParsedSegment, SpoolError, read_trusted_segment
from milhouse.spooling.ledger import (
    SegmentRecord,
    list_segment_records,
    read_segment_record,
)
from milhouse.state import open_control_database


@dataclass(frozen=True, slots=True)
class SegmentSummary:
    """Privacy-safe ledger summary of one committed spool segment."""

    batch_id: str
    day: str
    record_count: int
    byte_size: int
    privacy_class: str
    scope: str
    target_id: str | None
    origin: str
    delivered: bool


@dataclass(frozen=True, slots=True)
class EventSummary:
    """Privacy-safe metadata for one spooled record (no raw payload)."""

    batch_id: str
    record_id: str
    record_type: str
    name: str
    occurred_at: str
    expires_at: str
    target_id: str | None
    privacy_class: str
    severity: str


@dataclass(frozen=True, slots=True)
class SegmentDetail:
    """One segment's summary plus its per-record metadata, when the file is readable."""

    summary: SegmentSummary
    readable: bool
    events: tuple[EventSummary, ...]


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """A richer redacted diagnostic: health plus spool totals."""

    health: bootstrap.HealthReport
    segment_count: int
    record_count: int
    spool_readable: bool

    @property
    def ok(self) -> bool:
        return self.health.healthy and self.spool_readable


def _delivered(record: SegmentRecord) -> bool:
    return bool(record.exporters) and all(
        exporter.delivery_status == "delivered" for exporter in record.exporters
    )


def _summary(record: SegmentRecord) -> SegmentSummary:
    return SegmentSummary(
        batch_id=record.batch_id,
        day=record.day,
        record_count=record.record_count,
        byte_size=record.byte_size,
        privacy_class=record.privacy_class,
        scope=record.scope,
        target_id=record.target_id,
        origin=record.origin,
        delivered=_delivered(record),
    )


def _segment_path(paths: RuntimePaths, record: SegmentRecord) -> Path:
    return paths.spool / "pending" / record.day / f"{record.batch_id}.jsonl"


def _segments(paths: RuntimePaths) -> tuple[SegmentRecord, ...]:
    database = open_control_database(bootstrap.database_path(paths))
    try:
        return list_segment_records(database)
    finally:
        database.close()


def _events_of(record: SegmentRecord, parsed: ParsedSegment) -> list[EventSummary]:
    events: list[EventSummary] = []
    for frame in parsed.frames:
        envelope = frame.record
        events.append(
            EventSummary(
                batch_id=record.batch_id,
                record_id=envelope.record_id,
                record_type=envelope.record_type,
                name=envelope.name,
                occurred_at=format_timestamp(envelope.occurred_at),
                expires_at=format_timestamp(envelope.expires_at),
                target_id=envelope.target.id if envelope.target is not None else None,
                privacy_class=envelope.privacy_class,
                severity=envelope.severity,
            )
        )
    return events


def list_segments(paths: RuntimePaths) -> tuple[SegmentSummary, ...]:
    """Return a privacy-safe summary of every committed segment in the ledger."""

    return tuple(_summary(record) for record in _segments(paths))


def read_events(paths: RuntimePaths, installation_id: str) -> tuple[EventSummary, ...]:
    """Read every committed segment back through the trusted reader; return record metadata.

    An unreadable or disagreeing segment is skipped rather than raising, so one bad file never hides
    the rest.
    """

    events: list[EventSummary] = []
    for record in _segments(paths):
        try:
            parsed = read_trusted_segment(
                _segment_path(paths, record), installation_id=installation_id
            )
        except SpoolError:
            continue
        events.extend(_events_of(record, parsed))
    return tuple(events)


def show_segment(paths: RuntimePaths, batch_id: str, installation_id: str) -> SegmentDetail | None:
    """Return one segment's summary and record metadata, or ``None`` if it is not in the ledger."""

    database = open_control_database(bootstrap.database_path(paths))
    try:
        record = read_segment_record(database, batch_id)
    finally:
        database.close()
    if record is None:
        return None
    try:
        parsed = read_trusted_segment(_segment_path(paths, record), installation_id=installation_id)
    except SpoolError:
        return SegmentDetail(summary=_summary(record), readable=False, events=())
    return SegmentDetail(
        summary=_summary(record), readable=True, events=tuple(_events_of(record, parsed))
    )


def doctor(paths: RuntimePaths, *, now: datetime) -> DoctorReport:
    """Report health plus spool totals, never mutating and never raising on a bad spool."""

    health = bootstrap.health(paths, now=now)
    segment_count = 0
    record_count = 0
    spool_readable = True
    if bootstrap.database_path(paths).is_file():
        try:
            records = _segments(paths)
            segment_count = len(records)
            record_count = sum(record.record_count for record in records)
        except Exception:  # pragma: no cover - defensive: a diagnostic reports, never raises
            spool_readable = False
    return DoctorReport(
        health=health,
        segment_count=segment_count,
        record_count=record_count,
        spool_readable=spool_readable,
    )
