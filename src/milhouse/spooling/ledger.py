"""Shared segment-ledger primitives for the durable spool (W03).

The commit path (:mod:`milhouse.spooling.commit`) and the reconciliation scan
(:mod:`milhouse.spooling.reconcile`) both read, validate, authorize, and write ``_segments`` /
``_segment_exporters`` rows. This leaf module owns those shared primitives — the ``SegmentRecord``
shape, the fixed egress authorization of the local persistence surfaces, the fully semantic row
validator, and the single-row insert — so both callers enforce exactly the same contract and neither
imports the other. Every failure is a fixed ``MH_SPOOL_*`` error raised outside any handler, so no
filesystem, SQLite, or record detail reaches its cause, context, args, or traceback.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn

from milhouse.privacy import (
    EgressDisposition,
    EgressSurface,
    PrivacyError,
    require_egress,
)
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.segment import (
    BATCH_ID_PATTERN,
    EXPORTER_ID_PATTERN,
    FRAME_VERSION,
    SCHEMA_VERSION,
)
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_DAY_LENGTH = 10
_DELIVERY_PENDING = "pending"
_SCOPES = ("installation", "target")
_ALLOWED_PRIVACY = ("public", "internal", "sensitive")
_DELIVERY_STATES = ("pending", "delivered", "failed")
ORIGIN_COMMITTED = "committed"
ORIGIN_RECONCILED = "reconciled"
_ORIGINS = (ORIGIN_COMMITTED, ORIGIN_RECONCILED)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)
_STAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", flags=re.ASCII
)
SEGMENT_COLUMNS = (
    "batch_id",
    "day",
    "schema_version",
    "frame_version",
    "config_generation",
    "scope",
    "target_id",
    "privacy_class",
    "retention_days",
    "record_count",
    "content_sha256",
    "byte_size",
    "file_sha256",
    "committed_at",
    "origin",
)


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


@dataclass(frozen=True, slots=True)
class ExporterDelivery:
    """The delivery state of one required exporter for a committed segment."""

    exporter_id: str
    delivery_status: str


@dataclass(frozen=True, slots=True)
class SegmentRecord:
    """A committed segment's immutable ledger row plus its per-exporter delivery rows.

    ``origin`` is ``committed`` for a normal durable commit and ``reconciled`` for an orphan that
    reconciliation registered from its durable file, whose ``committed_at`` is a reconstructed
    day-start rather than the exact (lost) commit instant.
    """

    batch_id: str
    day: str
    schema_version: int
    frame_version: int
    config_generation: str
    scope: str
    target_id: str | None
    privacy_class: str
    retention_days: int
    record_count: int
    content_sha256: str
    byte_size: int
    file_sha256: str
    committed_at: str
    origin: str
    exporters: tuple[ExporterDelivery, ...]


def authorize_local_persistence(privacy_class: str) -> None:
    """Authorize the local_spool and local_sqlite surfaces for a class, or fail ``MH_SPOOL_EGRESS``.

    This is the single fail-closed policy boundary every persistence path — commit and recovery
    alike — must cross before writing a segment or a ledger row.
    """

    denied = False
    dispositions: tuple[EgressDisposition, ...] = ()
    try:
        dispositions = tuple(
            require_egress(surface=surface, privacy_class=privacy_class)  # type: ignore[arg-type]
            for surface in (EgressSurface.LOCAL_SPOOL, EgressSurface.LOCAL_SQLITE)
        )
    except PrivacyError:
        denied = True
    if denied or any(d is not EgressDisposition.REDACTED_RECORD for d in dispositions):
        _fail(
            "MH_SPOOL_EGRESS", "the local persistence surfaces do not authorize this privacy class"
        )


def validated_segment(row: Any, exporters: tuple[ExporterDelivery, ...]) -> SegmentRecord:
    """Reconstruct a SegmentRecord from a raw row, raising ValueError on any semantic violation.

    Callers run this inside a fail-closed boundary that maps the ValueError to ``MH_SPOOL_LEDGER``.
    The row must carry every :data:`SEGMENT_COLUMNS` value in order, including ``origin`` last.
    """

    batch_id = str(row[0])
    if BATCH_ID_PATTERN.fullmatch(batch_id) is None:
        raise ValueError("batch_id is not well formed")
    day = str(row[1])
    datetime.strptime(day, "%Y-%m-%d")  # a bare partition date, not an instant
    schema_version = int(row[2])
    frame_version = int(row[3])
    config_generation = str(row[4])
    scope = str(row[5])
    target_id = None if row[6] is None else str(row[6])
    privacy_class = str(row[7])
    retention_days = int(row[8])
    record_count = int(row[9])
    content_sha256 = str(row[10])
    byte_size = int(row[11])
    file_sha256 = str(row[12])
    committed_at = str(row[13])
    origin = str(row[14])
    if schema_version != SCHEMA_VERSION or frame_version != FRAME_VERSION:
        raise ValueError("unexpected schema or frame version")
    if _SHA256_HEX.fullmatch(config_generation) is None:
        raise ValueError("config_generation is not a sha-256 digest")
    if scope not in _SCOPES or (scope == "target") != (target_id is not None):
        raise ValueError("scope/target relation is invalid")
    if privacy_class not in _ALLOWED_PRIVACY:
        raise ValueError("privacy class is invalid")
    if not 1 <= retention_days <= 3650 or record_count < 0 or byte_size <= 0:
        raise ValueError("retention/count/size out of bounds")
    if _SHA256_HEX.fullmatch(content_sha256) is None or _SHA256_HEX.fullmatch(file_sha256) is None:
        raise ValueError("a digest is not a sha-256")
    if _STAMP.fullmatch(committed_at) is None or committed_at[:_DAY_LENGTH] != day:
        raise ValueError("committed_at is not a canonical stamp matching the day")
    if origin not in _ORIGINS:
        raise ValueError("origin is invalid")
    return SegmentRecord(
        batch_id=str(row[0]),
        day=day,
        schema_version=schema_version,
        frame_version=frame_version,
        config_generation=config_generation,
        scope=scope,
        target_id=target_id,
        privacy_class=privacy_class,
        retention_days=retention_days,
        record_count=record_count,
        content_sha256=content_sha256,
        byte_size=byte_size,
        file_sha256=file_sha256,
        committed_at=committed_at,
        origin=origin,
        exporters=exporters,
    )


def load_exporters(connection: sqlite3.Connection, batch_id: str) -> tuple[ExporterDelivery, ...]:
    rows = connection.execute(
        "SELECT exporter_id, delivery_status FROM _segment_exporters WHERE batch_id = ? "
        "ORDER BY exporter_id",
        (batch_id,),
    ).fetchall()
    exporters: list[ExporterDelivery] = []
    for exporter_id, delivery_status in rows:
        identifier = str(exporter_id)
        status = str(delivery_status)
        if EXPORTER_ID_PATTERN.fullmatch(identifier) is None:
            raise ValueError("exporter id is not well formed")
        if status not in _DELIVERY_STATES:
            raise ValueError("delivery status is invalid")
        exporters.append(ExporterDelivery(exporter_id=identifier, delivery_status=status))
    return tuple(exporters)


def insert_segment_row(connection: sqlite3.Connection, record: SegmentRecord) -> None:
    """Insert one segment ledger row plus its exporter rows on an open transaction connection."""

    values = (
        record.batch_id,
        record.day,
        record.schema_version,
        record.frame_version,
        record.config_generation,
        record.scope,
        record.target_id,
        record.privacy_class,
        record.retention_days,
        record.record_count,
        record.content_sha256,
        record.byte_size,
        record.file_sha256,
        record.committed_at,
        record.origin,
    )
    placeholders = ", ".join("?" for _ in SEGMENT_COLUMNS)
    connection.execute(
        f"INSERT INTO _segments ({', '.join(SEGMENT_COLUMNS)}) VALUES ({placeholders})",
        values,
    )
    for exporter in record.exporters:
        connection.execute(
            "INSERT INTO _segment_exporters (batch_id, exporter_id, delivery_status) "
            "VALUES (?, ?, ?)",
            (record.batch_id, exporter.exporter_id, exporter.delivery_status),
        )


def read_segment_record(database: ControlDatabase, batch_id: str) -> SegmentRecord | None:
    """Return the validated ledger record for ``batch_id``, or None. Fails ``MH_SPOOL_LEDGER``."""

    failed = False
    result: SegmentRecord | None = None
    try:
        connection = database.connection
        row = connection.execute(
            f"SELECT {', '.join(SEGMENT_COLUMNS)} FROM _segments WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if row is not None:
            result = validated_segment(row, load_exporters(connection, str(row[0])))
    except (sqlite3.Error, StateError, ValueError, TypeError):
        failed = True
    if failed:
        _fail("MH_SPOOL_LEDGER", "the segment ledger could not be read")
    return result


def list_segment_records(
    database: ControlDatabase, *, delivery_status: str | None = None
) -> tuple[SegmentRecord, ...]:
    """Return validated committed segments, optionally filtered by exporter delivery status."""

    failed = False
    records: tuple[SegmentRecord, ...] = ()
    try:
        connection = database.connection
        if delivery_status is None:
            rows = connection.execute(
                f"SELECT {', '.join(SEGMENT_COLUMNS)} FROM _segments ORDER BY batch_id"
            ).fetchall()
        else:
            rows = connection.execute(
                f"SELECT {', '.join('s.' + c for c in SEGMENT_COLUMNS)} FROM _segments s "
                "WHERE EXISTS (SELECT 1 FROM _segment_exporters e "
                "WHERE e.batch_id = s.batch_id AND e.delivery_status = ?) ORDER BY s.batch_id",
                (delivery_status,),
            ).fetchall()
        records = tuple(
            validated_segment(row, load_exporters(connection, str(row[0]))) for row in rows
        )
    except (sqlite3.Error, StateError, ValueError, TypeError):
        failed = True
    if failed:
        _fail("MH_SPOOL_LEDGER", "the segment ledger could not be read")
    return records
