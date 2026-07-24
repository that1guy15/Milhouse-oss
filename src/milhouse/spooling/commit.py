"""Durable spool commit and segment ledger, bound to one control plane (W03 slice 3a).

A :class:`DurableSpool` binds one control database, one commit barrier, and one spool root that all
live under the same canonical state root, so a caller cannot publish under a different barrier than
maintenance holds. Per ADR 0004 and plan section 4.7 a commit is a deliberate, authorized,
reconciled operation: it authorizes the ``local_spool`` and ``local_sqlite`` egress surfaces
(restricted input is rejected before any mutation), derives the ``YYYY-MM-DD`` partition from the
commit instant, then, while holding the shared commit barrier, creates the partition directory,
atomically publishes the exact segment bytes (write, flush, fsync, no-replace rename, parent fsync),
and inserts the segment ledger row plus one row per required exporter in a single SQLite
transaction. A crash or ledger failure after publication leaves a durable orphan and is reported as
commit-uncertain ``MH_SPOOL_COMMIT``, never as success. The ledger preserves every immutable header
field so recovery never infers policy from newer configuration, and every read is semantically
validated so a corrupt or foreign row fails closed with ``MH_SPOOL_LEDGER``. Every failure raises a
fixed ``MH_SPOOL_*`` error outside the handler.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from milhouse.config.filesystem import lexical_absolute_path
from milhouse.core.clock import TimeError, format_timestamp
from milhouse.privacy import (
    EgressDisposition,
    EgressSurface,
    PrivacyError,
    require_egress,
)
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.segment import (
    EXPORTER_ID_PATTERN,
    FRAME_VERSION,
    SCHEMA_VERSION,
    SegmentHeaderV1,
    SpoolFrameV1,
)
from milhouse.spooling.writer import build_segment_bytes, publish_segment_bytes
from milhouse.state.barrier import GlobalCommitBarrier
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_SPOOL = "spool"
_BARRIER_NAME = "commit.lock"
_PENDING = "pending"
_DIR_MODE = 0o700
_DELIVERY_PENDING = "pending"
_DAY_LENGTH = 10
_SCOPES = ("installation", "target")
_ALLOWED_PRIVACY = ("public", "internal", "sensitive")
_DELIVERY_STATES = ("pending", "delivered", "failed")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)
_STAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", flags=re.ASCII
)
_SEGMENT_COLUMNS = (
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
)


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


def _current_uid() -> int:
    # Match the W02 secure-file writer (filesystem.py), which validates against the effective uid.
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # pragma: no cover - Milhouse supports only POSIX hosts
        _fail("MH_SPOOL_UNSUPPORTED", "the spool requires a POSIX ownership model")
    return int(geteuid())


@dataclass(frozen=True, slots=True)
class ExporterDelivery:
    """The delivery state of one required exporter for a committed segment."""

    exporter_id: str
    delivery_status: str


@dataclass(frozen=True, slots=True)
class SegmentRecord:
    """A committed segment's immutable ledger row plus its per-exporter delivery rows."""

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
    exporters: tuple[ExporterDelivery, ...]


def _authorize(privacy_class: str) -> None:
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


def _committed_stamp(committed_at: datetime) -> str:
    invalid = False
    stamp = ""
    try:
        stamp = format_timestamp(committed_at)
    except (OverflowError, TimeError):
        invalid = True
    if invalid:
        _fail("MH_SPOOL_COMMIT", "the commit timestamp must be an aware in-range UTC instant")
    return stamp


def _require_private_dir(path: Path, subject: str) -> None:
    info: os.stat_result | None
    try:
        info = os.lstat(path)
    except OSError:
        info = None
    if (
        info is None
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != _current_uid()
        or stat.S_IMODE(info.st_mode) != _DIR_MODE
    ):
        _fail("MH_SPOOL_DIR", f"the {subject} must be an owned 0o700 directory")


def _secure_child_dir(parent: Path, name: str) -> Path:
    child = parent / name
    create_failed = False
    try:
        os.mkdir(child, _DIR_MODE)
    except FileExistsError:
        pass
    except OSError:
        create_failed = True
    if create_failed:
        _fail("MH_SPOOL_DIR", "a spool directory could not be created")
    _require_private_dir(child, "spool directory")
    return child


def _pending_day_dir(spool_root: Path, day: str) -> Path:
    _require_private_dir(spool_root, "spool root")
    return _secure_child_dir(_secure_child_dir(spool_root, _PENDING), day)


def _insert_ledger(database: ControlDatabase, record: SegmentRecord) -> None:
    segment_values = (
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
    )
    placeholders = ", ".join("?" for _ in _SEGMENT_COLUMNS)
    failed = False
    try:
        with database.transaction() as connection:
            connection.execute(
                f"INSERT INTO _segments ({', '.join(_SEGMENT_COLUMNS)}) VALUES ({placeholders})",
                segment_values,
            )
            for exporter in record.exporters:
                connection.execute(
                    "INSERT INTO _segment_exporters (batch_id, exporter_id, delivery_status) "
                    "VALUES (?, ?, ?)",
                    (record.batch_id, exporter.exporter_id, exporter.delivery_status),
                )
    except (sqlite3.Error, StateError):
        # The file is durably published; any ledger or transaction-boundary failure leaves a
        # registrable orphan and is reported as commit-uncertain, never as success.
        failed = True
    if failed:
        _fail("MH_SPOOL_COMMIT", "the segment ledger could not be committed")


def _validated_segment(row: Any, exporters: tuple[ExporterDelivery, ...]) -> SegmentRecord:
    """Reconstruct a SegmentRecord, raising ValueError on any semantic violation (caught above)."""

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
        exporters=exporters,
    )


def _load_exporters(connection: sqlite3.Connection, batch_id: str) -> tuple[ExporterDelivery, ...]:
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


class DurableSpool:
    """A durable spool bound to one control database, commit barrier, and spool root."""

    __slots__ = ("_barrier", "_database", "_spool_root")

    def __init__(
        self,
        *,
        database: ControlDatabase,
        barrier: GlobalCommitBarrier,
        spool_root: str | Path,
    ) -> None:
        if not isinstance(database, ControlDatabase):
            _fail("MH_SPOOL_STORE", "a control database is required")
        if not isinstance(barrier, GlobalCommitBarrier):
            _fail("MH_SPOOL_STORE", "a commit barrier is required")
        control_dir = lexical_absolute_path(database.path).parent
        state_root = control_dir.parent
        resolved_spool = lexical_absolute_path(spool_root)
        if lexical_absolute_path(barrier.path) != control_dir / _BARRIER_NAME:
            # Pin the exact lock, not just its directory: a barrier on a different file beside the
            # database would share no flock with maintenance, so publication would race a backup or
            # migration despite the barrier being "held".
            _fail("MH_SPOOL_STORE", "the barrier must be the control-plane commit lock")
        if resolved_spool != state_root / _SPOOL:
            _fail("MH_SPOOL_STORE", "the spool root must be <state_root>/spool")
        self._database = database
        self._barrier = barrier
        self._spool_root = resolved_spool

    def commit_segment(
        self,
        header: SegmentHeaderV1,
        frames: tuple[SpoolFrameV1, ...] | list[SpoolFrameV1],
        *,
        committed_at: datetime,
    ) -> SegmentRecord:
        """Authorize, publish, and record one segment under the shared commit barrier."""

        if not isinstance(header, SegmentHeaderV1):
            _fail("MH_SPOOL_HEADER", "a segment header is required")
        _authorize(header.privacy_class)
        stamp = _committed_stamp(committed_at)
        day = stamp[:_DAY_LENGTH]
        content = build_segment_bytes(header, frames)
        record = SegmentRecord(
            batch_id=header.batch_id,
            day=day,
            schema_version=SCHEMA_VERSION,
            frame_version=FRAME_VERSION,
            config_generation=header.config_generation,
            scope=header.scope,
            target_id=header.target_id,
            privacy_class=header.privacy_class,
            retention_days=header.retention_days,
            record_count=header.record_count,
            content_sha256=header.content_sha256,
            byte_size=len(content),
            file_sha256=hashlib.sha256(content).hexdigest(),
            committed_at=stamp,
            exporters=tuple(
                ExporterDelivery(exporter_id=exporter, delivery_status=_DELIVERY_PENDING)
                for exporter in header.required_exporters
            ),
        )
        with self._barrier.shared():
            day_dir = _pending_day_dir(self._spool_root, day)
            publish_segment_bytes(day_dir / f"{header.batch_id}.jsonl", content)
            _insert_ledger(self._database, record)
        return record

    def read_segment(self, batch_id: str) -> SegmentRecord | None:
        """Return the committed segment ledger record for ``batch_id``, or None. Read-only."""

        failed = False
        result: SegmentRecord | None = None
        try:
            connection = self._database.connection
            row = connection.execute(
                f"SELECT {', '.join(_SEGMENT_COLUMNS)} FROM _segments WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            if row is not None:
                result = _validated_segment(row, _load_exporters(connection, str(row[0])))
        except (sqlite3.Error, ValueError, TypeError):
            failed = True
        if failed:
            _fail("MH_SPOOL_LEDGER", "the segment ledger could not be read")
        return result

    def list_segments(self, *, delivery_status: str | None = None) -> tuple[SegmentRecord, ...]:
        """Return committed segments, optionally only those with an exporter in the given status."""

        failed = False
        records: tuple[SegmentRecord, ...] = ()
        try:
            connection = self._database.connection
            if delivery_status is None:
                rows = connection.execute(
                    f"SELECT {', '.join(_SEGMENT_COLUMNS)} FROM _segments ORDER BY batch_id"
                ).fetchall()
            else:
                rows = connection.execute(
                    f"SELECT {', '.join('s.' + c for c in _SEGMENT_COLUMNS)} FROM _segments s "
                    "WHERE EXISTS (SELECT 1 FROM _segment_exporters e "
                    "WHERE e.batch_id = s.batch_id AND e.delivery_status = ?) ORDER BY s.batch_id",
                    (delivery_status,),
                ).fetchall()
            records = tuple(
                _validated_segment(row, _load_exporters(connection, str(row[0]))) for row in rows
            )
        except (sqlite3.Error, ValueError, TypeError):
            failed = True
        if failed:
            _fail("MH_SPOOL_LEDGER", "the segment ledger could not be read")
        return records
