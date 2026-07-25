"""Durable spool commit, bound to one control plane with mandatory recovery (W03 slices 3a/3c).

A :class:`DurableSpool` binds one control database, one commit barrier, one spool root, and the
installation identity, all under the same canonical state root, so a caller cannot publish under a
different barrier than maintenance holds. Per ADR 0004 and plan sections 3.4/4.3, mandatory
spool/ledger reconciliation runs on writer acquisition AND inside every commit's own exclusive
critical section with no unlock window before publication, so recovery is never opt-in and a
long-lived writer can never proceed while another writer's crash left a durably-published segment
unregistered.

Per ADR 0004 and plan section 4.7 a commit is a deliberate, authorized, reconciled operation: it
authorizes the ``local_spool`` and ``local_sqlite`` egress surfaces (restricted input is rejected
before any mutation), derives the ``YYYY-MM-DD`` partition from the commit instant, then, holding
the exclusive commit barrier across reconciliation and publication, creates the partition
directory, atomically publishes the exact segment bytes (write, flush, fsync, no-replace rename,
parent fsync), and inserts the segment ledger row (``origin = 'committed'``) plus one row per
required exporter in a single SQLite transaction. A
crash or ledger failure after publication leaves a durable orphan and is reported as the fixed
commit-uncertain ``MH_SPOOL_COMMIT``, never as success. The ledger preserves every immutable header
field so recovery never infers policy from newer configuration, and every read is validated so a
corrupt row fails closed with ``MH_SPOOL_LEDGER``. Every failure raises a fixed ``MH_SPOOL_*`` error
outside the handler.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from milhouse.config.filesystem import lexical_absolute_path
from milhouse.core.clock import TimeError, format_timestamp
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.ledger import (
    ORIGIN_COMMITTED,
    ExporterDelivery,
    SegmentRecord,
    authorize_local_persistence,
    insert_segment_row,
    list_segment_records,
    read_segment_record,
)
from milhouse.spooling.reader import INSTALLATION_ID_PATTERN
from milhouse.spooling.segment import (
    FRAME_VERSION,
    SCHEMA_VERSION,
    SegmentHeaderV1,
    SpoolFrameV1,
)
from milhouse.spooling.writer import build_segment_bytes, publish_segment_bytes
from milhouse.state.barrier import GlobalCommitBarrier
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

if TYPE_CHECKING:
    from milhouse.spooling.reconcile import ReconciliationReport

_SPOOL = "spool"
_BARRIER_NAME = "commit.lock"
_PENDING = "pending"
_DIR_MODE = 0o700
_DELIVERY_PENDING = "pending"
_DAY_LENGTH = 10


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


def _current_uid() -> int:
    # Match the W02 secure-file writer (filesystem.py), which validates against the effective uid.
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # pragma: no cover - Milhouse supports only POSIX hosts
        _fail("MH_SPOOL_UNSUPPORTED", "the spool requires a POSIX ownership model")
    return int(geteuid())


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


class DurableSpool:
    """A durable spool bound to one control database, barrier, spool root, and installation id."""

    __slots__ = ("_barrier", "_database", "_installation_id", "_last_reconciliation", "_spool_root")

    def __init__(
        self,
        *,
        database: ControlDatabase,
        barrier: GlobalCommitBarrier,
        spool_root: str | Path,
        installation_id: str,
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
        if (
            type(installation_id) is not str
            or INSTALLATION_ID_PATTERN.fullmatch(installation_id) is None
        ):
            _fail("MH_SPOOL_IDENTITY", "a well-formed installation id is required")
        self._database = database
        self._barrier = barrier
        self._spool_root = resolved_spool
        self._installation_id = installation_id
        # A writer acquisition performs mandatory recovery: reconcile the spool with the ledger
        # under the exclusive barrier before any commit is possible. This constructor pass is an
        # additional check; every commit ALSO reconciles inside its own exclusive critical section
        # with no unlock window, so a long-lived writer can never proceed past another writer's
        # later crash orphan (the gate review's reproduced handoff gap).
        self._last_reconciliation = self._reconcile_exclusively(action=None)

    @property
    def last_reconciliation(self) -> ReconciliationReport:
        """The report from this writer's most recent mandatory reconciliation pass."""

        return self._last_reconciliation

    def _reconcile_exclusively(self, action: Callable[[], None] | None) -> ReconciliationReport:
        """Hold the exclusive barrier across mandatory reconciliation and an optional commit action.

        There is deliberately no unlock window between reconciliation and the action: another
        writer's crash orphan can never appear between recovery and this writer's publication.
        """

        # Imported here to keep the reconcile module's dependency on the ledger one-directional.
        from milhouse.spooling.reconcile import run_reconciliation_scan

        report: ReconciliationReport | None = None
        barrier_failed = False
        try:
            with self._barrier.exclusive():
                report = run_reconciliation_scan(
                    database=self._database,
                    spool_root=self._spool_root,
                    installation_id=self._installation_id,
                )
                self._last_reconciliation = report
                if action is not None:
                    action()
        except StateError:
            # The scan and ledger paths remap their own StateErrors; this only catches a
            # barrier-acquisition failure so the writer API never surfaces a non-MH_SPOOL_* error.
            barrier_failed = True
        if barrier_failed or report is None:
            _fail("MH_SPOOL_BARRIER", "the commit barrier could not be acquired")
        return report

    def commit_segment(
        self,
        header: SegmentHeaderV1,
        frames: tuple[SpoolFrameV1, ...] | list[SpoolFrameV1],
        *,
        committed_at: datetime,
    ) -> SegmentRecord:
        """Reconcile, authorize, publish, and record one segment in one exclusive critical section.

        Mandatory recovery runs first, under the same exclusive barrier hold as the publication and
        ledger insert, so no other writer can create an orphan between reconciliation and this
        commit and this writer cannot proceed while an earlier durable segment is unregistered.
        """

        if not isinstance(header, SegmentHeaderV1):
            _fail("MH_SPOOL_HEADER", "a segment header is required")
        authorize_local_persistence(header.privacy_class)
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
            origin=ORIGIN_COMMITTED,
            exporters=tuple(
                ExporterDelivery(exporter_id=exporter, delivery_status=_DELIVERY_PENDING)
                for exporter in header.required_exporters
            ),
        )

        def _publish_and_record() -> None:
            day_dir = _pending_day_dir(self._spool_root, day)
            publish_segment_bytes(day_dir / f"{header.batch_id}.jsonl", content)
            self._commit_ledger(record)

        self._reconcile_exclusively(action=_publish_and_record)
        return record

    def _commit_ledger(self, record: SegmentRecord) -> None:
        failed = False
        try:
            with self._database.transaction() as connection:
                insert_segment_row(connection, record)
        except (sqlite3.Error, StateError):
            # The file is durably published; any ledger or transaction-boundary failure leaves a
            # registrable orphan and is reported as commit-uncertain, never as success.
            failed = True
        if failed:
            _fail("MH_SPOOL_COMMIT", "the segment ledger could not be committed")

    def read_segment(self, batch_id: str) -> SegmentRecord | None:
        """Return the committed segment ledger record for ``batch_id``, or None. Read-only."""

        return read_segment_record(self._database, batch_id)

    def list_segments(self, *, delivery_status: str | None = None) -> tuple[SegmentRecord, ...]:
        """Return committed segments, optionally only those with an exporter in the given status."""

        return list_segment_records(self._database, delivery_status=delivery_status)
