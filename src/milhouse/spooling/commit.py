"""Durable spool commit, bound to one control plane with mandatory recovery (W03 slices 3a/3c).

A :class:`DurableSpool` binds one control database, one commit barrier, one spool root, and the
installation identity, all under the same canonical state root, so a caller cannot publish under a
different barrier than maintenance holds. Per ADR 0004 and plan sections 3.4/4.3, mandatory
spool/ledger reconciliation runs on writer acquisition AND at the start of every commit. A commit
holds the barrier exclusively for recovery, converts the same main lock to shared while the
exclusive gate prevents a cooperating-writer gap, then publishes under the required shared writer
side. Recovery is never opt-in, and a long-lived writer cannot proceed past another writer's crash
orphan.

Per ADR 0004 and plan section 4.7 a commit is a deliberate, authorized, reconciled operation: it
authorizes the ``local_spool`` and ``local_sqlite`` egress surfaces (restricted input is rejected
before any mutation), derives the ``YYYY-MM-DD`` partition from the commit instant, then creates and
durably links the private partition directories, atomically publishes the exact segment bytes
(write, flush, fsync, no-replace rename, parent fsync), and inserts the segment ledger row
(``origin = 'committed'``) plus one row per required exporter in a single SQLite transaction. The
publication and ledger insert run under the shared commit barrier. A
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

from milhouse.config.filesystem import (
    FileIdentity,
    SecureFileError,
    lexical_absolute_path,
    require_no_extended_acl,
)
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
    is_reserved_compaction_batch_id,
)
from milhouse.spooling.writer import build_segment_bytes, publish_segment_bytes
from milhouse.state.barrier import GlobalCommitBarrier, _is_bound_barrier
from milhouse.state.database import ControlDatabase, _validated_database_path
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
    """Require an owned, exact-0700, ACL-free directory, validated on an opened descriptor.

    The descriptor-based check closes the gap the earlier lstat version left: mode bits alone do
    not prove the access envelope, so the same extended-ACL probe the secure file primitives use
    runs against the opened directory itself.
    """

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    unsafe = False
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _current_uid()
            or stat.S_IMODE(info.st_mode) != _DIR_MODE
        ):
            unsafe = True
        else:
            require_no_extended_acl(descriptor)
    except (OSError, SecureFileError):
        unsafe = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive: close failure on a valid descriptor
                unsafe = True
    if unsafe:
        _fail("MH_SPOOL_DIR", f"the {subject} must be an owned, ACL-free 0o700 directory")


def _fsync_private_dir(path: Path, subject: str) -> None:
    """Re-open, validate, and fsync one private directory without leaking path details."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    failed = False
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _current_uid()
            or stat.S_IMODE(info.st_mode) != _DIR_MODE
        ):
            failed = True
        else:
            require_no_extended_acl(descriptor)
            os.fsync(descriptor)
    except (OSError, SecureFileError):
        failed = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                failed = True
    if failed:
        _fail("MH_SPOOL_DIR", f"the {subject} could not be made durable")


def _secure_child_dir(parent: Path, name: str) -> Path:
    """Create/repair one private child through the shared descriptor-relative primitive."""

    # Reconciliation owns the shared spool-directory primitive. Import lazily to preserve the
    # commit -> reconciliation dependency direction used by writer acquisition.
    from milhouse.spooling.reconcile import (
        _dir_flags,
        _ensure_private_dir_at,
        _validated_dir_descriptor,
    )

    child = parent / name
    parent_fd: int | None = None
    child_fd: int | None = None
    accepted = False
    try:
        parent_fd = os.open(parent, _dir_flags())
        parent_identity = _validated_dir_descriptor(parent_fd)
        if parent_identity is not None:
            child_pair = _ensure_private_dir_at(parent_fd, name, sync_child=True)
            if child_pair is not None:
                child_fd, child_identity = child_pair
                named_parent = FileIdentity.from_stat(os.stat(parent, follow_symlinks=False))
                named_child = FileIdentity.from_stat(
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                )
                accepted = (
                    named_parent == parent_identity
                    and _validated_dir_descriptor(parent_fd) == parent_identity
                    and named_child == child_identity
                    and _validated_dir_descriptor(child_fd) == child_identity
                )
    except (OSError, ValueError):
        accepted = False
    finally:
        for descriptor in (child_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:  # pragma: no cover - defensive close failure
                    accepted = False
    if not accepted:
        _fail("MH_SPOOL_DIR", "a spool directory could not be created")
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
        database_path = _validated_database_path(database)
        if database_path is None:
            _fail("MH_SPOOL_STORE", "a control database is required")
        if type(barrier) is not GlobalCommitBarrier:
            _fail("MH_SPOOL_STORE", "a commit barrier is required")
        control_dir = database_path.parent
        state_root = control_dir.parent
        invalid_spool = False
        try:
            resolved_spool = lexical_absolute_path(spool_root)
        except SecureFileError:
            invalid_spool = True
            resolved_spool = Path()
        if invalid_spool:
            _fail("MH_SPOOL_STORE", "a spool root path is required")
        if not _is_bound_barrier(barrier, control_dir / _BARRIER_NAME):
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
        # additional check; every commit ALSO reconciles exclusively, then hands the same main
        # descriptor to shared mode without a cooperating-writer gap before publication.
        self._last_reconciliation = self._reconcile_then_write(action=None)

    @property
    def last_reconciliation(self) -> ReconciliationReport:
        """The report from this writer's most recent mandatory reconciliation pass."""

        return self._last_reconciliation

    def _reconcile_then_write(self, action: Callable[[], None] | None) -> ReconciliationReport:
        """Run exclusive recovery, then an optional action under the shared writer side.

        The barrier owns the exclusive-to-shared transition on one main descriptor while its gate
        excludes cooperating entrants. There is no unlock window and no caller-mintable authority
        token that can bypass acquisition.
        """

        # Imported here to keep the reconcile module's dependency on the ledger one-directional.
        from milhouse.spooling.reconcile import _reconcile_under_barrier

        def _observe(report: ReconciliationReport) -> None:
            self._last_reconciliation = report

        report = _reconcile_under_barrier(
            database=self._database,
            barrier=self._barrier,
            spool_root=self._spool_root,
            installation_id=self._installation_id,
            action=action,
            observe=_observe,
        )
        if not report.complete:
            if any(
                anomaly.kind == "foreign_name"
                and anomaly.detail in {"spool_root_unsafe", "spool_root_changed"}
                for anomaly in report.anomalies
            ):
                _fail("MH_SPOOL_DIR", "the spool root must be an owned, ACL-free 0o700 directory")
            # A truncated inventory cannot prove orphan absence or batch uniqueness, so mandatory
            # recovery fails closed: neither acquisition nor a commit may proceed on a partial view.
            _fail("MH_SPOOL_INCOMPLETE", "reconciliation was truncated by a scan bound")
        if not report.recovery_safe:
            # Inventory was complete, but an exact prior-recovery cleanup could not be verified.
            # No later recovery or writer mutation ran, and this is not a scan-bound failure.
            _fail("MH_SPOOL_RECOVERY", "reconciliation recovery could not be verified")
        return report

    def commit_segment(
        self,
        header: SegmentHeaderV1,
        frames: tuple[SpoolFrameV1, ...] | list[SpoolFrameV1],
        *,
        committed_at: datetime,
    ) -> SegmentRecord:
        """Reconcile exclusively, then publish and record under the shared writer barrier.

        Mandatory recovery runs first. The main lock then converts to shared before publication,
        while the gate prevents another cooperating writer from creating an orphan in between.
        """

        if not isinstance(header, SegmentHeaderV1):
            _fail("MH_SPOOL_HEADER", "a segment header is required")
        if is_reserved_compaction_batch_id(header.batch_id):
            # The compaction successor namespace (``c`` + 64-hex) is reserved: a producer must never
            # commit into it, so a caller-chosen segment can never occupy a compaction-derived
            # successor id and strand a mixed-expiry segment's expired frames (plan §§4.8-4.9; G03
            # review finding #1). Compaction inserts its own rows directly, bypassing this ingress.
            _fail("MH_SPOOL_RESERVED_ID", "the compaction successor batch-id namespace is reserved")
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

        self._reconcile_then_write(action=_publish_and_record)
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
