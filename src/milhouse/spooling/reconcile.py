"""Spool reconciliation scan: reconcile the pending spool with the SQLite ledger (W03 slice 3c).

Per ADR 0004 and plan sections 3.4/4.3, startup and every writer acquisition reconcile the durable
spool with the control ledger before proceeding; :class:`milhouse.spooling.commit.DurableSpool` runs
this scan on acquisition, and :class:`SpoolReconciler` exposes it for an explicit startup pass. A
durable commit publishes the segment file and then records its ledger row (slice 3a); a crash
between those steps leaves a durably-published but unrecorded *orphan*. Holding the exclusive commit
barrier, the scan inventories ``<spool_root>/pending`` with secure, bounded, descriptor-relative
enumeration and then, comparing against the fully validated ``_segments`` ledger:

* registers each valid, unambiguous orphan (a trusted, provenance- and egress-authorized segment
  file with no ledger row and no conflicting duplicate) into the ledger, reconstructing only from
  the durable header, with a reconstructed day-start ``committed_at`` and ``origin = 'reconciled'``;
* certifies a present committed file healthy only when it agrees with its ledger row on every
  immutable field, both digests, byte size, and the exact required-exporter identity set;
* reports every ledger row whose file is missing, every malformed ledger row, every file that
  disagrees with its row, every batch id that appears at more than one path (registering none of
  them), and every foreign entry — carrying only validated identifiers and fixed reasons; an
  invalid name is omitted entirely, so no raw or derived untrusted name reaches a report surface.

The scan never deletes, quarantines, or moves a file; it registers valid orphans and returns a
:class:`ReconciliationReport`. Every failure is a fixed ``MH_SPOOL_*`` error raised outside any
handler.
"""

from __future__ import annotations

import errno
import os
import re
import sqlite3
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from milhouse.config.filesystem import FileIdentity, lexical_absolute_path
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.ledger import (
    ORIGIN_RECONCILED,
    SEGMENT_COLUMNS,
    ExporterDelivery,
    SegmentRecord,
    authorize_local_persistence,
    insert_segment_row,
    load_exporters,
    validated_segment,
)
from milhouse.spooling.reader import (
    INSTALLATION_ID_PATTERN,
    ParsedSegment,
    read_trusted_segment,
)
from milhouse.spooling.segment import (
    BATCH_ID_PATTERN,
    FRAME_VERSION,
    SCHEMA_VERSION,
)
from milhouse.state.barrier import GlobalCommitBarrier
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_SPOOL = "spool"
_PENDING = "pending"
_BARRIER_NAME = "commit.lock"
_SEGMENT_SUFFIX = ".jsonl"
_DIR_MODE = 0o700
_DELIVERY_PENDING = "pending"
# Reconciliation runs under the exclusive barrier, so every bound below caps how long a hostile or
# corrupt spool can hold it. Exceeding one reports a fixed limit anomaly and stops the scan.
_MAX_DAYS = 100_000
_MAX_ENTRIES = 1_000_000
_MAX_TOTAL = 1_000_000
_MAX_ANOMALIES = 100_000
# A strict ASCII partition-day shape. `datetime.strptime(day, "%Y-%m-%d")` alone is not enough: its
# `%d`/`%m` accept space-padded fields (e.g. "2026-07- 5"), which would then produce a committed_at
# the schema's length-only CHECK admits but the ledger reader's stricter stamp regex rejects — a
# poison row that fails-closes every later ledger read. The regex closes that gap; strptime still
# checks the calendar (rejecting, e.g., 2026-13-45).
_DAY_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", flags=re.ASCII)


@dataclass(frozen=True, slots=True)
class OrphanRegistration:
    """A valid orphan segment file that reconciliation registered into the ledger."""

    batch_id: str
    day: str


@dataclass(frozen=True, slots=True)
class SegmentAnomaly:
    """A spool/ledger disagreement that reconciliation surfaced but did not resolve.

    ``kind`` is one of ``missing_file`` (a ledger row with no file), ``corrupt_ledger`` (a malformed
    ledger row), ``corrupt_file`` (a committed file that fails trusted validation or disagrees with
    its row), ``corrupt_orphan`` (an unrecorded file that fails trusted validation or egress),
    ``conflict`` (a batch id at more than one path), ``foreign_name`` (an entry whose name is not a
    well-formed ``<batch-id>.jsonl`` under a valid day), or ``limit`` (a scan bound was exceeded).
    ``batch_id`` and ``day`` are validated identifiers or empty when the underlying name was
    invalid (untrusted names are omitted entirely, never echoed or fingerprinted); ``detail`` is a
    fixed reason or ``MH_SPOOL_*`` code — never a raw path.
    """

    batch_id: str
    day: str
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """The outcome of one reconciliation scan.

    ``complete`` is False when any enumeration bound or unreadable/unsafe directory truncated the
    inventory. An incomplete scan is certification- and mutation-free: it registers nothing,
    certifies nothing healthy, and asserts no missing files, because a truncated inventory cannot
    prove global batch uniqueness or absence.
    """

    registered: tuple[OrphanRegistration, ...]
    anomalies: tuple[SegmentAnomaly, ...]
    healthy: int
    scanned: int
    complete: bool


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


def _current_uid() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # pragma: no cover - Milhouse supports only POSIX hosts
        _fail("MH_SPOOL_UNSUPPORTED", "the spool requires a POSIX ownership model")
    return int(geteuid())


def _safe_id(batch_id: str) -> str:
    """Keep a well-formed batch id readable in the report; OMIT anything else entirely.

    An invalid name is untrusted input. The re-review showed a truncated bare SHA-256 is
    dictionary-recoverable for low-entropy names, and no keyed pseudonymization primitive is wired
    into the spool subsystem yet, so no derivative of an invalid name reaches any report surface:
    the field is empty and only the fixed reason identifies the anomaly class. Quarantine (a later
    slice) handles the file itself.
    """

    return batch_id if BATCH_ID_PATTERN.fullmatch(batch_id) is not None else ""


def _is_valid_day(day: str) -> bool:
    if _DAY_PATTERN.fullmatch(day) is None:
        return False
    valid = True
    try:
        datetime.strptime(day, "%Y-%m-%d")  # a bare partition date, not an instant
    except ValueError:
        valid = False
    return valid


def _secure_dir_names(
    path: Path,
) -> tuple[tuple[str, ...] | None, FileIdentity | None, str | None]:
    """List a directory over an owned 0700 no-follow descriptor, capping entries before collecting.

    Returns ``(names, identity, None)`` on success (``((), None, None)`` if absent), where
    ``identity`` is the opened directory's device/inode so a later per-file read can prove it still
    operates beneath the exact inventoried directory; or ``(None, None, reason)`` where reason is
    ``unsafe`` (symlink, non-directory, wrong owner, or mode) or ``unreadable``.
    """

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return (), None, None
    except OSError as exc:
        return None, None, "unsafe" if exc.errno in {errno.ELOOP, errno.ENOTDIR} else "unreadable"
    problem: str | None = None
    names: tuple[str, ...] | None = None
    identity: FileIdentity | None = None
    try:
        info = os.fstat(descriptor)
        identity = FileIdentity.from_stat(info)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _current_uid()
            or stat.S_IMODE(info.st_mode) != _DIR_MODE
        ):
            problem = "unsafe"
        else:
            collected: list[str] = []
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if len(collected) >= _MAX_ENTRIES:
                        problem = "too_many"
                        break
                    collected.append(entry.name)
            if problem is None:
                names = tuple(sorted(collected))
    except OSError:  # pragma: no cover - defensive: fstat/scandir failure after a successful open
        problem = "unreadable"
    finally:
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive: close failure on a valid descriptor
            problem = problem or "unreadable"
    if problem is not None:
        return None, None, problem
    return names, identity, None


def _run_reconciliation_scan(
    *, database: ControlDatabase, spool_root: str | Path, installation_id: str
) -> ReconciliationReport:
    """Run the raw mutating scan. INTERNAL: only barrier-owning entrypoints may call this.

    This function is deliberately not exported: it mutates the ledger and cannot itself verify the
    exclusive barrier, so the only supported reconciliation entrypoints are
    :class:`milhouse.spooling.commit.DurableSpool` (construction and every commit) and
    :meth:`SpoolReconciler.reconcile`, each of which acquires the exclusive barrier around it.
    """

    return _Scan(database, lexical_absolute_path(spool_root), installation_id).run()


class _Scan:
    __slots__ = (
        "_anomalies",
        "_complete",
        "_database",
        "_healthy",
        "_installation_id",
        "_pending_registrations",
        "_registered",
        "_scanned",
        "_spool_root",
        "_stopped",
    )

    def __init__(self, database: ControlDatabase, spool_root: Path, installation_id: str) -> None:
        self._database = database
        self._spool_root = spool_root
        self._installation_id = installation_id
        self._registered: list[OrphanRegistration] = []
        self._pending_registrations: list[tuple[ParsedSegment, str, str]] = []
        self._anomalies: list[SegmentAnomaly] = []
        self._healthy = 0
        self._scanned = 0
        self._stopped = False
        self._complete = True

    def run(self) -> ReconciliationReport:
        ledger, malformed = self._ledger_index()
        for batch_id in sorted(malformed):
            # the batch id came from a row that failed validation, so it may not be well formed
            self._anomaly(_safe_id(batch_id), "", "corrupt_ledger", "unreadable_row")

        candidates = self._inventory()
        counts = Counter(batch_id for _day, batch_id, _path, _identity in candidates)
        seen: set[str] = set()
        if self._complete:
            for day, batch_id, path, day_identity in candidates:
                if self._stopped:
                    # the anomaly cap fired mid-verification: the rest of the pass is unproven
                    self._complete = False
                    break
                seen.add(batch_id)
                if counts[batch_id] > 1:
                    self._anomaly(batch_id, day, "conflict", "duplicate_batch_id")
                elif batch_id in malformed:
                    continue  # the malformed-row anomaly already covers this batch
                elif batch_id in ledger:
                    self._verify_committed(path, day, batch_id, ledger[batch_id], day_identity)
                else:
                    self._reconcile_orphan(path, day, batch_id, day_identity)

        if self._complete:
            # Mutation happens only after a complete, within-bounds inventory proved every candidate
            # batch id globally unique, so a bound can never truncate authority onto a partial view.
            for parsed, batch_id, day in self._pending_registrations:
                self._register(parsed, batch_id, day)
                self._registered.append(OrphanRegistration(batch_id, day))
            for batch_id, record in ledger.items():
                if batch_id not in seen:
                    self._anomaly(batch_id, record.day, "missing_file", "absent")

        return ReconciliationReport(
            registered=tuple(self._registered),
            anomalies=tuple(self._anomalies),
            healthy=self._healthy if self._complete else 0,
            scanned=self._scanned,
            complete=self._complete,
        )

    def _anomaly(self, batch_id: str, day: str, kind: str, detail: str) -> None:
        if len(self._anomalies) < _MAX_ANOMALIES:
            self._anomalies.append(SegmentAnomaly(batch_id, day, kind, detail))
        elif not self._stopped:
            self._stopped = True
            self._anomalies.append(SegmentAnomaly("", "", "limit", "anomaly_limit"))

    def _ledger_index(self) -> tuple[dict[str, SegmentRecord], set[str]]:
        ledger: dict[str, SegmentRecord] = {}
        malformed: set[str] = set()
        failed = False
        try:
            connection = self._database.connection
            rows = connection.execute(
                f"SELECT {', '.join(SEGMENT_COLUMNS)} FROM _segments"
            ).fetchall()
            for row in rows:
                batch_id = str(row[0])
                try:
                    ledger[batch_id] = validated_segment(row, load_exporters(connection, batch_id))
                except (ValueError, TypeError):
                    malformed.add(batch_id)
        except (sqlite3.Error, StateError):
            failed = True
        if failed:
            _fail("MH_SPOOL_LEDGER", "the segment ledger could not be read")
        return ledger, malformed

    def _inventory(self) -> list[tuple[str, str, Path, FileIdentity]]:
        pending = self._spool_root / _PENDING
        day_names, _pending_identity, problem = _secure_dir_names(pending)
        if problem is not None:
            # an unlistable pending directory means the inventory cannot be proven complete
            self._anomaly("", "", "foreign_name", f"pending_{problem}")
            self._complete = False
            return []
        assert day_names is not None
        if len(day_names) > _MAX_DAYS:
            self._anomaly("", "", "limit", "day_limit")
            self._complete = False
            return []
        candidates: list[tuple[str, str, Path, FileIdentity]] = []
        for day in day_names:
            if not _is_valid_day(day):
                self._anomaly("", "", "foreign_name", "day")
                continue
            entries, day_identity, entry_problem = _secure_dir_names(pending / day)
            if entry_problem is not None:
                # an unlistable or truncated day leaves possible batches (and duplicates) unseen
                self._anomaly("", day, "foreign_name", f"day_{entry_problem}")
                self._complete = False
                continue
            assert entries is not None and day_identity is not None
            for name in entries:
                if self._scanned >= _MAX_TOTAL:
                    self._anomaly("", "", "limit", "scan_limit")
                    self._complete = False
                    return candidates
                self._scanned += 1
                resolved = self._classify_name(pending / day / name, day, name)
                if resolved is not None:
                    candidates.append((*resolved, day_identity))
        if self._stopped:
            self._complete = False  # the anomaly cap fired during inventory
        return candidates

    def _classify_name(self, path: Path, day: str, name: str) -> tuple[str, str, Path] | None:
        if not name.endswith(_SEGMENT_SUFFIX):
            self._anomaly("", day, "foreign_name", "suffix")
            return None
        batch_id = name[: -len(_SEGMENT_SUFFIX)]
        if BATCH_ID_PATTERN.fullmatch(batch_id) is None:
            self._anomaly("", day, "foreign_name", "batch_id")
            return None
        return day, batch_id, path

    def _verify_committed(
        self,
        path: Path,
        day: str,
        batch_id: str,
        record: SegmentRecord,
        day_identity: FileIdentity,
    ) -> None:
        parsed, code = self._trusted_read(path, day_identity)
        if code is not None:
            self._anomaly(batch_id, day, "corrupt_file", code)
        elif not _agrees(parsed, day, batch_id, record):
            self._anomaly(batch_id, day, "corrupt_file", "ledger_mismatch")
        else:
            self._healthy += 1

    def _reconcile_orphan(
        self, path: Path, day: str, batch_id: str, day_identity: FileIdentity
    ) -> None:
        parsed, code = self._trusted_read(path, day_identity)
        if code is not None:
            self._anomaly(batch_id, day, "corrupt_orphan", code)
            return
        assert parsed is not None
        if parsed.header.batch_id != batch_id:
            self._anomaly(batch_id, day, "foreign_name", "header_batch_id")
            return
        try:
            authorize_local_persistence(parsed.header.privacy_class)
        except SpoolError as denied:
            self._anomaly(batch_id, day, "corrupt_orphan", denied.code)
            return
        # registration is deferred: mutation begins only after the whole pass proves complete
        self._pending_registrations.append((parsed, batch_id, day))

    def _trusted_read(
        self, path: Path, day_identity: FileIdentity
    ) -> tuple[ParsedSegment | None, str | None]:
        parsed: ParsedSegment | None = None
        code: str | None = None
        try:
            parsed = read_trusted_segment(
                path,
                installation_id=self._installation_id,
                expected_parent=day_identity,
            )
        except SpoolError as error:
            code = error.code
        return parsed, code

    def _register(self, parsed: ParsedSegment, batch_id: str, day: str) -> None:
        if (
            _DAY_PATTERN.fullmatch(day) is None
        ):  # pragma: no cover - inventory filters to valid days
            _fail("MH_SPOOL_RECONCILE", "a reconciled orphan requires a canonical partition day")
        header = parsed.header
        record = SegmentRecord(
            batch_id=batch_id,
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
            byte_size=parsed.byte_size,
            file_sha256=parsed.file_sha256,
            committed_at=f"{day}T00:00:00.000Z",  # a reconstructed day-start; the instant is lost
            origin=ORIGIN_RECONCILED,
            exporters=tuple(
                ExporterDelivery(exporter_id=exporter, delivery_status=_DELIVERY_PENDING)
                for exporter in header.required_exporters
            ),
        )
        failed = False
        try:
            with self._database.transaction() as connection:
                insert_segment_row(connection, record)
        except (sqlite3.Error, StateError):
            failed = True
        if failed:
            _fail("MH_SPOOL_RECONCILE", "a reconciled orphan could not be registered")


def _agrees(parsed: ParsedSegment | None, day: str, batch_id: str, record: SegmentRecord) -> bool:
    # Compare every *file-attestable* immutable field. The exact sub-day commit instant and the
    # origin marker are not carried by the durable file (only the partition day is, and it is
    # checked), so they are not compared here; a within-day committed_at or origin edit is a
    # control-plane (SQLite-write) concern, not a spool/ledger disagreement this scan can attest.
    if parsed is None:  # pragma: no cover - callers pass a parsed segment
        return False
    header = parsed.header
    return (
        header.batch_id == batch_id == record.batch_id
        and day == record.day
        and record.schema_version == SCHEMA_VERSION
        and record.frame_version == FRAME_VERSION
        and header.config_generation == record.config_generation
        and header.scope == record.scope
        and header.target_id == record.target_id
        and header.privacy_class == record.privacy_class
        and header.retention_days == record.retention_days
        and header.record_count == record.record_count
        and header.content_sha256 == record.content_sha256
        and parsed.byte_size == record.byte_size
        and parsed.file_sha256 == record.file_sha256
        and set(header.required_exporters) == {e.exporter_id for e in record.exporters}
    )


class SpoolReconciler:
    """Reconcile the pending spool with the control ledger under the exclusive commit barrier."""

    __slots__ = ("_barrier", "_database", "_installation_id", "_spool_root")

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

    def reconcile(self) -> ReconciliationReport:
        """Scan pending against the ledger under the exclusive barrier; register valid orphans."""

        report: ReconciliationReport | None = None
        barrier_failed = False
        try:
            with self._barrier.exclusive():
                report = _run_reconciliation_scan(
                    database=self._database,
                    spool_root=self._spool_root,
                    installation_id=self._installation_id,
                )
        except StateError:
            barrier_failed = True
        if barrier_failed or report is None:
            _fail("MH_SPOOL_BARRIER", "the commit barrier could not be acquired")
        return report
