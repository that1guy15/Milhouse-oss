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

On a complete pass the scan also QUARANTINES, per plan section 3.4/4.3: corrupt committed and
orphan files, every copy of a conflicted batch id (``conflict_divergent`` when contents differ — the
plan's high-severity conflict — or ``conflict_duplicate`` when byte-identical, so directory order
never chooses a durable history), and crashed writers' staged temporaries all move to
``quarantine/<day>/`` under the same exclusive hold. Every quarantine subject is classified
descriptor-relative with no-follow semantics and its exact leaf inode captured; only an owned,
exact-0600, single-link, ACL-free regular file is ever queued or linked, so a staged symlink,
directory, FIFO, device, or foreign shape can never import outside content. The move re-verifies
the captured identity beneath the inventoried day descriptor, links without following symlinks,
makes the target name durable BEFORE touching the source, verifies target-inode equality (rolling
back on mismatch), and revalidates the source name immediately before its unlink — distinguishing
pre-move blocked, completed, and commit-uncertain outcomes. Foreign-named entries are reported but
left in place (they have no well-formed quarantine name). The scan never deletes; an incomplete
pass moves nothing. Every failure is a fixed ``MH_SPOOL_*`` error raised outside any handler.
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import sqlite3
import stat
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from milhouse.config.filesystem import (
    FileIdentity,
    SecureFileError,
    lexical_absolute_path,
    require_no_extended_acl,
)
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
    MAX_SEGMENT_FILE_BYTES,
    ParsedSegment,
    read_trusted_segment,
)
from milhouse.spooling.segment import (
    BATCH_ID_PATTERN,
    FRAME_VERSION,
    SCHEMA_VERSION,
)
from milhouse.state.barrier import ExclusiveHold, GlobalCommitBarrier
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_SPOOL = "spool"
_PENDING = "pending"
_QUARANTINE = "quarantine"
_STAGE_PREFIX = ".milhouse-stage-"
# Codes whose subject cannot be moved: the directory changed since inventory (the classified
# object is not the present one), the file vanished, or it is not a regular file (hard-linking
# a symlink or directory is unsafe). These stay report-only.
_UNQUARANTINABLE = frozenset({"MH_SPOOL_CHANGED", "MH_SPOOL_NOT_FOUND", "MH_SPOOL_NOT_REGULAR"})
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
# Bounded quarantine-name attempts: `<name>`, `1.<name>`, ... — shared by the move and the
# interrupted-move twin probe so both agree on which aliases can exist.
_MAX_MOVE_ATTEMPTS = 100
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
    well-formed ``<batch-id>.jsonl`` under a valid day), ``stale_temp`` (a crashed writer's staged
    temporary), ``quarantine_blocked`` (a quarantine subject could not be safely moved: the file
    stays in pending and is re-reported every scan — reasons ``unsafe`` (the subject is not an
    owned, exact-0600, single-link, ACL-free regular file: a staged symlink, directory, FIFO,
    device, or multi-link file is never queued, followed, or linked), ``unreachable``,
    ``changed``, ``collision``, ``io``), ``quarantine_uncertain`` (the quarantine target is
    durably named but the source state could not be confirmed; the next scan converges by
    adopting the same-inode twin), or ``limit`` (a scan bound was exceeded).
    ``batch_id`` and ``day`` are validated identifiers or empty when the underlying name was
    invalid (untrusted names are omitted entirely, never echoed or fingerprinted); ``detail`` is a
    fixed reason or ``MH_SPOOL_*`` code — never a raw path.
    """

    batch_id: str
    day: str
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class QuarantinedFile:
    """One file reconciliation moved to ``quarantine/<day>/`` with its fixed reason.

    ``batch_id`` is a validated identifier or empty (stale staged temporaries have no batch).
    ``detail`` is the fixed reason: an ``MH_SPOOL_*`` code for a corrupt file,
    ``conflict_divergent`` (duplicate batch ids with differing content — the plan's high-severity
    conflict), ``conflict_duplicate`` (byte-identical duplicates, quarantined without choosing a
    path), or ``stale_temp`` (a crashed writer's staged temporary).
    """

    batch_id: str
    day: str
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
    quarantined: tuple[QuarantinedFile, ...]
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


def _raw_sha256(path: Path) -> str | None:
    """Hash a file's raw bytes without parsing: no-follow, regular-only, size-bounded.

    Returns ``None`` on any failure (missing, non-regular, oversized, unreadable) so a conflicted
    copy that cannot be read classifies fail-safe as divergent.
    """

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    digest = hashlib.sha256()
    descriptor: int | None = None
    failed = False
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SEGMENT_FILE_BYTES:
            failed = True
        else:
            total = 0
            while True:
                chunk = os.read(descriptor, 1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SEGMENT_FILE_BYTES:
                    failed = True
                    break
                digest.update(chunk)
    except OSError:
        failed = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                failed = True
    return None if failed else digest.hexdigest()


def _dir_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)


def _fsync_dir(path: Path) -> bool:
    descriptor: int | None = None
    synced = False
    try:
        descriptor = os.open(path, _dir_flags())
        os.fsync(descriptor)
        synced = True
    except OSError:
        synced = False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                synced = False
    return synced


def _ensure_private_dir(path: Path) -> bool:
    """Create-if-absent and validate one owned, exact-0700, ACL-free quarantine directory.

    A freshly created directory entry is made durable by fsyncing its parent, so a crash after a
    quarantine move cannot lose the directory that names the moved file.
    """

    unsafe = False
    created = False
    descriptor: int | None = None
    try:
        os.mkdir(path, _DIR_MODE)
        created = True
    except FileExistsError:
        pass
    except OSError:
        unsafe = True
    if not unsafe and created and not _fsync_dir(path.parent):
        unsafe = True
    try:
        if not unsafe:
            descriptor = os.open(path, _dir_flags())
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
            except OSError:  # pragma: no cover - defensive close failure
                unsafe = True
    return not unsafe


def _leaf_probe_flags() -> int:
    """No-follow, non-blocking flags for opening a quarantine subject to inspect or move it.

    ``O_NOFOLLOW`` refuses a symlink outright; ``O_NONBLOCK`` keeps the probe from hanging on a
    hostile FIFO (a plain ``O_RDONLY`` open of a FIFO blocks until a writer appears) and from
    triggering device side effects. Neither affects reads of a regular file.
    """

    return (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _permitted_quarantine_shape(info: os.stat_result) -> bool:
    """Whether a quarantine subject is an owned, exact-0600, single-link REGULAR file.

    Nothing else may be hard-linked into quarantine: a directory, FIFO, character or block device,
    socket, foreign owner, loose or tightened mode, or multi-link file stays in pending with a
    fixed anomaly instead.
    """

    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == _current_uid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1
    )


def _interrupted_move_shape(info: os.stat_result) -> bool:
    """The one extra admissible shape: exactly two links, otherwise the permitted shape.

    A crash or failure after the quarantine link but before the pending unlink leaves the same
    inode under both names, so the pending twin of an interrupted move has ``st_nlink == 2``. It
    is admitted ONLY when :meth:`_Scan._has_quarantine_twin` proves the second name is our own
    durable quarantine entry; any other multi-link file stays refused.
    """

    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == _current_uid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 2
    )


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
        acl_unsafe = False
        try:
            require_no_extended_acl(descriptor)
        except SecureFileError:
            acl_unsafe = True
        if (
            acl_unsafe
            or not stat.S_ISDIR(info.st_mode)
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


def _require_bound_state_root(
    database: object, barrier: object, spool_root: str | Path, installation_id: str
) -> Path:
    """Require database, barrier, and spool root to share one canonical state root.

    A barrier from a different state root is not authority for this database/spool pair, so the
    binding is validated here (the wrapper) as well as at the public constructors, and the scan
    additionally re-validates the live token's own barrier identity against the database.
    """

    if not isinstance(barrier, GlobalCommitBarrier):
        _fail("MH_SPOOL_STORE", "a commit barrier is required")
    database_path = getattr(database, "path", None)
    if database_path is None:
        _fail("MH_SPOOL_STORE", "a control database is required")
    control_dir = lexical_absolute_path(database_path).parent
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
    return resolved_spool


def _reconcile_under_barrier(
    *,
    database: ControlDatabase,
    barrier: GlobalCommitBarrier,
    spool_root: str | Path,
    installation_id: str,
    action: Callable[[], None] | None = None,
    observe: Callable[[ReconciliationReport], None] | None = None,
) -> ReconciliationReport:
    """The only reconciliation entrypoint: acquires the exclusive barrier itself, then scans.

    There is no standalone callable that executes the scan without owning barrier authority: this
    wrapper first validates that database, barrier, and spool root share one canonical state root,
    then acquires the exclusive side and passes the live :class:`ExclusiveHold` token to
    :meth:`_Scan.run`, which re-validates the token's barrier identity against the database before
    its first ledger read — so even a direct internal call of the scan, or a live token issued by a
    different state root's barrier, fails closed before any mutation. ``action`` (the commit path's
    publish+ledger callback) runs inside the same hold when the scan is complete, preserving the
    no-gap reconcile-to-commit handoff; ``observe`` receives the report inside the hold before the
    action runs, so a caller records it even when the action then fails.
    """

    spool_root = _require_bound_state_root(database, barrier, spool_root, installation_id)
    report: ReconciliationReport | None = None
    barrier_failed = False
    try:
        with barrier.exclusive() as hold:
            report = _Scan(database, lexical_absolute_path(spool_root), installation_id).run(hold)
            if observe is not None:
                observe(report)
            if action is not None and report.complete:
                action()
    except StateError:
        # The scan and ledger paths remap their own StateErrors; this only catches a
        # barrier-acquisition failure so callers never surface a non-MH_SPOOL_* error.
        barrier_failed = True
    if barrier_failed or report is None:
        _fail("MH_SPOOL_BARRIER", "the commit barrier could not be acquired")
    return report


class _Scan:
    __slots__ = (
        "_anomalies",
        "_complete",
        "_database",
        "_healthy",
        "_installation_id",
        "_move_failures",
        "_pending_quarantines",
        "_pending_registrations",
        "_quarantined",
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
        # (day, name, day_identity, leaf_identity, batch_id_or_empty, detail): moved on success
        self._pending_quarantines: list[tuple[str, str, FileIdentity, FileIdentity, str, str]] = []
        self._quarantined: list[QuarantinedFile] = []
        self._move_failures: list[SegmentAnomaly] = []
        self._anomalies: list[SegmentAnomaly] = []
        self._healthy = 0
        self._scanned = 0
        self._stopped = False
        self._complete = True

    def run(self, authority: ExclusiveHold) -> ReconciliationReport:
        # Validated BEFORE the first ledger read: a direct call without a live exclusive hold of
        # THIS control plane's own commit lock fails closed with no mutation. A live token from any
        # other barrier is not authority for this database/spool pair — "some barrier is held" is
        # exactly the bypass the gate review reproduced. Underscore convention is not enforcement;
        # this identity comparison is.
        database_path = getattr(self._database, "path", None)
        expected_lock = (
            lexical_absolute_path(database_path).parent / _BARRIER_NAME
            if database_path is not None
            else None
        )
        if (
            not isinstance(authority, ExclusiveHold)
            or not authority.active
            or expected_lock is None
            or lexical_absolute_path(authority.barrier_path) != expected_lock
        ):
            _fail(
                "MH_SPOOL_BARRIER",
                "reconciliation requires a live exclusive hold of this control plane's barrier",
            )
        ledger, malformed = self._ledger_index()
        for batch_id in sorted(malformed):
            # the batch id came from a row that failed validation, so it may not be well formed
            self._anomaly(_safe_id(batch_id), "", "corrupt_ledger", "unreadable_row")

        candidates = self._inventory()
        counts = Counter(batch_id for _day, batch_id, _path, _identity in candidates)
        seen: set[str] = set()
        conflicted: dict[str, list[tuple[str, Path, FileIdentity]]] = {}
        if self._complete:
            for day, batch_id, path, day_identity in candidates:
                if self._capped():
                    break  # the anomaly cap fired: the rest of the pass is unproven
                seen.add(batch_id)
                if counts[batch_id] > 1:
                    self._anomaly(batch_id, day, "conflict", "duplicate_batch_id")
                    conflicted.setdefault(batch_id, []).append((day, path, day_identity))
                elif batch_id in malformed:
                    continue  # the malformed-row anomaly already covers this batch
                elif batch_id in ledger:
                    self._verify_committed(path, day, batch_id, ledger[batch_id], day_identity)
                else:
                    self._reconcile_orphan(path, day, batch_id, day_identity)

        # Conflict content comparison is classification (bounded raw reads, no parsing). Every
        # copy of a conflicted batch is staged for quarantine EXCEPT one that agrees with an
        # existing healthy ledger row: the ledger already unambiguously designates that copy, so
        # keeping it is not directory order choosing a history — and quarantining it would demote
        # an acknowledged committed segment to a dangling ledger row (the review's reproduction via
        # an ordinary same-batch retry). Differing contents mark the plan's high-severity
        # divergent conflict.
        if self._complete and not self._capped():
            for batch_id, copies in sorted(conflicted.items()):
                if self._capped():
                    break
                keeper: tuple[str, Path, FileIdentity] | None = None
                record = ledger.get(batch_id)
                if record is not None:
                    for day, path, day_identity in copies:
                        if day != record.day:
                            continue  # only the ledger's own day can agree (day is compared)
                        parsed, code = self._trusted_read(path, day_identity)
                        if code is None and _agrees(parsed, day, batch_id, record):
                            keeper = (day, path, day_identity)
                            self._healthy += 1
                        break
                detail = self._conflict_detail(copies)
                for day, path, day_identity in copies:
                    if keeper is not None and (day, path, day_identity) == keeper:
                        continue
                    self._queue_quarantine(day, path.name, day_identity, batch_id, detail)

        # Missing-ledger-file classification is classification, so it runs BEFORE any mutation.
        if self._complete:
            for batch_id, record in ledger.items():
                if self._capped():
                    break  # the cap fired (possibly during the candidate phase): stop classifying
                if batch_id not in seen:
                    self._anomaly(batch_id, record.day, "missing_file", "absent")

        # After every phase and again immediately before mutation: a fired anomaly cap voids the
        # pass even when it fired on the FINAL classified item (the re-review's reproduction, where
        # a top-of-loop check alone never runs again).
        if self._capped():
            self._complete = False
        if self._complete:
            # Mutation happens only after complete, within-bounds classification proved every
            # candidate batch id globally unique and the anomaly budget was never exhausted.
            for parsed, batch_id, day in self._pending_registrations:
                self._register(parsed, batch_id, day)
                self._registered.append(OrphanRegistration(batch_id, day))
            for (
                day,
                name,
                day_identity,
                leaf_identity,
                batch_id,
                detail,
            ) in self._pending_quarantines:
                outcome = self._move_to_quarantine(day, name, day_identity, leaf_identity)
                if outcome is None:
                    self._quarantined.append(QuarantinedFile(batch_id, day, detail))
                elif outcome == "uncertain":
                    # the target is durably named but the source state could not be confirmed:
                    # reported distinctly, never as completed and never as still-pending; the next
                    # scan converges by adopting the same-inode twin
                    self._move_failures.append(
                        SegmentAnomaly(batch_id, day, "quarantine_uncertain", "io")
                    )
                else:
                    # A quarantine that cannot complete never aborts recovery or a commit: the file
                    # stays in pending, is re-reported every scan, and authority is unaffected —
                    # the review showed one un-quarantinable file must not wedge all commits.
                    self._move_failures.append(
                        SegmentAnomaly(batch_id, day, "quarantine_blocked", outcome)
                    )
        else:
            self._pending_registrations.clear()
            self._pending_quarantines.clear()

        return ReconciliationReport(
            registered=tuple(self._registered),
            quarantined=tuple(self._quarantined),
            anomalies=tuple(self._anomalies) + tuple(self._move_failures),
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

    def _capped(self) -> bool:
        return self._stopped

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
            if self._capped():
                # The anomaly cap bounds lock-hold WORK, not just report size: once it fires, no
                # further directory is opened and no further entry is classified.
                self._complete = False
                return candidates
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
                if self._capped():
                    self._complete = False
                    return candidates
                if self._scanned >= _MAX_TOTAL:
                    self._anomaly("", "", "limit", "scan_limit")
                    self._complete = False
                    return candidates
                self._scanned += 1
                if name.startswith(_STAGE_PREFIX):
                    # a crashed writer's staged temporary: never a committed artifact, so it is
                    # quarantined by policy rather than recovered (replay regenerates the batch).
                    # The leaf is inspected no-follow like every quarantine subject: a staged
                    # symlink/directory/FIFO/foreign shape is refused, never followed or moved.
                    self._anomaly("", day, "stale_temp", "staged_temporary")
                    self._queue_quarantine(day, name, day_identity, "", "stale_temp")
                    continue
                resolved = self._classify_name(pending / day / name, day, name)
                if resolved is not None:
                    candidates.append((*resolved, day_identity))
        if self._capped():
            self._complete = False  # the anomaly cap fired on the final inventory item
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
            if code not in _UNQUARANTINABLE:
                self._queue_quarantine(day, path.name, day_identity, batch_id, code)
        elif not _agrees(parsed, day, batch_id, record):
            self._anomaly(batch_id, day, "corrupt_file", "ledger_mismatch")
            self._queue_quarantine(day, path.name, day_identity, batch_id, "ledger_mismatch")
        else:
            self._healthy += 1

    def _reconcile_orphan(
        self, path: Path, day: str, batch_id: str, day_identity: FileIdentity
    ) -> None:
        parsed, code = self._trusted_read(path, day_identity)
        if code is not None:
            self._anomaly(batch_id, day, "corrupt_orphan", code)
            if code not in _UNQUARANTINABLE:
                self._queue_quarantine(day, path.name, day_identity, batch_id, code)
            return
        assert parsed is not None
        if parsed.header.batch_id != batch_id:
            # a valid segment under the wrong name: reported but left in place, like other
            # foreign-named entries (it has no trustworthy quarantine name)
            self._anomaly(batch_id, day, "foreign_name", "header_batch_id")
            return
        try:
            authorize_local_persistence(parsed.header.privacy_class)
        except SpoolError as denied:
            self._anomaly(batch_id, day, "corrupt_orphan", denied.code)
            self._queue_quarantine(day, path.name, day_identity, batch_id, denied.code)
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

    def _conflict_detail(self, copies: list[tuple[str, Path, FileIdentity]]) -> str:
        """Classify a conflicted batch: byte-identical duplicates or a divergent durable history.

        An unreadable copy is treated as divergent (fail-safe severity). The raw bounded hash never
        parses content, so a corrupt conflicted copy still classifies deterministically.
        """

        digests: set[str | None] = {_raw_sha256(path) for _day, path, _identity in copies}
        if None in digests or len(digests) > 1:
            return "conflict_divergent"  # the plan's high-severity duplicate-id conflict
        return "conflict_duplicate"

    def _inspect_leaf(self, day: str, name: str, day_identity: FileIdentity) -> FileIdentity | None:
        """Capture the exact leaf identity of a quarantine subject, no-follow, or refuse it.

        Only the shape :func:`_permitted_quarantine_shape` admits (plus ACL-free) may be queued: a
        symlink (rejected by the no-follow open), directory, FIFO or device (rejected by the shape
        check; ``O_NONBLOCK`` keeps the probe open from hanging on a hostile FIFO or acting on a
        device), foreign owner, unsafe mode, extra hard link, or ACL bearer stays unmoved — the
        re-review demonstrated that linking an uninspected staged name imports arbitrary foreign
        file content into quarantine.
        """

        identity: FileIdentity | None = None
        day_fd: int | None = None
        leaf_fd: int | None = None
        try:
            day_fd = os.open(self._spool_root / _PENDING / day, _dir_flags())
            if FileIdentity.from_stat(os.fstat(day_fd)) != day_identity:
                identity = None
            else:
                leaf_fd = os.open(name, _leaf_probe_flags(), dir_fd=day_fd)
                info = os.fstat(leaf_fd)
                acl_unsafe = False
                try:
                    require_no_extended_acl(leaf_fd)
                except SecureFileError:
                    acl_unsafe = True
                if acl_unsafe:
                    identity = None
                elif _permitted_quarantine_shape(info):
                    identity = FileIdentity.from_stat(info)
                elif _interrupted_move_shape(info) and self._has_quarantine_twin(
                    day, name, FileIdentity.from_stat(info)
                ):
                    # our own interrupted move: the second hard link IS the durable quarantine
                    # twin, so the retry may adopt it and complete the pending unlink; any other
                    # extra link stays refused
                    identity = FileIdentity.from_stat(info)
        except OSError:
            identity = None
        finally:
            for descriptor in (leaf_fd, day_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:  # pragma: no cover - defensive close failure
                        identity = None
        return identity

    def _has_quarantine_twin(self, day: str, name: str, identity: FileIdentity) -> bool:
        """Whether ``quarantine/<day>/`` already durably names this exact inode.

        A crash between the quarantine link and the pending unlink leaves the same inode under
        both names; the retry proves that by inode before the pending twin may be admitted.
        """

        twin = False
        day_fd: int | None = None
        try:
            day_fd = os.open(self._spool_root / _QUARANTINE / day, _dir_flags())
            for attempt in range(_MAX_MOVE_ATTEMPTS):
                candidate = name if attempt == 0 else f"{attempt}.{name}"
                try:
                    info = os.stat(candidate, dir_fd=day_fd, follow_symlinks=False)
                except OSError:
                    continue
                if FileIdentity.from_stat(info) == identity:
                    twin = True
                    break
        except OSError:
            twin = False
        finally:
            if day_fd is not None:
                try:
                    os.close(day_fd)
                except OSError:  # pragma: no cover - defensive close failure
                    pass
        return twin

    def _queue_quarantine(
        self, day: str, name: str, day_identity: FileIdentity, batch_id: str, detail: str
    ) -> None:
        leaf = self._inspect_leaf(day, name, day_identity)
        if leaf is None:
            # an unquarantinable subject shape: reported, never moved, never followed
            self._anomaly(batch_id, day, "quarantine_blocked", "unsafe")
            return
        self._pending_quarantines.append((day, name, day_identity, leaf, batch_id, detail))

    def _move_to_quarantine(
        self, day: str, name: str, day_identity: FileIdentity, leaf_identity: FileIdentity
    ) -> str | None:
        """Move one inspected file to ``quarantine/<day>/`` bound to its exact leaf inode.

        Ordering is crash-safe: the quarantine directories are made durable at creation, the source
        is re-opened no-follow beneath the re-verified day directory and must match the inventoried
        leaf identity, the hard link is created without following symlinks, the TARGET directory is
        fsynced before the source is touched, the target inode is verified equal to the opened
        source inode (rolling the link back on mismatch), the source NAME is revalidated
        immediately before its unlink (a swapped-in replacement is never unlinked), and the source
        directory is fsynced last. A pre-placed twin of the same inode converges (adopted, source
        unlinked) instead of proliferating aliases. Returns ``None`` when the move completed,
        ``"unreachable"``/``"changed"``/``"collision"``/``"io"`` when nothing was moved (the file
        stays in pending), or ``"uncertain"`` when the target is durable but the source state could
        not be confirmed — never a raised error, so one unmovable file cannot wedge recovery.
        """

        quarantine_day = self._spool_root / _QUARANTINE / day
        if not (
            _ensure_private_dir(self._spool_root / _QUARANTINE)
            and _ensure_private_dir(quarantine_day)
        ):
            return "unreachable"
        source_dir_fd: int | None = None
        source_fd: int | None = None
        target_fd: int | None = None
        outcome: str | None = "io"
        try:
            source_dir_fd = os.open(self._spool_root / _PENDING / day, _dir_flags())
            if FileIdentity.from_stat(os.fstat(source_dir_fd)) != day_identity:
                return "changed"
            try:
                source_fd = os.open(name, _leaf_probe_flags(), dir_fd=source_dir_fd)
            except OSError:
                return "changed"  # vanished, or a symlink swapped in (rejected by no-follow)
            source_identity = FileIdentity.from_stat(os.fstat(source_fd))
            if source_identity != leaf_identity:
                return "changed"  # the classified object was replaced after inspection
            target_fd = os.open(quarantine_day, _dir_flags())
            linked: str | None = None
            converged = False
            for attempt in range(_MAX_MOVE_ATTEMPTS):
                candidate = name if attempt == 0 else f"{attempt}.{name}"
                try:
                    os.link(
                        name,
                        candidate,
                        src_dir_fd=source_dir_fd,
                        dst_dir_fd=target_fd,
                        follow_symlinks=False,
                    )
                    linked = candidate
                    break
                except FileExistsError:
                    try:
                        existing = os.stat(candidate, dir_fd=target_fd, follow_symlinks=False)
                    except OSError:
                        continue
                    if FileIdentity.from_stat(existing) == source_identity:
                        linked = candidate  # our own earlier interrupted move: adopt, don't alias
                        converged = True
                        break
                    continue
            if linked is None:
                return "collision"
            # make the target name durable BEFORE the source is touched
            try:
                os.fsync(target_fd)
            except OSError:
                if not converged:
                    self._rollback_link(target_fd, linked)
                return "io"
            checked = os.stat(linked, dir_fd=target_fd, follow_symlinks=False)
            if FileIdentity.from_stat(checked) != source_identity:
                if not converged:
                    self._rollback_link(target_fd, linked)
                return "changed"
            # the classified bytes are durably named in quarantine; from here failures are
            # commit-uncertain, never silently misreported as "still pending"
            outcome = "uncertain"
            try:
                current = os.stat(name, dir_fd=source_dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None  # the source name is already gone; the move is complete
            if FileIdentity.from_stat(current) != source_identity:
                # a replacement was swapped in after linking: never unlink the unclassified
                # object — the classified one is safely in quarantine, the newcomer is scanned next
                return None
            os.unlink(name, dir_fd=source_dir_fd)
            os.fsync(source_dir_fd)
            return None
        except OSError:
            return outcome
        finally:
            for descriptor in (target_fd, source_fd, source_dir_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:  # pragma: no cover - defensive close failure
                        pass

    def _rollback_link(self, target_fd: int, linked: str) -> None:
        try:
            os.unlink(linked, dir_fd=target_fd)
            os.fsync(target_fd)
        except OSError:  # pragma: no cover - best-effort rollback of an undurable link
            pass

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

        return _reconcile_under_barrier(
            database=self._database,
            barrier=self._barrier,
            spool_root=self._spool_root,
            installation_id=self._installation_id,
        )
