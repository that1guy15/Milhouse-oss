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
descriptor-relative with no-follow semantics, capturing its exact ``FileSnapshot`` AND a bounded
content digest; only an owned, exact-0600, single-link, ACL-free, size-bounded regular file is
ever queued, so a staged symlink, directory, FIFO, device, or foreign shape can never import
outside content. The move is a digest-verified COPY — a hard link cannot freeze content, because
both names remain the same writable inode — re-opening the source no-follow beneath the
re-verified day descriptor, requiring snapshot equality, reading the bytes from that descriptor,
requiring digest equality (re-checking the snapshot after the read), staging and
no-replace-publishing the copy (a candidate name is only ever absent or complete, and an existing
same-digest candidate is adopted, never aliased), fsyncing file then directory BEFORE the source
is touched, and revalidating the source name immediately before its unlink — narrowing (POSIX has
no compare-and-unlink, so no re-stat can fully eliminate) the stat-to-unlink window; the exclusive
hold and owner-only 0700 pending directory exclude every cooperating writer from that window, and
whatever happens to the source name, the quarantine target only ever holds the exact classified
bytes. Outcomes distinguish pre-move blocked, completed, and commit-uncertain, with every claim
verified, never assumed. Foreign-named entries are reported but
left in place (they have no well-formed quarantine name). The scan never deletes SPOOL DATA: the
only unlinks are a source whose verified copy is already durably in quarantine and the scan's own
staging debris (which never holds a last copy). An incomplete pass moves nothing. Every failure
is a fixed ``MH_SPOOL_*`` error raised outside any handler.
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
    FileSnapshot,
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
# object is not the present one), the file vanished, or it is not a regular file (copying a
# symlink target or a directory would import unclassified content). These stay report-only.
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
# Bounded quarantine-name attempts: `<name>`, `1.<name>`, ... — shared by the copy publisher and
# digest adoption so both agree on which candidate names can exist.
_MAX_MOVE_ATTEMPTS = 100
# The quarantine copy's fixed staging name (inside quarantine/<day>/): the candidate name is only
# ever absent or a COMPLETE copy, so a crash can never leave partial classified bytes at a name a
# later scan would have to disambiguate. Crash debris under this name is cleared on the next pass.
_QUARANTINE_STAGE = ".milhouse-stage-quarantine-copy"
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
    ``changed``, ``collision``, ``io``), ``quarantine_uncertain`` (a durable quarantine
    copy of the classified bytes exists — or could not be ruled out — but the pending source's
    state could not be confirmed; the next scan converges by adopting the same-digest copy), or
    ``limit`` (a scan bound was exceeded).
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
    """Create-if-absent, durably name, and validate one owned, exact-0700, ACL-free directory.

    The parent directory is fsynced on EVERY acceptance, not only when this call created the
    entry: the re-review planted a parent-fsync failure after creation and showed the retry
    trusting the still-visible directory without ever re-proving its entry durable — so a crash
    after a later move could lose the directory that names the moved file. A directory is
    accepted only once its parent entry has been fsynced successfully in this pass.
    """

    unsafe = False
    descriptor: int | None = None
    try:
        os.mkdir(path, _DIR_MODE)
    except FileExistsError:
        pass
    except OSError:
        unsafe = True
    if not unsafe and not _fsync_dir(path.parent):
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


def _read_descriptor(descriptor: int, size: int) -> bytes | None:
    """Read exactly ``size`` bytes from an opened regular file, refusing growth or shrinkage.

    The caller bounds ``size`` at classification time. After the exact read, a one-byte probe
    detects a file that grew mid-read; a short read detects one that shrank. Either drift (or
    any read failure) returns None so the caller refuses the subject instead of certifying
    bytes that do not match its captured snapshot.
    """

    failed = False
    chunks: list[bytes] = []
    remaining = size
    try:
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                failed = True
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if not failed and os.read(descriptor, 1):
            failed = True  # the file grew past its classified size mid-read
    except OSError:
        failed = True
    return None if failed else b"".join(chunks)


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
        # (day, name, day_identity, snapshot, digest, batch_id_or_empty, detail)
        self._pending_quarantines: list[
            tuple[str, str, FileIdentity, FileSnapshot, str, str, str]
        ] = []
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
                snapshot,
                digest,
                batch_id,
                detail,
            ) in self._pending_quarantines:
                outcome = self._move_to_quarantine(day, name, day_identity, snapshot, digest)
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

    def _inspect_leaf(
        self, day: str, name: str, day_identity: FileIdentity
    ) -> tuple[FileSnapshot, str] | None:
        """Classify a quarantine subject: capture its exact snapshot AND content digest, or refuse.

        Only the shape :func:`_permitted_quarantine_shape` admits (plus ACL-free, bounded size)
        may be queued: a symlink (rejected by the no-follow open), directory, FIFO or device
        (rejected by the shape check; ``O_NONBLOCK`` keeps the probe open from hanging on a
        hostile FIFO or acting on a device), foreign owner, unsafe mode, extra hard link, ACL
        bearer, or oversize file stays unmoved. The re-review demonstrated that inode identity
        alone cannot authorize a move — an in-place rewrite keeps the inode — so classification
        binds the subject to immutable CONTENT: the full ``FileSnapshot`` (device, inode, size,
        mtime, ctime) plus a bounded SHA-256 of the exact bytes, both captured from the opened
        descriptor and re-verified after the read.
        """

        result: tuple[FileSnapshot, str] | None = None
        day_fd: int | None = None
        leaf_fd: int | None = None
        try:
            day_fd = os.open(self._spool_root / _PENDING / day, _dir_flags())
            if FileIdentity.from_stat(os.fstat(day_fd)) == day_identity:
                leaf_fd = os.open(name, _leaf_probe_flags(), dir_fd=day_fd)
                info = os.fstat(leaf_fd)
                acl_unsafe = False
                try:
                    require_no_extended_acl(leaf_fd)
                except SecureFileError:
                    acl_unsafe = True
                if (
                    not acl_unsafe
                    and _permitted_quarantine_shape(info)
                    and info.st_size <= MAX_SEGMENT_FILE_BYTES
                ):
                    content = _read_descriptor(leaf_fd, info.st_size)
                    if content is not None and FileSnapshot.from_stat(
                        os.fstat(leaf_fd)
                    ) == FileSnapshot.from_stat(info):
                        result = (
                            FileSnapshot.from_stat(info),
                            hashlib.sha256(content).hexdigest(),
                        )
        except OSError:
            result = None
        finally:
            for descriptor in (leaf_fd, day_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:  # pragma: no cover - defensive close failure
                        result = None
        return result

    def _queue_quarantine(
        self, day: str, name: str, day_identity: FileIdentity, batch_id: str, detail: str
    ) -> None:
        classified = self._inspect_leaf(day, name, day_identity)
        if classified is None:
            # an unquarantinable subject shape: reported, never moved, never followed
            self._anomaly(batch_id, day, "quarantine_blocked", "unsafe")
            return
        snapshot, digest = classified
        self._pending_quarantines.append(
            (day, name, day_identity, snapshot, digest, batch_id, detail)
        )

    def _move_to_quarantine(
        self,
        day: str,
        name: str,
        day_identity: FileIdentity,
        snapshot: FileSnapshot,
        digest: str,
    ) -> str | None:
        """Move one classified file to ``quarantine/<day>/`` as a digest-verified COPY.

        A hard link cannot freeze content — both names remain the same writable inode — so the
        move copies (the re-review reproduced an in-place rewrite being certified as the
        classified file). The source is re-opened no-follow beneath the re-verified day
        descriptor and must match the classification-time snapshot exactly; its bytes are read
        FROM THAT DESCRIPTOR, must hash to the classified digest, and the snapshot is
        re-verified after the read — so no name swap or in-place mutation can substitute bytes.
        The copy is staged and no-replace-published inside the quarantine day (the candidate
        name is only ever absent or complete), fsynced file-then-directory BEFORE the source is
        touched. A pre-existing candidate holding the exact classified digest is ADOPTED (an
        earlier interrupted move), never aliased; any other occupant advances the bounded
        counter. The source NAME is then revalidated immediately before its unlink, refusing
        any replacement or mutation the re-stat can observe (POSIX offers no compare-and-unlink,
        so the stat-to-unlink window narrows to one syscall; the exclusive hold and owner-only
        pending directory exclude cooperating writers from it), and the source directory is
        fsynced last.
        Returns ``None`` when the classified bytes are durably quarantined,
        ``"unreachable"``/``"changed"``/``"collision"``/``"io"`` when verifiably nothing of this
        subject's moved (the file stays in pending), or ``"uncertain"`` when a copy of the
        classified bytes may exist — freshly published or as an unexaminable pre-existing
        occupant — but could not be proven or disproven; never a raised error, so one unmovable
        file cannot wedge recovery.
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
            if FileSnapshot.from_stat(os.fstat(source_fd)) != snapshot:
                return "changed"  # replaced OR rewritten in place since classification
            content = _read_descriptor(source_fd, snapshot.size)
            if content is None or hashlib.sha256(content).hexdigest() != digest:
                return "changed"  # the bytes are not the classified bytes
            if FileSnapshot.from_stat(os.fstat(source_fd)) != snapshot:
                return "changed"  # mutated during the read (ctime/mtime backstop)
            target_fd = os.open(quarantine_day, _dir_flags())
            placed = False
            for attempt in range(_MAX_MOVE_ATTEMPTS):
                candidate = name if attempt == 0 else f"{attempt}.{name}"
                if candidate == _QUARANTINE_STAGE:
                    # the fixed staging name is clearable debris by definition, so a copy
                    # published THERE would be destroyed by the next publish into this day —
                    # the verification workflow reproduced exactly that via a pending subject
                    # named like the stage; such a subject lands at a counter-prefixed name
                    continue
                published = self._publish_copy(target_fd, candidate, content)
                if published == "placed":
                    placed = True
                    break
                if published == "exists":
                    verdict = self._adopt_existing(target_fd, candidate, digest)
                    if verdict == "adopted":
                        placed = True  # our own earlier interrupted move: adopt, don't alias
                        break
                    if verdict in ("different", "absent"):
                        continue  # a foreign occupant: advance the bounded counter
                    # an unexaminable pre-existing occupant COULD be this source's own earlier
                    # interrupted copy: a clean blocked code would overclaim, so report the
                    # ambiguity honestly — the next scan converges once it can be examined
                    return "uncertain"
                # published == "failed": VERIFY whether the durable name appeared anyway —
                # the re-review showed a clean blocked code masking an unproven two-name state
                verdict = self._adopt_existing(target_fd, candidate, digest)
                if verdict == "adopted":
                    placed = True  # the copy landed and is now proven durable
                    break
                if verdict in ("different", "absent"):
                    return "io"  # verified: no classified copy exists; the source is untouched
                return "uncertain"  # a copy may exist but could not be proven or disproven
            if not placed:
                return "collision"
            # the classified bytes are durably named in quarantine; from here failures are
            # commit-uncertain, never silently misreported as "still pending"
            outcome = "uncertain"
            try:
                current = os.stat(name, dir_fd=source_dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None  # the source name is already gone; the move is complete
            if FileSnapshot.from_stat(current) != snapshot:
                # the name was replaced or rewritten after the copy: never unlink the
                # unclassified object — the classified bytes are safely in quarantine and the
                # newcomer is scanned next pass
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

    def _publish_copy(self, target_fd: int, candidate: str, content: bytes) -> str:
        """Stage and no-replace-publish one quarantine copy beneath the held day descriptor.

        Returns ``"placed"`` (the candidate is durably complete), ``"exists"`` (the candidate
        name was already taken — the caller decides adoption), or ``"failed"`` (the caller must
        verify whether the name appeared). The fixed staging name keeps the candidate name
        binary: absent, or a complete copy. Stage debris from an earlier crash is cleared.
        """

        stage_fd: int | None = None
        stage_live = False
        try:
            for _attempt in range(2):
                try:
                    stage_fd = os.open(
                        _QUARANTINE_STAGE,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                        dir_fd=target_fd,
                    )
                    stage_live = True
                    break
                except FileExistsError:
                    # our own crash debris beneath our private day directory: clear and retry
                    os.unlink(_QUARANTINE_STAGE, dir_fd=target_fd)
            if stage_fd is None:  # pragma: no cover - two O_EXCL failures require a live racer
                return "failed"
            if content and os.write(stage_fd, content) != len(content):
                return "failed"
            os.fsync(stage_fd)
            try:
                os.link(
                    _QUARANTINE_STAGE,
                    candidate,
                    src_dir_fd=target_fd,
                    dst_dir_fd=target_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                return "exists"
            os.unlink(_QUARANTINE_STAGE, dir_fd=target_fd)
            stage_live = False
            os.fsync(target_fd)  # the candidate name is durable only after this succeeds
            return "placed"
        except OSError:
            return "failed"
        finally:
            if stage_fd is not None:
                try:
                    os.close(stage_fd)
                except OSError:  # pragma: no cover - defensive close failure
                    pass
            if stage_live:
                # best-effort: never leave this pass's own staging name behind; a crash here
                # leaves debris the next publish into this day clears
                try:
                    os.unlink(_QUARANTINE_STAGE, dir_fd=target_fd)
                except OSError:  # pragma: no cover - debris cleanup is best-effort
                    pass

    def _adopt_existing(self, target_fd: int, candidate: str, digest: str) -> str:
        """Examine an existing candidate: adopt it only if it IS the classified bytes, durably.

        Returns ``"adopted"`` (the exact classified digest, re-fsynced file and directory),
        ``"different"`` (some other content — never replaced, never adopted), ``"absent"``, or
        ``"unknown"`` (could not be examined or made durable — the caller must not claim a
        clean outcome).
        """

        descriptor: int | None = None
        verdict = "unknown"
        try:
            try:
                descriptor = os.open(candidate, _leaf_probe_flags(), dir_fd=target_fd)
            except FileNotFoundError:
                return "absent"
            except OSError as error:
                if error.errno == errno.ELOOP:
                    return "different"  # a symlink is never our copy — and is never followed
                raise
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SEGMENT_FILE_BYTES:
                return "different"
            existing = _read_descriptor(descriptor, info.st_size)
            if existing is None:
                return "unknown"
            if hashlib.sha256(existing).hexdigest() != digest:
                return "different"
            os.fsync(descriptor)
            os.fsync(target_fd)
            return "adopted"
        except OSError:
            return verdict
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:  # pragma: no cover - defensive close failure
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
