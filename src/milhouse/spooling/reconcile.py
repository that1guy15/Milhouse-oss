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
is touched. Publication and adoption each reopen a fully validated live spool-root -> quarantine
-> day chain; a copy created by this pass retains cleanup authority and is removed and fsynced if
that namespace binding is later lost. Finalization performs every long digest and source-snapshot
check before a last pending live-binding proof, then atomically renames the exact source to a
private retirement name which encodes its bounded target candidate and fsyncs the day. It re-proves
the target bytes plus both complete live directory chains AFTER that reversible retirement; only
then is the retirement unlinked and fsynced. A failed proof leaves classified bytes discoverable as
a staged temporary for deterministic retry. POSIX has no rename/unlink primitive conditional on an
ancestor pathname still naming an opened directory, so the exclusive hold and owner-only 0700
directories exclude cooperating writers from the adjacent-proof syscall window; an uncooperative
same-UID process is outside that documented model. Outcomes distinguish pre-move blocked,
completed, and commit-uncertain, with every claim verified, never assumed.
Foreign-named entries are reported but
left in place (they have no well-formed quarantine name). The scan never deletes SPOOL DATA: the
only unlinks are a retired source after its verified copy and both namespaces are re-proven, the
scan's own empty reservation/staging debris, or a copy created by this pass after its live binding
is lost (none ever holds a last copy). An incomplete pass moves nothing. Every failure is a fixed
``MH_SPOOL_*`` error raised outside any handler.
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
    ParsedSegment,
    read_trusted_segment,
)
from milhouse.spooling.segment import (
    BATCH_ID_PATTERN,
    FRAME_VERSION,
    MAX_SEGMENT_FILE_BYTES,
    SCHEMA_VERSION,
)
from milhouse.state.barrier import GlobalCommitBarrier, _is_bound_barrier
from milhouse.state.database import ControlDatabase, _validated_database_path
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
# Final source removal is two-phase. The public pending name is first atomically replaced by one
# private retirement name; both namespaces are then re-proven before that retirement is unlinked.
# A failed proof therefore leaves recoverable staged bytes instead of deleting the source.
_RETIRE_PREFIX = ".milhouse-stage-quarantine-retired-"
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
    ``changed``, ``collision``, ``io``), ``quarantine_uncertain`` (a durable quarantine copy was
    created, exists, or could not be ruled out, but the pending source's state or live target
    binding could not be confirmed; the next scan converges by adopting a live same-digest copy or
    producing a fresh live copy), or
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


@dataclass(frozen=True, slots=True)
class _PlacedCopy:
    """A certified target plus cleanup authority for a copy created by this pass."""

    candidate: str
    snapshot: FileSnapshot
    target_identities: tuple[FileIdentity, FileIdentity, FileIdentity]
    cleanup_fd: int | None

    @property
    def created(self) -> bool:
        return self.cleanup_fd is not None


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


def _fsync_descriptor(descriptor: int) -> bool:
    try:
        os.fsync(descriptor)
        return True
    except OSError:
        return False


def _close_descriptors(descriptors: tuple[int, ...]) -> None:
    """Best-effort close a descriptor chain without masking the classified operation result."""

    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive close failure
            pass


def _descriptors_match(descriptors: tuple[int, ...], identities: tuple[FileIdentity, ...]) -> bool:
    """Revalidate every held directory's complete envelope and captured identity together."""

    return len(descriptors) == len(identities) and all(
        _validated_dir_descriptor(descriptor) == identity
        for descriptor, identity in zip(descriptors, identities, strict=True)
    )


def _validated_dir_descriptor(descriptor: int) -> FileIdentity | None:
    """Validate an opened directory descriptor (owned, 0700, ACL-free); return its identity."""

    unsafe = False
    identity: FileIdentity | None = None
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _current_uid()
            or stat.S_IMODE(info.st_mode) != _DIR_MODE
        ):
            unsafe = True
        else:
            require_no_extended_acl(descriptor)
            identity = FileIdentity.from_stat(info)
    except (OSError, SecureFileError):
        unsafe = True
    return None if unsafe else identity


def _ensure_private_dir_at(parent_fd: int, name: str) -> tuple[int, FileIdentity] | None:
    """Create-if-absent, durably name, validate, and OPEN one directory beneath a held parent.

    Everything is descriptor-relative to the already-validated parent, so no path re-walk can be
    redirected. The parent is fsynced on EVERY acceptance, not only when this call created the
    entry — a directory that survived an earlier failed parent fsync is never implicitly trusted
    (round-2 P1). Returns the OPEN no-follow descriptor plus its exact identity, or None; the
    caller owns the descriptor.
    """

    descriptor: int | None = None
    identity: FileIdentity | None = None
    try:
        try:
            os.mkdir(name, _DIR_MODE, dir_fd=parent_fd)
        except FileExistsError:
            pass
        if _fsync_descriptor(parent_fd):
            descriptor = os.open(name, _dir_flags(), dir_fd=parent_fd)
            identity = _validated_dir_descriptor(descriptor)
    except OSError:
        identity = None
    if identity is None or descriptor is None:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover - defensive close failure
                pass
        return None
    return descriptor, identity


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


def _retirement_candidate(name: str, snapshot: FileSnapshot) -> str | None:
    """Recover the exact quarantine candidate encoded in one retirement name.

    Device and inode bind the private name to the staged object. A planted name that merely uses
    the reserved prefix is therefore handled as an ordinary staged temporary, never as recovery
    authority for an unrelated quarantine candidate.
    """

    marker = f"{_RETIRE_PREFIX}{snapshot.device:x}-{snapshot.inode:x}--"
    if not name.startswith(marker):
        return None
    candidate = name[len(marker) :]
    return candidate or None


def _retirement_name(snapshot: FileSnapshot, candidate: str) -> str:
    """Encode the durable target name so an interrupted retirement can adopt it on retry."""

    return f"{_RETIRE_PREFIX}{snapshot.device:x}-{snapshot.inode:x}--{candidate}"


def _bounded_candidate_base(
    name: str, snapshot: FileSnapshot, digest: str, name_max: int
) -> str | None:
    """Choose a deterministic candidate whose worst-case retirement name fits ``NAME_MAX``."""

    attempt_prefix = f"{_MAX_MOVE_ATTEMPTS - 1}."
    retirement_overhead = len(os.fsencode(_retirement_name(snapshot, attempt_prefix)))
    candidate_budget = name_max - retirement_overhead
    encoded_name = os.fsencode(name)
    if 0 < len(encoded_name) <= candidate_budget:
        return name
    token = hashlib.sha256(encoded_name + b"\0" + digest.encode("ascii")).hexdigest()
    compact = f".milhouse-quarantine-{token}"
    if len(os.fsencode(compact)) <= candidate_budget:
        return compact
    return None


def _secure_names_from_descriptor(
    descriptor: int,
) -> tuple[tuple[str, ...] | None, FileIdentity | None, str | None]:
    """List one already-open directory while preserving its complete secure envelope."""

    identity = _validated_dir_descriptor(descriptor)
    if identity is None:
        return None, None, "unsafe"
    names: tuple[str, ...] | None = None
    problem: str | None = None
    try:
        collected: list[str] = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(collected) >= _MAX_ENTRIES:
                    problem = "too_many"
                    break
                collected.append(entry.name)
        if problem is None:
            names = tuple(sorted(collected))
        if _validated_dir_descriptor(descriptor) != identity:
            problem = "unsafe"
    except OSError:
        problem = "unreadable"
    if problem is not None:
        return None, None, problem
    return names, identity, None


def _require_bound_state_root(
    database: object, barrier: object, spool_root: str | Path, installation_id: str
) -> Path:
    """Require database, barrier, and spool root to share one canonical state root.

    A barrier from a different state root is not authority for this database/spool pair, so the
    binding is validated here (the wrapper) as well as at the public constructors, and the scan
    additionally binds the concrete barrier object to the database before any lock acquisition.
    """

    if type(barrier) is not GlobalCommitBarrier:
        _fail("MH_SPOOL_STORE", "a commit barrier is required")
    database_path = _validated_database_path(database)
    if database_path is None:
        _fail("MH_SPOOL_STORE", "a control database is required")
    control_dir = lexical_absolute_path(database_path).parent
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
    """The only reconciliation entrypoint: the scan owns the exact barrier context.

    This wrapper first validates that database, barrier, and spool root share one canonical state
    root. :meth:`_Scan.run` acquires that concrete barrier exclusively for reconciliation. When a
    durable-writer action follows, it converts the held main lock to shared without releasing the
    exclusive gate, then releases the gate and runs the action under the shared side. There is no
    caller-mintable authority token and no cooperating-writer gap. ``observe`` receives the report
    before the phase transition, so a caller records it even when ``action`` then fails.
    """

    spool_root = _require_bound_state_root(database, barrier, spool_root, installation_id)
    return _Scan(database, lexical_absolute_path(spool_root), installation_id).run(
        barrier, action=action, observe=observe
    )


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

    def run(
        self,
        barrier: GlobalCommitBarrier,
        *,
        action: Callable[[], None] | None = None,
        observe: Callable[[ReconciliationReport], None] | None = None,
    ) -> ReconciliationReport:
        """Acquire the bound barrier and retain it through recovery and any writer action."""

        # Validate the concrete barrier BEFORE the first ledger read. The scan acquires the lock
        # itself, so a direct call cannot substitute a forged token or rely on a caller's claim that
        # some lock is held.
        binding_failed = False
        resolved_spool: Path | None = None
        try:
            resolved_spool = _require_bound_state_root(
                self._database, barrier, self._spool_root, self._installation_id
            )
        except SpoolError:
            binding_failed = True
        if binding_failed:
            _fail(
                "MH_SPOOL_BARRIER",
                "reconciliation requires this control plane's bound commit barrier",
            )
        assert resolved_spool is not None
        # Use the exact normalized path that passed the binding. Retaining a raw ``symlink/..``
        # spelling would let POSIX traversal resolve somewhere different from lexical validation.
        self._spool_root = resolved_spool
        report: ReconciliationReport | None = None
        barrier_failed = False
        barrier_acquired = False
        barrier_context = (
            barrier.exclusive_then_shared() if action is not None else barrier.exclusive()
        )
        try:
            with barrier_context as transition:
                barrier_acquired = True
                ledger, malformed = self._ledger_index()
                for batch_id in sorted(malformed):
                    # The batch id came from a row that failed validation, so it may not be well
                    # formed.
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
                            self._verify_committed(
                                path, day, batch_id, ledger[batch_id], day_identity
                            )
                        else:
                            self._reconcile_orphan(path, day, batch_id, day_identity)

                # Conflict content comparison is classification (bounded raw reads, no parsing).
                # Every copy of a conflicted batch is staged for quarantine EXCEPT one that agrees
                # with an existing healthy ledger row: the ledger already unambiguously designates
                # that copy, so keeping it is not directory order choosing a history — and
                # quarantining it would demote an acknowledged committed segment to a dangling
                # ledger row (the review's reproduction via an ordinary same-batch retry).
                # Differing contents mark the plan's high-severity divergent conflict.
                if self._complete and not self._capped():
                    for batch_id, copies in sorted(conflicted.items()):
                        if self._capped():
                            break
                        keeper: tuple[str, Path, FileIdentity] | None = None
                        record = ledger.get(batch_id)
                        if record is not None:
                            for day, path, day_identity in copies:
                                if day != record.day:
                                    # Only the ledger's own day can agree (day is compared).
                                    continue
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

                # Missing-ledger-file classification is classification, so it runs BEFORE any
                # mutation.
                if self._complete:
                    for batch_id, record in ledger.items():
                        if self._capped():
                            # The cap fired (possibly during the candidate phase): stop classifying.
                            break
                        if batch_id not in seen:
                            self._anomaly(batch_id, record.day, "missing_file", "absent")

                # After every phase and again immediately before mutation: a fired anomaly cap
                # voids the pass even when it fired on the FINAL classified item (the re-review's
                # reproduction, where a top-of-loop check alone never runs again).
                if self._capped():
                    self._complete = False
                if self._complete:
                    # Mutation happens only after complete, within-bounds classification proved
                    # every candidate batch id globally unique and the anomaly budget was never
                    # exhausted.
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
                        outcome = self._move_to_quarantine(
                            day, name, day_identity, snapshot, digest
                        )
                        if outcome is None:
                            self._quarantined.append(QuarantinedFile(batch_id, day, detail))
                        elif outcome == "uncertain":
                            # The target is durably named but the source state could not be
                            # confirmed: reported distinctly, never as completed; the public source
                            # may remain or be recoverably retired in pending, and the next scan
                            # converges through the live certified copy or a fresh live copy.
                            self._move_failures.append(
                                SegmentAnomaly(batch_id, day, "quarantine_uncertain", "io")
                            )
                        else:
                            # A quarantine that cannot complete never aborts recovery or a commit:
                            # the file stays in pending, is re-reported every scan, and authority is
                            # unaffected — the review showed one un-quarantinable file must not
                            # wedge all commits.
                            self._move_failures.append(
                                SegmentAnomaly(batch_id, day, "quarantine_blocked", outcome)
                            )
                else:
                    self._pending_registrations.clear()
                    self._pending_quarantines.clear()

                report = ReconciliationReport(
                    registered=tuple(self._registered),
                    quarantined=tuple(self._quarantined),
                    anomalies=tuple(self._anomalies) + tuple(self._move_failures),
                    healthy=self._healthy if self._complete else 0,
                    scanned=self._scanned,
                    complete=self._complete,
                )
                if observe is not None:
                    observe(report)
                if action is not None and report.complete:
                    if transition is None:  # pragma: no cover - context selection is local above
                        _fail("MH_SPOOL_BARRIER", "the writer barrier transition is unavailable")
                    # Normalize only a failed lock-mode transition as a barrier failure. Once the
                    # transition succeeds, preserve any StateError raised by the writer action.
                    barrier_acquired = False
                    transition()
                    barrier_acquired = True
                    action()
        except StateError:
            if barrier_acquired:
                # Scan/ledger paths normalize their own failures. Preserve a StateError raised by
                # an observer or commit action instead of falsely reporting acquisition failure.
                raise
            # Normalize only failure to enter the barrier context; assign outside the handler so
            # the public SpoolError has no leaked exception context.
            barrier_failed = True
        if barrier_failed or report is None:
            _fail("MH_SPOOL_BARRIER", "the commit barrier could not be acquired")
        return report

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
        root_chain = self._open_existing_chain(())
        if root_chain is None:
            # Only a validated spool root may certify an empty inventory. A missing, symlinked,
            # foreign, loose, ACL-bearing, or unreadable configured root is never equivalent to an
            # empty pending child.
            self._anomaly("", "", "foreign_name", "spool_root_unsafe")
            self._complete = False
            return []
        root_descriptors, root_identities = root_chain
        held_descriptors = root_descriptors
        candidates: list[tuple[str, str, Path, FileIdentity]] = []
        try:
            root_fd = root_descriptors[-1]
            try:
                pending_fd = os.open(_PENDING, _dir_flags(), dir_fd=root_fd)
            except FileNotFoundError:
                # Absence is a valid empty spool only when the held root still has its complete
                # envelope and remains the configured live root at the decision point.
                if _descriptors_match(root_descriptors, root_identities) and self._binding_holds(
                    (), root_identities
                ):
                    return []
                self._anomaly("", "", "foreign_name", "spool_root_changed")
                self._complete = False
                return []
            except OSError:
                self._anomaly("", "", "foreign_name", "pending_unsafe")
                self._complete = False
                return []
            held_descriptors = (*root_descriptors, pending_fd)
            pending_identity = _validated_dir_descriptor(pending_fd)
            if pending_identity is None:
                self._anomaly("", "", "foreign_name", "pending_unsafe")
                self._complete = False
                return []
            pending_identities = (*root_identities, pending_identity)
            if not _descriptors_match(held_descriptors, pending_identities):
                self._anomaly("", "", "foreign_name", "pending_changed")
                self._complete = False
                return []
            day_names, pending_identity, problem = _secure_names_from_descriptor(pending_fd)
            if problem is not None or pending_identity != pending_identities[-1]:
                self._anomaly("", "", "foreign_name", f"pending_{problem or 'changed'}")
                self._complete = False
                return []
            assert day_names is not None
            if len(day_names) > _MAX_DAYS:
                self._anomaly("", "", "limit", "day_limit")
                self._complete = False
                return []
            for day in day_names:
                if self._capped():
                    # The anomaly cap bounds lock-hold WORK, not just report size: once it fires,
                    # no further directory is opened and no further entry is classified.
                    self._complete = False
                    return candidates
                if not _is_valid_day(day):
                    self._anomaly("", "", "foreign_name", "day")
                    continue
                if not self._inventory_day(pending_fd, pending, day, candidates):
                    return candidates
                if not _descriptors_match(
                    held_descriptors, pending_identities
                ) or not self._binding_holds((_PENDING,), pending_identities):
                    self._anomaly("", "", "foreign_name", "pending_changed")
                    self._complete = False
                    return candidates
            if not _descriptors_match(
                held_descriptors, pending_identities
            ) or not self._binding_holds((_PENDING,), pending_identities):
                self._anomaly("", "", "foreign_name", "pending_changed")
                self._complete = False
                return candidates
            if self._capped():
                self._complete = False  # the anomaly cap fired on the final inventory item
            return candidates
        finally:
            _close_descriptors(held_descriptors)

    def _inventory_day(
        self,
        pending_fd: int,
        pending: Path,
        day: str,
        candidates: list[tuple[str, str, Path, FileIdentity]],
    ) -> bool:
        """Inventory one day relative to the held pending descriptor; always close the day fd."""

        day_fd: int | None = None
        try:
            entries: tuple[str, ...] | None = None
            day_identity: FileIdentity | None = None
            entry_problem: str | None = None
            try:
                day_fd = os.open(day, _dir_flags(), dir_fd=pending_fd)
                entries, day_identity, entry_problem = _secure_names_from_descriptor(day_fd)
            except OSError as error:
                entry_problem = (
                    "unsafe" if error.errno in {errno.ELOOP, errno.ENOTDIR} else "unreadable"
                )
            if entry_problem is not None:
                # An unlistable or truncated day leaves possible batches and duplicates unseen.
                self._anomaly("", day, "foreign_name", f"day_{entry_problem}")
                self._complete = False
                return True
            assert entries is not None and day_identity is not None
            for name in entries:
                if self._capped():
                    self._complete = False
                    return False
                if self._scanned >= _MAX_TOTAL:
                    self._anomaly("", "", "limit", "scan_limit")
                    self._complete = False
                    return False
                self._scanned += 1
                if name.startswith(_STAGE_PREFIX):
                    # A crashed writer's staged temporary is never committed. Its leaf is still
                    # inspected no-follow before quarantine is queued.
                    self._anomaly("", day, "stale_temp", "staged_temporary")
                    self._queue_quarantine(day, name, day_identity, "", "stale_temp")
                    continue
                resolved = self._classify_name(pending / day / name, day, name)
                if resolved is not None:
                    candidates.append((*resolved, day_identity))
            return True
        finally:
            if day_fd is not None:
                try:
                    os.close(day_fd)
                except OSError:  # pragma: no cover - defensive close failure
                    self._complete = False

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

    def _open_quarantine_chain(
        self, day: str
    ) -> tuple[tuple[int, int, int], tuple[FileIdentity, FileIdentity, FileIdentity]] | None:
        """Open spool-root -> quarantine -> day as a validated descriptor chain.

        Every level is opened no-follow relative to its already-validated parent and its exact
        identity captured, so a path re-walk can never be redirected mid-chain. All three
        descriptors stay open for the caller, preventing a captured ancestor inode from being
        recycled while a mutation is in flight.
        """

        descriptors: list[int] = []
        result: (
            tuple[tuple[int, int, int], tuple[FileIdentity, FileIdentity, FileIdentity]] | None
        ) = None
        try:
            root_fd = os.open(self._spool_root, _dir_flags())
            descriptors.append(root_fd)
            root_identity = _validated_dir_descriptor(root_fd)
            if root_identity is not None:
                quarantine = _ensure_private_dir_at(root_fd, _QUARANTINE)
                if quarantine is not None:
                    quarantine_fd, quarantine_identity = quarantine
                    descriptors.append(quarantine_fd)
                    day_pair = _ensure_private_dir_at(quarantine_fd, day)
                    if day_pair is not None:
                        day_fd, day_identity = day_pair
                        descriptors.append(day_fd)
                        held_descriptors = (root_fd, quarantine_fd, day_fd)
                        identities = (root_identity, quarantine_identity, day_identity)
                        if _descriptors_match(held_descriptors, identities):
                            result = (held_descriptors, identities)
        except OSError:
            result = None
        finally:
            if result is None:
                _close_descriptors(tuple(descriptors))
        return result

    def _open_existing_chain(
        self, components: tuple[str, ...]
    ) -> tuple[tuple[int, ...], tuple[FileIdentity, ...]] | None:
        """Open and fully validate an existing live chain beneath the configured spool root.

        Every descriptor is opened no-follow relative to the previously validated descriptor.
        Ownership, exact 0700 mode, directory type, and the ACL envelope are checked at every
        level. Every descriptor remains open for the caller so none of the captured ancestor
        identities can be recycled before the caller finishes its proof or mutation.
        """

        descriptors: list[int] = []
        identities: list[FileIdentity] = []
        complete = False
        try:
            root_fd = os.open(self._spool_root, _dir_flags())
            descriptors.append(root_fd)
            root_identity = _validated_dir_descriptor(root_fd)
            if root_identity is None:
                return None
            identities.append(root_identity)
            parent_fd = root_fd
            for component in components:
                descriptor = os.open(component, _dir_flags(), dir_fd=parent_fd)
                descriptors.append(descriptor)
                identity = _validated_dir_descriptor(descriptor)
                if identity is None:
                    return None
                identities.append(identity)
                parent_fd = descriptor
            held_descriptors = tuple(descriptors)
            captured_identities = tuple(identities)
            if not _descriptors_match(held_descriptors, captured_identities):
                return None
            complete = True
            return held_descriptors, captured_identities
        except OSError:
            return None
        finally:
            if not complete:
                _close_descriptors(tuple(descriptors))

    def _binding_holds(
        self, components: tuple[str, ...], identities: tuple[FileIdentity, ...]
    ) -> bool:
        """Require a fresh secure live-chain walk to match every captured identity."""

        chain = self._open_existing_chain(components)
        if chain is None:
            return False
        descriptors, current_identities = chain
        try:
            return current_identities == identities
        finally:
            _close_descriptors(descriptors)

    def _open_matching_chain(
        self, components: tuple[str, ...], identities: tuple[FileIdentity, ...]
    ) -> tuple[int, ...] | None:
        """Open a fresh secure live chain and require every expected identity."""

        chain = self._open_existing_chain(components)
        if chain is None:
            return None
        descriptors, current_identities = chain
        if current_identities == identities:
            return descriptors
        _close_descriptors(descriptors)
        return None

    def _open_pending_chain(
        self, day: str, inventoried_day_identity: FileIdentity
    ) -> tuple[tuple[int, ...], tuple[FileIdentity, ...]] | None:
        """Open the live spool-root -> pending -> day chain from the configured root."""

        chain = self._open_existing_chain((_PENDING, day))
        if chain is None:
            return None
        descriptors, identities = chain
        if identities[-1] == inventoried_day_identity:
            return descriptors, identities
        _close_descriptors(descriptors)
        return None

    def _quarantine_binding_holds(
        self, day: str, identities: tuple[FileIdentity, FileIdentity, FileIdentity]
    ) -> bool:
        """Re-walk spool-root -> quarantine -> day and require its secure captured binding.

        The round-3 review displaced the held day descriptor with a rename after validation, so
        the copy landed outside ``spool/quarantine`` while the source was unlinked. Publication
        and retirement finalization each re-prove that the live pathname still resolves to the
        exact, owned, ACL-free 0700 directories the chain validated; a swap or envelope drift
        refuses destructive cleanup.
        """

        return self._binding_holds((_QUARANTINE, day), identities)

    def _pending_binding_holds(self, day: str, identities: tuple[FileIdentity, ...]) -> bool:
        """Re-prove the exact secure live spool-root -> pending -> day binding."""

        return self._binding_holds((_PENDING, day), identities)

    def _certify_live_target(
        self,
        day: str,
        identities: tuple[FileIdentity, FileIdentity, FileIdentity],
        candidate: str,
        digest: str,
    ) -> FileSnapshot | None:
        """Certify a target reached through a fresh exact secure live-chain walk."""

        chain = self._open_existing_chain((_QUARANTINE, day))
        if chain is None:
            return None
        descriptors, live_identities = chain
        try:
            if live_identities != identities:
                return None
            snapshot = self._certify_target(descriptors[-1], candidate, digest)
            if (
                snapshot is None
                or not _descriptors_match(descriptors, identities)
                or not self._quarantine_binding_holds(day, identities)
            ):
                return None
            return snapshot
        finally:
            _close_descriptors(descriptors)

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
        move copies (the round-2 review reproduced an in-place rewrite being certified as the
        classified file). The source is re-opened no-follow beneath a retained secure
        spool-root -> pending -> day descriptor chain and must match the classification-time
        snapshot exactly; its bytes are read FROM THAT DESCRIPTOR, must hash to the classified
        digest, and the snapshot is
        re-verified after the read — so no name swap or in-place mutation can substitute bytes.
        Publication and adoption each freshly reopen the quarantine chain, require every captured
        identity and access-control envelope, and rebind the live target after certification. A
        copy created by this pass retains a day descriptor used only for exact-copy cleanup, never
        as stale publication or destructive-cleanup authority. Finalization freshly opens pending,
        performs the long target and source checks, and re-proves the pending binding before the
        bounded reservation-and-rename sequence that retires the source under a private name.
        After that reversible rename it re-proves the live target and both namespace bindings
        before deleting the retirement; a failed proof leaves staged bytes for bounded retry. A
        displaced or access-control-drifted chain therefore refuses destructive cleanup
        (round-4/5 P1/P2). The copy is staged and no-replace-published (a
        candidate is only ever absent or complete), fsynced file then directory BEFORE the source
        is touched.
        A pre-existing candidate is adopted ONLY when it passes the full subject envelope
        (owned, exact-0600, single-link, ACL-free, snapshot-stable) AND holds the exact
        classified digest; any foreign or multi-link occupant advances the bounded counter
        (round-3 P1). The retired source, certified target, and complete live bindings are all
        revalidated immediately before retirement cleanup (POSIX offers no ancestor-conditional
        unlink; the exclusive hold and owner-only directories exclude cooperating writers from
        the adjacent syscall window). Returns ``None`` when the classified bytes are
        durably quarantined under the live namespace, ``"unreachable"``/``"changed"``/
        ``"collision"``/``"io"`` when verifiably nothing of this subject's moved (the file stays
        in pending), or ``"uncertain"`` when a copy may exist — or its namespace binding could
        not be re-proven — but the state could not be decided; never a raised error, so one
        unmovable file cannot wedge recovery.
        """

        target_chain = self._open_quarantine_chain(day)
        if target_chain is None:
            return "unreachable"
        target_descriptors, target_identities = target_chain
        _close_descriptors(target_descriptors)
        source_descriptors: tuple[int, ...] = ()
        source_fd: int | None = None
        placed: _PlacedCopy | None = None
        outcome: str | None = "io"
        try:
            source_chain = self._open_pending_chain(day, day_identity)
            if source_chain is None:
                return "changed"
            source_descriptors, source_identities = source_chain
            source_dir_fd = source_descriptors[-1]
            try:
                source_fd = os.open(name, _leaf_probe_flags(), dir_fd=source_dir_fd)
            except OSError:
                return "changed"
            if FileSnapshot.from_stat(os.fstat(source_fd)) != snapshot:
                return "changed"
            content = _read_descriptor(source_fd, snapshot.size)
            if content is None or hashlib.sha256(content).hexdigest() != digest:
                return "changed"
            if FileSnapshot.from_stat(os.fstat(source_fd)) != snapshot:
                return "changed"
            if not self._pending_binding_holds(day, source_identities):
                return "changed"
            if not self._quarantine_binding_holds(day, target_identities):
                return "changed"

            recovered_candidate = _retirement_candidate(name, snapshot)
            if recovered_candidate is None:
                try:
                    name_max = int(os.fpathconf(source_dir_fd, "PC_NAME_MAX"))
                except (OSError, ValueError):
                    return "io"
                candidate_base = _bounded_candidate_base(name, snapshot, digest, name_max)
                if candidate_base is None:
                    return "collision"
                attempts = _MAX_MOVE_ATTEMPTS
            else:
                candidate_base = recovered_candidate
                # The retirement encodes the deterministic candidate-set base. A retry first
                # adopts that exact destination, then may advance through the same bounded
                # counter sequence if the target was subsequently replaced or corrupted.
                attempts = _MAX_MOVE_ATTEMPTS
            for attempt in range(attempts):
                candidate = candidate_base if attempt == 0 else f"{attempt}.{candidate_base}"
                if candidate == _QUARANTINE_STAGE:
                    continue
                published, fresh = self._publish_copy(
                    day, target_identities, candidate, content, digest
                )
                if published == "placed":
                    assert fresh is not None
                    placed = fresh
                    break
                if published == "uncertain":
                    return "uncertain"
                if published == "exists":
                    verdict, adopted_snapshot = self._adopt_existing(
                        day, target_identities, candidate, digest
                    )
                    if verdict == "adopted":
                        assert adopted_snapshot is not None
                        placed = _PlacedCopy(
                            candidate, adopted_snapshot, target_identities, cleanup_fd=None
                        )
                        break
                    if verdict in ("different", "absent"):
                        continue
                    return "uncertain"
                # A failed fresh publication is rechecked through a NEW live chain. This cannot
                # adopt an escaped copy because adoption never reads through the publisher's held
                # descriptor.
                verdict, adopted_snapshot = self._adopt_existing(
                    day, target_identities, candidate, digest
                )
                if verdict == "adopted":
                    assert adopted_snapshot is not None
                    placed = _PlacedCopy(
                        candidate, adopted_snapshot, target_identities, cleanup_fd=None
                    )
                    break
                if verdict in ("different", "absent"):
                    return "io"
                return "uncertain"
            if placed is None:
                return "collision"

            outcome = "uncertain"
            finalized = self._finalize_source_removal(
                day=day,
                name=name,
                source_identities=source_identities,
                source_snapshot=snapshot,
                placed=placed,
                digest=digest,
            )
            if finalized is None:
                return None
            if finalized == "cleanup" and placed.created:
                self._cleanup_created_copy(placed, digest)
            return "uncertain"
        except OSError:
            return outcome
        finally:
            if placed is not None and placed.cleanup_fd is not None:
                try:
                    os.close(placed.cleanup_fd)
                except OSError:  # pragma: no cover - defensive close failure
                    pass
            if source_fd is not None:
                try:
                    os.close(source_fd)
                except OSError:  # pragma: no cover - defensive close failure
                    pass
            _close_descriptors(source_descriptors)

    def _finalize_source_removal(
        self,
        *,
        day: str,
        name: str,
        source_identities: tuple[FileIdentity, ...],
        source_snapshot: FileSnapshot,
        placed: _PlacedCopy,
        digest: str,
    ) -> str | None:
        """Retire the source atomically, re-prove both namespaces, then clean the retirement.

        The public source name is never directly unlinked. It is first moved over a private
        reservation in the same pending day, preserving whichever exact object owned the name at
        that atomic syscall. Only after the retirement snapshot, pending binding, target binding,
        and target copy are all re-proven is the retirement unlinked. A failed proof leaves staged
        recovery evidence for the next bounded inventory.
        """

        final_source_chain = self._open_matching_chain((_PENDING, day), source_identities)
        if final_source_chain is None:
            return "cleanup"
        final_source_fd = final_source_chain[-1]
        recovered_candidate = _retirement_candidate(name, source_snapshot)
        already_retired = recovered_candidate is not None
        retirement = (
            name if already_retired else _retirement_name(source_snapshot, placed.candidate)
        )
        reservation_fd: int | None = None
        reservation_snapshot: FileSnapshot | None = None
        try:
            try:
                initial = os.stat(name, dir_fd=final_source_fd, follow_symlinks=False)
            except FileNotFoundError:
                initial = None
            if (
                self._certify_live_target(day, placed.target_identities, placed.candidate, digest)
                != placed.snapshot
            ):
                return "cleanup"
            if not self._quarantine_binding_holds(day, placed.target_identities):
                return "cleanup"
            try:
                current = os.stat(name, dir_fd=final_source_fd, follow_symlinks=False)
            except FileNotFoundError:
                # Stable prior absence completes an already-retired move. If the source existed
                # at the initial check and then vanished, its binding changed during final
                # certification, so preserve the live copy but report an uncertain outcome.
                return None if initial is None else "uncertain"
            if initial is None or FileSnapshot.from_stat(current) != source_snapshot:
                # The classified target is complete, but a new source object now owns the name.
                # Preserve it for the next inventory rather than deleting unclassified bytes, and
                # do not report an ordinary completion for a source binding we did not retire.
                return "uncertain"
            if FileSnapshot.from_stat(initial) != source_snapshot:
                return "uncertain"

            # Revalidate immediately before creating the private reservation. A06 trusts the
            # installation account across the bounded reservation-and-rename syscall sequence;
            # the post-retirement proofs below report detected namespace drift as uncertain.
            if not self._pending_binding_holds(day, source_identities):
                return "cleanup"

            if not already_retired:
                reservation_fd = os.open(
                    retirement,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=final_source_fd,
                )
                os.fchmod(reservation_fd, 0o600)
                reservation_snapshot = FileSnapshot.from_stat(os.fstat(reservation_fd))
                os.close(reservation_fd)
                reservation_fd = None
                try:
                    os.replace(
                        name,
                        retirement,
                        src_dir_fd=final_source_fd,
                        dst_dir_fd=final_source_fd,
                    )
                except OSError:
                    # A failed rename normally leaves our empty reservation. Remove only that
                    # exact inode; if the rename actually landed despite an ambiguous error, its
                    # different snapshot/digest is preserved for the next inventory.
                    assert reservation_snapshot is not None
                    self._cleanup_candidate_at(
                        final_source_fd,
                        retirement,
                        hashlib.sha256(b"").hexdigest(),
                        reservation_snapshot,
                    )
                    return "uncertain"
                os.fsync(final_source_fd)

                retired_snapshot = self._certify_target(final_source_fd, retirement, digest)
                if retired_snapshot is None or (
                    retired_snapshot.device,
                    retired_snapshot.inode,
                    retired_snapshot.size,
                    retired_snapshot.modified_ns,
                ) != (
                    source_snapshot.device,
                    source_snapshot.inode,
                    source_snapshot.size,
                    source_snapshot.modified_ns,
                ):
                    # A replacement won the final name race or certification became unavailable.
                    # Retain the private name for inventory; restoring with replace would have a
                    # destructive absent-check race against a newly created public source.
                    return "uncertain"

            # Re-prove AFTER the reversible retirement. A namespace displaced during the long
            # digest read or final source decision leaves the classified bytes staged, never gone.
            if (
                self._certify_live_target(day, placed.target_identities, placed.candidate, digest)
                != placed.snapshot
            ):
                return "cleanup"
            if not self._pending_binding_holds(day, source_identities):
                # The source has already been retired. Preserve the separately certified live
                # quarantine copy rather than deleting it and leaving the only known source bytes
                # in a displaced pending namespace.
                return "uncertain"
            if not self._quarantine_binding_holds(day, placed.target_identities):
                return "cleanup"

            try:
                os.unlink(retirement, dir_fd=final_source_fd)
                os.fsync(final_source_fd)
            except OSError:
                # The retirement may remain (unlink failed) or already be gone (its directory
                # fsync failed). Never restore with a destructive replace; the next inventory can
                # safely decide whichever state is durably visible.
                return "uncertain"
            # No further mutation follows. Re-prove both live namespaces and the target so an
            # uncooperative same-UID rename in the unavoidable adjacent-syscall window is at least
            # reported as uncertain rather than falsely claimed as an ordinary completion.
            if not self._pending_binding_holds(day, source_identities):
                return "uncertain"
            if (
                self._certify_live_target(day, placed.target_identities, placed.candidate, digest)
                != placed.snapshot
            ):
                return "uncertain"
            return None
        except OSError:
            return "uncertain"
        finally:
            if reservation_fd is not None:
                try:
                    os.close(reservation_fd)
                except OSError:  # pragma: no cover - defensive close failure
                    pass
            _close_descriptors(final_source_chain)

    def _cleanup_candidate_at(
        self,
        target_fd: int,
        candidate: str,
        digest: str,
        expected_snapshot: FileSnapshot | None = None,
    ) -> bool:
        """Remove and fsync one exact certified candidate through retained authority."""

        try:
            certified = self._certify_target(target_fd, candidate, digest)
            if certified is None or (
                expected_snapshot is not None and certified != expected_snapshot
            ):
                return False
            os.unlink(candidate, dir_fd=target_fd)
            os.fsync(target_fd)
            try:
                os.stat(candidate, dir_fd=target_fd, follow_symlinks=False)
            except FileNotFoundError:
                return True
            return False
        except OSError:
            return False

    def _cleanup_created_copy(self, placed: _PlacedCopy, digest: str) -> bool:
        """Remove only this pass's exact copy through retained cleanup authority and fsync it."""

        target_fd = placed.cleanup_fd
        return target_fd is not None and self._cleanup_candidate_at(
            target_fd, placed.candidate, digest, placed.snapshot
        )

    def _certify_target(self, target_fd: int, candidate: str, digest: str) -> FileSnapshot | None:
        """Prove the candidate is a stable, enveloped copy of the classified bytes right now."""

        descriptor: int | None = None
        certified: FileSnapshot | None = None
        try:
            descriptor = os.open(candidate, _leaf_probe_flags(), dir_fd=target_fd)
            info = os.fstat(descriptor)
            acl_unsafe = False
            try:
                require_no_extended_acl(descriptor)
            except SecureFileError:
                acl_unsafe = True
            if (
                not acl_unsafe
                and _permitted_quarantine_shape(info)
                and info.st_size <= MAX_SEGMENT_FILE_BYTES
            ):
                existing = _read_descriptor(descriptor, info.st_size)
                if (
                    existing is not None
                    and hashlib.sha256(existing).hexdigest() == digest
                    and FileSnapshot.from_stat(os.fstat(descriptor)) == FileSnapshot.from_stat(info)
                ):
                    certified = FileSnapshot.from_stat(info)
        except OSError:
            certified = None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:  # pragma: no cover - defensive close failure
                    certified = None
        return certified

    def _publish_copy(
        self,
        day: str,
        identities: tuple[FileIdentity, FileIdentity, FileIdentity],
        candidate: str,
        content: bytes,
        digest: str,
    ) -> tuple[str, _PlacedCopy | None]:
        """Publish only through a fresh live target chain and retain cleanup authority.

        A descriptor captured before this call is never publication authority. If the fresh chain
        loses its live binding after a candidate appears, this method removes and fsyncs only that
        exact copy; an unproved cleanup is ``"uncertain"``.
        """

        target_descriptors = self._open_matching_chain((_QUARANTINE, day), identities)
        if target_descriptors is None:
            return "failed", None
        stage_fd: int | None = None
        stage_live = False
        candidate_live = False
        published_snapshot: FileSnapshot | None = None
        target_fd = target_descriptors[-1]
        result: tuple[str, _PlacedCopy | None] = ("failed", None)
        try:
            if not _descriptors_match(target_descriptors, identities):
                return result
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
                    os.fchmod(stage_fd, 0o600)
                    break
                except FileExistsError:
                    # our own crash debris beneath our private day directory: clear and retry
                    os.unlink(_QUARANTINE_STAGE, dir_fd=target_fd)
            if stage_fd is None:  # pragma: no cover - two O_EXCL failures require a live racer
                return result
            if content and os.write(stage_fd, content) != len(content):
                return result
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
                return "exists", None
            candidate_live = True
            os.unlink(_QUARANTINE_STAGE, dir_fd=target_fd)
            stage_live = False
            published_snapshot = FileSnapshot.from_stat(os.fstat(stage_fd))
            os.fsync(target_fd)  # the candidate name is durable only after this succeeds
            snapshot = self._certify_target(target_fd, candidate, digest)
            if snapshot is None:
                cleaned = self._cleanup_candidate_at(
                    target_fd, candidate, digest, expected_snapshot=published_snapshot
                )
                candidate_live = not cleaned
                return ("failed" if cleaned else "uncertain"), None
            if snapshot != published_snapshot:
                candidate_live = False  # a fresh live adoption must decide the replacement
                return "failed", None
            live_snapshot = self._certify_live_target(day, identities, candidate, digest)
            if not self._quarantine_binding_holds(day, identities) or not _descriptors_match(
                target_descriptors, identities
            ):
                cleaned = self._cleanup_candidate_at(
                    target_fd, candidate, digest, expected_snapshot=snapshot
                )
                candidate_live = not cleaned
                return ("failed" if cleaned else "uncertain"), None
            if live_snapshot != snapshot:
                candidate_live = False  # the live fresh adoption path must make the decision
                return "failed", None
            cleanup_fd = os.dup(target_fd)
            candidate_live = False  # ownership transfers to the returned cleanup descriptor
            result = (
                "placed",
                _PlacedCopy(candidate, snapshot, identities, cleanup_fd=cleanup_fd),
            )
            return result
        except OSError:
            if stage_live:
                try:
                    os.unlink(_QUARANTINE_STAGE, dir_fd=target_fd)
                    stage_live = False
                    if candidate_live and stage_fd is not None:
                        published_snapshot = FileSnapshot.from_stat(os.fstat(stage_fd))
                except OSError:
                    pass
            if candidate_live:
                if self._quarantine_binding_holds(day, identities) and _descriptors_match(
                    target_descriptors, identities
                ):
                    candidate_live = False  # preserve for the caller's fresh adoption proof
                    return "failed", None
                if published_snapshot is None:
                    return "uncertain", None
                cleaned = self._cleanup_candidate_at(
                    target_fd, candidate, digest, expected_snapshot=published_snapshot
                )
                candidate_live = not cleaned
                return ("failed" if cleaned else "uncertain"), None
            return result
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
            if candidate_live and published_snapshot is not None:
                self._cleanup_candidate_at(
                    target_fd, candidate, digest, expected_snapshot=published_snapshot
                )
            _close_descriptors(target_descriptors)

    def _adopt_existing(
        self,
        day: str,
        identities: tuple[FileIdentity, FileIdentity, FileIdentity],
        candidate: str,
        digest: str,
    ) -> tuple[str, FileSnapshot | None]:
        """Examine an existing candidate: adopt it only as a stable, ENVELOPED classified copy.

        The round-3 review pre-placed a same-digest foreign HARD LINK at the candidate name: a
        digest match alone certified a copy that stayed mutable through its outside alias while
        the source was deleted. Adoption therefore requires the full subject envelope — owned,
        exact-0600, single-link, ACL-free regular file within the size bound — plus a stable
        before/after ``FileSnapshot`` around the digest read; a foreign, multi-link, loose, or
        mutating occupant is ``"different"`` (a collision that advances the counter), never an
        interrupted move. Returns ``("adopted", snapshot)`` with the copy re-fsynced (file and
        directory) and its exact certified identity, ``("different", None)``,
        ``("absent", None)``, or ``("unknown", None)`` (could not be examined or made durable —
        the caller must not claim a clean outcome).
        """

        target_descriptors = self._open_matching_chain((_QUARANTINE, day), identities)
        if target_descriptors is None:
            return ("unknown", None)
        descriptor: int | None = None
        verdict = "unknown"
        snapshot: FileSnapshot | None = None
        target_fd = target_descriptors[-1]
        try:
            if not _descriptors_match(target_descriptors, identities):
                return ("unknown", None)
            try:
                descriptor = os.open(candidate, _leaf_probe_flags(), dir_fd=target_fd)
            except FileNotFoundError:
                return ("absent", None)
            except OSError as error:
                if error.errno == errno.ELOOP:
                    return ("different", None)  # a symlink is never our copy — never followed
                raise
            info = os.fstat(descriptor)
            acl_unsafe = False
            try:
                require_no_extended_acl(descriptor)
            except SecureFileError:
                acl_unsafe = True
            if (
                acl_unsafe
                or not _permitted_quarantine_shape(info)
                or info.st_size > MAX_SEGMENT_FILE_BYTES
            ):
                return ("different", None)  # outside the envelope: never ours, never adopted
            before = FileSnapshot.from_stat(info)
            existing = _read_descriptor(descriptor, info.st_size)
            if existing is None:
                return ("unknown", None)
            if hashlib.sha256(existing).hexdigest() != digest:
                return ("different", None)
            if FileSnapshot.from_stat(os.fstat(descriptor)) != before:
                return ("unknown", None)  # mutated during adoption: never certified
            os.fsync(descriptor)
            os.fsync(target_fd)
            if FileSnapshot.from_stat(os.fstat(descriptor)) != before:
                return ("unknown", None)  # mutated while being made durable
            if (
                not self._quarantine_binding_holds(day, identities)
                or self._certify_live_target(day, identities, candidate, digest) != before
                or not _descriptors_match(target_descriptors, identities)
            ):
                return ("unknown", None)
            verdict = "adopted"
            snapshot = before
            return (verdict, snapshot)
        except OSError:
            return (verdict, None)
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:  # pragma: no cover - defensive close failure
                    pass
            _close_descriptors(target_descriptors)

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
        resolved_spool = _require_bound_state_root(database, barrier, spool_root, installation_id)
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
