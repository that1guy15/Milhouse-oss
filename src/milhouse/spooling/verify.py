"""Read-only spool audit — ``spool verify`` (W03 slice 5a, plan sections 4.4/4.9).

``spool verify`` re-validates every committed segment against its ledger row WITHOUT mutating
anything, so an operator or the health surface can confirm the durable spool is intact and see its
delivery watermark. It is the read-only counterpart to reconciliation (which registers file→ledger
orphans) and replay (which reprocesses trusted state): verify walks ledger→file and reports the
integrity of each committed segment.

Crucially, verify differs from replay in its failure posture. Replay fails closed on the first bad
segment because it is about to reprocess trusted state; verify instead EXAMINES EVERY segment and
RECORDS which are unhealthy, so one corrupt or missing file never hides the state of the rest. For
each committed segment it opens the durable file through :func:`read_trusted_segment` (no-follow,
owner-only, canonical, record-authentic) and cross-checks it against the ledger row using
reconciliation's canonical agreement predicate — every file-attestable immutable field (batch id,
day, config generation, scope/target, privacy/retention class, required exporters, count) plus both
digests and byte size — so a post-commit ledger edit of a policy field with intact bytes is caught,
not just digest drift. Any failure is captured as that segment's fixed ``MH_SPOOL_*`` code rather
than raised. It also reports the destination delivery watermark — whether every required exporter is
delivered. Backup watermarks are a W16 concern and are out of scope here.

The report-don't-raise resilience is scoped to the durable *files*: a malformed ledger *row* (one
that fails ledger-row validation) surfaces as a single fixed ``MH_SPOOL_LEDGER`` from the ledger
read and stops the pass, exactly as it does for replay — a corrupt control row is a harder fault
than a bad file and is not something an audit silently rides over.

Verify never writes and never holds the barrier across the pass (that would block maintenance while
auditing every segment); the trusted reader's own mutation detection classifies a file that changes
mid-read. Only an argument-validation fault raises a fixed ``MH_SPOOL_*`` error outside the handler.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, cast

from milhouse.config.filesystem import SecureFileError, lexical_absolute_path
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.ledger import SegmentRecord, list_segment_records
from milhouse.spooling.reader import INSTALLATION_ID_PATTERN, read_trusted_segment
from milhouse.spooling.reconcile import _agrees
from milhouse.state.database import ControlDatabase, _validated_database_path

_PENDING = "pending"
_SPOOL = "spool"
_DELIVERED = "delivered"


def _require_bound_spool_root(database: ControlDatabase, spool_root: object) -> Path:
    """Resolve ``spool_root`` and require it to be this database's ``<state_root>/spool``.

    Without this bind, verify would happily certify a *shadow* copy of the spool as intact while the
    authoritative segment for the selected control database is missing or corrupt, so health could
    read green over a lost durable record. Fail closed on a mismatch (as retention does).
    """

    database_path = _validated_database_path(database)
    if database_path is None:
        _fail("MH_SPOOL_VERIFY", "a control database is required")
    if not isinstance(spool_root, (str, os.PathLike)):
        _fail("MH_SPOOL_VERIFY", "a spool root path is required")
    try:
        resolved = lexical_absolute_path(cast("str | Path", spool_root))
    except SecureFileError:
        _fail("MH_SPOOL_VERIFY", "a spool root path is required")
    if resolved != database_path.parent.parent / _SPOOL:
        _fail("MH_SPOOL_VERIFY", "the spool root must be <state_root>/spool")
    return resolved


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


@dataclass(frozen=True, slots=True)
class SegmentVerification:
    """The audit result for one committed segment.

    ``intact`` is the integrity verdict (durable file present, canonical, record-authentic, and in
    exact agreement with the ledger row); ``code`` is the fixed classification when it is not
    intact, and ``None`` when it is. ``delivered`` is a separate delivery-watermark dimension — an
    intact segment that has not finished delivery is still healthy, just not yet exported.
    """

    batch_id: str
    intact: bool
    code: str | None
    delivered: bool


@dataclass(frozen=True, slots=True)
class VerifyReport:
    """The result of one read-only verification pass over the committed segments."""

    segments: tuple[SegmentVerification, ...]

    @property
    def intact(self) -> bool:
        """True iff every audited segment agrees with its ledger row."""

        return all(segment.intact for segment in self.segments)

    @property
    def fully_delivered(self) -> bool:
        """True iff every audited segment has delivered to all its required exporters."""

        return all(segment.delivered for segment in self.segments)

    @property
    def compromised(self) -> tuple[SegmentVerification, ...]:
        """The segments that failed the integrity check, in audit order."""

        return tuple(segment for segment in self.segments if not segment.intact)


def _verify_segment(record: SegmentRecord, spool_root: Path, installation_id: str) -> str | None:
    """Return ``None`` if the segment is intact, else the fixed ``MH_SPOOL_*`` classification."""

    path = spool_root / _PENDING / record.day / f"{record.batch_id}.jsonl"
    try:
        parsed = read_trusted_segment(path, installation_id=installation_id)
    except SpoolError as error:
        # The reader classifies every corruption/absence/provenance failure into a fixed code;
        # record it as this segment's status and keep auditing the rest.
        return error.code
    # Reuse reconciliation's canonical ledger-agreement predicate — the single source of truth for
    # "does this durable file match its committing row" — so verify checks every file-attestable
    # immutable field (batch id, day, config generation, scope/target, privacy/retention class,
    # required exporters, count, and both digests), not just the digests. A post-commit ledger edit
    # of a policy field with intact bytes is therefore caught, and verify can never diverge from
    # what reconciliation would accept.
    if not _agrees(parsed, record.day, record.batch_id, record):
        return "MH_SPOOL_VERIFY"
    return None


def verify_spool(
    database: ControlDatabase,
    *,
    spool_root: str | Path,
    installation_id: str,
) -> VerifyReport:
    """Audit every committed segment against its ledger row without mutating anything.

    Each segment is examined independently and its integrity verdict plus delivery watermark are
    recorded; a corrupt or missing file is reported, never raised, so the report always reflects the
    whole spool. The pass holds no barrier, so it never blocks a concurrent commit or maintenance.
    """

    if type(database) is not ControlDatabase:
        _fail("MH_SPOOL_VERIFY", "a control database is required")
    root = _require_bound_spool_root(database, spool_root)
    if (
        type(installation_id) is not str
        or INSTALLATION_ID_PATTERN.fullmatch(installation_id) is None
    ):
        _fail("MH_SPOOL_IDENTITY", "a well-formed installation id is required")

    records = list_segment_records(database)
    verifications: list[SegmentVerification] = []
    for record in records:
        code = _verify_segment(record, root, installation_id)
        delivered = all(exporter.delivery_status == _DELIVERED for exporter in record.exporters)
        verifications.append(
            SegmentVerification(
                batch_id=record.batch_id,
                intact=code is None,
                code=code,
                delivered=delivered,
            )
        )
    return VerifyReport(segments=tuple(verifications))
