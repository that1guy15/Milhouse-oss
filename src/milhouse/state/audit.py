"""Append-only maintenance audit trail (W03 slice 5b, plan sections 4.4/4.6/4.9; D05 privacy fix).

Every deliberate maintenance mutation — retention pruning, purge, restore — records one
append-only row in ``_audit`` describing what happened in privacy-safe terms: a fixed action code, a
fixed actor class, a fixed outcome and reason code, an optional KEYED resource pseudonym, and safe
counts. An audit row never carries the acted-on raw payload, a secret, a path, a URL, or free text
(plan section 4.6 ``audit``, ADR 0007).

The public surface is a set of **purpose-specific constructors** (e.g.
:func:`record_retention_prune`) rather than a free-text sink: each constructor fixes its own
action/actor/outcome/reason codes as constants, so a caller cannot inject arbitrary text into those
fields. The one caller-supplied identifier — a batch id — is charset-validated and, per plan section
4.7, may be persisted ONLY as an installation-keyed HMAC pseudonym, never as a public unsalted hash
(a plain SHA-256 of a low-entropy id is dictionary-recoverable and correlates across installations).
The pseudonym key is created by ``init`` (W06) and is not yet wired into the control plane, so when
no :class:`~milhouse.privacy.pseudonym.Pseudonymizer` is supplied the identifier derivative is
OMITTED (the resource is ``NULL``) rather than stored reversibly — exactly as ``spooling/reconcile``
already does. Recording is transaction-scoped: the caller writes the row on the SAME open
connection, in the SAME transaction as the mutation it attests, so the trail and the state commit or
roll back together. Every fault normalizes to a fixed ``MH_STATE_AUDIT`` code raised outside the
handler.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn

from milhouse.core.clock import TimeError, format_timestamp
from milhouse.privacy.pseudonym import Pseudonymizer
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_AUDIT_TABLE = "_audit"
_MAX_COUNT = 2**63 - 1  # the largest value SQLite's signed 64-bit INTEGER can store
_DEFAULT_LIMIT = 1000
_MAX_LIMIT = 100_000
# An opaque resource identifier: a batch/target id shape. It admits ``[A-Za-z0-9._-]`` starting
# alphanumeric and so rejects every raw-text canary — a path (``/``), email (``@``), URL (``://``),
# prompt or multiline (whitespace/newline), and most secret/payload shapes.
_RESOURCE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", flags=re.ASCII)


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One append-only maintenance audit entry as recorded in the control database."""

    id: int
    recorded_at: str
    action: str
    actor: str
    outcome: str
    resource: str | None
    reason: str | None
    record_count: int | None
    byte_size: int | None
    content_sha256: str | None
    file_sha256: str | None


def _validate_resource(value: object) -> str:
    if type(value) is not str or _RESOURCE_PATTERN.fullmatch(value) is None:
        _fail("MH_STATE_AUDIT", "an audit resource must be an opaque identifier, not free text")
    return value


_RESOURCE_KIND = "batch"
_MAX_RESOURCE_BYTES = 128
# A keyed fingerprint for kind "batch" is exactly ``mh_fp1_e{epoch}_batch_{base32}``: an epoch of
# 1..2^31-1 and the lowercase base32 (52 chars) of the 32-byte SHA-256 HMAC digest. The audit
# boundary validates the pseudonymizer's output against this canonical grammar so a buggy
# Pseudonymizer cannot persist a secret-shaped, wrong-kind, or overlong value.
_FINGERPRINT_TOKEN = re.compile(r"mh_fp1_e[1-9][0-9]{0,9}_batch_[a-z2-7]{52}", flags=re.ASCII)


def _keyed_resource(pseudonymizer: Pseudonymizer | None, batch_id: str) -> str | None:
    """Return the keyed HMAC pseudonym of ``batch_id``, or ``None`` when no key is wired.

    Plan section 4.7 requires a persisted identifier derivative to be a keyed installation-local
    HMAC pseudonym, never a public unsalted hash. When no pseudonymizer is supplied the derivative
    is OMITTED (``None``) rather than persisted as a reversible hash — the precedent
    ``spooling/reconcile`` sets. When a key is wired, the same call yields a keyed ``mh_fp1_``
    token, no schema change.

    Derivation happens INSIDE a trusted boundary: the argument must be the exact concrete
    :class:`~milhouse.privacy.pseudonym.Pseudonymizer` type (``type(...) is Pseudonymizer``), not a
    subclass or a look-alike proxy. A grammar check alone is not proof of keyed derivation — an
    overridable ``fingerprint`` could return a canonical-*shaped* value derived from caller
    input (G03 review finding #2), so the type gate ensures the real HMAC method runs. The output is
    then ALSO validated against the exact ``mh_fp1_..._batch_...`` grammar and length bound as
    defence in depth, failing closed with a fixed code on any deviation.
    """

    if pseudonymizer is None:
        return None
    if type(pseudonymizer) is not Pseudonymizer:
        # Reject any subclass or look-alike proxy: only the concrete trusted type derives here, so a
        # caller cannot substitute an overriding ``fingerprint`` that echoes shaped input.
        _fail("MH_STATE_AUDIT", "audit lineage requires the trusted Pseudonymizer type")
    token = pseudonymizer.fingerprint(_RESOURCE_KIND, batch_id)
    if (  # pragma: no cover - the trusted Pseudonymizer always yields a canonical token
        not isinstance(token, str)
        or len(token) > _MAX_RESOURCE_BYTES
        or _FINGERPRINT_TOKEN.fullmatch(token) is None
    ):
        _fail("MH_STATE_AUDIT", "the audit pseudonym is not a valid keyed token")
    return token


def _validate_count(value: object, subject: str) -> int:
    # ``bool`` is an ``int`` subtype; reject it so a stray flag cannot pose as a count. The upper
    # bound keeps a too-large count from overflowing the signed-64 INTEGER binding at INSERT.
    if type(value) is not int or not 0 <= value <= _MAX_COUNT:
        _fail("MH_STATE_AUDIT", f"an audit {subject} must be a whole number in 0..2^63-1")
    return value


def _insert_audit(
    connection: sqlite3.Connection,
    *,
    now: datetime,
    action: str,
    actor: str,
    outcome: str,
    resource: str | None,
    reason: str,
    record_count: int,
    byte_size: int,
    content_sha256: str | None = None,
    file_sha256: str | None = None,
) -> None:
    """Insert one audit row. Internal: only the typed constructors call it, with fixed codes.

    ``action``/``actor``/``outcome``/``reason`` are code constants owned by the calling constructor,
    never caller free text; ``resource`` is a keyed pseudonym or ``None`` and the counts are the
    already-validated caller data. ``content_sha256``/``file_sha256`` are high-entropy digests of
    the acted-on segment bytes (immutable evidence), NULL for actions that have none. Only the
    timestamp is validated here before the insert; any residual backend fault normalizes to the
    fixed code.
    """

    invalid_time = False
    recorded_at = ""
    try:
        recorded_at = format_timestamp(now)
    except (OverflowError, TimeError):
        invalid_time = True
    if invalid_time:
        _fail("MH_STATE_AUDIT", "an audit timestamp must be an aware in-range UTC instant")
    failed = False
    try:
        connection.execute(
            f"INSERT INTO {_AUDIT_TABLE} "
            "(recorded_at, action, actor, outcome, resource, reason, record_count, byte_size, "
            "content_sha256, file_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                recorded_at,
                action,
                actor,
                outcome,
                resource,
                reason,
                record_count,
                byte_size,
                content_sha256,
                file_sha256,
            ),
        )
    except (sqlite3.Error, OverflowError):
        # Normalize any residual backend fault to the fixed code raised outside the handler, so no
        # SQLite/binding detail escapes; the caller's transaction still rolls back.
        failed = True
    if failed:
        _fail("MH_STATE_AUDIT", "the audit row could not be recorded")


def record_retention_prune(
    connection: sqlite3.Connection,
    *,
    now: datetime,
    batch_id: str,
    record_count: int,
    byte_size: int,
    undelivered: bool,
    pseudonymizer: Pseudonymizer | None = None,
) -> None:
    """Record that retention pruned one committed segment, on the caller's open transaction.

    The action/actor/outcome/reason codes are fixed here, so no free text reaches the audit row. The
    only caller-supplied identifier is ``batch_id``: it is charset-validated and persisted only as a
    keyed pseudonym when ``pseudonymizer`` is supplied, and OMITTED (resource ``NULL``) otherwise,
    so a reversible unsalted hash is never stored (plan section 4.7). ``undelivered`` distinguishes
    the critical case where the segment reached its privacy deadline before it was exported. Call
    inside the same transaction as the prune so the two commit or roll back together.
    """

    if type(undelivered) is not bool:
        _fail("MH_STATE_AUDIT", "the undelivered flag must be a boolean")
    _validate_resource(batch_id)
    _validate_count(record_count, "record count")
    _validate_count(byte_size, "byte size")
    _insert_audit(
        connection,
        now=now,
        action="retention_prune",
        actor="maintenance",
        outcome="pruned_undelivered" if undelivered else "pruned",
        reason="expired_undelivered" if undelivered else "expired",
        resource=_keyed_resource(pseudonymizer, batch_id),
        record_count=record_count,
        byte_size=byte_size,
    )


def _row_to_audit(row: Sequence[Any]) -> AuditRecord:
    return AuditRecord(
        id=int(row[0]),
        recorded_at=str(row[1]),
        action=str(row[2]),
        actor=str(row[3]),
        outcome=str(row[4]),
        resource=None if row[5] is None else str(row[5]),
        reason=None if row[6] is None else str(row[6]),
        record_count=None if row[7] is None else int(row[7]),
        byte_size=None if row[8] is None else int(row[8]),
        content_sha256=None if row[9] is None else str(row[9]),
        file_sha256=None if row[10] is None else str(row[10]),
    )


def list_audit(
    database: ControlDatabase, *, action: str | None = None, limit: int = _DEFAULT_LIMIT
) -> tuple[AuditRecord, ...]:
    """Return audit rows in append order (oldest first), optionally filtered to one ``action``."""

    if type(limit) is not int or not 0 < limit <= _MAX_LIMIT:
        _fail("MH_STATE_AUDIT", "an audit read limit must be a whole number in 1..100000")
    if action is not None and (type(action) is not str or not action):
        _fail("MH_STATE_AUDIT", "an audit action filter must be non-empty text")
    rows: list[tuple[Any, ...]] = []
    failed = False
    columns = (
        "id, recorded_at, action, actor, outcome, resource, reason, record_count, byte_size, "
        "content_sha256, file_sha256"
    )
    try:
        if action is None:
            rows = database.connection.execute(
                f"SELECT {columns} FROM {_AUDIT_TABLE} ORDER BY id LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = database.connection.execute(
                f"SELECT {columns} FROM {_AUDIT_TABLE} WHERE action = ? ORDER BY id LIMIT ?",
                (action, limit),
            ).fetchall()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("MH_STATE_AUDIT", "the audit trail could not be read")
    return tuple(_row_to_audit(row) for row in rows)
