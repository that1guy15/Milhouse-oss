"""Per-rule/version derivation checkpoints (W03 slice 4, pipeline rule 10).

A derivation rule projects committed records into a downstream view (alerts, feedback, rollups).
Its checkpoint records how far the rule has processed, keyed by ``(rule, rule_version)`` so a
rule-logic revision starts from a clean position rather than silently inheriting the prior
version's. Derivation must be restartable and idempotent: :func:`advance_checkpoint` advances only
via a compare-and-set against the exact revision the caller last observed, so a crash-restart or a
concurrent pass cannot fork or double-advance the projection — the loser fails closed and re-reads.

Unlike a source cursor, a checkpoint is not tied to one segment (it tracks a projection frontier,
not an ingestion offset), so it carries no segment foreign key. ``position`` is an opaque,
rule-defined coordinate carrying no raw payload. Acyclicity of the derivation graph is a registry
concern; this primitive only guarantees a single rule's checkpoint advances monotonically and
safely. Every SQLite or time failure normalizes to a stable ``MH_STATE_*`` code raised outside the
handler.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn

from milhouse.core.clock import TimeError, format_timestamp
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_CHECKPOINTS_TABLE = "_derivation_checkpoints"


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


@dataclass(frozen=True, slots=True)
class DerivationCheckpoint:
    """A per-rule/version derivation checkpoint as recorded in the control database."""

    rule: str
    rule_version: int
    position: str
    revision: int
    updated_at: str


def _validate_identifier(value: object, code: str, subject: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        _fail(code, f"a derivation {subject} must be bounded non-empty text")
    return value


def _validate_positive(value: object, code: str, subject: str) -> int:
    # ``bool`` is an ``int`` subtype; reject it so a stray flag cannot pose as a version.
    if type(value) is not int or value < 1:
        _fail(code, f"a derivation {subject} must be a whole number >= 1")
    return value


def _validate_revision(value: object) -> int:
    if type(value) is not int or value < 0:
        _fail(
            "MH_STATE_DERIVATION_REVISION",
            "an expected derivation revision must be a whole number >= 0",
        )
    return value


def _row_to_checkpoint(row: Sequence[Any]) -> DerivationCheckpoint:
    return DerivationCheckpoint(
        rule=str(row[0]),
        rule_version=int(row[1]),
        position=str(row[2]),
        revision=int(row[3]),
        updated_at=str(row[4]),
    )


def read_checkpoint(
    database: ControlDatabase, rule: str, rule_version: int
) -> DerivationCheckpoint | None:
    """Return the checkpoint for ``(rule, rule_version)``, or ``None`` if it has never advanced."""

    _validate_identifier(rule, "MH_STATE_DERIVATION_RULE", "rule")
    _validate_positive(rule_version, "MH_STATE_DERIVATION_VERSION", "rule version")
    row: tuple[object, ...] | None = None
    failed = False
    try:
        row = database.connection.execute(
            f"SELECT rule, rule_version, position, revision, updated_at "
            f"FROM {_CHECKPOINTS_TABLE} WHERE rule = ? AND rule_version = ?",
            (rule, rule_version),
        ).fetchone()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("MH_STATE_DERIVATION", "the derivation checkpoint could not be read")
    return None if row is None else _row_to_checkpoint(row)


def advance_checkpoint(
    database: ControlDatabase,
    rule: str,
    rule_version: int,
    *,
    position: str,
    now: datetime,
    expected_revision: int,
) -> DerivationCheckpoint:
    """Advance ``(rule, rule_version)`` to ``position`` via compare-and-set.

    ``expected_revision`` is the revision the caller last observed (``0`` if the checkpoint has
    never advanced). The advance runs in one transaction that asserts the stored revision still
    equals ``expected_revision``; on mismatch it fails closed without writing, so a restarted or
    concurrent derivation pass cannot fork or double-advance the projection.
    """

    _validate_identifier(rule, "MH_STATE_DERIVATION_RULE", "rule")
    _validate_positive(rule_version, "MH_STATE_DERIVATION_VERSION", "rule version")
    _validate_identifier(position, "MH_STATE_DERIVATION_POSITION", "position")
    _validate_revision(expected_revision)
    checkpoint: DerivationCheckpoint | None = None
    failed = False
    try:
        updated_at = format_timestamp(now)
        with database.transaction() as connection:
            existing = connection.execute(
                f"SELECT revision FROM {_CHECKPOINTS_TABLE} WHERE rule = ? AND rule_version = ?",
                (rule, rule_version),
            ).fetchone()
            current_revision = int(existing[0]) if existing is not None else 0
            if current_revision != expected_revision:
                _fail(
                    "MH_STATE_DERIVATION_CONFLICT",
                    "the derivation checkpoint was advanced concurrently",
                )
            revision = current_revision + 1
            connection.execute(
                f"INSERT INTO {_CHECKPOINTS_TABLE} "
                "(rule, rule_version, position, revision, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(rule, rule_version) DO UPDATE SET position = excluded.position, "
                "revision = excluded.revision, updated_at = excluded.updated_at",
                (rule, rule_version, position, revision, updated_at),
            )
        checkpoint = DerivationCheckpoint(
            rule=rule,
            rule_version=rule_version,
            position=position,
            revision=revision,
            updated_at=updated_at,
        )
    except (sqlite3.Error, OverflowError, TimeError):
        failed = True
    if failed:
        _fail("MH_STATE_DERIVATION", "the derivation checkpoint could not be advanced")
    assert checkpoint is not None
    return checkpoint
