"""Per-rule/version canary alert-engine state (W05 alerting, plan section 4.6).

The ``canary_state`` alert engine projects committed availability records into system-derived alert
transitions. Its per-rule state records the consecutive fail/success counters, the current
``inactive|firing|resolved`` state, the cooldown and last-sample instants, the last emitted
transition id, and a monotonic ``revision``, keyed by ``(rule_id, rule_version)`` so a rule-logic
revision starts from clean counters rather than silently inheriting the prior version's. Derivation
must be restartable and idempotent: :func:`advance_alert_state` advances only via a compare-and-set
against the exact revision the caller last observed, so a crash-restart or a concurrent pass cannot
fork or double-advance current alert state — the loser fails closed and re-reads.

This mirrors :mod:`milhouse.state.derivation`: the same projection-CAS protocol the plan requires
(section 4.6, "the same segment-ledger plus SQLite projection CAS protocol used for feedback"). The
row carries no raw payload — only bounded counters, a coded state, timestamp strings, and opaque
ids. Every SQLite or time failure normalizes to a stable ``MH_STATE_*`` code raised outside the
handler, so no backend detail reaches the error's cause, context, args, or traceback.
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

_ALERT_STATE_TABLE = "_alert_rule_state"
_ALERT_STATES = ("inactive", "firing", "resolved")
_MAX_TEXT_BYTES = 256


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


@dataclass(frozen=True, slots=True)
class AlertRuleState:
    """A per-rule/version canary alert-engine state row as recorded in the control database."""

    rule_id: str
    rule_version: int
    consecutive_fail_count: int
    consecutive_success_count: int
    current_state: str
    cooldown_until: str | None
    last_sample_at: str | None
    last_transition_id: str | None
    revision: int
    updated_at: str


def _validate_identifier(value: object, code: str, subject: str) -> str:
    if type(value) is not str or not value or len(value) > _MAX_TEXT_BYTES:
        _fail(code, f"an alert {subject} must be bounded non-empty text")
    return value


def _validate_positive(value: object, code: str, subject: str) -> int:
    # ``bool`` is an ``int`` subtype; reject it so a stray flag cannot pose as a version.
    if type(value) is not int or value < 1:
        _fail(code, f"an alert {subject} must be a whole number >= 1")
    return value


def _validate_count(value: object, subject: str) -> int:
    if type(value) is not int or value < 0:
        _fail("MH_STATE_ALERT_COUNT", f"an alert {subject} must be a whole number >= 0")
    return value


def _validate_state(value: object) -> str:
    if type(value) is not str or value not in _ALERT_STATES:
        _fail(
            "MH_STATE_ALERT_STATE", "an alert current state must be inactive, firing, or resolved"
        )
    return value


def _validate_optional_text(value: object, code: str, subject: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value or len(value) > _MAX_TEXT_BYTES:
        _fail(code, f"an alert {subject} must be absent or bounded non-empty text")
    return value


def _validate_revision(value: object) -> int:
    if type(value) is not int or value < 0:
        _fail(
            "MH_STATE_ALERT_REVISION",
            "an expected alert revision must be a whole number >= 0",
        )
    return value


def _row_to_state(row: Sequence[Any]) -> AlertRuleState:
    return AlertRuleState(
        rule_id=str(row[0]),
        rule_version=int(row[1]),
        consecutive_fail_count=int(row[2]),
        consecutive_success_count=int(row[3]),
        current_state=str(row[4]),
        cooldown_until=None if row[5] is None else str(row[5]),
        last_sample_at=None if row[6] is None else str(row[6]),
        last_transition_id=None if row[7] is None else str(row[7]),
        revision=int(row[8]),
        updated_at=str(row[9]),
    )


def read_alert_state(
    database: ControlDatabase, rule_id: str, rule_version: int
) -> AlertRuleState | None:
    """Return the alert state for ``(rule_id, rule_version)``, or ``None`` if it never advanced."""

    _validate_identifier(rule_id, "MH_STATE_ALERT_RULE", "rule id")
    _validate_positive(rule_version, "MH_STATE_ALERT_VERSION", "rule version")
    row: tuple[object, ...] | None = None
    failed = False
    try:
        row = database.connection.execute(
            "SELECT rule_id, rule_version, consecutive_fail_count, consecutive_success_count, "
            "current_state, cooldown_until, last_sample_at, last_transition_id, revision, "
            f"updated_at FROM {_ALERT_STATE_TABLE} WHERE rule_id = ? AND rule_version = ?",
            (rule_id, rule_version),
        ).fetchone()
    except sqlite3.Error:
        failed = True
    if failed:
        _fail("MH_STATE_ALERT", "the alert rule state could not be read")
    return None if row is None else _row_to_state(row)


def advance_alert_state(
    database: ControlDatabase,
    rule_id: str,
    rule_version: int,
    *,
    consecutive_fail_count: int,
    consecutive_success_count: int,
    current_state: str,
    cooldown_until: str | None,
    last_sample_at: str | None,
    last_transition_id: str | None,
    now: datetime,
    expected_revision: int,
) -> AlertRuleState:
    """Advance ``(rule_id, rule_version)`` to the new alert state via compare-and-set.

    ``expected_revision`` is the revision the caller last observed (``0`` if the state has never
    advanced). The advance runs in one transaction that asserts the stored revision still equals
    ``expected_revision``; on mismatch it fails closed with ``MH_STATE_ALERT_CONFLICT`` without
    writing, so a restarted or concurrent alert-derivation pass cannot fork or double-advance the
    projection. Every advance bumps the revision by one — even a counter-only sample that emitted no
    transition — so the compare-and-set stays sound across steady-state polls.
    """

    _validate_identifier(rule_id, "MH_STATE_ALERT_RULE", "rule id")
    _validate_positive(rule_version, "MH_STATE_ALERT_VERSION", "rule version")
    _validate_count(consecutive_fail_count, "consecutive fail count")
    _validate_count(consecutive_success_count, "consecutive success count")
    _validate_state(current_state)
    _validate_optional_text(cooldown_until, "MH_STATE_ALERT_TIMESTAMP", "cooldown instant")
    _validate_optional_text(last_sample_at, "MH_STATE_ALERT_TIMESTAMP", "last sample instant")
    _validate_optional_text(last_transition_id, "MH_STATE_ALERT_TRANSITION", "last transition id")
    _validate_revision(expected_revision)
    state: AlertRuleState | None = None
    failed = False
    try:
        updated_at = format_timestamp(now)
        with database.transaction() as connection:
            existing = connection.execute(
                f"SELECT revision FROM {_ALERT_STATE_TABLE} WHERE rule_id = ? AND rule_version = ?",
                (rule_id, rule_version),
            ).fetchone()
            current_revision = int(existing[0]) if existing is not None else 0
            if current_revision != expected_revision:
                _fail(
                    "MH_STATE_ALERT_CONFLICT",
                    "the alert rule state was advanced concurrently",
                )
            revision = current_revision + 1
            connection.execute(
                f"INSERT INTO {_ALERT_STATE_TABLE} "
                "(rule_id, rule_version, consecutive_fail_count, consecutive_success_count, "
                "current_state, cooldown_until, last_sample_at, last_transition_id, revision, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(rule_id, rule_version) DO UPDATE SET "
                "consecutive_fail_count = excluded.consecutive_fail_count, "
                "consecutive_success_count = excluded.consecutive_success_count, "
                "current_state = excluded.current_state, "
                "cooldown_until = excluded.cooldown_until, "
                "last_sample_at = excluded.last_sample_at, "
                "last_transition_id = excluded.last_transition_id, "
                "revision = excluded.revision, updated_at = excluded.updated_at",
                (
                    rule_id,
                    rule_version,
                    consecutive_fail_count,
                    consecutive_success_count,
                    current_state,
                    cooldown_until,
                    last_sample_at,
                    last_transition_id,
                    revision,
                    updated_at,
                ),
            )
        state = AlertRuleState(
            rule_id=rule_id,
            rule_version=rule_version,
            consecutive_fail_count=consecutive_fail_count,
            consecutive_success_count=consecutive_success_count,
            current_state=current_state,
            cooldown_until=cooldown_until,
            last_sample_at=last_sample_at,
            last_transition_id=last_transition_id,
            revision=revision,
            updated_at=updated_at,
        )
    except (sqlite3.Error, OverflowError, TimeError):
        failed = True
    if failed:
        _fail("MH_STATE_ALERT", "the alert rule state could not be advanced")
    assert state is not None
    return state
