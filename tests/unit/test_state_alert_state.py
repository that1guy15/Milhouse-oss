"""Behavioural guarantees for per-rule/version canary alert-engine state (W05 alerting).

The alert state advances only via a compare-and-set against the revision the caller last observed,
so a restarted or concurrent alert-derivation pass cannot fork or double-advance current state. A
rule-logic revision (a new ``rule_version``) starts from clean counters rather than inheriting the
prior version's. This mirrors the derivation-checkpoint suite; here the row also carries the
consecutive counters, the coded state, the cooldown/last-sample instants, and the last transition.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.state import (
    GlobalCommitBarrier,
    StateError,
    advance_alert_state,
    initialize_control_state,
    open_control_database,
    read_alert_state,
)

_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_LATER = datetime(2026, 7, 28, 12, 5, 0, tzinfo=UTC)


def _database(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    return database


def _advance(database, **overrides):
    kwargs = {
        "consecutive_fail_count": 1,
        "consecutive_success_count": 0,
        "current_state": "firing",
        "cooldown_until": "2026-07-28T12:01:00.000Z",
        "last_sample_at": "2026-07-28T12:00:00.000Z",
        "last_transition_id": "mh_atr1_example",
        "now": _NOW,
        "expected_revision": 0,
    }
    kwargs.update(overrides)
    return advance_alert_state(database, "canary-rule", 1, **kwargs)


def test_a_rule_with_no_state_reads_as_none(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert read_alert_state(database, "canary-rule", 1) is None
    finally:
        database.close()


def test_the_first_advance_creates_revision_one(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        state = _advance(database)
        assert state.revision == 1
        assert state.current_state == "firing"
        assert state.consecutive_fail_count == 1
        assert state.cooldown_until == "2026-07-28T12:01:00.000Z"
        assert state.updated_at == "2026-07-28T12:00:00.000Z"
        assert read_alert_state(database, "canary-rule", 1) == state
    finally:
        database.close()


def test_a_subsequent_advance_increments_the_revision(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _advance(database)
        second = _advance(
            database,
            consecutive_fail_count=0,
            consecutive_success_count=2,
            current_state="resolved",
            now=_LATER,
            expected_revision=1,
        )
        assert (second.revision, second.current_state) == (2, "resolved")
        assert second.consecutive_success_count == 2
        assert second.updated_at == "2026-07-28T12:05:00.000Z"
    finally:
        database.close()


def test_a_counter_only_advance_still_bumps_the_revision(tmp_path: Path) -> None:
    # A steady-state poll that emitted no transition still advances the revision, so the
    # compare-and-set stays sound across polls that only update the consecutive counters.
    database = _database(tmp_path)
    try:
        _advance(database, current_state="inactive", cooldown_until=None, last_transition_id=None)
        second = _advance(
            database,
            consecutive_fail_count=2,
            current_state="inactive",
            cooldown_until=None,
            last_transition_id=None,
            now=_LATER,
            expected_revision=1,
        )
        assert second.revision == 2
        assert second.consecutive_fail_count == 2
        assert second.current_state == "inactive"
        assert second.cooldown_until is None
        assert second.last_transition_id is None
    finally:
        database.close()


def test_a_stale_expected_revision_is_rejected_without_writing(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _advance(database)
        with pytest.raises(StateError) as captured:
            _advance(database, current_state="resolved", now=_LATER, expected_revision=0)
        assert captured.value.code == "MH_STATE_ALERT_CONFLICT"
        # A rejection raised inside the transaction must still leak no chained backend detail.
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
        current = read_alert_state(database, "canary-rule", 1)
        assert current is not None
        assert (current.revision, current.current_state) == (1, "firing")
    finally:
        database.close()


def test_expecting_a_prior_revision_on_a_fresh_rule_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            _advance(database, expected_revision=1)
        assert captured.value.code == "MH_STATE_ALERT_CONFLICT"
    finally:
        database.close()


def test_a_new_rule_version_does_not_inherit_the_prior_versions_state(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _advance(database)
        assert read_alert_state(database, "canary-rule", 2) is None
        version_two = advance_alert_state(
            database,
            "canary-rule",
            2,
            consecutive_fail_count=0,
            consecutive_success_count=0,
            current_state="inactive",
            cooldown_until=None,
            last_sample_at="2026-07-28T12:05:00.000Z",
            last_transition_id=None,
            now=_LATER,
            expected_revision=0,
        )
        assert (version_two.revision, version_two.current_state) == (1, "inactive")
        version_one = read_alert_state(database, "canary-rule", 1)
        assert version_one is not None and version_one.current_state == "firing"
    finally:
        database.close()


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"current_state": "unknown"}, "MH_STATE_ALERT_STATE"),
        ({"consecutive_fail_count": -1}, "MH_STATE_ALERT_COUNT"),
        ({"consecutive_success_count": True}, "MH_STATE_ALERT_COUNT"),
        ({"expected_revision": -1}, "MH_STATE_ALERT_REVISION"),
        ({"cooldown_until": ""}, "MH_STATE_ALERT_TIMESTAMP"),
        ({"last_transition_id": 5}, "MH_STATE_ALERT_TRANSITION"),
    ],
)
def test_malformed_arguments_are_rejected(
    tmp_path: Path, overrides: dict[str, object], code: str
) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            _advance(database, **overrides)
        assert captured.value.code == code
    finally:
        database.close()


def test_a_malformed_rule_key_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            read_alert_state(database, "", 1)
        assert captured.value.code == "MH_STATE_ALERT_RULE"
        with pytest.raises(StateError) as captured:
            read_alert_state(database, "canary-rule", 0)
        assert captured.value.code == "MH_STATE_ALERT_VERSION"
    finally:
        database.close()


def test_reads_and_advances_against_a_broken_store_normalize_to_a_stable_code(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _alert_rule_state")
        with pytest.raises(StateError) as captured:
            read_alert_state(database, "canary-rule", 1)
        assert captured.value.code == "MH_STATE_ALERT"
        assert captured.value.__cause__ is None
        with pytest.raises(StateError) as captured:
            _advance(database)
        assert captured.value.code == "MH_STATE_ALERT"
        assert captured.value.__context__ is None
    finally:
        database.close()
