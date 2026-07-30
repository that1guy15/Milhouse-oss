"""Behavioural guarantees for per-rule/version derivation checkpoints (W03 slice 4, rule 10).

A checkpoint advances only via a compare-and-set against the revision the caller last observed, so a
restarted or concurrent derivation pass cannot fork or double-advance the projection. A rule-logic
revision (a new ``rule_version``) starts from a clean position rather than inheriting the prior one.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.state import (
    GlobalCommitBarrier,
    StateError,
    advance_checkpoint,
    initialize_control_state,
    open_control_database,
    read_checkpoint,
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


def test_a_rule_with_no_checkpoint_reads_as_none(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert read_checkpoint(database, "alerts", 1) is None
    finally:
        database.close()


def test_the_first_advance_creates_revision_one(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        checkpoint = advance_checkpoint(
            database, "alerts", 1, position="batch-7", now=_NOW, expected_revision=0
        )
        assert (checkpoint.position, checkpoint.revision) == ("batch-7", 1)
        assert checkpoint.updated_at == "2026-07-28T12:00:00.000Z"
        assert read_checkpoint(database, "alerts", 1) == checkpoint
    finally:
        database.close()


def test_a_subsequent_advance_increments_the_revision(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        advance_checkpoint(database, "alerts", 1, position="p1", now=_NOW, expected_revision=0)
        second = advance_checkpoint(
            database, "alerts", 1, position="p2", now=_LATER, expected_revision=1
        )
        assert (second.position, second.revision) == ("p2", 2)
        assert second.updated_at == "2026-07-28T12:05:00.000Z"
    finally:
        database.close()


def test_a_stale_expected_revision_is_rejected_without_writing(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        advance_checkpoint(database, "alerts", 1, position="p1", now=_NOW, expected_revision=0)
        with pytest.raises(StateError) as captured:
            advance_checkpoint(
                database, "alerts", 1, position="rogue", now=_LATER, expected_revision=0
            )
        assert captured.value.code == "MH_STATE_DERIVATION_CONFLICT"
        # A rejection raised inside the transaction must still leak no chained backend detail.
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
        current = read_checkpoint(database, "alerts", 1)
        assert current is not None
        assert (current.position, current.revision) == ("p1", 1)
    finally:
        database.close()


def test_expecting_a_prior_revision_on_a_fresh_checkpoint_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            advance_checkpoint(database, "alerts", 1, position="p1", now=_NOW, expected_revision=1)
        assert captured.value.code == "MH_STATE_DERIVATION_CONFLICT"
    finally:
        database.close()


def test_a_new_rule_version_does_not_inherit_the_prior_versions_checkpoint(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        advance_checkpoint(database, "alerts", 1, position="v1-far", now=_NOW, expected_revision=0)
        # Version 2 is a distinct key: it starts empty, so its first advance expects revision 0.
        assert read_checkpoint(database, "alerts", 2) is None
        version_two = advance_checkpoint(
            database, "alerts", 2, position="v2-start", now=_LATER, expected_revision=0
        )
        assert (version_two.position, version_two.revision) == ("v2-start", 1)
        # Version 1 is untouched.
        version_one = read_checkpoint(database, "alerts", 1)
        assert version_one is not None and version_one.position == "v1-far"
    finally:
        database.close()


def test_checkpoints_for_distinct_rules_are_independent(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        advance_checkpoint(database, "alerts", 1, position="a", now=_NOW, expected_revision=0)
        advance_checkpoint(database, "feedback", 1, position="f", now=_NOW, expected_revision=0)
        alerts = read_checkpoint(database, "alerts", 1)
        feedback = read_checkpoint(database, "feedback", 1)
        assert alerts is not None and alerts.position == "a"
        assert feedback is not None and feedback.position == "f"
    finally:
        database.close()


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("rule", "", "MH_STATE_DERIVATION_RULE"),
        ("rule", 5, "MH_STATE_DERIVATION_RULE"),
        ("rule_version", 0, "MH_STATE_DERIVATION_VERSION"),
        ("rule_version", True, "MH_STATE_DERIVATION_VERSION"),
        ("position", "", "MH_STATE_DERIVATION_POSITION"),
        ("expected_revision", -1, "MH_STATE_DERIVATION_REVISION"),
        ("expected_revision", True, "MH_STATE_DERIVATION_REVISION"),
    ],
)
def test_malformed_arguments_are_rejected(
    tmp_path: Path, field: str, value: object, code: str
) -> None:
    database = _database(tmp_path)
    try:
        kwargs: dict[str, object] = {
            "rule": "alerts",
            "rule_version": 1,
            "position": "p1",
            "now": _NOW,
            "expected_revision": 0,
        }
        kwargs[field] = value
        rule = kwargs.pop("rule")
        rule_version = kwargs.pop("rule_version")
        with pytest.raises(StateError) as captured:
            advance_checkpoint(database, rule, rule_version, **kwargs)  # type: ignore[arg-type]
        assert captured.value.code == code
    finally:
        database.close()


def test_read_checkpoint_rejects_a_malformed_key(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            read_checkpoint(database, "", 1)
        assert captured.value.code == "MH_STATE_DERIVATION_RULE"
        with pytest.raises(StateError) as captured:
            read_checkpoint(database, "alerts", 0)
        assert captured.value.code == "MH_STATE_DERIVATION_VERSION"
    finally:
        database.close()


def test_a_read_against_a_broken_store_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _derivation_checkpoints")
        with pytest.raises(StateError) as captured:
            read_checkpoint(database, "alerts", 1)
        assert captured.value.code == "MH_STATE_DERIVATION"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


def test_an_advance_against_a_broken_store_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _derivation_checkpoints")
        with pytest.raises(StateError) as captured:
            advance_checkpoint(database, "alerts", 1, position="p1", now=_NOW, expected_revision=0)
        assert captured.value.code == "MH_STATE_DERIVATION"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()
