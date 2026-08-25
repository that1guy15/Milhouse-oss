"""Offline tests for the query repository: view SELECTs, timestamp coercion, parameter binding."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import pytest

from milhouse.storage import (
    FeedbackStateRow,
    StorageError,
    StoredRecordV1,
    fetch_current_feedback,
    fetch_current_records,
)


class _RowClient:
    """A ClickHouseClient that returns canned rows and records every statement + parameters."""

    def __init__(self, rows: Sequence[Sequence[Any]]) -> None:
        self._rows = rows
        self.statements: list[str] = []
        self.parameters: list[Mapping[str, Any] | None] = []

    def command(self, statement: str) -> None:  # pragma: no cover - repository never commands
        raise AssertionError("the repository must not issue commands")

    def insert(  # pragma: no cover - repository never inserts
        self,
        database: str,
        table: str,
        rows: Sequence[Sequence[Any]],
        *,
        column_names: Sequence[str],
    ) -> None:
        raise AssertionError("the repository must not insert")

    def query(
        self, statement: str, *, parameters: Mapping[str, Any] | None = None
    ) -> Sequence[Sequence[Any]]:
        self.statements.append(statement)
        self.parameters.append(parameters)
        return self._rows


def _record_row(**overrides: Any) -> list[Any]:
    row: dict[str, Any] = {
        "record_id": "mh_record",
        "record_type": "event",
        "name": "source.event",
        "target_id": "example-target",
        "occurred_at": datetime(2026, 7, 21, 15, 0, 0, 123000, tzinfo=UTC),
        "ingested_at": datetime(2026, 7, 21, 15, 0, 2, tzinfo=UTC),
        "expires_at": datetime(2026, 8, 20, 15, 0, 0, tzinfo=UTC),
        "severity": "info",
        "privacy_class": "internal",
    }
    row.update(overrides)
    return list(row.values())


def test_fetch_current_records_maps_rows_and_normalizes_timestamps() -> None:
    client = _RowClient([_record_row()])
    rows = fetch_current_records(client, "milhouse")
    assert rows == (
        StoredRecordV1(
            record_id="mh_record",
            record_type="event",
            name="source.event",
            target_id="example-target",
            occurred_at="2026-07-21T15:00:00.123Z",
            ingested_at="2026-07-21T15:00:02.000Z",
            expires_at="2026-08-20T15:00:00.000Z",
            severity="info",
            privacy_class="internal",
        ),
    )
    # No filter → no bound parameters and a query over the retention/dedup view.
    assert client.parameters == [None]
    assert "milhouse.records_current" in client.statements[0]


def test_fetch_current_records_binds_target_as_a_parameter_not_sql() -> None:
    client = _RowClient([])
    fetch_current_records(client, "milhouse", target_id="'; DROP TABLE records; --")
    statement = client.statements[0]
    # The value is bound server-side; it never appears in the statement text.
    assert "{target:String}" in statement
    assert "DROP TABLE" not in statement
    assert client.parameters[0] == {"target": "'; DROP TABLE records; --"}


def test_fetch_current_records_coerces_naive_and_non_datetime_timestamps() -> None:
    naive = _RowClient([_record_row(occurred_at=datetime(2026, 7, 21, 15, 0, 0))])
    assert fetch_current_records(naive, "milhouse")[0].occurred_at == "2026-07-21T15:00:00.000Z"
    # Defensive: a driver that hands back a pre-formatted string is passed through untouched.
    already = _RowClient([_record_row(occurred_at="2026-07-21T15:00:00.000Z")])
    assert fetch_current_records(already, "milhouse")[0].occurred_at == "2026-07-21T15:00:00.000Z"


def test_fetch_current_feedback_maps_rows() -> None:
    client = _RowClient(
        [["feedback-1", "accepted", 3, datetime(2026, 7, 21, 15, 0, 0, tzinfo=UTC)]]
    )
    rows = fetch_current_feedback(client, "milhouse")
    assert rows == (
        FeedbackStateRow(
            item_id="feedback-1",
            current_state="accepted",
            current_revision=3,
            last_transition_at="2026-07-21T15:00:00.000Z",
        ),
    )
    assert "milhouse.feedback_current" in client.statements[0]


def test_repository_rejects_a_malformed_database_identifier() -> None:
    client = _RowClient([])
    with pytest.raises(StorageError) as records_error:
        fetch_current_records(client, "bad-db!")
    assert records_error.value.code == "MH_STORAGE_CONFIG"
    with pytest.raises(StorageError) as feedback_error:
        fetch_current_feedback(client, "bad-db!")
    assert feedback_error.value.code == "MH_STORAGE_CONFIG"
    assert client.statements == []  # fail closed before any query
