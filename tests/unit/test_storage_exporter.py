"""Offline tests for the record → ClickHouse exporter: column mapping, feedback routing, egress."""

from __future__ import annotations

from typing import Any

import pytest
from _record_factories import (
    event_record,
    feedback_item_record,
    feedback_transition_record,
)
from _storage_fakes import FakeClickHouseClient

import milhouse.storage.exporter as exporter_module
from milhouse.storage import ExportSummary, StorageError, export_records


def _insert_for(
    client: FakeClickHouseClient, table: str
) -> tuple[list[list[Any]], tuple[str, ...]]:
    matches = [(rows, columns) for _db, tbl, rows, columns in client.inserts if tbl == table]
    assert len(matches) == 1, f"expected exactly one insert into {table}, got {len(matches)}"
    return matches[0]


def test_empty_export_writes_nothing() -> None:
    client = FakeClickHouseClient()
    summary = export_records(client, "milhouse", [])
    assert summary == ExportSummary(records=0, feedback_items=0, feedback_transitions=0)
    assert client.inserts == []  # every table batch was empty → no driver round-trip


def test_event_record_maps_to_the_records_columns() -> None:
    client = FakeClickHouseClient()
    record = event_record()

    summary = export_records(client, "milhouse", [record])

    assert summary == ExportSummary(records=1, feedback_items=0, feedback_transitions=0)
    rows, columns = _insert_for(client, "records")
    assert columns == (
        "schema_version",
        "record_id",
        "record_type",
        "name",
        "target_id",
        "occurred_at",
        "observed_at",
        "ingested_at",
        "expires_at",
        "source_event_id",
        "source_entity_id",
        "operation_id",
        "dedupe_key",
        "content_hash",
        "severity",
        "privacy_class",
    )
    row = dict(zip(columns, rows[0], strict=True))
    assert row["record_id"] == record.record_id
    assert row["record_type"] == "event"
    assert row["target_id"] == "example-target"
    # Assert each timestamp against its own field so a swap of two adjacent datetimes is caught.
    assert row["occurred_at"] == record.occurred_at
    assert row["observed_at"] == record.observed_at
    assert row["ingested_at"] == record.ingested_at
    assert row["expires_at"] == record.expires_at
    assert (
        record.occurred_at != record.observed_at != record.ingested_at
    )  # distinct, so the above bites
    assert row["source_event_id"] == "event-1"
    assert row["dedupe_key"] == record.dedupe_key
    assert row["content_hash"] == record.content_hash
    assert row["privacy_class"] == "internal"


def test_installation_scoped_record_maps_absent_target_and_source_to_empty_string() -> None:
    client = FakeClickHouseClient()
    record = event_record(
        scope="installation", target=None, source_event_id=None, source_entity_id=None
    )

    export_records(client, "milhouse", [record])

    rows, columns = _insert_for(client, "records")
    row = dict(zip(columns, rows[0], strict=True))
    assert row["target_id"] == ""
    assert row["source_event_id"] == ""
    assert row["source_entity_id"] == ""


def test_feedback_records_route_to_records_and_their_projections() -> None:
    client = FakeClickHouseClient()
    item = feedback_item_record()
    transition = feedback_transition_record()

    summary = export_records(client, "milhouse", [item, transition])

    assert summary == ExportSummary(records=2, feedback_items=1, feedback_transitions=1)

    item_rows, item_columns = _insert_for(client, "feedback_items")
    item_row = dict(zip(item_columns, item_rows[0], strict=True))
    assert item_row["item_id"] == "feedback-1"
    assert item_row["title"] == "Synthetic feedback"
    assert item_row["priority"] == "P2"
    assert item_row["actionability"] == "needs_approval"
    assert item_row["privacy_class"] == "internal"

    tr_rows, tr_columns = _insert_for(client, "feedback_transitions")
    tr_row = dict(zip(tr_columns, tr_rows[0], strict=True))
    assert tr_row["transition_id"] == "transition-1"
    assert tr_row["item_id"] == "feedback-1"
    assert tr_row["from_state"] == "open"
    assert tr_row["to_state"] == "accepted"
    assert tr_row["revision"] == 1
    assert tr_row["actor_type"] == "operator"
    assert tr_row["occurred_at"] == transition.occurred_at


def test_export_rejects_a_malformed_database_identifier() -> None:
    client = FakeClickHouseClient()
    with pytest.raises(StorageError) as captured:
        export_records(client, "bad-db!", [event_record()])
    assert captured.value.code == "MH_STORAGE_CONFIG"
    assert client.inserts == []  # fail closed before any write


def test_every_record_is_authorized_against_the_local_clickhouse_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[Any, str]] = []

    def _spy(*, surface: Any, privacy_class: str) -> str:
        seen.append((surface, privacy_class))
        return "redacted_record"

    monkeypatch.setattr(exporter_module, "require_egress", _spy)
    client = FakeClickHouseClient()
    export_records(client, "milhouse", [event_record(), feedback_item_record()])

    assert len(seen) == 2  # one authorization per record, before any write
    assert all(str(surface) == "local_clickhouse" for surface, _ in seen)
    assert [privacy_class for _, privacy_class in seen] == ["internal", "internal"]


def test_egress_denial_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from milhouse.privacy.pseudonym import PrivacyError

    def _deny(*, surface: Any, privacy_class: str) -> str:
        raise PrivacyError("MH_EGRESS_RESTRICTED", "restricted input cannot reach persistence")

    monkeypatch.setattr(exporter_module, "require_egress", _deny)
    client = FakeClickHouseClient()
    with pytest.raises(PrivacyError):
        export_records(client, "milhouse", [event_record()])
    assert client.inserts == []  # nothing written when authorization fails
