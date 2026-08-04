"""Offline tests for the checksum-protected ClickHouse migration runner (fake client)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from _storage_fakes import FakeClickHouseClient

from milhouse.storage import StorageError, migrate, plan, status
from milhouse.storage.schema import CLICKHOUSE_MIGRATIONS

_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
_DB = "milhouse"


def _migrate(client: FakeClickHouseClient) -> object:
    return migrate(client, _DB, now=_NOW, milhouse_version="1.0.0")


def test_fresh_plan_lists_all_pending_and_does_not_mutate() -> None:
    client = FakeClickHouseClient()

    report = plan(client, _DB)

    assert [state.version for state in report.pending] == [1, 2, 3, 4]
    assert report.applied == ()
    assert report.current_version == 0
    # Non-mutation: plan never created the database, the ledger, or any table.
    assert client.databases == set()
    assert client.tables == set()
    assert client.commands == []


def test_status_is_read_only_like_plan() -> None:
    client = FakeClickHouseClient()
    report = status(client, _DB)
    assert len(report.pending) == 4
    assert client.commands == []


def test_migrate_applies_all_in_order_with_ledger_rows() -> None:
    client = FakeClickHouseClient()

    result = _migrate(client)

    assert result.applied_now == (1, 2, 3, 4)
    assert result.already_applied == ()
    assert result.current_version == 4
    assert (_DB, "records") in client.tables
    assert (_DB, "records_current") in client.tables
    ledger = client.ledger[_DB]
    assert set(ledger) == {1, 2, 3, 4}
    for migration in CLICKHOUSE_MIGRATIONS:
        assert ledger[migration.version] == (migration.name, migration.checksum)


def test_migrate_is_idempotent() -> None:
    client = FakeClickHouseClient()
    _migrate(client)

    result = _migrate(client)

    assert result.applied_now == ()
    assert result.already_applied == (1, 2, 3, 4)
    assert plan(client, _DB).current_version == 4


def test_migrate_refuses_a_tampered_applied_checksum() -> None:
    client = FakeClickHouseClient()
    _migrate(client)
    # Simulate an applied migration whose file was changed after it was recorded.
    client.ledger[_DB][1] = ("core", "0" * 64)

    with pytest.raises(StorageError) as captured:
        _migrate(client)
    assert captured.value.code == "MH_STORAGE_MIGRATION"


def test_plan_refuses_a_noncontiguous_ledger() -> None:
    client = FakeClickHouseClient()
    client.seed_ledger(_DB, 2, "records", CLICKHOUSE_MIGRATIONS[1].checksum)  # version 1 missing

    with pytest.raises(StorageError) as captured:
        plan(client, _DB)
    assert captured.value.code == "MH_STORAGE_MIGRATION"


def test_invalid_database_identifier_is_rejected() -> None:
    client = FakeClickHouseClient()
    with pytest.raises(StorageError) as captured:
        plan(client, "bad name; DROP")
    assert captured.value.code == "MH_STORAGE_MIGRATION"


def test_migrate_rejects_a_naive_now() -> None:
    client = FakeClickHouseClient()
    with pytest.raises(StorageError) as captured:
        migrate(client, _DB, now=datetime(2026, 8, 3, 12, 0, 0), milhouse_version="1.0.0")  # naive
    assert captured.value.code == "MH_STORAGE_MIGRATION"


def test_ledger_version_beyond_definitions_is_rejected() -> None:
    client = FakeClickHouseClient()
    for migration in CLICKHOUSE_MIGRATIONS:
        client.seed_ledger(_DB, migration.version, migration.name, migration.checksum)
    client.seed_ledger(_DB, 5, "phantom", "0" * 64)  # a recorded version with no definition

    with pytest.raises(StorageError) as captured:
        plan(client, _DB)
    assert captured.value.code == "MH_STORAGE_MIGRATION"
