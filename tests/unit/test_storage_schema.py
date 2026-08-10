"""Golden, immutability tests for the packaged ClickHouse migrations."""

from __future__ import annotations

from milhouse.storage.schema import CLICKHOUSE_MIGRATIONS

# Immutability anchor: these checksums are contract-locked. A change here means a released migration
# file was edited, which the runner refuses against any deployment that already applied it.
_GOLDEN: dict[int, tuple[str, str]] = {
    1: ("core", "a9c65ca3d46801b81e2f0cc47a3816c574fa67097420acff90cc0ca709b1c517"),
    2: ("records", "9fa60c6b7cd76cbf7ee76a3fd7ec8c697cf63c5aea7af9291eef7aaafd733136"),
    3: ("feedback", "74b77862bef24a211d52d120601a06128babc8943a97002a0ceb7d5ac0b05b1d"),
    4: ("views", "bb5757f2bc3f49045a472e4bc4164c41526cd8b42c1004ae1dab7f61d1596651"),
    5: (
        "feedback_transition_dedup",
        "158761bee4c675ac39eaec9cc6146423c6fb91aa5bd9794a41f946d581ff9e08",
    ),
    6: (
        "installation_ownership",
        "959adb37cfe942aeda7547fb82da736eddde1c18fd4d108d358510bd2ed26b1b",
    ),
}


def test_migrations_are_contiguous_named_and_nonempty() -> None:
    assert tuple(m.version for m in CLICKHOUSE_MIGRATIONS) == (1, 2, 3, 4, 5, 6)
    for migration in CLICKHOUSE_MIGRATIONS:
        assert migration.name
        assert migration.sql.strip()
        assert len(migration.checksum) == 64


def test_migration_checksums_match_the_golden_constants() -> None:
    for migration in CLICKHOUSE_MIGRATIONS:
        expected_name, expected_checksum = _GOLDEN[migration.version]
        assert migration.name == expected_name
        assert migration.checksum == expected_checksum


def test_records_migration_uses_replacing_engine_and_ttl() -> None:
    records = next(m for m in CLICKHOUSE_MIGRATIONS if m.name == "records")
    assert "ReplacingMergeTree(ingested_at)" in records.sql
    assert "ORDER BY (target_id, record_type, record_id)" in records.sql
    assert "TTL" in records.sql
    # No in-place update/delete anywhere in the packaged schema.
    for migration in CLICKHOUSE_MIGRATIONS:
        assert "ALTER TABLE" not in migration.sql.upper() or "UPDATE" not in migration.sql.upper()


def test_feedback_transition_dedup_migration_recreates_a_replacing_engine() -> None:
    dedup = next(m for m in CLICKHOUSE_MIGRATIONS if m.name == "feedback_transition_dedup")
    # The append-only transition log becomes a ReplacingMergeTree keyed on the globally-unique
    # transition_id, so an at-least-once redelivery of the same transition collapses on merge.
    assert "ReplacingMergeTree" in dedup.sql
    assert "ORDER BY (item_id, transition_id)" in dedup.sql
    # Existing rows are preserved via copy-then-atomic-swap, not an in-place ALTER.
    assert "INSERT INTO" in dedup.sql and "EXCHANGE TABLES" in dedup.sql


def test_records_current_view_enforces_retention_at_query_time() -> None:
    views = next(m for m in CLICKHOUSE_MIGRATIONS if m.name == "views")
    assert "records_current" in views.sql
    # Retention is enforced at query time independent of merge-time TTL deletion.
    assert "expires_at > now64" in views.sql


def test_installation_ownership_migration_is_a_single_owner_replacing_table() -> None:
    ownership = next(m for m in CLICKHOUSE_MIGRATIONS if m.name == "installation_ownership")
    assert "_installation" in ownership.sql
    # One logical owner row keyed on a fixed id; ReplacingMergeTree(claimed_at) keeps the newest
    # claim so a --reclaim supersedes rather than forking a second owner.
    assert "ReplacingMergeTree(claimed_at)" in ownership.sql
    assert "ORDER BY id" in ownership.sql
    # Idempotent DDL (retry-safe) and no destructive statement.
    assert "CREATE TABLE IF NOT EXISTS" in ownership.sql
    assert "DROP TABLE" not in ownership.sql.upper()
    assert "DROP DATABASE" not in ownership.sql.upper()
