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
}


def test_migrations_are_contiguous_named_and_nonempty() -> None:
    assert tuple(m.version for m in CLICKHOUSE_MIGRATIONS) == (1, 2, 3, 4)
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


def test_records_current_view_enforces_retention_at_query_time() -> None:
    views = next(m for m in CLICKHOUSE_MIGRATIONS if m.name == "views")
    assert "records_current" in views.sql
    # Retention is enforced at query time independent of merge-time TTL deletion.
    assert "expires_at > now64" in views.sql
