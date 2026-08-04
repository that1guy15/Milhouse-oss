-- 0002_records: the canonical redacted records table.
-- ReplacingMergeTree(ingested_at) keeps the newest ingestion per (target, record type, record id),
-- giving logical deduplication by ``record_id``; correctness-sensitive queries use the current view
-- or ``FINAL`` (see 0004_views). Retention is driven by each record's own ``expires_at`` via a TTL,
-- so an expired row is removed on merge. Nothing is ever updated or deleted in place. Every column
-- holds already-redacted, privacy-safe data; there is no raw payload column.
CREATE TABLE IF NOT EXISTS {database}.records
(
    schema_version LowCardinality(String),
    record_id String,
    record_type LowCardinality(String),
    name String,
    target_id String,
    occurred_at DateTime64(3, 'UTC'),
    observed_at DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC'),
    expires_at DateTime64(3, 'UTC'),
    source_event_id String,
    source_entity_id String,
    operation_id String,
    dedupe_key String,
    content_hash String,
    severity LowCardinality(String),
    privacy_class LowCardinality(String)
)
ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (target_id, record_type, record_id)
TTL toDateTime(expires_at)
SETTINGS index_granularity = 8192;
