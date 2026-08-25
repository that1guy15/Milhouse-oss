-- 0001_core: migration ledger and shared conventions.
-- The ``{database}`` placeholder is substituted by the runner with the validated, pattern-checked
-- configuration identifier; the runner creates the database itself before applying this migration.
-- The ledger records one row per applied migration (version, name, checksum, applied instant, and
-- the Milhouse version that applied it) and is deduplicated by ``version`` keeping the newest
-- ``applied_at`` so a replayed insert never forks the recorded history.
CREATE TABLE IF NOT EXISTS {database}._migrations
(
    version UInt32,
    name String,
    checksum String,
    applied_at DateTime64(3, 'UTC'),
    milhouse_version String
)
ENGINE = ReplacingMergeTree(applied_at)
ORDER BY version;
