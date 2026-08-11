-- 0006_installation_ownership: enforce ONE installation per ClickHouse destination (fail-closed).
-- Milhouse's single-writer correctness rests on the local control-plane commit barrier, which fences
-- exactly one installation's ClickHouse writers. That barrier is a machine-local lock: it cannot see
-- a SECOND installation -- a different state root, clone, or host -- pointed at the SAME ClickHouse,
-- so two installations could each believe they hold the single writer while silently comingling and
-- corrupting each other's analytical data. This table records the ONE installation that owns this
-- destination: a single logical row at id = 1 holding the owning installation id, the instant it was
-- claimed, and the Milhouse version that claimed it. storage migrate stamps it (--reclaim supersedes
-- a prior owner to deliberately re-point an install at a new host), and storage export/backup/restore
-- refuse to run unless this destination is owned by the local installation. ReplacingMergeTree keyed
-- on claimed_at collapses to the single newest claim, so a reclaim is one more insert that supersedes
-- on merge -- never a second logical owner; a FINAL read observes the current owner before merges run.
-- The {database} placeholder is substituted by the runner with the validated configuration identifier;
-- the table is created idempotently so a re-run after a partial apply is safe. Retention is never
-- shortened and no live row is dropped.
CREATE TABLE IF NOT EXISTS {database}._installation
(
    id UInt8,
    installation_id String,
    claimed_at DateTime64(3, 'UTC'),
    milhouse_version String
)
ENGINE = ReplacingMergeTree(claimed_at)
ORDER BY id;
