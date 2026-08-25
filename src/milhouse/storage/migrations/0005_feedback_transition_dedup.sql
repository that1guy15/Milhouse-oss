-- 0005_feedback_transition_dedup: make the append-only transition log idempotent on re-insert.
-- feedback_transitions shipped as a plain MergeTree, so an at-least-once redelivery — a crash after
-- the ClickHouse insert but before the segment delivery-ledger compare-and-set, or two concurrent
-- drains — wrote a DUPLICATE physical row for the same immutable transition_id. Recreate it as a
-- ReplacingMergeTree whose sort key ends in the globally-unique transition_id, so identical
-- redeliveries collapse on merge (item_id leads the key to keep per-item locality the view scans).
-- Existing rows are preserved: copy into a new table, then atomically EXCHANGE it into place and drop
-- the old one. A leading DROP of the scratch table makes a re-run after a partial apply safe. The
-- feedback_current view (0004) derives state with argMax/max over the total order (revision,
-- occurred_at, transition_id) and is already duplicate-robust, so it is unchanged. Retention is not
-- shortened and no live row is dropped.
DROP TABLE IF EXISTS {database}.feedback_transitions_0005;

CREATE TABLE IF NOT EXISTS {database}.feedback_transitions_0005
(
    transition_id String,
    item_id String,
    revision UInt32,
    from_state LowCardinality(String),
    to_state LowCardinality(String),
    occurred_at DateTime64(3, 'UTC'),
    actor_type LowCardinality(String),
    rationale String
)
ENGINE = ReplacingMergeTree
ORDER BY (item_id, transition_id);

INSERT INTO {database}.feedback_transitions_0005
SELECT transition_id, item_id, revision, from_state, to_state, occurred_at, actor_type, rationale
FROM {database}.feedback_transitions;

EXCHANGE TABLES {database}.feedback_transitions AND {database}.feedback_transitions_0005;

DROP TABLE IF EXISTS {database}.feedback_transitions_0005;
