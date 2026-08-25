-- 0003_feedback: feedback item creations and the append-only transition log.
-- ``feedback_items`` is the creation projection (deduplicated by item id, newest creation wins).
-- ``feedback_transitions`` is strictly append-only: current state is DERIVED from the total order
-- (revision, occurred_at, transition_id) in 0004_views, never by updating a row in place. This
-- mirrors the locked feedback contract (plan section 4.6).
CREATE TABLE IF NOT EXISTS {database}.feedback_items
(
    item_id String,
    fingerprint String,
    created_at DateTime64(3, 'UTC'),
    target_id String,
    title String,
    severity LowCardinality(String),
    priority LowCardinality(String),
    actionability LowCardinality(String),
    confidence LowCardinality(String),
    privacy_class LowCardinality(String)
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (target_id, item_id);

CREATE TABLE IF NOT EXISTS {database}.feedback_transitions
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
ENGINE = MergeTree
ORDER BY (item_id, revision, transition_id);
