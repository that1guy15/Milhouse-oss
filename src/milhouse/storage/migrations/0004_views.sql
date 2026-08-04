-- 0004_views: deduplicating / current-state views.
-- ``records_current`` is the deduplicated record view (ReplacingMergeTree FINAL) AND the
-- retention-enforcing surface for record queries: the ``expires_at`` predicate hides any
-- retention-elapsed row at query time, so retention is enforced independently of ClickHouse's
-- merge-time TTL deletion (TTL still reclaims storage on merge). ``feedback_current`` derives each
-- item's current state from the append-only transition log using argMax over the locked total order
-- (revision, occurred_at, transition_id) from plan section 4.6 — no in-place state is stored. Richer
-- query/aggregation views (source freshness, metric windows) arrive with the query service (W09).
CREATE VIEW IF NOT EXISTS {database}.records_current AS
SELECT *
FROM {database}.records
FINAL
WHERE expires_at > now64(3, 'UTC');

CREATE VIEW IF NOT EXISTS {database}.feedback_current AS
SELECT
    item_id,
    argMax(to_state, (revision, occurred_at, transition_id)) AS current_state,
    max(revision) AS current_revision,
    max(occurred_at) AS last_transition_at
FROM {database}.feedback_transitions
GROUP BY item_id;
