# ADR 0003: Canonical records, identity, and metrics

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Replay, correction handling, retention, verification, and analytical correctness require one immutable record contract and deterministic identity across processes and platforms.

## Decision

Every durable observation is a strict `RecordEnvelopeV1` with `schema_version = "1.0"` and the fields, record types, payloads, classifications, bounds, and timestamps fixed in plan section 4.2. Records are immutable observations, not mutable provider snapshots.

`record_id` is `mh_` plus the fixed-length lowercase unpadded base32 SHA-256 digest of the canonical identity tuple. Canonical JSON is UTF-8 with sorted keys, no insignificant whitespace, normalized values, and UTC RFC3339 millisecond timestamps. `content_hash` is lowercase hexadecimal SHA-256 over meaningful redacted content and excludes observation, operation, retention, implementation-version, batch, and delivery metadata exactly as specified by the plan.

`operation_id` is required provenance but normally not identity. `collector_run_id` is required only for collector-produced records. Mutable provider entities correlate through `source_entity_id`; every provider revision, update coordinate, or state transition creates a new immutable observation. Replaying preserves record and batch identity. A repeated ID/hash is a no-op; a repeated ID with another hash is a conflict.

`expires_at` is computed once from the first committed `ingested_at`; replay or repeat observation cannot extend it.

Metric payloads declare `gauge`, `counter_delta`, `window_total`, or `cumulative_counter`. Window totals include bounds and are never summed across overlapping windows. Cumulative counters are converted to validated deltas before aggregation.

## Consequences

All collectors document their entity identity, observation coordinate, correction semantics, and update fixtures. Query, report, replay, and verification code share canonical serialization and cannot invent alternate identity or aggregation rules.

## Plan references

- [Section 4.2: Canonical record envelope](../implementation-plan.md#42-canonical-record-envelope)
- [Sections 9.1-9.2: required identity and metric testing](../implementation-plan.md#91-test-topology)
- [W02: identity implementation gate](../implementation-plan.md#w02--domain-configuration-identity-trust-and-privacy)
