# ADR 0005: ClickHouse analytical storage

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Milhouse needs fast local analytics without making collection availability or acknowledged-record recovery depend on an analytical database.

## Decision

ClickHouse is the derived analytical store, not the durable collection authority. The reference deployment is local, loopback-only, authenticated ClickHouse 26.3 LTS pinned to an exact supported patch and image digest per release. ClickHouse 25.8 LTS is the compatibility line while security-supported. Hosted/external ClickHouse is optional, disabled by default, and governed by a separate egress allowlist.

Packaged immutable SQL migrations have versions and checksums. `storage status` and `storage plan` do not mutate; `storage migrate` refuses changed applied checksums. Migrations do not silently drop data, shorten retention, or perform irreversible conversions.

Canonical redacted records use `ReplacingMergeTree(ingested_at)` with a key containing target, record type, and record ID. Correctness-sensitive reads use deduplicated views or `FINAL`. Feedback history remains append-only, and current state is derived by the plan's total ordering. Normal operations do not update or delete records in place.

ClickHouse outage does not stop collection. Export checkpoints advance only after destination confirmation. Repeated replay is logically idempotent. Unexpired spool data is authoritative for rebuilding ClickHouse; verified native backup adds recovery coverage and records its exporter watermark.

## Consequences

Compose cannot expose an unauthenticated or remotely usable default account. Release testing covers fresh migrations, supported-version compatibility, outage/replay, deduplication, backup/restore, and checksum enforcement.

## Plan references

- [Sections 3.2-3.3: storage and dependency policy](../implementation-plan.md#32-storage-responsibilities)
- [Section 4.5: ClickHouse schema and migrations](../implementation-plan.md#45-clickhouse-schema-and-migrations)
- [W04: secure ClickHouse and recovery gates](../implementation-plan.md#w04--secure-clickhouse-migrations-repository-and-recovery)
