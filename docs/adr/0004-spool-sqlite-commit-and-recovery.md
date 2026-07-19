# ADR 0004: Spool, SQLite, commit, and recovery

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Collection must continue through analytical-store outages and crashes without claiming impossible cross-filesystem/database atomicity.

## Decision

The segmented redacted JSONL spool is the durable record log and replay authority. SQLite in WAL mode is the transactional control plane for segment/export ledgers, privacy-safe indexes, cursors, leases, state projections, idempotency, migrations, and safe audit metadata. SQLite never stores raw provider, report, error, or agent content.

Each self-describing segment has one scope, one target when target-scoped, and one compatible privacy/retention class. It contains a `SegmentHeaderV1` plus ordered `SpoolFrameV1` records and cryptographic digests.

A durable commit is deliberately reconciled across the filesystem and SQLite:

1. write, flush, and fsync a unique temporary segment;
2. atomically rename it and fsync the parent directory;
3. insert the validated matching ledger row and commit SQLite;
4. only then acknowledge the batch;
5. advance a source cursor only in a transaction referencing that committed ledger row.

All durable writers take the shared global commit barrier; backup, restore, migration, and declared maintenance take the exclusive side. Startup and writer acquisition register valid orphan segments, report a ledger row with a missing segment as unhealthy corruption, and recover or quarantine stale temporary artifacts. Derived records use the same spool protocol and idempotent per-rule/version checkpoints before projections advance.

Delivery is physically at least once and logically effectively once through deterministic IDs, conflict detection, destination confirmation, and checkpoints. Pending records remain retryable until delivered or their hard privacy expiry. Delivered records remain in the redacted spool until each record's class expiry. Audited restartable compaction removes only expired frames. Full mode never prunes the last recoverable unexpired copy.

## Consequences

No writer bypasses the runtime pipeline or writes directly to projections/destinations. Crash tests cover every commit, cursor, derivation, export, confirmation, and checkpoint boundary. Backup snapshots use the global barrier and a segment watermark; target purge uses exclusive fences.

## Plan references

- [Sections 3.2 and 3.4: storage and runtime pipeline](../implementation-plan.md#32-storage-responsibilities)
- [Sections 4.3-4.4: spool and SQLite contracts](../implementation-plan.md#43-spool-format-and-state)
- [Section 10.3: point-in-time backup protocol](../implementation-plan.md#103-backups-and-recovery)
- [W03: durable spool and failure-injection gate](../implementation-plan.md#w03--sqlite-state-durable-spool-replay-and-retention)
