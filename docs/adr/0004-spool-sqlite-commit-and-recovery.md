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

## Amendment A06: installation-account filesystem-containment boundary (2026-07-28)

Owner-approved plan amendment A06 scopes threat-model security objective 4 to the attacker model
that Milhouse can enforce on its supported POSIX hosts. Filesystem code must prevent writes or
unlinks outside approved roots caused by untrusted input, traversal, symlinks, other local users, or
cooperating Milhouse processes. Quarantine and reconciliation must bind mutation to validated live
directory chains and exact pass-owned objects, use recoverable fsynced source retirement, preserve
validated recovery copies when namespace state becomes uncertain, and report detected displacement
as uncertain rather than successful.

POSIX provides no operation that atomically proves an ancestor pathname still names an opened
directory and then performs a later descriptor-relative mutation. A hostile process already running
as the Milhouse operating-system account can rename an ancestor in that adjacent syscall window and
displace the mutation outside the approved root's current pathname. The residual applies to both
quarantine publication and pending-source retirement. The Milhouse operating-system account and the
host administrator are therefore trusted for filesystem containment; hostile same-UID containment
is not claimed. Operators should run Milhouse under a dedicated service account and run no untrusted
code under that identity.

This amendment narrows the literal attacker model previously implied by objective 4. It retains the
traversal, symlink, different-user, cooperating-writer, namespace-displacement, and retry acceptance
tests, and it does not change any wire byte, stored schema, retention rule, egress surface, product
scope, or release gate. ADR 0008 already treats explicitly installed in-process plugins as trusted
code running with the Milhouse user's authority; A06 makes the corresponding filesystem trust
boundary explicit without treating plugin manifests as containment.

## Plan references

- [Sections 3.2 and 3.4: storage and runtime pipeline](../implementation-plan.md#32-storage-responsibilities)
- [Sections 4.3-4.4: spool and SQLite contracts](../implementation-plan.md#43-spool-format-and-state)
- [Section 10.3: point-in-time backup protocol](../implementation-plan.md#103-backups-and-recovery)
- [W03: durable spool and failure-injection gate](../implementation-plan.md#w03--sqlite-state-durable-spool-replay-and-retention)
