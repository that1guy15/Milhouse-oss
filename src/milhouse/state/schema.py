"""The immutable package-owned control-plane schema (W03 slice 1).

The initial control schema is an ordered migration sequence rather than ad-hoc DDL by feature code,
so the physical schema can never diverge from the recorded migration version and checksums (the
review's P1 concern). Later W03 slices append segment/exporter ledger, index, and cursor migrations
to this tuple; shipped entries are immutable. The ``_leases`` table carries a monotonic ``fence``
token so a stale holder cannot resume work after takeover.
"""

from __future__ import annotations

from datetime import datetime

from milhouse.state.barrier import GlobalCommitBarrier
from milhouse.state.database import ControlDatabase
from milhouse.state.migrations import Migration, migrate

CONTROL_MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        1,
        "create_leases",
        (
            "CREATE TABLE _leases ("
            "name TEXT PRIMARY KEY NOT NULL, "
            "holder TEXT NOT NULL, "
            "fence INTEGER NOT NULL, "
            "acquired_at TEXT NOT NULL, "
            "expires_at TEXT NOT NULL)",
        ),
    ),
    Migration(
        2,
        "create_segments",
        (
            "CREATE TABLE _segments ("
            "batch_id TEXT PRIMARY KEY NOT NULL, "
            "day TEXT NOT NULL, "
            "schema_version INTEGER NOT NULL, "
            "frame_version INTEGER NOT NULL, "
            "config_generation TEXT NOT NULL, "
            "scope TEXT NOT NULL, "
            "target_id TEXT, "
            "privacy_class TEXT NOT NULL, "
            "retention_days INTEGER NOT NULL, "
            "record_count INTEGER NOT NULL, "
            "content_sha256 TEXT NOT NULL, "
            "byte_size INTEGER NOT NULL, "
            "file_sha256 TEXT NOT NULL, "
            "committed_at TEXT NOT NULL, "
            "CHECK (schema_version = 1), "
            "CHECK (frame_version = 1), "
            "CHECK (length(config_generation) = 64), "
            "CHECK (length(day) = 10), "
            "CHECK (scope IN ('installation', 'target')), "
            "CHECK ((scope = 'target') = (target_id IS NOT NULL)), "
            "CHECK (privacy_class IN ('public', 'internal', 'sensitive')), "
            "CHECK (retention_days BETWEEN 1 AND 3650), "
            "CHECK (record_count >= 0), "
            "CHECK (length(content_sha256) = 64), "
            "CHECK (byte_size > 0), "
            "CHECK (length(file_sha256) = 64))",
            "CREATE TABLE _segment_exporters ("
            "batch_id TEXT NOT NULL REFERENCES _segments (batch_id), "
            "exporter_id TEXT NOT NULL, "
            "delivery_status TEXT NOT NULL, "
            "PRIMARY KEY (batch_id, exporter_id), "
            "CHECK (delivery_status IN ('pending', 'delivered', 'failed')))",
            "CREATE INDEX _segment_exporters_by_status ON _segment_exporters (delivery_status)",
        ),
    ),
    Migration(
        3,
        "add_segment_origin",
        (
            # Reconciliation registers a durably-published-but-unrecorded orphan segment whose exact
            # commit instant is lost, so it records a reconstructed day-start committed_at and marks
            # the row 'reconciled'. A normal commit omits the column and defaults to 'committed', so
            # the ledger never asserts a false precise commit time as if it were original.
            "ALTER TABLE _segments ADD COLUMN origin TEXT NOT NULL DEFAULT 'committed' "
            "CHECK (origin IN ('committed', 'reconciled'))",
        ),
    ),
    Migration(
        4,
        "create_source_cursors",
        (
            # A source cursor advances only in a transaction that references an existing committed
            # segment ledger row (plan section 3.4 rule 9): the ``batch_id`` foreign key makes that
            # invariant structural — a cursor can never be written ahead of a committed segment. The
            # opaque ``position`` carries no raw provider payload, only a resumable coordinate.
            "CREATE TABLE _cursors ("
            "source TEXT PRIMARY KEY NOT NULL, "
            "position TEXT NOT NULL, "
            "batch_id TEXT NOT NULL REFERENCES _segments (batch_id), "
            "revision INTEGER NOT NULL, "
            "updated_at TEXT NOT NULL, "
            "CHECK (length(source) > 0), "
            "CHECK (length(position) > 0), "
            "CHECK (revision >= 1))",
        ),
    ),
    Migration(
        5,
        "create_derivation_checkpoints",
        (
            # Per-rule/version derivation checkpoints (plan section 3.4 rule 10). Derivation is
            # restartable and idempotent: a rule advances its checkpoint only via a compare-and-set
            # against the exact prior position, so a concurrent or replayed pass cannot fork the
            # projection. The (rule, rule_version) key keeps a rule-logic revision from silently
            # inheriting a prior version's checkpoint. ``position`` carries no raw payload.
            "CREATE TABLE _derivation_checkpoints ("
            "rule TEXT NOT NULL, "
            "rule_version INTEGER NOT NULL, "
            "position TEXT NOT NULL, "
            "revision INTEGER NOT NULL, "
            "updated_at TEXT NOT NULL, "
            "PRIMARY KEY (rule, rule_version), "
            "CHECK (length(rule) > 0), "
            "CHECK (rule_version >= 1), "
            "CHECK (revision >= 1))",
        ),
    ),
    Migration(
        6,
        "create_audit",
        (
            # Append-only audit trail for maintenance actions (plan sections 4.4/4.9). An audit row
            # records only the action, the actor class, an optional opaque resource id, an outcome,
            # a safe coded reason, and safe counts — never the acted-on raw payload (plan section
            # 4.6 'audit'). ``INTEGER PRIMARY KEY AUTOINCREMENT`` gives a monotonic, never-reused
            # sequence so the trail cannot silently lose or reorder an entry. Retention (slice 5b)
            # is the first writer; compaction (5c), purge, and backup reuse this table.
            "CREATE TABLE _audit ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "recorded_at TEXT NOT NULL, "
            "action TEXT NOT NULL, "
            "actor TEXT NOT NULL, "
            "outcome TEXT NOT NULL, "
            "resource TEXT, "
            "reason TEXT, "
            "record_count INTEGER, "
            "byte_size INTEGER, "
            "CHECK (length(action) > 0), "
            "CHECK (length(actor) > 0), "
            "CHECK (length(outcome) > 0), "
            "CHECK (record_count IS NULL OR record_count >= 0), "
            "CHECK (byte_size IS NULL OR byte_size >= 0))",
        ),
    ),
    Migration(
        7,
        "detachable_source_cursors",
        (
            # D05 privacy-expiry fix: migration 4 gave _cursors.batch_id a NOT NULL foreign key to
            # _segments, which blocked retention from deleting a privacy-expired segment an idle
            # source's cursor still referenced (the delete raised a foreign-key error that retention
            # skipped, so expired payload was retained indefinitely). Recreate _cursors with a
            # NULLABLE batch_id so retention can DETACH the cursor (set batch_id = NULL, preserving
            # the payload-free position/revision checkpoint) in the same transaction as the prune,
            # rather than losing the cursor or silently cascading it. advance_cursor still writes a
            # non-null batch_id and still requires a committed segment, so 'advance only against a
            # committed segment' is unchanged at advance time; NULL means 'advanced against a
            # since-pruned segment'. Rows are copied verbatim, so no cursor state is lost.
            "CREATE TABLE _cursors_new ("
            "source TEXT PRIMARY KEY NOT NULL, "
            "position TEXT NOT NULL, "
            "batch_id TEXT REFERENCES _segments (batch_id), "
            "revision INTEGER NOT NULL, "
            "updated_at TEXT NOT NULL, "
            "CHECK (length(source) > 0), "
            "CHECK (length(position) > 0), "
            "CHECK (revision >= 1))",
            "INSERT INTO _cursors_new (source, position, batch_id, revision, updated_at) "
            "SELECT source, position, batch_id, revision, updated_at FROM _cursors",
            "DROP TABLE _cursors",
            "ALTER TABLE _cursors_new RENAME TO _cursors",
        ),
    ),
    Migration(
        8,
        "redact_unkeyed_audit_resource",
        (
            # Privacy fix (plan section 4.7): a persisted identifier derivative must be a keyed
            # installation-local HMAC pseudonym, never a public unsalted hash — a plain SHA-256 of a
            # low-entropy batch id is dictionary-recoverable and correlates across installations.
            # Slice 5b's retention audit stored such plain digests in resource. The keyed pseudonym
            # key is created by `init` (W06), not yet wired into the control plane, so the audit
            # writers now OMIT the derivative (store NULL) until keying is available. This clears
            # any already-written unsalted resource so no reversible id survives the upgrade;
            # keyed tokens written later carry an mh_fp1_ prefix and are never produced before this.
            "UPDATE _audit SET resource = NULL WHERE resource IS NOT NULL",
        ),
    ),
)


def initialize_control_state(
    database: ControlDatabase, *, barrier: GlobalCommitBarrier, applied_at: datetime
) -> int:
    """Apply the package-owned control schema under the barrier; return the schema version."""

    return migrate(database, CONTROL_MIGRATIONS, barrier=barrier, applied_at=applied_at)
