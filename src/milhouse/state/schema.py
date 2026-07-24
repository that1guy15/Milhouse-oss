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
)


def initialize_control_state(
    database: ControlDatabase, *, barrier: GlobalCommitBarrier, applied_at: datetime
) -> int:
    """Apply the package-owned control schema under the barrier; return the schema version."""

    return migrate(database, CONTROL_MIGRATIONS, barrier=barrier, applied_at=applied_at)
