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
)


def initialize_control_state(
    database: ControlDatabase, *, barrier: GlobalCommitBarrier, applied_at: datetime
) -> int:
    """Apply the package-owned control schema under the barrier; return the schema version."""

    return migrate(database, CONTROL_MIGRATIONS, barrier=barrier, applied_at=applied_at)
