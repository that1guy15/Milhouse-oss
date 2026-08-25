"""W04 ClickHouse analytical storage: packaged migrations, checksum-protected runner, and client."""

from __future__ import annotations

from milhouse.storage.backup import (
    BackupSnapshot,
    backup_statement,
    fetch_record_ids,
    reconcile_delivered,
    restore_statement,
    snapshot_state,
    verify_restored,
)
from milhouse.storage.client import (
    ClickHouseClient,
    ConnectedClickHouseClient,
    build_client,
)
from milhouse.storage.delivery import CLICKHOUSE_EXPORTER_ID, ClickHouseExporter
from milhouse.storage.errors import StorageError
from milhouse.storage.exporter import ExportSummary, export_records
from milhouse.storage.ownership import claim, read_owner, require_owner
from milhouse.storage.repository import (
    FeedbackStateRow,
    StoredRecordV1,
    fetch_current_feedback,
    fetch_current_records,
)
from milhouse.storage.runner import (
    MigrateResult,
    MigrationState,
    StoragePlan,
    migrate,
    plan,
    status,
)
from milhouse.storage.schema import CLICKHOUSE_MIGRATIONS, StorageMigration

__all__ = [
    "CLICKHOUSE_EXPORTER_ID",
    "CLICKHOUSE_MIGRATIONS",
    "BackupSnapshot",
    "ClickHouseClient",
    "ClickHouseExporter",
    "ConnectedClickHouseClient",
    "ExportSummary",
    "FeedbackStateRow",
    "MigrateResult",
    "MigrationState",
    "StorageError",
    "StorageMigration",
    "StoragePlan",
    "StoredRecordV1",
    "backup_statement",
    "build_client",
    "claim",
    "export_records",
    "fetch_current_feedback",
    "fetch_current_records",
    "fetch_record_ids",
    "migrate",
    "plan",
    "read_owner",
    "reconcile_delivered",
    "require_owner",
    "restore_statement",
    "snapshot_state",
    "status",
    "verify_restored",
]
