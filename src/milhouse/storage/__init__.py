"""W04 ClickHouse analytical storage: packaged migrations, checksum-protected runner, and client."""

from __future__ import annotations

from milhouse.storage.client import (
    ClickHouseClient,
    ConnectedClickHouseClient,
    build_client,
)
from milhouse.storage.errors import StorageError
from milhouse.storage.exporter import ExportSummary, export_records
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
    "CLICKHOUSE_MIGRATIONS",
    "ClickHouseClient",
    "ConnectedClickHouseClient",
    "ExportSummary",
    "FeedbackStateRow",
    "MigrateResult",
    "MigrationState",
    "StorageError",
    "StorageMigration",
    "StoragePlan",
    "StoredRecordV1",
    "build_client",
    "export_records",
    "fetch_current_feedback",
    "fetch_current_records",
    "migrate",
    "plan",
    "status",
]
