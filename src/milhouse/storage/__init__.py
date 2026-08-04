"""W04 ClickHouse analytical storage: packaged migrations, checksum-protected runner, and client."""

from __future__ import annotations

from milhouse.storage.client import (
    ClickHouseClient,
    ConnectedClickHouseClient,
    build_client,
)
from milhouse.storage.errors import StorageError
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
    "MigrateResult",
    "MigrationState",
    "StorageError",
    "StorageMigration",
    "StoragePlan",
    "build_client",
    "migrate",
    "plan",
    "status",
]
