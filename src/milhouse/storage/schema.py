"""Load the packaged, immutable ClickHouse SQL migrations (W04, plan section 4.5).

Each migration is a ``.sql`` file shipped as package data. Its content is fixed once released; the
runner records a SHA-256 checksum of the exact file bytes in the ClickHouse ledger and refuses to
proceed if an already-applied migration's checksum ever changes. The ``{database}`` placeholder is
substituted by the runner with the validated configuration identifier at apply time.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib import resources

from milhouse.storage.errors import StorageError

_MIGRATIONS_PACKAGE = "milhouse.storage.migrations"
#: (version, name, filename) for each ordered migration. Append-only; never reorder or rewrite.
_MIGRATION_FILES: tuple[tuple[int, str, str], ...] = (
    (1, "core", "0001_core.sql"),
    (2, "records", "0002_records.sql"),
    (3, "feedback", "0003_feedback.sql"),
    (4, "views", "0004_views.sql"),
    (5, "feedback_transition_dedup", "0005_feedback_transition_dedup.sql"),
)


@dataclass(frozen=True, slots=True)
class StorageMigration:
    """One ordered, immutable ClickHouse migration and the checksum of its exact file bytes."""

    version: int
    name: str
    sql: str
    checksum: str


def _load() -> tuple[StorageMigration, ...]:
    migrations: list[StorageMigration] = []
    for index, (version, name, filename) in enumerate(_MIGRATION_FILES):
        if version != index + 1:  # pragma: no cover - the packaged file list is contiguous
            raise StorageError("MH_STORAGE_MIGRATION", "migrations must be contiguous from 1")
        raw = resources.files(_MIGRATIONS_PACKAGE).joinpath(filename).read_bytes()
        sql = raw.decode("utf-8")
        if not sql.strip():  # pragma: no cover - the packaged migration bodies are non-empty
            raise StorageError("MH_STORAGE_MIGRATION", "each migration must have a non-empty body")
        migrations.append(
            StorageMigration(
                version=version,
                name=name,
                sql=sql,
                checksum=hashlib.sha256(raw).hexdigest(),
            )
        )
    return tuple(migrations)


#: The ordered, immutable ClickHouse migration set, loaded once at import.
CLICKHOUSE_MIGRATIONS: tuple[StorageMigration, ...] = _load()
