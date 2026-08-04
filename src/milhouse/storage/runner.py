"""Checksum-protected ClickHouse migration runner (W04, plan section 4.5).

``plan`` and ``status`` are strictly read-only — they never create the database, the ledger, or any
schema. ``migrate`` creates the database if needed, then applies each pending migration's DDL
followed by a ledger row, in order. Before applying anything it re-reads the ledger and refuses to
proceed if an already-applied migration's recorded checksum no longer matches its packaged file
(fail-closed ``MH_STORAGE_MIGRATION``), so a modified applied migration can never be silently
re-run or diverge. Migrations use idempotent ``CREATE ... IF NOT EXISTS`` DDL and never drop data or
shorten retention.

The runner works over a small :class:`~milhouse.storage.client.ClickHouseClient` seam, so all of its
ordering, checksum, and non-mutation logic is unit-testable against a fake client with no network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from milhouse.core.clock import TimeError, truncate_to_milliseconds
from milhouse.storage.client import ClickHouseClient
from milhouse.storage.errors import StorageError
from milhouse.storage.schema import CLICKHOUSE_MIGRATIONS, StorageMigration

_LEDGER = "_migrations"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}", flags=re.ASCII)


def _fail(message: str) -> None:
    raise StorageError("MH_STORAGE_MIGRATION", message)


@dataclass(frozen=True, slots=True)
class MigrationState:
    """One migration's applied/pending state for status reporting."""

    version: int
    name: str
    applied: bool


@dataclass(frozen=True, slots=True)
class StoragePlan:
    """A non-mutating view of applied vs pending migrations for a database."""

    database: str
    states: tuple[MigrationState, ...]

    @property
    def applied(self) -> tuple[MigrationState, ...]:
        return tuple(state for state in self.states if state.applied)

    @property
    def pending(self) -> tuple[MigrationState, ...]:
        return tuple(state for state in self.states if not state.applied)

    @property
    def current_version(self) -> int:
        applied = [state.version for state in self.states if state.applied]
        return max(applied) if applied else 0


@dataclass(frozen=True, slots=True)
class MigrateResult:
    """The outcome of one ``migrate`` pass."""

    database: str
    applied_now: tuple[int, ...]
    already_applied: tuple[int, ...]

    @property
    def current_version(self) -> int:
        combined = (*self.already_applied, *self.applied_now)
        return max(combined) if combined else 0


def _validate_database(database: object) -> str:
    if type(database) is not str or _IDENTIFIER.fullmatch(database) is None:
        _fail("a bounded ClickHouse database identifier is required")
    return database  # type: ignore[return-value]


def _substitute(sql: str, database: str) -> str:
    return sql.replace("{database}", database)


def _statements(sql: str) -> tuple[str, ...]:
    # Strip ``--`` line comments before splitting on ``;`` so a semicolon inside a comment never
    # fragments a statement (the packaged DDL has no ``--`` inside a string literal). The checksum
    # is taken over the raw file, so stripping comments here never affects immutability.
    without_comments = re.sub(r"--[^\n]*", "", sql)
    return tuple(part.strip() for part in without_comments.split(";") if part.strip())


def _timestamp(now: datetime) -> str:
    try:
        normalized = truncate_to_milliseconds(now)
    except (TimeError, OverflowError, AttributeError, TypeError):
        _fail("the migration timestamp must be an aware in-range UTC instant")
    return normalized.strftime("%Y-%m-%d %H:%M:%S.") + f"{normalized.microsecond // 1000:03d}"


def _database_exists(client: ClickHouseClient, database: str) -> bool:
    rows = client.query(f"SELECT count() FROM system.databases WHERE name = '{database}'")
    return bool(rows) and int(rows[0][0]) > 0


def _ledger_exists(client: ClickHouseClient, database: str) -> bool:
    rows = client.query(
        f"SELECT count() FROM system.tables WHERE database = '{database}' AND name = '{_LEDGER}'"
    )
    return bool(rows) and int(rows[0][0]) > 0


def _load_ledger(client: ClickHouseClient, database: str) -> dict[int, tuple[str, str]]:
    """Return {version: (name, checksum)} from the ledger, or empty if it does not exist yet."""

    if not _database_exists(client, database) or not _ledger_exists(client, database):
        return {}
    rows = client.query(
        f"SELECT version, name, checksum FROM {database}.{_LEDGER} FINAL ORDER BY version"
    )
    return {int(version): (str(name), str(checksum)) for version, name, checksum in rows}


def _validate_applied_prefix(
    applied: dict[int, tuple[str, str]], migrations: tuple[StorageMigration, ...]
) -> None:
    if not applied:
        return
    versions = sorted(applied)
    if versions != list(range(1, len(versions) + 1)):
        _fail("the migration ledger is not a contiguous prefix")
    if versions[-1] > len(migrations):
        _fail("the migration ledger records versions with no matching definition")
    for migration in migrations[: versions[-1]]:
        recorded_name, recorded_checksum = applied[migration.version]
        if recorded_name != migration.name or recorded_checksum != migration.checksum:
            _fail("an applied migration was modified after it was recorded")


def plan(
    client: ClickHouseClient,
    database: str,
    *,
    migrations: tuple[StorageMigration, ...] = CLICKHOUSE_MIGRATIONS,
) -> StoragePlan:
    """Return the applied/pending plan WITHOUT mutating anything (no database or ledger created)."""

    database = _validate_database(database)
    applied = _load_ledger(client, database)
    _validate_applied_prefix(applied, migrations)
    states = tuple(
        MigrationState(migration.version, migration.name, migration.version in applied)
        for migration in migrations
    )
    return StoragePlan(database=database, states=states)


def status(
    client: ClickHouseClient,
    database: str,
    *,
    migrations: tuple[StorageMigration, ...] = CLICKHOUSE_MIGRATIONS,
) -> StoragePlan:
    """Alias of :func:`plan`; both are read-only migration-status reports."""

    return plan(client, database, migrations=migrations)


def migrate(
    client: ClickHouseClient,
    database: str,
    *,
    now: datetime,
    milhouse_version: str,
    migrations: tuple[StorageMigration, ...] = CLICKHOUSE_MIGRATIONS,
) -> MigrateResult:
    """Apply every pending migration in order; refuse an altered applied checksum first."""

    database = _validate_database(database)
    stamp = _timestamp(now)
    client.command(f"CREATE DATABASE IF NOT EXISTS {database}")
    applied = _load_ledger(client, database)
    _validate_applied_prefix(applied, migrations)

    applied_now: list[int] = []
    already: list[int] = []
    for migration in migrations:
        if migration.version in applied:
            already.append(migration.version)
            continue
        for statement in _statements(_substitute(migration.sql, database)):
            client.command(statement)
        columns = "version, name, checksum, applied_at, milhouse_version"
        values = (
            f"({migration.version}, '{migration.name}', '{migration.checksum}', "
            f"'{stamp}', '{milhouse_version}')"
        )
        client.command(f"INSERT INTO {database}.{_LEDGER} ({columns}) VALUES {values}")
        applied_now.append(migration.version)
    return MigrateResult(
        database=database, applied_now=tuple(applied_now), already_applied=tuple(already)
    )
