"""Ordered, checksum-enforced, transactional control-plane migrations (W03 slice 1).

Each migration carries a version, a name, and a tuple of single SQL statements. Migrations apply
strictly in contiguous order from version 1; each applies together with its ledger row in one
``BEGIN IMMEDIATE`` transaction, so a crash mid-migration leaves schema and ledger consistent. An
already-applied migration whose checksum or name later differs, or a ledger that is not a contiguous
prefix of the definitions, is corruption and fails closed with a fixed ``MH_STATE_MIGRATION`` error.
Statements are single statements, not a script: SQLite's ``executescript`` implicitly commits, which
would break the atomic schema-plus-ledger boundary.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn

from milhouse.core.clock import format_timestamp
from milhouse.state.database import ControlDatabase
from milhouse.state.errors import StateError

_SCHEMA_TABLE = "_schema_migrations"


def _fail(message: str) -> NoReturn:
    raise StateError("MH_STATE_MIGRATION", message)


@dataclass(frozen=True, slots=True)
class Migration:
    """One ordered control-plane migration: a version, a name, and single SQL statements."""

    version: int
    name: str
    statements: tuple[str, ...]


def _checksum(migration: Migration) -> str:
    payload = "\n".join((str(migration.version), migration.name, *migration.statements))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_definitions(migrations: tuple[Migration, ...]) -> None:
    for index, migration in enumerate(migrations):
        expected_version = index + 1
        if type(migration) is not Migration or migration.version != expected_version:
            _fail("migrations must be contiguous positive versions starting at 1")
        if type(migration.name) is not str or not migration.name:
            _fail("each migration requires a non-empty name")
        if type(migration.statements) is not tuple or not migration.statements:
            _fail("each migration requires at least one statement")
        for statement in migration.statements:
            if type(statement) is not str or not statement.strip():
                _fail("each migration statement must be non-empty text")


def _ensure_schema_table(database: ControlDatabase) -> None:
    with database.transaction() as connection:
        connection.execute(
            f"CREATE TABLE IF NOT EXISTS {_SCHEMA_TABLE} ("
            "version INTEGER PRIMARY KEY NOT NULL, "
            "name TEXT NOT NULL, "
            "checksum TEXT NOT NULL, "
            "applied_at TEXT NOT NULL)"
        )


def _load_applied(connection: sqlite3.Connection) -> dict[int, tuple[str, str]]:
    rows = connection.execute(
        f"SELECT version, name, checksum FROM {_SCHEMA_TABLE} ORDER BY version"
    ).fetchall()
    return {int(version): (str(name), str(checksum)) for version, name, checksum in rows}


def _validate_applied_prefix(
    applied: dict[int, tuple[str, str]], migrations: tuple[Migration, ...]
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
        if recorded_name != migration.name or recorded_checksum != _checksum(migration):
            _fail("an applied migration was modified after it was recorded")


def _apply_one(database: ControlDatabase, migration: Migration, checksum: str, stamp: str) -> None:
    failed = False
    try:
        with database.transaction() as connection:
            for statement in migration.statements:
                connection.execute(statement)
            connection.execute(
                f"INSERT INTO {_SCHEMA_TABLE} (version, name, checksum, applied_at) "
                "VALUES (?, ?, ?, ?)",
                (migration.version, migration.name, checksum, stamp),
            )
    except sqlite3.Error:
        # the transaction already rolled back; normalize the SQLite detail to a fixed error.
        failed = True
    if failed:
        _fail("a migration statement failed to apply")


def apply_migrations(
    database: ControlDatabase,
    migrations: tuple[Migration, ...],
    *,
    applied_at: datetime,
) -> int:
    """Apply any unapplied migrations in contiguous order and return the resulting schema version.

    ``applied_at`` must be an aware UTC instant; it is stored as the canonical RFC3339 millisecond
    string. Applying an empty definition set is a no-op that returns the current version.
    """

    if type(migrations) is not tuple:
        _fail("migrations must be provided as an ordered tuple")
    _validate_definitions(migrations)
    stamp = format_timestamp(applied_at)
    _ensure_schema_table(database)
    applied = _load_applied(database.connection)
    _validate_applied_prefix(applied, migrations)
    highest = max(applied) if applied else 0
    for migration in migrations:
        if migration.version <= highest:
            continue
        _apply_one(database, migration, _checksum(migration), stamp)
        highest = migration.version
    return highest


def schema_version(database: ControlDatabase) -> int:
    """Return the highest applied migration version, or 0 when no migrations have been applied."""

    _ensure_schema_table(database)
    row = database.connection.execute(f"SELECT max(version) FROM {_SCHEMA_TABLE}").fetchone()
    if row is None or row[0] is None:
        return 0
    return int(row[0])
