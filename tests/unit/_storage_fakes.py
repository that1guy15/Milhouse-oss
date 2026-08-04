"""A typed in-memory fake ``ClickHouseClient`` for offline storage-runner/CLI tests.

It recognizes exactly the query/command shapes the runner emits — ``system.databases`` /
``system.tables`` existence probes, the ledger SELECT, ``CREATE DATABASE``/``CREATE TABLE``/
``CREATE VIEW`` DDL, and the ledger ``INSERT`` — and records the resulting state, so the runner's
ordering, checksum, and non-mutation logic can be exercised with no network.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

_COUNT_DB = re.compile(r"SELECT count\(\) FROM system\.databases WHERE name = '([^']+)'")
_COUNT_TABLE = re.compile(
    r"SELECT count\(\) FROM system\.tables WHERE database = '([^']+)' AND name = '([^']+)'"
)
_LEDGER_SELECT = re.compile(r"SELECT version, name, checksum FROM (\w+)\._migrations FINAL")
_CREATE_DB = re.compile(r"CREATE DATABASE IF NOT EXISTS (\w+)")
_CREATE_OBJ = re.compile(r"CREATE (?:TABLE|VIEW) IF NOT EXISTS (\w+)\.(\w+)")
_INSERT = re.compile(
    r"INSERT INTO (\w+)\._migrations \([^)]*\) VALUES "
    r"\((\d+), '([^']*)', '([^']*)', '[^']*', '[^']*'\)"
)


class FakeClickHouseClient:
    """Records databases, tables, and ledger rows from the runner's statements."""

    def __init__(self) -> None:
        self.databases: set[str] = set()
        self.tables: set[tuple[str, str]] = set()
        # database -> {version: (name, checksum)}
        self.ledger: dict[str, dict[int, tuple[str, str]]] = {}
        self.commands: list[str] = []

    def close(self) -> None:
        """Match the CLI's ``client.close()`` on the concrete client (no-op for the fake)."""

    def seed_ledger(self, database: str, version: int, name: str, checksum: str) -> None:
        """Pre-populate an applied-migration row (e.g. to simulate a tampered checksum)."""

        self.databases.add(database)
        self.tables.add((database, "_migrations"))
        self.ledger.setdefault(database, {})[version] = (name, checksum)

    def command(self, statement: str) -> None:
        self.commands.append(statement)
        database = _CREATE_DB.search(statement)
        if database is not None:
            self.databases.add(database.group(1))
            return
        obj = _CREATE_OBJ.search(statement)
        if obj is not None:
            self.tables.add((obj.group(1), obj.group(2)))
            return
        insert = _INSERT.search(statement)
        if insert is not None:
            db, version, name, checksum = insert.groups()
            self.ledger.setdefault(db, {})[int(version)] = (name, checksum)

    def query(self, statement: str) -> Sequence[Sequence[Any]]:
        db_probe = _COUNT_DB.search(statement)
        if db_probe is not None:
            return [[1 if db_probe.group(1) in self.databases else 0]]
        table_probe = _COUNT_TABLE.search(statement)
        if table_probe is not None:
            present = (table_probe.group(1), table_probe.group(2)) in self.tables
            return [[1 if present else 0]]
        ledger = _LEDGER_SELECT.search(statement)
        if ledger is not None:
            rows = self.ledger.get(ledger.group(1), {})
            return [[version, name, checksum] for version, (name, checksum) in sorted(rows.items())]
        raise AssertionError(f"unexpected query: {statement}")
