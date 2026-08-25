"""A typed in-memory fake ``ClickHouseClient`` for offline storage-runner/CLI/backup tests.

It recognizes exactly the query/command shapes the storage layer emits — ``system.databases`` /
``system.tables`` existence probes, the ledger SELECT, ``CREATE DATABASE``/``CREATE TABLE``/
``CREATE VIEW`` DDL, the ledger ``INSERT``, the ``_installation`` ownership SELECT/INSERT, the
native ``BACKUP``/``RESTORE``/``DROP DATABASE`` commands, and the raw
``SELECT record_id FROM <db>.records`` shape — and records the resulting state, so the runner's
ordering/checksum/non-mutation logic, the installation-ownership guard, AND the backup verification
core can be exercised with no network.

The single-owner ``_installation`` table is modelled per client instance as the current owning
installation id per database (the ``owners`` map), so one shared fake stands in for one ClickHouse
destination that two distinct installations can be pointed at — the exact shape the ownership guard
must distinguish. A later ``_installation`` INSERT supersedes the owner, mirroring
``ReplacingMergeTree(claimed_at)`` keeping the newest claim, and the owner travels with a
``BACKUP``/``RESTORE`` of the database slice.

Backup fidelity is modelled only at the level of logical STATE — which databases/tables exist, the
migration ledger rows, and the ``insert()`` calls (hence each ``records`` row's ``record_id``). A
``BACKUP`` copies that per-database state onto an in-memory "disk" and a ``RESTORE`` REPLACES the
database slice with a copied one (equivalent to the E06 live drill's ``DROP DATABASE`` +
``RESTORE``, so a re-restore is faithful). It models NO merges, ``FINAL``, or TTL, so only record-id
*set* equality and migration state are meaningful against it — never physical row fidelity, which is
host-gated (E06).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

_COUNT_DB = re.compile(r"SELECT count\(\) FROM system\.databases WHERE name = '([^']+)'")
_COUNT_TABLE = re.compile(
    r"SELECT count\(\) FROM system\.tables WHERE database = '([^']+)' AND name = '([^']+)'"
)
_LEDGER_SELECT = re.compile(r"SELECT version, name, checksum FROM (\w+)\._migrations FINAL")
# ``\brecords\b`` matches the raw records table but NOT ``records_current`` (``_`` is a word
# character, so no word boundary falls between ``records`` and ``_current``).
_RECORD_IDS = re.compile(r"SELECT record_id FROM (\w+)\.records\b")
_OWNER_SELECT = re.compile(r"SELECT installation_id FROM (\w+)\._installation FINAL")
_CREATE_DB = re.compile(r"CREATE DATABASE IF NOT EXISTS (\w+)")
_CREATE_OBJ = re.compile(r"CREATE (?:TABLE|VIEW) IF NOT EXISTS (\w+)\.(\w+)")
_INSERT = re.compile(
    r"INSERT INTO (\w+)\._migrations \([^)]*\) VALUES "
    r"\((\d+), '([^']*)', '([^']*)', '[^']*', '[^']*'\)"
)
_OWNER_INSERT = re.compile(
    r"INSERT INTO (\w+)\._installation \([^)]*\) VALUES \(\d+, '([^']*)', '[^']*', '[^']*'\)"
)
_BACKUP = re.compile(r"BACKUP DATABASE (\w+) TO Disk\('\w+', '(\w+)'\)")
_RESTORE = re.compile(r"RESTORE DATABASE (\w+) FROM Disk\('\w+', '(\w+)'\)")
_DROP_DB = re.compile(r"DROP DATABASE (?:IF EXISTS )?(\w+)")

# One database's captured state on the in-memory backup "disk".
_DatabaseSnapshot = dict[str, Any]

Insert = tuple[str, str, list[list[Any]], tuple[str, ...]]


class FakeClickHouseClient:
    """Records databases, tables, ledger rows, and inserts from the storage layer's statements."""

    def __init__(self) -> None:
        self.databases: set[str] = set()
        self.tables: set[tuple[str, str]] = set()
        # database -> {version: (name, checksum)}
        self.ledger: dict[str, dict[int, tuple[str, str]]] = {}
        # database -> current owning installation id (the single-owner ``_installation`` row); a
        # later INSERT supersedes it, mirroring ReplacingMergeTree(claimed_at) keeping the newest.
        self.owners: dict[str, str] = {}
        self.commands: list[str] = []
        # every insert() call: (database, table, rows, column_names)
        self.inserts: list[Insert] = []
        # in-memory backup "disk": archive name -> captured per-database state
        self.backups: dict[str, _DatabaseSnapshot] = {}

    def close(self) -> None:
        """Match the CLI's ``client.close()`` on the concrete client (no-op for the fake)."""

    def seed_ledger(self, database: str, version: int, name: str, checksum: str) -> None:
        """Pre-populate an applied-migration row (e.g. to simulate a tampered checksum)."""

        self.databases.add(database)
        self.tables.add((database, "_migrations"))
        self.ledger.setdefault(database, {})[version] = (name, checksum)

    def _snapshot_database(self, database: str) -> _DatabaseSnapshot:
        return {
            "exists": database in self.databases,
            "tables": {table for table in self.tables if table[0] == database},
            "ledger": dict(self.ledger.get(database, {})),
            "owner": self.owners.get(database),
            "inserts": [row for row in self.inserts if row[0] == database],
        }

    def _drop_database(self, database: str) -> None:
        self.databases.discard(database)
        self.tables = {table for table in self.tables if table[0] != database}
        self.ledger.pop(database, None)
        self.owners.pop(database, None)
        self.inserts = [row for row in self.inserts if row[0] != database]

    def _apply_snapshot(self, database: str, snapshot: _DatabaseSnapshot | None) -> None:
        # RESTORE replaces the database slice with the backed-up one (drop, then re-materialize). A
        # backup's ``_installation`` owner travels with it, so restoring another install's backup
        # materializes THAT installation's owner — exactly what the restore guard must reject.
        self._drop_database(database)
        if snapshot is None:
            return  # restoring an unknown archive materializes nothing (empty slice)
        if snapshot["exists"]:
            self.databases.add(database)
        self.tables |= set(snapshot["tables"])
        if snapshot["ledger"]:
            self.ledger[database] = dict(snapshot["ledger"])
        if snapshot["owner"] is not None:
            self.owners[database] = snapshot["owner"]
        self.inserts.extend(snapshot["inserts"])

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
            return
        owner_insert = _OWNER_INSERT.search(statement)
        if owner_insert is not None:
            # A later claim supersedes the owner (ReplacingMergeTree(claimed_at) keeps the newest).
            self.owners[owner_insert.group(1)] = owner_insert.group(2)
            return
        backup = _BACKUP.search(statement)
        if backup is not None:
            self.backups[backup.group(2)] = self._snapshot_database(backup.group(1))
            return
        restore = _RESTORE.search(statement)
        if restore is not None:
            self._apply_snapshot(restore.group(1), self.backups.get(restore.group(2)))
            return
        drop = _DROP_DB.search(statement)
        if drop is not None:
            self._drop_database(drop.group(1))

    def insert(
        self,
        database: str,
        table: str,
        rows: Sequence[Sequence[Any]],
        *,
        column_names: Sequence[str],
    ) -> None:
        if not rows:
            return  # mirror the real client: an empty batch is a no-op, no call recorded
        self.inserts.append((database, table, [list(row) for row in rows], tuple(column_names)))

    def query(
        self, statement: str, *, parameters: Mapping[str, Any] | None = None
    ) -> Sequence[Sequence[Any]]:
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
        record_ids = _RECORD_IDS.search(statement)
        if record_ids is not None:
            return [[value] for value in self._record_ids(record_ids.group(1))]
        owner = _OWNER_SELECT.search(statement)
        if owner is not None:
            claimed = self.owners.get(owner.group(1))
            return [[claimed]] if claimed is not None else []
        raise AssertionError(f"unexpected query: {statement}")

    def _record_ids(self, database: str) -> list[str]:
        # Rebuild the raw ``records`` record-id column from the recorded ``records`` inserts (every
        # physical row, no dedup/FINAL/TTL) — the offline stand-in for ``SELECT record_id FROM
        # <db>.records``.
        ids: list[str] = []
        for db, table, rows, columns in self.inserts:
            if db != database or table != "records" or "record_id" not in columns:
                continue
            index = list(columns).index("record_id")
            ids.extend(str(row[index]) for row in rows)
        return ids
