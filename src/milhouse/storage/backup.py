"""Native ClickHouse backup/restore verification core (W04 G04b, plan sections 4.5 and 10.3).

A ClickHouse native ``BACKUP``/``RESTORE`` is ClickHouse-side only: it carries the analytical
database — ``records``, ``feedback_*``, and the ``_migrations`` ledger — and nothing else. The
exporter *checkpoints* that decide which spool segments have reached ClickHouse live in the SQLite
``_segment_exporters`` delivery ledger, which a ClickHouse backup does NOT contain; the composite
backup that snapshots SQLite (its online-backup API) alongside a manifest is W16/G16. So this module
scopes G04b's "a native backup restores cleanly and matches record IDs, exporter checkpoints, and
migration state" into two fail-closed, offline-honest checks over the ClickHouse side:

* :func:`verify_restored` — a FULL record-id-set + migration-state EQUALITY (the restored
  ``records`` hold exactly the source's record-id set and the restored ``_migrations`` reports the
  same version and applied set). It requires a ``source`` snapshot captured BEFORE the backup, so it
  is proven only by the offline round-trip test and the host-gated live smoke — NOT by the
  standalone ``storage restore`` command, whose backup-time manifest is a W16 concern.
* :func:`reconcile_delivered` — a BOUNDED cross-store consistency check standing in for "matches
  exporter checkpoints": every spool segment the SQLite ledger marks ``delivered`` to the
  ``clickhouse`` exporter has all of its record ids PRESENT in the restored store. This is a subset
  check (delivered ``⊆`` restored), NOT equality — the restored store may legitimately hold more.
  Feedback-state parity (``feedback_current``) is deferred to G16 after W08 and is NOT checked here.

The boundary is kept honest. The production ``storage restore`` command verifies the restored schema
is at the current defined head and runs the BOUNDED :func:`reconcile_delivered`; the strict full
record-id EQUALITY is exercised only by the round-trip test and live smoke (which capture ``source``
before the backup), and for the standalone command would require the W16 backup manifest. The REAL
native ``BACKUP``/``RESTORE`` round-trip, its physical row/merge/TTL fidelity,
restore-to-a-new-state-root, and cross-version compatibility are exercised only against a live
ClickHouse (E06, host-gated) — this module never asserts them, and this increment does not claim
G04b passed.

Every failure is a fixed, privacy-safe ``StorageError`` (``MH_STORAGE_BACKUP`` /
``MH_STORAGE_RESTORE``) carrying no secret, credential, driver payload, or machine-local path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from milhouse.spooling.ledger import list_segment_records
from milhouse.spooling.reader import read_trusted_segment
from milhouse.state.database import ControlDatabase
from milhouse.storage._identifiers import require_identifier
from milhouse.storage.client import ClickHouseClient
from milhouse.storage.delivery import CLICKHOUSE_EXPORTER_ID
from milhouse.storage.errors import StorageError
from milhouse.storage.runner import status

# The ClickHouse ``Disk(...)`` a native BACKUP/RESTORE targets. The server MUST declare this disk
# and allow it for backups (``<storage_configuration><disks><backups>`` +
# ``<backups><allowed_disk>backups</allowed_disk>``), or the command fails with "Disk backups does
# not exist"; the reference deployment provisions it in ``ops/clickhouse/config.d/backups.xml``.
# Keeping the disk a fixed constant (never caller-supplied) means only the bounded archive name —
# the validated second Disk() argument — is ever interpolated into a statement.
_BACKUP_DISK = "backups"

# The committed-segment file layout the durable spool publishes and the replay path reads:
# ``<spool_root>/pending/<day>/<batch_id>.jsonl`` (mirrors ``milhouse.spooling.replay``). Record ids
# are not stored in the SQLite ledger — only the durable segment file carries them — so the
# cross-store reconciliation re-reads each delivered segment through the trusted reader.
_PENDING_DIRNAME = "pending"


@dataclass(frozen=True, slots=True)
class BackupSnapshot:
    """An offline-comparable fingerprint of a ClickHouse database's backup-relevant state.

    ``record_ids`` is the set of distinct ``record_id`` values in the RAW ``records`` table (every
    physical row, before ``FINAL`` deduplication or TTL removal), so it reflects exactly what a
    native backup copies rather than a query-time view. ``migration_version`` and
    ``applied_versions`` come from the checksum-protected ``_migrations`` ledger via
    :func:`milhouse.storage.runner.status`.
    """

    database: str
    migration_version: int
    applied_versions: frozenset[int]
    record_ids: frozenset[str]


def _require_database(database: object, *, code: str) -> str:
    return require_identifier(
        database, code=code, message="a bounded ClickHouse database identifier is required"
    )


def fetch_record_ids(client: ClickHouseClient, database: str) -> frozenset[str]:
    """Return the distinct ``record_id`` set from the RAW ``records`` table (validated).

    Reads ``SELECT record_id FROM <database>.records`` — the raw ``ReplacingMergeTree``, NOT the
    ``records_current`` view — so TTL removal (query-time ``expires_at`` filtering) and ``FINAL``
    deduplication cannot skew the set against what a native backup physically carries. The database
    name is validated as a bounded identifier (it is structural and cannot be parameter-bound); no
    value is interpolated. Physical duplicates of a ``record_id`` (an at-least-once redelivery not
    yet merged) collapse into the returned ``frozenset``, which is exactly the identity the
    round-trip comparison needs.
    """

    db = _require_database(database, code="MH_STORAGE_BACKUP")
    rows = client.query(f"SELECT record_id FROM {db}.records")
    return frozenset(str(row[0]) for row in rows)


def snapshot_state(client: ClickHouseClient, database: str) -> BackupSnapshot:
    """Capture the backup-relevant state of ``database`` as a :class:`BackupSnapshot`.

    Combines the migration state (version + applied set from :func:`milhouse.storage.runner.status`,
    read-only) with the raw record-id set (:func:`fetch_record_ids`). Taken once before a backup and
    once after a restore, two snapshots are compared by :func:`verify_restored`.
    """

    db = _require_database(database, code="MH_STORAGE_BACKUP")
    plan = status(client, db)
    applied = frozenset(state.version for state in plan.states if state.applied)
    return BackupSnapshot(
        database=db,
        migration_version=plan.current_version,
        applied_versions=applied,
        record_ids=fetch_record_ids(client, db),
    )


def verify_restored(source: BackupSnapshot, restored: BackupSnapshot) -> None:
    """Assert a restored snapshot matches its source, else fail closed with ``MH_STORAGE_RESTORE``.

    Fails on ANY record-id-set difference or migration version/applied-set difference and returns
    ``None`` only on an exact match. The message names the mismatched dimension but never the record
    ids or versions themselves, so it carries no potentially identifying content.
    """

    if source.record_ids != restored.record_ids:
        raise StorageError(
            "MH_STORAGE_RESTORE", "the restored record-id set does not match the source snapshot"
        )
    if (
        source.migration_version != restored.migration_version
        or source.applied_versions != restored.applied_versions
    ):
        raise StorageError(
            "MH_STORAGE_RESTORE", "the restored migration state does not match the source snapshot"
        )


def reconcile_delivered(
    control_database: ControlDatabase,
    restored: BackupSnapshot,
    *,
    spool_root: str | Path,
    installation_id: str,
) -> None:
    """Require every ``clickhouse``-delivered segment's record ids to be present in ``restored``.

    The offline-honest reading of G04b's "matches exporter checkpoints": the SQLite
    ``_segment_exporters`` ledger is the authority on which committed segments were delivered to the
    ``clickhouse`` exporter, so after restoring the native ClickHouse backup the restored
    ``records`` must contain the record ids of every such segment. Each delivered segment's record
    ids are read from its durable spool file through :func:`read_trusted_segment` (full no-follow,
    ownership, canonical, and record-provenance re-verification against ``installation_id``) because
    the ledger row itself carries no record ids — hence ``spool_root`` and ``installation_id`` are
    required alongside the control database the task's sketch names.

    This is the BOUNDED cross-store check the production ``storage restore`` command runs; it does
    NOT prove full record-id-set equality (that is :func:`verify_restored`, which is test/live
    only). A subset check (delivered ids ``⊆ restored.record_ids``), not equality, because the
    restored store may legitimately hold MORE (records from other sources). It ASSUMES no
    clickhouse-delivered record has yet reached its TTL expiry: a delivered record a live TTL merge
    has physically removed WOULD fail this check, so that TTL interaction — and any pruning of a
    delivered-then-expired segment — is host-gated (E06) and not modelled here. A missing delivered
    id fails closed with ``MH_STORAGE_RESTORE``. Reading the ledger or a durable segment raises the
    spool's own fixed ``MH_SPOOL_*`` error, which is likewise fail-closed.
    """

    root = Path(spool_root)
    for record in list_segment_records(control_database, delivery_status="delivered"):
        if not any(
            exporter.exporter_id == CLICKHOUSE_EXPORTER_ID
            and exporter.delivery_status == "delivered"
            for exporter in record.exporters
        ):
            continue  # delivered to some OTHER exporter, but not confirmed to clickhouse
        path = root / _PENDING_DIRNAME / record.day / f"{record.batch_id}.jsonl"
        parsed = read_trusted_segment(path, installation_id=installation_id)
        for frame in parsed.frames:
            if frame.record.record_id not in restored.record_ids:
                raise StorageError(
                    "MH_STORAGE_RESTORE",
                    "a clickhouse-delivered record id is absent from the restored store",
                )


def backup_statement(database: str, destination: str) -> str:
    """Build ``BACKUP DATABASE <database> TO Disk('backups', '<destination>')`` (pure, validated).

    Both the database and the destination archive name are validated as bounded
    ``[A-Za-z_][A-Za-z0-9_]{0,127}`` identifiers before the statement is built — they are structural
    parts of a ``BACKUP`` statement that cannot be server-side parameter-bound — so a malformed or
    hostile name fails closed with ``MH_STORAGE_BACKUP`` and can never be interpolated.
    """

    db = _require_database(database, code="MH_STORAGE_BACKUP")
    dest = require_identifier(
        destination,
        code="MH_STORAGE_BACKUP",
        message="a bounded backup destination name is required",
    )
    return f"BACKUP DATABASE {db} TO Disk('{_BACKUP_DISK}', '{dest}')"


def restore_statement(database: str, source: str) -> str:
    """Build ``RESTORE DATABASE <database> FROM Disk('backups', '<source>')`` (pure, validated).

    The mirror of :func:`backup_statement`: the database and source archive name are validated as
    bounded identifiers before the statement is built, failing closed with ``MH_STORAGE_RESTORE`` on
    any malformed name so nothing unbounded is interpolated into a ``RESTORE`` statement.
    """

    db = _require_database(database, code="MH_STORAGE_RESTORE")
    src = require_identifier(
        source, code="MH_STORAGE_RESTORE", message="a bounded backup source name is required"
    )
    return f"RESTORE DATABASE {db} FROM Disk('{_BACKUP_DISK}', '{src}')"


__all__ = [
    "BackupSnapshot",
    "backup_statement",
    "fetch_record_ids",
    "reconcile_delivered",
    "restore_statement",
    "snapshot_state",
    "verify_restored",
]
