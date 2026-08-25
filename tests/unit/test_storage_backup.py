"""Offline verification core for native ClickHouse backup/restore (W04 G04b, plan 4.5 and 10.3).

These prove exactly the offline-honest half of G04b's "a native backup restores cleanly and matches
record IDs, exporter checkpoints, and migration state":

* the record-id-set + migration-state round-trip (:func:`snapshot_state` / :func:`verify_restored`),
  including that any drift fails closed with the fixed ``MH_STORAGE_RESTORE`` code;
* the cross-store reconciliation (:func:`reconcile_delivered`) against a REAL spool delivery
  ledger — the offline reading of "matches exporter checkpoints", including a missing delivered id
  failing closed;
* the pure, identifier-validated statement builders.

They assert only ID-set/migration equality and cross-store subset membership because the fake models
no merges/``FINAL``/TTL. The REAL native ``BACKUP``/``RESTORE`` round-trip, physical row fidelity,
and version compatibility are host-gated (E06, ``tests/live/test_clickhouse_smoke.py``); this suite
does not claim G04b passed. Feedback-state parity is deferred to G16.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from _record_factories import (
    INSTALLATION_ID,
    NOW,
    event_record,
    feedback_item_record,
    feedback_transition_record,
)
from _storage_fakes import FakeClickHouseClient

from milhouse.domain.records import RecordEnvelopeV1
from milhouse.spooling import (
    DurableSpool,
    SegmentHeaderV1,
    SegmentRecord,
    SpoolFrameV1,
    replay_segments,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
)
from milhouse.storage import (
    CLICKHOUSE_EXPORTER_ID,
    BackupSnapshot,
    ClickHouseExporter,
    StorageError,
    backup_statement,
    export_records,
    fetch_record_ids,
    migrate,
    reconcile_delivered,
    restore_statement,
    snapshot_state,
    verify_restored,
)

_DB = "milhouse"
_GENERATION = "a" * 64
_FULL_SCHEMA = frozenset({1, 2, 3, 4, 5, 6})


# --- backup/restore round-trip over the fake (state-level fidelity) ---


def test_backup_restore_round_trip_matches_record_ids_and_migration_state() -> None:
    fake = FakeClickHouseClient()
    migrate(fake, _DB, now=NOW, milhouse_version="test")
    records = (event_record(), feedback_item_record(), feedback_transition_record())
    export_records(fake, _DB, records)

    source = snapshot_state(fake, _DB)
    assert source.migration_version == 6
    assert source.applied_versions == _FULL_SCHEMA
    assert source.record_ids == frozenset(record.record_id for record in records)

    fake.command(backup_statement(_DB, "backup_one"))
    # Dropping the live database leaves the backup intact on the in-memory "disk".
    fake.command(f"DROP DATABASE IF EXISTS {_DB}")
    dropped = snapshot_state(fake, _DB)
    assert dropped.migration_version == 0
    assert dropped.record_ids == frozenset()

    fake.command(restore_statement(_DB, "backup_one"))
    restored = snapshot_state(fake, _DB)
    verify_restored(source, restored)  # returns None on an exact match
    assert restored == source


def test_snapshot_state_reads_raw_records_not_the_current_view() -> None:
    # snapshot_state fingerprints the RAW records table, so an unmerged physical duplicate (an
    # at-least-once redelivery) collapses into the id set rather than skewing it — and it never
    # queries records_current, whose TTL/FINAL the fake does not model.
    fake = FakeClickHouseClient()
    migrate(fake, _DB, now=NOW, milhouse_version="test")
    record = event_record()
    export_records(fake, _DB, (record,))
    export_records(fake, _DB, (record,))  # redeliver the same record_id physically
    assert snapshot_state(fake, _DB).record_ids == frozenset({record.record_id})


def test_verify_restored_returns_none_on_exact_match() -> None:
    snapshot = BackupSnapshot(
        database=_DB,
        migration_version=6,
        applied_versions=_FULL_SCHEMA,
        record_ids=frozenset({"mh_r_a", "mh_r_b"}),
    )
    assert verify_restored(snapshot, snapshot) is None


def test_verify_restored_fails_closed_on_a_record_id_mismatch() -> None:
    source = BackupSnapshot(_DB, 6, _FULL_SCHEMA, frozenset({"mh_r_a", "mh_r_b"}))
    restored = BackupSnapshot(_DB, 6, _FULL_SCHEMA, frozenset({"mh_r_a"}))  # lost mh_r_b
    with pytest.raises(StorageError) as captured:
        verify_restored(source, restored)
    assert captured.value.code == "MH_STORAGE_RESTORE"


def test_verify_restored_fails_closed_on_a_migration_state_mismatch() -> None:
    ids = frozenset({"mh_r_a"})
    source = BackupSnapshot(_DB, 6, _FULL_SCHEMA, ids)
    # Same record ids, but a lower/incomplete migration head must still fail closed.
    behind = BackupSnapshot(_DB, 5, frozenset({1, 2, 3, 4, 5}), ids)
    with pytest.raises(StorageError) as captured:
        verify_restored(source, behind)
    assert captured.value.code == "MH_STORAGE_RESTORE"


# --- cross-store reconciliation against a REAL spool delivery ledger ---


def _spool(tmp_path: Path):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=NOW)
    spool_root = tmp_path / "spool"
    spool_root.mkdir(mode=0o700)
    os.chmod(spool_root, 0o700)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=INSTALLATION_ID
    )
    return database, barrier, spool_root, store


def _commit(
    store: DurableSpool, batch_id: str, records: tuple[RecordEnvelopeV1, ...]
) -> SegmentRecord:
    frames = [
        SpoolFrameV1(batch_id=batch_id, sequence=index, record=record)
        for index, record in enumerate(records, start=1)
    ]
    header = SegmentHeaderV1(
        batch_id=batch_id,
        config_generation=_GENERATION,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=(CLICKHOUSE_EXPORTER_ID,),
        record_count=len(frames),
        content_sha256=spool_content_sha256([spool_frame_line(frame) for frame in frames]),
    )
    return store.commit_segment(header, frames, committed_at=NOW)


def _deliver(database, barrier, spool_root, fake: FakeClickHouseClient) -> None:
    replay_segments(
        database,
        barrier,
        spool_root=spool_root,
        installation_id=INSTALLATION_ID,
        exporters={CLICKHOUSE_EXPORTER_ID: ClickHouseExporter(fake, _DB)},
        now=NOW,
        delivery_status="pending",
    )


def test_reconcile_delivered_passes_when_every_delivered_id_is_present(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record = feedback_transition_record()
        _commit(store, "batch-a", (record,))
        fake = FakeClickHouseClient()
        _deliver(database, barrier, spool_root, fake)

        restored = snapshot_state(fake, _DB)
        assert record.record_id in restored.record_ids
        # Every clickhouse-delivered segment's record ids are present in the restored store.
        reconcile_delivered(
            database, restored, spool_root=spool_root, installation_id=INSTALLATION_ID
        )
    finally:
        database.close()


def test_reconcile_delivered_fails_closed_when_a_delivered_id_is_missing(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", (feedback_transition_record(),))
        fake = FakeClickHouseClient()
        _deliver(database, barrier, spool_root, fake)

        # A restored store MISSING the delivered record id fails closed — the store does not match
        # what the SQLite ledger delivered to clickhouse.
        empty = BackupSnapshot(
            database=_DB, migration_version=0, applied_versions=frozenset(), record_ids=frozenset()
        )
        with pytest.raises(StorageError) as captured:
            reconcile_delivered(
                database, empty, spool_root=spool_root, installation_id=INSTALLATION_ID
            )
        assert captured.value.code == "MH_STORAGE_RESTORE"
    finally:
        database.close()


def test_reconcile_delivered_ignores_a_segment_not_delivered_to_clickhouse(tmp_path: Path) -> None:
    # A committed-but-undelivered segment (never confirmed to clickhouse) is not reconciled, so an
    # empty restored store still passes: reconciliation is scoped to CONFIRMED clickhouse delivery.
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", (feedback_transition_record(),))  # committed, never delivered
        empty = BackupSnapshot(
            database=_DB, migration_version=0, applied_versions=frozenset(), record_ids=frozenset()
        )
        reconcile_delivered(database, empty, spool_root=spool_root, installation_id=INSTALLATION_ID)
    finally:
        database.close()


# --- pure statement builders ---


def test_backup_and_restore_statement_shapes() -> None:
    assert (
        backup_statement("milhouse", "backup_one")
        == "BACKUP DATABASE milhouse TO Disk('backups', 'backup_one')"
    )
    assert (
        restore_statement("milhouse", "backup_one")
        == "RESTORE DATABASE milhouse FROM Disk('backups', 'backup_one')"
    )


@pytest.mark.parametrize("bad", ["bad-db", "bad.db", "1bad", "", "milhouse; DROP", "a" * 200])
def test_backup_statement_rejects_a_bad_database_or_destination(bad: str) -> None:
    with pytest.raises(StorageError) as on_database:
        backup_statement(bad, "backup_one")
    assert on_database.value.code == "MH_STORAGE_BACKUP"
    with pytest.raises(StorageError) as on_destination:
        backup_statement("milhouse", bad)
    assert on_destination.value.code == "MH_STORAGE_BACKUP"


@pytest.mark.parametrize("bad", ["bad-db", "bad src", "src;", ""])
def test_restore_statement_rejects_a_bad_database_or_source(bad: str) -> None:
    with pytest.raises(StorageError) as on_database:
        restore_statement(bad, "backup_one")
    assert on_database.value.code == "MH_STORAGE_RESTORE"
    with pytest.raises(StorageError) as on_source:
        restore_statement("milhouse", bad)
    assert on_source.value.code == "MH_STORAGE_RESTORE"


def test_fetch_record_ids_rejects_a_bad_database_before_querying() -> None:
    with pytest.raises(StorageError) as captured:
        fetch_record_ids(FakeClickHouseClient(), "bad-db")
    assert captured.value.code == "MH_STORAGE_BACKUP"
