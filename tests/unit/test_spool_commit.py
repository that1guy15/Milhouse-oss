from __future__ import annotations

import contextlib
import hashlib
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.spooling import (
    DurableSpool,
    SegmentHeaderV1,
    SegmentRecord,
    SpoolError,
    SpoolFrameV1,
    build_segment_bytes,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling import commit as commit_module
from milhouse.spooling import reconcile as reconcile_module
from milhouse.spooling.ledger import (
    authorize_local_persistence,
    load_exporters,
    validated_segment,
)
from milhouse.state import (
    GlobalCommitBarrier,
    StateError,
    initialize_control_state,
    open_control_database,
    schema_version,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)
_DAY = "2026-07-24"
_GENERATION = "a" * 64


def _envelope(
    privacy_class: str = "internal", source_event_id: str = "event-1"
) -> RecordEnvelopeV1:
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": _NOW,
        "observed_at": _NOW + timedelta(seconds=1),
        "ingested_at": _NOW + timedelta(seconds=2),
        "expires_at": _NOW + timedelta(days=30),
        "source_event_id": source_event_id,
        "operation_id": "operation-1",
        "collector_run_id": "collector-run-1",
        "scope": "target",
        "source": SourceDescriptorV1.model_validate(
            {
                "id": "example-source",
                "type": "source.event",
                "producer": "collector",
                "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
                "source_generation_digest": "0" * 64,
                "observation": {"kind": "source.revision", "parts": {"revision": 1}},
            }
        ),
        "collector": CollectorDescriptorV1(
            id="c", type="site.canary", implementation_version="1.0.0"
        ),
        "target": TargetDescriptorV1(
            id="example-target", name="E", kind="web.service", environment="test"
        ),
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": privacy_class,
        "redaction_version": "r1-e1",
        "data": EventDataV1(category="availability", status="healthy", message="ok"),
    }
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=_INSTALLATION_ID)


def _frames(privacy_class: str = "internal") -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(batch_id="batch-1", sequence=1, record=_envelope(privacy_class, "event-1")),
        SpoolFrameV1(batch_id="batch-1", sequence=2, record=_envelope(privacy_class, "event-2")),
    ]


def _header(
    frames: list[SpoolFrameV1],
    *,
    privacy_class: str = "internal",
    exporters: tuple[str, ...] = ("clickhouse",),
) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    return SegmentHeaderV1(
        batch_id="batch-1",
        config_generation=_GENERATION,
        scope="target",
        target_id="example-target",
        privacy_class=privacy_class,
        retention_days=30,
        required_exporters=exporters,
        record_count=len(frames),
        content_sha256=spool_content_sha256(lines),
    )


def _spool(tmp_path: Path):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    spool_root = tmp_path / "spool"
    spool_root.mkdir(mode=0o700)
    os.chmod(spool_root, 0o700)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    )
    return database, store, spool_root


def test_migration_creates_the_segment_and_exporter_ledgers(tmp_path: Path) -> None:
    database, _store, _spool_root = _spool(tmp_path)
    try:
        assert schema_version(database) == 11
        tables = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {
            "_segments",
            "_segment_exporters",
            "_cursors",
            "_derivation_checkpoints",
            "_audit",
        } <= tables
    finally:
        database.close()


@pytest.mark.parametrize("privacy_class", ["public", "internal", "sensitive"])
def test_commit_publishes_and_records_each_authorized_privacy_class(
    tmp_path: Path, privacy_class: str
) -> None:
    database, store, spool_root = _spool(tmp_path)
    try:
        frames = _frames(privacy_class)
        header = _header(frames, privacy_class=privacy_class)
        record = store.commit_segment(header, frames, committed_at=_NOW)
        assert isinstance(record, SegmentRecord)
        assert record.privacy_class == privacy_class

        path = spool_root / "pending" / _DAY / "batch-1.jsonl"
        content = build_segment_bytes(header, frames)
        assert path.read_bytes() == content
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600
        # the ledger digest/size describe the exact published bytes (single snapshot)
        assert record.byte_size == len(content)
        assert record.file_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    finally:
        database.close()


def test_commit_hardens_pending_directories_under_a_restrictive_umask(tmp_path: Path) -> None:
    database, store, spool_root = _spool(tmp_path)
    prior_umask = os.umask(0o777)
    try:
        frames = _frames()
        store.commit_segment(_header(frames), frames, committed_at=_NOW)
    finally:
        os.umask(prior_umask)
    try:
        pending = spool_root / "pending"
        day_dir = pending / _DAY
        assert stat.S_IMODE(os.lstat(pending).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(day_dir).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(day_dir / "batch-1.jsonl").st_mode) == 0o600
    finally:
        database.close()


@pytest.mark.parametrize("failed_level", ["pending", "day"])
def test_interrupted_pending_directory_hardening_converges_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_level: str
) -> None:
    database, store, spool_root = _spool(tmp_path)
    pending = spool_root / "pending"
    if failed_level == "day":
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
    failed_name = "pending" if failed_level == "pending" else _DAY
    failed_path = pending if failed_level == "pending" else pending / _DAY
    real_chmod = os.chmod
    failed: list[str] = []

    def _failing_chmod(target, mode, *args, **kwargs):  # type: ignore[no-untyped-def]
        if not failed and target == failed_name:
            failed.append(target)
            raise OSError("planted directory hardening interruption")
        return real_chmod(target, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", _failing_chmod)
    frames = _frames()
    header = _header(frames)
    prior_umask = os.umask(0o777)
    try:
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(header, frames, committed_at=_NOW)
    finally:
        os.umask(prior_umask)
    try:
        assert captured.value.code == "MH_SPOOL_DIR"
        assert failed == [failed_name]
        assert stat.S_IMODE(os.lstat(failed_path).st_mode) == 0

        store.commit_segment(header, frames, committed_at=_NOW)
        assert stat.S_IMODE(os.lstat(pending).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(pending / _DAY).st_mode) == 0o700
        assert (pending / _DAY / "batch-1.jsonl").is_file()
    finally:
        database.close()


@pytest.mark.parametrize("failed_level", ["pending", "day"])
def test_pending_child_fsync_failure_blocks_and_converges_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_level: str
) -> None:
    database, store, spool_root = _spool(tmp_path)
    pending = spool_root / "pending"
    if failed_level == "day":
        pending.mkdir(mode=0o700)
        os.chmod(pending, 0o700)
    failed_path = pending if failed_level == "pending" else pending / _DAY
    real_fsync = os.fsync
    failed = False

    def _failing_fsync(descriptor: int) -> None:
        nonlocal failed
        info = os.fstat(descriptor)
        if not failed and failed_path.exists():
            expected = os.lstat(failed_path)
            if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
                failed = True
                raise OSError("planted child directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", _failing_fsync)
    frames = _frames()
    header = _header(frames)
    try:
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(header, frames, committed_at=_NOW)
        assert captured.value.code == "MH_SPOOL_DIR"
        assert failed
        assert stat.S_IMODE(os.lstat(failed_path).st_mode) == 0o700

        store.commit_segment(header, frames, committed_at=_NOW)
        assert (pending / _DAY / "batch-1.jsonl").is_file()
    finally:
        database.close()


def test_pre_fchmod_writer_stage_is_cleaned_before_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, store, spool_root = _spool(tmp_path)
    day_dir = spool_root / "pending" / _DAY
    day_dir.mkdir(mode=0o700, parents=True)
    os.chmod(spool_root / "pending", 0o700)
    os.chmod(day_dir, 0o700)
    real_fchmod = os.fchmod
    failed = False

    def _failing_fchmod(descriptor: int, mode: int) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("planted pre-write fchmod failure")
        real_fchmod(descriptor, mode)

    monkeypatch.setattr(os, "fchmod", _failing_fchmod)
    frames = _frames()
    header = _header(frames)
    prior_umask = os.umask(0o777)
    try:
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(header, frames, committed_at=_NOW)
    finally:
        os.umask(prior_umask)
    try:
        assert captured.value.code == "MH_SPOOL_WRITE"
        stages = tuple(day_dir.glob(".milhouse-stage-*"))
        assert len(stages) == 1
        stage = stages[0]
        assert len(stage.name.removeprefix(".milhouse-stage-")) == 32
        assert stat.S_IMODE(os.lstat(stage).st_mode) == 0
        assert os.lstat(stage).st_size == 0

        store.commit_segment(header, frames, committed_at=_NOW)
        assert not stage.exists()
        assert (day_dir / "batch-1.jsonl").is_file()
        assert store.last_reconciliation.complete
        assert store.last_reconciliation.recovery_safe
        assert any(anomaly.kind == "stale_temp" for anomaly in store.last_reconciliation.anomalies)
    finally:
        database.close()


def test_restricted_is_rejected_and_leaves_no_directory_file_or_row(tmp_path: Path) -> None:
    database, _store, spool_root = _spool(tmp_path)
    try:
        # a restricted segment cannot even be constructed: the header rejects it up front
        with pytest.raises(SpoolError) as captured:
            _header(_frames(), privacy_class="restricted")
        assert captured.value.code == "MH_SPOOL_PRIVACY"
        # no persistence occurred
        assert not (spool_root / "pending").exists()
        assert database.connection.execute("SELECT count(*) FROM _segments").fetchone()[0] == 0
    finally:
        database.close()


def test_the_ledger_preserves_every_immutable_header_field(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        frames = _frames()
        header = _header(frames)
        store.commit_segment(header, frames, committed_at=_NOW)
        record = store.read_segment("batch-1")
        assert record is not None
        assert record.schema_version == 1
        assert record.frame_version == 1
        assert record.config_generation == _GENERATION
        assert record.scope == "target"
        assert record.target_id == "example-target"
        assert record.retention_days == 30
        assert record.content_sha256 == header.content_sha256
        assert record.day == _DAY
    finally:
        database.close()


@pytest.mark.parametrize("exporters", [(), ("clickhouse",), ("alpha", "beta")])
def test_commit_records_one_row_per_required_exporter(
    tmp_path: Path, exporters: tuple[str, ...]
) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        frames = _frames()
        header = _header(frames, exporters=exporters)
        record = store.commit_segment(header, frames, committed_at=_NOW)
        assert tuple(e.exporter_id for e in record.exporters) == exporters
        assert all(e.delivery_status == "pending" for e in record.exporters)
        assert store.read_segment("batch-1") == record
        rows = database.connection.execute(
            "SELECT count(*) FROM _segment_exporters WHERE batch_id = 'batch-1'"
        ).fetchone()[0]
        assert rows == len(exporters)
    finally:
        database.close()


def test_list_segments_filters_by_exporter_delivery_status(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        frames = _frames()
        record = store.commit_segment(_header(frames), frames, committed_at=_NOW)
        assert store.list_segments() == (record,)
        assert store.list_segments(delivery_status="pending") == (record,)
        assert store.list_segments(delivery_status="delivered") == ()
    finally:
        database.close()


def test_the_partition_day_is_derived_from_the_commit_instant(tmp_path: Path) -> None:
    database, store, spool_root = _spool(tmp_path)
    try:
        # a non-UTC instant just before UTC midnight normalizes to the next UTC day
        eastern_evening = datetime(2026, 3, 1, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
        frames = _frames()
        record = store.commit_segment(_header(frames), frames, committed_at=eastern_evening)
        assert record.day == "2026-03-02"  # 23:30 UTC-5 == 04:30Z next day
        assert (spool_root / "pending" / "2026-03-02" / "batch-1.jsonl").exists()
    finally:
        database.close()


def test_a_naive_commit_instant_fails_closed(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        frames = _frames()
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(_header(frames), frames, committed_at=datetime(2026, 7, 24, 12, 0))
        assert captured.value.code == "MH_SPOOL_COMMIT"
    finally:
        database.close()


def test_a_semantically_corrupt_ledger_row_fails_closed(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        # length-10 but not a real calendar date: passes the CHECK, must fail read-time validation
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                "config_generation, scope, target_id, privacy_class, retention_days, record_count, "
                "content_sha256, byte_size, file_sha256, committed_at) VALUES "
                "('b', '2026-13-45', 1, 1, ?, 'target', 't', 'internal', 30, 1, ?, 10, ?, "
                "'2026-13-45T00:00:00.000Z')",
                ("a" * 64, "b" * 64, "c" * 64),
            )
        with pytest.raises(SpoolError) as read_error:
            store.read_segment("b")
        assert read_error.value.code == "MH_SPOOL_LEDGER"
        with pytest.raises(SpoolError) as list_error:
            store.list_segments()
        assert list_error.value.code == "MH_SPOOL_LEDGER"
    finally:
        database.close()


# A valid ledger row in _SEGMENT_COLUMNS order, then one mutation per column a read must reject.
# Most of these are also blocked by a table CHECK, so this exercises the read-time validator
# directly (its defense behind those constraints) and gives per-column MH_SPOOL_LEDGER evidence.
_VALID_ROW: tuple[object, ...] = (
    "batch-1",
    _DAY,
    1,
    1,
    "a" * 64,
    "target",
    "example-target",
    "internal",
    30,
    2,
    "c" * 64,
    100,
    "d" * 64,
    "2026-07-24T00:00:00.000Z",
    "committed",
)


def _mutate(index: int, value: object) -> tuple[object, ...]:
    row = list(_VALID_ROW)
    row[index] = value
    return tuple(row)


def test_a_valid_row_reconstructs_a_segment_record() -> None:
    record = validated_segment(_VALID_ROW, ())
    assert record.batch_id == "batch-1"
    assert record.day == _DAY
    assert record.committed_at == "2026-07-24T00:00:00.000Z"
    assert record.origin == "committed"


@pytest.mark.parametrize(
    "row",
    [
        _mutate(1, "2026-13-45"),  # day: length 10 but not a calendar date
        _mutate(2, 2),  # schema_version
        _mutate(3, 2),  # frame_version
        _mutate(4, "z" * 64),  # config_generation: not hex
        _mutate(5, "cluster"),  # scope: not an allowed scope
        _mutate(6, None),  # target scope but no target id
        _mutate(5, "installation"),  # installation scope but a target id is present
        _mutate(7, "restricted"),  # privacy class
        _mutate(8, 0),  # retention below the floor
        _mutate(8, 4000),  # retention above the ceiling
        _mutate(9, -1),  # negative record count
        _mutate(11, 0),  # non-positive byte size
        _mutate(10, "z" * 64),  # content digest: not hex
        _mutate(12, "z" * 64),  # file digest: not hex
        _mutate(13, "not-a-stamp"),  # committed_at: not a canonical stamp
        _mutate(13, "2025-01-01T00:00:00.000Z"),  # canonical stamp, wrong day
        _mutate(14, "bogus"),  # origin: not a known origin
    ],
)
def test_every_semantically_invalid_column_is_rejected(row: tuple[object, ...]) -> None:
    with pytest.raises(ValueError):
        validated_segment(row, ())


def test_an_invalid_delivery_status_is_rejected_by_the_check(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        frames = _frames()
        store.commit_segment(_header(frames), frames, committed_at=_NOW)
        with pytest.raises(sqlite3.IntegrityError):
            with database.transaction() as connection:
                connection.execute(
                    "INSERT INTO _segment_exporters (batch_id, exporter_id, delivery_status) "
                    "VALUES ('batch-1', 'other', 'bogus')"
                )
    finally:
        database.close()


def test_the_exporter_status_validator_fails_closed_without_the_check() -> None:
    # defense in depth: even against a tampered or rebuilt table WITHOUT the CHECK constraint, the
    # read-time validator rejects an invalid delivery status
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(
            "CREATE TABLE _segment_exporters "
            "(batch_id TEXT, exporter_id TEXT, delivery_status TEXT)"
        )
        connection.execute("INSERT INTO _segment_exporters VALUES ('b', 'alpha', 'bogus')")
        with pytest.raises(ValueError):
            load_exporters(connection, "b")
    finally:
        connection.close()


def test_a_malformed_exporter_id_fails_closed(tmp_path: Path) -> None:
    # The _segment_exporters table constrains delivery_status but not exporter_id shape, so a
    # foreign or tampered exporter row must still fail closed on read.
    database, store, _spool_root = _spool(tmp_path)
    try:
        frames = _frames()
        store.commit_segment(_header(frames), frames, committed_at=_NOW)
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _segment_exporters (batch_id, exporter_id, delivery_status) "
                "VALUES ('batch-1', ?, 'pending')",
                ("not a valid id",),
            )
        with pytest.raises(SpoolError) as captured:
            store.read_segment("batch-1")
        assert captured.value.code == "MH_SPOOL_LEDGER"
    finally:
        database.close()


def test_check_constraints_reject_an_invalid_write(tmp_path: Path) -> None:
    database, _store, _spool_root = _spool(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):  # the CHECK constraint rejects the write
            with database.transaction() as connection:
                connection.execute(
                    "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                    "config_generation, scope, target_id, privacy_class, retention_days, "
                    "record_count, content_sha256, byte_size, file_sha256, committed_at) VALUES "
                    "('b', '2026-07-24', 1, 1, ?, 'target', 't', 'restricted', 30, 1, ?, 10, ?, "
                    "'2026-07-24T00:00:00.000Z')",
                    ("a" * 64, "b" * 64, "c" * 64),
                )
    finally:
        database.close()


def test_the_origin_check_rejects_an_unknown_origin(tmp_path: Path) -> None:
    database, _store, _spool_root = _spool(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):  # migration 3's origin CHECK
            with database.transaction() as connection:
                connection.execute(
                    "INSERT INTO _segments (batch_id, day, schema_version, frame_version, "
                    "config_generation, scope, target_id, privacy_class, retention_days, "
                    "record_count, content_sha256, byte_size, file_sha256, committed_at, origin) "
                    "VALUES ('b', '2026-07-24', 1, 1, ?, 'target', 't', 'internal', 30, 1, ?, 10, "
                    "?, '2026-07-24T00:00:00.000Z', 'bogus')",
                    ("a" * 64, "b" * 64, "c" * 64),
                )
    finally:
        database.close()


@pytest.mark.parametrize("privacy_class", ["public", "internal", "sensitive"])
def test_authorize_admits_every_local_persistable_class(privacy_class: str) -> None:
    authorize_local_persistence(privacy_class)  # returns without raising


def test_authorize_denies_a_restricted_class() -> None:
    # Defense behind the header check: if a restricted class reached commit, egress would deny it.
    with pytest.raises(SpoolError) as captured:
        authorize_local_persistence("restricted")
    assert captured.value.code == "MH_SPOOL_EGRESS"


def test_an_egress_denial_leaks_no_rejected_privacy_value() -> None:
    with pytest.raises(SpoolError) as captured:
        authorize_local_persistence("restricted")
    error = captured.value
    surface = " ".join([error.code, str(error), repr(error), *(str(a) for a in error.args)])
    assert "restricted" not in surface  # the rejected value never reaches the error surface
    assert error.__cause__ is None
    assert error.__context__ is None


def test_the_store_rejects_a_non_control_database_or_barrier(tmp_path: Path) -> None:
    database, _store, spool_root = _spool(tmp_path)
    barrier = GlobalCommitBarrier(tmp_path / "control" / "commit.lock")
    try:
        with pytest.raises(SpoolError) as database_error:
            DurableSpool(
                database=object(),  # type: ignore[arg-type]
                barrier=barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
            )
        assert database_error.value.code == "MH_SPOOL_STORE"
        with pytest.raises(SpoolError) as barrier_error:
            DurableSpool(
                database=database,
                barrier=object(),  # type: ignore[arg-type]
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
            )
        assert barrier_error.value.code == "MH_SPOOL_STORE"
    finally:
        database.close()


def test_commit_reports_a_barrier_acquisition_failure(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    os.chmod(tmp_path / "control" / "commit.lock", 0o644)  # tamper the lock after acquisition
    try:
        frames = _frames()
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(_header(frames), frames, committed_at=_NOW)
        assert captured.value.code == "MH_SPOOL_BARRIER"
    finally:
        os.chmod(tmp_path / "control" / "commit.lock", 0o600)
        database.close()


def test_commit_rejects_a_non_header_argument(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(object(), _frames(), committed_at=_NOW)  # type: ignore[arg-type]
        assert captured.value.code == "MH_SPOOL_HEADER"
    finally:
        database.close()


def test_reading_an_unknown_batch_returns_none(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        assert store.read_segment("no-such-batch") is None
    finally:
        database.close()


def test_the_store_rejects_a_mismatched_barrier_or_spool_root(tmp_path: Path) -> None:
    database, _store, spool_root = _spool(tmp_path)
    try:
        foreign = tmp_path / "elsewhere"
        foreign.mkdir(mode=0o700)
        os.chmod(foreign, 0o700)
        with pytest.raises(SpoolError) as barrier_error:
            DurableSpool(
                database=database,
                barrier=GlobalCommitBarrier(foreign / "commit.lock"),
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
            )
        assert barrier_error.value.code == "MH_SPOOL_STORE"
        with pytest.raises(SpoolError) as spool_error:
            DurableSpool(
                database=database,
                barrier=GlobalCommitBarrier(tmp_path / "control" / "commit.lock"),
                spool_root=foreign,
                installation_id=_INSTALLATION_ID,
            )
        assert spool_error.value.code == "MH_SPOOL_STORE"
        with pytest.raises(SpoolError) as invalid_spool:
            DurableSpool(
                database=database,
                barrier=GlobalCommitBarrier(tmp_path / "control" / "commit.lock"),
                spool_root=object(),  # type: ignore[arg-type]
                installation_id=_INSTALLATION_ID,
            )
        assert invalid_spool.value.code == "MH_SPOOL_STORE"
        assert invalid_spool.value.__cause__ is None
        assert invalid_spool.value.__context__ is None
        # A barrier beside the database but on a different lock file shares no flock with
        # maintenance, so it must be rejected even though it lives in the control directory.
        with pytest.raises(SpoolError) as wrong_lock:
            DurableSpool(
                database=database,
                barrier=GlobalCommitBarrier(tmp_path / "control" / "other.lock"),
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
            )
        assert wrong_lock.value.code == "MH_SPOOL_STORE"
        displaced_gate = GlobalCommitBarrier(tmp_path / "control" / "commit.lock")
        object.__setattr__(
            displaced_gate, "_gate_path", tmp_path / "elsewhere" / "commit.lock.gate"
        )
        with pytest.raises(SpoolError) as wrong_gate:
            DurableSpool(
                database=database,
                barrier=displaced_gate,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
            )
        assert wrong_gate.value.code == "MH_SPOOL_STORE"
        with pytest.raises(SpoolError) as id_error:
            DurableSpool(
                database=database,
                barrier=GlobalCommitBarrier(tmp_path / "control" / "commit.lock"),
                spool_root=spool_root,
                installation_id="bad",
            )
        assert id_error.value.code == "MH_SPOOL_IDENTITY"
    finally:
        database.close()


def test_spool_directories_are_created_inside_the_barrier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, store, spool_root = _spool(tmp_path)
    pending = spool_root / "pending"
    real_handoff = GlobalCommitBarrier.exclusive_then_shared

    @contextlib.contextmanager
    def _asserting_handoff(self, *, blocking: bool = True):  # type: ignore[no-untyped-def]
        assert not pending.exists()  # no namespace mutation before the barrier is held
        with real_handoff(self, blocking=blocking) as transition:
            yield transition

    monkeypatch.setattr(GlobalCommitBarrier, "exclusive_then_shared", _asserting_handoff)
    try:
        frames = _frames()
        store.commit_segment(_header(frames), frames, committed_at=_NOW)
        assert pending.exists()
    finally:
        database.close()


def test_a_duplicate_batch_fails_closed_without_touching_the_ledger(tmp_path: Path) -> None:
    database, store, _spool_root = _spool(tmp_path)
    try:
        frames = _frames()
        header = _header(frames)
        store.commit_segment(header, frames, committed_at=_NOW)
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(header, frames, committed_at=_NOW)
        assert captured.value.code == "MH_SPOOL_EXISTS"
        assert len(store.list_segments()) == 1
    finally:
        database.close()


def test_an_unreadable_ledger_fails_the_commit_before_any_publication(tmp_path: Path) -> None:
    # the pre-commit mandatory scan reads the ledger first: a broken ledger now fails closed
    # BEFORE any file is published, instead of leaving a commit-uncertain orphan
    database, store, spool_root = _spool(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _segments")
        frames = _frames()
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(_header(frames), frames, committed_at=_NOW)
        assert captured.value.code == "MH_SPOOL_LEDGER"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
        assert not (spool_root / "pending").exists()  # nothing was published
    finally:
        database.close()


def test_a_transaction_boundary_failure_after_publication_is_commit_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, store, spool_root = _spool(tmp_path)

    @contextlib.contextmanager
    def _fail_transaction(_self):  # type: ignore[no-untyped-def]
        raise StateError("MH_STATE_TXN", "planted transaction-boundary failure")
        yield  # pragma: no cover - contextmanager requires a generator

    monkeypatch.setattr(type(database), "transaction", _fail_transaction)
    try:
        frames = _frames()
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(_header(frames), frames, committed_at=_NOW)
        assert captured.value.code == "MH_SPOOL_COMMIT"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
        assert (spool_root / "pending" / _DAY / "batch-1.jsonl").exists()
    finally:
        database.close()


@pytest.mark.parametrize("failed_parent", ["spool", "pending"])
def test_a_pending_parent_fsync_failure_blocks_acknowledgement_and_is_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_parent: str
) -> None:
    database, store, spool_root = _spool(tmp_path)
    real_fsync = os.fsync
    failed_once = False
    observed: list[str] = []

    def _tracked_fsync(descriptor: int) -> None:
        nonlocal failed_once
        info = os.fstat(descriptor)
        label = "other"
        if info.st_ino == os.stat(spool_root).st_ino:
            label = "spool"
        else:
            pending = spool_root / "pending"
            if pending.exists() and info.st_ino == os.stat(pending).st_ino:
                label = "pending"
        observed.append(label)
        if label == failed_parent and not failed_once:
            failed_once = True
            raise OSError("planted parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(commit_module.os, "fsync", _tracked_fsync)
    frames = _frames()
    header = _header(frames)
    try:
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(header, frames, committed_at=_NOW)
        assert captured.value.code == "MH_SPOOL_DIR"
        assert database.connection.execute("SELECT count(*) FROM _segments").fetchone()[0] == 0
        assert not (spool_root / "pending" / _DAY / "batch-1.jsonl").exists()

        # The failed mkdir may remain visible. A retry must fsync every accepted parent again before
        # publication and may acknowledge only after both ancestor entries are durable.
        before_retry = len(observed)
        store.commit_segment(header, frames, committed_at=_NOW)
        assert failed_parent in observed[before_retry:]
        assert database.connection.execute("SELECT count(*) FROM _segments").fetchone()[0] == 1
        assert (spool_root / "pending" / _DAY / "batch-1.jsonl").exists()
    finally:
        database.close()


def test_a_non_private_spool_root_fails_closed(tmp_path: Path) -> None:
    database, store, spool_root = _spool(tmp_path)
    os.chmod(spool_root, 0o777)
    try:
        frames = _frames()
        with pytest.raises(SpoolError) as captured:
            store.commit_segment(_header(frames), frames, committed_at=_NOW)
        assert captured.value.code == "MH_SPOOL_DIR"
    finally:
        os.chmod(spool_root, 0o700)
        database.close()


@pytest.mark.parametrize("helper_name", ["_require_private_dir", "_fsync_private_dir"])
def test_private_directory_helpers_reject_unsafe_and_missing_paths(
    tmp_path: Path, helper_name: str
) -> None:
    helper = getattr(commit_module, helper_name)
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o700)
    os.chmod(unsafe, 0o777)

    with pytest.raises(SpoolError) as unsafe_error:
        helper(unsafe, "test directory")
    assert unsafe_error.value.code == "MH_SPOOL_DIR"
    assert unsafe_error.value.__cause__ is None
    assert unsafe_error.value.__context__ is None

    with pytest.raises(SpoolError) as missing_error:
        helper(tmp_path / "missing", "test directory")
    assert missing_error.value.code == "MH_SPOOL_DIR"
    assert missing_error.value.__cause__ is None
    assert missing_error.value.__context__ is None


def test_child_directory_creation_failure_is_normalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o700)

    def _fail_mkdir(_path, _mode, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise OSError("planted mkdir failure")

    monkeypatch.setattr(commit_module.os, "mkdir", _fail_mkdir)
    with pytest.raises(SpoolError) as captured:
        commit_module._secure_child_dir(parent, "pending")
    assert captured.value.code == "MH_SPOOL_DIR"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_child_directory_creation_rejects_an_unvalidated_parent_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o700)

    monkeypatch.setattr(reconcile_module, "_validated_dir_descriptor", lambda _fd: None)
    with pytest.raises(SpoolError) as captured:
        commit_module._secure_child_dir(parent, "pending")
    assert captured.value.code == "MH_SPOOL_DIR"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert not (parent / "pending").exists()
