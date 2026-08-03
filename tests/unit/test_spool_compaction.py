"""Behavioural + crash guarantees for audited compaction (W03 slice 5c).

compact_apply rewrites a mixed-expiry committed segment into a new segment holding only the still
unexpired frames, under exclusive maintenance authority with a confirm token. It re-verifies the old
segment under the lock, publishes and verifies the new file before retiring the old, records the
old->new lineage in the audit trail, and converges after an interrupted pass — the deterministic new
batch id makes a re-run idempotent, and no unexpired record is ever lost.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.config import load_config, resolve_runtime_paths
from milhouse.config._models import MilhouseConfig
from milhouse.config.filesystem import SecureFileError, SecureFileErrorKind
from milhouse.config.paths import RuntimePaths
from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.privacy import create_pseudonym_key
from milhouse.privacy.pseudonym import Pseudonymizer
from milhouse.spooling import (
    CompactionResult,
    DurableSpool,
    SegmentHeaderV1,
    SpoolFrameV1,
    compact_apply,
    deliver_segment,
    read_trusted_segment,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling import compaction as compaction_module
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.intents import is_recorded_successor, read_rehome_target
from milhouse.spooling.ledger import ORIGIN_COMMITTED, insert_segment_row, read_segment_record
from milhouse.spooling.segment import is_reserved_compaction_batch_id
from milhouse.state import (
    GlobalCommitBarrier,
    StateError,
    advance_cursor,
    initialize_control_state,
    list_audit,
    open_control_database,
    read_cursor,
)
from milhouse.state.installation import establish_installation_key, read_installation_key

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_DAY = "2026-07-28"
_GENERATION = "a" * 64
_EXPIRED_AT = _NOW + timedelta(hours=1)
_LIVE_AT = _NOW + timedelta(days=30)
_APPLY_NOW = _NOW + timedelta(days=1)
# A07: compaction loads the installation key from the config/paths boundary; every apply passes a
# runtime whose key file holds these fixed bytes, so lineage fingerprints match this Pseudonymizer.
_KEY_BYTES = b"\xa1" * 32
_PSEUDONYMIZER = Pseudonymizer(_KEY_BYTES)
_EXAMPLE_CONFIG = Path(__file__).resolve().parents[2] / "config/examples/local-only.toml"


def _make_runtime(base: Path) -> tuple[MilhouseConfig, RuntimePaths]:
    base = base.resolve()  # macOS /var -> /private/var; the loader rejects symlink components
    config_dir = base / "config"
    config_dir.mkdir(parents=True)
    config_file = config_dir / "milhouse.toml"
    config_file.write_text(
        _EXAMPLE_CONFIG.read_text(encoding="utf-8").replace(
            'home = "../../data/local-only"', 'home = "../state"'
        ),
        encoding="utf-8",
    )
    config, selection = load_config(config_file, platform_default=config_file, env={})
    paths = resolve_runtime_paths(
        config, config_path=selection, platform_data_root=base / "platform", env={}
    )
    paths.pseudonym_key.parent.mkdir(parents=True, mode=0o700)
    return config, paths


# A07 binds compaction to each control database's OWN state root: the config/runtime state root must
# equal the database's state root, and the key id/epoch loaded there must equal the record in that
# database. So each test's runtime is co-located with its database (see _spool) and registered
# by database identity; _compact resolves it. There is no shared, database-independent runtime —
# exactly the caller-forgeable-key defect this closes (G03 review #79-P1-2).
_RUNTIMES: dict[int, tuple[MilhouseConfig, RuntimePaths]] = {}


def _provision_key(database, config: MilhouseConfig, paths: RuntimePaths) -> Pseudonymizer:
    """Create the installation key (deterministic bytes) at the config/paths location and record its
    non-secret id/epoch in the control plane, exactly as `init` (W06) will."""

    pseudonymizer = create_pseudonym_key(config, paths, random_bytes=lambda size: _KEY_BYTES)
    with database.transaction() as connection:
        establish_installation_key(connection, key_id=pseudonymizer.key_id, epoch=1, now=_NOW)
    return pseudonymizer


class _FakeExporter:
    def __init__(self, exporter_id: str) -> None:
        self._exporter_id = exporter_id

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record, frames) -> None:
        return None


def _envelope(source_event_id: str, expires_at: datetime) -> RecordEnvelopeV1:
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": _NOW,
        "observed_at": _NOW + timedelta(seconds=1),
        "ingested_at": _NOW + timedelta(seconds=2),
        "expires_at": expires_at,
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
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "data": EventDataV1(category="availability", status="healthy", message="ok"),
    }
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=_INSTALLATION_ID)


def _frames(batch_id: str, specs: list[tuple[str, datetime]]) -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(batch_id=batch_id, sequence=index, record=_envelope(event_id, expires_at))
        for index, (event_id, expires_at) in enumerate(specs, start=1)
    ]


def _header(
    batch_id: str, frames: list[SpoolFrameV1], exporters=("clickhouse",)
) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    return SegmentHeaderV1(
        batch_id=batch_id,
        config_generation=_GENERATION,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=exporters,
        record_count=len(frames),
        content_sha256=spool_content_sha256(lines),
    )


def _spool(tmp_path: Path, *, provision_key: bool = True):
    # Co-locate the control database and spool UNDER the runtime's own state root, so the database's
    # state root (database_path.parent.parent) equals paths.state_root — the binding A07 requires.
    # The control dir (the key's parent, ``<state_root>/control``) and the spool (``<state_root>/
    # spool``) are already created by the runtime; the database, barrier, and key all live
    # in the control dir alongside the key file.
    config, paths = _make_runtime(tmp_path)
    control = paths.pseudonym_key.parent
    os.chmod(control, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    spool_root = paths.spool
    spool_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(spool_root, 0o700)
    if provision_key:
        _provision_key(database, config, paths)
    _RUNTIMES[id(database)] = (config, paths)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    )
    return database, barrier, spool_root, store


def _commit(store, batch_id: str, specs: list[tuple[str, datetime]], exporters=("clickhouse",)):
    frames = _frames(batch_id, specs)
    record = store.commit_segment(_header(batch_id, frames, exporters), frames, committed_at=_NOW)
    return record, frames


def _segment_file(spool_root: Path, batch_id: str) -> Path:
    return spool_root / "pending" / _DAY / f"{batch_id}.jsonl"


def _segment_rows(database) -> set[str]:
    return {
        row[0] for row in database.connection.execute("SELECT batch_id FROM _segments").fetchall()
    }


def _reconcile(database, barrier, spool_root) -> None:
    # A fresh writer acquisition runs mandatory reconciliation, re-registering orphan files.
    DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    )


def _compact(
    database, barrier, spool_root, *, now=_APPLY_NOW, confirm=True, runtime=None
) -> CompactionResult:
    config, paths = runtime if runtime is not None else _RUNTIMES[id(database)]
    return compact_apply(
        database,
        barrier,
        spool_root=spool_root,
        installation_id=_INSTALLATION_ID,
        now=now,
        confirm=confirm,
        config=config,
        paths=paths,
    )


def _record_ids(spool_root: Path, batch_id: str) -> list[str]:
    parsed = read_trusted_segment(
        _segment_file(spool_root, batch_id), installation_id=_INSTALLATION_ID
    )
    return [str(frame.record.record_id) for frame in parsed.frames]


def _audit_bytes(database) -> bytes:
    return b"".join(
        bytes(str(cell), "utf-8")
        for row in database.connection.execute("SELECT * FROM _audit").fetchall()
        for cell in row
        if cell is not None
    )


# --------------------------------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------------------------------


def test_confirm_is_required(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        with pytest.raises(SpoolError) as captured:
            _compact(database, barrier, spool_root, confirm=False)
        assert captured.value.code == "MH_SPOOL_COMPACTION"
        assert _segment_rows(database) == {"batch-a"}  # untouched
        assert _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_a_foreign_barrier_is_refused(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        foreign = GlobalCommitBarrier(tmp_path / "unrelated.lock")
        with pytest.raises(SpoolError) as captured:
            _compact(database, foreign, spool_root)
        assert captured.value.code == "MH_SPOOL_COMPACTION"
    finally:
        database.close()


def test_a_mismatched_spool_root_is_refused(tmp_path: Path) -> None:
    database, barrier, _spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        shadow = tmp_path / "shadow"
        shadow.mkdir(mode=0o700)
        with pytest.raises(SpoolError) as captured:
            _compact(database, barrier, shadow)
        assert captured.value.code == "MH_SPOOL_COMPACTION"
    finally:
        database.close()


def test_a_naive_now_is_rejected(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        with pytest.raises(SpoolError) as captured:
            _compact(database, barrier, spool_root, now=datetime(2026, 7, 29, 12))  # naive
        assert captured.value.code == "MH_SPOOL_COMPACTION"
    finally:
        database.close()


def test_a_bad_installation_id_is_rejected(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    config, paths = _RUNTIMES[id(database)]
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        with pytest.raises(SpoolError) as captured:
            compact_apply(
                database,
                barrier,
                spool_root=spool_root,
                installation_id="not-an-id",
                now=_APPLY_NOW,
                confirm=True,
                config=config,
                paths=paths,
            )
        assert captured.value.code == "MH_SPOOL_IDENTITY"
    finally:
        database.close()


def test_a_wrong_type_database_or_root_is_rejected(tmp_path: Path) -> None:
    database, barrier, spool_root, _store = _spool(tmp_path)
    config, paths = _RUNTIMES[id(database)]
    try:
        with pytest.raises(SpoolError) as bad_db:
            compact_apply(
                object(),  # type: ignore[arg-type]
                barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
                config=config,
                paths=paths,
            )
        assert bad_db.value.code == "MH_SPOOL_COMPACTION"
        with pytest.raises(SpoolError) as bad_root:
            compact_apply(
                database,
                barrier,
                spool_root=123,  # type: ignore[arg-type]
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
                config=config,
                paths=paths,
            )
        assert bad_root.value.code == "MH_SPOOL_COMPACTION"
    finally:
        database.close()


def test_a_wrong_type_barrier_is_rejected(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    config, paths = _RUNTIMES[id(database)]
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        with pytest.raises(SpoolError) as captured:
            compact_apply(
                database,
                object(),  # type: ignore[arg-type]
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
                config=config,
                paths=paths,
            )
        assert captured.value.code == "MH_SPOOL_COMPACTION"
    finally:
        database.close()


def test_compaction_establishes_the_installation_key_on_first_use(tmp_path: Path) -> None:
    # W03 owns a usable maintenance lifecycle before the later CLI work packages exist. A newly
    # initialized or upgraded control plane with migration 11 but no key row/file therefore creates
    # and records its key under the barrier before compacting.
    database, barrier, spool_root, store = _spool(tmp_path, provision_key=False)
    _config, paths = _RUNTIMES[id(database)]
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        assert read_installation_key(database) is None
        assert not paths.pseudonym_key.exists()

        result = _compact(database, barrier, spool_root)

        assert len(result.compacted) == 1
        recorded = read_installation_key(database)
        assert recorded is not None
        assert recorded[1] == 1
        assert paths.pseudonym_key.is_file()
        assert _segment_rows(database) != {"batch-a"}
    finally:
        database.close()


def test_key_file_to_control_row_interruption_is_adopted_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The key file is durably published before its non-secret identity row. A database failure in
    # that window leaves a valid unrecorded file, never a row-without-key. The next production call
    # adopts that exact file and converges before touching spool state.
    database, barrier, spool_root, store = _spool(tmp_path, provision_key=False)
    _config, paths = _RUNTIMES[id(database)]
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])

        def fail_establishment(*_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            raise StateError("MH_STATE_INSTALLATION_KEY", "synthetic establishment failure")

        monkeypatch.setattr(compaction_module, "establish_installation_key", fail_establishment)
        with pytest.raises(SpoolError) as captured:
            _compact(database, barrier, spool_root)
        assert captured.value.code == "MH_SPOOL_COMPACTION"
        assert paths.pseudonym_key.is_file()
        assert read_installation_key(database) is None
        assert _segment_rows(database) == {"batch-a"}
        assert list_audit(database) == ()

        monkeypatch.setattr(
            compaction_module, "establish_installation_key", establish_installation_key
        )
        result = _compact(database, barrier, spool_root)
        assert len(result.compacted) == 1
        assert read_installation_key(database) is not None
    finally:
        database.close()


def test_key_establishment_reuses_identity_completed_while_waiting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, _spool_root, _store = _spool(tmp_path, provision_key=False)
    config, paths = _RUNTIMES[id(database)]
    observed = iter((None, _PSEUDONYMIZER))
    monkeypatch.setattr(
        compaction_module,
        "_load_recorded_installation_key",
        lambda *_args: next(observed),
    )
    try:
        loaded = compaction_module._load_or_establish_installation_key(
            database, barrier, config, paths, _APPLY_NOW
        )
        assert loaded is _PSEUDONYMIZER
        assert read_installation_key(database) is None
    finally:
        database.close()


def test_key_establishment_rejects_an_invalid_existing_key_before_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, _spool_root, _store = _spool(tmp_path, provision_key=False)
    config, paths = _RUNTIMES[id(database)]
    monkeypatch.setattr(
        compaction_module,
        "_load_recorded_installation_key",
        lambda *_args: None,
    )

    def invalid_key(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise compaction_module.PrivacyError("MH_PRIVACY_KEY_MODE", "synthetic invalid key")

    monkeypatch.setattr(compaction_module, "load_pseudonym_key", invalid_key)
    try:
        with pytest.raises(SpoolError) as captured:
            compaction_module._load_or_establish_installation_key(
                database, barrier, config, paths, _APPLY_NOW
            )
        assert captured.value.code == "MH_SPOOL_COMPACTION"
        assert read_installation_key(database) is None
    finally:
        database.close()


def test_compaction_fails_closed_on_a_wrong_installation_key(tmp_path: Path) -> None:
    # A07 / review #79-P1-2 (exact reproduction): loading a valid key at the bound path is NOT proof
    # of installation identity. After provisioning key A (recorded in the control plane), replacing
    # the key file with a DIFFERENT valid 32-byte key B fails compaction closed before mutation —
    # the loaded key's id no longer matches the recorded id, so no unattributable lineage lands.
    database, barrier, spool_root, store = _spool(tmp_path)
    _config, paths = _RUNTIMES[id(database)]
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        paths.pseudonym_key.write_bytes(b"\xb2" * 32)  # a different valid 32-byte key (key B)
        os.chmod(paths.pseudonym_key, 0o600)
        with pytest.raises(SpoolError) as captured:
            _compact(database, barrier, spool_root)
        assert captured.value.code == "MH_SPOOL_COMPACTION"
        assert _segment_rows(database) == {"batch-a"}  # nothing mutated
        assert list_audit(database) == ()  # no lineage written
    finally:
        database.close()


def test_compaction_fails_closed_on_a_cross_installation_state_root(tmp_path: Path) -> None:
    # A07 / review #79-P1-2 (reproduction): the config/runtime state root must equal the control
    # database's state root, so a config/paths pair from ANOTHER fully provisioned installation (its
    # own state root + key) cannot key this database's lineage. It fails closed before any mutation.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        other_db, _ob, _osr, _ostore = _spool(tmp_path / "other")
        try:
            other_runtime = _RUNTIMES[id(other_db)]
            with pytest.raises(SpoolError) as captured:
                _compact(database, barrier, spool_root, runtime=other_runtime)
            assert captured.value.code == "MH_SPOOL_COMPACTION"
            assert _segment_rows(database) == {"batch-a"}  # nothing mutated
            assert list_audit(database) == ()  # no lineage written
        finally:
            other_db.close()
    finally:
        database.close()


def test_a_closed_database_is_rejected(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
    database.close()
    with pytest.raises(SpoolError) as captured:
        _compact(database, barrier, spool_root)
    assert captured.value.code == "MH_SPOOL_COMPACTION"


# --------------------------------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------------------------------


def test_a_fully_live_segment_is_left_alone(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _LIVE_AT), ("a2", _LIVE_AT)])
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert [(s.batch_id, s.status) for s in result.skipped] == [("batch-a", "live")]
        assert _segment_rows(database) == {"batch-a"}
        assert _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_a_fully_expired_segment_is_left_for_retention(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _EXPIRED_AT)])
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert [s.status for s in result.skipped] == ["fully_expired"]
        assert _segment_rows(database) == {"batch-a"}  # compaction never deletes; retention does
    finally:
        database.close()


def test_an_unreadable_segment_is_skipped(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        # Corrupt the durable file so the trusted read fails closed.
        path = _segment_file(spool_root, "batch-a")
        os.chmod(path, 0o600)
        with path.open("r+b") as handle:
            handle.write(b"{ corrupt")
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert result.skipped[0].status == "unreadable"
        assert result.skipped[0].code is not None
        assert _segment_rows(database) == {"batch-a"}  # left intact
    finally:
        database.close()


def test_a_disagreeing_segment_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _LIVE_AT)])
        # Force the old segment's file to disagree with its ledger row.
        monkeypatch.setattr(compaction_module, "_agrees", lambda *args, **kwargs: False)
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert result.skipped[0].status == "disagreeing"
        assert _segment_rows(database) == {"batch-a"}
    finally:
        database.close()


# --------------------------------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------------------------------


def test_compacts_a_mixed_segment_into_unexpired_only(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _record, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        live_record_id = str(frames[1].record.record_id)

        result = _compact(database, barrier, spool_root)

        assert len(result.compacted) == 1
        done = result.compacted[0]
        assert done.old_batch_id == "batch-a"
        assert done.new_batch_id.startswith("c")
        assert (done.dropped_records, done.retained_records) == (1, 1)
        assert done.file_outcome == "removed"
        assert result.dropped_records == 1
        assert result.retained_records == 1

        # Old segment fully retired; new segment committed with ONLY the live record.
        assert _segment_rows(database) == {done.new_batch_id}
        assert not _segment_file(spool_root, "batch-a").exists()
        assert _segment_file(spool_root, done.new_batch_id).exists()
        assert _record_ids(spool_root, done.new_batch_id) == [live_record_id]
    finally:
        database.close()


def test_the_new_batch_id_is_deterministic_in_the_survivors(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        # The successor id is a deterministic function of the FULL intended identity (survivors +
        # policy + exporters + source), so re-deriving the same inputs yields the same reserved id,
        # and compaction publishes exactly that id.
        expected = compaction_module._derive_batch_id(record, [frames[1]])
        assert expected == compaction_module._derive_batch_id(record, [frames[1]])  # deterministic
        assert is_reserved_compaction_batch_id(expected)
        result = _compact(database, barrier, spool_root)
        assert result.compacted[0].new_batch_id == expected
    finally:
        database.close()


def test_records_old_to_new_lineage_in_the_audit_trail(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _record, _frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        result = _compact(database, barrier, spool_root)
        new_batch_id = result.compacted[0].new_batch_id

        audit = list_audit(database, action="compaction")
        assert [row.outcome for row in audit] == ["compacted_from", "compacted_into"]
        assert all(row.actor == "maintenance" and row.reason == "mixed_expiry" for row in audit)
        # Keyed lineage is mandatory: each row carries the installation-keyed pseudonym of its batch
        # id (never a raw id or a public SHA-256), an ordered from->into pair with reclaim counts.
        assert audit[0].resource == _PSEUDONYMIZER.fingerprint("batch", "batch-a")
        assert audit[1].resource == _PSEUDONYMIZER.fingerprint("batch", new_batch_id)
        assert all(row.resource is not None and row.resource.startswith("mh_fp1_") for row in audit)
        assert b"batch-a" not in _audit_bytes(database)
        assert new_batch_id.encode("utf-8") not in _audit_bytes(database)
        assert audit[0].record_count == 2  # old total
        assert audit[1].record_count == 1  # retained
    finally:
        database.close()


def test_a_cursor_is_repointed_to_the_new_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        advance_cursor(
            database, "github", position="page-7", batch_id="batch-a", now=_NOW, expected_revision=0
        )
        result = _compact(database, barrier, spool_root)
        new_batch_id = result.compacted[0].new_batch_id

        cursor = read_cursor(database, "github")
        assert cursor is not None
        assert cursor.batch_id == new_batch_id  # re-pointed to the segment that holds the live data
        assert (cursor.position, cursor.revision) == ("page-7", 1)  # checkpoint preserved
    finally:
        database.close()


def test_the_new_segment_inherits_the_delivered_status(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}, now=_NOW
        )
        result = _compact(database, barrier, spool_root)
        new_batch_id = result.compacted[0].new_batch_id
        status = database.connection.execute(
            "SELECT delivery_status FROM _segment_exporters WHERE batch_id = ?", (new_batch_id,)
        ).fetchone()[0]
        assert status == "delivered"  # the live records were already delivered; do not re-deliver
    finally:
        database.close()


def test_a_delivered_mixed_segment_is_still_compactable(tmp_path: Path) -> None:
    # Delivery withholds a mixed segment (hard-expiry), but its DELIVERED live records must still be
    # compacted so the expired frames are removed from disk.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        # At _APPLY_NOW the segment is mixed, so delivery withholds it.
        attempts = deliver_segment(
            database,
            barrier,
            record,
            frames,
            {"clickhouse": _FakeExporter("clickhouse")},
            now=_APPLY_NOW,
        )
        assert [a.outcome for a in attempts] == ["expired"]
        result = _compact(database, barrier, spool_root)
        assert result.compacted[0].retained_records == 1
    finally:
        database.close()


# --------------------------------------------------------------------------------------------------
# Crash convergence
# --------------------------------------------------------------------------------------------------


def test_an_interrupted_old_file_unlink_reconverges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _, frames = _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        live_record_id = str(frames[1].record.record_id)

        # Crash AFTER the ledger swap commits but BEFORE the old file is unlinked.
        def failing_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(compaction_module, "remove_regular_file_no_follow", failing_remove)
        first = _compact(database, barrier, spool_root)
        new_batch_id = first.compacted[0].new_batch_id
        assert first.compacted[0].file_outcome == "orphaned"
        assert [c.old_batch_id for c in first.orphaned_files] == ["batch-a"]
        # Row-first: old row gone, old file lingers (with a durable retirement tombstone written in
        # the swap txn), new segment committed. No data lost.
        assert _segment_rows(database) == {new_batch_id}
        assert _segment_file(spool_root, "batch-a").exists()

        # Mandatory reconciliation finds the tombstone + the lingering old file and COMPLETES the
        # retirement (unlink + clear tombstone) rather than re-registering the retired mixed segment
        # as a live committed segment with its expired frame (G03 review #79-P1-3). It converges in
        # ONE reconcile pass — no second compaction is required — and never re-adopts the old bytes.
        monkeypatch.undo()
        _reconcile(database, barrier, spool_root)
        assert _segment_rows(database) == {new_batch_id}
        assert not _segment_file(spool_root, "batch-a").exists()
        assert _record_ids(spool_root, new_batch_id) == [
            live_record_id
        ]  # still exactly the survivor
    finally:
        database.close()


def test_an_interrupted_swap_leaves_a_reregisterable_new_orphan(
    tmp_path: Path,
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        # Break the swap txn (drop the audit table so record_compaction fails and rolls back).
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")

        first = _compact(database, barrier, spool_root)
        assert first.compacted == ()
        assert first.skipped[0].status == "commit_failed"
        # The old segment is fully intact; the new file was published but has no ledger row.
        assert _segment_rows(database) == {"batch-a"}
        assert _segment_file(spool_root, "batch-a").exists()

        # Restore the audit table and re-run: the orphan new file is adopted and the old retired.
        _recreate_audit_table(database)

        second = _compact(database, barrier, spool_root)
        assert len(second.compacted) == 1
        new_batch_id = second.compacted[0].new_batch_id
        assert _segment_rows(database) == {new_batch_id}
        assert not _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_a_foreign_file_at_the_new_name_is_verified_and_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If a valid-but-different segment already occupies the derived new name, compaction must verify
    # and refuse (never retire the old segment against an unverified new file).
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        # First reads (old) agree; the second read (new) disagrees.
        calls = {"n": 0}
        real_agrees = compaction_module._agrees

        def counting_agrees(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_agrees(*args, **kwargs)
            return False

        monkeypatch.setattr(compaction_module, "_agrees", counting_agrees)
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert result.skipped[0].status == "verify_failed"
        assert _segment_rows(database) == {"batch-a"}  # old untouched
    finally:
        database.close()


def test_a_read_failure_on_the_new_file_leaves_the_old_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        calls = {"n": 0}
        real_read = compaction_module.read_trusted_segment

        def failing_second_read(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_read(*args, **kwargs)
            raise SpoolError("MH_SPOOL_VERIFY", "unreadable new segment")

        monkeypatch.setattr(compaction_module, "read_trusted_segment", failing_second_read)
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert result.skipped[0].status == "verify_failed"
        assert _segment_rows(database) == {"batch-a"}
    finally:
        database.close()


def test_a_publish_failure_leaves_the_old_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])

        def failing_publish(*args: object, **kwargs: object) -> None:
            raise SpoolError("MH_SPOOL_WRITE", "cannot publish")

        # Compaction publishes its successor through the unexported reserved-only authority, not the
        # public publish_segment_bytes (G03 review #79-P1-1), so patch that authority.
        monkeypatch.setattr(compaction_module, "_publish_reserved_successor", failing_publish)
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert result.skipped[0].status == "publish_failed"
        assert _segment_rows(database) == {"batch-a"}
    finally:
        database.close()


def test_a_build_failure_leaves_the_old_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])

        def failing_build(*args: object, **kwargs: object):
            raise SpoolError("MH_SPOOL_SIZE", "too big")

        monkeypatch.setattr(compaction_module, "build_segment_bytes", failing_build)
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert result.skipped[0].status == "verify_failed"
        assert _segment_rows(database) == {"batch-a"}
    finally:
        database.close()


def test_a_post_unlink_uncertainty_is_reported_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])

        def uncertain_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN)

        monkeypatch.setattr(compaction_module, "remove_regular_file_no_follow", uncertain_remove)
        result = _compact(database, barrier, spool_root)
        assert result.compacted[0].file_outcome == "uncertain"
        assert [c.old_batch_id for c in result.uncertain_files] == ["batch-a"]
        assert result.orphaned_files == ()
    finally:
        database.close()


def test_multiple_segments_compact_independently(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-mixed", [("e1", _EXPIRED_AT), ("l1", _LIVE_AT)])
        _commit(store, "batch-live", [("l2", _LIVE_AT)])
        _commit(store, "batch-expired", [("e2", _EXPIRED_AT)])
        result = _compact(database, barrier, spool_root)
        assert [c.old_batch_id for c in result.compacted] == ["batch-mixed"]
        assert {s.status for s in result.skipped} == {"live", "fully_expired"}
        rows = _segment_rows(database)
        assert "batch-live" in rows and "batch-expired" in rows and "batch-mixed" not in rows
    finally:
        database.close()


# --------------------------------------------------------------------------------------------------
# PR #69 review remediations
# --------------------------------------------------------------------------------------------------


def _recreate_audit_table(database) -> None:
    # Replay every DDL statement that builds the CURRENT _audit schema — the create plus later
    # column-adding migrations — so a recreated table matches production (record_compaction now
    # writes the migration-9 content/file digest columns).
    from milhouse.state.schema import CONTROL_MIGRATIONS

    ddl = [
        stmt
        for migration in CONTROL_MIGRATIONS
        if migration.name in ("create_audit", "add_audit_content_digests")
        for stmt in migration.statements
    ]
    with database.transaction() as connection:
        for stmt in ddl:
            connection.execute(stmt)


def _exporter_states(database, batch_id: str) -> dict[str, str]:
    return dict(
        database.connection.execute(
            "SELECT exporter_id, delivery_status FROM _segment_exporters WHERE batch_id = ?",
            (batch_id,),
        ).fetchall()
    )


def test_a_producer_cannot_commit_into_the_reserved_successor_namespace(tmp_path: Path) -> None:
    # P1 (review finding #1/#2): a compaction successor id (``c`` + 64-hex) is a valid batch-id
    # shape, so a producer COULD otherwise commit a segment at a derived successor id and strand a
    # mixed-expiry segment's expired frames past their privacy deadline. The commit ingress reserves
    # the namespace: a producer commit into it fails closed and publishes nothing.
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        reserved = "c" + "a" * 64
        assert is_reserved_compaction_batch_id(reserved)  # a valid reserved successor shape

        with pytest.raises(SpoolError) as excinfo:
            _commit(store, reserved, [("live-1", _LIVE_AT)])
        assert excinfo.value.code == "MH_SPOOL_RESERVED_ID"
        assert _segment_rows(database) == set()  # nothing committed
        assert not _segment_file(spool_root, reserved).exists()  # nothing published
    finally:
        database.close()


def test_the_writer_rejects_a_reserved_named_segment_file(tmp_path: Path) -> None:
    # P1 (review finding #2): the reservation must hold at EVERY producer publish ingress, not just
    # commit_segment. Publishing a reserved-named file via write_spool_segment or a default
    # publish_segment_bytes is rejected, so no producer can create a reserved-named file that
    # reconciliation would later adopt as a foreign successor and strand a real compaction.
    from milhouse.spooling.writer import publish_segment_bytes, write_spool_segment

    reserved = "c" + "b" * 64
    frames = _frames(reserved, [("live-1", _LIVE_AT)])
    header = _header(reserved, frames)
    path = tmp_path / f"{reserved}.jsonl"

    with pytest.raises(SpoolError) as e1:
        publish_segment_bytes(path, b"x")
    assert e1.value.code == "MH_SPOOL_RESERVED_ID"
    with pytest.raises(SpoolError) as e2:
        write_spool_segment(path, header, frames)
    assert e2.value.code == "MH_SPOOL_RESERVED_ID"
    assert not path.exists()  # nothing published either way


def test_the_public_publish_surface_has_no_reserved_bypass(tmp_path: Path) -> None:
    # A07 / review #79-P1-1 (exact reproduction is now unreachable): the public publish surface has
    # NO caller-selectable reserved bypass (the old allow_reserved=True escape hatch), so a direct
    # publisher can never occupy the predictable successor slot and strand a real compaction. Only
    # compaction's UNEXPORTED authority publishes into the reserved namespace, and it refuses any
    # non-reserved name.
    import inspect

    from milhouse.spooling import writer as writer_module

    assert "allow_reserved" not in inspect.signature(writer_module.publish_segment_bytes).parameters
    reserved_path = tmp_path / f"{'c' + 'd' * 64}.jsonl"
    with pytest.raises(SpoolError) as public:
        writer_module.publish_segment_bytes(reserved_path, b"x")
    assert public.value.code == "MH_SPOOL_RESERVED_ID"
    assert not reserved_path.exists()
    # The unexported authority is reserved-only: an ordinary producer name is refused.
    ordinary_path = tmp_path / "ordinary.jsonl"
    with pytest.raises(SpoolError) as authority:
        writer_module._publish_reserved_successor(ordinary_path, b"x")
    assert authority.value.code == "MH_SPOOL_RESERVED_ID"
    assert not ordinary_path.exists()


def _seed_reserved_occupant(
    database, store, spool_root: Path, reserved: str, specs, *, garbage=False
):
    """Seed a legacy committed reserved-namespace segment (matching row + file).

    A ``c[0-9a-f]{64}`` id is a valid producer batch-id shape, so before the reservation a producer
    could have committed a segment at one. The commit ingress now rejects it, so this builds the
    segment bytes at the reserved id, publishes them via the compaction authority (garbage bytes
    when requested, to model an unreadable occupant), and inserts a committed-origin row — the exact
    pre-reservation upgrade state A07's remediation must auto-converge. Returns the seed's frames.
    """

    base, base_frames = _commit(store, "batch-seed", specs)
    legacy_record, content = compaction_module._build_new_segment(base, list(base_frames), reserved)
    legacy_record = replace(legacy_record, origin=ORIGIN_COMMITTED)
    with database.transaction() as connection:
        connection.execute("DELETE FROM _segment_exporters WHERE batch_id = ?", ("batch-seed",))
        connection.execute("DELETE FROM _segments WHERE batch_id = ?", ("batch-seed",))
        insert_segment_row(connection, legacy_record)
    compaction_module._publish_reserved_successor(
        _segment_file(spool_root, reserved), b"not a valid segment file" if garbage else content
    )
    _segment_file(spool_root, "batch-seed").unlink()
    return base_frames


def test_a_legacy_reserved_namespace_committed_segment_is_auto_converged(tmp_path: Path) -> None:
    # A07 / review #79-P1-4: a committed segment in the reserved c[0-9a-f]{64} namespace with
    # origin='committed' is a legacy producer occupant that predates the reservation (compaction
    # successors are always origin='reconciled'). Compaction AUTO-CONVERGES it — rewriting it to a
    # fresh NON-reserved id, preserving every record — rather than wedging acquisition (the earlier
    # fail-closed guard blocked a legal upgraded install's writers, retention, and recovery).
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        reserved = "c" + "e" * 64
        base_frames = _seed_reserved_occupant(
            database, store, spool_root, reserved, [("r1", _LIVE_AT), ("r2", _LIVE_AT)]
        )

        # Acquisition is NOT wedged: a fresh acquisition reconciles with the occupant present.
        _reconcile(database, barrier, spool_root)
        assert reserved in _segment_rows(database)

        # Compaction auto-converges: the occupant is rehomed to a non-reserved id, records kept.
        result = _compact(database, barrier, spool_root)
        assert [r.old_batch_id for r in result.rehomed] == [reserved]
        new_id = result.rehomed[0].new_batch_id
        assert not is_reserved_compaction_batch_id(new_id)  # out of the reserved namespace
        assert result.rehomed[0].dropped_records == 0  # every record preserved
        assert _segment_rows(database) == {new_id}
        assert not _segment_file(spool_root, reserved).exists()  # old file retired
        assert set(_record_ids(spool_root, new_id)) == {
            str(frame.record.record_id) for frame in base_frames
        }
    finally:
        database.close()


def test_a_rehome_of_an_unreadable_occupant_is_skipped(tmp_path: Path) -> None:
    # A07 / review #79-P1-4: if a legacy reserved-namespace occupant's file cannot be read, the
    # rehome fails closed for THIS pass (reported, never wedging) and leaves the occupant fully
    # intact for a later pass — a live record is never lost.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        reserved = "c" + "a" * 64
        _seed_reserved_occupant(
            database, store, spool_root, reserved, [("r1", _LIVE_AT)], garbage=True
        )
        result = _compact(database, barrier, spool_root)
        assert result.rehomed == ()  # the unreadable occupant was not rehomed
        assert any(skip.status == "unreadable" for skip in result.skipped)
        assert reserved in _segment_rows(database)  # left fully intact
        assert _segment_file(spool_root, reserved).exists()
    finally:
        database.close()


def test_a_rehome_of_a_disagreeing_occupant_is_skipped(tmp_path: Path) -> None:
    # A07 / review #79-P1-4: if a legacy occupant's file no longer agrees with its ledger row, the
    # rehome fails closed for this pass rather than retiring it against a mismatched file.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        reserved = "c" + "b" * 64
        _seed_reserved_occupant(database, store, spool_root, reserved, [("r1", _LIVE_AT)])
        # Mangle the ledger row so it disagrees with the (valid) file.
        with database.transaction() as connection:
            connection.execute(
                "UPDATE _segments SET record_count = record_count + 1 WHERE batch_id = ?",
                (reserved,),
            )
        result = _compact(database, barrier, spool_root)
        assert result.rehomed == ()  # the disagreeing occupant was not rehomed
        assert any(skip.status == "disagreeing" for skip in result.skipped)
        assert reserved in _segment_rows(database)  # left intact
    finally:
        database.close()


def test_a_rehome_converges_when_a_producer_occupies_the_first_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A07 / review #79-P1-1: collision-resistant allocation has no finite probe terminal. Force its
    # first sampled target to an ordinary producer segment, then prove it retries a second sample.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        reserved = "c" + "e" * 64
        base_frames = _seed_reserved_occupant(
            database, store, spool_root, reserved, [("r1", _LIVE_AT), ("r2", _LIVE_AT)]
        )
        first_target = "r" + format(0, "064x")  # force the first random sample to this id below
        _commit(store, first_target, [("producer-1", _LIVE_AT)])  # a legal ordinary producer seg
        targets = iter(["0" * 64, "1" * 64])
        monkeypatch.setattr(compaction_module, "_random_rehome_suffix", lambda: next(targets))

        result = _compact(database, barrier, spool_root)
        assert [r.old_batch_id for r in result.rehomed] == [reserved]  # still converged
        new_id = result.rehomed[0].new_batch_id
        assert new_id != first_target  # skipped the occupied target
        assert not is_reserved_compaction_batch_id(new_id)
        assert first_target in _segment_rows(database)  # the producer segment is untouched
        assert reserved not in _segment_rows(database)  # the legacy occupant is gone
        assert set(_record_ids(spool_root, new_id)) == {
            str(frame.record.record_id) for frame in base_frames
        }
    finally:
        database.close()


def test_a_foreign_segment_at_a_recorded_rehome_target_is_reallocated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash-bound ordinary target cannot become a permanent producer-controlled wedge."""

    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        reserved = "c" + "f" * 64
        base_frames = _seed_reserved_occupant(
            database, store, spool_root, reserved, [("r1", _LIVE_AT), ("r2", _LIVE_AT)]
        )
        targets = iter(["a" * 64, "b" * 64])
        monkeypatch.setattr(compaction_module, "_random_rehome_suffix", lambda: next(targets))
        real_publish = compaction_module.publish_segment_bytes

        def fail_publish(_path: Path, _content: bytes) -> None:
            raise SpoolError("MH_SPOOL_WRITE", "injected pre-publish failure")

        monkeypatch.setattr(compaction_module, "publish_segment_bytes", fail_publish)
        first = _compact(database, barrier, spool_root)
        assert any(item.status == "publish_failed" for item in first.skipped)
        assert read_rehome_target(database.connection, reserved) == "r" + "a" * 64

        # During the interruption, a supported producer legally occupies the recorded ordinary id.
        monkeypatch.setattr(compaction_module, "publish_segment_bytes", real_publish)
        _commit(store, "r" + "a" * 64, [("producer-1", _LIVE_AT)])
        second = _compact(database, barrier, spool_root)

        assert [item.new_batch_id for item in second.rehomed] == ["r" + "b" * 64]
        assert "r" + "a" * 64 in _segment_rows(database)  # producer segment untouched
        assert reserved not in _segment_rows(database)
        assert set(_record_ids(spool_root, "r" + "b" * 64)) == {
            str(frame.record.record_id) for frame in base_frames
        }
    finally:
        database.close()


def test_a_pre_upgrade_reserved_orphan_is_rehomed_not_kept_as_a_successor(tmp_path: Path) -> None:
    # A07 / review #79-P1-2 (exact reproduction, DEFEATED): a pre-upgrade producer crash can leave
    # a valid reserved-namespace FILE with no ledger row; mandatory reconciliation registers it
    # origin='reconciled'. Origin cannot prove it a genuine compaction successor — only a durable
    # successor intent can, and a legacy orphan has none — so the rehome rewrites it out of the
    # reserved namespace rather than mistaking it for a successor and stranding.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        base, base_frames = _commit(store, "batch-seed", [("r1", _LIVE_AT), ("r2", _LIVE_AT)])
        reserved = "c" + "d" * 64
        _record, content = compaction_module._build_new_segment(base, list(base_frames), reserved)
        # A pre-upgrade orphan: the reserved FILE exists with NO ledger row and NO successor intent.
        with database.transaction() as connection:
            connection.execute("DELETE FROM _segment_exporters WHERE batch_id = ?", ("batch-seed",))
            connection.execute("DELETE FROM _segments WHERE batch_id = ?", ("batch-seed",))
        compaction_module._publish_reserved_successor(_segment_file(spool_root, reserved), content)
        _segment_file(spool_root, "batch-seed").unlink()

        # Mandatory reconciliation registers the orphan as a committed segment (origin=reconciled).
        _reconcile(database, barrier, spool_root)
        assert reserved in _segment_rows(database)

        # Compaction rehomes it (no successor intent proves it genuine); nothing is stranded.
        result = _compact(database, barrier, spool_root)
        assert [r.old_batch_id for r in result.rehomed] == [reserved]
        new_id = result.rehomed[0].new_batch_id
        assert not is_reserved_compaction_batch_id(new_id)
        assert _segment_rows(database) == {new_id}
        assert set(_record_ids(spool_root, new_id)) == {
            str(frame.record.record_id) for frame in base_frames
        }
    finally:
        database.close()


def test_schema11_crash_published_successor_is_adopted_without_duplicate_history(
    tmp_path: Path,
) -> None:
    """Migration 12 must reconstruct a genuine old-source -> successor pair before rehome."""

    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        old_record, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        deliver_segment(
            database,
            barrier,
            old_record,
            frames,
            {"clickhouse": _FakeExporter("clickhouse")},
            now=_NOW,
        )
        advance_cursor(
            database,
            "github",
            position="page-7",
            batch_id="batch-a",
            now=_NOW,
            expected_revision=0,
        )
        current = read_segment_record(database, "batch-a")
        assert current is not None
        successor = compaction_module._derive_batch_id(current, [frames[1]])
        _successor_record, content = compaction_module._build_new_segment(
            current, [frames[1]], successor
        )

        # Return the control plane to the exact pre-migration-12 schema prefix, then model the
        # supported crash after the old compactor published its real successor but before its swap.
        with database.transaction() as connection:
            connection.execute("DROP TABLE _sequences")
            connection.execute("DROP TABLE _compaction_intents")
            connection.execute("DELETE FROM _schema_migrations WHERE version = 12")
        compaction_module._publish_reserved_successor(_segment_file(spool_root, successor), content)
        initialize_control_state(database, barrier=barrier, applied_at=_APPLY_NOW)
        _reconcile(database, barrier, spool_root)
        assert _segment_rows(database) == {"batch-a", successor}
        assert (
            database.connection.execute("SELECT count(*) FROM _compaction_intents").fetchone()[0]
            == 0
        )

        result = _compact(database, barrier, spool_root)

        # The migration recovery collapses the pair; it never rehomes the real successor and then
        # recreates it, which would leave the live record in two authoritative segments.
        assert result.rehomed == ()
        assert _segment_rows(database) == {successor}
        assert _record_ids(spool_root, successor) == [str(frames[1].record.record_id)]
        cursor = read_cursor(database, "github")
        assert cursor is not None
        assert (cursor.batch_id, cursor.position, cursor.revision) == (successor, "page-7", 1)
        delivery = database.connection.execute(
            "SELECT delivery_status FROM _segment_exporters WHERE batch_id = ?", (successor,)
        ).fetchone()
        assert delivery == ("delivered",)
    finally:
        database.close()


def test_schema11_successive_crash_successors_collapse_to_one_authoritative_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Discover the complete pre-intent set, then retain one most-current successor."""

    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        old_record, frames = _commit(
            store,
            "batch-a",
            [
                ("expired-first", _EXPIRED_AT),
                ("expired-second", _NOW + timedelta(hours=12)),
                ("live", _LIVE_AT),
            ],
        )
        deliver_segment(
            database,
            barrier,
            old_record,
            frames,
            {"clickhouse": _FakeExporter("clickhouse")},
            now=_NOW,
        )
        advance_cursor(
            database,
            "github",
            position="page-8",
            batch_id="batch-a",
            now=_NOW,
            expected_revision=0,
        )
        source = read_segment_record(database, "batch-a")
        assert source is not None
        earlier = compaction_module._derive_batch_id(source, list(frames[1:]))
        latest = compaction_module._derive_batch_id(source, [frames[2]])
        _earlier_record, earlier_content = compaction_module._build_new_segment(
            source, list(frames[1:]), earlier
        )
        _latest_record, latest_content = compaction_module._build_new_segment(
            source, [frames[2]], latest
        )

        # Schema 11 can legally contain both names: one pass published [B,C] and crashed; after B
        # expired, a later pass against the still-authoritative source published [C] and crashed.
        with database.transaction() as connection:
            connection.execute("DROP TABLE _sequences")
            connection.execute("DROP TABLE _compaction_intents")
            connection.execute("DELETE FROM _schema_migrations WHERE version = 12")
        compaction_module._publish_reserved_successor(
            _segment_file(spool_root, earlier), earlier_content
        )
        compaction_module._publish_reserved_successor(
            _segment_file(spool_root, latest), latest_content
        )
        initialize_control_state(database, barrier=barrier, applied_at=_APPLY_NOW)
        _reconcile(database, barrier, spool_root)
        assert _segment_rows(database) == {"batch-a", earlier, latest}

        real_swap = compaction_module._swap_ledger
        monkeypatch.setattr(compaction_module, "_swap_ledger", lambda *_args, **_kwargs: False)
        interrupted = _compact(database, barrier, spool_root)
        assert any(item.status == "commit_failed" for item in interrupted.skipped)
        assert _segment_rows(database) == {"batch-a", earlier, latest}
        assert database.connection.execute("SELECT count(*) FROM _retirements").fetchone() == (0,)
        assert is_recorded_successor(database.connection, latest)

        monkeypatch.setattr(compaction_module, "_swap_ledger", real_swap)
        monkeypatch.setattr(compaction_module, "_remove_old_file", lambda _path: "orphaned")
        result = _compact(database, barrier, spool_root)

        assert result.rehomed == ()
        assert {item.old_batch_id for item in result.compacted} == {"batch-a", earlier}
        assert {item.new_batch_id for item in result.compacted} == {latest}
        assert {item.file_outcome for item in result.compacted} == {"orphaned"}
        assert _segment_rows(database) == {latest}
        assert _record_ids(spool_root, latest) == [str(frames[2].record.record_id)]
        assert (
            sum(len(_record_ids(spool_root, batch_id)) for batch_id in _segment_rows(database)) == 1
        )
        cursor = read_cursor(database, "github")
        assert cursor is not None
        assert (cursor.batch_id, cursor.position, cursor.revision) == (latest, "page-8", 1)
        delivery = database.connection.execute(
            "SELECT delivery_status FROM _segment_exporters WHERE batch_id = ?", (latest,)
        ).fetchone()
        assert delivery == ("delivered",)
        intents = database.connection.execute(
            "SELECT target_batch_id, source_batch_id, kind FROM _compaction_intents"
        ).fetchall()
        assert intents == [(latest, "batch-a", "successor")]
        assert database.connection.execute("SELECT count(*) FROM _retirements").fetchone() == (2,)
    finally:
        database.close()


def test_historical_successor_subset_rejects_foreign_or_live_omissions() -> None:
    source = tuple(_frames("source", [("a", _EXPIRED_AT), ("b", _LIVE_AT)]))
    foreign = tuple(_frames("target", [("foreign", _LIVE_AT)]))
    assert compaction_module._historical_successor_subset(source, foreign, _APPLY_NOW) is None

    all_live = tuple(_frames("source", [("a", _LIVE_AT), ("b", _LIVE_AT)]))
    retained = tuple(_frames("target", [("b", _LIVE_AT)]))
    assert compaction_module._historical_successor_subset(all_live, retained, _APPLY_NOW) is None


def test_fully_expired_pre_intent_successor_set_stays_protected_for_retention(
    tmp_path: Path,
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        source, frames = _commit(
            store,
            "batch-a",
            [("expired-first", _EXPIRED_AT), ("expired-second", _NOW + timedelta(hours=12))],
        )
        target = compaction_module._derive_batch_id(source, [frames[1]])
        _target_record, content = compaction_module._build_new_segment(source, [frames[1]], target)
        compaction_module._publish_reserved_successor(_segment_file(spool_root, target), content)
        _reconcile(database, barrier, spool_root)

        result = _compact(database, barrier, spool_root)

        assert any(
            item.batch_id == "batch-a" and item.status == "reserved_conflict"
            for item in result.skipped
        )
        assert _segment_rows(database) == {"batch-a", target}
    finally:
        database.close()


def test_pre_intent_successor_recovery_restarts_after_intent_before_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        source, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        target = compaction_module._derive_batch_id(source, [frames[1]])
        _target_record, content = compaction_module._build_new_segment(source, [frames[1]], target)
        compaction_module._publish_reserved_successor(_segment_file(spool_root, target), content)
        _reconcile(database, barrier, spool_root)

        real_swap = compaction_module._swap_ledger
        monkeypatch.setattr(compaction_module, "_swap_ledger", lambda *_args, **_kwargs: False)
        first = _compact(database, barrier, spool_root)
        assert any(item.status == "commit_failed" for item in first.skipped)
        assert _segment_rows(database) == {"batch-a", target}
        assert is_recorded_successor(database.connection, target)

        monkeypatch.setattr(compaction_module, "_swap_ledger", real_swap)
        second = _compact(database, barrier, spool_root)
        assert any(item.new_batch_id == target for item in second.compacted)
        assert second.rehomed == ()
        assert _segment_rows(database) == {target}
        assert _record_ids(spool_root, target) == [str(frames[1].record.record_id)]
    finally:
        database.close()


def test_rehome_random_allocation_retries_any_finite_producer_occupation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The allocator has no caller-exhaustible probe bound or SQLite sequence ceiling."""

    assert "_MAX_REHOME_PROBE" not in vars(compaction_module)
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        reserved = "c" + "e" * 64
        base_frames = _seed_reserved_occupant(
            database, store, spool_root, reserved, [("r1", _LIVE_AT), ("r2", _LIVE_AT)]
        )
        occupied_tokens = ["1" * 64, "2" * 64, "3" * 64]
        for token in occupied_tokens:
            _commit(store, "r" + token, [(f"producer-{token[0]}", _LIVE_AT)])
        tokens = iter([*occupied_tokens, "4" * 64])
        monkeypatch.setattr(compaction_module, "_random_rehome_suffix", lambda: next(tokens))

        result = _compact(database, barrier, spool_root)

        assert [item.new_batch_id for item in result.rehomed] == ["r" + "4" * 64], [
            (item.batch_id, item.status, item.code) for item in result.skipped
        ]
        assert all("r" + token in _segment_rows(database) for token in occupied_tokens)
        assert reserved not in _segment_rows(database)
        assert set(_record_ids(spool_root, "r" + "4" * 64)) == {
            str(frame.record.record_id) for frame in base_frames
        }
    finally:
        database.close()


def test_a_rehome_reuses_its_recorded_target_after_an_interrupted_swap(tmp_path: Path) -> None:
    # A07 / review #79-P1-1 restart: the rehome binds the source to its target via a durable rehome
    # intent BEFORE publishing, so a swap interrupted after the target is published
    # REUSES the same target on the next pass (adopts the orphan) and converges — never allocating a
    # second target or losing a record.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        reserved = "c" + "f" * 64
        base_frames = _seed_reserved_occupant(
            database, store, spool_root, reserved, [("r1", _LIVE_AT)]
        )
        # Interrupt the rehome swap (drop _audit so record_compaction fails and the swap rolls back)
        # AFTER the intent is committed and the target file is published.
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")
        first = _compact(database, barrier, spool_root)
        assert first.rehomed == ()
        assert any(skip.status == "commit_failed" for skip in first.skipped)
        assert reserved in _segment_rows(database)  # occupant not yet retired

        _recreate_audit_table(database)
        second = _compact(database, barrier, spool_root)
        assert [r.old_batch_id for r in second.rehomed] == [reserved]
        new_id = second.rehomed[0].new_batch_id
        assert _segment_rows(database) == {new_id}
        assert set(_record_ids(spool_root, new_id)) == {
            str(frame.record.record_id) for frame in base_frames
        }
    finally:
        database.close()


def test_a_successor_intent_failure_leaves_the_old_segment_intact(tmp_path: Path) -> None:
    # A07 / review #79-P1-2: the successor provenance intent is recorded BEFORE the successor is
    # published; if it cannot be recorded, compaction fails closed before publishing or mutating, so
    # no reserved successor is ever created without its authoritative provenance.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        with database.transaction() as connection:
            connection.execute("DROP TABLE _compaction_intents")
        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert result.skipped[0].status == "commit_failed"
        assert _segment_rows(database) == {"batch-a"}  # nothing published or mutated
    finally:
        database.close()


def test_a_genuine_successor_is_not_rehomed_on_a_later_pass(tmp_path: Path) -> None:
    # A successor's provenance intent PERSISTS while the successor exists (cleared only when the
    # successor is itself retired), so a subsequent compaction pass never mistakes the genuine
    # reserved successor for a legacy occupant and rehomes it out of the reserved namespace.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        first = _compact(database, barrier, spool_root)
        successor = first.compacted[0].new_batch_id
        assert is_reserved_compaction_batch_id(successor)

        second = _compact(database, barrier, spool_root)
        assert second.rehomed == ()  # the genuine successor is NOT rehomed
        assert second.compacted == ()  # and it is fully live, so not re-compacted
        assert _segment_rows(database) == {successor}  # it stays in the reserved namespace
    finally:
        database.close()


def test_two_mixed_segments_sharing_a_survivor_but_differing_in_exporters_both_compact(
    tmp_path: Path,
) -> None:
    # P1 (review finding #2): _derive_batch_id must key on the FULL intended identity, not just the
    # surviving record ids. Two valid mixed segments with the SAME live record id but DIFFERENT
    # exporters must derive DIFFERENT successors and BOTH compact — never collide so the second
    # returns reserved_conflict and strands its expired frame (reproduced; no SHA-256 collision).
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _a, frames_a = _commit(
            store,
            "batch-a",
            [("exp-a", _EXPIRED_AT), ("shared", _LIVE_AT)],
            exporters=("clickhouse",),
        )
        _b, frames_b = _commit(
            store, "batch-b", [("exp-b", _EXPIRED_AT), ("shared", _LIVE_AT)], exporters=("s3",)
        )
        # Precondition: the two live survivors are the SAME finalized record (same record id).
        assert frames_a[1].record.record_id == frames_b[1].record.record_id

        result = _compact(database, barrier, spool_root)

        assert {c.old_batch_id for c in result.compacted} == {
            "batch-a",
            "batch-b",
        }  # both compacted
        assert all(c.dropped_records == 1 for c in result.compacted)  # each expired frame removed
        assert result.skipped == ()  # nothing stranded / reserved_conflict
        assert len({c.new_batch_id for c in result.compacted}) == 2  # distinct successors
        assert "batch-a" not in _segment_rows(database) and "batch-b" not in _segment_rows(database)
    finally:
        database.close()


def test_the_compaction_successor_id_lands_in_the_reserved_namespace(tmp_path: Path) -> None:
    # The successor a real compaction writes must land in the reserved namespace, so the commit
    # ingress actually protects the id compaction derives (no producer can pre-occupy it).
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        result = _compact(database, barrier, spool_root)
        assert is_reserved_compaction_batch_id(result.compacted[0].new_batch_id)
    finally:
        database.close()


def test_compaction_records_keyed_lineage_from_the_loaded_installation_key(tmp_path: Path) -> None:
    # P1 (review findings #2/#3, per A07): compaction LOADS the installation key from the config/
    # paths boundary and records keyed old->new lineage — BOTH audit rows carry keyed mh_fp1_...
    # tokens (matching the provisioned key), never a raw id or a public SHA-256, so the lineage is
    # attributable and wired into W03 with a non-forgeable key.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _record, _frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        result = _compact(database, barrier, spool_root)
        new_id = result.compacted[0].new_batch_id

        rows = list_audit(database, action="compaction")
        assert [row.outcome for row in rows] == ["compacted_from", "compacted_into"]
        assert rows[0].resource == _PSEUDONYMIZER.fingerprint("batch", "batch-a")
        assert rows[1].resource == _PSEUDONYMIZER.fingerprint("batch", new_id)
        assert all(r.resource is not None and r.resource.startswith("mh_fp1_") for r in rows)
        # Neither the raw ids nor their public SHA-256 appear anywhere in the audit table.
        blob = _audit_bytes(database)
        assert b"batch-a" not in blob and new_id.encode("utf-8") not in blob
        assert hashlib.sha256(b"batch-a").hexdigest().encode("utf-8") not in blob
        assert hashlib.sha256(new_id.encode("utf-8")).hexdigest().encode("utf-8") not in blob
    finally:
        database.close()


def test_compaction_records_the_old_and_new_segment_digests_in_the_audit(tmp_path: Path) -> None:
    # P1 (review finding #4): plan §§4.8-4.9 require compaction to record the OLD/NEW content and
    # file HASHES transactionally as immutable evidence of the retired and replacement bytes — a
    # keyed batch-id pseudonym (lineage) is not that evidence. The compacted_from row has the old
    # segment's digests and the compacted_into row the new segment's, matching the ledger rows.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, _frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        result = _compact(database, barrier, spool_root)
        new_id = result.compacted[0].new_batch_id
        new_content, new_file = database.connection.execute(
            "SELECT content_sha256, file_sha256 FROM _segments WHERE batch_id = ?", (new_id,)
        ).fetchone()

        rows = list_audit(database, action="compaction")
        assert (rows[0].content_sha256, rows[0].file_sha256) == (
            record.content_sha256,
            record.file_sha256,
        )
        assert (rows[1].content_sha256, rows[1].file_sha256) == (new_content, new_file)
        assert all(
            r.content_sha256 is not None
            and r.file_sha256 is not None
            and len(r.content_sha256) == 64
            and len(r.file_sha256) == 64
            for r in rows
        )
    finally:
        database.close()


def test_compaction_fails_closed_when_the_reserved_id_holds_a_foreign_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The reserved namespace makes a foreign committed row at the derived id reachable ONLY by a
    # SHA-256 collision. Simulate that (derive collides with an unrelated committed segment):
    # compaction must fail closed with ``reserved_conflict`` and leave the mixed segment fully
    # intact — never retire it against foreign data — rather than strand silently.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        _commit(store, "batch-foreign", [("foreign-live", _LIVE_AT)])
        monkeypatch.setattr(
            compaction_module, "_derive_batch_id", lambda record, live_frames: "batch-foreign"
        )

        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert ("batch-a", "reserved_conflict") in [(s.batch_id, s.status) for s in result.skipped]
        rows = _segment_rows(database)
        assert "batch-a" in rows and "batch-foreign" in rows  # both untouched, retryable
        assert _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_compaction_fails_closed_when_the_reserved_id_holds_an_unreadable_file(
    tmp_path: Path,
) -> None:
    # A file at the derived id with NO ledger row that does not parse (reachable only by a collision
    # artifact): compaction fails closed with ``reserved_conflict``, never retiring the old segment.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _record, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        derived = compaction_module._derive_batch_id(_record, [frames[1]])
        derived_path = _segment_file(spool_root, derived)
        derived_path.write_bytes(b"{ not a valid segment\n")
        os.chmod(derived_path, 0o600)

        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert ("batch-a", "reserved_conflict") in [(s.batch_id, s.status) for s in result.skipped]
        assert "batch-a" in _segment_rows(database)  # old intact
    finally:
        database.close()


def test_compaction_fails_closed_when_the_reserved_id_holds_a_foreign_file(tmp_path: Path) -> None:
    # A VALID but non-successor segment file at the derived id with no ledger row (again reachable
    # only by a collision): it verifies as disagreeing and compaction fails closed, keeping the old.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _record, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        derived = compaction_module._derive_batch_id(_record, [frames[1]])
        # Build a valid segment file at the derived name whose content differs from the successor.
        foreign_frames = _frames(derived, [("foreign-live", _LIVE_AT)])
        foreign_bytes = compaction_module.build_segment_bytes(
            _header(derived, foreign_frames), foreign_frames
        )
        derived_path = _segment_file(spool_root, derived)
        derived_path.write_bytes(foreign_bytes)
        os.chmod(derived_path, 0o600)

        result = _compact(database, barrier, spool_root)
        assert result.compacted == ()
        assert ("batch-a", "reserved_conflict") in [(s.batch_id, s.status) for s in result.skipped]
        assert "batch-a" in _segment_rows(database)  # old intact
    finally:
        database.close()


def test_a_compacted_segment_uses_reconciled_provenance_for_its_reconstructed_instant(
    tmp_path: Path,
) -> None:
    # P2 (review): the compacted segment's exact commit instant is unknown and must stay within the
    # records' own day, so it uses a reconstructed day-start committed_at and origin="reconciled"
    # (the ledger's marker for a reconstructed instant) even though compaction runs on a later day.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)])
        assert _APPLY_NOW.date().isoformat() != _DAY  # compaction runs on a later UTC day
        result = _compact(database, barrier, spool_root)  # default now = _APPLY_NOW
        new_batch_id = result.compacted[0].new_batch_id
        committed_at, origin, day = database.connection.execute(
            "SELECT committed_at, origin, day FROM _segments WHERE batch_id = ?", (new_batch_id,)
        ).fetchone()
        assert committed_at == f"{_DAY}T00:00:00.000Z"  # reconstructed day-start, within the day
        assert origin == "reconciled"  # truthful marker for a reconstructed instant
        assert day == _DAY
    finally:
        database.close()


def test_a_crash_after_publish_restores_mixed_exporter_states(tmp_path: Path) -> None:
    # P1 (review): a crash after successor publication and before the swap leaves an orphan that
    # reconciliation re-registers with every exporter pending. The retry must restore the old
    # segment's terminal/retryable states, never leave a delivered record regressed to pending.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(
            store,
            "batch-a",
            [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)],
            exporters=("alpha", "beta", "gamma"),
        )
        with database.transaction() as connection:
            connection.execute(
                "UPDATE _segment_exporters SET delivery_status = 'delivered' "
                "WHERE batch_id = 'batch-a' AND exporter_id = 'alpha'"
            )
            connection.execute(
                "UPDATE _segment_exporters SET delivery_status = 'failed' "
                "WHERE batch_id = 'batch-a' AND exporter_id = 'gamma'"
            )  # beta stays pending — a genuinely mixed exporter state

        # Crash after publication, before the swap commits (drop _audit so record_compaction fails).
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")
        first = _compact(database, barrier, spool_root)
        assert first.compacted == ()  # swap rolled back; the successor is an unrecorded orphan
        assert _segment_rows(database) == {"batch-a"}  # old fully intact

        # Real reconciliation re-registers the orphan successor (with every exporter pending).
        _recreate_audit_table(database)
        _reconcile(database, barrier, spool_root)

        # The retry adopts the successor and restores the old segment's exporter states exactly.
        second = _compact(database, barrier, spool_root)
        new_batch_id = second.compacted[0].new_batch_id
        assert _exporter_states(database, new_batch_id) == {
            "alpha": "delivered",
            "beta": "pending",
            "gamma": "failed",
        }
    finally:
        database.close()


def test_a_delivered_successor_is_never_regressed_by_a_reregistered_old(tmp_path: Path) -> None:
    # P1 (review), the other direction: after a successful swap whose old-file unlink was
    # interrupted, mandatory reconciliation must retire the stale OLD file (via its tombstone),
    # than re-registering it as live — and the already-delivered successor must never be touched
    # (G03 review #79-P1-3).
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(
            store, "batch-a", [("expired-1", _EXPIRED_AT), ("live-1", _LIVE_AT)]
        )
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}, now=_NOW
        )

        import milhouse.spooling.compaction as module

        original_remove = module.remove_regular_file_no_follow

        def failing_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        module.remove_regular_file_no_follow = failing_remove  # type: ignore[assignment]
        try:
            first = _compact(database, barrier, spool_root)
        finally:
            module.remove_regular_file_no_follow = original_remove  # type: ignore[assignment]
        new_batch_id = first.compacted[0].new_batch_id
        assert first.compacted[0].file_outcome == "orphaned"
        assert _exporter_states(database, new_batch_id) == {"clickhouse": "delivered"}
        assert _segment_file(spool_root, "batch-a").exists()

        # Mandatory reconciliation completes the old segment's retirement (its tombstone), never
        # re-registering it, and never touches the delivered successor.
        _reconcile(database, barrier, spool_root)
        assert _segment_rows(database) == {new_batch_id}
        assert not _segment_file(spool_root, "batch-a").exists()
        assert _exporter_states(database, new_batch_id) == {"clickhouse": "delivered"}
    finally:
        database.close()
