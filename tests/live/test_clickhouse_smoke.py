"""Opt-in live G04a/G04b smoke against a real loopback ClickHouse. NOT part of Required CI.

Runs only when ``MILHOUSE_LIVE_CLICKHOUSE`` is set (and a loopback server is reachable via the
``MILHOUSE_CLICKHOUSE_*`` env vars). It exercises the live criteria the offline suite cannot prove:
anonymous access fails, authenticated access succeeds, a fresh deployment migrates to the full
schema, migration status works, checksum enforcement refuses a tampered ledger, and — for G04b — a
real export round-trips records and derives feedback current state through the views.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.config._models import StorageClickHouseConfig
from milhouse.config.secrets import SecretEnvironment
from milhouse.core.clock import SystemClock
from milhouse.domain.records import TargetDescriptorV1
from milhouse.spooling import (
    DurableSpool,
    SegmentHeaderV1,
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
    ClickHouseExporter,
    StorageError,
    backup_statement,
    build_client,
    claim,
    export_records,
    fetch_current_feedback,
    fetch_current_records,
    migrate,
    plan,
    read_owner,
    reconcile_delivered,
    require_owner,
    restore_statement,
    snapshot_state,
    status,
    verify_restored,
)

# Reuse the exact, CI-validated record builders from the unit suite so this standalone smoke never
# drifts from the domain contract (its own construction would not be checked by Required CI).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from _record_factories import (
    INSTALLATION_ID,
    event_record,
    feedback_item_record,
    feedback_transition_record,
)

pytestmark = pytest.mark.live

_ENABLED = os.environ.get("MILHOUSE_LIVE_CLICKHOUSE")
_SMOKE_DB = "milhouse_live_smoke"
_requires_live = pytest.mark.skipif(
    not _ENABLED,
    reason="set MILHOUSE_LIVE_CLICKHOUSE=1 and MILHOUSE_CLICKHOUSE_* against a loopback server",
)


def _config(
    *, user_env: str = "MILHOUSE_CLICKHOUSE_USER", pass_env: str = "MILHOUSE_CLICKHOUSE_PASSWORD"
) -> StorageClickHouseConfig:
    return StorageClickHouseConfig(
        enabled=True,
        url_env="MILHOUSE_CLICKHOUSE_URL",
        username_env=user_env,
        password_env=pass_env,
        database=_SMOKE_DB,
        connect_timeout_seconds=5,
    )


def _secrets(overrides: dict[str, str] | None = None) -> SecretEnvironment:
    values = {
        key: os.environ[key]
        for key in (
            "MILHOUSE_CLICKHOUSE_URL",
            "MILHOUSE_CLICKHOUSE_USER",
            "MILHOUSE_CLICKHOUSE_PASSWORD",
        )
        if key in os.environ
    }
    values.update(overrides or {})
    return SecretEnvironment(values, {})


@_requires_live
def test_live_fresh_migrate_status_idempotent_and_checksum_enforcement() -> None:
    client = build_client(_config(), _secrets())
    try:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")

        assert plan(client, _SMOKE_DB).current_version == 0  # fresh deployment

        result = migrate(client, _SMOKE_DB, now=datetime.now(UTC), milhouse_version="live-smoke")
        assert result.current_version == 6  # migrated to the full schema
        assert status(client, _SMOKE_DB).current_version == 6  # status reports it

        again = migrate(client, _SMOKE_DB, now=datetime.now(UTC), milhouse_version="live-smoke")
        assert again.applied_now == ()  # idempotent

        client.command(
            f"ALTER TABLE {_SMOKE_DB}._migrations UPDATE checksum = 'deadbeef' "
            "WHERE version = 1 SETTINGS mutations_sync = 1"
        )
        with pytest.raises(StorageError) as captured:
            migrate(client, _SMOKE_DB, now=datetime.now(UTC), milhouse_version="live-smoke")
        assert captured.value.code == "MH_STORAGE_MIGRATION"
    finally:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")
        client.close()


@_requires_live
def test_live_default_empty_password_account_is_denied() -> None:
    # The built-in `default` account with an EMPTY password is the anonymous/unauthenticated vector
    # G04a must reject and the whole compose/users.d hardening exists to lock. A hardened deployment
    # rejects it; an open server (missing the users.d lock) would let this connect — exactly the
    # regression this case exists to catch.
    client = build_client(
        _config(user_env="MILHOUSE_LIVE_DEFAULT_USER", pass_env="MILHOUSE_LIVE_DEFAULT_PASSWORD"),
        _secrets({"MILHOUSE_LIVE_DEFAULT_USER": "default", "MILHOUSE_LIVE_DEFAULT_PASSWORD": ""}),
    )
    with pytest.raises(StorageError) as captured:
        client.query("SELECT 1")
    assert captured.value.code == "MH_STORAGE_CLIENT"
    client.close()


@_requires_live
def test_live_export_round_trips_records_and_derives_feedback_state() -> None:
    client = build_client(_config(), _secrets())
    try:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")
        migrate(client, _SMOKE_DB, now=datetime.now(UTC), milhouse_version="live-smoke")

        # Build against a real clock instant so expires_at is in the future — otherwise the fixed
        # factory anchor would age past records_current's retention filter and fail spuriously.
        now = SystemClock().now()
        event = event_record(now=now)
        item = feedback_item_record(now=now)
        transition = feedback_transition_record(now=now)
        other = event_record(
            now=now,
            target=TargetDescriptorV1(
                id="other-target", name="Other", kind="web.service", environment="test"
            ),
        )
        summary = export_records(client, _SMOKE_DB, [event, item, transition, other])
        assert (summary.records, summary.feedback_items, summary.feedback_transitions) == (4, 1, 1)

        # Re-export: the deduplicating records table collapses the repeat.
        export_records(client, _SMOKE_DB, [event, item, transition, other])

        records = fetch_current_records(client, _SMOKE_DB)
        appearances = [row for row in records if row.record_id == event.record_id]
        assert len(appearances) == 1  # deduplicated by ReplacingMergeTree FINAL
        assert appearances[0].record_type == "event"

        # The target filter is bound server-side and actually EXCLUDES non-matching targets.
        filtered = fetch_current_records(client, _SMOKE_DB, target_id="example-target")
        filtered_ids = {row.record_id for row in filtered}
        assert event.record_id in filtered_ids
        assert other.record_id not in filtered_ids  # other-target is excluded
        assert all(row.target_id == "example-target" for row in filtered)

        feedback = {row.item_id: row for row in fetch_current_feedback(client, _SMOKE_DB)}
        assert feedback["feedback-1"].current_state == "accepted"  # argMax over the locked order
        assert feedback["feedback-1"].current_revision == 1

        # G04b / E06 owner-host evidence (live only): the re-export above re-inserted the same
        # transition, so feedback_transitions physically holds two rows for it. Migration 0005
        # recreated the table as ReplacingMergeTree(item_id, transition_id), so a merge collapses
        # them to ONE physical row — the terminal proof 0005 de-dups a redelivered transition (the
        # at-least-once retry / concurrent-drain cost). This can only run against a real ClickHouse
        # (the offline fake models no merges), and it also proves 0005's EXCHANGE TABLES swap ran on
        # the deployment's table engine — a fresh migrate above would have failed otherwise.
        client.command(f"OPTIMIZE TABLE {_SMOKE_DB}.feedback_transitions FINAL")
        collapsed = client.query(
            f"SELECT count() FROM {_SMOKE_DB}.feedback_transitions FINAL "
            "WHERE transition_id = {tid:String}",
            parameters={"tid": transition.data.transition_id},
        )
        assert int(collapsed[0][0]) == 1  # the redelivered transition collapsed to one physical row
    finally:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")
        client.close()


@_requires_live
def test_live_native_backup_restore_round_trips_and_reconciles(tmp_path: Path) -> None:
    # G04b / E06 owner-host evidence (live only): the physical native BACKUP/RESTORE round-trip the
    # offline suite cannot prove (FakeClickHouseClient models no BACKUP engine, merges, or TTL). A
    # real BACKUP DATABASE → DROP DATABASE → RESTORE DATABASE must reproduce the record-id set and
    # migration state (verify_restored), and the restored store must contain every record id the
    # SQLite delivery ledger marks delivered to clickhouse (reconcile_delivered — the cross-store
    # "matches exporter checkpoints" reading; feedback-state parity is deferred to G16). Requires a
    # ClickHouse deployment with a configured backup disk named ``backups``
    # (``<backups><allowed_disk>backups</allowed_disk></backups>``); it self-skips out of Required
    # CI like every other case here.
    client = build_client(_config(), _secrets())
    control = None
    try:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")
        now = SystemClock().now()
        migrate(client, _SMOKE_DB, now=now, milhouse_version="live-smoke")

        # A real control plane + durable spool under tmp_path so a real delivery advances the SQLite
        # ledger, giving reconcile_delivered an authoritative delivered-to-clickhouse set to check.
        state_root = tmp_path / "state"
        control_dir = state_root / "control"
        control_dir.mkdir(mode=0o700, parents=True)
        os.chmod(control_dir, 0o700)
        spool_root = state_root / "spool"
        spool_root.mkdir(mode=0o700)
        os.chmod(spool_root, 0o700)
        control = open_control_database(control_dir / "milhouse.sqlite3")
        barrier = GlobalCommitBarrier(control_dir / "commit.lock")
        initialize_control_state(control, barrier=barrier, applied_at=now)
        store = DurableSpool(
            database=control,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=INSTALLATION_ID,
        )

        record = event_record(now=now)
        frames = [SpoolFrameV1(batch_id="batch-live", sequence=1, record=record)]
        header = SegmentHeaderV1(
            batch_id="batch-live",
            config_generation="a" * 64,
            scope="target",
            target_id="example-target",
            privacy_class="internal",
            retention_days=30,
            required_exporters=(CLICKHOUSE_EXPORTER_ID,),
            record_count=1,
            content_sha256=spool_content_sha256([spool_frame_line(frames[0])]),
        )
        store.commit_segment(header, frames, committed_at=now)
        replay_segments(
            control,
            barrier,
            spool_root=spool_root,
            installation_id=INSTALLATION_ID,
            exporters={CLICKHOUSE_EXPORTER_ID: ClickHouseExporter(client, _SMOKE_DB)},
            now=now,
            delivery_status="pending",
        )

        source = snapshot_state(client, _SMOKE_DB)
        assert source.migration_version == 6
        assert record.record_id in source.record_ids

        # Drive the real DR restore SEQUENCE the ``storage restore`` command performs (backup → DROP
        # DATABASE → RESTORE into the emptied target → post-restore validity gate → reconcile) via
        # the same functions the CLI uses, plus the strict physical round-trip only possible here
        # (``source`` captured BEFORE the backup/drop).
        client.command(backup_statement(_SMOKE_DB, "live_backup"))
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")  # disaster: empty the target
        client.command(restore_statement(_SMOKE_DB, "live_backup"))

        # (a) the restore brought a checksum-consistent schema at the current defined head — the
        # CLI's post-restore validity gate, exercised against the real restored ledger.
        restored_plan = status(client, _SMOKE_DB)
        assert restored_plan.current_version == max(entry.version for entry in restored_plan.states)
        restored = snapshot_state(client, _SMOKE_DB)
        # (b) the physical native round-trip reproduced the exact record-id set + migration state.
        verify_restored(source, restored)
        # (c) every clickhouse-delivered record id survived the round-trip (cross-store reconcile).
        reconcile_delivered(
            control, restored, spool_root=spool_root, installation_id=INSTALLATION_ID
        )
    finally:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")
        if control is not None:
            control.close()
        client.close()


@_requires_live
def test_live_installation_ownership_claims_and_rejects_a_cross_installation() -> None:
    # The installation-ownership guard against a REAL ClickHouse: a fresh migrate provisions the
    # ``_installation`` table, a claim stamps the owner, the same installation verifies, and a
    # DIFFERENT installation is refused fail-closed for both a require-check and a claim — unless it
    # deliberately reclaims, which supersedes the prior owner (ReplacingMergeTree(claimed_at)).
    client = build_client(_config(), _secrets())
    id_a = "mh_in1_" + "a" * 32
    id_b = "mh_in1_" + "b" * 32
    try:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")
        now = datetime.now(UTC)
        migrate(client, _SMOKE_DB, now=now, milhouse_version="live-smoke")
        assert read_owner(client, _SMOKE_DB) is None  # migrated but unclaimed

        claim(client, _SMOKE_DB, installation_id=id_a, now=now, milhouse_version="live-smoke")
        assert read_owner(client, _SMOKE_DB) == id_a
        require_owner(client, _SMOKE_DB, installation_id=id_a)  # the owner is admitted (no raise)
        # A same-id re-claim is an idempotent no-op.
        claim(client, _SMOKE_DB, installation_id=id_a, now=now, milhouse_version="live-smoke")
        assert read_owner(client, _SMOKE_DB) == id_a

        # A different installation is refused fail-closed on both the read barrier and a claim.
        with pytest.raises(StorageError) as required:
            require_owner(client, _SMOKE_DB, installation_id=id_b)
        assert required.value.code == "MH_STORAGE_OWNERSHIP"
        with pytest.raises(StorageError) as claimed:
            claim(client, _SMOKE_DB, installation_id=id_b, now=now, milhouse_version="live-smoke")
        assert claimed.value.code == "MH_STORAGE_OWNERSHIP"
        assert read_owner(client, _SMOKE_DB) == id_a  # unchanged by the refused claim

        # A deliberate --reclaim supersedes the prior owner; a strictly later claimed_at wins.
        claim(
            client,
            _SMOKE_DB,
            installation_id=id_b,
            now=now + timedelta(seconds=1),
            milhouse_version="live-smoke",
            reclaim=True,
        )
        assert read_owner(client, _SMOKE_DB) == id_b
        require_owner(client, _SMOKE_DB, installation_id=id_b)
    finally:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")
        client.close()
