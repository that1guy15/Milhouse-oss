"""CLI tests for the ``storage`` command group (fake client; no ClickHouse, no secrets)."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from _record_factories import NOW
from _storage_fakes import FakeClickHouseClient
from click.testing import CliRunner, Result

from milhouse.cli import bootstrap, demo, root
from milhouse.cli.root import main
from milhouse.config import RuntimePaths, load_config, resolve_runtime_paths
from milhouse.config.secrets import SecretEnvironment
from milhouse.spooling import (
    DurableSpool,
    SegmentHeaderV1,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.state import GlobalCommitBarrier, open_control_database
from milhouse.storage import FeedbackStateRow, StoredRecordV1

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_CONFIG = (_REPO_ROOT / "config" / "example.toml").read_text(encoding="utf-8")


def _config(tmp_path: Path, *, enabled: bool = True) -> Path:
    # Drop the secret env-file reference (the client/secrets are stubbed in these tests).
    text = _EXAMPLE_CONFIG.replace('env_files = ["../.env"]', "env_files = []")
    if not enabled:
        text = text.replace(
            "[storage.clickhouse]\nenabled = true", "[storage.clickhouse]\nenabled = false"
        )
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text(text, encoding="utf-8")
    return config_file


def _paths(config: Path) -> RuntimePaths:
    # Resolve the same runtime paths the CLI resolves from this config (its [paths] home pins the
    # state root next to the config, so the platform default is irrelevant).
    cfg, cfg_path = load_config(config, platform_default=config)
    return resolve_runtime_paths(cfg, config_path=cfg_path, platform_data_root=config.parent)


def _json_payload(output: str) -> dict[str, object]:
    # The command echoes the JSON to stdout; CliRunner mixes any stderr NOTE/WARNING into output, so
    # pick the single JSON object line.
    return json.loads(next(line for line in output.splitlines() if line.startswith("{")))


def _init_paths(config: Path) -> RuntimePaths:
    paths = _paths(config)
    bootstrap.initialize(paths, now=NOW)  # state root + control DB + installation identity
    return paths


def _commit_segment(paths: RuntimePaths, batch_id: str, exporters: tuple[str, ...]) -> None:
    # Commit one real durable segment with the given required_exporters (state must be initialized).
    # The record is built with the demo's builder so it is finalized under THIS install's identity
    # (the trusted read re-derives it).
    installation_id = bootstrap.read_installation_id(paths)
    assert installation_id is not None
    control = open_control_database(bootstrap.database_path(paths))
    try:
        barrier = GlobalCommitBarrier(
            paths.state_root / bootstrap.CONTROL_DIRNAME / bootstrap.BARRIER_NAME
        )
        store = DurableSpool(
            database=control,
            barrier=barrier,
            spool_root=paths.spool,
            installation_id=installation_id,
        )
        record = demo._demo_record(installation_id, now=NOW)
        frames = [SpoolFrameV1(batch_id=batch_id, sequence=1, record=record)]
        header = SegmentHeaderV1(
            batch_id=batch_id,
            config_generation="d" * 64,
            scope="target",
            target_id="demo-target",
            privacy_class="internal",
            retention_days=30,
            required_exporters=exporters,
            record_count=1,
            content_sha256=spool_content_sha256([spool_frame_line(f) for f in frames]),
        )
        store.commit_segment(header, frames, committed_at=NOW)
    finally:
        control.close()


@pytest.fixture
def _stub(monkeypatch: pytest.MonkeyPatch) -> FakeClickHouseClient:
    fake = FakeClickHouseClient()
    monkeypatch.setattr(
        root, "load_secret_environment", lambda config, paths: SecretEnvironment({}, {})
    )
    monkeypatch.setattr(root.storage, "build_client", lambda config, secrets: fake)
    return fake


def test_cli_storage_status_then_migrate(tmp_path: Path, _stub: FakeClickHouseClient) -> None:
    config = _config(tmp_path)
    _init_paths(config)  # migrate fences under the commit barrier (needs init)
    runner = CliRunner()

    status = runner.invoke(main, ["--config", str(config), "storage", "status"])
    assert status.exit_code == 0
    assert "pending=5" in status.output
    assert _stub.databases == set()  # status did not mutate

    migrated = runner.invoke(main, ["--config", str(config), "storage", "migrate"])
    assert migrated.exit_code == 0
    assert "version 5" in migrated.output

    after = runner.invoke(main, ["--config", str(config), "storage", "status", "--json"])
    assert after.exit_code == 0
    assert '"current_version": 5' in after.output


def test_cli_storage_plan_is_read_only(tmp_path: Path, _stub: FakeClickHouseClient) -> None:
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "plan", "--json"])
    assert result.exit_code == 0
    assert '"database": "milhouse"' in result.output
    assert _stub.commands == []


def test_cli_storage_migrate_json(tmp_path: Path, _stub: FakeClickHouseClient) -> None:
    config = _config(tmp_path)
    _init_paths(config)  # migrate fences under the commit barrier (needs init)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "migrate", "--json"])
    assert result.exit_code == 0
    assert '"applied_now": [1, 2, 3, 4, 5]' in result.output
    assert '"current_version": 5' in result.output


def test_cli_storage_migrate_requires_an_initialized_control_plane(
    tmp_path: Path, _stub: FakeClickHouseClient
) -> None:
    # migrate fences under the control-plane commit barrier, whose lock lives under an initialized
    # control dir. Without init it fails on the "not initialized" path, before any ClickHouse call.
    config = _config(tmp_path)  # no _init_paths
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "migrate"])
    assert result.exit_code == 1
    assert _stub.commands == []  # never reached the migration runner


def test_cli_storage_migrate_is_fenced_by_the_exclusive_commit_barrier(
    tmp_path: Path, _stub: FakeClickHouseClient
) -> None:
    # storage export delivers ClickHouse rows under barrier.shared(); a table-rebuild migration
    # (0005's copy → swap → drop) must not run concurrently, or a row inserted mid-rebuild could be
    # dropped. So storage migrate takes the EXCLUSIVE side of control/commit.lock and blocks while
    # any shared hold (an in-flight export) is active. The full "concurrent writer during a REAL
    # migration" proof is host-gated (live ClickHouse, E06); here we prove the mutual exclusion.
    config = _config(tmp_path)
    paths = _init_paths(config)
    barrier = GlobalCommitBarrier(
        paths.state_root / bootstrap.CONTROL_DIRNAME / bootstrap.BARRIER_NAME
    )
    holding = threading.Event()
    release = threading.Event()
    migrate_done = threading.Event()
    captured: dict[str, object] = {}

    def _hold_shared() -> None:
        with barrier.shared():  # simulate an in-flight export holding the shared delivery side
            holding.set()
            release.wait(timeout=15)

    def _run_migrate() -> None:
        captured["result"] = CliRunner().invoke(
            main, ["--config", str(config), "storage", "migrate"]
        )
        migrate_done.set()

    holder = threading.Thread(target=_hold_shared)
    holder.start()
    try:
        assert holding.wait(timeout=10)  # the shared hold is active
        migrator = threading.Thread(target=_run_migrate)
        migrator.start()
        try:
            # While the shared hold is active, migrate is blocked on exclusive() and cannot complete
            # nor run any migration statement.
            assert not migrate_done.wait(timeout=1.0)
            assert _stub.commands == []
            release.set()  # the "export" finishes; migrate now acquires exclusive and proceeds
            assert migrate_done.wait(timeout=10)
        finally:
            migrator.join(timeout=10)
    finally:
        release.set()
        holder.join(timeout=10)

    result = captured["result"]
    assert isinstance(result, Result)
    assert result.exit_code == 0
    assert "version 5" in result.output  # it did migrate, once unblocked


def test_cli_storage_disabled_is_an_error(tmp_path: Path, _stub: FakeClickHouseClient) -> None:
    config = _config(tmp_path, enabled=False)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "status"])
    assert result.exit_code == 1
    assert "disabled" in result.output


def test_cli_storage_config_error_is_exit_two(tmp_path: Path, _stub: FakeClickHouseClient) -> None:
    result = CliRunner().invoke(
        main, ["--config", str(tmp_path / "missing.toml"), "storage", "status"]
    )
    assert result.exit_code == 2


class _RaisingClient(FakeClickHouseClient):
    """A fake whose ``insert`` raises so the delivery is contained as a retryable failure."""

    def insert(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("clickhouse insert unavailable")


class _FixedClock:
    """A fixed-instant clock so the export's hard-expiry gate is deterministic in tests."""

    def __init__(self, instant: datetime) -> None:
        self._instant = instant

    def now(self) -> datetime:
        return self._instant


def _spool_one_pending_segment(config: Path) -> None:
    # The spool-only demo initializes state and commits one pending "clickhouse" segment (one event
    # record), so the ledger-gated export has real work to drain — no monkeypatched spool.
    assert CliRunner().invoke(main, ["--config", str(config), "demo"]).exit_code == 0


def test_cli_storage_export_delivers_committed_segments(
    tmp_path: Path, _stub: FakeClickHouseClient
) -> None:
    config = _config(tmp_path)
    _spool_one_pending_segment(config)

    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])

    assert result.exit_code == 0
    assert (
        "segments=1 records=1 delivered=1 already_delivered=0 failed=0 expired=0" in result.output
    )
    assert [table for _db, table, *_ in _stub.inserts] == ["records"]  # the event's record row


def test_cli_storage_export_over_an_empty_ledger_is_zero(
    tmp_path: Path, _stub: FakeClickHouseClient
) -> None:
    # An initialized install with no committed segments drains nothing and writes nothing.
    config = _config(tmp_path)
    assert CliRunner().invoke(main, ["--config", str(config), "init"]).exit_code == 0

    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export", "--json"])

    assert result.exit_code == 0
    assert '"segments": 0' in result.output
    assert '"records": 0' in result.output
    assert '"delivered": 0' in result.output
    assert '"failed": 0' in result.output
    assert _stub.inserts == []


def test_cli_storage_export_is_idempotent_already_delivered_no_reinsert(
    tmp_path: Path, _stub: FakeClickHouseClient
) -> None:
    config = _config(tmp_path)
    _spool_one_pending_segment(config)
    assert CliRunner().invoke(main, ["--config", str(config), "storage", "export"]).exit_code == 0
    inserts_after_first = len(_stub.inserts)

    # A full re-drain re-reads the delivered segment, but the terminal ledger row makes delivery an
    # idempotent no-op: already_delivered, with ZERO new inserts (no duplicate records /
    # feedback_transitions row) — the exactly-once-logical guarantee.
    second = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])
    assert second.exit_code == 0
    assert (
        "segments=1 records=1 delivered=0 already_delivered=1 failed=0 expired=0" in second.output
    )
    assert len(_stub.inserts) == inserts_after_first


def test_cli_storage_export_failed_delivery_is_fail_loud_and_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A ClickHouse insert that raises is contained as a retryable "failed" delivery; the export is
    # then incomplete, so it warns on stderr and exits non-zero rather than implying a full success.
    raising = _RaisingClient()
    monkeypatch.setattr(
        root, "load_secret_environment", lambda config, paths: SecretEnvironment({}, {})
    )
    monkeypatch.setattr(root.storage, "build_client", lambda config, secrets: raising)
    config = _config(tmp_path)
    _spool_one_pending_segment(config)

    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])

    assert result.exit_code == 1
    assert "failed=1" in result.output
    assert "export incomplete" in result.output
    assert raising.inserts == []  # the raising insert recorded nothing


def test_cli_storage_export_recovers_a_failed_segment_on_the_next_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The CLI outage-recovery proof: a ClickHouse outage leaves the segment "failed" and the export
    # exits non-zero; the NEXT export (healthy client) redelivers that same segment exactly once.
    config = _config(tmp_path)
    _spool_one_pending_segment(config)
    monkeypatch.setattr(
        root, "load_secret_environment", lambda config, paths: SecretEnvironment({}, {})
    )

    # Outage: the insert raises → the segment is left retryable "failed", export exits non-zero.
    raising = _RaisingClient()
    monkeypatch.setattr(root.storage, "build_client", lambda config, secrets: raising)
    outage = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])
    assert outage.exit_code == 1
    assert "failed=1" in outage.output
    assert raising.inserts == []

    # Recovery: a healthy client on the next run redelivers the previously-failed segment once.
    healthy = FakeClickHouseClient()
    monkeypatch.setattr(root.storage, "build_client", lambda config, secrets: healthy)
    recovered = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])
    assert recovered.exit_code == 0
    assert (
        "segments=1 records=1 delivered=1 already_delivered=0 failed=0 expired=0"
        in recovered.output
    )
    assert [table for _db, table, *_ in healthy.inserts] == ["records"]  # delivered exactly once


def test_cli_storage_export_notes_expired_withheld_segments(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A committed segment whose records reach their privacy expiry BEFORE delivery is withheld
    # (privacy-correct — expired records must never egress). That is not an error (exit 0), but it
    # must be observable: an informational stderr NOTE, so the withholding is never silent.
    config = _config(tmp_path)
    _spool_one_pending_segment(config)  # records expire ~30 days after real now
    # Export far past the records' expiry so the hard-expiry gate withholds the segment.
    future = datetime.now(UTC) + timedelta(days=60)
    monkeypatch.setattr(root, "SystemClock", lambda: _FixedClock(future))

    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])

    assert result.exit_code == 0  # withheld-as-expired is not an error, only failed forces exit 1
    assert "expired=1" in result.output
    assert "reached their privacy expiry before delivery and were not exported" in result.output
    assert _stub.inserts == []  # nothing was forwarded to ClickHouse


def test_cli_storage_export_reports_a_segment_with_an_empty_exporter_set_as_unhandled(
    tmp_path: Path, _stub: FakeClickHouseClient
) -> None:
    # required_exporters=() → drained but never forwarded → NOT in ClickHouse. The export must
    # report it ``unhandled``, scope ``records`` to handled segments, note it, and exit non-zero
    # (else a silent rebuild gap). Expiry is irrelevant: an obligation-free segment yields zero
    # attempts.
    config = _config(tmp_path)
    _commit_segment(_init_paths(config), "batch-no-obligation", ())

    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])

    assert result.exit_code == 1  # unhandled is incomplete, same posture as failed
    assert "segments=1 records=0" in result.output  # records scoped to clickhouse-handled segments
    assert "unhandled=1" in result.output
    assert "no clickhouse delivery obligation" in result.output
    assert _stub.inserts == []  # nothing forwarded to ClickHouse


def test_cli_storage_export_reports_a_segment_with_only_another_exporter_as_unhandled(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A segment whose required_exporters names ONLY a non-clickhouse exporter is likewise not in
    # ClickHouse (its one delivery attempt is for the other id, never clickhouse). The clock is
    # pinned so the drain is deterministic (the attempt is ``no_exporter``, never ``expired``).
    config = _config(tmp_path)
    _commit_segment(_init_paths(config), "batch-webhook-only", ("webhook",))
    monkeypatch.setattr(root, "SystemClock", lambda: _FixedClock(NOW))

    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])

    assert result.exit_code == 1
    assert "segments=1 records=0" in result.output
    assert "unhandled=1" in result.output
    assert "expired=0" in result.output  # a non-clickhouse obligation is unhandled, not expired
    assert "no clickhouse delivery obligation" in result.output
    assert _stub.inserts == []


def test_cli_storage_export_mixed_delivered_and_unhandled_scopes_records_and_exits_nonzero(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A mixed drain: one clickhouse-obligated segment (delivered) plus one obligation-free segment
    # (unhandled). ``records`` counts only the delivered segment, and the presence of an unhandled
    # segment still forces a non-zero exit. Clock pinned so the clickhouse segment is not expired.
    config = _config(tmp_path)
    paths = _init_paths(config)
    _commit_segment(paths, "batch-clickhouse", ("clickhouse",))
    _commit_segment(paths, "batch-no-obligation", ())
    monkeypatch.setattr(root, "SystemClock", lambda: _FixedClock(NOW))

    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])

    assert result.exit_code == 1  # an unhandled segment makes the export incomplete
    assert (
        "segments=2 records=1 delivered=1 already_delivered=0 failed=0 expired=0 unhandled=1"
        in result.output
    )
    assert "no clickhouse delivery obligation" in result.output
    assert [table for _db, table, *_ in _stub.inserts] == ["records"]  # only the delivered segment


def test_cli_storage_export_records_count_is_confirmed_egress_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ``records`` must count only CONFIRMED egress (delivered / already_delivered), never a failed
    # (retry-eligible) attempt — a fully-failed export must not report records=1, overstating what
    # reached ClickHouse. The clock is pinned so the segment is not expired at the drain.
    config = _config(tmp_path)
    paths = _init_paths(config)
    _commit_segment(paths, "batch-ch", ("clickhouse",))
    monkeypatch.setattr(
        root, "load_secret_environment", lambda config, paths: SecretEnvironment({}, {})
    )
    monkeypatch.setattr(root, "SystemClock", lambda: _FixedClock(NOW))

    # (a) The insert raises before any row lands → the segment is failed and CONFIRMED records is 0.
    raising = _RaisingClient()
    monkeypatch.setattr(root.storage, "build_client", lambda config, secrets: raising)
    text_a = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])
    assert text_a.exit_code == 1
    assert (
        "export: segments=1 records=0 delivered=0 already_delivered=0 "
        "failed=1 expired=0 unhandled=0" in text_a.output
    )
    json_a = CliRunner().invoke(main, ["--config", str(config), "storage", "export", "--json"])
    assert json_a.exit_code == 1
    assert _json_payload(json_a.output) == {
        "already_delivered": 0,
        "delivered": 0,
        "expired": 0,
        "failed": 1,
        "records": 0,
        "segments": 1,
        "unhandled": 0,
    }
    assert raising.inserts == []

    # (b) A healthy retry delivers the SAME segment → its records now appear in the confirmed count
    # exactly once (as delivered now, then already_delivered on the idempotent re-run).
    healthy = FakeClickHouseClient()
    monkeypatch.setattr(root.storage, "build_client", lambda config, secrets: healthy)
    text_b = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])
    assert text_b.exit_code == 0
    assert (
        "export: segments=1 records=1 delivered=1 already_delivered=0 "
        "failed=0 expired=0 unhandled=0" in text_b.output
    )
    assert [table for _db, table, *_ in healthy.inserts] == ["records"]  # delivered exactly once
    json_b = CliRunner().invoke(main, ["--config", str(config), "storage", "export", "--json"])
    assert json_b.exit_code == 0
    assert _json_payload(json_b.output) == {
        "already_delivered": 1,
        "delivered": 0,
        "expired": 0,
        "failed": 0,
        "records": 1,  # already_delivered is confirmed egress, counted exactly once
        "segments": 1,
        "unhandled": 0,
    }
    assert [table for _db, table, *_ in healthy.inserts] == [
        "records"
    ]  # no new insert on the no-op


def test_cli_storage_records(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def _fetch(
        client: object, database: str, *, target_id: str | None = None
    ) -> tuple[object, ...]:
        seen["target_id"] = target_id
        return (
            StoredRecordV1(
                record_id="mh_r1",
                record_type="event",
                name="source.event",
                target_id="example-target",
                occurred_at="2026-07-21T15:00:00.000Z",
                ingested_at="2026-07-21T15:00:02.000Z",
                expires_at="2026-08-20T15:00:00.000Z",
                severity="info",
                privacy_class="internal",
            ),
        )

    monkeypatch.setattr(root.storage, "fetch_current_records", _fetch)
    config = _config(tmp_path)
    result = CliRunner().invoke(
        main, ["--config", str(config), "storage", "records", "--target", "example-target"]
    )
    assert result.exit_code == 0
    assert "mh_r1 event/source.event" in result.output
    assert seen["target_id"] == "example-target"

    as_json = CliRunner().invoke(main, ["--config", str(config), "storage", "records", "--json"])
    assert as_json.exit_code == 0
    assert '"record_id": "mh_r1"' in as_json.output
    assert seen["target_id"] is None  # no --target → unfiltered


def test_cli_storage_records_empty(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(root.storage, "fetch_current_records", lambda *a, **k: ())
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "records"])
    assert result.exit_code == 0
    assert "no current records" in result.output


def test_cli_storage_feedback(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        root.storage,
        "fetch_current_feedback",
        lambda client, database: (
            FeedbackStateRow(
                item_id="feedback-1",
                current_state="accepted",
                current_revision=3,
                last_transition_at="2026-07-21T15:00:00.000Z",
            ),
        ),
    )
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "feedback"])
    assert result.exit_code == 0
    assert "feedback-1 state=accepted revision=3" in result.output

    as_json = CliRunner().invoke(main, ["--config", str(config), "storage", "feedback", "--json"])
    assert '"current_state": "accepted"' in as_json.output


def test_cli_storage_feedback_empty(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(root.storage, "fetch_current_feedback", lambda *a, **k: ())
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "feedback"])
    assert result.exit_code == 0
    assert "no feedback items" in result.output
