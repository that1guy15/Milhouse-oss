"""CLI tests for the ``storage`` command group (fake client; no ClickHouse, no secrets)."""

from __future__ import annotations

from pathlib import Path

import pytest
from _record_factories import event_record
from _storage_fakes import FakeClickHouseClient
from click.testing import CliRunner

from milhouse.cli import root
from milhouse.cli.root import main
from milhouse.cli.views import TrustedRecordScan
from milhouse.config.secrets import SecretEnvironment
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
    runner = CliRunner()

    status = runner.invoke(main, ["--config", str(config), "storage", "status"])
    assert status.exit_code == 0
    assert "pending=4" in status.output
    assert _stub.databases == set()  # status did not mutate

    migrated = runner.invoke(main, ["--config", str(config), "storage", "migrate"])
    assert migrated.exit_code == 0
    assert "version 4" in migrated.output

    after = runner.invoke(main, ["--config", str(config), "storage", "status", "--json"])
    assert after.exit_code == 0
    assert '"current_version": 4' in after.output


def test_cli_storage_plan_is_read_only(tmp_path: Path, _stub: FakeClickHouseClient) -> None:
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "plan", "--json"])
    assert result.exit_code == 0
    assert '"database": "milhouse"' in result.output
    assert _stub.commands == []


def test_cli_storage_migrate_json(tmp_path: Path, _stub: FakeClickHouseClient) -> None:
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "migrate", "--json"])
    assert result.exit_code == 0
    assert '"applied_now": [1, 2, 3, 4]' in result.output
    assert '"current_version": 4' in result.output


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


@pytest.fixture
def _spooled_records(monkeypatch: pytest.MonkeyPatch) -> None:
    # Bypass bootstrap + the real spool: the export command is wired to one spooled event record.
    monkeypatch.setattr(root, "_require_installation_id", lambda paths: "mh_installation")
    monkeypatch.setattr(
        root.views,
        "read_trusted_records",
        lambda paths, iid: TrustedRecordScan(records=(event_record(),), skipped=()),
    )


def test_cli_storage_export(
    tmp_path: Path, _stub: FakeClickHouseClient, _spooled_records: None
) -> None:
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])
    assert result.exit_code == 0
    assert "records=1 feedback_items=0 feedback_transitions=0 skipped_segments=0" in result.output
    assert [table for _db, table, *_ in _stub.inserts] == ["records"]


def test_cli_storage_export_json_and_empty(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Point the export at an empty spool → zero rows, no inserts recorded.
    monkeypatch.setattr(root, "_require_installation_id", lambda paths: "mh_installation")
    monkeypatch.setattr(
        root.views, "read_trusted_records", lambda paths, iid: TrustedRecordScan((), ())
    )
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export", "--json"])
    assert result.exit_code == 0
    assert '"records": 0' in result.output
    assert '"skipped_segments": []' in result.output
    assert _stub.inserts == []


def test_cli_storage_export_reports_unreadable_segments_and_exits_nonzero(
    tmp_path: Path, _stub: FakeClickHouseClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A committed segment that fails the trusted read must be surfaced, not silently dropped.
    monkeypatch.setattr(root, "_require_installation_id", lambda paths: "mh_installation")
    monkeypatch.setattr(
        root.views,
        "read_trusted_records",
        lambda paths, iid: TrustedRecordScan(records=(event_record(),), skipped=("batch-bad",)),
    )
    config = _config(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config), "storage", "export"])
    assert result.exit_code == 1  # incomplete export is fail-loud, not exit 0
    assert "skipped_segments=1" in result.output
    assert "export incomplete" in result.output
    assert [table for _db, table, *_ in _stub.inserts] == ["records"]  # the good record still wrote


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
