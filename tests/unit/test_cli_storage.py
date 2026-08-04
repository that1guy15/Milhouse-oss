"""CLI tests for the ``storage`` command group (fake client; no ClickHouse, no secrets)."""

from __future__ import annotations

from pathlib import Path

import pytest
from _storage_fakes import FakeClickHouseClient
from click.testing import CliRunner

from milhouse.cli import root
from milhouse.cli.root import main
from milhouse.config.secrets import SecretEnvironment

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
