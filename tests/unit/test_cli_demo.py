"""Tests for the spool-only ``demo`` data-flow command."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from click.testing import CliRunner

from milhouse.cli import bootstrap, demo
from milhouse.cli.root import main
from milhouse.config import RuntimePaths, load_config, resolve_runtime_paths

_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_CONFIG = (_REPO_ROOT / "config" / "example.toml").read_text(encoding="utf-8")


def _config_file(tmp_path: Path) -> Path:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text(_EXAMPLE_CONFIG, encoding="utf-8")
    return config_file


def _paths(tmp_path: Path) -> RuntimePaths:
    config_file = _config_file(tmp_path)
    config, config_path = load_config(config_file, platform_default=config_file)
    return resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )


def test_demo_spools_one_record_and_reads_it_back(tmp_path: Path) -> None:
    paths = _paths(tmp_path)

    report = demo.run_demo(paths, now=_NOW)

    assert report.records_spooled == 1
    assert report.read_back_ok is True
    assert report.batch_id.startswith("demo-")
    assert report.day == "2026-08-03"
    segment = paths.spool / "pending" / report.day / f"{report.batch_id}.jsonl"
    assert segment.is_file()


def test_demo_initializes_a_fresh_state_root(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    # No prior init: demo must establish the control plane and identity itself.
    assert not bootstrap.database_path(paths).is_file()

    demo.run_demo(paths, now=_NOW)

    assert bootstrap.database_path(paths).is_file()
    assert bootstrap.read_installation_id(paths) is not None


def test_demo_is_rerunnable_with_distinct_segments(tmp_path: Path) -> None:
    paths = _paths(tmp_path)

    first = demo.run_demo(paths, now=_NOW)
    second = demo.run_demo(paths, now=_NOW)

    assert first.batch_id != second.batch_id
    assert first.read_back_ok and second.read_back_ok
    day_dir = paths.spool / "pending" / first.day
    spooled = {p.stem for p in day_dir.glob("demo-*.jsonl")}
    assert {first.batch_id, second.batch_id} <= spooled


def test_demo_record_is_bound_to_the_installation_identity(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    bootstrap.initialize(paths, now=_NOW)
    installation_id = bootstrap.read_installation_id(paths)
    assert installation_id is not None

    # Building the record with the established identity succeeds and derives a record id.
    record = demo._demo_record(installation_id, now=_NOW)
    assert record.record_id.startswith("mh_")


# --- CLI surface ---------------------------------------------------------------------------------


def test_cli_demo_reports_success(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["--config", str(config_file), "demo"])
    assert result.exit_code == 0
    assert "read-back ok" in result.output
    assert "spooled 1 record" in result.output


def test_cli_demo_json_is_stable(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["--config", str(config_file), "demo", "--json"])
    assert result.exit_code == 0
    assert '"read_back_ok": true' in result.output
    assert '"records_spooled": 1' in result.output


def test_cli_demo_reports_config_error_with_exit_code_two(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    runner = CliRunner()
    result = runner.invoke(main, ["--config", str(missing), "demo"])
    assert result.exit_code == 2
