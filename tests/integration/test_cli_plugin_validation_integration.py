from __future__ import annotations

from collections.abc import Iterable
from importlib import metadata
from pathlib import Path

import pytest
from click.testing import CliRunner

import milhouse.config.plugins as plugin_validation
from milhouse.cli import main

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPOSITORY_ROOT / "config/example.toml"


def _plugin_config(tmp_path: Path, *, version: str = "3.4.5") -> Path:
    plugin_section = """[plugins]
allow_third_party = true

[[plugins.allowed]]
distribution = "integration-plugin"
version = "3.4.5"
group = "milhouse.collectors"
entry_point = "integration_plugin.collector:Collector"
"""
    text = EXAMPLE_CONFIG.read_text(encoding="utf-8").replace(
        "[plugins]\nallow_third_party = false\n",
        plugin_section,
    )
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _distribution(tmp_path: Path, *, version: str) -> metadata.PathDistribution:
    dist_info = tmp_path / "integration_plugin-3.4.5.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: integration-plugin\nVersion: {version}\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        "[milhouse.collectors]\nintegration = integration_plugin.collector:Collector\n",
        encoding="utf-8",
    )
    return metadata.PathDistribution(dist_info)


def test_config_validate_checks_installed_plugin_metadata_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _plugin_config(tmp_path)
    installed = _distribution(tmp_path, version="3.4.5")

    def finder(distribution: str) -> Iterable[metadata.Distribution]:
        assert distribution == "integration-plugin"
        return (installed,)

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)

    result = CliRunner().invoke(
        main,
        ["--config", str(config_path), "config", "validate"],
    )

    assert result.exit_code == 0
    assert result.stdout == "configuration is valid\n"
    assert result.stderr == ""


def test_config_validate_refuses_version_drift_without_exposing_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _plugin_config(tmp_path)
    installed_canary = "3.4.5+private-build-314159"
    installed = _distribution(tmp_path, version=installed_canary)

    def finder(_distribution: str) -> Iterable[metadata.Distribution]:
        return (installed,)

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)

    result = CliRunner().invoke(
        main,
        ["--config", str(config_path), "config", "validate"],
    )

    assert result.exit_code == 2
    assert "config.plugins.version_mismatch" in result.stderr
    assert "plugins.allowed item 1" in result.stderr
    assert "integration-plugin" not in result.output
    assert installed_canary not in result.output
