from __future__ import annotations

import sys
import traceback
from collections.abc import Iterable
from importlib import invalidate_caches, metadata
from pathlib import Path

import pytest

import milhouse.config.plugins as plugin_validation
from milhouse.config._models import PluginsConfig
from milhouse.config.errors import ConfigError


def _policy(*, distribution: str, entry_point: str) -> PluginsConfig:
    return PluginsConfig.model_validate(
        {
            "allow_third_party": True,
            "allowed": [
                {
                    "distribution": distribution,
                    "version": "1.0.0",
                    "group": "milhouse.collectors",
                    "entry_point": entry_point,
                }
            ],
        }
    )


def test_metadata_validation_never_imports_allowlisted_plugin_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "synthetic_plugin_import_canary"
    distribution_name = "synthetic-security-plugin"
    sentinel = tmp_path / "plugin-imported"
    module = tmp_path / f"{module_name}.py"
    module.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('imported')\n"
        "class Collector:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    dist_info = tmp_path / "synthetic_security_plugin-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {distribution_name}\nVersion: 1.0.0\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[milhouse.collectors]\nsynthetic = {module_name}:Collector\n",
        encoding="utf-8",
    )
    distribution = metadata.PathDistribution(dist_info)

    def finder(name: str) -> Iterable[metadata.Distribution]:
        assert name == distribution_name
        return (distribution,)

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)

    plugin_validation.validate_configured_plugins(
        _policy(distribution=distribution_name, entry_point=f"{module_name}:Collector")
    )

    assert module_name not in sys.modules
    assert not sentinel.exists()


def test_real_distribution_metadata_is_validated_without_importing_its_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    distribution_name = "milhouse-synthetic-metadata-contract-7f31"
    module_name = "milhouse_synthetic_metadata_contract_7f31"
    sentinel = tmp_path / "real-metadata-plugin-imported"
    distribution = tmp_path / f"{distribution_name.replace('-', '_')}-1.0.0.dist-info"
    distribution.mkdir()
    (distribution / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {distribution_name}\nVersion: 1.0.0\n",
        encoding="utf-8",
    )
    (distribution / "entry_points.txt").write_text(
        f"[milhouse.collectors]\nsynthetic = {module_name}:Collector\n",
        encoding="utf-8",
    )
    (tmp_path / f"{module_name}.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('imported')\n"
        "class Collector:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    invalidate_caches()

    plugin_validation.validate_configured_plugins(
        _policy(distribution=distribution_name, entry_point=f"{module_name}:Collector")
    )

    assert module_name not in sys.modules
    assert not sentinel.exists()


def test_unlisted_distributions_are_never_discovered_or_inspected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = "configured-plugin"
    unlisted_canary = "unlisted-private-plugin-314159"
    calls: list[str] = []

    dist_info = tmp_path / "configured_plugin-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {configured}\nVersion: 1.0.0\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        "[milhouse.collectors]\nconfigured = configured_plugin:Collector\n",
        encoding="utf-8",
    )
    distribution = metadata.PathDistribution(dist_info)

    def finder(name: str) -> Iterable[metadata.Distribution]:
        calls.append(name)
        if name == unlisted_canary:
            raise AssertionError("unlisted distribution was inspected")
        return (distribution,)

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)

    plugin_validation.validate_configured_plugins(
        _policy(distribution=configured, entry_point="configured_plugin:Collector")
    )

    assert calls == [configured]


def test_hostile_entry_point_metadata_cannot_survive_the_error_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "private-entry-point-canary-271828"
    distribution_name = "hostile-metadata-plugin"

    class HostileEntryPoint:
        @property
        def group(self) -> str:
            raise RuntimeError(canary)

    class Distribution:
        def __init__(self) -> None:
            self.metadata = {"Name": distribution_name}
            self.version = "1.0.0"
            self.entry_points = (HostileEntryPoint(),)

    def finder(_name: str) -> Iterable[metadata.Distribution]:
        return (Distribution(),)  # type: ignore[return-value]

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(
            _policy(distribution=distribution_name, entry_point="hostile_plugin:Collector")
        )

    assert captured.value.code == "config.plugins.metadata_invalid"
    assert canary not in "".join(traceback.format_exception(captured.value))
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
