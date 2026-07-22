from __future__ import annotations

from collections.abc import Iterable
from importlib import metadata
from pathlib import Path

import pytest

import milhouse.config.plugins as plugin_validation
from milhouse.config._models import PluginsConfig
from milhouse.config.errors import ConfigError


def _policy() -> PluginsConfig:
    return PluginsConfig.model_validate(
        {
            "allow_third_party": True,
            "allowed": [
                {
                    "distribution": "contract-plugin",
                    "version": "2.0.0",
                    "group": "milhouse.collectors",
                    "entry_point": "contract_plugin.collector:Collector",
                }
            ],
        }
    )


def _install(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    entry_point: metadata.EntryPoint,
) -> None:
    dist_info = tmp_path / "contract_plugin-2.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: contract-plugin\nVersion: 2.0.0\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[{entry_point.group}]\n{entry_point.name} = {entry_point.value}\n",
        encoding="utf-8",
    )
    distribution = metadata.PathDistribution(dist_info)

    def finder(_distribution: str) -> Iterable[metadata.Distribution]:
        return (distribution,)

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)


def test_allowlist_entry_point_binds_exactly_to_entry_point_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        tmp_path,
        metadata.EntryPoint(
            name="contract_plugin.collector",
            value="another_plugin.collector:Collector",
            group="milhouse.collectors",
        ),
    )

    with pytest.raises(ConfigError, match=r"config\.plugins\.entry_point_missing"):
        plugin_validation.validate_configured_plugins(_policy())


def test_entry_point_name_is_not_an_unstated_allowlist_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        tmp_path,
        metadata.EntryPoint(
            name="runtime-alias",
            value="contract_plugin.collector:Collector",
            group="milhouse.collectors",
        ),
    )

    assert plugin_validation.validate_configured_plugins(_policy()) is None
