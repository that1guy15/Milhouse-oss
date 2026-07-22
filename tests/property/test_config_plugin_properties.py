from __future__ import annotations

from collections.abc import Iterable
from importlib import metadata
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest
from hypothesis import given
from hypothesis import strategies as st

import milhouse.config.plugins as plugin_validation
from milhouse.config._models import PluginsConfig
from milhouse.config.errors import ConfigError


@given(
    epoch=st.integers(min_value=0, max_value=9),
    major=st.integers(min_value=0, max_value=999),
    minor=st.integers(min_value=0, max_value=999),
)
def test_installed_version_matching_is_exact_and_value_free(
    epoch: int,
    major: int,
    minor: int,
) -> None:
    version = f"{epoch}!{major}.{minor}"
    installed_version = f"{epoch + 1}!{major}.{minor}"

    temporary = TemporaryDirectory()
    root = Path(temporary.name)
    dist_info = root / "property_plugin-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: property-plugin\nVersion: {installed_version}\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        "[milhouse.collectors]\nproperty = property_plugin.collector:Collector\n",
        encoding="utf-8",
    )
    distribution = metadata.PathDistribution(dist_info)

    def finder(_distribution: str) -> Iterable[metadata.Distribution]:
        return (distribution,)

    policy = PluginsConfig.model_validate(
        {
            "allow_third_party": True,
            "allowed": [
                {
                    "distribution": "property-plugin",
                    "version": version,
                    "group": "milhouse.collectors",
                    "entry_point": "property_plugin.collector:Collector",
                }
            ],
        }
    )

    with (
        patch.object(plugin_validation, "_installed_distributions", finder),
        pytest.raises(ConfigError) as captured,
    ):
        plugin_validation.validate_configured_plugins(policy)

    assert captured.value.code == "config.plugins.version_mismatch"
    assert captured.value.message == (
        "plugins.allowed item 1 does not exactly match the installed distribution version"
    )
    temporary.cleanup()
