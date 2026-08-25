"""Collector registry: first-party resolution and fail-closed third-party plugin binding (W05).

Covers the registration API with a fake first-party collector, the exact-object third-party plugin
binding that re-validates installed metadata AND binds the concrete entry-point object (closing the
config-time to load-time TOCTOU), and every fail-closed path — unknown, unallowlisted, disabled,
wrong group, and a config-valid-but-since-changed installed entry point. Every failure is a fixed
``RegistryError`` code that never renders a distribution name, object reference, or path.
"""

from __future__ import annotations

import importlib
import importlib.metadata
from pathlib import Path

import pytest
from _runtime_harness import GROUP, canary_config, fake_factory

from milhouse.config._models import PluginAllowlistEntry, PluginsConfig
from milhouse.runtime import Collector, CollectorRegistry
from milhouse.runtime.errors import RegistryError

_DISTRIBUTION = "milhousefakeplugin"
_MODULE = "mh_fake_plugin"
_ENTRY_POINT = f"{_MODULE}:make_collector"

_MODULE_SOURCE = """
from dataclasses import dataclass

from milhouse.domain.records import CollectorDescriptorV1
from milhouse.runtime import CollectorResult


@dataclass
class _PluginCollector:
    descriptor: CollectorDescriptorV1

    def collect(self, context):
        return CollectorResult(status="ok")


def make_collector():
    return _PluginCollector(
        descriptor=CollectorDescriptorV1(
            id="plugin-canary", type="site.canary", implementation_version="9.9.9"
        )
    )
"""


def _install_distribution(
    site: Path, *, version: str = "1.0.0", entry_points: str | None = None
) -> None:
    """Materialize a real, path-backed installed distribution for importlib.metadata to discover."""

    (site / f"{_MODULE}.py").write_text(_MODULE_SOURCE)
    dist_info = site / f"{_DISTRIBUTION}-{version}.dist-info"
    dist_info.mkdir(exist_ok=True)
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {_DISTRIBUTION}\nVersion: {version}\n\n"
    )
    body = entry_points if entry_points is not None else f"[{GROUP}]\nfake = {_ENTRY_POINT}\n"
    (dist_info / "entry_points.txt").write_text(body)


@pytest.fixture
def installed_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install the fake plugin on sys.path and clean the imported module up afterwards."""

    site = tmp_path / "site"
    site.mkdir()
    _install_distribution(site)
    monkeypatch.syspath_prepend(str(site))
    importlib.invalidate_caches()
    monkeypatch.delitem(__import__("sys").modules, _MODULE, raising=False)
    return site


def _entry() -> PluginAllowlistEntry:
    return PluginAllowlistEntry(
        distribution=_DISTRIBUTION, version="1.0.0", group=GROUP, entry_point=_ENTRY_POINT
    )


def _plugins(entry: PluginAllowlistEntry | None = None) -> PluginsConfig:
    return PluginsConfig(allow_third_party=True, allowed=[entry or _entry()])


# --- first-party -------------------------------------------------------------------------------


def test_first_party_resolution_via_the_registration_api() -> None:
    registry = CollectorRegistry()
    registry.register("site_canary", fake_factory(("ok",)))
    assert registry.registered_types == frozenset({"site_canary"})

    collector = registry.resolve(canary_config("canary1"))
    assert isinstance(collector, Collector)
    # The factory bound the configured id into the collector's descriptor.
    assert collector.descriptor.id == "canary1"


def test_duplicate_first_party_registration_fails_closed() -> None:
    registry = CollectorRegistry()
    registry.register("site_canary", fake_factory(("ok",)))
    with pytest.raises(RegistryError) as caught:
        registry.register("site_canary", fake_factory(("ok",)))
    assert caught.value.code == "MH_RUNTIME_REGISTRY_DUPLICATE"


def test_unknown_first_party_type_fails_closed() -> None:
    # No factory registered: a not-yet-implemented collector fails closed, never a crash or skip.
    registry = CollectorRegistry()
    with pytest.raises(RegistryError) as caught:
        registry.resolve(canary_config("canary1"))
    assert caught.value.code == "MH_RUNTIME_COLLECTOR_UNREGISTERED"


def test_a_factory_returning_a_non_collector_fails_closed() -> None:
    registry = CollectorRegistry()
    registry.register("site_canary", lambda config: object())
    with pytest.raises(RegistryError) as caught:
        registry.resolve(canary_config("canary1"))
    assert caught.value.code == "MH_RUNTIME_COLLECTOR_INVALID"


# --- third-party plugin binding ----------------------------------------------------------------


def test_plugin_binding_revalidates_and_binds_the_exact_object(installed_plugin: Path) -> None:
    registry = CollectorRegistry()
    entry = _entry()
    collector = registry.bind_plugin_collector(entry, plugins=_plugins(entry))
    assert isinstance(collector, Collector)
    assert collector.descriptor.id == "plugin-canary"
    assert collector.descriptor.implementation_version == "9.9.9"


def test_plugin_binding_fails_closed_when_the_installed_entry_point_changed(
    installed_plugin: Path,
) -> None:
    # The TOCTOU: configuration validated the allowlist against version 1.0.0 with a specific object
    # reference. Between validation and load the installed entry point is swapped to a different
    # object. Re-validation at bind time binds the EXACT object it will load and fails closed.
    registry = CollectorRegistry()
    entry = _entry()
    plugins = _plugins(entry)
    assert registry.bind_plugin_collector(entry, plugins=plugins).descriptor.id == "plugin-canary"

    _install_distribution(installed_plugin, entry_points=f"[{GROUP}]\nfake = {_MODULE}:other\n")
    importlib.invalidate_caches()
    with pytest.raises(RegistryError) as caught:
        registry.bind_plugin_collector(entry, plugins=plugins)
    assert caught.value.code == "MH_RUNTIME_PLUGIN_REJECTED"


def test_plugin_binding_fails_closed_when_the_installed_version_changed(
    installed_plugin: Path,
) -> None:
    # A distribution whose installed version drifted from the allowlisted one must not be loaded.
    registry = CollectorRegistry()
    entry = _entry()
    plugins = _plugins(entry)
    _install_distribution(installed_plugin, version="2.0.0")
    # Remove the 1.0.0 dist-info so only the changed 2.0.0 remains installed.
    for stale in (installed_plugin / f"{_DISTRIBUTION}-1.0.0.dist-info").iterdir():
        stale.unlink()
    (installed_plugin / f"{_DISTRIBUTION}-1.0.0.dist-info").rmdir()
    importlib.invalidate_caches()
    with pytest.raises(RegistryError) as caught:
        registry.bind_plugin_collector(entry, plugins=plugins)
    assert caught.value.code == "MH_RUNTIME_PLUGIN_REJECTED"


def test_plugin_binding_fails_closed_when_third_party_is_disabled() -> None:
    registry = CollectorRegistry()
    entry = _entry()
    # An allowlist entry requires allow_third_party; construct a disabled config without it.
    plugins = PluginsConfig(allow_third_party=False)
    with pytest.raises(RegistryError) as caught:
        registry.bind_plugin_collector(entry, plugins=plugins)
    assert caught.value.code == "MH_RUNTIME_PLUGIN_DISABLED"


def test_plugin_binding_fails_closed_when_not_allowlisted() -> None:
    registry = CollectorRegistry()
    other = PluginAllowlistEntry(
        distribution="anotherplugin", version="1.0.0", group=GROUP, entry_point="anotherplugin:make"
    )
    plugins = _plugins()  # allowlists only the canonical entry, not ``other``
    with pytest.raises(RegistryError) as caught:
        registry.bind_plugin_collector(other, plugins=plugins)
    assert caught.value.code == "MH_RUNTIME_PLUGIN_NOT_ALLOWLISTED"


def test_plugin_binding_fails_closed_for_a_non_collector_group() -> None:
    registry = CollectorRegistry()
    entry = PluginAllowlistEntry(
        distribution=_DISTRIBUTION,
        version="1.0.0",
        group="milhouse.exporters",
        entry_point=_ENTRY_POINT,
    )
    plugins = _plugins(entry)
    with pytest.raises(RegistryError) as caught:
        registry.bind_plugin_collector(entry, plugins=plugins)
    assert caught.value.code == "MH_RUNTIME_PLUGIN_GROUP"


def test_a_registry_error_never_renders_a_distribution_name_or_path(
    installed_plugin: Path,
) -> None:
    registry = CollectorRegistry()
    entry = _entry()
    plugins = _plugins(entry)
    _install_distribution(installed_plugin, entry_points=f"[{GROUP}]\nfake = {_MODULE}:other\n")
    importlib.invalidate_caches()
    with pytest.raises(RegistryError) as caught:
        registry.bind_plugin_collector(entry, plugins=plugins)
    rendered = f"{caught.value.code}: {caught.value.message}"
    assert _DISTRIBUTION not in rendered
    assert _ENTRY_POINT not in rendered
    assert str(installed_plugin) not in rendered
