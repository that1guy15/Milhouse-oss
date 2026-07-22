from __future__ import annotations

import sys
import traceback
from collections.abc import Iterable
from importlib import metadata
from pathlib import Path

import pytest

import milhouse.config.plugins as plugin_validation
from milhouse.config._models import PluginsConfig
from milhouse.config.errors import ConfigError

_DISTRIBUTION = "milhouse-real-metadata-plugin"
_VERSION = "1.2.3"
_GROUP = "milhouse.collectors"
_ENTRY_POINT = "real_metadata_plugin.collector:Collector"


def _policy(
    *,
    distribution: str = _DISTRIBUTION,
    version: str = _VERSION,
    entries: tuple[tuple[str, str], ...] = ((_GROUP, _ENTRY_POINT),),
) -> PluginsConfig:
    return PluginsConfig.model_validate(
        {
            "allow_third_party": True,
            "allowed": [
                {
                    "distribution": distribution,
                    "version": version,
                    "group": group,
                    "entry_point": entry_point,
                }
                for group, entry_point in entries
            ],
        }
    )


def _metadata_bytes(*, name: str = _DISTRIBUTION, version: str = _VERSION) -> bytes:
    return (f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n").encode()


def _entry_point_bytes(
    entries: tuple[tuple[str, str, str], ...] = (("real", _GROUP, _ENTRY_POINT),),
) -> bytes:
    sections: dict[str, list[tuple[str, str]]] = {}
    for name, group, value in entries:
        sections.setdefault(group, []).append((name, value))
    text = "".join(
        f"[{group}]\n" + "".join(f"{name} = {value}\n" for name, value in group_entries)
        for group, group_entries in sections.items()
    )
    return text.encode("utf-8")


def _real_distribution(
    tmp_path: Path,
    *,
    core_metadata: bytes | None = None,
    entry_point_metadata: bytes | None = None,
) -> metadata.PathDistribution:
    dist_info = tmp_path / "milhouse_real_metadata_plugin-1.2.3.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_bytes(
        _metadata_bytes() if core_metadata is None else core_metadata
    )
    (dist_info / "entry_points.txt").write_bytes(
        _entry_point_bytes() if entry_point_metadata is None else entry_point_metadata
    )
    distribution = metadata.PathDistribution(dist_info)
    assert type(distribution) is metadata.PathDistribution
    return distribution


def _install_real_distribution(
    monkeypatch: pytest.MonkeyPatch,
    distribution: metadata.PathDistribution,
) -> list[str]:
    calls: list[str] = []

    def finder(name: str) -> Iterable[metadata.Distribution]:
        calls.append(name)
        return (distribution,)

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)
    return calls


def _assert_value_free_error(
    error: ConfigError,
    *,
    code: str = "config.plugins.metadata_invalid",
    prohibited: tuple[str, ...] = (),
) -> None:
    rendered = "".join(traceback.format_exception(error))
    assert error.code == code
    assert error.message.startswith("plugins.allowed item 1 ")
    for value in (_DISTRIBUTION, _ENTRY_POINT, *prohibited):
        assert value not in rendered
    assert error.__cause__ is None
    assert error.__context__ is None


@pytest.mark.parametrize(
    ("filename", "limit_name", "parsed_property"),
    [
        ("METADATA", "MAX_PLUGIN_CORE_METADATA_BYTES", "metadata"),
        (
            "entry_points.txt",
            "MAX_PLUGIN_ENTRY_POINT_METADATA_BYTES",
            "entry_points",
        ),
    ],
)
def test_real_dist_info_byte_caps_refuse_before_parsed_property_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    limit_name: str,
    parsed_property: str,
) -> None:
    limit = getattr(plugin_validation, limit_name)
    canary = "private-oversized-metadata-canary-314159"
    core_metadata = _metadata_bytes()
    entry_point_metadata = _entry_point_bytes()
    if filename == "METADATA":
        prefix = core_metadata + b"X-Padding: "
        core_metadata = prefix + canary.encode() + b"x" * (limit - len(prefix) + 1)
    else:
        prefix = entry_point_metadata + b"# " + canary.encode() + b"\n"
        entry_point_metadata = prefix + b"#" * (limit - len(prefix) + 1)
    selected = core_metadata if filename == "METADATA" else entry_point_metadata
    assert len(selected) > limit

    distribution = _real_distribution(
        tmp_path,
        core_metadata=core_metadata,
        entry_point_metadata=entry_point_metadata,
    )
    calls = _install_real_distribution(monkeypatch, distribution)
    descriptor = getattr(metadata.PathDistribution, parsed_property)
    parsed_property_accessed = False

    def tracked(self: metadata.PathDistribution) -> object:
        nonlocal parsed_property_accessed
        parsed_property_accessed = True
        return descriptor.__get__(self, type(self))

    monkeypatch.setattr(metadata.PathDistribution, parsed_property, property(tracked))

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(_policy())

    _assert_value_free_error(captured.value, prohibited=(canary,))
    assert parsed_property_accessed is False
    assert calls == [_DISTRIBUTION]


@pytest.mark.parametrize("extra_entries", [0, 1])
def test_real_dist_info_entry_count_cap_has_exact_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra_entries: int,
) -> None:
    count = plugin_validation.MAX_PLUGIN_ENTRY_POINTS_PER_DISTRIBUTION + extra_entries
    entries = tuple((f"entry{index}", _GROUP, f"bounded_plugin:C{index}") for index in range(count))
    entry_point_metadata = _entry_point_bytes(entries)
    assert len(entry_point_metadata) < plugin_validation.MAX_PLUGIN_ENTRY_POINT_METADATA_BYTES
    distribution = _real_distribution(
        tmp_path,
        entry_point_metadata=entry_point_metadata,
    )
    _install_real_distribution(monkeypatch, distribution)
    policy = _policy(entries=((_GROUP, "bounded_plugin:C0"),))

    if extra_entries == 0:
        assert plugin_validation.validate_configured_plugins(policy) is None
    else:
        with pytest.raises(ConfigError) as captured:
            plugin_validation.validate_configured_plugins(policy)
        _assert_value_free_error(captured.value)


def test_real_dist_info_pep440_epoch_matches_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    version = "2!1.4.0"
    distribution = _real_distribution(
        tmp_path,
        core_metadata=_metadata_bytes(version=version),
    )
    _install_real_distribution(monkeypatch, distribution)

    assert plugin_validation.validate_configured_plugins(_policy(version=version)) is None


@pytest.mark.parametrize("configured_version", ["1!1.4.0", "1.4.0"])
def test_real_dist_info_pep440_epoch_drift_is_not_equivalent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configured_version: str,
) -> None:
    installed_version = "2!1.4.0"
    distribution = _real_distribution(
        tmp_path,
        core_metadata=_metadata_bytes(version=installed_version),
    )
    _install_real_distribution(monkeypatch, distribution)

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(_policy(version=configured_version))

    _assert_value_free_error(
        captured.value,
        code="config.plugins.version_mismatch",
        prohibited=(configured_version, installed_version),
    )


@pytest.mark.parametrize(
    "installed_value",
    [
        "private_canary.module",
        "private_canary..module:Collector",
        ".private_canary:Collector",
        "private_canary.module:.Collector",
        "private_canary.module:Collector..factory",
        "private_canary.module:Collector[extra]",
        "private_canary.module:Collector:extra",
    ],
)
def test_real_dist_info_malformed_installed_object_references_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installed_value: str,
) -> None:
    distribution = _real_distribution(
        tmp_path,
        entry_point_metadata=_entry_point_bytes((("malformed", _GROUP, installed_value),)),
    )
    _install_real_distribution(monkeypatch, distribution)

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(_policy())

    _assert_value_free_error(captured.value, prohibited=(installed_value, "private_canary"))


def test_real_dist_info_valid_dotted_object_reference_passes_without_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "synthetic_plugin_pkg.handlers.deep"
    entry_point = f"{module}:Collector.factory"
    sentinel = tmp_path / "plugin-code-imported"
    package = tmp_path / "synthetic_plugin_pkg"
    handlers = package / "handlers"
    handlers.mkdir(parents=True)
    (package / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('package')\n",
        encoding="utf-8",
    )
    (handlers / "__init__.py").write_text("", encoding="utf-8")
    (handlers / "deep.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('module')\n"
        "class Collector:\n"
        "    @staticmethod\n"
        "    def factory():\n"
        "        return None\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    distribution = _real_distribution(
        tmp_path,
        entry_point_metadata=_entry_point_bytes((("dotted", _GROUP, entry_point),)),
    )
    _install_real_distribution(monkeypatch, distribution)

    assert (
        plugin_validation.validate_configured_plugins(_policy(entries=((_GROUP, entry_point),)))
        is None
    )
    assert not sentinel.exists()
    assert all(
        name != "synthetic_plugin_pkg" and not name.startswith("synthetic_plugin_pkg.")
        for name in sys.modules
    )


def test_parsed_only_distribution_backend_is_rejected_value_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "private-unsupported-backend-canary-271828"

    class ParsedOnlyDistribution:
        def __init__(self) -> None:
            self.metadata = {"Name": _DISTRIBUTION, "X-Private": canary}
            self.version = _VERSION
            self.entry_points = (
                metadata.EntryPoint(name="real", value=_ENTRY_POINT, group=_GROUP),
            )

    def finder(_name: str) -> Iterable[metadata.Distribution]:
        return (ParsedOnlyDistribution(),)  # type: ignore[return-value]

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(_policy())

    _assert_value_free_error(captured.value, prohibited=(canary,))


def test_repeated_allowlist_entries_read_one_real_distribution_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = "shared_plugin.collector:Collector"
    exporter = "shared_plugin.exporter:Exporter"
    distribution = _real_distribution(
        tmp_path,
        entry_point_metadata=_entry_point_bytes(
            (
                ("collector", "milhouse.collectors", collector),
                ("exporter", "milhouse.exporters", exporter),
            )
        ),
    )
    calls = _install_real_distribution(monkeypatch, distribution)
    original_reader = plugin_validation._read_distribution_files
    metadata_reads = 0

    def tracked_reader(
        installed: metadata.Distribution,
    ) -> plugin_validation._DistributionFilesResult:
        nonlocal metadata_reads
        metadata_reads += 1
        return original_reader(installed)

    monkeypatch.setattr(plugin_validation, "_read_distribution_files", tracked_reader)

    assert (
        plugin_validation.validate_configured_plugins(
            _policy(
                entries=(
                    ("milhouse.collectors", collector),
                    ("milhouse.exporters", exporter),
                )
            )
        )
        is None
    )
    assert calls == [_DISTRIBUTION]
    assert metadata_reads == 1


def test_malformed_real_core_metadata_diagnostic_is_value_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "private-core-metadata-canary-161803"
    distribution = _real_distribution(
        tmp_path,
        core_metadata=(f"Metadata-Version: 2.1\nName: {canary}\nVersion: not valid\n").encode(),
    )
    _install_real_distribution(monkeypatch, distribution)

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(_policy())

    _assert_value_free_error(captured.value, prohibited=(canary, "not valid"))
