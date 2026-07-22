from __future__ import annotations

import traceback
from collections.abc import Iterable
from importlib import metadata
from pathlib import Path

import pytest

import milhouse.config.plugins as plugin_validation
from milhouse.config._models import PluginsConfig
from milhouse.config.errors import ConfigError

_DISTRIBUTION = "example-plugin"
_VERSION = "1.2.3"
_GROUP = "milhouse.collectors"
_VALUE = "example_plugin.collector:Collector"


class _Distribution:
    def __init__(
        self,
        *,
        name: object = _DISTRIBUTION,
        version: object = _VERSION,
        entry_points: object = (),
    ) -> None:
        self._name = name
        self._version = version
        self._entry_points = entry_points

    @property
    def metadata(self) -> object:
        return {"Name": self._name}

    @property
    def version(self) -> object:
        return self._version

    @property
    def entry_points(self) -> object:
        return self._entry_points


def _entry_point(
    *,
    name: str = "example",
    value: str = _VALUE,
    group: str = _GROUP,
) -> metadata.EntryPoint:
    return metadata.EntryPoint(name=name, value=value, group=group)


def _real_distribution(
    tmp_path: Path,
    *,
    directory_name: str = "example_plugin-1.2.3.dist-info",
    name: str = _DISTRIBUTION,
    version: str = _VERSION,
    entry_points: tuple[metadata.EntryPoint, ...] = (),
    entry_points_text: str | None = None,
) -> metadata.PathDistribution:
    dist_info = tmp_path / directory_name
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        encoding="utf-8",
    )
    if entry_points_text is None:
        grouped: dict[str, list[metadata.EntryPoint]] = {}
        for entry_point in entry_points:
            grouped.setdefault(entry_point.group, []).append(entry_point)
        entry_points_text = "".join(
            f"[{group}]\n"
            + "".join(
                f"{entry_point.name} = {entry_point.value}\n"
                for entry_point in grouped_entry_points
            )
            for group, grouped_entry_points in grouped.items()
        )
    (dist_info / "entry_points.txt").write_text(entry_points_text, encoding="utf-8")
    distribution = metadata.PathDistribution(dist_info)
    assert type(distribution) is metadata.PathDistribution
    return distribution


def _plugins(
    *,
    allow_third_party: bool = True,
    distribution: str = _DISTRIBUTION,
    version: str = _VERSION,
    group: str = _GROUP,
    entry_point: str = _VALUE,
) -> PluginsConfig:
    allowed: list[dict[str, object]] = []
    if allow_third_party:
        allowed.append(
            {
                "distribution": distribution,
                "version": version,
                "group": group,
                "entry_point": entry_point,
            }
        )
    return PluginsConfig.model_validate(
        {"allow_third_party": allow_third_party, "allowed": allowed}
    )


def _set_distributions(
    monkeypatch: pytest.MonkeyPatch,
    values: Iterable[object],
) -> list[str]:
    calls: list[str] = []

    def finder(distribution: str) -> Iterable[metadata.Distribution]:
        calls.append(distribution)
        return values  # type: ignore[return-value]

    monkeypatch.setattr(plugin_validation, "_installed_distributions", finder)
    return calls


@pytest.mark.parametrize(
    "plugins",
    [
        PluginsConfig.model_validate({"allow_third_party": False, "allowed": []}),
        PluginsConfig.model_validate({"allow_third_party": True, "allowed": []}),
    ],
)
def test_disabled_or_empty_policy_reads_no_installed_metadata(
    plugins: PluginsConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(_distribution: str) -> Iterable[metadata.Distribution]:
        raise AssertionError("disabled plugin policy read installed metadata")

    monkeypatch.setattr(plugin_validation, "_installed_distributions", forbidden)

    assert plugin_validation.validate_configured_plugins(plugins) is None


def test_exact_installed_metadata_match_is_accepted_without_loading_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = _real_distribution(tmp_path, entry_points=(_entry_point(),))
    calls = _set_distributions(monkeypatch, (installed,))

    def forbidden_load(_entry_point: metadata.EntryPoint) -> object:
        raise AssertionError("plugin validation loaded code")

    monkeypatch.setattr(metadata.EntryPoint, "load", forbidden_load)

    assert plugin_validation.validate_configured_plugins(_plugins()) is None
    assert calls == [_DISTRIBUTION]


def test_default_distribution_lookup_delegates_only_the_configured_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = _Distribution(entry_points=(_entry_point(),))
    calls: list[dict[str, str]] = []

    def distributions(**kwargs: str) -> Iterable[metadata.Distribution]:
        calls.append(kwargs)
        return (sentinel,)  # type: ignore[return-value]

    monkeypatch.setattr(metadata, "distributions", distributions)

    assert tuple(plugin_validation._installed_distributions(_DISTRIBUTION)) == (sentinel,)
    assert calls == [{"name": _DISTRIBUTION}]


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("missing", "config.plugins.distribution_missing"),
        ("ambiguous_distribution", "config.plugins.distribution_ambiguous"),
        ("name_mismatch", "config.plugins.distribution_mismatch"),
        ("version_mismatch", "config.plugins.version_mismatch"),
        ("entry_point_missing", "config.plugins.entry_point_missing"),
        ("entry_point_ambiguous", "config.plugins.entry_point_ambiguous"),
    ],
)
def test_metadata_mismatches_are_refused_with_stable_value_free_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    code: str,
) -> None:
    canary = "private-package-canary-314159"
    if case == "missing":
        installed: tuple[object, ...] = ()
    elif case == "ambiguous_distribution":
        installed = (
            _real_distribution(
                tmp_path,
                directory_name="example_plugin_first-1.2.3.dist-info",
                entry_points=(_entry_point(),),
            ),
            _real_distribution(
                tmp_path,
                directory_name="example_plugin_second-1.2.3.dist-info",
                entry_points=(_entry_point(),),
            ),
        )
    elif case == "name_mismatch":
        installed = (
            _real_distribution(
                tmp_path,
                name="Example-Plugin",
                entry_points=(_entry_point(),),
            ),
        )
    elif case == "version_mismatch":
        installed = (
            _real_distribution(
                tmp_path,
                version="1.2.4",
                entry_points=(_entry_point(),),
            ),
        )
    elif case == "entry_point_missing":
        installed = (
            _real_distribution(
                tmp_path,
                entry_points=(_entry_point(value="other.module:Plugin"),),
            ),
        )
    else:
        assert case == "entry_point_ambiguous"
        installed = (
            _real_distribution(
                tmp_path,
                entry_points=(
                    _entry_point(name="first"),
                    _entry_point(name="second"),
                ),
            ),
        )
    _set_distributions(monkeypatch, installed)

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(
            _plugins(distribution=_DISTRIBUTION, entry_point=_VALUE)
        )

    assert captured.value.code == code
    assert "plugins.allowed item 1" in captured.value.message
    assert canary not in str(captured.value)
    assert _DISTRIBUTION not in str(captured.value)
    assert _VALUE not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_unrelated_entry_point_groups_are_not_interpreted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = _real_distribution(
        tmp_path,
        entry_points_text=(
            "[another.application]\n"
            "private = not an object reference and must stay uninterpreted\n"
            f"[{_GROUP}]\n"
            f"example = {_VALUE}\n"
        ),
    )
    _set_distributions(monkeypatch, (installed,))

    assert plugin_validation.validate_configured_plugins(_plugins()) is None


def test_discovery_failure_drops_hostile_exception_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "private-discovery-canary-271828"

    class HostileFailure(Exception):
        def __str__(self) -> str:
            return canary

        __repr__ = __str__

    def broken(_distribution: str) -> Iterable[metadata.Distribution]:
        raise HostileFailure(canary)

    monkeypatch.setattr(plugin_validation, "_installed_distributions", broken)

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(_plugins())

    assert captured.value.code == "config.plugins.discovery_failed"
    assert canary not in "".join(traceback.format_exception(captured.value))
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    "status",
    [
        plugin_validation._DistributionFilesStatus.INVALID,
        plugin_validation._DistributionFilesStatus.TOO_LARGE,
    ],
)
def test_invalid_distribution_file_results_are_normalized(
    monkeypatch: pytest.MonkeyPatch,
    status: plugin_validation._DistributionFilesStatus,
) -> None:
    monkeypatch.setattr(
        plugin_validation,
        "_read_distribution_files",
        lambda _distribution: plugin_validation._DistributionFilesResult(status),
    )

    with pytest.raises(ConfigError) as captured:
        plugin_validation._read_distribution(_Distribution(), item=1)  # type: ignore[arg-type]

    assert captured.value.code == "config.plugins.metadata_invalid"
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    "contents",
    [
        b"",
        b"Name: example-plugin\n",
        b"Version: 1.2.3\n",
        b"Name: ../invalid\nVersion: 1.2.3\n",
        b"Name: example-plugin\nVersion: invalid version\n",
    ],
)
def test_malformed_core_metadata_is_refused(
    contents: bytes,
) -> None:
    assert plugin_validation._parse_core_metadata(contents) is None


def test_invalid_policy_object_is_refused_before_metadata_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(_distribution: str) -> Iterable[metadata.Distribution]:
        raise AssertionError("invalid policy reached metadata discovery")

    monkeypatch.setattr(plugin_validation, "_installed_distributions", forbidden)

    with pytest.raises(ConfigError, match=r"config\.plugins\.invalid"):
        plugin_validation.validate_configured_plugins(object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("distribution", "../unsafe"),
        ("version", "version with spaces"),
        ("version", object()),
        ("group", "milhouse.unknown"),
        ("entry_point", "not-an-entry-point"),
    ],
)
def test_mutated_allowlist_fields_are_revalidated_before_metadata_access(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    plugins = _plugins()
    setattr(plugins.allowed[0], field, value)

    def forbidden(_distribution: str) -> Iterable[metadata.Distribution]:
        raise AssertionError("invalid mutated policy reached metadata discovery")

    monkeypatch.setattr(plugin_validation, "_installed_distributions", forbidden)

    with pytest.raises(ConfigError, match=r"config\.plugins\.invalid"):
        plugin_validation.validate_configured_plugins(plugins)


def test_unreadable_mutated_allowlist_is_refused_without_metadata_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenAllowed:
        def __bool__(self) -> bool:
            return True

        def __iter__(self) -> Iterable[object]:
            raise RuntimeError("private-allowlist-canary-314159")

    plugins = _plugins()
    plugins.allowed = BrokenAllowed()  # type: ignore[assignment]

    def forbidden(_distribution: str) -> Iterable[metadata.Distribution]:
        raise AssertionError("unreadable allowlist reached metadata discovery")

    monkeypatch.setattr(plugin_validation, "_installed_distributions", forbidden)

    with pytest.raises(ConfigError, match=r"config\.plugins\.invalid") as captured:
        plugin_validation.validate_configured_plugins(plugins)

    assert captured.value.__context__ is None


def test_unreadable_allowlist_entry_is_refused_without_retaining_its_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "private-entry-canary-271828"

    class BrokenEntry:
        @property
        def distribution(self) -> str:
            raise RuntimeError(canary)

    plugins = _plugins()
    plugins.allowed = [BrokenEntry()]  # type: ignore[list-item]
    monkeypatch.setattr(plugin_validation, "PluginAllowlistEntry", BrokenEntry)

    with pytest.raises(ConfigError, match=r"config\.plugins\.invalid") as captured:
        plugin_validation.validate_configured_plugins(plugins)

    assert canary not in "".join(traceback.format_exception(captured.value))
    assert captured.value.__context__ is None


def test_mutated_allowlist_length_is_revalidated_before_metadata_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugins = _plugins()
    plugins.allowed = plugins.allowed * 129

    def forbidden(_distribution: str) -> Iterable[metadata.Distribution]:
        raise AssertionError("oversized mutated policy reached metadata discovery")

    monkeypatch.setattr(plugin_validation, "_installed_distributions", forbidden)

    with pytest.raises(ConfigError, match=r"config\.plugins\.invalid"):
        plugin_validation.validate_configured_plugins(plugins)


def test_mutated_allowlist_rejects_foreign_entries_before_reading_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugins = _plugins()
    plugins.allowed = [object()]  # type: ignore[list-item]

    def forbidden(_distribution: str) -> Iterable[metadata.Distribution]:
        raise AssertionError("foreign allowlist item reached metadata discovery")

    monkeypatch.setattr(plugin_validation, "_installed_distributions", forbidden)

    with pytest.raises(ConfigError, match=r"config\.plugins\.invalid"):
        plugin_validation.validate_configured_plugins(plugins)


def test_installed_entry_point_inventory_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry_points = tuple(
        _entry_point(name=f"entry-{index}", value=f"plugin_{index}:Collector")
        for index in range(plugin_validation.MAX_PLUGIN_ENTRY_POINTS_PER_DISTRIBUTION + 1)
    )
    _set_distributions(
        monkeypatch,
        (_real_distribution(tmp_path, entry_points=entry_points),),
    )

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(_plugins())

    assert captured.value.code == "config.plugins.metadata_invalid"
    assert captured.value.message == "plugins.allowed item 1 has too many installed entry points"


@pytest.mark.parametrize(
    "contents",
    [
        b"entry = module:Collector\n",
        b"[bad group]\nentry = module:Collector\n",
        b"[milhouse.collectors]\nmissing-equals\n",
        b"[milhouse.collectors]\nentry = module..bad:Collector\n",
    ],
)
def test_invalid_entry_point_metadata_shapes_are_refused(
    contents: bytes,
) -> None:
    result = plugin_validation._parse_entry_points(contents)

    assert result.status is plugin_validation._EntryPointsStatus.INVALID


def test_distribution_discovery_stops_after_ambiguity_is_proven(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def candidates() -> Iterable[metadata.Distribution]:
        yield _Distribution(entry_points=(_entry_point(),))  # type: ignore[misc]
        yield _Distribution(entry_points=(_entry_point(),))  # type: ignore[misc]
        raise AssertionError("validator read beyond the ambiguity bound")

    monkeypatch.setattr(
        plugin_validation,
        "_installed_distributions",
        lambda _distribution: candidates(),
    )

    with pytest.raises(ConfigError) as captured:
        plugin_validation.validate_configured_plugins(_plugins())

    assert captured.value.code == "config.plugins.distribution_ambiguous"
