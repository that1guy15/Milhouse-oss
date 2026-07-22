"""Metadata-only validation for explicitly allowlisted third-party plugins."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from importlib import metadata
from itertools import islice
from pathlib import Path

from milhouse.config._models import (
    MAX_PLUGIN_ALLOWLIST_ENTRIES,
    PluginAllowlistEntry,
    PluginsConfig,
    _validate_plugin_distribution,
    _validate_plugin_entry_point,
    _validate_plugin_version,
)
from milhouse.config.errors import ConfigError

MAX_PLUGIN_CORE_METADATA_BYTES = 128 * 1_024
MAX_PLUGIN_ENTRY_POINT_METADATA_BYTES = 64 * 1_024
MAX_PLUGIN_ENTRY_POINTS_PER_DISTRIBUTION = 1_024

_PLUGIN_GROUPS = frozenset({"milhouse.collectors", "milhouse.notifications", "milhouse.exporters"})
_HEADER_NAME_PATTERN = re.compile(r"[!-9;-~]+", flags=re.ASCII)
_ENTRY_POINT_GROUP_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
    flags=re.ASCII,
)
_ENTRY_POINT_NAME_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
    flags=re.ASCII,
)
_PATH_TYPE = type(Path())
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAGS = _READ_FLAGS | getattr(os, "O_DIRECTORY", 0)


class _FileReadStatus(Enum):
    OK = "ok"
    MISSING = "missing"
    INVALID = "invalid"
    TOO_LARGE = "too_large"


class _DistributionFilesStatus(Enum):
    OK = "ok"
    INVALID = "invalid"
    TOO_LARGE = "too_large"


class _EntryPointsStatus(Enum):
    OK = "ok"
    INVALID = "invalid"
    TOO_MANY = "too_many"


@dataclass(frozen=True, slots=True, repr=False)
class _AllowedPlugin:
    distribution: str
    version: str
    group: str
    entry_point: str


@dataclass(frozen=True, slots=True, repr=False)
class _InstalledEntryPoint:
    group: str
    value: str


@dataclass(frozen=True, slots=True, repr=False)
class _InstalledDistribution:
    name: str
    version: str
    entry_points: tuple[_InstalledEntryPoint, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _FileReadResult:
    status: _FileReadStatus
    contents: bytes = b""


@dataclass(frozen=True, slots=True, repr=False)
class _DistributionFilesResult:
    status: _DistributionFilesStatus
    core_metadata: bytes = b""
    entry_points: bytes = b""


@dataclass(frozen=True, slots=True, repr=False)
class _EntryPointsResult:
    status: _EntryPointsStatus
    entry_points: tuple[_InstalledEntryPoint, ...] = ()


@dataclass(frozen=True, slots=True, repr=False)
class _DirectoryHandle:
    descriptor: int
    snapshot: os.stat_result


def _installed_distributions(distribution: str) -> Iterable[metadata.Distribution]:
    """Return installed distributions matching Python's normalized package-name lookup."""

    return metadata.distributions(name=distribution)


def _plugin_error(code: str, message: str, *, item: int) -> ConfigError:
    return ConfigError(code, f"plugins.allowed item {item} {message}")


def _shared_value_is_valid(validator: Callable[[object], str], value: str) -> bool:
    try:
        validated = validator(value)
    except BaseException:
        return False
    return validated == value


def _snapshot_allowlist(plugins: PluginsConfig) -> tuple[_AllowedPlugin, ...]:
    try:
        allowed = tuple(plugins.allowed)
    except BaseException:
        allowed = ()
        valid = False
    else:
        valid = len(allowed) <= MAX_PLUGIN_ALLOWLIST_ENTRIES
    if not valid:
        raise ConfigError(
            "config.plugins.invalid",
            "plugin allowlist validation failed",
        )

    snapshots: list[_AllowedPlugin] = []
    for entry in allowed:
        if type(entry) is not PluginAllowlistEntry:
            raise ConfigError(
                "config.plugins.invalid",
                "plugin allowlist validation failed",
            )
        try:
            distribution = entry.distribution
            version = entry.version
            group = entry.group
            entry_point = entry.entry_point
        except BaseException:
            fields: tuple[object, ...] = ()
        else:
            fields = (distribution, version, group, entry_point)
        if not all(type(field) is str for field in fields) or len(fields) != 4:
            raise ConfigError(
                "config.plugins.invalid",
                "plugin allowlist validation failed",
            )
        if (
            not _shared_value_is_valid(_validate_plugin_distribution, distribution)
            or not _shared_value_is_valid(_validate_plugin_version, version)
            or group not in _PLUGIN_GROUPS
            or not _shared_value_is_valid(_validate_plugin_entry_point, entry_point)
        ):
            raise ConfigError(
                "config.plugins.invalid",
                "plugin allowlist validation failed",
            )
        snapshots.append(
            _AllowedPlugin(
                distribution=distribution,
                version=version,
                group=group,
                entry_point=entry_point,
            )
        )
    return tuple(snapshots)


def _find_distribution(plugin: _AllowedPlugin, *, item: int) -> metadata.Distribution:
    try:
        candidates = tuple(islice(_installed_distributions(plugin.distribution), 2))
    except BaseException:
        candidates = ()
        discovery_failed = True
    else:
        discovery_failed = False
    if discovery_failed:
        raise _plugin_error(
            "config.plugins.discovery_failed",
            "could not be checked against installed package metadata",
            item=item,
        )
    if not candidates:
        raise _plugin_error(
            "config.plugins.distribution_missing",
            "does not name an installed distribution",
            item=item,
        )
    if len(candidates) != 1:
        raise _plugin_error(
            "config.plugins.distribution_ambiguous",
            "matches more than one installed distribution",
            item=item,
        )
    return candidates[0]


def _same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_mode == right.st_mode
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _close_descriptor(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except BaseException:
        return


def _path_distribution_root(distribution: metadata.Distribution) -> str | None:
    if type(distribution) is not metadata.PathDistribution:
        return None
    try:
        root = distribution._path
    except BaseException:
        return None
    if type(root) is not _PATH_TYPE:
        return None
    path_root = root
    try:
        raw_root = os.fspath(path_root)
        is_absolute = path_root.is_absolute()
    except BaseException:
        return None
    if type(raw_root) is not str or "\x00" in raw_root or not is_absolute:
        return None
    return raw_root


def _open_metadata_directory(root: str) -> _DirectoryHandle | None:
    descriptor: int | None = None
    try:
        before = os.lstat(root)
        if not stat.S_ISDIR(before.st_mode):
            return None
        descriptor = os.open(root, _DIRECTORY_FLAGS)
        opened = os.fstat(descriptor)
    except BaseException:
        if descriptor is not None:
            _close_descriptor(descriptor)
        return None
    if not stat.S_ISDIR(opened.st_mode) or not _same_snapshot(before, opened):
        _close_descriptor(descriptor)
        return None
    return _DirectoryHandle(descriptor=descriptor, snapshot=opened)


def _read_bounded_regular_file(
    directory: _DirectoryHandle,
    filename: str,
    *,
    limit: int,
) -> _FileReadResult:
    descriptor: int | None = None
    try:
        before = os.stat(filename, dir_fd=directory.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return _FileReadResult(_FileReadStatus.MISSING)
    except BaseException:
        return _FileReadResult(_FileReadStatus.INVALID)
    if not stat.S_ISREG(before.st_mode):
        return _FileReadResult(_FileReadStatus.INVALID)
    if before.st_size > limit:
        return _FileReadResult(_FileReadStatus.TOO_LARGE)

    try:
        descriptor = os.open(filename, _READ_FLAGS, dir_fd=directory.descriptor)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_snapshot(before, opened):
            return _FileReadResult(_FileReadStatus.INVALID)

        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1_024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        if len(contents) > limit:
            return _FileReadResult(_FileReadStatus.TOO_LARGE)

        after = os.fstat(descriptor)
        current = os.stat(filename, dir_fd=directory.descriptor, follow_symlinks=False)
        if not _same_snapshot(opened, after) or not _same_snapshot(opened, current):
            return _FileReadResult(_FileReadStatus.INVALID)
    except BaseException:
        return _FileReadResult(_FileReadStatus.INVALID)
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)
    return _FileReadResult(_FileReadStatus.OK, contents)


def _read_distribution_files(
    distribution: metadata.Distribution,
) -> _DistributionFilesResult:
    root = _path_distribution_root(distribution)
    if root is None:
        return _DistributionFilesResult(_DistributionFilesStatus.INVALID)
    directory = _open_metadata_directory(root)
    if directory is None:
        return _DistributionFilesResult(_DistributionFilesStatus.INVALID)

    try:
        core = _read_bounded_regular_file(
            directory,
            "METADATA",
            limit=MAX_PLUGIN_CORE_METADATA_BYTES,
        )
        if core.status is _FileReadStatus.MISSING:
            core = _read_bounded_regular_file(
                directory,
                "PKG-INFO",
                limit=MAX_PLUGIN_CORE_METADATA_BYTES,
            )
        entry_points = _read_bounded_regular_file(
            directory,
            "entry_points.txt",
            limit=MAX_PLUGIN_ENTRY_POINT_METADATA_BYTES,
        )
        try:
            current_directory = os.fstat(directory.descriptor)
        except BaseException:
            current_directory = None
    finally:
        _close_descriptor(directory.descriptor)

    if current_directory is None or not _same_snapshot(directory.snapshot, current_directory):
        return _DistributionFilesResult(_DistributionFilesStatus.INVALID)
    if core.status is _FileReadStatus.TOO_LARGE or entry_points.status is _FileReadStatus.TOO_LARGE:
        return _DistributionFilesResult(_DistributionFilesStatus.TOO_LARGE)
    if core.status is not _FileReadStatus.OK:
        return _DistributionFilesResult(_DistributionFilesStatus.INVALID)
    if entry_points.status is _FileReadStatus.MISSING:
        entry_point_contents = b""
    elif entry_points.status is _FileReadStatus.OK:
        entry_point_contents = entry_points.contents
    else:
        return _DistributionFilesResult(_DistributionFilesStatus.INVALID)
    return _DistributionFilesResult(
        _DistributionFilesStatus.OK,
        core_metadata=core.contents,
        entry_points=entry_point_contents,
    )


def _parse_core_metadata(contents: bytes) -> tuple[str, str] | None:
    try:
        text = contents.decode("utf-8", errors="strict")
    except BaseException:
        return None

    values: dict[str, str] = {}
    previous_key = ""
    for raw_line in text.split("\n"):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if line == "":
            break
        if "\r" in line or "\x00" in line:
            return None
        if line[0] in " \t":
            if previous_key in {"name", "version"}:
                return None
            continue
        key, separator, raw_value = line.partition(":")
        if separator != ":" or _HEADER_NAME_PATTERN.fullmatch(key) is None:
            return None
        previous_key = key.casefold()
        if previous_key not in {"name", "version"}:
            continue
        if previous_key in values:
            return None
        value = raw_value.strip(" \t")
        if not value:
            return None
        values[previous_key] = value

    name = values.get("name")
    version = values.get("version")
    if type(name) is not str or type(version) is not str:
        return None
    if not _shared_value_is_valid(_validate_plugin_distribution, name):
        return None
    if not _shared_value_is_valid(_validate_plugin_version, version):
        return None
    return name, version


def _parse_entry_points(contents: bytes) -> _EntryPointsResult:
    try:
        text = contents.decode("utf-8", errors="strict")
    except BaseException:
        return _EntryPointsResult(_EntryPointsStatus.INVALID)

    current_group: str | None = None
    seen_groups: set[str] = set()
    seen_names: set[tuple[str, str]] = set()
    installed: list[_InstalledEntryPoint] = []
    entry_count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            group = line[1:-1]
            if _ENTRY_POINT_GROUP_PATTERN.fullmatch(group) is None or group in seen_groups:
                return _EntryPointsResult(_EntryPointsStatus.INVALID)
            seen_groups.add(group)
            current_group = group
            continue
        if current_group is None:
            return _EntryPointsResult(_EntryPointsStatus.INVALID)
        name, separator, raw_value = line.partition("=")
        name = name.strip()
        value = raw_value.strip()
        key = (current_group, name)
        if (
            separator != "="
            or _ENTRY_POINT_NAME_PATTERN.fullmatch(name) is None
            or not value
            or key in seen_names
        ):
            return _EntryPointsResult(_EntryPointsStatus.INVALID)
        seen_names.add(key)
        entry_count += 1
        if entry_count > MAX_PLUGIN_ENTRY_POINTS_PER_DISTRIBUTION:
            return _EntryPointsResult(_EntryPointsStatus.TOO_MANY)
        if current_group not in _PLUGIN_GROUPS:
            continue
        if not _shared_value_is_valid(_validate_plugin_entry_point, value):
            return _EntryPointsResult(_EntryPointsStatus.INVALID)
        installed.append(_InstalledEntryPoint(group=current_group, value=value))
    return _EntryPointsResult(_EntryPointsStatus.OK, tuple(installed))


def _read_distribution(
    distribution: metadata.Distribution,
    *,
    item: int,
) -> _InstalledDistribution:
    files = _read_distribution_files(distribution)
    if files.status is not _DistributionFilesStatus.OK:
        raise _plugin_error(
            "config.plugins.metadata_invalid",
            "has invalid installed package metadata",
            item=item,
        )
    core = _parse_core_metadata(files.core_metadata)
    if core is None:
        raise _plugin_error(
            "config.plugins.metadata_invalid",
            "has invalid installed package metadata",
            item=item,
        )
    entry_points = _parse_entry_points(files.entry_points)
    if entry_points.status is _EntryPointsStatus.TOO_MANY:
        raise _plugin_error(
            "config.plugins.metadata_invalid",
            "has too many installed entry points",
            item=item,
        )
    if entry_points.status is not _EntryPointsStatus.OK:
        raise _plugin_error(
            "config.plugins.metadata_invalid",
            "has invalid installed entry-point metadata",
            item=item,
        )
    name, version = core
    return _InstalledDistribution(
        name=name,
        version=version,
        entry_points=entry_points.entry_points,
    )


def _validate_plugin(
    plugin: _AllowedPlugin,
    installed: _InstalledDistribution,
    *,
    item: int,
) -> None:
    if installed.name != plugin.distribution:
        raise _plugin_error(
            "config.plugins.distribution_mismatch",
            "does not exactly match the installed distribution name",
            item=item,
        )
    if installed.version != plugin.version:
        raise _plugin_error(
            "config.plugins.version_mismatch",
            "does not exactly match the installed distribution version",
            item=item,
        )

    matches = sum(
        entry_point.group == plugin.group and entry_point.value == plugin.entry_point
        for entry_point in installed.entry_points
    )
    if matches == 0:
        raise _plugin_error(
            "config.plugins.entry_point_missing",
            "does not exactly match an installed entry point",
            item=item,
        )
    if matches != 1:
        raise _plugin_error(
            "config.plugins.entry_point_ambiguous",
            "matches more than one installed entry point",
            item=item,
        )


def validate_configured_plugins(plugins: PluginsConfig) -> None:
    """Validate every enabled allowlist entry without importing or loading plugin code.

    Disabled or empty third-party policy performs no installed-package metadata reads. Python's
    normalized distribution lookup locates candidates, but acceptance requires one exact raw
    distribution name, version, entry-point group, and object-reference match from bounded,
    path-backed metadata. One immutable installed snapshot is reused per configured distribution.
    W05 runtime loading must revalidate and bind the exact entry-point object it will load so this
    configuration check cannot become a time-of-check/time-of-use grant.
    """

    if type(plugins) is not PluginsConfig:
        raise ConfigError(
            "config.plugins.invalid",
            "plugin allowlist validation failed",
        )
    if plugins.allow_third_party is not True:
        return
    allowlist = _snapshot_allowlist(plugins)
    if not allowlist:
        return

    installed_cache: dict[str, _InstalledDistribution] = {}
    for item, plugin in enumerate(allowlist, start=1):
        installed = installed_cache.get(plugin.distribution)
        if installed is None:
            distribution = _find_distribution(plugin, item=item)
            installed = _read_distribution(distribution, item=item)
            installed_cache[plugin.distribution] = installed
        _validate_plugin(plugin, installed, item=item)


__all__ = [
    "MAX_PLUGIN_CORE_METADATA_BYTES",
    "MAX_PLUGIN_ENTRY_POINTS_PER_DISTRIBUTION",
    "MAX_PLUGIN_ENTRY_POINT_METADATA_BYTES",
    "validate_configured_plugins",
]
