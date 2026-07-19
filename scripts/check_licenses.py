#!/usr/bin/env python3
"""Enforce Milhouse license policy against pip-licenses inventory and uv.lock."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, cast

from packaging.markers import InvalidMarker, Marker, default_environment

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_INVENTORY_RECORDS = 10_000
MAX_GRAPH_STATES = 1_024
ROOT_PACKAGE = "milhouse-observability"
INVENTORY_FIELDS = (
    "License-Expression",
    "License-Metadata",
    "License-Classifier",
)
FIELD_CONFIG_KEYS = {
    "License-Expression": "license_expression",
    "License-Metadata": "license_metadata",
    "License-Classifier": "license_classifier",
}
INVENTORY_KEYS = frozenset((*INVENTORY_FIELDS, "Name", "Version"))
POLICY_KEYS = frozenset(
    {
        "policy_version",
        "root_package",
        "unknown_values",
        "forbidden_markers",
        "recognized",
        "artifact_evidence",
        "exceptions",
    }
)
EXPECTED_UNKNOWN_VALUES = frozenset(
    {"", "n/a", "none", "not found", "null", "unknown", "unlicensed"}
)
EXPECTED_FORBIDDEN_MARKERS = frozenset(
    {
        "agpl",
        "gpl",
        "lgpl",
        "gnu affero general public license",
        "gnu general public license",
        "gnu lesser general public license",
    }
)
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
WHEEL_URL = re.compile(r"^https://files\.pythonhosted\.org/[A-Za-z0-9._/+%-]+\.whl$")
METADATA_PATH = re.compile(r"^[A-Za-z0-9._+-]+\.dist-info/METADATA$")
SUPPORTED_PYTHON_MINORS = ("3.11", "3.12", "3.13", "3.14")
SUPPORTED_PLATFORMS = (
    ("darwin", "Darwin", "x86_64"),
    ("darwin", "Darwin", "arm64"),
    ("linux", "Linux", "x86_64"),
    ("linux", "Linux", "aarch64"),
)
WINDOWS_PLATFORMS = (
    ("win32", "Windows", "x86"),
    ("win32", "Windows", "AMD64"),
    ("win32", "Windows", "ARM64"),
)


class LicensePolicyError(RuntimeError):
    """Raised when policy evidence is malformed, incomplete, or prohibited."""


@dataclass(frozen=True)
class LicenseRecord:
    """One normalized pip-licenses record."""

    name: str
    version: str
    values: tuple[str, str, str]


@dataclass(frozen=True)
class ReviewedException:
    """One exact reviewed development-only license exception."""

    name: str
    version: str
    path: tuple[str, ...]
    values: tuple[str, str, str]
    reason: str


@dataclass(frozen=True)
class ArtifactEvidence:
    """License fields extracted from one exact hash-bound locked wheel."""

    name: str
    version: str
    artifact_url: str
    artifact_hash: str
    metadata_path: str
    values: tuple[str, str, str]


@dataclass(frozen=True)
class Policy:
    """Parsed fail-closed policy."""

    unknown_values: frozenset[str]
    forbidden_markers: frozenset[str]
    recognized: Mapping[str, frozenset[str]]
    artifact_evidence: Mapping[str, ArtifactEvidence]
    exceptions: Mapping[str, ReviewedException]


@dataclass(frozen=True)
class Dependency:
    """One uv.lock dependency edge and its selected extras."""

    name: str
    extras: tuple[str, ...]
    marker: str | None


@dataclass(frozen=True)
class LockedPackage:
    """The lock fields needed for closure and exception proof."""

    name: str
    version: str | None
    dependencies: tuple[Dependency, ...]
    optional_dependencies: Mapping[str, tuple[Dependency, ...]]
    dev_dependencies: Mapping[str, tuple[Dependency, ...]]
    wheels: Mapping[str, str]


@dataclass(frozen=True)
class LockData:
    """Strictly parsed lock graph and root dependency groups."""

    packages: Mapping[str, LockedPackage]
    root: LockedPackage


@dataclass(frozen=True)
class Closure:
    """A conservative dependency closure with traversed edges."""

    names: frozenset[str]
    edges: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class InventoryCoverage:
    """Validated host, support-matrix, and excluded lock-member coverage."""

    current_names: frozenset[str]
    supported_names: frozenset[str]
    artifact_names: frozenset[str]
    excluded_windows_names: frozenset[str]


EXPECTED_EXCEPTION_CONTRACTS = {
    "chardet": (
        "5.2.0",
        (ROOT_PACKAGE, "cyclonedx-bom", "chardet"),
        (
            "UNKNOWN",
            "LGPL",
            "GNU Lesser General Public License v2 or later (LGPLv2+)",
        ),
    ),
    "docutils": (
        "0.23",
        (ROOT_PACKAGE, "twine", "readme-renderer", "docutils"),
        (
            "UNKNOWN",
            "UNKNOWN",
            "BSD License; GNU General Public License (GPL); Public Domain",
        ),
    ),
}


def fail(message: str) -> NoReturn:
    """Exit with a bounded diagnostic that never echoes license payload text."""

    print(f"license-policy: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalize_name(name: str) -> str:
    """Normalize a Python distribution name using the PEP 503 rule."""

    return re.sub(r"[-_.]+", "-", name).casefold()


def _marker_environment(
    python_minor: str,
    sys_platform: str,
    platform_system: str,
    platform_machine: str,
) -> dict[str, str]:
    return {
        "implementation_name": "cpython",
        "implementation_version": f"{python_minor}.0",
        "os_name": "nt" if sys_platform == "win32" else "posix",
        "platform_machine": platform_machine,
        "platform_release": "",
        "platform_system": platform_system,
        "platform_version": "",
        "python_full_version": f"{python_minor}.0",
        "platform_python_implementation": "CPython",
        "python_version": python_minor,
        "sys_platform": sys_platform,
        "extra": "",
    }


def _environment_matrix(
    platforms: Sequence[tuple[str, str, str]],
) -> tuple[Mapping[str, str], ...]:
    return tuple(
        _marker_environment(python_minor, *platform)
        for python_minor in SUPPORTED_PYTHON_MINORS
        for platform in platforms
    )


SUPPORTED_ENVIRONMENTS = _environment_matrix(SUPPORTED_PLATFORMS)
WINDOWS_ENVIRONMENTS = _environment_matrix(WINDOWS_PLATFORMS)


def host_environment() -> Mapping[str, str]:
    """Return the current supported marker environment or fail closed."""

    environment = cast(dict[str, str], dict(default_environment()))
    environment["extra"] = ""
    if (
        environment["python_version"] not in SUPPORTED_PYTHON_MINORS
        or environment["sys_platform"] not in {"darwin", "linux"}
        or environment["platform_python_implementation"] != "CPython"
    ):
        raise LicensePolicyError(
            "license inventory must run on supported CPython 3.11-3.14 macOS or Linux"
        )
    return environment


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise LicensePolicyError(f"{label} must be an object with string keys")
    return cast(dict[str, object], value)


def _bounded_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise LicensePolicyError(f"{label} must be a string")
    if (
        (not value and not allow_empty)
        or len(value) > 512
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise LicensePolicyError(f"{label} is empty, oversized, or contains a control character")
    return value


def _string_list(
    value: object,
    label: str,
    *,
    allow_empty_item: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise LicensePolicyError(f"{label} must be a non-empty list")
    strings = tuple(
        _bounded_text(item, f"{label} item", allow_empty=allow_empty_item) for item in value
    )
    if len(strings) != len(set(strings)):
        raise LicensePolicyError(f"{label} must be unique")
    return strings


def _read_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise LicensePolicyError(f"{label} must be a regular, non-symlink file")
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise LicensePolicyError(f"{label} exceeds the 8 MiB safety bound")
        return path.read_bytes()
    except OSError as exc:
        raise LicensePolicyError(f"cannot read {label}") from exc


def _contains_forbidden(value: str, markers: frozenset[str]) -> bool:
    normalized = value.casefold()
    return any(marker in normalized for marker in markers)


def _inventory_values(raw: object, label: str) -> tuple[str, str, str]:
    item = _mapping(raw, label)
    if set(item) != set(FIELD_CONFIG_KEYS.values()):
        raise LicensePolicyError(f"{label} schema is invalid")
    values = tuple(
        _bounded_text(
            item[FIELD_CONFIG_KEYS[field]],
            f"{label} {FIELD_CONFIG_KEYS[field]}",
            allow_empty=True,
        )
        for field in INVENTORY_FIELDS
    )
    return cast(tuple[str, str, str], values)


def load_policy(path: Path) -> Policy:
    """Parse policy TOML and enforce the exact reviewed exception contracts."""

    try:
        document = tomllib.loads(_read_bytes(path, "license policy").decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise LicensePolicyError("license policy is not valid UTF-8 TOML") from exc
    root = _mapping(document, "license policy")
    if set(root) != POLICY_KEYS:
        raise LicensePolicyError("license policy has missing or unknown top-level keys")
    if type(root["policy_version"]) is not int or root["policy_version"] != 1:
        raise LicensePolicyError("license policy version must be exactly 1")
    root_package = _bounded_text(root["root_package"], "license policy root_package")
    if normalize_name(root_package) != ROOT_PACKAGE:
        raise LicensePolicyError("license policy has the wrong root package")

    unknown_values = frozenset(
        item.casefold()
        for item in _string_list(
            root["unknown_values"],
            "license policy unknown_values",
            allow_empty_item=True,
        )
    )
    if unknown_values != EXPECTED_UNKNOWN_VALUES:
        raise LicensePolicyError("license policy unknown markers differ from the reviewed contract")
    forbidden_markers = frozenset(
        item.casefold()
        for item in _string_list(
            root["forbidden_markers"],
            "license policy forbidden_markers",
        )
    )
    if forbidden_markers != EXPECTED_FORBIDDEN_MARKERS:
        raise LicensePolicyError(
            "license policy forbidden markers differ from the reviewed contract"
        )

    raw_recognized = _mapping(root["recognized"], "license policy recognized")
    if set(raw_recognized) != set(FIELD_CONFIG_KEYS.values()):
        raise LicensePolicyError("license policy recognized fields are incomplete or unknown")
    recognized: dict[str, frozenset[str]] = {}
    for inventory_field, config_key in FIELD_CONFIG_KEYS.items():
        recognized_values = frozenset(
            _string_list(raw_recognized[config_key], f"recognized.{config_key}")
        )
        for value in recognized_values:
            if value.casefold() in unknown_values or _contains_forbidden(value, forbidden_markers):
                raise LicensePolicyError(
                    f"recognized.{config_key} contains an unknown or prohibited marker"
                )
        recognized[inventory_field] = recognized_values

    raw_evidence = root["artifact_evidence"]
    if not isinstance(raw_evidence, list):
        raise LicensePolicyError("license policy artifact_evidence must be a list")
    artifact_evidence: dict[str, ArtifactEvidence] = {}
    for index, raw_artifact in enumerate(raw_evidence):
        item = _mapping(raw_artifact, f"artifact evidence {index}")
        if set(item) != {
            "name",
            "version",
            "artifact_url",
            "artifact_hash",
            "metadata_path",
            "inventory",
        }:
            raise LicensePolicyError("artifact evidence has missing or unknown keys")
        raw_name = _bounded_text(item["name"], "artifact evidence name")
        if not SAFE_NAME.fullmatch(raw_name):
            raise LicensePolicyError("artifact evidence name is invalid")
        name = normalize_name(raw_name)
        version = _bounded_text(item["version"], f"artifact evidence {name} version")
        url = _bounded_text(item["artifact_url"], f"artifact evidence {name} URL")
        artifact_hash = _bounded_text(item["artifact_hash"], f"artifact evidence {name} hash")
        metadata_path = _bounded_text(
            item["metadata_path"], f"artifact evidence {name} metadata path"
        )
        metadata_identity = metadata_path.removesuffix(".dist-info/METADATA")
        metadata_name, separator, metadata_version = metadata_identity.rpartition("-")
        if (
            not SAFE_VERSION.fullmatch(version)
            or not WHEEL_URL.fullmatch(url)
            or not SHA256.fullmatch(artifact_hash)
            or not METADATA_PATH.fullmatch(metadata_path)
            or not separator
            or normalize_name(metadata_name) != name
            or metadata_version != version
        ):
            raise LicensePolicyError(f"artifact evidence {name} identity is invalid")
        if name in artifact_evidence:
            raise LicensePolicyError(f"artifact evidence {name} is duplicated")
        artifact_evidence[name] = ArtifactEvidence(
            name=name,
            version=version,
            artifact_url=url,
            artifact_hash=artifact_hash,
            metadata_path=metadata_path,
            values=_inventory_values(item["inventory"], f"artifact evidence {name} inventory"),
        )

    raw_exceptions = root["exceptions"]
    if not isinstance(raw_exceptions, list):
        raise LicensePolicyError("license policy exceptions must be a list")
    exceptions: dict[str, ReviewedException] = {}
    for index, raw_exception in enumerate(raw_exceptions):
        item = _mapping(raw_exception, f"license exception {index}")
        if set(item) != {"name", "version", "path", "reason", "inventory"}:
            raise LicensePolicyError("license exception has missing or unknown keys")
        raw_name = _bounded_text(item["name"], "license exception name")
        if not SAFE_NAME.fullmatch(raw_name):
            raise LicensePolicyError("license exception name is invalid")
        name = normalize_name(raw_name)
        version = _bounded_text(item["version"], f"license exception {name} version")
        if not SAFE_VERSION.fullmatch(version):
            raise LicensePolicyError(f"license exception {name} version is invalid")
        raw_path = _string_list(item["path"], f"license exception {name} path")
        dependency_path = tuple(normalize_name(part) for part in raw_path)
        reason = _bounded_text(item["reason"], f"license exception {name} reason")
        if name in exceptions:
            raise LicensePolicyError(f"license exception {name} is duplicated")
        exception = ReviewedException(
            name=name,
            version=version,
            path=dependency_path,
            values=_inventory_values(item["inventory"], f"license exception {name} inventory"),
            reason=reason,
        )
        exceptions[name] = exception

    if set(exceptions) != set(EXPECTED_EXCEPTION_CONTRACTS):
        raise LicensePolicyError("license policy must contain exactly the reviewed exceptions")
    for name, (
        version,
        dependency_path,
        expected_values,
    ) in EXPECTED_EXCEPTION_CONTRACTS.items():
        exception = exceptions[name]
        if (
            exception.version != version
            or exception.path != dependency_path
            or exception.values != expected_values
        ):
            raise LicensePolicyError(f"license exception {name} differs from its reviewed contract")

    policy = Policy(
        unknown_values=unknown_values,
        forbidden_markers=forbidden_markers,
        recognized=recognized,
        artifact_evidence=artifact_evidence,
        exceptions=exceptions,
    )
    for evidence in artifact_evidence.values():
        _validate_license_values(
            evidence.name,
            evidence.values,
            policy,
            source="artifact evidence",
        )
    return policy


def load_inventory(path: Path) -> tuple[LicenseRecord, ...]:
    """Parse exact pip-licenses --from=all --format=json output."""

    try:
        value = json.loads(_read_bytes(path, "license inventory").decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LicensePolicyError("license inventory is not valid UTF-8 JSON") from exc
    if not isinstance(value, list) or not value or len(value) > MAX_INVENTORY_RECORDS:
        raise LicensePolicyError("license inventory must be a non-empty bounded list")
    records: dict[str, LicenseRecord] = {}
    for index, raw_record in enumerate(value):
        item = _mapping(raw_record, f"license inventory record {index}")
        if set(item) != INVENTORY_KEYS:
            raise LicensePolicyError(
                "license inventory schema must match pip-licenses --from=all --format=json"
            )
        raw_name = _bounded_text(item["Name"], f"license inventory record {index} name")
        if not SAFE_NAME.fullmatch(raw_name):
            raise LicensePolicyError("license inventory contains an invalid package name")
        name = normalize_name(raw_name)
        version = _bounded_text(item["Version"], f"license inventory {name} version")
        if not SAFE_VERSION.fullmatch(version):
            raise LicensePolicyError(f"license inventory {name} has an invalid version")
        values = tuple(
            _bounded_text(
                item[field],
                f"license inventory {name} {field}",
                allow_empty=True,
            )
            for field in INVENTORY_FIELDS
        )
        record = LicenseRecord(
            name=name,
            version=version,
            values=cast(tuple[str, str, str], values),
        )
        previous = records.get(name)
        if previous is not None and previous != record:
            raise LicensePolicyError(f"license inventory has conflicting entries for {name}")
        records[name] = record
    return tuple(records[name] for name in sorted(records))


def _parse_dependency(raw: object, label: str) -> Dependency:
    item = _mapping(raw, label)
    if not set(item).issubset({"name", "marker", "extra"}) or "name" not in item:
        raise LicensePolicyError(f"{label} has unsupported lock fields")
    raw_name = _bounded_text(item["name"], f"{label} name")
    if not SAFE_NAME.fullmatch(raw_name):
        raise LicensePolicyError(f"{label} has an invalid name")
    name = normalize_name(raw_name)
    raw_marker = item.get("marker")
    marker: str | None = None
    if raw_marker is not None:
        marker = _bounded_text(raw_marker, f"{label} marker")
        try:
            Marker(marker)
        except InvalidMarker as exc:
            raise LicensePolicyError(f"{label} marker is invalid") from exc
    raw_extras = item.get("extra", [])
    if not isinstance(raw_extras, list):
        raise LicensePolicyError(f"{label} extra must be a list")
    extras = tuple(_bounded_text(extra, f"{label} extra item") for extra in raw_extras)
    if len(extras) != len(set(extras)):
        raise LicensePolicyError(f"{label} extras must be unique")
    return Dependency(name=name, extras=tuple(sorted(extras)), marker=marker)


def _parse_dependency_list(raw: object, label: str) -> tuple[Dependency, ...]:
    if not isinstance(raw, list):
        raise LicensePolicyError(f"{label} must be a list")
    dependencies = tuple(
        _parse_dependency(item, f"{label} item {index}") for index, item in enumerate(raw)
    )
    identities = tuple(
        (dependency.name, dependency.extras, dependency.marker) for dependency in dependencies
    )
    if len(identities) != len(set(identities)):
        raise LicensePolicyError(f"{label} contains duplicate dependencies")
    return dependencies


def _parse_dependency_groups(raw: object, label: str) -> dict[str, tuple[Dependency, ...]]:
    groups = _mapping(raw, label)
    parsed: dict[str, tuple[Dependency, ...]] = {}
    for group_name, dependencies in groups.items():
        _bounded_text(group_name, f"{label} group name")
        parsed[group_name] = _parse_dependency_list(dependencies, f"{label}.{group_name}")
    return parsed


def _parse_wheels(raw: object, label: str) -> dict[str, str]:
    if not isinstance(raw, list) or not raw:
        raise LicensePolicyError(f"{label} must be a non-empty list")
    wheels: dict[str, str] = {}
    for index, value in enumerate(raw):
        item = _mapping(value, f"{label} item {index}")
        if set(item) != {"url", "hash", "size", "upload-time"}:
            raise LicensePolicyError(f"{label} item has missing or unknown fields")
        url = _bounded_text(item["url"], f"{label} URL")
        artifact_hash = _bounded_text(item["hash"], f"{label} hash")
        _bounded_text(item["upload-time"], f"{label} upload-time")
        size = item["size"]
        if (
            not WHEEL_URL.fullmatch(url)
            or not SHA256.fullmatch(artifact_hash)
            or type(size) is not int
            or size <= 0
        ):
            raise LicensePolicyError(f"{label} contains invalid artifact metadata")
        if url in wheels or artifact_hash in wheels.values():
            raise LicensePolicyError(f"{label} contains a duplicate artifact")
        wheels[url] = artifact_hash
    return wheels


def load_lock(path: Path) -> LockData:
    """Parse the uv lock graph strictly enough to prove dependency closures and paths."""

    try:
        document = tomllib.loads(_read_bytes(path, "uv lock").decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise LicensePolicyError("uv lock is not valid UTF-8 TOML") from exc
    root_document = _mapping(document, "uv lock")
    if set(root_document) != {
        "version",
        "revision",
        "requires-python",
        "resolution-markers",
        "package",
    }:
        raise LicensePolicyError("uv lock has missing or unknown top-level fields")
    if type(root_document["version"]) is not int or root_document["version"] != 1:
        raise LicensePolicyError("uv lock schema version must be exactly 1")
    if type(root_document["revision"]) is not int or root_document["revision"] != 3:
        raise LicensePolicyError("uv lock revision must be exactly 3")
    _bounded_text(root_document["requires-python"], "uv lock requires-python")
    resolution_markers = root_document["resolution-markers"]
    if not isinstance(resolution_markers, list) or not resolution_markers:
        raise LicensePolicyError("uv lock resolution-markers must be a non-empty list")
    for marker in resolution_markers:
        _bounded_text(marker, "uv lock resolution marker")

    raw_packages = root_document["package"]
    if not isinstance(raw_packages, list) or not raw_packages:
        raise LicensePolicyError("uv lock package must be a non-empty list")
    packages: dict[str, LockedPackage] = {}
    root_source: object | None = None
    for index, raw_package in enumerate(raw_packages):
        item = _mapping(raw_package, f"uv lock package {index}")
        raw_name = _bounded_text(item.get("name"), f"uv lock package {index} name")
        if not SAFE_NAME.fullmatch(raw_name):
            raise LicensePolicyError("uv lock contains an invalid package name")
        name = normalize_name(raw_name)
        raw_version = item.get("version")
        version: str | None
        if raw_version is None:
            version = None
        else:
            version = _bounded_text(raw_version, f"uv lock package {name} version")
            if not SAFE_VERSION.fullmatch(version):
                raise LicensePolicyError(f"uv lock package {name} has an invalid version")
        dependencies = _parse_dependency_list(
            item.get("dependencies", []), f"uv lock package {name} dependencies"
        )
        optional_dependencies = _parse_dependency_groups(
            item.get("optional-dependencies", {}),
            f"uv lock package {name} optional-dependencies",
        )
        dev_dependencies = _parse_dependency_groups(
            item.get("dev-dependencies", {}),
            f"uv lock package {name} dev-dependencies",
        )
        wheels = (
            {}
            if name == ROOT_PACKAGE
            else _parse_wheels(item.get("wheels"), f"uv lock package {name} wheels")
        )
        if name in packages:
            raise LicensePolicyError(f"uv lock package {name} is duplicated")
        packages[name] = LockedPackage(
            name=name,
            version=version,
            dependencies=dependencies,
            optional_dependencies=optional_dependencies,
            dev_dependencies=dev_dependencies,
            wheels=wheels,
        )
        if name == ROOT_PACKAGE:
            root_source = item.get("source")

    root = packages.get(ROOT_PACKAGE)
    if root is None:
        raise LicensePolicyError("uv lock is missing the Milhouse root package")
    if root.version is not None or root_source != {"editable": "."}:
        raise LicensePolicyError("uv lock root must be the unversioned editable Milhouse package")
    if set(root.optional_dependencies) != {"receiver"}:
        raise LicensePolicyError("uv lock root must contain exactly the receiver optional group")
    if set(root.dev_dependencies) != {"dev"}:
        raise LicensePolicyError("uv lock root must contain exactly the dev dependency group")
    for package in packages.values():
        if package.name != ROOT_PACKAGE and package.version is None:
            raise LicensePolicyError(f"uv lock package {package.name} is missing its version")
        if package.name != ROOT_PACKAGE and package.dev_dependencies:
            raise LicensePolicyError(
                f"uv lock package {package.name} unexpectedly defines dev dependencies"
            )
        for dependency in package.dependencies:
            _validate_dependency_reference(packages, dependency, package.name)
        for group_name, dependencies in package.optional_dependencies.items():
            for dependency in dependencies:
                _validate_dependency_reference(
                    packages, dependency, f"{package.name}[{group_name}]"
                )
        for group_name, dependencies in package.dev_dependencies.items():
            for dependency in dependencies:
                _validate_dependency_reference(packages, dependency, f"{package.name}:{group_name}")
    return LockData(packages=packages, root=root)


def _validate_dependency_reference(
    packages: Mapping[str, LockedPackage], dependency: Dependency, parent: str
) -> None:
    target = packages.get(dependency.name)
    if target is None:
        raise LicensePolicyError(f"uv lock dependency from {parent} has no package entry")
    missing_extras = set(dependency.extras) - set(target.optional_dependencies)
    if missing_extras:
        raise LicensePolicyError(f"uv lock dependency from {parent} selects an unavailable extra")


def dependency_closure(
    lock: LockData,
    initial: Sequence[Dependency],
    environment: Mapping[str, str] | None,
) -> Closure:
    """Traverse one marker environment; ``None`` deliberately includes every edge."""

    pending: deque[tuple[str, Dependency]] = deque(
        (ROOT_PACKAGE, dependency) for dependency in initial
    )
    names = {ROOT_PACKAGE}
    edges: set[tuple[str, str]] = set()
    processed_base: set[str] = set()
    processed_extras: defaultdict[str, set[str]] = defaultdict(set)
    while pending:
        parent, dependency = pending.popleft()
        if dependency.marker is not None and environment is not None:
            if not Marker(dependency.marker).evaluate(environment=dict(environment)):
                continue
        package = lock.packages.get(dependency.name)
        if package is None:
            raise LicensePolicyError("uv lock traversal reached a missing package")
        names.add(package.name)
        edges.add((parent, package.name))
        if package.name not in processed_base:
            processed_base.add(package.name)
            pending.extend((package.name, child) for child in package.dependencies)
        for extra in dependency.extras:
            if extra in processed_extras[package.name]:
                continue
            group = package.optional_dependencies.get(extra)
            if group is None:
                raise LicensePolicyError("uv lock traversal reached a missing optional group")
            processed_extras[package.name].add(extra)
            pending.extend((package.name, child) for child in group)
    return Closure(names=frozenset(names), edges=frozenset(edges))


def _matrix_closures(
    lock: LockData,
    initial: Sequence[Dependency],
    environments: Sequence[Mapping[str, str]],
) -> tuple[Closure, ...]:
    return tuple(dependency_closure(lock, initial, environment) for environment in environments)


def _union_closures(closures: Sequence[Closure]) -> Closure:
    return Closure(
        names=frozenset().union(*(closure.names for closure in closures)),
        edges=frozenset().union(*(closure.edges for closure in closures)),
    )


def _dependency_paths(closure: Closure, target: str) -> frozenset[tuple[str, ...]]:
    adjacency: defaultdict[str, set[str]] = defaultdict(set)
    for parent, child in closure.edges:
        adjacency[parent].add(child)
    paths: set[tuple[str, ...]] = set()
    pending: deque[tuple[str, tuple[str, ...]]] = deque([(ROOT_PACKAGE, (ROOT_PACKAGE,))])
    traversed = 0
    while pending:
        if traversed == MAX_GRAPH_STATES:
            raise LicensePolicyError("uv lock graph exceeds the exception traversal bound")
        node, path = pending.popleft()
        traversed += 1
        if node == target:
            paths.add(path)
            continue
        pending.extend(
            (child, (*path, child)) for child in sorted(adjacency[node]) if child not in path
        )
    return frozenset(paths)


def validate_exception_graph(lock: LockData, policy: Policy) -> None:
    """Prove exact dev-only paths and absence from root runtime plus receiver closure."""

    runtime_initial = (*lock.root.dependencies, *lock.root.optional_dependencies["receiver"])
    all_initial = (*runtime_initial, *lock.root.dev_dependencies["dev"])
    runtime_closure = dependency_closure(lock, runtime_initial, None)
    all_closure = dependency_closure(lock, all_initial, None)
    for exception in policy.exceptions.values():
        package = lock.packages.get(exception.name)
        if package is None or package.version != exception.version:
            raise LicensePolicyError(f"reviewed exception {exception.name} has lock version drift")
        if exception.name in runtime_closure.names:
            raise LicensePolicyError(
                f"reviewed exception {exception.name} is reachable from runtime or receiver"
            )
        paths = _dependency_paths(all_closure, exception.name)
        if paths != {exception.path}:
            raise LicensePolicyError(
                f"reviewed exception {exception.name} has dependency path drift"
            )


def _validate_license_values(
    name: str,
    values: tuple[str, str, str],
    policy: Policy,
    *,
    source: str,
    version: str | None = None,
) -> None:
    forbidden = any(_contains_forbidden(value, policy.forbidden_markers) for value in values)
    exception = policy.exceptions.get(name)
    if forbidden:
        if (
            source != "license inventory"
            or exception is None
            or version != exception.version
            or values != exception.values
        ):
            raise LicensePolicyError(f"{source} package {name} has an unreviewed copyleft marker")
        return
    known_fields = 0
    for field, value in zip(INVENTORY_FIELDS, values, strict=True):
        if value.casefold() in policy.unknown_values:
            continue
        known_fields += 1
        if value not in policy.recognized[field]:
            raise LicensePolicyError(f"{source} package {name} has an unrecognized {field}")
    if known_fields == 0:
        raise LicensePolicyError(f"{source} package {name} has only unknown license data")


def _coverage_closures(
    lock: LockData,
) -> tuple[Closure, frozenset[str], Closure, Closure]:
    initial = (
        *lock.root.dependencies,
        *lock.root.optional_dependencies["receiver"],
        *lock.root.dev_dependencies["dev"],
    )
    matrix = _matrix_closures(lock, initial, SUPPORTED_ENVIRONMENTS)
    supported = _union_closures(matrix)
    always = frozenset.intersection(*(closure.names for closure in matrix))
    conservative = dependency_closure(lock, initial, None)
    windows = _union_closures(_matrix_closures(lock, initial, WINDOWS_ENVIRONMENTS))
    return supported, always, conservative, windows


def validate_inventory(
    inventory: Sequence[LicenseRecord],
    lock: LockData,
    policy: Policy,
    *,
    environment: Mapping[str, str] | None = None,
) -> InventoryCoverage:
    """Bind inventory and artifact evidence to the host and supported lock closures."""

    validate_exception_graph(lock, policy)
    supported, always, conservative, windows = _coverage_closures(lock)
    locked_names = frozenset(lock.packages)
    if conservative.names != locked_names:
        raise LicensePolicyError("uv lock contains package entries unreachable from the root")
    excluded = conservative.names - supported.names
    if not excluded.issubset(windows.names):
        raise LicensePolicyError("uv lock excludes a package that is not Windows-only")

    conditional = supported.names - always
    evidence_names = frozenset(policy.artifact_evidence)
    if evidence_names != conditional:
        raise LicensePolicyError(
            "artifact evidence must exactly cover conditionally supported lock packages"
        )
    for evidence in policy.artifact_evidence.values():
        locked = lock.packages[evidence.name]
        if (
            locked.version != evidence.version
            or locked.wheels.get(evidence.artifact_url) != evidence.artifact_hash
        ):
            raise LicensePolicyError(
                f"artifact evidence package {evidence.name} differs from uv.lock"
            )
        _validate_license_values(
            evidence.name,
            evidence.values,
            policy,
            source="artifact evidence",
        )

    current = dependency_closure(
        lock,
        (
            *lock.root.dependencies,
            *lock.root.optional_dependencies["receiver"],
            *lock.root.dev_dependencies["dev"],
        ),
        environment or host_environment(),
    )
    if not current.names.issubset(supported.names):
        raise LicensePolicyError("current host closure differs from the supported platform matrix")
    records = {record.name: record for record in inventory}
    missing = current.names - records.keys()
    extra = records.keys() - current.names
    if missing:
        raise LicensePolicyError(
            "license inventory is incomplete; use pip-licenses --from=all "
            "--format=json --with-system"
        )
    if extra:
        raise LicensePolicyError("license inventory contains a package outside the current closure")
    for record in inventory:
        locked = lock.packages[record.name]
        if record.name != ROOT_PACKAGE and locked.version != record.version:
            raise LicensePolicyError(
                f"license inventory package {record.name} version differs from uv.lock"
            )
        _validate_license_values(
            record.name,
            record.values,
            policy,
            source="license inventory",
            version=record.version,
        )
    return InventoryCoverage(
        current_names=current.names,
        supported_names=supported.names,
        artifact_names=evidence_names,
        excluded_windows_names=excluded,
    )


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inventory",
        type=Path,
        required=True,
        help="JSON emitted by pip-licenses --from=all --format=json --with-system",
    )
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("config/license-policy.toml"),
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        policy = load_policy(args.policy)
        lock = load_lock(args.lock)
        inventory = load_inventory(args.inventory)
        coverage = validate_inventory(inventory, lock, policy)
    except LicensePolicyError as exc:
        fail(str(exc))
    print(
        f"license-policy: {len(inventory)} package(s) passed; "
        f"{len(policy.exceptions)} reviewed dev-only exception(s), "
        f"{len(coverage.artifact_names)} conditional artifact record(s), and "
        f"{len(coverage.excluded_windows_names)} Windows-only lock member(s) verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
