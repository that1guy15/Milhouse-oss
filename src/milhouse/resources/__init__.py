"""Typed access to Milhouse package resources."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import PurePosixPath
from typing import Final

_DISTRIBUTION: Final = "milhouse-observability"
_IMPORT_PACKAGE: Final = "milhouse"
_MANIFEST_VERSION: Final = 1
_MANIFEST_KEYS: Final = frozenset(
    {"manifest_version", "distribution", "import_package", "resources"}
)


class ResourceManifestError(ValueError):
    """Raised when the packaged resource manifest violates its contract."""


def _validate_resource_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ResourceManifestError("resource paths must be non-empty strings")
    if "\\" in value:
        raise ResourceManifestError("resource paths must use POSIX separators")

    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ResourceManifestError("resource paths must be normalized package-relative paths")
    if path.as_posix() != value:
        raise ResourceManifestError("resource paths must be normalized package-relative paths")
    return value


@dataclass(frozen=True, slots=True)
class ResourceManifest:
    """Validated inventory of data shipped inside the ``milhouse`` package."""

    manifest_version: int
    distribution: str
    import_package: str
    resources: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: object) -> ResourceManifest:
        """Validate an untrusted decoded JSON value as the resource manifest."""

        if not isinstance(value, Mapping):
            raise ResourceManifestError("resource manifest must be a JSON object")
        if set(value) != _MANIFEST_KEYS:
            raise ResourceManifestError("resource manifest fields do not match version 1")

        manifest_version = value["manifest_version"]
        if type(manifest_version) is not int or manifest_version != _MANIFEST_VERSION:
            raise ResourceManifestError("unsupported resource manifest version")

        distribution = value["distribution"]
        if distribution != _DISTRIBUTION:
            raise ResourceManifestError("resource manifest distribution does not match Milhouse")

        import_package = value["import_package"]
        if import_package != _IMPORT_PACKAGE:
            raise ResourceManifestError("resource manifest import package does not match Milhouse")

        declared = value["resources"]
        if isinstance(declared, (str, bytes)) or not isinstance(declared, Sequence):
            raise ResourceManifestError("resource manifest resources must be an array")
        resource_paths = tuple(_validate_resource_path(item) for item in declared)
        if not resource_paths:
            raise ResourceManifestError("resource manifest must declare at least one resource")
        if tuple(sorted(set(resource_paths))) != resource_paths:
            raise ResourceManifestError("resource manifest resources must be sorted and unique")

        return cls(
            manifest_version=manifest_version,
            distribution=distribution,
            import_package=import_package,
            resources=resource_paths,
        )


def load_manifest() -> ResourceManifest:
    """Load and validate the manifest using ``importlib.resources``."""

    manifest_file = resources.files(__package__).joinpath("manifest.json")
    try:
        decoded = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResourceManifestError("unable to read the packaged resource manifest") from exc
    return ResourceManifest.from_mapping(decoded)


def read_resource_text(relative_path: str) -> str:
    """Read a declared UTF-8 package resource by its manifest path."""

    validated_path = _validate_resource_path(relative_path)
    manifest = load_manifest()
    if validated_path not in manifest.resources:
        raise ResourceManifestError("resource is not declared in the package manifest")

    target = resources.files(_IMPORT_PACKAGE)
    for part in PurePosixPath(validated_path).parts:
        target = target.joinpath(part)
    try:
        return target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ResourceManifestError("unable to read a declared package resource") from exc


__all__ = [
    "ResourceManifest",
    "ResourceManifestError",
    "load_manifest",
    "read_resource_text",
]
