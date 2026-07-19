#!/usr/bin/env python3
"""Verify wheel/sdist inventory, hashes, and isolated installed behavior."""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import BinaryIO, NoReturn

from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet

if __package__:
    from .run_uv import candidate_uv, uv_environment, verify_uv
else:
    from run_uv import (  # type: ignore[import-not-found, no-redef]
        candidate_uv,
        uv_environment,
        verify_uv,
    )


DISTRIBUTION = "milhouse-observability"
IMPORT_PACKAGE = "milhouse"
EXPECTED_CONSOLE_SCRIPTS = {"milhouse": "milhouse.cli:main"}
MAX_MEMBERS = 10_000
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
REQUIRED_PACKAGE_FILES = {
    "milhouse/__init__.py",
    "milhouse/__main__.py",
    "milhouse/cli/__init__.py",
    "milhouse/cli/__main__.py",
    "milhouse/cli/root.py",
    "milhouse/py.typed",
    "milhouse/resources/__init__.py",
    "milhouse/resources/manifest.json",
}
WHEEL_METADATA_FILES = {
    "METADATA",
    "RECORD",
    "WHEEL",
    "entry_points.txt",
    "licenses/LICENSE",
    "top_level.txt",
}
SDIST_ROOT_FILES = {
    "CHANGELOG.md",
    "LICENSE",
    "MANIFEST.in",
    "PKG-INFO",
    "README.md",
    "pyproject.toml",
    "setup.cfg",
}
SDIST_EGG_INFO_FILES = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "requires.txt",
    "top_level.txt",
}
FORBIDDEN_PARTS = {
    ".env",
    ".git",
    ".github",
    ".milhouse",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "backups",
    "logs",
    "spool",
}


class ArtifactError(RuntimeError):
    """Raised for unsafe, inconsistent, or nonfunctional distributions."""


class _EntryPointParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


@dataclass(frozen=True)
class Inventory:
    path: Path
    kind: str
    names: frozenset[str]
    name: str
    version: str
    metadata: tuple[tuple[str, tuple[str, ...]], ...]
    description_bytes: bytes
    license_bytes: bytes
    console_scripts: tuple[tuple[str, str], ...]
    package_files: dict[str, bytes]
    resources: dict[str, bytes]
    sdist_files: dict[str, bytes]


@dataclass(frozen=True)
class SourceInventory:
    name: str
    version: str
    metadata: tuple[tuple[str, tuple[str, ...]], ...]
    description_bytes: bytes
    license_bytes: bytes
    console_scripts: tuple[tuple[str, str], ...]
    package_files: dict[str, bytes]
    resources: dict[str, bytes]
    sdist_files: dict[str, bytes]


@dataclass(frozen=True)
class PinnedArtifact:
    """Private immutable snapshot of one public artifact candidate."""

    source_path: Path
    path: Path
    digest: str
    source_info: os.stat_result


def fail(message: str) -> NoReturn:
    print(f"artifacts: {message}", file=sys.stderr)
    raise SystemExit(1)


def _digest(stream: BinaryIO) -> str:
    result = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        result.update(chunk)
    return result.hexdigest()


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return _digest(stream)


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int):
        raise ArtifactError("descriptor-safe artifact operations are unavailable")
    return value


def _artifact_source_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_NONBLOCK")
    )


def _artifact_destination_flags() -> int:
    return (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NOFOLLOW")
    )


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_uid,
        left.st_gid,
        left.st_nlink,
        stat.S_IFMT(left.st_mode),
        stat.S_IMODE(left.st_mode),
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_uid,
        right.st_gid,
        right.st_nlink,
        stat.S_IFMT(right.st_mode),
        stat.S_IMODE(right.st_mode),
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise ArtifactError("artifact snapshot write made no progress")
        remaining = remaining[written:]


def _descriptor_digest(descriptor: int) -> tuple[str, int]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _copy_descriptor(source: int, destination: int) -> tuple[str, int]:
    os.lseek(source, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while chunk := os.read(source, 1024 * 1024):
        _write_all(destination, chunk)
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _pin_artifact(path: Path, destination_directory: Path) -> PinnedArtifact:
    """Copy a stable non-symlink artifact into a private descriptor-verified snapshot."""

    source_path = path.absolute()
    source_fd = destination_fd = destination_directory_fd = -1
    destination_created = False
    snapshot_valid = False
    copied_digest = ""
    source_info: os.stat_result | None = None
    destination_path = destination_directory / source_path.name
    try:
        try:
            destination_directory.mkdir(mode=0o700)
        except FileExistsError:
            directory_info = os.stat(destination_directory, follow_symlinks=False)
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != os.geteuid()
                or stat.S_IMODE(directory_info.st_mode) & 0o077
            ):
                raise ArtifactError("artifact snapshot directory is unsafe") from None

        directory_named = os.stat(destination_directory, follow_symlinks=False)
        destination_directory_fd = os.open(
            destination_directory,
            os.O_RDONLY
            | _required_flag("O_DIRECTORY")
            | _required_flag("O_NOFOLLOW")
            | _required_flag("O_CLOEXEC"),
        )
        directory_info = os.fstat(destination_directory_fd)
        if (
            not _same_file_snapshot(directory_named, directory_info)
            or not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or stat.S_IMODE(directory_info.st_mode) & 0o077
        ):
            raise ArtifactError("artifact snapshot directory is unsafe")

        source_fd = os.open(source_path, _artifact_source_flags())
        before = os.fstat(source_fd)
        source_info = before
        named_before = os.stat(source_path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file_snapshot(before, named_before)
            or before.st_size > MAX_EXPANDED_BYTES
        ):
            raise ArtifactError("artifact source is not a stable bounded regular file")

        destination_fd = os.open(
            source_path.name,
            _artifact_destination_flags(),
            0o600,
            dir_fd=destination_directory_fd,
        )
        destination_created = True
        copied_digest, copied_size = _copy_descriptor(source_fd, destination_fd)
        os.fsync(destination_fd)
        os.fchmod(destination_fd, 0o600)
        destination_info = os.fstat(destination_fd)
        destination_digest, destination_size = _descriptor_digest(destination_fd)

        verified_digest, verified_size = _descriptor_digest(source_fd)
        after = os.fstat(source_fd)
        named_after = os.stat(source_path, follow_symlinks=False)
        if (
            not _same_file_snapshot(before, after)
            or not _same_file_snapshot(after, named_after)
            or copied_size != before.st_size
            or verified_size != before.st_size
            or copied_digest != verified_digest
        ):
            raise ArtifactError("artifact source changed while it was being pinned")
        if (
            not stat.S_ISREG(destination_info.st_mode)
            or destination_info.st_nlink != 1
            or destination_info.st_size != copied_size
            or stat.S_IMODE(destination_info.st_mode) != 0o600
            or destination_size != copied_size
            or destination_digest != copied_digest
        ):
            raise ArtifactError("private artifact snapshot could not be verified")
        snapshot_valid = True
    except ArtifactError:
        raise
    except OSError as exc:
        raise ArtifactError("artifact could not be pinned safely") from exc
    finally:
        for descriptor in (destination_fd, source_fd):
            if descriptor >= 0:
                os.close(descriptor)
        if destination_created and not snapshot_valid and destination_directory_fd >= 0:
            try:
                os.unlink(source_path.name, dir_fd=destination_directory_fd)
            except OSError:
                pass
        if destination_directory_fd >= 0:
            os.close(destination_directory_fd)
    if source_info is None or not copied_digest:  # pragma: no cover - success invariant
        raise ArtifactError("private artifact snapshot could not be verified")
    return PinnedArtifact(source_path, destination_path, copied_digest, source_info)


def _verify_pinned_source(artifact: PinnedArtifact) -> None:
    descriptor = -1
    try:
        descriptor = os.open(artifact.source_path, _artifact_source_flags())
        before = os.fstat(descriptor)
        named = os.stat(artifact.source_path, follow_symlinks=False)
        digest, size = _descriptor_digest(descriptor)
        after = os.fstat(descriptor)
        named_after = os.stat(artifact.source_path, follow_symlinks=False)
        if (
            not _same_file_snapshot(before, artifact.source_info)
            or not _same_file_snapshot(before, named)
            or not _same_file_snapshot(before, after)
            or not _same_file_snapshot(after, named_after)
            or size != artifact.source_info.st_size
            or digest != artifact.digest
        ):
            raise ArtifactError("public artifact changed after it was pinned")
    except ArtifactError:
        raise
    except OSError as exc:
        raise ArtifactError("public artifact could not be reverified") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _inventory_signature(artifact: Inventory) -> tuple[object, ...]:
    return (
        artifact.kind,
        artifact.names,
        artifact.name,
        artifact.version,
        artifact.metadata,
        artifact.description_bytes,
        artifact.license_bytes,
        artifact.console_scripts,
        artifact.package_files,
        artifact.resources,
        artifact.sdist_files,
    )


def _require_inventory_parity(public: Inventory, pinned: Inventory) -> None:
    if _inventory_signature(public) != _inventory_signature(pinned):
        raise ArtifactError(f"{public.kind} private snapshot does not match public inventory")


def _safe_name(raw_name: str) -> PurePosixPath:
    if not raw_name or "\\" in raw_name or "\x00" in raw_name:
        raise ArtifactError("archive contains an unsafe member name")
    name = PurePosixPath(raw_name)
    if name.is_absolute() or any(part in {"", ".", ".."} for part in name.parts):
        raise ArtifactError(f"archive contains unsafe path {raw_name!r}")
    if any(part in FORBIDDEN_PARTS or part.endswith((".pyc", ".pyo")) for part in name.parts):
        raise ArtifactError(f"archive contains prohibited path {raw_name!r}")
    return name


def _metadata(
    raw: bytes,
    label: str,
) -> tuple[str, str, tuple[tuple[str, tuple[str, ...]], ...], bytes]:
    message = BytesParser(policy=default).parsebytes(raw)
    if message.defects or message.is_multipart():
        raise ArtifactError(f"{label} has malformed or multipart core metadata")
    name = message.get("Name")
    version = message.get("Version")
    if not isinstance(name, str) or name.casefold().replace("_", "-") != DISTRIBUTION:
        raise ArtifactError(f"{label} has the wrong distribution name")
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version):
        raise ArtifactError(f"{label} has an invalid version")
    fields: dict[str, list[str]] = {}
    for field, value in message.raw_items():
        normalized_field = field.casefold()
        normalized_value = str(value).strip()
        if not normalized_field or not normalized_value:
            raise ArtifactError(f"{label} has an empty core metadata header")
        fields.setdefault(normalized_field, []).append(normalized_value)
    payload = message.get_payload(decode=True)
    if not isinstance(payload, bytes):
        raise ArtifactError(f"{label} has a non-text metadata description")
    metadata = tuple((field, tuple(sorted(values))) for field, values in sorted(fields.items()))
    return name, version, metadata, payload


def _manifest_resources(raw: bytes, label: str) -> tuple[str, ...]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"{label} has an invalid resource manifest") from exc
    if not isinstance(value, dict) or set(value) != {
        "distribution",
        "import_package",
        "manifest_version",
        "resources",
    }:
        raise ArtifactError(f"{label} resource manifest has the wrong schema")
    if type(value["manifest_version"]) is not int or value["manifest_version"] != 1:
        raise ArtifactError(f"{label} resource manifest has an unsupported version")
    if value["distribution"] != DISTRIBUTION or value["import_package"] != IMPORT_PACKAGE:
        raise ArtifactError(f"{label} resource manifest identity mismatch")
    resources = value["resources"]
    if (
        not isinstance(resources, list)
        or not resources
        or not all(isinstance(item, str) for item in resources)
    ):
        raise ArtifactError(f"{label} resource manifest requires string resources")
    typed = tuple(resources)
    if typed != tuple(sorted(set(typed))):
        raise ArtifactError(f"{label} resource manifest must be sorted and unique")
    for item in typed:
        if not item or "\\" in item or "\x00" in item:
            raise ArtifactError(f"{label} resource manifest contains an unsafe path")
        path = PurePosixPath(item)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != item
        ):
            raise ArtifactError(f"{label} resource manifest contains an unsafe path")
    return typed


def _console_scripts(raw: bytes, label: str) -> tuple[tuple[str, str], ...]:
    parser = _EntryPointParser(interpolation=None, strict=True)
    try:
        parser.read_string(raw.decode("utf-8"))
    except (UnicodeError, configparser.Error) as exc:
        raise ArtifactError(f"{label} has invalid console entry-point metadata") from exc
    if set(parser.sections()) != {"console_scripts"}:
        raise ArtifactError(f"{label} must contain only the console_scripts entry-point group")
    scripts = dict(parser.items("console_scripts", raw=True))
    if scripts != EXPECTED_CONSOLE_SCRIPTS:
        raise ArtifactError(f"{label} console scripts must be exactly {EXPECTED_CONSOLE_SCRIPTS!r}")
    return tuple(sorted(scripts.items()))


def _read_regular(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ArtifactError(f"{label} must be a regular, non-symlink file")
    if path.stat().st_size > MAX_EXPANDED_BYTES:
        raise ArtifactError(f"{label} exceeds the safety bound")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ArtifactError(f"cannot read {label}: {exc}") from exc


def _source_version(raw: bytes) -> str:
    try:
        module = ast.parse(raw.decode("utf-8"), filename="src/milhouse/__init__.py")
    except (SyntaxError, UnicodeError) as exc:
        raise ArtifactError("source version module is not valid UTF-8 Python") from exc
    versions: list[str] = []
    for statement in module.body:
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "__version__"
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            versions.append(statement.value.value)
    if len(versions) != 1 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", versions[0]):
        raise ArtifactError("source package must contain one literal valid __version__")
    return versions[0]


def _project_string(project: dict[str, object], key: str) -> str:
    value = project.get(key)
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value:
        raise ArtifactError(f"source pyproject project.{key} must be a nonempty string")
    return value


def _project_string_list(project: dict[str, object], key: str) -> tuple[str, ...]:
    value = project.get(key)
    if (
        not isinstance(value, list)
        or not all(isinstance(item, str) and item for item in value)
        or len(value) != len(set(value))
    ):
        raise ArtifactError(f"source pyproject project.{key} must be a unique string list")
    return tuple(value)


def _normalized_requirement(raw: str, *, extra: str | None = None) -> str:
    try:
        requirement = Requirement(raw)
        if extra is not None:
            extra_marker = Marker(f'extra == "{extra}"')
            requirement.marker = (
                Marker(f"({requirement.marker}) and ({extra_marker})")
                if requirement.marker is not None
                else extra_marker
            )
    except (InvalidRequirement, ValueError) as exc:
        raise ArtifactError("source pyproject contains an invalid dependency requirement") from exc
    return str(requirement)


def _source_core_metadata(
    project: dict[str, object],
    version: str,
    readme_bytes: bytes,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Derive the complete core-metadata contract from the PEP 621 source."""

    name = _project_string(project, "name")
    if name.casefold().replace("_", "-") != DISTRIBUTION:
        raise ArtifactError("source pyproject has the wrong distribution name")
    if project.get("readme") != "README.md":
        raise ArtifactError("source pyproject readme must be exactly README.md")
    if project.get("license") != "Apache-2.0":
        raise ArtifactError("source pyproject license must be exactly Apache-2.0")
    license_files = _project_string_list(project, "license-files")
    if license_files != ("LICENSE",):
        raise ArtifactError("source pyproject license-files must be exactly LICENSE")
    dynamic = _project_string_list(project, "dynamic")
    if dynamic != ("version",):
        raise ArtifactError("source pyproject dynamic metadata must be exactly version")
    authors = project.get("authors")
    if (
        not isinstance(authors, list)
        or len(authors) != 1
        or not isinstance(authors[0], dict)
        or set(authors[0]) != {"name"}
        or not isinstance(authors[0]["name"], str)
        or not authors[0]["name"]
    ):
        raise ArtifactError("source pyproject authors must contain exactly one named author")
    author = authors[0]["name"]

    raw_urls = project.get("urls")
    if (
        not isinstance(raw_urls, dict)
        or not raw_urls
        or not all(
            isinstance(label, str) and label and isinstance(url, str) and url
            for label, url in raw_urls.items()
        )
    ):
        raise ArtifactError("source pyproject project.urls must be a nonempty string mapping")
    urls = tuple(f"{label}, {url}" for label, url in raw_urls.items())
    classifiers = _project_string_list(project, "classifiers")
    dependencies = tuple(
        _normalized_requirement(value) for value in _project_string_list(project, "dependencies")
    )
    raw_optional = project.get("optional-dependencies")
    if not isinstance(raw_optional, dict) or not raw_optional:
        raise ArtifactError("source pyproject optional-dependencies must be a nonempty mapping")
    optional: list[str] = []
    extras: list[str] = []
    for extra, values in raw_optional.items():
        if not isinstance(extra, str) or not extra or not isinstance(values, list):
            raise ArtifactError("source pyproject optional-dependencies has an invalid group")
        extras.append(extra)
        if not all(isinstance(value, str) and value for value in values):
            raise ArtifactError("source pyproject optional-dependencies requires strings")
        optional.extend(_normalized_requirement(value, extra=extra) for value in values)
    try:
        requires_python = str(SpecifierSet(_project_string(project, "requires-python")))
    except InvalidSpecifier as exc:
        raise ArtifactError("source pyproject requires-python is invalid") from exc
    if not readme_bytes:
        raise ArtifactError("source README.md must not be empty")

    fields: dict[str, tuple[str, ...]] = {
        "author": (author,),
        "classifier": classifiers,
        "description-content-type": ("text/markdown",),
        # Setuptools 83 emits this backend-derived field for PEP 639 license-files.
        "dynamic": ("license-file",),
        "license-expression": ("Apache-2.0",),
        "license-file": license_files,
        "metadata-version": ("2.4",),
        "name": (name,),
        "project-url": urls,
        "provides-extra": tuple(extras),
        "requires-dist": (*dependencies, *optional),
        "requires-python": (requires_python,),
        "summary": (_project_string(project, "description"),),
        "version": (version,),
    }
    return tuple(
        (field, tuple(sorted(values))) for field, values in sorted(fields.items()) if values
    )


def inspect_source(repo_root: Path) -> SourceInventory:
    """Build the explicit source allowlist used for artifact parity."""

    package_root = repo_root / "src" / IMPORT_PACKAGE
    if package_root.is_symlink() or not package_root.is_dir():
        raise ArtifactError("source import package must be a regular directory")
    manifest_path = package_root / "resources" / "manifest.json"
    manifest_raw = _read_regular(manifest_path, "source resource manifest")
    declared = _manifest_resources(manifest_raw, "source")
    declared_package_paths = {f"{IMPORT_PACKAGE}/{item}" for item in declared}

    package_files: dict[str, bytes] = {}
    for candidate in sorted(package_root.rglob("*")):
        relative = candidate.relative_to(repo_root / "src")
        if "__pycache__" in relative.parts or candidate.suffix in {".pyc", ".pyo"}:
            continue
        if candidate.is_symlink():
            raise ArtifactError(f"source package contains symlink {relative.as_posix()!r}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise ArtifactError(f"source package contains special file {relative.as_posix()!r}")
        name = relative.as_posix()
        allowed = candidate.suffix == ".py" or name == f"{IMPORT_PACKAGE}/py.typed"
        if not allowed and name not in declared_package_paths:
            raise ArtifactError(f"source package contains undeclared file {name!r}")
        package_files[name] = _read_regular(candidate, f"source package file {name!r}")

    missing = REQUIRED_PACKAGE_FILES - package_files.keys()
    if missing:
        raise ArtifactError(
            "source package is missing required files: " + ", ".join(sorted(missing))
        )
    undeclared = declared_package_paths - package_files.keys()
    if undeclared:
        raise ArtifactError(
            "source manifest declares missing files: " + ", ".join(sorted(undeclared))
        )
    resources = {relative: package_files[f"{IMPORT_PACKAGE}/{relative}"] for relative in declared}

    sdist_files = {
        name: _read_regular(repo_root / name, f"source file {name!r}")
        for name in SDIST_ROOT_FILES - {"PKG-INFO", "setup.cfg"}
    }
    try:
        pyproject = tomllib.loads(sdist_files["pyproject.toml"].decode("utf-8"))
        project = pyproject["project"]
        if not isinstance(project, dict):
            raise TypeError
        name = project["name"]
        raw_scripts = project["scripts"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ArtifactError("source pyproject has invalid project metadata") from exc
    if not isinstance(name, str) or name.casefold().replace("_", "-") != DISTRIBUTION:
        raise ArtifactError("source pyproject has the wrong distribution name")
    if not isinstance(raw_scripts, dict) or raw_scripts != EXPECTED_CONSOLE_SCRIPTS:
        raise ArtifactError(
            f"source pyproject console scripts must be exactly {EXPECTED_CONSOLE_SCRIPTS!r}"
        )
    version = _source_version(package_files[f"{IMPORT_PACKAGE}/__init__.py"])
    description_bytes = sdist_files["README.md"]
    metadata = _source_core_metadata(project, version, description_bytes)
    return SourceInventory(
        name,
        version,
        metadata,
        description_bytes,
        sdist_files["LICENSE"],
        tuple(sorted(raw_scripts.items())),
        package_files,
        resources,
        sdist_files,
    )


def _verify_wheel_record(
    archive: zipfile.ZipFile,
    file_names: set[str],
    dist_info: str,
) -> None:
    record_name = f"{dist_info}/RECORD"
    try:
        text = archive.read(record_name).decode("utf-8")
        rows = tuple(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (KeyError, UnicodeError, csv.Error) as exc:
        raise ArtifactError("wheel RECORD is missing or malformed") from exc
    if not rows or any(len(row) != 3 for row in rows):
        raise ArtifactError("wheel RECORD rows must contain exactly three fields")
    records: dict[str, tuple[str, str]] = {}
    for raw_name, digest, size in rows:
        name = _safe_name(raw_name).as_posix()
        if name in records:
            raise ArtifactError(f"wheel RECORD duplicates {name!r}")
        records[name] = (digest, size)
    if set(records) != file_names:
        raise ArtifactError("wheel RECORD inventory does not exactly match ZIP files")
    for name, (digest, size) in records.items():
        if name == record_name:
            if digest or size:
                raise ArtifactError("wheel RECORD self-row must have blank hash and size")
            continue
        content = archive.read(name)
        expected_digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
        if digest != f"sha256={expected_digest.decode('ascii')}":
            raise ArtifactError(f"wheel RECORD sha256 mismatch for {name!r}")
        if size != str(len(content)):
            raise ArtifactError(f"wheel RECORD size mismatch for {name!r}")


def inspect_wheel(path: Path) -> Inventory:
    if path.is_symlink() or not path.is_file() or not path.name.endswith("-py3-none-any.whl"):
        raise ArtifactError("wheel must be a regular universal py3-none-any artifact")
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > MAX_MEMBERS:
                raise ArtifactError("wheel member count is outside the safety bound")
            if sum(item.file_size for item in entries) > MAX_EXPANDED_BYTES:
                raise ArtifactError("wheel expanded size exceeds the safety bound")
            names: set[str] = set()
            file_names: set[str] = set()
            for item in entries:
                name = _safe_name(item.filename).as_posix().rstrip("/")
                if name in names:
                    raise ArtifactError(f"wheel contains duplicate member {name!r}")
                names.add(name)
                if not item.is_dir():
                    file_names.add(name)
                mode = item.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    raise ArtifactError("wheel contains a symbolic link")
            metadata_names = [name for name in file_names if name.endswith(".dist-info/METADATA")]
            entry_names = [
                name for name in file_names if name.endswith(".dist-info/entry_points.txt")
            ]
            license_names = [
                name for name in file_names if name.endswith(".dist-info/licenses/LICENSE")
            ]
            if len(metadata_names) != 1 or len(entry_names) != 1 or not license_names:
                raise ArtifactError(
                    "wheel metadata, entry point, or LICENSE inventory is incomplete"
                )
            dist_info = metadata_names[0].rsplit("/", 1)[0]
            _verify_wheel_record(archive, file_names, dist_info)
            name, version, metadata, description_bytes = _metadata(
                archive.read(metadata_names[0]), "wheel"
            )
            license_bytes = archive.read(license_names[0])
            console_scripts = _console_scripts(archive.read(entry_names[0]), "wheel")
            missing = REQUIRED_PACKAGE_FILES - file_names
            if missing:
                raise ArtifactError(
                    "wheel is missing package resources: " + ", ".join(sorted(missing))
                )
            manifest_raw = archive.read("milhouse/resources/manifest.json")
            declared = _manifest_resources(manifest_raw, "wheel")
            resources: dict[str, bytes] = {}
            for relative in declared:
                member = f"milhouse/{relative}"
                if member not in file_names:
                    raise ArtifactError(f"wheel is missing declared resource {relative!r}")
                resources[relative] = archive.read(member)
            package_files = {
                member: archive.read(member)
                for member in sorted(file_names)
                if member.startswith(f"{IMPORT_PACKAGE}/")
            }
            allowed_package_files = {
                member
                for member in package_files
                if member.endswith(".py") or member == f"{IMPORT_PACKAGE}/py.typed"
            } | {f"{IMPORT_PACKAGE}/{relative}" for relative in declared}
            if set(package_files) != allowed_package_files:
                extra = sorted(set(package_files) - allowed_package_files)
                raise ArtifactError("wheel contains undeclared package files: " + ", ".join(extra))
            expected_files = set(package_files) | {
                f"{dist_info}/{relative}" for relative in WHEEL_METADATA_FILES
            }
            if file_names != expected_files:
                extra = sorted(file_names - expected_files)
                missing_inventory = sorted(expected_files - file_names)
                details = []
                if extra:
                    details.append("unexpected " + ", ".join(extra))
                if missing_inventory:
                    details.append("missing " + ", ".join(missing_inventory))
                raise ArtifactError("wheel inventory mismatch: " + "; ".join(details))
            return Inventory(
                path,
                "wheel",
                frozenset(file_names),
                name,
                version,
                metadata,
                description_bytes,
                license_bytes,
                console_scripts,
                package_files,
                resources,
                {},
            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArtifactError(f"cannot inspect wheel: {exc}") from exc


def _bounded_sdist_members(
    archive: tarfile.TarFile,
    *,
    extraction: bool,
) -> Iterator[tuple[tarfile.TarInfo, PurePosixPath]]:
    """Yield safe streamed members after one shared count, size, path, and type policy."""

    label = "sdist extraction" if extraction else "sdist"
    count = 0
    expanded_bytes = 0
    for item in archive:
        count += 1
        if count > MAX_MEMBERS:
            raise ArtifactError(f"{label} member count is outside the safety bound")
        size = item.size
        if type(size) is not int or size < 0:
            raise ArtifactError(f"{label} member has an invalid negative declared size")
        if size > MAX_EXPANDED_BYTES:
            if extraction:
                raise ArtifactError("sdist extraction exceeds the expanded-size safety bound")
            raise ArtifactError("sdist expanded size exceeds the safety bound")
        expanded_bytes += size
        if expanded_bytes < 0 or expanded_bytes > MAX_EXPANDED_BYTES:
            if extraction:
                raise ArtifactError("sdist extraction exceeds the expanded-size safety bound")
            raise ArtifactError("sdist expanded size exceeds the safety bound")
        member = _safe_name(item.name)
        if not (item.isfile() or item.isdir()):
            if extraction:
                raise ArtifactError("sdist extraction refuses links and special files")
            raise ArtifactError("sdist contains a link or special file")
        yield item, member
    if count == 0:
        raise ArtifactError(f"{label} member count is outside the safety bound")


def inspect_sdist(path: Path) -> Inventory:
    if path.is_symlink() or not path.is_file() or not path.name.endswith(".tar.gz"):
        raise ArtifactError("sdist must be a regular .tar.gz artifact")
    try:
        with tarfile.open(path, "r|gz") as archive:
            normalized: dict[str, bytes | None] = {}
            roots: set[str] = set()
            for item, member in _bounded_sdist_members(archive, extraction=False):
                roots.add(member.parts[0])
                relative = (
                    PurePosixPath(*member.parts[1:]).as_posix() if len(member.parts) > 1 else ""
                )
                if relative in normalized:
                    raise ArtifactError(f"sdist contains duplicate member {relative!r}")
                if item.isdir():
                    normalized[relative] = None
                    continue
                stream = archive.extractfile(item)
                if stream is None:
                    raise ArtifactError(f"cannot read sdist member {relative!r}")
                with stream:
                    content = stream.read()
                if len(content) != item.size:
                    raise ArtifactError(f"sdist member {relative!r} ended before its declared size")
                normalized[relative] = content
            if len(roots) != 1:
                raise ArtifactError("sdist must contain exactly one top-level directory")

            def read(relative: str) -> bytes:
                content = normalized.get(relative)
                if content is None:
                    raise ArtifactError(f"sdist is missing required file {relative!r}")
                return content

            name, version, metadata, description_bytes = _metadata(read("PKG-INFO"), "sdist")
            license_bytes = read("LICENSE")
            read("pyproject.toml")
            egg_info = f"src/{DISTRIBUTION.replace('-', '_')}.egg-info"
            console_scripts = _console_scripts(read(f"{egg_info}/entry_points.txt"), "sdist")
            manifest_raw = read("src/milhouse/resources/manifest.json")
            declared = _manifest_resources(manifest_raw, "sdist")
            resources = {relative: read(f"src/milhouse/{relative}") for relative in declared}
            required = {f"src/{item}" for item in REQUIRED_PACKAGE_FILES}
            missing = required - normalized.keys()
            if missing:
                raise ArtifactError(
                    "sdist is missing package resources: " + ", ".join(sorted(missing))
                )
            package_files = {
                relative.removeprefix("src/"): content
                for relative, content in sorted(normalized.items())
                if relative.startswith(f"src/{IMPORT_PACKAGE}/") and content is not None
            }
            allowed_package_files = {
                member
                for member in package_files
                if member.endswith(".py") or member == f"{IMPORT_PACKAGE}/py.typed"
            } | {f"{IMPORT_PACKAGE}/{relative}" for relative in declared}
            if set(package_files) != allowed_package_files:
                extra = sorted(set(package_files) - allowed_package_files)
                raise ArtifactError("sdist contains undeclared package files: " + ", ".join(extra))
            expected_files = (
                SDIST_ROOT_FILES
                | {f"src/{member}" for member in package_files}
                | {f"{egg_info}/{member}" for member in SDIST_EGG_INFO_FILES}
            )
            actual_files = {
                relative for relative, content in normalized.items() if content is not None
            }
            if actual_files != expected_files:
                extra = sorted(actual_files - expected_files)
                missing_inventory = sorted(expected_files - actual_files)
                details = []
                if extra:
                    details.append("unexpected " + ", ".join(extra))
                if missing_inventory:
                    details.append("missing " + ", ".join(missing_inventory))
                raise ArtifactError("sdist inventory mismatch: " + "; ".join(details))
            return Inventory(
                path,
                "sdist",
                frozenset(actual_files),
                name,
                version,
                metadata,
                description_bytes,
                license_bytes,
                console_scripts,
                package_files,
                resources,
                {
                    relative: read(relative)
                    for relative in SDIST_ROOT_FILES - {"PKG-INFO", "setup.cfg"}
                },
            )
    except (OSError, tarfile.TarError) as exc:
        raise ArtifactError(f"cannot inspect sdist: {exc}") from exc


def find_artifacts(directory: Path) -> tuple[Path, Path]:
    if directory.is_symlink() or not directory.is_dir():
        raise ArtifactError("distribution directory must be a regular directory")
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ArtifactError("distribution directory must contain exactly one wheel and one sdist")
    return wheels[0], sdists[0]


def _extract_sdist(path: Path, destination: Path) -> Path:
    """Extract a previously validated sdist without tar path/link semantics."""

    roots: set[str] = set()
    try:
        with tarfile.open(path, "r|gz") as archive:
            for item, member in _bounded_sdist_members(archive, extraction=True):
                roots.add(member.parts[0])
                target = destination.joinpath(*member.parts)
                if item.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = archive.extractfile(item)
                if stream is None:
                    raise ArtifactError(f"cannot extract sdist member {item.name!r}")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with stream, os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(stream, output, length=1024 * 1024)
    except (OSError, tarfile.TarError) as exc:
        raise ArtifactError(f"cannot safely extract sdist: {exc}") from exc
    if len(roots) != 1:
        raise ArtifactError("sdist extraction requires exactly one source root")
    source_root = destination / next(iter(roots))
    if source_root.is_symlink() or not source_root.is_dir():
        raise ArtifactError("sdist extraction did not produce a regular source root")
    return source_root


def _run(command: Sequence[str], cwd: Path, env: dict[str, str], label: str) -> str:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ArtifactError(f"{label} could not execute: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        summary = detail[-1][:240] if detail else f"exit {completed.returncode}"
        raise ArtifactError(f"{label} failed: {summary}")
    return completed.stdout.strip()


def _sync_locked_environment(
    uv: Path,
    repo_root: Path,
    root: Path,
    artifact_kind: str,
    offline: bool,
    *,
    receiver: bool,
) -> tuple[Path, dict[str, str]]:
    environment_name = "receiver-environment" if receiver else "environment"
    environment = root / environment_name
    env = uv_environment()
    env["UV_PROJECT_ENVIRONMENT"] = str(environment)
    env["UV_NO_PROGRESS"] = "1"
    sync = [
        str(uv),
        "--no-config",
        "sync",
        "--frozen",
        "--no-install-project",
        "--no-dev",
        "--exact",
    ]
    label_scope = artifact_kind
    if receiver:
        sync.extend(("--extra", "receiver"))
        label_scope = f"{artifact_kind} receiver"
    if offline:
        sync.append("--offline")
    _run(sync, repo_root, env, f"{label_scope} locked dependency sync")
    return environment, env


def _install_artifact(
    uv: Path,
    install_target: Path,
    root: Path,
    environment: Path,
    env: dict[str, str],
    artifact_kind: str,
    offline: bool,
    *,
    receiver: bool,
) -> None:
    python = environment / "bin" / "python"
    label_scope = f"{artifact_kind} receiver" if receiver else artifact_kind
    requirement = str(install_target)
    if receiver:
        requirement = f"{DISTRIBUTION}[receiver] @ {install_target.as_uri()}"
    install = [
        str(uv),
        "--no-config",
        "pip",
        "install",
        "--python",
        str(python),
        "--no-deps",
    ]
    if offline:
        install.append("--offline")
    install.append(requirement)
    _run(install, root, env, f"{label_scope} install")
    _run(
        [str(uv), "--no-config", "pip", "check", "--python", str(python)],
        root,
        env,
        f"{label_scope} pip check",
    )


def install_smoke(artifact: Inventory, repo_root: Path, offline: bool) -> None:
    uv = candidate_uv()
    verify_uv(uv)
    with tempfile.TemporaryDirectory(prefix=f"milhouse-{artifact.kind}-") as temporary:
        root = Path(temporary)
        environment, env = _sync_locked_environment(
            uv, repo_root, root, artifact.kind, offline, receiver=False
        )
        install_target = artifact.path.resolve(strict=True)
        if artifact.kind == "sdist":
            extracted = root / "sdist-source"
            extracted.mkdir(mode=0o700)
            source_root = _extract_sdist(install_target, extracted)
            built = root / "sdist-wheel"
            built.mkdir(mode=0o700)
            build_env = uv_environment()
            _run(
                [
                    sys.executable,
                    "-I",
                    "-m",
                    "build",
                    "--wheel",
                    "--no-isolation",
                    "--outdir",
                    str(built),
                    str(source_root),
                ],
                root,
                build_env,
                "sdist locked wheel build",
            )
            derived_paths = sorted(built.glob("*.whl"))
            if len(derived_paths) != 1:
                raise ArtifactError("sdist build did not produce exactly one wheel")
            derived = inspect_wheel(derived_paths[0])
            if (
                derived.version != artifact.version
                or derived.metadata != artifact.metadata
                or derived.description_bytes != artifact.description_bytes
                or derived.license_bytes != artifact.license_bytes
                or derived.console_scripts != artifact.console_scripts
                or derived.package_files != artifact.package_files
            ):
                raise ArtifactError("wheel built from sdist does not match sdist contents")
            install_target = derived.path.resolve(strict=True)
        _install_artifact(
            uv,
            install_target,
            root,
            environment,
            env,
            artifact.kind,
            offline,
            receiver=False,
        )
        python = environment / "bin" / "python"
        executable = environment / "bin" / "milhouse"
        _run([str(executable), "--help"], root, env, f"{artifact.kind} CLI help")
        version_output = _run(
            [str(executable), "--version"], root, env, f"{artifact.kind} CLI version"
        )
        if artifact.version not in version_output.split():
            raise ArtifactError(f"{artifact.kind} CLI version does not match metadata")
        smoke = (
            "import json; from importlib.metadata import version; "
            "from milhouse.resources import load_manifest, read_resource_text; "
            "m=load_manifest(); [read_resource_text(p) for p in m.resources]; "
            "print(json.dumps({'version':version('milhouse-observability'),'resources':list(m.resources)}))"
        )
        output = _run(
            [str(python), "-I", "-c", smoke], root, env, f"{artifact.kind} resource smoke"
        )
        try:
            result = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ArtifactError(
                f"{artifact.kind} resource smoke returned invalid evidence"
            ) from exc
        if not isinstance(result, dict) or result.get("version") != artifact.version:
            raise ArtifactError(f"{artifact.kind} installed metadata drifted")
        if result.get("resources") != sorted(artifact.resources):
            raise ArtifactError(f"{artifact.kind} installed resource inventory drifted")

        receiver_environment, receiver_env = _sync_locked_environment(
            uv, repo_root, root, artifact.kind, offline, receiver=True
        )
        _install_artifact(
            uv,
            install_target,
            root,
            receiver_environment,
            receiver_env,
            artifact.kind,
            offline,
            receiver=True,
        )


def write_hashes(
    path: Path,
    artifacts: Sequence[Path],
    *,
    trusted_hashes: dict[Path, str] | None = None,
) -> None:
    entries: list[tuple[str, str]] = []
    for artifact in sorted(artifacts):
        digest = sha256(artifact) if trusted_hashes is None else trusted_hashes.get(artifact, "")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ArtifactError("hash manifest requires one trusted sha256 per artifact")
        entries.append((artifact.name, digest))
    content = "".join(f"{digest}  {name}\n" for name, digest in entries).encode("utf-8")

    absolute = path.absolute()
    if not absolute.name or absolute.name in {".", ".."}:
        raise ArtifactError("hash manifest path must name a regular file")
    parent_fd = temporary_fd = -1
    temporary_created = False
    replaced = False
    temporary_name = f".{absolute.name}.{os.getpid()}.tmp"
    try:
        try:
            os.mkdir(absolute.parent, 0o700)
        except FileExistsError:
            pass
        parent_named = os.stat(absolute.parent, follow_symlinks=False)
        parent_fd = os.open(
            absolute.parent,
            os.O_RDONLY
            | _required_flag("O_DIRECTORY")
            | _required_flag("O_NOFOLLOW")
            | _required_flag("O_CLOEXEC"),
        )
        parent_info = os.fstat(parent_fd)
        if (
            not _same_file_snapshot(parent_named, parent_info)
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ArtifactError("hash manifest parent directory is unsafe")

        try:
            current = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            if stat.S_ISLNK(current.st_mode):
                raise ArtifactError("hash manifest path must not be a symlink")
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.geteuid()
                or current.st_nlink != 1
            ):
                raise ArtifactError("hash manifest path must be a safe owned regular file")

        try:
            temporary_fd = os.open(
                temporary_name,
                _artifact_destination_flags(),
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError as exc:
            raise ArtifactError("hash manifest temporary path is unsafe or already exists") from exc
        temporary_created = True
        with os.fdopen(temporary_fd, "wb") as stream:
            temporary_fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
            temporary_info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(temporary_info.st_mode)
                or temporary_info.st_nlink != 1
                or temporary_info.st_size != len(content)
                or stat.S_IMODE(temporary_info.st_mode) != 0o644
            ):
                raise ArtifactError("hash manifest temporary file could not be verified")

        os.replace(
            temporary_name,
            absolute.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        replaced = True
        os.fsync(parent_fd)
        published = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(published.st_mode)
            or published.st_nlink != 1
            or (published.st_dev, published.st_ino)
            != (temporary_info.st_dev, temporary_info.st_ino)
            or stat.S_IMODE(published.st_mode) != 0o644
        ):
            raise ArtifactError("hash manifest atomic replacement could not be verified")
    except ArtifactError:
        raise
    except OSError as exc:
        raise ArtifactError("hash manifest could not be written safely") from exc
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_created and not replaced and parent_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except OSError:
                pass
        if parent_fd >= 0:
            os.close(parent_fd)


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--write-hashes", type=Path)
    parser.add_argument("--skip-install", action="store_true")
    parser.add_argument("--offline", action="store_true")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        repo_root = args.repo_root.resolve(strict=True)
        source = inspect_source(repo_root)
        wheel_path, sdist_path = find_artifacts(args.dist_dir)
        with tempfile.TemporaryDirectory(prefix="milhouse-artifact-snapshots-") as temporary:
            snapshot_root = Path(temporary)
            wheel_pin = _pin_artifact(wheel_path, snapshot_root / "wheel")
            sdist_pin = _pin_artifact(sdist_path, snapshot_root / "sdist")

            public_wheel = inspect_wheel(wheel_path)
            public_sdist = inspect_sdist(sdist_path)
            _verify_pinned_source(wheel_pin)
            _verify_pinned_source(sdist_pin)
            wheel = replace(inspect_wheel(wheel_pin.path), path=wheel_pin.path)
            sdist = replace(inspect_sdist(sdist_pin.path), path=sdist_pin.path)
            _require_inventory_parity(public_wheel, wheel)
            _require_inventory_parity(public_sdist, sdist)

            if (wheel.name.casefold(), wheel.version) != (
                sdist.name.casefold(),
                sdist.version,
            ):
                raise ArtifactError("wheel and sdist metadata do not match")
            if (
                wheel.name.casefold().replace("_", "-") != source.name.casefold().replace("_", "-")
                or wheel.version != source.version
            ):
                raise ArtifactError("artifact identity does not match the current source")
            if wheel.metadata != sdist.metadata:
                raise ArtifactError("wheel and sdist complete core metadata headers differ")
            if wheel.description_bytes != sdist.description_bytes:
                raise ArtifactError("wheel and sdist metadata descriptions differ")
            if wheel.metadata != source.metadata:
                raise ArtifactError("artifact core metadata does not match the current source")
            if wheel.description_bytes != source.description_bytes:
                raise ArtifactError("artifact metadata description does not match README.md")
            if wheel.license_bytes != sdist.license_bytes:
                raise ArtifactError("wheel and sdist LICENSE contents differ")
            if wheel.license_bytes != source.license_bytes:
                raise ArtifactError("artifact LICENSE does not match the current source")
            if wheel.console_scripts != sdist.console_scripts:
                raise ArtifactError("wheel and sdist console entry points differ")
            if wheel.console_scripts != source.console_scripts:
                raise ArtifactError("artifact console entry points do not match the current source")
            if wheel.package_files != sdist.package_files:
                raise ArtifactError("wheel and sdist package-file inventories differ")
            if wheel.package_files != source.package_files:
                raise ArtifactError("artifact package files do not match the current source")
            if wheel.resources != sdist.resources:
                raise ArtifactError("wheel and sdist packaged resources differ")
            if wheel.resources != source.resources:
                raise ArtifactError("artifact resources do not match the current source")
            if sdist.sdist_files != source.sdist_files:
                raise ArtifactError("sdist project files do not match the current source")
            if not args.skip_install:
                install_smoke(wheel, repo_root, args.offline)
                install_smoke(sdist, repo_root, args.offline)

            # Reverify the public names only after all executable smoke work. Hash evidence is
            # derived from the private snapshots, never from a pathname that can be replaced.
            _verify_pinned_source(wheel_pin)
            _verify_pinned_source(sdist_pin)
            trusted_hashes = {
                wheel_path: wheel_pin.digest,
                sdist_path: sdist_pin.digest,
            }
            if args.write_hashes:
                write_hashes(
                    args.write_hashes,
                    (wheel_path, sdist_path),
                    trusted_hashes=trusted_hashes,
                )
            wheel_digest = wheel_pin.digest
            sdist_digest = sdist_pin.digest
            wheel_name = wheel_path.name
            sdist_name = sdist_path.name
            version = wheel.version
        _verify_pinned_source(wheel_pin)
        _verify_pinned_source(sdist_pin)
    except (ArtifactError, OSError, SystemExit) as exc:
        if isinstance(exc, SystemExit):
            raise
        fail(str(exc))
    print(f"artifacts: wheel+sdist {version} passed")
    print(f"{wheel_digest}  {wheel_name}")
    print(f"{sdist_digest}  {sdist_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
