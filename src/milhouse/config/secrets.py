"""Explicit, bounded, precedence-preserving secret environment loading."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from io import StringIO
from pathlib import Path
from types import MappingProxyType
from typing import Any

from dotenv.parser import parse_stream
from pydantic import BaseModel

from milhouse.config.errors import ConfigError
from milhouse.config.filesystem import (
    FileSnapshot,
    SecureFileError,
    SecureFileErrorKind,
    open_regular_file_no_follow,
)
from milhouse.config.loader import verify_config_generation
from milhouse.config.models import MilhouseConfig
from milhouse.config.paths import RuntimePaths, resolve_config_source_path

MAX_ENV_FILE_BYTES = 1_048_576
MAX_ENV_FILE_ENTRIES = 4_096
MAX_SECRET_VALUE_CHARS = 65_536

_ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class SecretSourceKind(StrEnum):
    """Safe source categories that never disclose a local file path."""

    PROCESS = "process"
    CLI_ENV_FILE = "cli_env_file"
    CONFIG_ENV_FILE = "config_env_file"


@dataclass(frozen=True, slots=True, repr=False)
class SecretSource:
    """Non-secret provenance for one resolved secret reference."""

    kind: SecretSourceKind
    ordinal: int | None = None

    def __repr__(self) -> str:
        ordinal = "None" if self.ordinal is None else str(self.ordinal)
        return f"SecretSource(kind={self.kind.value!r}, ordinal={ordinal})"


@dataclass(frozen=True, slots=True, repr=False, init=False)
class SecretEnvironment:
    """A non-enumerating secret container with a deliberately value-safe representation."""

    _values: Mapping[str, str]
    _sources: Mapping[str, SecretSource]

    def __init__(
        self,
        values: Mapping[str, str],
        sources: Mapping[str, SecretSource],
    ) -> None:
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))
        object.__setattr__(self, "_sources", MappingProxyType(dict(sources)))

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return f"SecretEnvironment(resolved={len(self)})"

    __str__ = __repr__

    def get(self, reference: str) -> str | None:
        """Return a referenced value without making the container enumerable."""

        return self._values.get(reference)

    def require(self, reference: str) -> str:
        """Return a referenced value or raise a stable error that omits its name and value."""

        value = self._values.get(reference)
        if value is None:
            raise ConfigError("secrets.value.missing", "required secret value is not set")
        return value

    def source(self, reference: str) -> SecretSource | None:
        """Return safe source metadata without exposing a selected file path."""

        return self._sources.get(reference)


def collect_secret_references(config: MilhouseConfig) -> frozenset[str]:
    """Collect credential environment-variable references from the validated config tree."""

    references: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, BaseModel):
            for field_name in type(value).model_fields:
                child = getattr(value, field_name)
                if field_name.endswith("_env") and isinstance(child, str):
                    references.add(child)
                else:
                    visit(child)
        elif isinstance(value, Mapping):
            for child in value.values():
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)

    visit(config)
    return frozenset(references)


def _read_env_text(path: Path) -> str:
    try:
        opened = open_regular_file_no_follow(path)
    except SecureFileError as error:
        if error.kind is SecureFileErrorKind.NOT_FOUND:
            raise ConfigError("secrets.file.not_found", "selected env file was not found") from None
        if error.kind is SecureFileErrorKind.NOT_REGULAR:
            raise ConfigError(
                "secrets.file.not_regular",
                "selected env file must be a regular non-symlink file",
            ) from None
        if error.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED:
            raise ConfigError(
                "secrets.file.security_unsupported",
                "safe selected env file opening is unavailable",
            ) from None
        raise ConfigError(
            "secrets.file.unreadable", "selected env file could not be opened"
        ) from None

    descriptor = opened.descriptor
    snapshot = opened.snapshot
    if snapshot.size > MAX_ENV_FILE_BYTES:
        os.close(descriptor)
        raise ConfigError(
            "secrets.file.too_large",
            f"selected env file exceeds the {MAX_ENV_FILE_BYTES}-byte bound",
        )

    try:
        stream = os.fdopen(descriptor, "rb", closefd=True)
    except OSError:
        os.close(descriptor)
        raise ConfigError(
            "secrets.file.unreadable", "selected env file could not be read"
        ) from None

    try:
        with stream:
            raw = stream.read(MAX_ENV_FILE_BYTES + 1)
            after_read = os.fstat(stream.fileno())
            if snapshot != FileSnapshot.from_stat(after_read):
                raise ConfigError(
                    "secrets.file.changed", "selected env file changed while it was being read"
                )
    except ConfigError:
        raise
    except OSError:
        raise ConfigError(
            "secrets.file.unreadable", "selected env file could not be read"
        ) from None

    if len(raw) > MAX_ENV_FILE_BYTES:
        raise ConfigError(
            "secrets.file.too_large",
            f"selected env file exceeds the {MAX_ENV_FILE_BYTES}-byte bound",
        )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(
            "secrets.file.unreadable", "selected env file could not be read as UTF-8"
        ) from None


def _parse_env_file(path: Path, *, wanted: set[str]) -> dict[str, str]:
    text = _read_env_text(path)
    selected: dict[str, str] = {}
    seen: set[str] = set()
    entries = 0

    for binding in parse_stream(StringIO(text)):
        if binding.error:
            raise ConfigError("secrets.file.syntax", "selected env file contains invalid syntax")
        if binding.key is None:
            continue
        entries += 1
        if entries > MAX_ENV_FILE_ENTRIES:
            raise ConfigError(
                "secrets.file.too_many", "selected env file contains too many entries"
            )
        if binding.value is None:
            raise ConfigError(
                "secrets.file.syntax", "selected env file contains an assignment without a value"
            )
        if _ENV_NAME_PATTERN.fullmatch(binding.key) is None:
            raise ConfigError(
                "secrets.file.name_invalid", "selected env file contains an invalid name"
            )
        if binding.key in seen:
            raise ConfigError(
                "secrets.file.duplicate", "selected env file contains a duplicate name"
            )
        seen.add(binding.key)
        if len(binding.value) > MAX_SECRET_VALUE_CHARS:
            raise ConfigError(
                "secrets.file.value_too_large",
                "selected env file contains a value that exceeds the safe bound",
            )
        if binding.key in wanted:
            selected[binding.key] = binding.value
    return selected


def load_secret_environment(
    config: MilhouseConfig,
    paths: RuntimePaths,
    *,
    process_env: Mapping[str, str] | None = None,
    explicit_env_file: str | Path | None = None,
) -> SecretEnvironment:
    """Load only referenced values with process/CLI/config-file first-source-wins precedence."""

    verify_config_generation(config, paths.config_selection)
    expected_env_files = tuple(
        resolve_config_source_path(value, config_dir=paths.config_dir)
        for value in config.secrets.env_files
    )
    if expected_env_files != paths.configured_env_files:
        raise ConfigError(
            "secrets.paths.mismatch", "resolved env paths do not match the validated config"
        )
    verify_config_generation(config, paths.config_selection)

    references = collect_secret_references(config)
    unresolved = set(references)
    environment = os.environ if process_env is None else process_env
    values: dict[str, str] = {}
    sources: dict[str, SecretSource] = {}

    for reference in sorted(references):
        if reference not in environment:
            continue
        value = environment[reference]
        if not isinstance(value, str):
            raise ConfigError("secrets.value.invalid", "process secret value must be text")
        if len(value) > MAX_SECRET_VALUE_CHARS:
            raise ConfigError(
                "secrets.value.too_large", "process secret value exceeds the safe bound"
            )
        values[reference] = value
        sources[reference] = SecretSource(SecretSourceKind.PROCESS)
        unresolved.remove(reference)

    selected_files: list[tuple[Path, SecretSource]] = []
    if unresolved and explicit_env_file is not None:
        selected_files.append(
            (
                resolve_config_source_path(explicit_env_file, config_dir=paths.config_dir),
                SecretSource(SecretSourceKind.CLI_ENV_FILE),
            )
        )
    if unresolved:
        selected_files.extend(
            (path, SecretSource(SecretSourceKind.CONFIG_ENV_FILE, ordinal))
            for ordinal, path in enumerate(expected_env_files, start=1)
        )

    for path, source in selected_files:
        if not unresolved:
            break
        verify_config_generation(config, paths.config_selection)
        selected = _parse_env_file(path, wanted=unresolved)
        verify_config_generation(config, paths.config_selection)
        for reference, value in selected.items():
            values[reference] = value
            sources[reference] = source
            unresolved.remove(reference)

    verify_config_generation(config, paths.config_selection)
    return SecretEnvironment(values, sources)


__all__ = [
    "MAX_ENV_FILE_BYTES",
    "MAX_ENV_FILE_ENTRIES",
    "MAX_SECRET_VALUE_CHARS",
    "SecretEnvironment",
    "SecretSource",
    "SecretSourceKind",
    "collect_secret_references",
    "load_secret_environment",
]
