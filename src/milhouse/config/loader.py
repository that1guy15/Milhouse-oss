"""Config path precedence, bounded TOML loading, and stable load errors."""

from __future__ import annotations

import errno
import os
import re
import stat
import tomllib
from collections.abc import Mapping
from pathlib import Path

from pydantic import ValidationError

from milhouse.config.models import CONFIG_VERSION, MilhouseConfig

CONFIG_PATH_ENV_VAR = "MILHOUSE_CONFIG"
MAX_CONFIG_BYTES = 1_048_576

_TOML_LOCATION_PATTERN = re.compile(r"at line (\d+), column (\d+)")


class ConfigError(Exception):
    """A stable, value-free configuration loading or validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def resolve_config_path(
    cli_path: str | Path | None,
    *,
    platform_default: str | Path,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the config file path: ``--config``, then ``MILHOUSE_CONFIG``, then the
    caller-supplied platform default. The current working directory is never searched."""

    if cli_path is not None:
        if str(cli_path) == "":
            raise ConfigError("config.path.invalid", "--config must not be empty")
        return Path(cli_path)

    environment = os.environ if env is None else env
    env_value = environment.get(CONFIG_PATH_ENV_VAR)
    if env_value:
        return Path(env_value)

    return Path(platform_default)


def _read_config_text(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow
    before: os.stat_result | None = None

    try:
        if nofollow == 0:
            before = os.lstat(path)
            if stat.S_ISLNK(before.st_mode):
                raise ConfigError("config.file.not_regular", "config path must not be a symlink")
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise ConfigError("config.file.not_found", "config file was not found") from None
    except ConfigError:
        raise
    except ValueError:
        raise ConfigError("config.path.invalid", "config path is invalid") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ConfigError(
                "config.file.not_regular", "config path must not be a symlink"
            ) from None
        raise ConfigError("config.file.unreadable", "config file could not be opened") from None

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigError("config.file.not_regular", "config path must be a regular file")
        if before is not None and (before.st_dev, before.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise ConfigError(
                "config.file.changed", "config file changed while it was being opened"
            )
        if metadata.st_size > MAX_CONFIG_BYTES:
            raise ConfigError(
                "config.file.too_large",
                f"config file exceeds the {MAX_CONFIG_BYTES}-byte bound",
            )
    except ConfigError:
        os.close(descriptor)
        raise
    except OSError:
        os.close(descriptor)
        raise ConfigError("config.file.unreadable", "config file could not be read") from None

    try:
        stream = os.fdopen(descriptor, "rb", closefd=True)
    except OSError:
        os.close(descriptor)
        raise ConfigError("config.file.unreadable", "config file could not be read") from None

    try:
        with stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
            after_read = os.fstat(stream.fileno())
            if (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            ) != (
                after_read.st_dev,
                after_read.st_ino,
                after_read.st_size,
                after_read.st_mtime_ns,
                after_read.st_ctime_ns,
            ):
                raise ConfigError(
                    "config.file.changed", "config file changed while it was being read"
                )
    except ConfigError:
        raise
    except OSError:
        raise ConfigError("config.file.unreadable", "config file could not be read") from None

    if not raw:
        raise ConfigError("config.file.empty", "config file is empty")
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(
            "config.file.too_large",
            f"config file exceeds the {MAX_CONFIG_BYTES}-byte bound",
        )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(
            "config.file.unreadable", "config file could not be read as UTF-8"
        ) from None


def _extract_toml_location(message: str) -> str | None:
    match = _TOML_LOCATION_PATTERN.search(message)
    if match is None:
        return None
    return f"line {match.group(1)}, column {match.group(2)}"


def _parse_toml(text: str) -> dict[str, object]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        location = _extract_toml_location(str(exc))
        message = "config file contains invalid TOML syntax"
        if location:
            message = f"{message} ({location})"
        raise ConfigError("config.toml.syntax", message) from None
    return data


def _check_config_version(data: Mapping[str, object]) -> None:
    version = data.get("config_version")
    if type(version) is int and version == CONFIG_VERSION:
        return
    raise ConfigError("config.version.unsupported", f"config_version must equal {CONFIG_VERSION}")


def _validate_model(data: Mapping[str, object]) -> MilhouseConfig:
    try:
        return MilhouseConfig.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
        raise ConfigError(
            "config.schema.invalid", details or "config failed schema validation"
        ) from None


def load_config_file(path: str | Path) -> MilhouseConfig:
    """Load and strictly validate a bounded, regular-file TOML config document."""

    text = _read_config_text(Path(path))
    data = _parse_toml(text)
    _check_config_version(data)
    return _validate_model(data)


def load_config(
    cli_path: str | Path | None,
    *,
    platform_default: str | Path,
    env: Mapping[str, str] | None = None,
) -> tuple[MilhouseConfig, Path]:
    """Resolve the config path by precedence, then load and validate it."""

    path = resolve_config_path(cli_path, platform_default=platform_default, env=env)
    return load_config_file(path), path


__all__ = [
    "CONFIG_PATH_ENV_VAR",
    "MAX_CONFIG_BYTES",
    "ConfigError",
    "load_config",
    "load_config_file",
    "resolve_config_path",
]
