"""Config path precedence, bounded TOML loading, and stable load errors."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from milhouse.config._models import CONFIG_VERSION, MilhouseConfig, StrictModel
from milhouse.config.errors import ConfigError
from milhouse.config.filesystem import (
    FileIdentity,
    FileSelection,
    FileSnapshot,
    SecureFileError,
    SecureFileErrorKind,
    inspect_regular_file_no_follow,
    open_regular_file_no_follow,
)

CONFIG_PATH_ENV_VAR = "MILHOUSE_CONFIG"
MAX_CONFIG_BYTES = 1_048_576
MAX_CONFIG_DIAGNOSTIC_BYTES = 1_024
MAX_CONFIG_DIAGNOSTICS = 8

_TOML_LOCATION_PATTERN = re.compile(r"at line (\d+), column (\d+)")
_SAFE_VALUE_ERROR_MESSAGES = frozenset(
    {
        "alert rule collector is not a declared collector id",
        "alert rule must reference a site_canary collector",
        "collector contains an undeclared mapped target id",
        "collector job is not bound to a declared collector id",
        "collector provider has an incompatible provider type",
        "collector provider is not a declared provider id",
        "collector target is not a declared target id",
        "configuration contains an invalid discriminator",
        "configuration contains an unknown field",
        f"config_version must equal {CONFIG_VERSION}",
        "expected_statuses entries must be valid HTTP status codes",
        "feedback rule target is not a declared target id",
        "github issues notification requires a github provider",
        "header_name is required when auth_mode is 'header'",
        "incident rule references an alert rule bound to another target",
        "incident rule references an undeclared alert rule id",
        "incident rule target is not a declared target id",
        "interval_seconds and weekday are invalid when schedule is 'daily'",
        "interval_seconds is invalid when schedule is 'weekly'",
        "interval_seconds is required when schedule is 'interval'",
        "local_time is required when schedule is 'daily'",
        "mcp.default_limit must not exceed mcp.maximum_limit",
        "notification provider is not a declared provider id",
        "notification repository is not allowlisted by its github provider",
        "path must be an absolute canonical path",
        "path must be relative, not absolute",
        "path must not contain empty, '.', or '..' segments",
        "plugins.allowed requires allow_third_party=true",
        "previous_secret_env and previous_secret_expires_at must both be set or both absent",
        "previous_secret_env must differ from secret_env",
        "project.default_target is not a declared target id",
        "receiver source target is not a declared target id",
        "timestamp must be in the future",
        "timestamp must be RFC3339 with a zero UTC offset",
        "timezone must be a known IANA zone name",
        "weekday and local_time are invalid when schedule is 'interval'",
        "weekday and local_time are required when schedule is 'weekly'",
    }
)


def _known_config_location_parts() -> frozenset[str]:
    names: set[str] = set()
    pending = [StrictModel]
    while pending:
        model = pending.pop()
        names.update(model.model_fields)
        pending.extend(model.__subclasses__())
    return frozenset(names)


_KNOWN_CONFIG_LOCATION_PARTS = _known_config_location_parts()


@dataclass(frozen=True, slots=True, repr=False)
class ConfigFileSelection:
    """Path and identity of the exact config file securely read by ``load_config``."""

    path: Path
    parent_identity: FileIdentity
    snapshot: FileSnapshot
    config_digest: str

    def __fspath__(self) -> str:
        return os.fspath(self.path)

    def __repr__(self) -> str:
        return "ConfigFileSelection(selected=True)"

    __str__ = __repr__


def _config_open_error(error: SecureFileError) -> ConfigError:
    if error.kind is SecureFileErrorKind.INVALID:
        return ConfigError("config.path.invalid", "config path is invalid")
    if error.kind is SecureFileErrorKind.NOT_FOUND:
        return ConfigError("config.file.not_found", "config file was not found")
    if error.kind is SecureFileErrorKind.NOT_REGULAR:
        return ConfigError("config.file.not_regular", "config path must be a regular file")
    if error.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED:
        return ConfigError(
            "config.file.security_unsupported",
            "safe config file opening is unavailable",
        )
    return ConfigError("config.file.unreadable", "config file could not be opened")


def _bind_selection(selection: FileSelection, *, config_digest: str) -> ConfigFileSelection:
    return ConfigFileSelection(
        path=selection.path,
        parent_identity=selection.parent_identity,
        snapshot=selection.snapshot,
        config_digest=config_digest,
    )


def validated_config_digest(config: MilhouseConfig) -> str:
    """Return a deterministic opaque binding for one fully validated config model."""

    try:
        payload = json.dumps(
            config.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except Exception:
        raise ConfigError(
            "config.selection.mismatch",
            "validated config does not match the selected file generation",
        ) from None
    return hashlib.sha256(payload).hexdigest()


def verify_config_file_selection(selection: ConfigFileSelection) -> ConfigFileSelection:
    """Refuse a selected config path whose parent, file identity, or content changed."""

    try:
        current = inspect_regular_file_no_follow(selection.path)
    except SecureFileError:
        raise ConfigError(
            "config.file.changed", "config path changed after it was selected"
        ) from None
    if (
        current.path != selection.path
        or current.parent_identity != selection.parent_identity
        or current.snapshot != selection.snapshot
    ):
        raise ConfigError("config.file.changed", "config path changed after it was selected")
    return selection


def verify_config_generation(
    config: MilhouseConfig, selection: ConfigFileSelection
) -> ConfigFileSelection:
    """Verify that a model and securely selected config file belong to one loaded generation."""

    if not hmac.compare_digest(validated_config_digest(config), selection.config_digest):
        raise ConfigError(
            "config.selection.mismatch",
            "validated config does not match the selected file generation",
        )
    return verify_config_file_selection(selection)


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


def _read_config_text(path: Path) -> tuple[str, FileSelection]:
    try:
        opened = open_regular_file_no_follow(path)
    except SecureFileError as error:
        raise _config_open_error(error) from None

    descriptor = opened.descriptor
    selection = opened.selection
    if selection.snapshot.size > MAX_CONFIG_BYTES:
        os.close(descriptor)
        raise ConfigError(
            "config.file.too_large",
            f"config file exceeds the {MAX_CONFIG_BYTES}-byte bound",
        )

    try:
        stream = os.fdopen(descriptor, "rb", closefd=True)
    except OSError:
        os.close(descriptor)
        raise ConfigError("config.file.unreadable", "config file could not be read") from None

    try:
        with stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
            after_read = os.fstat(stream.fileno())
            if selection.snapshot != FileSnapshot.from_stat(after_read):
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
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(
            "config.file.unreadable", "config file could not be read as UTF-8"
        ) from None

    try:
        current = inspect_regular_file_no_follow(selection.path)
    except SecureFileError:
        raise ConfigError(
            "config.file.changed", "config path changed while it was being read"
        ) from None
    if (
        current.parent_identity != selection.parent_identity
        or current.snapshot != selection.snapshot
    ):
        raise ConfigError("config.file.changed", "config path changed while it was being read")
    return text, selection


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


def _safe_config_location(location: object, *, error_type: str) -> str:
    if type(location) is not tuple:
        return "configuration"
    parts = location[:-1] if error_type == "extra_forbidden" and location else location
    safe_parts = [
        part if type(part) is str and part in _KNOWN_CONFIG_LOCATION_PARTS else "<item>"
        for part in parts
    ]
    if error_type == "extra_forbidden":
        safe_parts.append("<unknown>")
    return ".".join(safe_parts) or "configuration"


def _safe_value_error_message(message: object) -> str:
    if type(message) is not str:
        return "value failed configuration validation"
    detail = message.removeprefix("Value error, ")
    if detail.endswith(" contains a duplicate entry"):
        return "configuration contains a duplicate entry"
    if detail in _SAFE_VALUE_ERROR_MESSAGES:
        return detail
    return "value failed configuration validation"


def _safe_schema_error_message(error_type: str, message: object) -> str:
    if error_type == "extra_forbidden":
        return "unknown field is not permitted"
    if error_type == "value_error":
        return _safe_value_error_message(message)
    if error_type == "missing":
        return "required field is missing"
    if error_type in {"union_tag_invalid", "union_tag_not_found"}:
        return "discriminator value is invalid"
    if error_type.startswith("url_"):
        return "URL value is invalid"
    if error_type.startswith(("datetime_", "date_", "timezone_")):
        return "timestamp value is invalid"
    if error_type.startswith("ip_"):
        return "IP address value is invalid"
    if error_type in {
        "bool_type",
        "bytes_type",
        "dict_type",
        "float_type",
        "int_type",
        "list_type",
        "string_type",
        "tuple_type",
    }:
        return "value has the wrong type"
    if error_type in {
        "bytes_too_long",
        "bytes_too_short",
        "decimal_max_digits",
        "decimal_max_places",
        "decimal_whole_digits",
        "greater_than",
        "greater_than_equal",
        "less_than",
        "less_than_equal",
        "list_too_long",
        "list_too_short",
        "string_too_long",
        "string_too_short",
        "too_long",
        "too_short",
    }:
        return "value is outside the allowed bounds"
    if error_type in {"literal_error", "string_pattern_mismatch"}:
        return "value does not match the required format"
    return "value failed configuration validation"


def _bounded_schema_diagnostics(error: ValidationError) -> str:
    failures = error.errors(include_url=False, include_context=False, include_input=False)
    details: list[str] = []
    for failure in failures[:MAX_CONFIG_DIAGNOSTICS]:
        error_type_value = failure.get("type")
        error_type = error_type_value if type(error_type_value) is str else "unknown"
        location = _safe_config_location(failure.get("loc"), error_type=error_type)
        message = _safe_schema_error_message(error_type, failure.get("msg"))
        candidate = f"{location}: {message}"
        joined = "; ".join((*details, candidate))
        if len(joined.encode("utf-8")) > MAX_CONFIG_DIAGNOSTIC_BYTES:
            break
        details.append(candidate)

    omitted = len(failures) - len(details)
    if omitted:
        while True:
            suffix = f"{omitted} additional configuration errors omitted"
            joined = "; ".join((*details, suffix))
            if len(joined.encode("utf-8")) <= MAX_CONFIG_DIAGNOSTIC_BYTES or not details:
                details.append(suffix)
                break
            details.pop()
            omitted = len(failures) - len(details)
    return "; ".join(details) or "config failed schema validation"


def _validate_model(data: Mapping[str, object]) -> MilhouseConfig:
    try:
        return MilhouseConfig.model_validate(data)
    except ValidationError as exc:
        failure = ConfigError("config.schema.invalid", _bounded_schema_diagnostics(exc))
    raise failure


def load_config_file(path: str | Path) -> MilhouseConfig:
    """Load and strictly validate a bounded, regular-file TOML config document."""

    config, _selection = _load_config_document(path)
    return config


def _load_config_document(path: str | Path) -> tuple[MilhouseConfig, ConfigFileSelection]:
    text, selection = _read_config_text(Path(path))
    data = _parse_toml(text)
    _check_config_version(data)
    config = _validate_model(data)
    return config, _bind_selection(selection, config_digest=validated_config_digest(config))


def load_config(
    cli_path: str | Path | None,
    *,
    platform_default: str | Path,
    env: Mapping[str, str] | None = None,
) -> tuple[MilhouseConfig, ConfigFileSelection]:
    """Resolve the config path by precedence, then load and validate it."""

    path = resolve_config_path(cli_path, platform_default=platform_default, env=env)
    return _load_config_document(path)


__all__ = [
    "CONFIG_PATH_ENV_VAR",
    "MAX_CONFIG_BYTES",
    "ConfigError",
    "ConfigFileSelection",
    "load_config",
    "load_config_file",
    "resolve_config_path",
    "validated_config_digest",
    "verify_config_file_selection",
    "verify_config_generation",
]
