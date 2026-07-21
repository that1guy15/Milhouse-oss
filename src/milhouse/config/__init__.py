"""Milhouse configuration v1: strict Pydantic models, loader, and JSON Schema."""

from __future__ import annotations

from milhouse.config.errors import ConfigError
from milhouse.config.loader import (
    CONFIG_PATH_ENV_VAR,
    MAX_CONFIG_BYTES,
    ConfigFileSelection,
    load_config,
    load_config_file,
    resolve_config_path,
)
from milhouse.config.models import CONFIG_VERSION, MilhouseConfig
from milhouse.config.paths import (
    MILHOUSE_HOME_ENV_VAR,
    RuntimePaths,
    resolve_config_source_path,
    resolve_runtime_paths,
)
from milhouse.config.schema import (
    JSON_SCHEMA_DIALECT,
    JSON_SCHEMA_ID,
    generate_json_schema,
    generate_json_schema_bytes,
)
from milhouse.config.secrets import (
    MAX_ENV_FILE_BYTES,
    MAX_ENV_FILE_ENTRIES,
    MAX_SECRET_VALUE_CHARS,
    SecretEnvironment,
    SecretSource,
    SecretSourceKind,
    collect_secret_references,
    load_secret_environment,
)

__all__ = [
    "CONFIG_PATH_ENV_VAR",
    "CONFIG_VERSION",
    "JSON_SCHEMA_DIALECT",
    "JSON_SCHEMA_ID",
    "MAX_CONFIG_BYTES",
    "MAX_ENV_FILE_BYTES",
    "MAX_ENV_FILE_ENTRIES",
    "MAX_SECRET_VALUE_CHARS",
    "MILHOUSE_HOME_ENV_VAR",
    "ConfigError",
    "ConfigFileSelection",
    "MilhouseConfig",
    "RuntimePaths",
    "SecretEnvironment",
    "SecretSource",
    "SecretSourceKind",
    "collect_secret_references",
    "generate_json_schema",
    "generate_json_schema_bytes",
    "load_config",
    "load_config_file",
    "load_secret_environment",
    "resolve_config_path",
    "resolve_config_source_path",
    "resolve_runtime_paths",
]
