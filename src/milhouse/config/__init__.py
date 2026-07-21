"""Milhouse configuration v1: strict Pydantic models, loader, and JSON Schema."""

from __future__ import annotations

from milhouse.config.loader import (
    CONFIG_PATH_ENV_VAR,
    MAX_CONFIG_BYTES,
    ConfigError,
    load_config,
    load_config_file,
    resolve_config_path,
)
from milhouse.config.models import CONFIG_VERSION, MilhouseConfig
from milhouse.config.schema import (
    JSON_SCHEMA_DIALECT,
    JSON_SCHEMA_ID,
    generate_json_schema,
    generate_json_schema_bytes,
)

__all__ = [
    "CONFIG_PATH_ENV_VAR",
    "CONFIG_VERSION",
    "JSON_SCHEMA_DIALECT",
    "JSON_SCHEMA_ID",
    "MAX_CONFIG_BYTES",
    "ConfigError",
    "MilhouseConfig",
    "generate_json_schema",
    "generate_json_schema_bytes",
    "load_config",
    "load_config_file",
    "resolve_config_path",
]
