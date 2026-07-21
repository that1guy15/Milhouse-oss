"""Deterministic Draft 2020-12 JSON Schema export for Milhouse configuration v1."""

from __future__ import annotations

import json

from milhouse.config._models import MilhouseConfig

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
JSON_SCHEMA_ID = "urn:milhouse:config-schema:v1"


def generate_json_schema() -> dict[str, object]:
    """Return the config v1 JSON Schema as a plain, ordered mapping."""

    schema = MilhouseConfig.model_json_schema(mode="validation")
    ordered: dict[str, object] = {"$schema": JSON_SCHEMA_DIALECT, "$id": JSON_SCHEMA_ID}
    ordered.update(schema)
    return ordered


def generate_json_schema_bytes() -> bytes:
    """Serialize the config v1 JSON Schema as deterministic, sorted, UTF-8 bytes."""

    schema = generate_json_schema()
    text = json.dumps(schema, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    return text.encode("utf-8")


__all__ = [
    "JSON_SCHEMA_DIALECT",
    "JSON_SCHEMA_ID",
    "generate_json_schema",
    "generate_json_schema_bytes",
]
