"""Strict data-file parsers shared by repository validation scripts."""

from __future__ import annotations

import json
import math
import tomllib
from pathlib import Path
from typing import NoReturn, cast

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
SUPPORTED_SUFFIXES = {".json", ".toml", ".yaml", ".yml"}
YAML_CORE_TAGS = {
    "tag:yaml.org,2002:bool",
    "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:map",
    "tag:yaml.org,2002:null",
    "tag:yaml.org,2002:seq",
    "tag:yaml.org,2002:str",
}


class DataError(ValueError):
    """Raised when a repository data file is unsafe or malformed."""


def _reject_json_constant(value: str) -> NoReturn:
    raise DataError(f"non-finite JSON number {value!r} is prohibited")


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DataError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise DataError("input must be a regular, non-symlink file")
    size = path.stat().st_size
    if size == 0:
        raise DataError("empty documents are prohibited")
    if size > MAX_DOCUMENT_BYTES:
        raise DataError("document exceeds the 16 MiB safety bound")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise DataError(f"cannot read UTF-8 input: {exc}") from exc


def _load_json(text: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise DataError(f"invalid JSON: {exc}") from exc


def _load_toml(text: str) -> object:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise DataError(f"invalid TOML: {exc}") from exc


def _load_yaml(text: str) -> object:
    try:
        import yaml
    except ImportError as exc:
        raise DataError("PyYAML is required for YAML validation") from exc

    try:
        for token in yaml.scan(text):
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)):
                raise DataError("YAML aliases and anchors are prohibited")
        document = yaml.compose(text, Loader=yaml.BaseLoader)
    except yaml.YAMLError as exc:
        raise DataError(f"invalid YAML: {exc}") from exc
    if document is None:
        raise DataError("empty YAML documents are prohibited")

    def convert(node: yaml.nodes.Node) -> object:
        if node.tag not in YAML_CORE_TAGS:
            raise DataError(f"nonstandard YAML tag {node.tag!r} is prohibited")
        if isinstance(node, yaml.nodes.MappingNode):
            result: dict[str, object] = {}
            for key_node, value_node in node.value:
                if not isinstance(key_node, yaml.nodes.ScalarNode):
                    raise DataError("YAML mapping keys must be scalar strings")
                if key_node.tag not in YAML_CORE_TAGS:
                    raise DataError(f"nonstandard YAML tag {key_node.tag!r} is prohibited")
                key = key_node.value
                if key in result:
                    raise DataError(f"duplicate YAML key {key!r}")
                result[key] = convert(value_node)
            return result
        if isinstance(node, yaml.nodes.SequenceNode):
            return [convert(item) for item in node.value]
        if not isinstance(node, yaml.nodes.ScalarNode):
            raise DataError("unsupported YAML node")
        value = node.value
        if node.style is not None:
            return value
        lowered = value.casefold()
        if lowered in {".nan", ".inf", "+.inf", "-.inf"}:
            raise DataError("non-finite YAML numbers are prohibited")
        if lowered in {"null", "~"}:
            return None
        if lowered in {"true", "false"}:
            return lowered == "true"
        if value and value.lstrip("+-").isdigit():
            try:
                return int(value, 10)
            except ValueError:
                pass
        return value

    return convert(document)


def _reject_non_finite_numbers(value: object) -> object:
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 1_000_000:
            raise DataError("document contains too many nested values")
        if isinstance(current, float) and not math.isfinite(current):
            raise DataError("non-finite numeric values are prohibited")
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, (list, tuple, set, frozenset)):
            pending.extend(current)
    return value


def load_data(path: Path) -> object:
    """Load a supported data file with strict, fail-closed syntax."""

    text = _read_text(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _reject_non_finite_numbers(_load_json(text))
    if suffix == ".toml":
        return _reject_non_finite_numbers(_load_toml(text))
    if suffix in {".yaml", ".yml"}:
        return _reject_non_finite_numbers(_load_yaml(text))
    raise DataError(f"unsupported data-file suffix {suffix!r}")


def require_mapping(value: object, label: str) -> dict[str, object]:
    """Return a typed string-key mapping or fail."""

    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise DataError(f"{label} must be a string-keyed mapping")
    return cast(dict[str, object], value)
