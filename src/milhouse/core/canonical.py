"""Canonical JSON bytes used by Milhouse hashes and durable projections."""

from __future__ import annotations

import json
import math
import unicodedata
from datetime import datetime
from decimal import Decimal

from milhouse.core.clock import format_timestamp
from milhouse.core.errors import MilhouseValueError

MIN_CANONICAL_INT = -(2**63)
MAX_CANONICAL_INT = 2**63 - 1
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_NODES = 10_000
DEFAULT_MAX_BYTES = 262_144


class CanonicalizationError(MilhouseValueError):
    """Safe, stable failure raised for values outside CanonicalJSONV1."""


def _normalize_string(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalizationError(
            "MH_CANONICAL_UNICODE", "surrogate code points are not supported"
        )
    normalized_lines = value.replace("\r\n", "\n").replace("\r", "\n")
    return unicodedata.normalize("NFC", normalized_lines)


def _quote_string(value: str) -> str:
    return json.dumps(
        _normalize_string(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )


def _serialize_integer(value: int) -> str:
    if value < MIN_CANONICAL_INT or value > MAX_CANONICAL_INT:
        raise CanonicalizationError(
            "MH_CANONICAL_INTEGER_RANGE", "an integer is outside the signed 64-bit domain"
        )
    return str(value)


def _serialize_float(value: float) -> str:
    if not math.isfinite(value):
        raise CanonicalizationError("MH_CANONICAL_FLOAT", "a float must be finite")
    if value == 0:
        return "0"
    if value.is_integer():
        return _serialize_integer(int(value))

    decimal_value = Decimal(repr(value))
    parts = decimal_value.as_tuple()
    digits = "".join(str(digit) for digit in parts.digits)
    exponent = parts.exponent
    if not isinstance(exponent, int):  # pragma: no cover - finite input guarantees an integer
        raise CanonicalizationError("MH_CANONICAL_FLOAT", "a float exponent is invalid")

    digit_count = len(digits)
    decimal_position = digit_count + exponent
    if 0 < decimal_position <= 21:
        body = f"{digits[:decimal_position]}.{digits[decimal_position:]}"
    elif -6 < decimal_position <= 0:
        body = f"0.{('0' * -decimal_position)}{digits}"
    else:
        scientific_exponent = decimal_position - 1
        mantissa = digits[0] if digit_count == 1 else f"{digits[0]}.{digits[1:]}"
        exponent_text = (
            f"+{scientific_exponent}" if scientific_exponent >= 0 else str(scientific_exponent)
        )
        body = f"{mantissa}e{exponent_text}"
    return f"-{body}" if parts.sign else body


class _CanonicalEncoder:
    def __init__(self, *, max_depth: int, max_nodes: int) -> None:
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.nodes = 0

    def encode(self, value: object) -> str:
        return self._encode_value(value, container_depth=0)

    def _count_node(self) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise CanonicalizationError(
                "MH_CANONICAL_NODES", "the canonical value exceeds the node limit"
            )

    def _encode_value(self, value: object, *, container_depth: int) -> str:
        self._count_node()
        if value is None:
            return "null"
        if type(value) is bool:
            return "true" if value else "false"
        if type(value) is int:
            return _serialize_integer(value)
        if type(value) is float:
            return _serialize_float(value)
        if type(value) is str:
            return _quote_string(value)
        if type(value) is datetime:
            try:
                return _quote_string(format_timestamp(value))
            except (OverflowError, ValueError) as error:
                raise CanonicalizationError(
                    "MH_CANONICAL_TIMESTAMP", "a timestamp must be aware and valid"
                ) from error
        if type(value) is list:
            return self._encode_array(value, container_depth=container_depth + 1)
        if type(value) is dict:
            return self._encode_object(value, container_depth=container_depth + 1)
        raise CanonicalizationError(
            "MH_CANONICAL_TYPE", "the value type is not supported by canonical JSON"
        )

    def _check_depth(self, container_depth: int) -> None:
        if container_depth > self.max_depth:
            raise CanonicalizationError(
                "MH_CANONICAL_DEPTH", "the canonical value exceeds the container-depth limit"
            )

    def _encode_array(self, value: list[object], *, container_depth: int) -> str:
        self._check_depth(container_depth)
        members = [self._encode_value(member, container_depth=container_depth) for member in value]
        return f"[{','.join(members)}]"

    def _encode_object(self, value: dict[object, object], *, container_depth: int) -> str:
        self._check_depth(container_depth)
        normalized: dict[str, object] = {}
        for key, member in value.items():
            if type(key) is not str:
                raise CanonicalizationError(
                    "MH_CANONICAL_KEY_TYPE", "canonical object keys must be strings"
                )
            normalized_key = _normalize_string(key)
            if normalized_key in normalized:
                raise CanonicalizationError(
                    "MH_CANONICAL_KEY_COLLISION",
                    "object keys collide after canonical normalization",
                )
            normalized[normalized_key] = member

        items: list[str] = []
        for key in sorted(normalized, key=lambda candidate: candidate.encode("utf-8")):
            encoded_value = self._encode_value(normalized[key], container_depth=container_depth)
            items.append(f"{_quote_string(key)}:{encoded_value}")
        return f"{{{','.join(items)}}}"


def canonical_json_bytes(
    value: object,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> bytes:
    """Serialize one supported value to bounded CanonicalJSONV1 UTF-8 bytes."""

    for name, limit in (
        ("max_depth", max_depth),
        ("max_nodes", max_nodes),
        ("max_bytes", max_bytes),
    ):
        if type(limit) is not int or limit < 1:
            raise ValueError(f"{name} must be a positive integer")

    text = _CanonicalEncoder(max_depth=max_depth, max_nodes=max_nodes).encode(value)
    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        raise CanonicalizationError(
            "MH_CANONICAL_SIZE", "the canonical value exceeds the UTF-8 byte limit"
        )
    return encoded


def canonical_json_text(
    value: object,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> str:
    """Serialize one supported value to canonical text without a trailing newline."""

    return canonical_json_bytes(
        value,
        max_depth=max_depth,
        max_nodes=max_nodes,
        max_bytes=max_bytes,
    ).decode("utf-8")
