from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from milhouse.core.canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    canonical_json_text,
)


def test_canonical_json_normalizes_strings_keys_and_line_endings() -> None:
    value = {
        "z": "line one\r\nline two\rline three",
        "e\u0301": "e\u0301",
        "a": "\b\t\n\f\r\u001f",
    }

    assert canonical_json_bytes(value) == (
        b'{"a":"\\b\\t\\n\\f\\n\\u001f",'
        b'"z":"line one\\nline two\\nline three",'
        b'"\xc3\xa9":"\xc3\xa9"}'
    )


def test_canonical_json_sorts_normalized_utf8_keys_and_preserves_array_order() -> None:
    assert canonical_json_bytes({"\ue000": [3, 2, 1], "\u0080": True, "a": None}) == (
        b'{"a":null,"\xc2\x80":true,"\xee\x80\x80":[3,2,1]}'
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (-0.0, b"0"),
        (100.0, b"100"),
        (1e-6, b"0.000001"),
        (1e-7, b"1e-7"),
        (5e-324, b"5e-324"),
        (333333333.33333329, b"333333333.3333333"),
        (0.002, b"0.002"),
        (1e-27, b"1e-27"),
    ],
)
def test_canonical_json_uses_ecmascript_number_format(value: float, expected: bytes) -> None:
    assert canonical_json_bytes(value) == expected


def test_integral_float_inside_int64_uses_the_equal_integer_bytes() -> None:
    value = 5.968169141485936e18
    equal_integer = int(value)

    assert canonical_json_bytes(value) == str(equal_integer).encode("ascii")
    assert canonical_json_bytes(value) == canonical_json_bytes(equal_integer)


def test_canonical_json_normalizes_aware_timestamps_to_truncated_utc_milliseconds() -> None:
    source = datetime(
        2026,
        7,
        21,
        12,
        34,
        56,
        987654,
        tzinfo=timezone(timedelta(hours=-5)),
    )

    assert canonical_json_bytes(source) == b'"2026-07-21T17:34:56.987Z"'


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ({"e\u0301": 1, "\u00e9": 2}, "MH_CANONICAL_KEY_COLLISION"),
        ({1: "not a string key"}, "MH_CANONICAL_KEY_TYPE"),
        ((1, 2), "MH_CANONICAL_TYPE"),
        ({1, 2}, "MH_CANONICAL_TYPE"),
        (b"bytes", "MH_CANONICAL_TYPE"),
        (Decimal("1.5"), "MH_CANONICAL_TYPE"),
        (float("nan"), "MH_CANONICAL_FLOAT"),
        (float("inf"), "MH_CANONICAL_FLOAT"),
        (2**63, "MH_CANONICAL_INTEGER_RANGE"),
        (float(2**63), "MH_CANONICAL_INTEGER_RANGE"),
        (1e20, "MH_CANONICAL_INTEGER_RANGE"),
        (1e21, "MH_CANONICAL_INTEGER_RANGE"),
        ("\ud800", "MH_CANONICAL_UNICODE"),
        (datetime(2026, 1, 1), "MH_CANONICAL_TIMESTAMP"),
        (
            datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=14))),
            "MH_CANONICAL_TIMESTAMP",
        ),
    ],
)
def test_canonical_json_rejects_ambiguous_or_unsupported_values(value: object, code: str) -> None:
    with pytest.raises(CanonicalizationError) as captured:
        canonical_json_bytes(value)

    assert captured.value.code == code
    assert repr(value) not in str(captured.value)


def test_canonical_json_enforces_depth_node_and_byte_bounds() -> None:
    nested: object = 0
    for _ in range(33):
        nested = [nested]

    with pytest.raises(CanonicalizationError) as depth_error:
        canonical_json_bytes(nested)
    assert depth_error.value.code == "MH_CANONICAL_DEPTH"

    with pytest.raises(CanonicalizationError) as node_error:
        canonical_json_bytes([0, 1, 2], max_nodes=3)
    assert node_error.value.code == "MH_CANONICAL_NODES"

    with pytest.raises(CanonicalizationError) as byte_error:
        canonical_json_bytes("abcd", max_bytes=5)
    assert byte_error.value.code == "MH_CANONICAL_SIZE"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("max_depth", 0),
        ("max_nodes", -1),
        ("max_bytes", True),
        ("max_bytes", 1.5),
    ],
)
def test_canonical_json_rejects_invalid_resource_limits(name: str, value: object) -> None:
    limits: dict[str, object] = {
        "max_depth": 32,
        "max_nodes": 10_000,
        "max_bytes": 262_144,
    }
    limits[name] = value

    with pytest.raises(ValueError, match=f"{name} must be a positive integer"):
        canonical_json_bytes({"valid": True}, **limits)  # type: ignore[arg-type]


def test_canonical_json_text_returns_the_same_canonical_wire_without_newline() -> None:
    assert canonical_json_text({"status": "ok"}) == '{"status":"ok"}'
