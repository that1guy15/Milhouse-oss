from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import UTC, datetime

import pytest

from milhouse.core.log_wire import (
    MAX_HEADER_LINE_BYTES,
    MAX_TRAILER_LINE_BYTES,
    StructuredLogHeaderV1,
    StructuredLogTrailerV1,
    structured_log_content_sha256,
    structured_log_header_line,
    structured_log_trailer_line,
)
from milhouse.core.logging import LoggingError

_OPENED = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
_CLOSED = datetime(2026, 7, 21, 12, 5, 0, tzinfo=UTC)
_LAST = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
_EXPIRES = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
_DIGEST = "b" * 64


def _header() -> StructuredLogHeaderV1:
    return StructuredLogHeaderV1(sequence=1, opened_at=_OPENED, retention_days=14)


def _trailer(**overrides: object) -> StructuredLogTrailerV1:
    fields: dict[str, object] = {
        "sequence": 1,
        "closed_at": _CLOSED,
        "last_event_at": _LAST,
        "event_count": 2,
        "content_sha256": _DIGEST,
        "expires_at": _EXPIRES,
    }
    fields.update(overrides)
    return StructuredLogTrailerV1(**fields)  # type: ignore[arg-type]


def test_header_line_golden_bytes() -> None:
    assert structured_log_header_line(_header()) == (
        b'{"line":"header","opened_at":"2026-07-21T12:00:00.000Z","retention_days":14,'
        b'"schema":1,"scope":"installation","sequence":1}\n'
    )


def test_trailer_line_golden_bytes() -> None:
    assert structured_log_trailer_line(_trailer()) == (
        b'{"closed_at":"2026-07-21T12:05:00.000Z","content_sha256":"' + (b"b" * 64) + b'",'
        b'"event_count":2,"expires_at":"2026-08-04T12:00:00.000Z",'
        b'"last_event_at":"2026-07-21T12:00:00.000Z","line":"trailer","schema":1,"sequence":1}\n'
    )


def test_header_and_trailer_are_closed_key_sets_with_one_lf() -> None:
    for line, keys in (
        (
            structured_log_header_line(_header()),
            {"line", "opened_at", "retention_days", "schema", "scope", "sequence"},
        ),
        (
            structured_log_trailer_line(_trailer()),
            {
                "closed_at",
                "content_sha256",
                "event_count",
                "expires_at",
                "last_event_at",
                "line",
                "schema",
                "sequence",
            },
        ),
    ):
        assert line.endswith(b"\n")
        assert line.count(b"\n") == 1
        assert set(json.loads(line)) == keys


def test_content_sha256_covers_header_plus_events_including_lf_excluding_trailer() -> None:
    header_line = structured_log_header_line(_header())
    events = [b'{"line":"event","n":1}\n', b'{"line":"event","n":2}\n']
    trailer_line = structured_log_trailer_line(_trailer())

    digest = structured_log_content_sha256(header_line, events)

    assert digest == hashlib.sha256(header_line + b"".join(events)).hexdigest()
    # the trailer bytes must not be part of the digest
    assert digest != hashlib.sha256(header_line + b"".join(events) + trailer_line).hexdigest()


def test_content_sha256_of_an_empty_segment_is_the_header_only() -> None:
    header_line = structured_log_header_line(_header())
    assert structured_log_content_sha256(header_line, []) == hashlib.sha256(header_line).hexdigest()


def test_empty_segment_trailer_has_no_last_event_time() -> None:
    empty = _trailer(event_count=0, last_event_at=None, content_sha256="a" * 64)
    decoded = json.loads(structured_log_trailer_line(empty))
    assert decoded["event_count"] == 0
    assert decoded["last_event_at"] is None

    with pytest.raises(LoggingError) as captured:
        _trailer(event_count=0, last_event_at=_LAST)
    assert captured.value.code == "MH_LOG_TRAILER_EVENT_TIME"

    with pytest.raises(LoggingError) as missing:
        _trailer(event_count=2, last_event_at=None)
    assert missing.value.code == "MH_LOG_TRAILER_EVENT_TIME"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("sequence", 0, "MH_LOG_SEQUENCE"),
        ("sequence", 2**63, "MH_LOG_SEQUENCE"),
        ("opened_at", datetime(2026, 7, 21, 12, 0, 0), "MH_LOG_HEADER_TIME"),
        ("retention_days", 0, "MH_LOG_HEADER_RETENTION"),
        ("retention_days", True, "MH_LOG_HEADER_RETENTION"),
    ],
)
def test_header_rejects_invalid_fields(field: str, value: object, code: str) -> None:
    fields: dict[str, object] = {"sequence": 1, "opened_at": _OPENED, "retention_days": 14}
    fields[field] = value
    with pytest.raises(LoggingError) as captured:
        StructuredLogHeaderV1(**fields)  # type: ignore[arg-type]
    assert captured.value.code == code


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("closed_at", datetime(2026, 7, 21, 12, 5, 0), "MH_LOG_TRAILER_TIME"),
        ("expires_at", datetime(2026, 8, 4, 12, 0, 0), "MH_LOG_TRAILER_TIME"),
        ("event_count", -1, "MH_LOG_TRAILER_COUNT"),
        ("content_sha256", "B" * 64, "MH_LOG_TRAILER_DIGEST"),
        ("content_sha256", "b" * 63, "MH_LOG_TRAILER_DIGEST"),
        ("content_sha256", 123, "MH_LOG_TRAILER_DIGEST"),
    ],
)
def test_trailer_rejects_invalid_fields(field: str, value: object, code: str) -> None:
    with pytest.raises(LoggingError) as captured:
        _trailer(**{field: value})
    assert captured.value.code == code


def test_header_and_trailer_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        _header().sequence = 2  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        _trailer().event_count = 3  # type: ignore[misc]


def test_header_and_trailer_projections_reject_foreign_values() -> None:
    with pytest.raises(LoggingError) as header:
        structured_log_header_line({"line": "header"})  # type: ignore[arg-type]
    assert header.value.code == "MH_LOG_HEADER"
    with pytest.raises(LoggingError) as trailer:
        structured_log_trailer_line({"line": "trailer"})  # type: ignore[arg-type]
    assert trailer.value.code == "MH_LOG_TRAILER"


def test_header_and_trailer_lines_stay_within_the_byte_bound() -> None:
    assert len(structured_log_header_line(_header())) <= MAX_HEADER_LINE_BYTES
    assert len(structured_log_trailer_line(_trailer())) <= MAX_TRAILER_LINE_BYTES
