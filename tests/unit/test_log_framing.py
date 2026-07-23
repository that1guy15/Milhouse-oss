from __future__ import annotations

import dataclasses
import hashlib
import json
import traceback
from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest

from milhouse.config._models import _DAYS_MAX
from milhouse.core.log_wire import (
    MAX_HEADER_LINE_BYTES,
    MAX_LOG_RETENTION_DAYS,
    MAX_TRAILER_LINE_BYTES,
    StructuredLogHeaderV1,
    StructuredLogTrailerV1,
    structured_log_content_sha256,
    structured_log_header_line,
    structured_log_trailer_line,
)
from milhouse.core.logging import LoggingError

_SECRET_CANARY = "SYNTHETIC_SECRET_CANARY"


class _HostileTz(tzinfo):
    """A ``tzinfo`` whose offset accessors raise, simulating adversarial timestamp input."""

    def utcoffset(self, dt: datetime | None) -> timedelta:
        raise ValueError(_SECRET_CANARY)

    def tzname(self, dt: datetime | None) -> str:
        raise ValueError(_SECRET_CANARY)

    def dst(self, dt: datetime | None) -> timedelta:
        raise ValueError(_SECRET_CANARY)


def _hostile_timestamp() -> datetime:
    return datetime(2026, 7, 21, 12, 0, 0, tzinfo=_HostileTz())


def _leak_surfaces(error: BaseException) -> str:
    """Concatenate every surface a caught error could leak source detail through.

    The exception graph is walked recursively along ``__cause__`` and ``__context__`` so a canary
    hidden anywhere in the chain (including notes and rendered tracebacks) is detected.
    """

    seen: set[int] = set()
    parts: list[str] = []

    def visit(exc: BaseException | None) -> None:
        if exc is None or id(exc) in seen:
            return
        seen.add(id(exc))
        parts.append(str(exc))
        parts.append(repr(exc))
        parts.append(repr(exc.args))
        parts.extend(str(note) for note in getattr(exc, "__notes__", ()) or ())
        parts.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        visit(exc.__cause__)
        visit(exc.__context__)

    visit(error)
    return " || ".join(parts)


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


def test_retention_bound_equals_the_config_retention_ceiling() -> None:
    # The wire retention bound and the config `[retention].logs_days` ceiling are one shared value;
    # this test fails loudly if either drifts.
    assert MAX_LOG_RETENTION_DAYS == _DAYS_MAX


def test_header_accepts_retention_at_the_upper_bound() -> None:
    header = StructuredLogHeaderV1(
        sequence=1, opened_at=_OPENED, retention_days=MAX_LOG_RETENTION_DAYS
    )
    assert header.retention_days == MAX_LOG_RETENTION_DAYS
    assert (
        json.loads(structured_log_header_line(header))["retention_days"] == MAX_LOG_RETENTION_DAYS
    )


def test_header_rejects_retention_above_the_upper_bound() -> None:
    with pytest.raises(LoggingError) as captured:
        StructuredLogHeaderV1(
            sequence=1, opened_at=_OPENED, retention_days=MAX_LOG_RETENTION_DAYS + 1
        )
    assert captured.value.code == "MH_LOG_HEADER_RETENTION"


def test_aware_non_utc_timestamps_are_normalized_to_utc() -> None:
    # 07:00 at UTC-5 is 12:00Z; the wire must store and project the normalized UTC instant.
    eastern = datetime(2026, 7, 21, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5)))
    header = StructuredLogHeaderV1(sequence=1, opened_at=eastern, retention_days=14)
    assert header.opened_at.tzinfo is UTC
    assert json.loads(structured_log_header_line(header))["opened_at"] == "2026-07-21T12:00:00.000Z"


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("opened_at", "MH_LOG_HEADER_TIME"),
    ],
)
def test_header_hostile_timestamp_fails_closed_without_leaking(field: str, code: str) -> None:
    fields: dict[str, object] = {"sequence": 1, "opened_at": _OPENED, "retention_days": 14}
    fields[field] = _hostile_timestamp()
    with pytest.raises(LoggingError) as captured:
        StructuredLogHeaderV1(**fields)  # type: ignore[arg-type]
    assert captured.value.code == code
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert _SECRET_CANARY not in _leak_surfaces(captured.value)


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("closed_at", "MH_LOG_TRAILER_TIME"),
        ("expires_at", "MH_LOG_TRAILER_TIME"),
        ("last_event_at", "MH_LOG_TRAILER_EVENT_TIME"),
    ],
)
def test_trailer_hostile_timestamp_fails_closed_without_leaking(field: str, code: str) -> None:
    with pytest.raises(LoggingError) as captured:
        _trailer(**{field: _hostile_timestamp()})
    assert captured.value.code == code
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert _SECRET_CANARY not in _leak_surfaces(captured.value)


def test_digest_hostile_iterable_fails_closed_without_leaking() -> None:
    class _HostileIter:
        def __iter__(self) -> object:
            raise RuntimeError(_SECRET_CANARY)

    class _HostileNext:
        def __iter__(self) -> object:
            return self

        def __next__(self) -> bytes:
            raise RuntimeError(_SECRET_CANARY)

    for event_lines in (_HostileIter(), _HostileNext()):
        with pytest.raises(LoggingError) as captured:
            structured_log_content_sha256(b"header\n", event_lines)  # type: ignore[arg-type]
        assert captured.value.code == "MH_LOG_DIGEST"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
        assert _SECRET_CANARY not in _leak_surfaces(captured.value)


def test_digest_rejects_non_bytes_event_line_without_partial_leak() -> None:
    with pytest.raises(LoggingError) as captured:
        structured_log_content_sha256(b"header\n", [b"ok\n", "not-bytes"])  # type: ignore[list-item]
    assert captured.value.code == "MH_LOG_DIGEST"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
