from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest

import milhouse.core as core
import milhouse.core.clock as clock_module
from milhouse.core.clock import (
    Clock,
    FixedClock,
    MonotonicClock,
    SystemClock,
    TimeError,
    WallClock,
    _parse_bounded_duration_seconds,
    format_timestamp,
    truncate_to_milliseconds,
)


class _MissingOffset(tzinfo):
    def utcoffset(self, value: datetime | None) -> None:
        return None

    def dst(self, value: datetime | None) -> None:
        return None

    def tzname(self, value: datetime | None) -> str:
        return "missing-offset"


class _StringSubclass(str):
    pass


def test_fixed_clock_returns_one_normalized_instant() -> None:
    source = datetime(2026, 7, 21, 1, 2, 3, 456789, tzinfo=timezone(timedelta(hours=2)))
    clock = FixedClock(source, monotonic_nanoseconds=42)

    assert clock.now() == datetime(2026, 7, 20, 23, 2, 3, 456000, tzinfo=UTC)
    assert clock.monotonic_ns() == 42
    assert format_timestamp(clock.now()) == "2026-07-20T23:02:03.456Z"


def test_fixed_clock_defaults_to_zero_monotonic_nanoseconds() -> None:
    clock = FixedClock(datetime(2026, 7, 21, tzinfo=UTC))

    assert clock.monotonic_ns() == 0


@pytest.mark.parametrize("value", (-1, True, 1.5, "1"))
def test_fixed_clock_rejects_noncanonical_monotonic_readings(value: object) -> None:
    with pytest.raises(TimeError) as captured:
        FixedClock(
            datetime(2026, 7, 21, tzinfo=UTC),
            monotonic_nanoseconds=value,  # type: ignore[arg-type]
        )

    assert captured.value.code == "MH_TIME_MONOTONIC"


def test_fixed_clock_monotonic_argument_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        FixedClock(datetime(2026, 7, 21, tzinfo=UTC), 1)  # type: ignore[misc]


def test_system_clock_uses_utc_wall_time_and_process_monotonic_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = datetime(2026, 7, 21, 1, 2, 3, 456789, tzinfo=UTC)

    class _KnownDateTime:
        @classmethod
        def now(cls, selected_timezone: tzinfo) -> datetime:
            assert selected_timezone is UTC
            return source

    monkeypatch.setattr(clock_module, "datetime", _KnownDateTime)
    monkeypatch.setattr(clock_module.time, "monotonic_ns", lambda: 987_654_321)
    clock = SystemClock()

    assert clock.now() == datetime(2026, 7, 21, 1, 2, 3, 456000, tzinfo=UTC)
    assert clock.monotonic_ns() == 987_654_321


def test_system_clock_is_aware_utc_and_millisecond_bounded() -> None:
    clock = SystemClock()
    observed = clock.now()
    first_monotonic = clock.monotonic_ns()
    second_monotonic = clock.monotonic_ns()

    assert observed.tzinfo is UTC
    assert observed.microsecond % 1000 == 0
    assert type(first_monotonic) is int
    assert second_monotonic >= first_monotonic >= 0


def test_clock_protocols_are_exported_from_the_core_namespace() -> None:
    assert core.WallClock is WallClock
    assert core.MonotonicClock is MonotonicClock
    assert core.Clock is Clock
    assert core.FixedClock is FixedClock
    assert core.SystemClock is SystemClock
    assert core.TimeError is TimeError


def test_clock_rejects_naive_instants() -> None:
    with pytest.raises(TimeError) as captured:
        truncate_to_milliseconds(datetime(2026, 7, 21))

    assert captured.value.code == "MH_TIME_NAIVE"


def test_clock_rejects_timezone_without_a_defined_offset() -> None:
    with pytest.raises(TimeError) as captured:
        truncate_to_milliseconds(datetime(2026, 7, 21, tzinfo=_MissingOffset()))

    assert captured.value.code == "MH_TIME_NAIVE"


@pytest.mark.parametrize(
    ("value", "expected_seconds"),
    (
        ("0s", 0),
        ("9s", 9),
        ("2m", 120),
        ("3h", 10_800),
        ("4d", 345_600),
        ("999999999999999999s", 999_999_999_999_999_999),
    ),
)
def test_duration_parser_accepts_canonical_ascii_elapsed_durations(
    value: str,
    expected_seconds: int,
) -> None:
    assert (
        _parse_bounded_duration_seconds(
            value,
            minimum_seconds=0,
            maximum_seconds=expected_seconds,
        )
        == expected_seconds
    )


def test_duration_days_are_fixed_elapsed_seconds() -> None:
    assert (
        _parse_bounded_duration_seconds(
            "1d",
            minimum_seconds=86_400,
            maximum_seconds=86_400,
        )
        == 86_400
    )


@pytest.mark.parametrize(
    "value",
    (
        "",
        "00s",
        "01s",
        "+1s",
        "-1s",
        "1.0s",
        "1e3s",
        " 1s",
        "1s ",
        "1 s",
        "1\ts",
        "1\ns",
        "1\x00s",
        "1S",
        "1w",
        "1m30s",
        "\uff11s",
        "\u0661s",
        "1\u200bs",
        "1000000000000000000s",
    ),
)
def test_duration_parser_rejects_noncanonical_grammar(value: str) -> None:
    with pytest.raises(TimeError) as captured:
        _parse_bounded_duration_seconds(
            value,
            minimum_seconds=0,
            maximum_seconds=10**30,
        )

    assert captured.value.code == "MH_TIME_DURATION_FORMAT"
    assert str(captured.value) == ("MH_TIME_DURATION_FORMAT: expected one canonical ASCII duration")


@pytest.mark.parametrize("value", (None, 1, True, b"1s", _StringSubclass("1s")))
def test_duration_parser_rejects_non_string_or_subclass_values(value: object) -> None:
    with pytest.raises(TimeError) as captured:
        _parse_bounded_duration_seconds(
            value,
            minimum_seconds=0,
            maximum_seconds=1,
        )

    assert captured.value.code == "MH_TIME_DURATION_FORMAT"


@pytest.mark.parametrize(
    ("minimum_seconds", "maximum_seconds"),
    (
        (-1, 0),
        (2, 1),
        (True, 1),
        (0, False),
        (0.0, 1),
        (0, 1.0),
        ("0", 1),
        (0, "1"),
    ),
)
def test_duration_parser_rejects_invalid_caller_bounds(
    minimum_seconds: object,
    maximum_seconds: object,
) -> None:
    with pytest.raises(TimeError) as captured:
        _parse_bounded_duration_seconds(
            "1s",
            minimum_seconds=minimum_seconds,
            maximum_seconds=maximum_seconds,
        )

    assert captured.value.code == "MH_TIME_DURATION_BOUNDS"
    assert str(captured.value) == (
        "MH_TIME_DURATION_BOUNDS: duration bounds must be nonnegative integers"
        if type(minimum_seconds) is not int or type(maximum_seconds) is not int
        else "MH_TIME_DURATION_BOUNDS: duration bounds must be nonnegative and ordered"
    )


@pytest.mark.parametrize(
    ("value", "minimum_seconds", "maximum_seconds"),
    (("1s", 2, 2), ("3s", 0, 2)),
)
def test_duration_parser_enforces_inclusive_caller_bounds(
    value: str,
    minimum_seconds: int,
    maximum_seconds: int,
) -> None:
    with pytest.raises(TimeError) as captured:
        _parse_bounded_duration_seconds(
            value,
            minimum_seconds=minimum_seconds,
            maximum_seconds=maximum_seconds,
        )

    assert captured.value.code == "MH_TIME_DURATION_RANGE"
    assert str(captured.value) == "MH_TIME_DURATION_RANGE: duration is outside the allowed range"


def test_time_error_has_stable_code_message_and_repr() -> None:
    with pytest.raises(TimeError) as captured:
        _parse_bounded_duration_seconds(
            "01s",
            minimum_seconds=0,
            maximum_seconds=1,
        )

    assert captured.value.code == "MH_TIME_DURATION_FORMAT"
    assert captured.value.message == "expected one canonical ASCII duration"
    assert captured.value.args == (
        "MH_TIME_DURATION_FORMAT: expected one canonical ASCII duration",
    )
    assert repr(captured.value) == (
        "TimeError(code='MH_TIME_DURATION_FORMAT', message='expected one canonical ASCII duration')"
    )
