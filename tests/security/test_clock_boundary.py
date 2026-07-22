from __future__ import annotations

import secrets
import traceback
from collections.abc import Callable
from datetime import datetime, timedelta, tzinfo

import pytest

import milhouse.core.clock as clock_module
from milhouse.core.clock import (
    SystemClock,
    TimeError,
    _parse_bounded_duration_seconds,
    format_timestamp,
)


class _HostileValue:
    def __init__(self, private_value: str) -> None:
        self.private_value = private_value

    def __str__(self) -> str:
        return self.private_value

    def __repr__(self) -> str:
        return self.private_value


class _HostileTimezone(tzinfo):
    def __init__(
        self,
        private_value: str,
        *,
        successful_reads: int,
        failure_type: type[BaseException] = RuntimeError,
    ) -> None:
        self.private_value = private_value
        self.successful_reads = successful_reads
        self.failure_type = failure_type

    def utcoffset(self, value: datetime | None) -> timedelta:
        if self.successful_reads:
            self.successful_reads -= 1
            return timedelta(0)
        raise self.failure_type(self.private_value)

    def dst(self, value: datetime | None) -> timedelta:
        return timedelta(0)

    def tzname(self, value: datetime | None) -> str:
        return "hostile"


def _time_rejection_is_value_free(
    operation: Callable[[], object],
    *,
    private_value: str,
) -> tuple[bool, str | None, bool, bool, bool]:
    try:
        operation()
    except Exception as error:
        rendered = "".join(traceback.format_exception(error))
        return (
            isinstance(error, TimeError),
            getattr(error, "code", None),
            private_value not in rendered,
            error.__cause__ is None,
            error.__context__ is None,
        )
    return False, None, True, True, True


def _duration_rejection_is_value_free(
    value: object,
    *,
    minimum_seconds: object = 0,
    maximum_seconds: object = 1,
    private_value: str,
) -> tuple[bool, str | None, bool]:
    try:
        _parse_bounded_duration_seconds(
            value,
            minimum_seconds=minimum_seconds,
            maximum_seconds=maximum_seconds,
        )
    except Exception as error:  # reduce the failure before pytest renders the candidate
        rendered = "".join(traceback.format_exception(error))
        return (
            isinstance(error, TimeError),
            getattr(error, "code", None),
            private_value not in rendered,
        )
    return False, None, True


@pytest.mark.security
def test_duration_format_error_never_echoes_runtime_generated_input(
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_value = secrets.token_urlsafe(32)
    candidate = f"1s:{private_value}"

    result = _duration_rejection_is_value_free(candidate, private_value=private_value)
    captured = capsys.readouterr()
    candidate = ""
    del private_value

    assert result == (True, "MH_TIME_DURATION_FORMAT", True)
    assert not captured.out and not captured.err


@pytest.mark.security
def test_duration_type_error_never_renders_a_hostile_object() -> None:
    private_value = secrets.token_urlsafe(32)
    candidate = _HostileValue(private_value)

    result = _duration_rejection_is_value_free(candidate, private_value=private_value)
    candidate.private_value = ""
    del candidate, private_value

    assert result == (True, "MH_TIME_DURATION_FORMAT", True)


@pytest.mark.security
def test_duration_bounds_error_never_renders_a_hostile_bound() -> None:
    private_value = secrets.token_urlsafe(32)
    hostile_bound = _HostileValue(private_value)

    result = _duration_rejection_is_value_free(
        "1s",
        minimum_seconds=hostile_bound,
        private_value=private_value,
    )
    hostile_bound.private_value = ""
    del hostile_bound, private_value

    assert result == (True, "MH_TIME_DURATION_BOUNDS", True)


@pytest.mark.security
@pytest.mark.parametrize(
    "candidate",
    (
        "\u00001s",
        "1s\u0000",
        "\u20281s",
        "1s\u2029",
        "\ufeff1s",
        "1\u2060s",
        "1\uff53",
        "\uff10s",
    ),
)
def test_duration_parser_rejects_control_and_unicode_lookalike_forms(candidate: str) -> None:
    with pytest.raises(TimeError) as captured:
        _parse_bounded_duration_seconds(
            candidate,
            minimum_seconds=0,
            maximum_seconds=1,
        )

    assert captured.value.code == "MH_TIME_DURATION_FORMAT"


@pytest.mark.security
def test_timestamp_type_error_never_renders_a_hostile_object() -> None:
    private_value = secrets.token_urlsafe(32)
    candidate = _HostileValue(private_value)

    result = _time_rejection_is_value_free(
        lambda: format_timestamp(candidate),  # type: ignore[arg-type]
        private_value=private_value,
    )
    candidate.private_value = ""
    private_value = ""

    assert result == (True, "MH_TIME_TIMESTAMP", True, True, True)


@pytest.mark.security
@pytest.mark.parametrize("successful_reads", (0, 1))
def test_timestamp_normalization_never_leaks_timezone_failures(successful_reads: int) -> None:
    private_value = secrets.token_urlsafe(32)
    hostile_timezone = _HostileTimezone(
        private_value,
        successful_reads=successful_reads,
    )
    candidate = datetime(2026, 7, 21, tzinfo=hostile_timezone)

    result = _time_rejection_is_value_free(
        lambda: format_timestamp(candidate),
        private_value=private_value,
    )
    hostile_timezone.private_value = ""
    private_value = ""

    assert result == (True, "MH_TIME_TIMESTAMP", True, True, True)


class _PrivateBaseFailure(BaseException):
    pass


@pytest.mark.security
@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit, _PrivateBaseFailure])
def test_timestamp_normalization_contains_secret_bearing_base_exceptions(
    failure_type: type[BaseException],
) -> None:
    private_value = secrets.token_urlsafe(32)
    hostile_timezone = _HostileTimezone(
        private_value,
        successful_reads=0,
        failure_type=failure_type,
    )
    candidate = datetime(2026, 7, 21, tzinfo=hostile_timezone)

    result = _time_rejection_is_value_free(
        lambda: format_timestamp(candidate),
        private_value=private_value,
    )

    assert result == (True, "MH_TIME_TIMESTAMP", True, True, True)


@pytest.mark.security
def test_system_wall_clock_failure_is_stable_and_value_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_value = secrets.token_urlsafe(32)

    class _FailingDateTime:
        @classmethod
        def now(cls, selected_timezone: tzinfo) -> datetime:
            raise RuntimeError(private_value)

    monkeypatch.setattr(clock_module, "datetime", _FailingDateTime)
    result = _time_rejection_is_value_free(SystemClock().now, private_value=private_value)
    private_value = ""

    assert result == (True, "MH_TIME_WALL", True, True, True)


@pytest.mark.security
def test_system_monotonic_clock_failure_is_stable_and_value_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_value = secrets.token_urlsafe(32)

    def fail_read() -> int:
        raise RuntimeError(private_value)

    monkeypatch.setattr(clock_module.time, "monotonic_ns", fail_read)
    result = _time_rejection_is_value_free(SystemClock().monotonic_ns, private_value=private_value)
    private_value = ""

    assert result == (True, "MH_TIME_MONOTONIC", True, True, True)
