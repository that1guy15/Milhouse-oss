"""Injected UTC and monotonic clocks plus strict internal duration parsing."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, TypeVar

from milhouse.core.errors import MilhouseValueError

_DATETIME_TYPE = datetime
_DURATION_PATTERN = re.compile(r"(0|[1-9][0-9]{0,17})([smhd])", flags=re.ASCII)
_MAX_DURATION_TEXT_LENGTH = 19
_SECONDS_PER_UNIT = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 24 * 60 * 60,
}
_T = TypeVar("_T")


class TimeError(MilhouseValueError):
    """A stable time-boundary failure that never renders the rejected value."""


class WallClock(Protocol):
    """Source of persisted wall-clock instants."""

    def now(self) -> datetime:
        """Return an aware UTC instant truncated to milliseconds."""


class MonotonicClock(Protocol):
    """Source of process-local elapsed-time readings that are never persisted."""

    def monotonic_ns(self) -> int:
        """Return a nonnegative monotonic reading in nanoseconds."""


class Clock(WallClock, MonotonicClock, Protocol):
    """Combined injectable wall and elapsed-time source."""


def _read_time_source(
    operation: Callable[[], _T],
    *,
    code: str,
    message: str,
) -> _T:
    """Translate backend failures without retaining their exception context."""

    try:
        return operation()
    except Exception:
        pass
    raise TimeError(code, message)


def _validate_monotonic_nanoseconds(value: object) -> int:
    if type(value) is not int or value < 0:
        raise TimeError(
            "MH_TIME_MONOTONIC",
            "a nonnegative integer monotonic reading is required",
        )
    return value


def truncate_to_milliseconds(value: datetime) -> datetime:
    """Normalize an aware instant to UTC and truncate sub-millisecond precision."""

    if type(value) is not _DATETIME_TYPE:
        raise TimeError("MH_TIME_TIMESTAMP", "a valid datetime is required")
    if value.tzinfo is None:
        raise TimeError("MH_TIME_NAIVE", "an aware timestamp is required")
    offset = _read_time_source(
        value.utcoffset,
        code="MH_TIME_TIMESTAMP",
        message="timestamp normalization failed",
    )
    if offset is None:
        raise TimeError("MH_TIME_NAIVE", "an aware timestamp is required")
    normalized = _read_time_source(
        lambda: value.astimezone(UTC),
        code="MH_TIME_TIMESTAMP",
        message="timestamp normalization failed",
    )
    return normalized.replace(microsecond=(normalized.microsecond // 1000) * 1000)


def format_timestamp(value: datetime) -> str:
    """Return the canonical RFC3339 UTC millisecond representation."""

    normalized = truncate_to_milliseconds(value)
    return (
        f"{normalized.year:04d}-{normalized.month:02d}-{normalized.day:02d}"
        f"T{normalized.hour:02d}:{normalized.minute:02d}:{normalized.second:02d}."
        f"{normalized.microsecond // 1000:03d}Z"
    )


def _parse_bounded_duration_seconds(
    value: object,
    *,
    minimum_seconds: object,
    maximum_seconds: object,
) -> int:
    """Parse one internal ASCII elapsed duration within explicit caller bounds.

    This is intentionally not a public CLI or persisted-data grammar.  Future owning surfaces must
    select and document their own bounds before wrapping it.  A day is exactly 86,400 elapsed
    seconds and has no calendar or daylight-saving semantics.
    """

    if type(minimum_seconds) is not int or type(maximum_seconds) is not int:
        raise TimeError(
            "MH_TIME_DURATION_BOUNDS",
            "duration bounds must be nonnegative integers",
        )
    if minimum_seconds < 0 or maximum_seconds < minimum_seconds:
        raise TimeError(
            "MH_TIME_DURATION_BOUNDS",
            "duration bounds must be nonnegative and ordered",
        )
    if type(value) is not str or not value or len(value) > _MAX_DURATION_TEXT_LENGTH:
        raise TimeError(
            "MH_TIME_DURATION_FORMAT",
            "expected one canonical ASCII duration",
        )
    match = _DURATION_PATTERN.fullmatch(value)
    if match is None:
        raise TimeError(
            "MH_TIME_DURATION_FORMAT",
            "expected one canonical ASCII duration",
        )
    amount = int(match.group(1))
    seconds = amount * _SECONDS_PER_UNIT[match.group(2)]
    if seconds < minimum_seconds or seconds > maximum_seconds:
        raise TimeError(
            "MH_TIME_DURATION_RANGE",
            "duration is outside the allowed range",
        )
    return seconds


@dataclass(frozen=True, slots=True)
class FixedClock:
    """Clock whose wall and monotonic values are fixed for deterministic operations."""

    instant: datetime
    monotonic_nanoseconds: int = field(default=0, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "instant", truncate_to_milliseconds(self.instant))
        object.__setattr__(
            self,
            "monotonic_nanoseconds",
            _validate_monotonic_nanoseconds(self.monotonic_nanoseconds),
        )

    def now(self) -> datetime:
        return self.instant

    def monotonic_ns(self) -> int:
        return self.monotonic_nanoseconds


@dataclass(frozen=True, slots=True)
class SystemClock:
    """Production UTC wall and process-local monotonic clock."""

    def now(self) -> datetime:
        value = _read_time_source(
            lambda: datetime.now(UTC),
            code="MH_TIME_WALL",
            message="wall clock read failed",
        )
        return truncate_to_milliseconds(value)

    def monotonic_ns(self) -> int:
        value = _read_time_source(
            time.monotonic_ns,
            code="MH_TIME_MONOTONIC",
            message="monotonic clock read failed",
        )
        return _validate_monotonic_nanoseconds(value)
