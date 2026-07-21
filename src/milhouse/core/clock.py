"""UTC clock injection and canonical timestamp handling."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Source of wall-clock instants for deterministic domain construction."""

    def now(self) -> datetime:
        """Return an aware UTC instant truncated to milliseconds."""


def truncate_to_milliseconds(value: datetime) -> datetime:
    """Normalize an aware instant to UTC and truncate sub-millisecond precision."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("MH_TIME_NAIVE: an aware timestamp is required")
    normalized = value.astimezone(UTC)
    return normalized.replace(microsecond=(normalized.microsecond // 1000) * 1000)


def format_timestamp(value: datetime) -> str:
    """Return the canonical RFC3339 UTC millisecond representation."""

    normalized = truncate_to_milliseconds(value)
    return (
        f"{normalized.year:04d}-{normalized.month:02d}-{normalized.day:02d}"
        f"T{normalized.hour:02d}:{normalized.minute:02d}:{normalized.second:02d}."
        f"{normalized.microsecond // 1000:03d}Z"
    )


@dataclass(frozen=True, slots=True)
class FixedClock:
    """Clock whose value is fixed for tests and reproducible operations."""

    instant: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "instant", truncate_to_milliseconds(self.instant))

    def now(self) -> datetime:
        return self.instant


@dataclass(frozen=True, slots=True)
class SystemClock:
    """Production wall clock."""

    def now(self) -> datetime:
        return truncate_to_milliseconds(datetime.now(UTC))
