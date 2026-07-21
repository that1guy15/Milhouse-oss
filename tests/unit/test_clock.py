from datetime import UTC, datetime, timedelta, timezone

import pytest

from milhouse.core.clock import FixedClock, SystemClock, format_timestamp, truncate_to_milliseconds


def test_fixed_clock_returns_one_normalized_instant() -> None:
    source = datetime(2026, 7, 21, 1, 2, 3, 456789, tzinfo=timezone(timedelta(hours=2)))
    clock = FixedClock(source)

    assert clock.now() == datetime(2026, 7, 20, 23, 2, 3, 456000, tzinfo=UTC)
    assert format_timestamp(clock.now()) == "2026-07-20T23:02:03.456Z"


def test_system_clock_is_aware_utc_and_millisecond_bounded() -> None:
    observed = SystemClock().now()

    assert observed.tzinfo is UTC
    assert observed.microsecond % 1000 == 0


def test_clock_rejects_naive_instants() -> None:
    with pytest.raises(ValueError, match="MH_TIME_NAIVE"):
        truncate_to_milliseconds(datetime(2026, 7, 21))
