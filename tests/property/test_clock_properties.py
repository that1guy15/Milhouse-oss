from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from milhouse.core.clock import (
    TimeError,
    _parse_bounded_duration_seconds,
    format_timestamp,
    truncate_to_milliseconds,
)

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3_600, "d": 86_400}
_CANONICAL_AMOUNTS = st.integers(min_value=0, max_value=10**18 - 1)
_UNITS = st.sampled_from(tuple(_UNIT_SECONDS))
_NON_ASCII_DECIMAL_DIGITS = st.characters(whitelist_categories=("Nd",)).filter(
    lambda value: value not in "0123456789"
)


@pytest.mark.property
@given(amount=_CANONICAL_AMOUNTS, unit=_UNITS)
def test_canonical_duration_round_trips_to_exact_elapsed_seconds(amount: int, unit: str) -> None:
    expected = amount * _UNIT_SECONDS[unit]

    parsed = _parse_bounded_duration_seconds(
        f"{amount}{unit}",
        minimum_seconds=expected,
        maximum_seconds=expected,
    )

    assert parsed == expected


@pytest.mark.property
@given(amount=st.integers(min_value=0, max_value=10**17 - 1), unit=_UNITS)
def test_every_leading_zero_duration_is_rejected(amount: int, unit: str) -> None:
    with pytest.raises(TimeError) as captured:
        _parse_bounded_duration_seconds(
            f"0{amount}{unit}",
            minimum_seconds=0,
            maximum_seconds=10**24,
        )

    assert captured.value.code == "MH_TIME_DURATION_FORMAT"


@pytest.mark.property
@given(
    digits=st.lists(_NON_ASCII_DECIMAL_DIGITS, min_size=1, max_size=18).map("".join),
    unit=_UNITS,
)
def test_unicode_decimal_digits_never_enter_the_ascii_duration_grammar(
    digits: str,
    unit: str,
) -> None:
    with pytest.raises(TimeError) as captured:
        _parse_bounded_duration_seconds(
            f"{digits}{unit}",
            minimum_seconds=0,
            maximum_seconds=10**24,
        )

    assert captured.value.code == "MH_TIME_DURATION_FORMAT"


@pytest.mark.property
@given(
    value=st.datetimes(
        min_value=datetime(1900, 1, 1),
        max_value=datetime(2099, 12, 31, 23, 59, 59, 999999),
        timezones=st.timezones(),
        allow_imaginary=False,
    )
)
def test_aware_instants_normalize_to_canonical_utc_milliseconds(value: datetime) -> None:
    normalized = truncate_to_milliseconds(value)
    source_utc = value.astimezone(UTC)
    discarded = source_utc - normalized

    assert normalized.tzinfo is UTC
    assert normalized.microsecond % 1000 == 0
    assert 0 <= discarded.total_seconds() < 0.001
    assert format_timestamp(value).endswith("Z")
    assert len(format_timestamp(value)) == 24
