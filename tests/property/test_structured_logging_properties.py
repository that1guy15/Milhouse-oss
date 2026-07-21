from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from milhouse.config import ConfigError
from milhouse.core import FixedClock
from milhouse.core.errors import UNEXPECTED_ERROR_CODE
from milhouse.core.logging import (
    LogEventSpec,
    LogFingerprintSpec,
    LoggingError,
    LogLevel,
    LogMetric,
    LogMetricKind,
    LogMetricSpec,
    StructuredLogEventV1,
    StructuredLogger,
)
from milhouse.privacy import Pseudonymizer

_VALUE = LogMetricSpec("value", LogMetricKind.GAUGE)
_FLAG = LogMetricSpec("flag", LogMetricKind.FLAG)
_FINGERPRINT = LogFingerprintSpec("logging")
_FAILED = LogEventSpec(
    "operation.failed",
    LogLevel.ERROR,
    metrics=(_VALUE, _FLAG),
    error_codes=("config.test.failure",),
    allow_unexpected_error=True,
    fingerprint=_FINGERPRINT,
)


class _Sink:
    def __init__(self) -> None:
        self.event: StructuredLogEventV1 | None = None

    def write(self, event: StructuredLogEventV1) -> None:
        self.event = event


def _logger() -> tuple[StructuredLogger, _Sink]:
    sink = _Sink()
    clock = FixedClock(datetime(2026, 7, 21, tzinfo=UTC))
    return (
        StructuredLogger(
            catalog=(_FAILED,),
            clock=clock,
            sink=sink,
            pseudonymizer=Pseudonymizer(b"p" * 32),
        ),
        sink,
    )


@pytest.mark.property
@given(payload=st.binary(min_size=4, max_size=64))
def test_error_events_never_contain_runtime_exception_text(payload: bytes) -> None:
    canary = f"runtime_canary_{payload.hex()}_end"
    logger, sink = _logger()

    emitted = logger.emit(
        _FAILED,
        error=ConfigError("config.test.failure", canary),
    )

    assert emitted is sink.event
    assert canary not in repr(emitted)


@pytest.mark.property
@given(payload=st.binary(min_size=4, max_size=64))
def test_unknown_exception_graphs_always_reduce_to_fixed_metadata(payload: bytes) -> None:
    canary = f"runtime_canary_{payload.hex()}_end"
    error = RuntimeError(canary)
    error.__cause__ = ValueError(canary)
    error.__context__ = OSError(canary)
    error.add_note(canary)
    logger, _sink = _logger()

    emitted = logger.emit(_FAILED, error=error)

    assert emitted is not None
    assert emitted.error is not None
    assert emitted.error.code == UNEXPECTED_ERROR_CODE
    assert canary not in repr(emitted)


@pytest.mark.property
@given(payload=st.binary(min_size=4, max_size=64))
def test_runtime_text_cannot_become_metric_or_raw_fingerprint(payload: bytes) -> None:
    canary = f"runtime_canary_{payload.hex()}_end"
    with pytest.raises(LoggingError) as captured:
        LogMetric(_VALUE, canary)  # type: ignore[arg-type]
    assert canary not in str(captured.value)

    logger, _sink = _logger()
    event = logger.emit(_FAILED, fingerprint_value=canary)

    assert event is not None
    assert event.fingerprint is not None
    assert canary not in event.fingerprint
    assert canary not in repr(event)


@pytest.mark.property
@given(payload=st.binary(min_size=4, max_size=32))
def test_grammar_shaped_runtime_error_code_reduces_to_fixed_metadata(payload: bytes) -> None:
    canary = f"runtime_{payload.hex()}_end"
    logger, _sink = _logger()

    event = logger.emit(_FAILED, error=ConfigError(f"config.{canary}", canary))

    assert event is not None
    assert event.error is not None
    assert event.error.code == UNEXPECTED_ERROR_CODE
    assert canary not in repr(event)


@pytest.mark.property
@given(
    value=st.one_of(
        st.booleans(),
        st.integers(min_value=-(2**63), max_value=2**63 - 1),
        st.floats(
            min_value=float(-(2**63)),
            max_value=float(2**63 - 1_024),
            allow_nan=False,
            allow_infinity=False,
        ),
    )
)
def test_safe_exact_scalar_metrics_round_trip(value: bool | int | float) -> None:
    spec = _FLAG if type(value) is bool else _VALUE
    metric = LogMetric(spec, value)

    assert type(metric.value) is type(value)
    assert metric.value == value
