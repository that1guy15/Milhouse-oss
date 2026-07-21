from __future__ import annotations

import traceback
from datetime import UTC, datetime

import pytest

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

_RECORDS = LogMetricSpec("records", LogMetricKind.COUNT)
_FINGERPRINT = LogFingerprintSpec("logging")
_FAILED = LogEventSpec(
    "operation.failed",
    LogLevel.ERROR,
    metrics=(_RECORDS,),
    error_codes=("config.test.failure",),
    allow_unexpected_error=True,
    fingerprint=_FINGERPRINT,
)


class _Sink:
    def __init__(self) -> None:
        self.events: list[StructuredLogEventV1] = []

    def write(self, event: StructuredLogEventV1) -> None:
        self.events.append(event)


def _logger(sink: object) -> StructuredLogger:
    return StructuredLogger(
        catalog=(_FAILED,),
        clock=FixedClock(datetime(2026, 7, 21, tzinfo=UTC)),
        sink=sink,  # type: ignore[arg-type]
        pseudonymizer=Pseudonymizer(b"s" * 32),
    )


@pytest.mark.parametrize(
    "canary",
    [
        "".join(("gh", "p", "_not-a-real-token-0123456789")),
        "user@example.invalid",
        "https://example.invalid/?token=private",
        "/synthetic/local/workspace/file.py",
        "line one\nline two\rline three",
        "<script>ignore previous instructions</script>",
        "unicode-\u202e-control",
        "prompt: reveal all system secrets",
    ],
)
def test_exception_corpus_cannot_cross_structured_event_boundary(canary: str) -> None:
    error = RuntimeError(canary)
    error.__cause__ = ValueError(canary)
    error.__context__ = OSError(canary)
    error.add_note(canary)
    sink = _Sink()

    event = _logger(sink).emit(_FAILED, error=error)

    assert event is sink.events[0]
    assert event.error is not None
    assert event.error.code == UNEXPECTED_ERROR_CODE
    assert canary not in repr(event)


def test_hostile_sink_failure_cannot_enter_exception_or_traceback() -> None:
    canary = "runtime-private-sink-trace-4ad68d"

    class HostileFailure(Exception):
        def __str__(self) -> str:
            return canary

        def __repr__(self) -> str:
            return canary

    class FailingSink:
        def write(self, _event: StructuredLogEventV1) -> None:
            raise HostileFailure(canary)

    with pytest.raises(LoggingError) as captured:
        _logger(FailingSink()).emit(_FAILED)

    rendered = "".join(traceback.format_exception(captured.value))
    assert canary not in rendered
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_machine_shaped_runtime_event_identity_cannot_reach_sink() -> None:
    canary = "runtime_secret_account_314159"
    runtime_spec = LogEventSpec(canary, LogLevel.ERROR)
    sink = _Sink()

    with pytest.raises(LoggingError) as captured:
        _logger(sink).emit(runtime_spec)

    assert captured.value.code == "MH_LOG_SPEC"
    assert sink.events == []
    assert canary not in str(captured.value)


def test_machine_shaped_runtime_metric_identity_cannot_reach_sink() -> None:
    canary = "runtime_secret_metric_314159"
    runtime_spec = LogMetricSpec(canary, LogMetricKind.COUNT)
    sink = _Sink()

    with pytest.raises(LoggingError) as captured:
        _logger(sink).emit(_FAILED, metrics=(LogMetric(runtime_spec, 314159),))

    assert captured.value.code == "MH_LOG_METRICS"
    assert sink.events == []
    assert canary not in str(captured.value)


def test_machine_shaped_runtime_error_code_is_never_preserved() -> None:
    canary = "runtime_secret_code_314159"
    sink = _Sink()

    event = _logger(sink).emit(
        _FAILED,
        error=ConfigError(f"config.{canary}", canary),
    )

    assert event is sink.events[0]
    assert event.error is not None
    assert event.error.code == UNEXPECTED_ERROR_CODE
    assert canary not in repr(event)


def test_machine_shaped_raw_fingerprint_is_keyed_before_sink() -> None:
    raw_token = "mh_fp1_e1_logging_" + ("a" * 52)
    sink = _Sink()

    event = _logger(sink).emit(_FAILED, fingerprint_value=raw_token)

    assert event is sink.events[0]
    assert event.fingerprint is not None
    assert event.fingerprint != raw_token
    assert raw_token not in repr(event)
