from __future__ import annotations

import io
import traceback
from datetime import UTC, datetime

import pytest

from milhouse.config import ConfigError
from milhouse.core import FixedClock
from milhouse.core.log_wire import StreamLogSink
from milhouse.core.logging import (
    LogEventSpec,
    LogFingerprintSpec,
    LoggingError,
    LogLevel,
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
    fingerprint=_FINGERPRINT,
)


class _Sink:
    def write(self, event: StructuredLogEventV1) -> None:
        return None


def _event(**emit_kwargs: object) -> StructuredLogEventV1:
    logger = StructuredLogger(
        catalog=(_FAILED,),
        clock=FixedClock(datetime(2026, 7, 21, tzinfo=UTC)),
        sink=_Sink(),
        pseudonymizer=Pseudonymizer(b"s" * 32),
    )
    event = logger.emit(_FAILED, **emit_kwargs)  # type: ignore[arg-type]
    assert event is not None
    return event


@pytest.mark.security
def test_stream_sink_never_emits_a_planted_secret() -> None:
    canary = "runtime-secret-log-sink-5b7e21"
    stream = io.BytesIO()

    StreamLogSink(stream).write(
        _event(
            error=ConfigError("config.test.failure", "synthetic"),
            fingerprint_value=canary,
        )
    )

    emitted = stream.getvalue()
    assert canary.encode("utf-8") not in emitted
    assert b"synthetic" not in emitted  # the error message text never reaches the wire
    assert emitted.count(b"\n") == 1


@pytest.mark.security
def test_stream_sink_fails_closed_and_emits_nothing_when_egress_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from milhouse.core import log_wire
    from milhouse.privacy import EgressDisposition

    monkeypatch.setattr(
        log_wire,
        "require_egress",
        lambda **_kwargs: EgressDisposition.REDACTED_RECORD,
    )
    stream = io.BytesIO()
    with pytest.raises(LoggingError) as captured:
        StreamLogSink(stream).write(_event())

    assert captured.value.code == "MH_LOG_WIRE_EGRESS"
    assert stream.getvalue() == b""


def _graph(error: BaseException) -> tuple[str, ...]:
    return (
        str(error),
        repr(error),
        repr(error.args),
        "".join(traceback.format_exception(error)),
    )


@pytest.mark.security
def test_stream_sink_normalizes_a_stream_raised_logging_error() -> None:
    canary = "runtime-private-logging-detail-3a7d"

    class _Raiser:
        def write(self, _data: object) -> object:
            raise LoggingError("MH_LOG_SINK", canary)

    with pytest.raises(LoggingError) as captured:
        StreamLogSink(_Raiser()).write(_event())

    error = captured.value
    assert error.code == "MH_LOG_SINK_WRITE"  # normalized, never passed through
    assert error.__cause__ is None
    assert error.__context__ is None
    assert all(canary not in part for part in _graph(error))


@pytest.mark.security
def test_stream_sink_normalizes_a_hostile_write_descriptor() -> None:
    canary = "runtime-private-descriptor-detail-6b2e"

    class _Hostile:
        @property
        def write(self) -> object:
            raise RuntimeError(canary)

    with pytest.raises(LoggingError) as captured:
        StreamLogSink(_Hostile())

    error = captured.value
    assert error.code == "MH_LOG_SINK_STREAM"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert all(canary not in part for part in _graph(error))
