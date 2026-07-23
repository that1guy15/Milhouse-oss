from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from milhouse.core import FixedClock
from milhouse.core.log_wire import StreamLogSink, structured_log_event_line
from milhouse.core.logging import (
    LogEventSpec,
    LoggingError,
    LogLevel,
    LogMetric,
    LogMetricKind,
    LogMetricSpec,
    StructuredLogEventV1,
    StructuredLogger,
)

_RECORDS = LogMetricSpec("records", LogMetricKind.COUNT)
_COMMIT = LogEventSpec("spool.commit", LogLevel.INFO, metrics=(_RECORDS,))
_RETRY = LogEventSpec("spool.retry", LogLevel.WARNING, metrics=(_RECORDS,))


@dataclass
class _CapturingSink:
    events: list[StructuredLogEventV1] = field(default_factory=list)

    def write(self, event: StructuredLogEventV1) -> None:
        self.events.append(event)


def _logger(
    sink: object, *, catalog: tuple[LogEventSpec, ...] = (_COMMIT, _RETRY)
) -> StructuredLogger:
    return StructuredLogger(
        catalog=catalog,
        clock=FixedClock(datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)),
        sink=sink,  # type: ignore[arg-type]
        minimum_level=LogLevel.DEBUG,
    )


def _event() -> StructuredLogEventV1:
    capture = _CapturingSink()
    event = _logger(capture).emit(_COMMIT, metrics=(LogMetric(_RECORDS, 3),))
    assert event is not None
    return event


def test_stream_sink_writes_exactly_one_canonical_line() -> None:
    stream = io.BytesIO()
    event = _event()

    StreamLogSink(stream).write(event)

    written = stream.getvalue()
    assert written == structured_log_event_line(event)
    assert written.endswith(b"\n")
    assert written.count(b"\n") == 1


def test_stream_sink_appends_sequential_event_lines() -> None:
    stream = io.BytesIO()
    sink = StreamLogSink(stream)
    capture = _CapturingSink()
    logger = _logger(capture)

    first = logger.emit(_COMMIT, metrics=(LogMetric(_RECORDS, 1),))
    second = logger.emit(_RETRY, metrics=(LogMetric(_RECORDS, 2),))
    assert first is not None
    assert second is not None
    sink.write(first)
    sink.write(second)

    assert stream.getvalue() == structured_log_event_line(first) + structured_log_event_line(second)
    assert stream.getvalue().count(b"\n") == 2


def test_stream_sink_rejects_a_non_writable_stream() -> None:
    with pytest.raises(LoggingError) as captured:
        StreamLogSink(object())  # type: ignore[arg-type]
    assert captured.value.code == "MH_LOG_SINK_STREAM"


def test_stream_sink_rejects_a_non_event_value() -> None:
    sink = StreamLogSink(io.BytesIO())
    with pytest.raises(LoggingError) as captured:
        sink.write({"name": "spool.commit"})  # type: ignore[arg-type]
    assert captured.value.code == "MH_LOG_SINK_EVENT"


def test_stream_sink_wraps_a_hostile_stream_failure_without_leaking_detail() -> None:
    canary = "runtime-private-stream-detail-9c1f"

    class _HostileStream:
        def write(self, _data: bytes) -> int:
            raise OSError(canary)

    with pytest.raises(LoggingError) as captured:
        StreamLogSink(_HostileStream()).write(_event())

    assert captured.value.code == "MH_LOG_SINK_WRITE"
    assert canary not in str(captured.value)
    assert captured.value.__cause__ is None


def test_structured_logger_delivers_to_a_stream_sink_without_touching_stdio(
    capsys: pytest.CaptureFixture[str],
) -> None:
    stream = io.BytesIO()
    event = _logger(StreamLogSink(stream)).emit(_COMMIT, metrics=(LogMetric(_RECORDS, 7),))

    assert event is not None
    assert stream.getvalue() == structured_log_event_line(event)
    assert capsys.readouterr() == ("", "")
